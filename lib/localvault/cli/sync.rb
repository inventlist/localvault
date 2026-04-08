require "thor"
require "fileutils"

module LocalVault
  class CLI
    class Sync < Thor
      desc "push [NAME]", "Push a vault to InventList cloud sync"
      # Push a local vault to InventList cloud sync.
      #
      # Packs the vault's meta and encrypted secrets into a SyncBundle and uploads
      # it. Preserves existing key slots from the remote and bootstraps an owner
      # slot if the current identity has no slot yet. Defaults to the configured
      # default vault if no name is given.
      def push(vault_name = nil)
        return unless logged_in?

        vault_name ||= Config.default_vault
        store = Store.new(vault_name)

        unless store.exists?
          $stderr.puts "Error: Vault '#{vault_name}' does not exist. Run: localvault init #{vault_name}"
          return
        end

        # Load remote state to determine vault mode. MUST distinguish a
        # genuinely-absent remote (404) from a transient API failure: treating
        # a 5xx as "no remote" would silently downgrade a team vault to a
        # personal v1 bundle on the next push.
        remote_data, load_error = load_remote_bundle_data(vault_name)
        if load_error
          $stderr.puts "Error: #{load_error}"
          $stderr.puts "Refusing to push — cannot verify vault mode. Retry when the server is reachable."
          return
        end
        handle = Config.inventlist_handle

        if remote_data && remote_data[:owner]
          # Team vault — check push authorization
          owner = remote_data[:owner]
          key_slots = remote_data[:key_slots] || {}
          has_scoped = key_slots.values.any? { |s| s.is_a?(Hash) && s["scopes"].is_a?(Array) }
          my_slot = key_slots[handle]
          am_scoped = my_slot.is_a?(Hash) && my_slot["scopes"].is_a?(Array)

          if am_scoped
            $stderr.puts "Error: You have scoped access to vault '#{vault_name}'. Only the owner (@#{owner}) can push."
            return
          end

          if has_scoped && owner != handle
            $stderr.puts "Error: Vault '#{vault_name}' has scoped members. Only the owner (@#{owner}) can push."
            return
          end

          # Authorized — push as v3, preserve key_slots
          key_slots = bootstrap_owner_slot(key_slots, store)
          blob = SyncBundle.pack_v3(store, owner: owner, key_slots: key_slots)
        else
          # Personal vault — push as v1
          blob = SyncBundle.pack(store)
        end

        client = ApiClient.new(token: Config.token)
        client.push_vault(vault_name, blob)

        $stdout.puts "Synced vault '#{vault_name}' (#{blob.bytesize} bytes)"
      rescue ApiClient::ApiError => e
        $stderr.puts "Error: #{e.message}"
      end

      desc "pull [NAME]", "Pull a vault from InventList cloud sync"
      method_option :force, type: :boolean, default: false, desc: "Overwrite existing local vault"
      # Pull a vault from InventList cloud sync to the local filesystem.
      #
      # Downloads the SyncBundle, writes meta.yml and secrets.enc locally, and
      # attempts automatic unlock via key slot. Refuses to overwrite an existing
      # local vault unless +--force+ is passed. Defaults to the configured default
      # vault if no name is given.
      def pull(vault_name = nil)
        return unless logged_in?

        vault_name ||= Config.default_vault
        store  = Store.new(vault_name)

        if store.exists? && !options[:force]
          $stderr.puts "Error: Vault '#{vault_name}' already exists locally. Use --force to overwrite."
          return
        end

        client = ApiClient.new(token: Config.token)
        blob   = client.pull_vault(vault_name)
        data   = SyncBundle.unpack(blob, expected_name: vault_name)

        FileUtils.mkdir_p(store.vault_path, mode: 0o700)
        File.write(store.meta_path, data[:meta])
        File.chmod(0o600, store.meta_path)
        if data[:secrets].empty?
          FileUtils.rm_f(store.secrets_path)
        else
          store.write_encrypted(data[:secrets])
        end

        $stdout.puts "Pulled vault '#{vault_name}'."

        if try_unlock_via_key_slot(vault_name, data[:key_slots])
          $stdout.puts "Unlocked via your identity key."
        else
          $stdout.puts "Unlock it with: localvault unlock -v #{vault_name}"
        end
      rescue SyncBundle::UnpackError => e
        $stderr.puts "Error: #{e.message}"
      rescue ApiClient::ApiError => e
        if e.status == 404
          $stderr.puts "Error: Vault '#{vault_name}' not found in cloud."
        else
          $stderr.puts "Error: #{e.message}"
        end
      end

      desc "status", "Show sync status for all vaults"
      # Display sync status for all local and remote vaults.
      #
      # Shows a table with vault name, status (synced / remote only / local only),
      # and last sync timestamp. Compares local vaults against the cloud inventory.
      def status
        return unless logged_in?

        client    = ApiClient.new(token: Config.token)
        result    = client.list_vaults
        remote    = (result["vaults"] || []).each_with_object({}) { |v, h| h[v["name"]] = v }
        local_set = Store.list_vaults.to_set
        all_names = (remote.keys + local_set.to_a).uniq.sort

        if all_names.empty?
          $stdout.puts "No vaults found locally or in cloud."
          return
        end

        rows = all_names.map do |name|
          r         = remote[name]
          l_exists  = local_set.include?(name)
          row_status = if r && l_exists then "synced"
                       elsif r          then "remote only"
                       else                  "local only"
                       end
          synced_at = r ? (r["synced_at"]&.slice(0, 10) || "—") : "—"
          [name, row_status, synced_at]
        end

        max_name   = (["Vault"] + rows.map { |r| r[0] }).map(&:length).max
        max_status = (["Status"] + rows.map { |r| r[1] }).map(&:length).max

        $stdout.puts "#{"Vault".ljust(max_name)}  #{"Status".ljust(max_status)}  Synced At"
        $stdout.puts "#{"─" * max_name}  #{"─" * max_status}  ─────────"
        rows.each do |name, row_status, synced_at|
          $stdout.puts "#{name.ljust(max_name)}  #{row_status.ljust(max_status)}  #{synced_at}"
        end
      rescue ApiClient::ApiError => e
        $stderr.puts "Error: #{e.message}"
      end

      def self.exit_on_failure?
        true
      end

      private

      # Try to decrypt via key slot matching the current identity.
      #
      # For full-access members (scopes: nil): decrypts enc_key to get the master key.
      # For scoped members (scopes: [...]): decrypts enc_key to get the per-member key,
      # then decrypts the per-member blob and writes it as the local vault's secrets.
      #
      # On success, caches the key in SessionCache. Returns true/false.
      def try_unlock_via_key_slot(vault_name, key_slots)
        return false unless key_slots.is_a?(Hash) && !key_slots.empty?
        return false unless Identity.exists?

        handle = Config.inventlist_handle
        return false unless handle

        slot = key_slots[handle]
        return false unless slot.is_a?(Hash) && slot["enc_key"].is_a?(String)

        decrypted_key = KeySlot.decrypt(slot["enc_key"], Identity.private_key_bytes)

        if slot["scopes"].is_a?(Array) && slot["blob"].is_a?(String)
          # Scoped member: decrypt per-member blob and write as local vault
          blob_encrypted = Base64.strict_decode64(slot["blob"])
          filtered_json = Crypto.decrypt(blob_encrypted, decrypted_key)
          # Verify it's valid JSON
          JSON.parse(filtered_json)

          # Re-encrypt the filtered secrets with the member key as local "master key"
          store = Store.new(vault_name)
          store.write_encrypted(Crypto.encrypt(filtered_json, decrypted_key))

          SessionCache.set(vault_name, decrypted_key)
        else
          # Full-access member: decrypted_key IS the master key
          vault = Vault.new(name: vault_name, master_key: decrypted_key)
          vault.all  # verify

          SessionCache.set(vault_name, decrypted_key)
        end
        true
      rescue KeySlot::DecryptionError, Crypto::DecryptionError, ArgumentError, JSON::ParserError
        false
      end

      def logged_in?
        return true if Config.token

        $stderr.puts "Error: Not logged in."
        $stderr.puts
        $stderr.puts "  localvault login YOUR_TOKEN"
        $stderr.puts
        $stderr.puts "Get your token at: https://inventlist.com/@YOUR_HANDLE/edit#developer"
        $stderr.puts "New to InventList? Sign up free at https://inventlist.com"
        $stderr.puts "Docs: https://inventlist.com/sites/localvault/series/localvault"
        false
      end

      # Load the full unpacked remote bundle data (owner, key_slots, etc).
      # Returns [data, error_message]:
      #   - [hash, nil] on success
      #   - [nil,  nil] when there genuinely is no remote bundle (404 / empty)
      #   - [nil,  msg] on any other failure (transient network, 5xx, bad bundle)
      #
      # The caller MUST distinguish these cases — treating a transient error
      # as "no remote" is a data-corruption bug: sync push would then re-upload
      # the vault as a v1 personal bundle, silently downgrading a team vault
      # and wiping its owner + key_slots.
      def load_remote_bundle_data(vault_name)
        client = ApiClient.new(token: Config.token)
        blob = client.pull_vault(vault_name)
        return [nil, nil] unless blob.is_a?(String) && !blob.empty?
        [SyncBundle.unpack(blob), nil]
      rescue ApiClient::ApiError => e
        return [nil, nil] if e.status == 404
        [nil, "Could not load remote bundle for '#{vault_name}': #{e.message}"]
      rescue SyncBundle::UnpackError => e
        [nil, "Could not parse remote bundle for '#{vault_name}': #{e.message}"]
      end

      # Load key_slots from the last pushed blob (if any).
      # Returns {} if no remote blob or if it's a v1 bundle.
      def load_existing_key_slots(vault_name)
        client = ApiClient.new(token: Config.token)
        blob = client.pull_vault(vault_name)
        return {} unless blob.is_a?(String) && !blob.empty?
        data = SyncBundle.unpack(blob)
        data[:key_slots] || {}
      rescue ApiClient::ApiError, SyncBundle::UnpackError
        {}
      end

      # Add the owner's key slot if identity exists and no slot is present.
      # Requires the vault to be unlockable (needs master key for encryption).
      def bootstrap_owner_slot(key_slots, store)
        return key_slots unless Identity.exists?
        handle = Config.inventlist_handle
        return key_slots unless handle

        # Already has owner slot — don't churn
        return key_slots if key_slots.key?(handle)

        # Need the master key to create the slot — try SessionCache
        master_key = SessionCache.get(store.vault_name)
        return key_slots unless master_key

        pub_b64 = Identity.public_key
        enc_key = KeySlot.create(master_key, pub_b64)
        key_slots[handle] = { "pub" => pub_b64, "enc_key" => enc_key }
        key_slots
      end
    end
  end
end
