require "thor"
require "fileutils"

module LocalVault
  class CLI
    class Sync < Thor
      desc "push [NAME]", "Push a vault to InventList cloud sync"
      def push(vault_name = nil)
        return unless logged_in?

        vault_name ||= Config.default_vault
        store = Store.new(vault_name)

        unless store.exists?
          $stderr.puts "Error: Vault '#{vault_name}' does not exist. Run: localvault init #{vault_name}"
          return
        end

        key_slots = load_existing_key_slots(vault_name)
        key_slots = bootstrap_owner_slot(key_slots, store)

        blob   = SyncBundle.pack(store, key_slots: key_slots)
        client = ApiClient.new(token: Config.token)
        client.push_vault(vault_name, blob)

        $stdout.puts "Synced vault '#{vault_name}' (#{blob.bytesize} bytes)"
      rescue ApiClient::ApiError => e
        $stderr.puts "Error: #{e.message}"
      end

      desc "pull [NAME]", "Pull a vault from InventList cloud sync"
      method_option :force, type: :boolean, default: false, desc: "Overwrite existing local vault"
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

      # Try to decrypt the master key from a key slot matching the current identity.
      # On success, caches the master key in SessionCache. Returns true/false.
      def try_unlock_via_key_slot(vault_name, key_slots)
        return false unless key_slots.is_a?(Hash) && !key_slots.empty?
        return false unless Identity.exists?

        handle = Config.inventlist_handle
        return false unless handle

        slot = key_slots[handle]
        return false unless slot.is_a?(Hash) && slot["enc_key"].is_a?(String)

        master_key = KeySlot.decrypt(slot["enc_key"], Identity.private_key_bytes)

        # Verify the key actually works by trying to decrypt
        vault = Vault.new(name: vault_name, master_key: master_key)
        vault.all

        SessionCache.set(vault_name, master_key)
        true
      rescue KeySlot::DecryptionError, Crypto::DecryptionError
        false
      end

      def logged_in?
        return true if Config.token

        $stderr.puts "Error: Not logged in. Run: localvault login TOKEN"
        false
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
