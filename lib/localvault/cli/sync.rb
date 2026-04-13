require "thor"
require "fileutils"
require "digest"

module LocalVault
  class CLI
    class Sync < Thor
      desc "all", "Sync all vaults bidirectionally (push local changes, pull remote changes)"
      method_option :dry_run, type: :boolean, default: false, desc: "Show what would happen without making changes"
      # Smart bidirectional sync for all vaults.
      #
      # Uses per-vault .sync_state files (written by push/pull) to track
      # the last-synced checksum and detect what changed on each side:
      #
      # - Local-only vault → push
      # - Remote-only vault → pull
      # - Both exist, only local changed → push
      # - Both exist, only remote changed → pull
      # - Both exist, neither changed → skip
      # - Both exist, both changed → CONFLICT (manual resolution)
      # - Shared vault (not owned by you) → pull-only
      def all
        return unless logged_in?

        client     = ApiClient.new(token: Config.token)
        my_handle  = Config.inventlist_handle
        result     = client.list_vaults
        remote_map = (result["vaults"] || []).each_with_object({}) { |v, h| h[v["name"]] = v }
        local_set  = Store.list_vaults.to_set
        all_names  = (remote_map.keys + local_set.to_a).uniq.sort

        if all_names.empty?
          $stdout.puts "No vaults to sync."
          return
        end

        plan = all_names.map { |name| classify_vault(name, local_set, remote_map, my_handle) }

        # Print plan
        max_name   = (["Vault"]  + plan.map { |p| p[:name] }).map(&:length).max
        max_action = (["Action"] + plan.map { |p| p[:action].to_s }).map(&:length).max

        $stdout.puts
        $stdout.puts "  #{"Vault".ljust(max_name)}  #{"Action".ljust(max_action)}  Reason"
        $stdout.puts "  #{"─" * max_name}  #{"─" * max_action}  ──────"
        plan.each do |p|
          label = p[:action] == :conflict ? "CONFLICT" : p[:action].to_s
          $stdout.puts "  #{p[:name].ljust(max_name)}  #{label.ljust(max_action)}  #{p[:reason]}"
        end
        $stdout.puts

        if options[:dry_run]
          $stdout.puts "Dry run — no changes made."
          return
        end

        # Execute
        pushed = pulled = skipped = conflicts = errors = 0
        plan.each do |entry|
          case entry[:action]
          when :push
            if perform_push(entry[:name], client)
              pushed += 1
            else
              errors += 1
            end
          when :pull
            if perform_pull(entry[:name], client, force: true)
              pulled += 1
            else
              errors += 1
            end
          when :skip
            skipped += 1
          when :conflict
            conflicts += 1
          end
        end

        # Summary
        parts = []
        parts << "#{pushed} pushed"     if pushed > 0
        parts << "#{pulled} pulled"     if pulled > 0
        parts << "#{skipped} up to date" if skipped > 0
        parts << "#{errors} failed"     if errors > 0
        parts << "#{conflicts} conflict#{conflicts == 1 ? "" : "s"}" if conflicts > 0
        $stdout.puts "Summary: #{parts.join(", ")}"

        # Conflict guidance
        if conflicts > 0
          $stdout.puts
          plan.select { |p| p[:action] == :conflict }.each do |p|
            $stderr.puts "  #{p[:name]} — #{p[:reason]}"
            $stderr.puts "    Resolve with:"
            $stderr.puts "      localvault sync push #{p[:name]}   (keep local, overwrite remote)"
            $stderr.puts "      localvault sync pull #{p[:name]} --force  (keep remote, overwrite local)"
          end
        end
      rescue ApiClient::ApiError => e
        $stderr.puts "Error: #{e.message}"
      end

      default_task :all

      desc "push [NAME]", "Push a vault to InventList cloud sync"
      def push(vault_name = nil)
        return unless logged_in?
        vault_name ||= Config.default_vault
        client = ApiClient.new(token: Config.token)
        perform_push(vault_name, client)
      end

      desc "pull [NAME]", "Pull a vault from InventList cloud sync"
      method_option :force, type: :boolean, default: false, desc: "Overwrite existing local vault"
      def pull(vault_name = nil)
        return unless logged_in?
        vault_name ||= Config.default_vault
        client = ApiClient.new(token: Config.token)
        perform_pull(vault_name, client, force: options[:force])
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

      # ── Core push logic ──────────────────────────────────────────

      def perform_push(vault_name, client)
        store = Store.new(vault_name)
        unless store.exists?
          $stderr.puts "Error: Vault '#{vault_name}' does not exist. Run: localvault init #{vault_name}"
          return false
        end

        remote_data, load_error = load_remote_bundle_data(vault_name)
        if load_error
          $stderr.puts "Error: #{load_error}"
          $stderr.puts "Refusing to push — cannot verify vault mode."
          return false
        end

        handle = Config.inventlist_handle

        if remote_data && remote_data[:owner]
          owner     = remote_data[:owner]
          key_slots = remote_data[:key_slots] || {}
          has_scoped = key_slots.values.any? { |s| s.is_a?(Hash) && s["scopes"].is_a?(Array) }
          my_slot    = key_slots[handle]
          am_scoped  = my_slot.is_a?(Hash) && my_slot["scopes"].is_a?(Array)

          if am_scoped
            $stderr.puts "Error: You have scoped access to vault '#{vault_name}'. Only the owner (@#{owner}) can push."
            return false
          end
          if has_scoped && owner != handle
            $stderr.puts "Error: Vault '#{vault_name}' has scoped members. Only the owner (@#{owner}) can push."
            return false
          end

          key_slots = bootstrap_owner_slot(key_slots, store)
          blob = SyncBundle.pack_v3(store, owner: owner, key_slots: key_slots)
        else
          blob = SyncBundle.pack(store)
        end

        client.push_vault(vault_name, blob)

        # Record sync state
        SyncState.new(vault_name).write!(
          checksum: SyncState.local_checksum(store),
          direction: "push"
        )

        $stdout.puts "  pushed #{vault_name} (#{blob.bytesize} bytes)"
        true
      rescue ApiClient::ApiError => e
        $stderr.puts "Error pushing '#{vault_name}': #{e.message}"
        false
      end

      # ── Core pull logic ──────────────────────────────────────────

      def perform_pull(vault_name, client, force: false)
        store = Store.new(vault_name)
        if store.exists? && !force
          $stderr.puts "Error: Vault '#{vault_name}' already exists locally. Use --force to overwrite."
          return false
        end

        blob = client.pull_vault(vault_name)
        data = SyncBundle.unpack(blob, expected_name: vault_name)

        FileUtils.mkdir_p(store.vault_path, mode: 0o700)
        File.write(store.meta_path, data[:meta])
        File.chmod(0o600, store.meta_path)
        if data[:secrets].empty?
          FileUtils.rm_f(store.secrets_path)
        else
          store.write_encrypted(data[:secrets])
        end

        # Record sync state
        SyncState.new(vault_name).write!(
          checksum: SyncState.local_checksum(store),
          direction: "pull"
        )

        $stdout.puts "  pulled #{vault_name}"

        if try_unlock_via_key_slot(vault_name, data[:key_slots])
          $stdout.puts "  unlocked via identity key"
        else
          $stdout.puts "  unlock it with: localvault unlock #{vault_name}"
        end
        true
      rescue SyncBundle::UnpackError => e
        $stderr.puts "Error pulling '#{vault_name}': #{e.message}"
        false
      rescue ApiClient::ApiError => e
        if e.status == 404
          $stderr.puts "Error: Vault '#{vault_name}' not found in cloud."
        else
          $stderr.puts "Error pulling '#{vault_name}': #{e.message}"
        end
        false
      end

      # ── Classification ───────────────────────────────────────────

      def classify_vault(name, local_set, remote_map, my_handle)
        l_exists = local_set.include?(name)
        r_info   = remote_map[name]
        r_exists = !r_info.nil?

        store      = l_exists ? Store.new(name) : nil
        ss         = SyncState.new(name)
        s_exists   = ss.exists?
        baseline   = ss.last_synced_checksum

        local_checksum  = l_exists && store ? SyncState.local_checksum(store) : nil
        remote_checksum = r_info&.dig("checksum")

        # Ownership
        owner_handle = r_info&.dig("owner_handle")
        is_shared    = r_info&.dig("shared") == true
        is_read_only = is_shared || (owner_handle && owner_handle != my_handle)

        action, reason = determine_action(
          l_exists, r_exists, s_exists,
          local_checksum, remote_checksum, baseline,
          is_read_only
        )

        { name: name, action: action, reason: reason }
      end

      def determine_action(l_exists, r_exists, s_exists,
                           local_cs, remote_cs, baseline, is_read_only)
        # Only local
        if l_exists && !r_exists
          return is_read_only ? [:skip, "shared vault, local copy only"] : [:push, "local only"]
        end

        # Only remote
        return [:pull, "remote only"] if !l_exists && r_exists

        # Neither (shouldn't happen since we iterate union)
        return [:skip, "no data"] unless l_exists && r_exists

        # Both exist — no baseline (first sync for this vault)
        unless s_exists
          if local_cs == remote_cs || (local_cs.nil? && remote_cs.nil?)
            return [:skip, "already in sync (first check)"]
          else
            return [:conflict, "both exist, no sync baseline — cannot determine which side changed"]
          end
        end

        # Both exist, have baseline
        local_changed  = local_cs != baseline
        remote_changed = remote_cs != baseline

        if !local_changed && !remote_changed
          [:skip, "up to date"]
        elsif local_changed && !remote_changed
          is_read_only ? [:skip, "shared vault (local edits, pull-only)"] : [:push, "local changes"]
        elsif !local_changed && remote_changed
          [:pull, "remote changes"]
        else
          [:conflict, "both local and remote changed since last sync"]
        end
      end

      # ── Helpers ──────────────────────────────────────────────────

      def try_unlock_via_key_slot(vault_name, key_slots)
        return false unless key_slots.is_a?(Hash) && !key_slots.empty?
        return false unless Identity.exists?

        handle = Config.inventlist_handle
        return false unless handle

        slot = key_slots[handle]
        return false unless slot.is_a?(Hash) && slot["enc_key"].is_a?(String)

        decrypted_key = KeySlot.decrypt(slot["enc_key"], Identity.private_key_bytes)

        if slot["scopes"].is_a?(Array) && slot["blob"].is_a?(String)
          blob_encrypted = Base64.strict_decode64(slot["blob"])
          filtered_json = Crypto.decrypt(blob_encrypted, decrypted_key)
          JSON.parse(filtered_json)

          store = Store.new(vault_name)
          store.write_encrypted(Crypto.encrypt(filtered_json, decrypted_key))
          SessionCache.set(vault_name, decrypted_key)
        else
          vault = Vault.new(name: vault_name, master_key: decrypted_key)
          vault.all
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

      def load_existing_key_slots(vault_name)
        client = ApiClient.new(token: Config.token)
        blob = client.pull_vault(vault_name)
        return {} unless blob.is_a?(String) && !blob.empty?
        data = SyncBundle.unpack(blob)
        data[:key_slots] || {}
      rescue ApiClient::ApiError, SyncBundle::UnpackError
        {}
      end

      def bootstrap_owner_slot(key_slots, store)
        return key_slots unless Identity.exists?
        handle = Config.inventlist_handle
        return key_slots unless handle
        return key_slots if key_slots.key?(handle)

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
