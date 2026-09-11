require "thor"
require "fileutils"
require "digest"
require "io/console"
require_relative "team_helpers"

module LocalVault
  class CLI
    class Sync < Thor
      include LocalVault::CLI::TeamHelpers

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
      # - Both exist, no baseline but secrets identical → adopt (record baseline)
      # - Both exist, both changed → CONFLICT (resolve with sync merge / push / pull --force)
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

        plan = all_names.map { |name| classify_vault(name, local_set, remote_map, my_handle, client) }

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
        pushed = pulled = skipped = adopted = conflicts = errors = 0
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
          when :adopt
            if perform_adopt(entry[:name])
              adopted += 1
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
        parts << "#{pushed} pushed"      if pushed > 0
        parts << "#{pulled} pulled"      if pulled > 0
        parts << "#{adopted} baselined"  if adopted > 0
        parts << "#{skipped} up to date" if skipped > 0
        parts << "#{errors} failed"      if errors > 0
        parts << "#{conflicts} conflict#{conflicts == 1 ? "" : "s"}" if conflicts > 0
        $stdout.puts "Summary: #{parts.join(", ")}"

        # Conflict guidance — key names only, never values
        if conflicts > 0
          $stdout.puts
          plan.select { |p| p[:action] == :conflict }.each do |p|
            $stderr.puts "  #{p[:name]} — #{p[:reason]}"
            result = quiet_merge_preview(p[:name], client)
            if result
              print_merge_report(result, indent: "    ", io: $stderr)
              print_resolution_help(p[:name], result, io: $stderr)
            else
              $stderr.puts "    See which keys differ (no values shown):"
              $stderr.puts "      localvault sync diff #{p[:name]}"
              print_resolution_help(p[:name], nil, io: $stderr)
            end
          end
        end
      rescue ApiClient::ApiError => e
        $stderr.puts "Error: #{e.message}"
      end

      default_task :all

      desc "push [NAME]", "Push a vault to InventList cloud sync"
      method_option :vault, type: :string, aliases: "-v", desc: "Vault name (same as NAME)"
      def push(vault_name = nil)
        return unless logged_in?
        vault_name ||= options[:vault] || Config.default_vault
        client = ApiClient.new(token: Config.token)
        perform_push(vault_name, client)
      end

      desc "pull [NAME]", "Pull a vault from InventList cloud sync"
      method_option :force, type: :boolean, default: false, desc: "Overwrite existing local vault"
      method_option :vault, type: :string, aliases: "-v", desc: "Vault name (same as NAME)"
      def pull(vault_name = nil)
        return unless logged_in?
        vault_name ||= options[:vault] || Config.default_vault
        client = ApiClient.new(token: Config.token)
        perform_pull(vault_name, client, force: options[:force])
      end

      desc "diff [NAME]", "Show which keys differ between local and cloud (names only, no values)"
      method_option :vault, type: :string, aliases: "-v", desc: "Vault name (same as NAME)"
      def diff(vault_name = nil)
        return unless logged_in?
        vault_name ||= options[:vault] || Config.default_vault
        client = ApiClient.new(token: Config.token)

        result = build_merge(vault_name, client)
        return false unless result

        if result.local_changes.empty? && result.remote_changes.empty? &&
           result.same_changes.empty? && result.conflicts.empty?
          $stdout.puts "#{vault_name}: local and cloud hold the same secrets."
          return true
        end

        $stdout.puts "#{vault_name} — three-way diff against last sync (values never shown)"
        print_merge_report(result, indent: "  ", io: $stdout)
        $stdout.puts
        print_resolution_help(vault_name, result, io: $stdout)
        true
      rescue ApiClient::ApiError => e
        $stderr.puts "Error: #{e.message}"
        false
      end

      desc "merge [NAME]", "Three-way merge local and cloud, then push the result"
      method_option :vault,   type: :string,  aliases: "-v", desc: "Vault name (same as NAME)"
      method_option :prefer,  type: :string,  enum: %w[local remote], desc: "Resolve every conflicting key from this side"
      method_option :local,   type: :array,   default: [], desc: "Keys to keep from local (repeatable)"
      method_option :remote,  type: :array,   default: [], desc: "Keys to take from cloud (repeatable)"
      method_option :dry_run, type: :boolean, default: false, desc: "Show the merge plan without writing or pushing"
      method_option :push,    type: :boolean, default: true, desc: "Push after merging (--no-push keeps it local)"
      # Merge cloud changes into the local vault key by key using the
      # ancestor snapshot recorded at the last sync. Non-conflicting changes
      # from both sides apply automatically; a key changed differently on
      # both sides needs +--prefer+ or a per-key +--local+/+--remote+ pick.
      def merge(vault_name = nil)
        return unless logged_in?
        vault_name ||= options[:vault] || Config.default_vault
        client = ApiClient.new(token: Config.token)

        both = options[:local] & options[:remote]
        unless both.empty?
          $stderr.puts "Error: #{both.join(", ")} given to both --local and --remote. Pick one side per key."
          return false
        end
        picks = {}
        options[:local].each  { |k| picks[k] = :local }
        options[:remote].each { |k| picks[k] = :remote }
        prefer = options[:prefer]&.to_sym

        result = build_merge(vault_name, client, prefer: prefer, picks: picks)
        return false unless result

        unknown = picks.keys - result.conflict_keys_before_picks
        unless unknown.empty?
          $stderr.puts "Warning: #{unknown.join(", ")} #{unknown.size == 1 ? "is" : "are"} not in conflict — ignored."
        end

        $stdout.puts "#{vault_name} — merge plan (values never shown)"
        print_merge_report(result, indent: "  ", io: $stdout)

        unless result.clean?
          $stdout.puts
          $stderr.puts "Error: #{result.conflicts.size} key#{result.conflicts.size == 1 ? "" : "s"} changed on both sides. Choose a side:"
          print_resolution_help(vault_name, result, io: $stderr, merge_only: true)
          return false
        end

        if options[:dry_run]
          $stdout.puts
          $stdout.puts "Dry run — no changes made."
          return true
        end

        master_key = @merge_master_key
        vault = Vault.new(name: vault_name, master_key: master_key)
        vault.replace(result.merged)
        $stdout.puts "  merged #{vault_name} locally"

        unless options[:push]
          $stdout.puts "  not pushed (--no-push). Push later with: localvault sync push #{vault_name}"
          return true
        end

        perform_push(vault_name, client)
      rescue ApiClient::ApiError => e
        $stderr.puts "Error: #{e.message}"
        false
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

      # Push a single vault to the cloud. Detects team vs personal mode,
      # checks push authorization, packs the SyncBundle, uploads, and
      # records the checksum in +.sync_state+ on success.
      #
      # Used by both the public +push+ command and the +all+ sync loop.
      #
      # @param vault_name [String] vault to push
      # @param client [ApiClient] authenticated API client
      # @return [Boolean] true on success, false on any error
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
          key_slots = refresh_scoped_slots(key_slots, store)
          return false unless key_slots
          blob = SyncBundle.pack_v3(store, owner: owner, key_slots: key_slots)
        else
          blob = SyncBundle.pack(store)
        end

        client.push_vault(vault_name, blob)

        # Record sync state + ancestor snapshot for future merges
        SyncState.new(vault_name).record!(store, direction: "push")

        $stdout.puts "  pushed #{vault_name} (#{blob.bytesize} bytes)"
        true
      rescue ApiClient::ApiError => e
        $stderr.puts "Error pushing '#{vault_name}': #{e.message}"
        false
      end

      # ── Core pull logic ──────────────────────────────────────────

      # Pull a single vault from the cloud. Downloads the SyncBundle,
      # writes meta.yml and secrets.enc locally, records +.sync_state+,
      # and attempts automatic unlock via the user's identity key slot.
      #
      # @param vault_name [String] vault to pull
      # @param client [ApiClient] authenticated API client
      # @param force [Boolean] overwrite existing local vault (default: false)
      # @return [Boolean] true on success, false on any error
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

        # Record sync state + ancestor snapshot for future merges
        SyncState.new(vault_name).record!(store, direction: "pull")

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

      # Determine the sync action for a single vault by comparing local,
      # remote, and baseline state. Returns a hash with +:name+, +:action+
      # (one of +:push+, +:pull+, +:skip+, +:conflict+), and +:reason+.
      #
      # @param name [String] vault name
      # @param local_set [Set<String>] vaults that exist on disk
      # @param remote_map [Hash{String => Hash}] remote vault info keyed by name
      # @param my_handle [String] current user's InventList handle
      # @param client [ApiClient] authenticated API client (used to hash remote secrets)
      # @return [Hash] +{name:, action:, reason:}+
      def classify_vault(name, local_set, remote_map, my_handle, client)
        l_exists = local_set.include?(name)
        r_info   = remote_map[name]
        r_exists = !r_info.nil?

        store      = l_exists ? Store.new(name) : nil
        ss         = SyncState.new(name)
        s_exists   = ss.exists?
        baseline   = ss.last_synced_checksum

        local_checksum = l_exists && store ? SyncState.local_checksum(store) : nil

        # The server's list `checksum` hashes the whole sync bundle, which lives
        # in a different hash space than our baseline and +local_checksum+ (both
        # SHA256 of the encrypted *secrets* bytes). Comparing across those spaces
        # never matches, so it would flag every both-exist vault as changed or
        # conflicting. To compare like-for-like we download the bundle and hash
        # its secrets bytes — but only when both sides exist, since for local-only
        # / remote-only vaults the direction is unambiguous and no compare is needed.
        if l_exists && r_exists
          begin
            remote_checksum = remote_secrets_checksum(name, client)
          rescue SyncBundle::UnpackError
            # A corrupt/unparseable remote bundle must not be conflated with an
            # empty vault (both would otherwise yield nil and could falsely
            # "adopt"). Surface it as a conflict the user can inspect.
            return { name: name, action: :conflict, reason: "remote bundle unreadable — cannot compare" }
          end
        end

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

      # Core decision matrix. Compares local/remote existence, checksums,
      # and the stored baseline to decide: push, pull, skip, or conflict.
      #
      # @return [Array(Symbol, String)] +[action, reason]+ tuple
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

        # Both exist — no baseline (first sync for this vault). Compare the
        # secrets bytes directly: if they match, the sides are already in sync
        # and we just record a baseline so future syncs can detect drift.
        unless s_exists
          if local_cs == remote_cs
            return [:adopt, "in sync — recording baseline"]
          else
            return [:conflict, "both exist, no sync baseline — run 'sync push' or 'sync pull' to resolve"]
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

      # Record a sync baseline for a vault whose local and remote secrets are
      # already byte-identical, without transferring any data. Lets the next
      # sync detect drift instead of re-comparing from scratch every time.
      #
      # @param vault_name [String] vault to baseline
      # @return [Boolean] true on success, false on any error
      def perform_adopt(vault_name)
        store = Store.new(vault_name)
        SyncState.new(vault_name).record!(store, direction: "adopt")
        $stdout.puts "  baselined #{vault_name} (already in sync)"
        true
      rescue StandardError => e
        $stderr.puts "Error baselining '#{vault_name}': #{e.message}"
        false
      end

      # SHA256 of a remote vault's encrypted secrets bytes — the same hash space
      # as +SyncState.local_checksum+ and the stored baseline, so the two can be
      # compared directly. Returns nil when the vault has no secrets (empty), is
      # missing remotely (404), or the bundle can't be parsed.
      #
      # @param vault_name [String] vault to fetch
      # @param client [ApiClient] authenticated API client
      # @return [String, nil] hex digest of the remote secrets bytes, or nil if empty/missing
      # @raise [SyncBundle::UnpackError] if the bundle exists but can't be parsed
      def remote_secrets_checksum(vault_name, client)
        blob = client.pull_vault(vault_name)
        return nil unless blob.is_a?(String) && !blob.empty?
        secrets = SyncBundle.unpack(blob)[:secrets]
        return nil if secrets.nil? || secrets.empty?
        Digest::SHA256.hexdigest(secrets)
      rescue ApiClient::ApiError => e
        raise unless e.status == 404
        nil
      end

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

      # ── Merge helpers ────────────────────────────────────────────

      # Decrypt base / local / remote and run the three-way merge. Prompts
      # for the passphrase when the vault isn't unlocked. Returns nil (after
      # printing the reason) when anything needed is missing.
      #
      # @return [SyncMerge::Result, nil]
      def build_merge(vault_name, client, prefer: nil, picks: {})
        store = Store.new(vault_name)
        unless store.exists?
          $stderr.puts "Error: Vault '#{vault_name}' does not exist locally. Use: localvault sync pull #{vault_name}"
          return nil
        end

        master_key = ensure_master_key(vault_name)
        return nil unless master_key
        @merge_master_key = master_key

        blob = client.pull_vault(vault_name)
        unless blob.is_a?(String) && !blob.empty?
          $stderr.puts "Error: Vault '#{vault_name}' has no cloud copy. Use: localvault sync push #{vault_name}"
          return nil
        end
        data = SyncBundle.unpack(blob, expected_name: vault_name)

        # Team vaults: only the owner holds the full plaintext and may push, so
        # only the owner can merge. Members take the cloud copy instead.
        handle = Config.inventlist_handle
        if data[:owner] && data[:owner] != handle
          my_slot = (data[:key_slots] || {})[handle]
          access  = my_slot.is_a?(Hash) && my_slot["scopes"].is_a?(Array) ? "scoped" : "member"
          $stderr.puts "Error: '#{vault_name}' is a team vault owned by @#{data[:owner]}; you have #{access} access."
          $stderr.puts "Only the owner can merge or push. Take the cloud copy with:"
          $stderr.puts "  localvault sync pull #{vault_name} --force"
          return nil
        end

        merge_secrets(vault_name, store, master_key, data[:secrets], prefer: prefer, picks: picks)
      rescue SyncBundle::UnpackError => e
        $stderr.puts "Error: Could not parse cloud bundle for '#{vault_name}': #{e.message}"
        nil
      rescue Crypto::DecryptionError
        $stderr.puts "Error: The cloud copy of '#{vault_name}' is encrypted with a different key (rekeyed or rotated elsewhere)."
        $stderr.puts "Merge is not possible. Take one side:"
        print_resolution_help(vault_name, nil, io: $stderr)
        nil
      rescue ApiClient::ApiError => e
        if e.status == 404
          $stderr.puts "Error: Vault '#{vault_name}' not found in cloud. Use: localvault sync push #{vault_name}"
          nil
        else
          raise
        end
      end

      # Same as +build_merge+ but never prompts and never prints — used by
      # +sync all+ to enrich conflict output when the key is already cached.
      #
      # @return [SyncMerge::Result, nil]
      def quiet_merge_preview(vault_name, client)
        master_key = SessionCache.get(vault_name)
        return nil unless master_key
        store = Store.new(vault_name)
        blob  = client.pull_vault(vault_name)
        return nil unless blob.is_a?(String) && !blob.empty?
        remote_bytes = SyncBundle.unpack(blob)[:secrets]
        merge_secrets(vault_name, store, master_key, remote_bytes)
      rescue ApiClient::ApiError, SyncBundle::UnpackError, Crypto::DecryptionError,
             SyncMerge::StructureError, JSON::ParserError
        nil
      end

      def merge_secrets(vault_name, store, master_key, remote_bytes, prefer: nil, picks: {})
        base_bytes = SyncState.new(vault_name).read_base
        base   = base_bytes ? decrypt_secrets(base_bytes, master_key) : nil
        local  = decrypt_secrets(store.read_encrypted, master_key)
        remote = decrypt_secrets(remote_bytes, master_key)
        result = SyncMerge.merge(base, local, remote, prefer: prefer, picks: picks)
        # Remember what needed a choice before picks so the CLI can validate them.
        unresolved = (prefer || !picks.empty?) ? SyncMerge.merge(base, local, remote) : result
        result.conflict_keys_before_picks = unresolved.conflicts.map(&:key)
        result
      rescue JSON::ParserError
        # Never echo the parser's excerpt: it would contain decrypted bytes.
        $stderr.puts "Error: decrypted secrets for '#{vault_name}' are not valid JSON (corrupt vault data). Merge aborted."
        nil
      rescue SyncMerge::StructureError => e
        $stderr.puts "Error: cannot merge '#{vault_name}': #{e.message}."
        $stderr.puts "Rename one of them on one side, or take a whole side:"
        print_resolution_help(vault_name, nil, io: $stderr)
        nil
      end

      def decrypt_secrets(bytes, master_key)
        return {} if bytes.nil? || bytes.empty?
        JSON.parse(Crypto.decrypt(bytes, master_key))
      end

      # Print the key-level report. Only key names and change kinds appear.
      def print_merge_report(result, indent:, io:)
        lines = []
        result.remote_changes.each { |c| lines << ["cloud",    c.kind.to_s, c.key, "will take cloud"] }
        result.local_changes.each  { |c| lines << ["local",    c.kind.to_s, c.key, "will keep local"] }
        result.same_changes.each   { |c| lines << ["both",     c.kind.to_s, c.key, "identical, keep"] }
        result.conflicts.each      { |c| lines << ["CONFLICT", conflict_label(c.kind), c.key, "needs a choice"] }

        if lines.empty?
          io.puts "#{indent}no key differences"
          return
        end

        w0 = lines.map { |l| l[0].length }.max
        w1 = lines.map { |l| l[1].length }.max
        w2 = lines.map { |l| l[2].length }.max
        lines.each do |side, kind, key, note|
          io.puts "#{indent}#{side.ljust(w0)}  #{kind.ljust(w1)}  #{key.ljust(w2)}  #{note}"
        end
      end

      def conflict_label(kind)
        case kind
        when :local_deleted  then "deleted here, changed in cloud"
        when :remote_deleted then "changed here, deleted in cloud"
        when :structure      then "secret vs group, differs per side"
        else                      "changed on both sides"
        end
      end

      # Print the exact commands that resolve this vault's state.
      def print_resolution_help(vault_name, result, io:, merge_only: false)
        if result.nil? || result.clean?
          io.puts "    Merge (keeps every change from both sides):" unless merge_only
          io.puts "      localvault sync merge #{vault_name}"
        else
          keys = result.conflicts.map(&:key)
          io.puts "    Merge, choosing a side for the conflicting key#{keys.size == 1 ? "" : "s"}:"
          io.puts "      localvault sync merge #{vault_name} --prefer local"
          io.puts "      localvault sync merge #{vault_name} --prefer remote"
          io.puts "    Or pick per key:"
          example = keys.size == 1 ? "--local #{keys.first}" : "--local #{keys.first} --remote #{keys[1]}"
          io.puts "      localvault sync merge #{vault_name} #{example}"
        end
        return if merge_only
        io.puts "    Or take one side entirely:"
        io.puts "      localvault sync push #{vault_name}          (keep local, overwrite cloud)"
        io.puts "      localvault sync pull #{vault_name} --force  (keep cloud, overwrite local)"
      end

      def prompt_passphrase(msg = "Passphrase: ")
        IO.console&.getpass(msg) || $stdin.gets&.chomp || ""
      rescue Interrupt
        $stderr.puts
        ""
      end

      def logged_in?
        return true if Config.token

        $stderr.puts "Error: Not logged in."
        $stderr.puts
        $stderr.puts "  localvault login YOUR_TOKEN"
        $stderr.puts
        $stderr.puts "Get your token at: https://inventlist.com/@YOUR_HANDLE/edit#developer"
        $stderr.puts "Or use your own server: localvault config set server URL (free InventList account: https://inventlist.com)"
        $stderr.puts "Docs: https://kuickr.co/localvault/series"
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

      # Scoped members read a per-member blob, not the vault ciphertext, so a
      # push must rebuild those blobs from the current plaintext or members
      # keep seeing the pre-push values. Needs the master key; when the vault
      # is locked the push is refused rather than publishing inconsistent
      # views. Returns nil when the push must not proceed.
      #
      # @return [Hash, nil] refreshed key slots, or nil to abort the push
      def refresh_scoped_slots(key_slots, store)
        scoped = key_slots.select { |_, s| s.is_a?(Hash) && s["scopes"].is_a?(Array) && s["pub"].is_a?(String) }
        return key_slots if scoped.empty?

        master_key = SessionCache.get(store.vault_name)
        unless master_key
          $stderr.puts "Error: '#{store.vault_name}' has scoped members whose copies must be rebuilt on push, but the vault is locked."
          $stderr.puts "Run: localvault unlock #{store.vault_name} && localvault sync push #{store.vault_name}"
          return nil
        end

        vault   = Vault.new(name: store.vault_name, master_key: master_key)
        secrets = vault.all
        scoped.each do |h, slot|
          filtered   = vault.filter(slot["scopes"], from: secrets)
          member_key = RbNaCl::Random.random_bytes(32)
          key_slots[h] = slot.merge(
            "enc_key" => KeySlot.create(member_key, slot["pub"]),
            "blob"    => Base64.strict_encode64(Crypto.encrypt(JSON.generate(filtered), member_key))
          )
        rescue ArgumentError, KeySlot::DecryptionError
          # A member whose stored public key is unusable could never decrypt
          # anything anyway; keep their old slot rather than block the owner.
          $stderr.puts "  warning: @#{h}'s public key is invalid; their scoped copy was not refreshed."
        end
        key_slots
      rescue Crypto::DecryptionError, JSON::ParserError => e
        # Fixed message: a parser error's excerpt would contain decrypted bytes.
        $stderr.puts "Error: could not read '#{store.vault_name}' to rebuild scoped members' copies (#{e.class.name.split("::").last}). Push refused."
        nil
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
