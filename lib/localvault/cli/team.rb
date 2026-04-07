require "thor"
require "securerandom"

module LocalVault
  class CLI
    class Team < Thor
      desc "init", "Initialize a vault as a team vault (sets you as owner)"
      method_option :vault, type: :string, aliases: "-v"
      # Initialize a vault as a team vault with you as the owner.
      #
      # This is the explicit transition from personal sync to team-shared sync.
      # Creates the owner's key slot and bumps the bundle to v3.
      def init
        unless Config.token
          $stderr.puts "Error: Not logged in."
          $stderr.puts "\n  localvault login YOUR_TOKEN\n"
          $stderr.puts "Get your token at: https://inventlist.com/@YOUR_HANDLE/edit#developer"
          return
        end

        unless Identity.exists?
          $stderr.puts "Error: No keypair found. Run: localvault keygen"
          return
        end

        vault_name = options[:vault] || Config.default_vault
        handle = Config.inventlist_handle

        master_key = SessionCache.get(vault_name)
        unless master_key
          $stderr.puts "Error: Vault '#{vault_name}' is not unlocked. Run: localvault show -v #{vault_name}"
          return
        end

        client = ApiClient.new(token: Config.token)
        begin
          blob = client.pull_vault(vault_name)
          unless blob.is_a?(String) && !blob.empty?
            $stderr.puts "Error: Vault '#{vault_name}' has not been synced. Run: localvault sync push -v #{vault_name}"
            return
          end
          data = SyncBundle.unpack(blob)
          if data[:owner]
            $stderr.puts "Error: Vault '#{vault_name}' is already a team vault. Owner: @#{data[:owner]}"
            return
          end
        rescue ApiClient::ApiError => e
          if e.status == 404
            $stderr.puts "Error: Vault '#{vault_name}' has not been synced. Run: localvault sync push -v #{vault_name}"
          else
            $stderr.puts "Error: #{e.message}"
          end
          return
        end

        # Create owner key slot
        pub_b64 = Identity.public_key
        enc_key = KeySlot.create(master_key, pub_b64)
        key_slots = {
          handle => { "pub" => pub_b64, "enc_key" => enc_key, "scopes" => nil, "blob" => nil }
        }

        # Preserve existing key slots from v2 (upgrade path)
        data[:key_slots].each do |h, slot|
          next if h == handle
          next unless slot.is_a?(Hash) && slot["pub"].is_a?(String)
          key_slots[h] = slot.merge("scopes" => nil, "blob" => nil)
        end

        store = Store.new(vault_name)
        new_blob = SyncBundle.pack_v3(store, owner: handle, key_slots: key_slots)
        client.push_vault(vault_name, new_blob)

        $stdout.puts "Vault '#{vault_name}' is now a team vault."
        $stdout.puts "Owner: @#{handle}"
        $stdout.puts "\nNext: localvault team add @handle -v #{vault_name}"
      rescue SyncBundle::UnpackError => e
        $stderr.puts "Error: #{e.message}"
      end

      desc "list [VAULT]", "Show who has access to a vault"
      method_option :vault, type: :string, aliases: "-v"
      # List all users who have access to a vault.
      #
      # Checks sync-based key slots first; falls back to direct shares if no
      # key slots exist. Displays member handles (key slots) or a share table
      # with ID, recipient, status, and date.
      def list(vault_name = nil)
        unless Config.token
          $stderr.puts "Error: Not logged in."
          $stderr.puts
          $stderr.puts "  localvault login YOUR_TOKEN"
          $stderr.puts
          $stderr.puts "Get your token at: https://inventlist.com/@YOUR_HANDLE/edit#developer"
          $stderr.puts "New to InventList? Sign up free at https://inventlist.com"
          $stderr.puts "Docs: https://inventlist.com/sites/localvault/series/localvault"
          return
        end

        vault_name ||= options[:vault] || Config.default_vault
        client = ApiClient.new(token: Config.token)

        # Try sync-based key slots first
        key_slots = load_key_slots(client, vault_name)
        if key_slots && !key_slots.empty?
          list_key_slots(vault_name, key_slots)
          return
        end

        # Fall back to direct shares
        result = client.sent_shares(vault_name: vault_name)
        shares = (result["shares"] || []).reject { |s| s["status"] == "revoked" }

        if shares.empty?
          $stdout.puts "No active shares for vault '#{vault_name}'."
          return
        end

        $stdout.puts "Vault: #{vault_name} — #{shares.size} share(s)"
        $stdout.puts
        $stdout.printf("%-8s  %-20s  %-10s  %-12s\n", "ID", "Recipient", "Status", "Shared")
        $stdout.puts("-" * 56)
        shares.each do |s|
          date = s["created_at"]&.slice(0, 10) || ""
          $stdout.printf("%-8s  %-20s  %-10s  %-12s\n",
            s["id"].to_s, "@#{s["recipient_handle"]}", s["status"], date)
        end
      rescue ApiClient::ApiError => e
        $stderr.puts "Error: #{e.message}"
      end

      desc "verify HANDLE", "Check if a user exists and has a public key for sharing"
      # Verify a user's handle and public key status before adding them.
      #
      # Checks InventList for the handle and whether they have a published
      # X25519 public key. Does not modify anything.
      def verify(handle)
        unless Config.token
          $stderr.puts "Error: Not logged in."
          $stderr.puts "\n  localvault login YOUR_TOKEN\n"
          $stderr.puts "Get your token at: https://inventlist.com/@YOUR_HANDLE/edit#developer"
          return
        end

        handle = handle.delete_prefix("@")
        client = ApiClient.new(token: Config.token)
        result = client.get_public_key(handle)
        pub_key = result["public_key"]

        if pub_key && !pub_key.empty?
          fingerprint = pub_key.length > 12 ? "#{pub_key[0..7]}...#{pub_key[-4..]}" : pub_key
          $stdout.puts "@#{handle} — public key published"
          $stdout.puts "  Fingerprint: #{fingerprint}"
          $stdout.puts "  Ready for: localvault team add @#{handle} -v VAULT"
        else
          $stderr.puts "@#{handle} exists but has no public key published."
          $stderr.puts "They need to run: localvault login TOKEN"
        end
      rescue ApiClient::ApiError => e
        if e.status == 404
          $stderr.puts "Error: @#{handle} not found on InventList."
        else
          $stderr.puts "Error: #{e.message}"
        end
      end

      desc "add HANDLE", "Add a teammate to a synced vault via key slot"
      method_option :vault, type: :string, aliases: "-v"
      method_option :scope, type: :array, desc: "Groups or keys to share (omit for full access)"
      # Grant a user access to a synced vault by creating a key slot.
      #
      # With --scope, creates a per-member encrypted blob containing only the
      # specified keys. Without --scope, grants full vault access.
      # Requires the vault to be a team vault (run team init first).
      def add(handle)
        unless Config.token
          $stderr.puts "Error: Not logged in."
          $stderr.puts "\n  localvault login YOUR_TOKEN\n"
          $stderr.puts "Get your token at: https://inventlist.com/@YOUR_HANDLE/edit#developer"
          return
        end

        unless Identity.exists?
          $stderr.puts "Error: No keypair found. Run: localvault keygen"
          return
        end

        target = handle
        vault_name = options[:vault] || Config.default_vault
        scope_list = options[:scope]

        master_key = SessionCache.get(vault_name)
        unless master_key
          $stderr.puts "Error: Vault '#{vault_name}' is not unlocked. Run: localvault show -v #{vault_name}"
          return
        end

        client = ApiClient.new(token: Config.token)

        # Load existing bundle — must be a team vault (v3)
        existing_blob = client.pull_vault(vault_name) rescue nil
        unless existing_blob.is_a?(String) && !existing_blob.empty?
          $stderr.puts "Error: Vault '#{vault_name}' is not a team vault. Run: localvault team init -v #{vault_name}"
          return
        end

        data = SyncBundle.unpack(existing_blob)
        unless data[:owner]
          $stderr.puts "Error: Vault '#{vault_name}' is not a team vault. Run: localvault team init -v #{vault_name}"
          return
        end

        unless data[:owner] == Config.inventlist_handle
          $stderr.puts "Error: Only the vault owner (@#{data[:owner]}) can manage team access."
          return
        end

        key_slots = data[:key_slots].is_a?(Hash) ? data[:key_slots] : {}

        # Resolve recipients — single @handle, team:HANDLE, or crew:SLUG
        recipients = resolve_add_recipients(client, target)
        if recipients.empty?
          $stderr.puts "Error: No recipients with public keys found for '#{target}'"
          return
        end

        added = 0
        recipients.each do |member_handle, pub_key|
          next if member_handle == Config.inventlist_handle  # skip self

          # Skip if already has full access
          if key_slots.key?(member_handle) && key_slots[member_handle].is_a?(Hash) && key_slots[member_handle]["scopes"].nil?
            $stdout.puts "@#{member_handle} already has full vault access." if scope_list
            next
          end

          if scope_list
            existing_scopes = key_slots.dig(member_handle, "scopes") || []
            merged_scopes = (existing_scopes + scope_list).uniq

            vault = Vault.new(name: vault_name, master_key: master_key)
            filtered = vault.filter(merged_scopes)

            member_key = RbNaCl::Random.random_bytes(32)
            encrypted_blob = Crypto.encrypt(JSON.generate(filtered), member_key)

            begin
              enc_key = KeySlot.create(member_key, pub_key)
            rescue ArgumentError, KeySlot::DecryptionError => e
              $stderr.puts "Error: @#{member_handle}'s public key is invalid: #{e.message}"
              next
            end

            key_slots[member_handle] = {
              "pub" => pub_key, "enc_key" => enc_key,
              "scopes" => merged_scopes,
              "blob" => Base64.strict_encode64(encrypted_blob)
            }
          else
            begin
              enc_key = KeySlot.create(master_key, pub_key)
            rescue ArgumentError, KeySlot::DecryptionError => e
              $stderr.puts "Error: @#{member_handle}'s public key is invalid: #{e.message}"
              next
            end

            key_slots[member_handle] = { "pub" => pub_key, "enc_key" => enc_key, "scopes" => nil, "blob" => nil }
          end
          added += 1
        end

        if added == 0
          $stdout.puts "No new members added."
          return
        end

        store = Store.new(vault_name)
        blob = SyncBundle.pack_v3(store, owner: data[:owner], key_slots: key_slots)
        client.push_vault(vault_name, blob)

        if recipients.size == 1
          h = recipients.first[0]
          if scope_list
            $stdout.puts "Added @#{h} to vault '#{vault_name}' (scopes: #{key_slots[h]["scopes"].join(", ")})."
          else
            $stdout.puts "Added @#{h} to vault '#{vault_name}'."
          end
        else
          $stdout.puts "Added #{added} member(s) to vault '#{vault_name}'."
        end
      rescue ApiClient::ApiError => e
        if e.status == 404
          $stderr.puts "Error: @#{handle} not found or has no public key."
        else
          $stderr.puts "Error: #{e.message}"
        end
      rescue SyncBundle::UnpackError => e
        $stderr.puts "Error: #{e.message}"
      end

      desc "remove HANDLE", "Remove a person's access to a vault"
      method_option :vault, type: :string, aliases: "-v"
      method_option :rotate, type: :boolean, default: false, desc: "Re-encrypt vault with new master key (full revocation)"
      method_option :scope, type: :array, desc: "Remove specific scopes only (keeps other scopes)"
      # Remove a user's access to a vault.
      #
      # Removes the user's key slot and pushes the updated bundle. With +--rotate+,
      # re-encrypts the vault with a new master key and recreates all remaining
      # key slots for full cryptographic revocation. Falls back to revoking a
      # direct share if no key slots exist.
      def remove(handle)
        unless Config.token
          $stderr.puts "Error: Not logged in."
          $stderr.puts
          $stderr.puts "  localvault login YOUR_TOKEN"
          $stderr.puts
          $stderr.puts "Get your token at: https://inventlist.com/@YOUR_HANDLE/edit#developer"
          $stderr.puts "New to InventList? Sign up free at https://inventlist.com"
          $stderr.puts "Docs: https://inventlist.com/sites/localvault/series/localvault"
          return
        end

        handle = handle.delete_prefix("@")
        vault_name = options[:vault] || Config.default_vault
        client = ApiClient.new(token: Config.token)

        # Try sync-based key slot removal first
        team_data = load_team_data(client, vault_name)
        if team_data && team_data[:key_slots] && !team_data[:key_slots].empty?
          # Must be a v3 team vault with owner
          unless team_data[:owner]
            $stderr.puts "Error: Vault '#{vault_name}' is not a team vault. Run: localvault team init -v #{vault_name}"
            return
          end
          unless team_data[:owner] == Config.inventlist_handle
            $stderr.puts "Error: Only the vault owner (@#{team_data[:owner]}) can manage team access."
            return
          end
          remove_key_slot(handle, vault_name, team_data[:key_slots], client,
                          rotate: options[:rotate], remove_scopes: options[:scope],
                          owner: team_data[:owner])
          return
        end

        # Fall back to direct share revocation
        result = client.sent_shares(vault_name: vault_name)
        share = (result["shares"] || []).find do |s|
          s["recipient_handle"] == handle && s["status"] != "revoked"
        end

        unless share
          $stderr.puts "Error: No active share found for @#{handle}."
          return
        end

        client.revoke_share(share["id"])
        $stdout.puts "Removed @#{handle} from vault '#{vault_name}'."
      rescue ApiClient::ApiError => e
        $stderr.puts "Error: #{e.message}"
      end

      desc "rotate", "Re-encrypt a team vault with a new master key (no member changes)"
      method_option :vault, type: :string, aliases: "-v"
      # Re-key a team vault without adding or removing members.
      #
      # Prompts for a new passphrase, re-encrypts all secrets, and rebuilds
      # all key slots. Useful for periodic key rotation.
      def rotate
        unless Config.token
          $stderr.puts "Error: Not logged in."
          return
        end

        vault_name = options[:vault] || Config.default_vault
        client = ApiClient.new(token: Config.token)

        team_data = load_team_data(client, vault_name)
        unless team_data && team_data[:key_slots] && !team_data[:key_slots].empty?
          $stderr.puts "Error: Vault '#{vault_name}' has no team access. Nothing to rotate."
          return
        end

        unless team_data[:owner]
          $stderr.puts "Error: Vault '#{vault_name}' is not a team vault. Run: localvault team init -v #{vault_name}"
          return
        end

        unless team_data[:owner] == Config.inventlist_handle
          $stderr.puts "Error: Only the vault owner (@#{team_data[:owner]}) can rotate keys."
          return
        end

        key_slots = team_data[:key_slots]
        vault_owner = team_data[:owner]

        master_key = SessionCache.get(vault_name)
        unless master_key
          $stderr.puts "Error: Vault '#{vault_name}' is not unlocked."
          return
        end

        passphrase = prompt_passphrase("New passphrase for vault '#{vault_name}': ")
        if passphrase.nil? || passphrase.empty?
          $stderr.puts "Error: Passphrase cannot be empty."
          return
        end

        vault = Vault.new(name: vault_name, master_key: master_key)
        secrets = vault.all
        store = Store.new(vault_name)

        new_salt = Crypto.generate_salt
        new_master_key = Crypto.derive_master_key(passphrase, new_salt)

        store.write_encrypted(Crypto.encrypt(JSON.generate(secrets), new_master_key))
        store.create_meta!(salt: new_salt)

        new_slots = {}
        key_slots.each do |h, slot|
          next unless slot.is_a?(Hash) && slot["pub"].is_a?(String)
          if slot["scopes"].is_a?(Array)
            filtered = vault.filter(slot["scopes"])
            member_key = RbNaCl::Random.random_bytes(32)
            encrypted_blob = Crypto.encrypt(JSON.generate(filtered), member_key)
            new_slots[h] = { "pub" => slot["pub"], "enc_key" => KeySlot.create(member_key, slot["pub"]), "scopes" => slot["scopes"], "blob" => Base64.strict_encode64(encrypted_blob) }
          else
            new_slots[h] = { "pub" => slot["pub"], "enc_key" => KeySlot.create(new_master_key, slot["pub"]), "scopes" => nil, "blob" => nil }
          end
        end

        blob = SyncBundle.pack_v3(store, owner: vault_owner, key_slots: new_slots)
        client.push_vault(vault_name, blob)
        SessionCache.set(vault_name, new_master_key)

        $stdout.puts "Vault '#{vault_name}' re-encrypted with new master key."
        $stdout.puts "#{new_slots.size} member(s) updated."
      rescue ApiClient::ApiError => e
        $stderr.puts "Error: #{e.message}"
      end

      private

      def prompt_passphrase(msg = "Passphrase: ")
        IO.console&.getpass(msg) || $stdin.gets&.chomp || ""
      rescue Interrupt
        $stderr.puts
        ""
      end

      def load_key_slots(client, vault_name)
        data = load_team_data(client, vault_name)
        data ? data[:key_slots] : nil
      end

      # Load full bundle data including owner. Returns nil if no remote or not a team vault.
      def load_team_data(client, vault_name)
        return nil unless client.respond_to?(:pull_vault)
        blob = client.pull_vault(vault_name)
        return nil unless blob.is_a?(String) && !blob.empty?
        data = SyncBundle.unpack(blob)
        return nil unless data[:key_slots].is_a?(Hash)
        data
      rescue ApiClient::ApiError, SyncBundle::UnpackError, NoMethodError
        nil
      end

      # Resolve target into list of [handle, public_key] pairs.
      # Supports @handle, team:HANDLE, and crew:SLUG.
      def resolve_add_recipients(client, target)
        if target.start_with?("team:")
          team_handle = target.delete_prefix("team:")
          result = client.team_public_keys(team_handle)
          (result["members"] || [])
            .select { |m| m["handle"] && m["public_key"] && !m["public_key"].empty? }
            .map { |m| [m["handle"], m["public_key"]] }
        elsif target.start_with?("crew:")
          slug = target.delete_prefix("crew:")
          result = client.crew_public_keys(slug)
          (result["members"] || [])
            .select { |m| m["handle"] && m["public_key"] && !m["public_key"].empty? }
            .map { |m| [m["handle"], m["public_key"]] }
        else
          handle = target.delete_prefix("@")
          result = client.get_public_key(handle)
          pub_key = result["public_key"]
          return [] unless pub_key && !pub_key.empty?
          [[handle, pub_key]]
        end
      rescue ApiClient::ApiError => e
        $stderr.puts "Warning: #{e.message}"
        []
      end

      # Remove a member's key slot, optionally rotating the vault master key.
      # Supports partial scope removal via remove_scopes.
      def remove_key_slot(handle, vault_name, key_slots, client, rotate: false, remove_scopes: nil, owner: nil)
        owner ||= Config.inventlist_handle
        unless key_slots.key?(handle)
          $stderr.puts "Error: @#{handle} has no slot in vault '#{vault_name}'."
          return
        end

        store = Store.new(vault_name)

        # Partial scope removal
        if remove_scopes && key_slots[handle].is_a?(Hash) && key_slots[handle]["scopes"].is_a?(Array)
          remaining = key_slots[handle]["scopes"] - remove_scopes
          if remaining.empty?
            # Last scope removed — remove member entirely
            key_slots.delete(handle)
            $stdout.puts "Removed @#{handle} from vault '#{vault_name}' (last scope removed)."
          else
            # Rebuild blob with remaining scopes
            master_key = SessionCache.get(vault_name)
            if master_key
              vault = Vault.new(name: vault_name, master_key: master_key)
              filtered = vault.filter(remaining)
              member_key = RbNaCl::Random.random_bytes(32)
              encrypted_blob = Crypto.encrypt(JSON.generate(filtered), member_key)
              enc_key = KeySlot.create(member_key, key_slots[handle]["pub"])
              key_slots[handle] = {
                "pub" => key_slots[handle]["pub"],
                "enc_key" => enc_key,
                "scopes" => remaining,
                "blob" => Base64.strict_encode64(encrypted_blob)
              }
            end
            $stdout.puts "Removed scope(s) #{remove_scopes.join(", ")} from @#{handle}. Remaining: #{remaining.join(", ")}"
          end

          blob = SyncBundle.pack_v3(store, owner: owner, key_slots: key_slots)
          client.push_vault(vault_name, blob)
          return
        end

        # Full member removal
        valid_slots = key_slots.select { |_, v| v.is_a?(Hash) && v["pub"].is_a?(String) }
        if handle == Config.inventlist_handle && valid_slots.size <= 1
          $stderr.puts "Error: Cannot remove yourself — you are the only member."
          return
        end

        key_slots.delete(handle)

        if rotate
          master_key = SessionCache.get(vault_name)
          unless master_key
            $stderr.puts "Error: Vault '#{vault_name}' is not unlocked. Run: localvault show -v #{vault_name}"
            return
          end

          # Prompt for new passphrase
          passphrase = prompt_passphrase("New passphrase for vault '#{vault_name}': ")
          if passphrase.nil? || passphrase.empty?
            $stderr.puts "Error: Passphrase cannot be empty."
            return
          end

          vault = Vault.new(name: vault_name, master_key: master_key)
          secrets = vault.all

          new_salt = Crypto.generate_salt
          new_master_key = Crypto.derive_master_key(passphrase, new_salt)

          new_json = JSON.generate(secrets)
          new_encrypted = Crypto.encrypt(new_json, new_master_key)
          store.write_encrypted(new_encrypted)
          store.create_meta!(salt: new_salt)

          new_slots = {}
          key_slots.each do |h, slot|
            next unless slot.is_a?(Hash) && slot["pub"].is_a?(String)
            if slot["scopes"].is_a?(Array)
              # Scoped member — rebuild per-member blob
              filtered = vault.filter(slot["scopes"])
              member_key = RbNaCl::Random.random_bytes(32)
              encrypted_blob = Crypto.encrypt(JSON.generate(filtered), member_key)
              new_slots[h] = {
                "pub" => slot["pub"],
                "enc_key" => KeySlot.create(member_key, slot["pub"]),
                "scopes" => slot["scopes"],
                "blob" => Base64.strict_encode64(encrypted_blob)
              }
            else
              # Full-access member
              new_slots[h] = { "pub" => slot["pub"], "enc_key" => KeySlot.create(new_master_key, slot["pub"]), "scopes" => nil, "blob" => nil }
            end
          end

          blob = SyncBundle.pack_v3(store, owner: owner, key_slots: new_slots)
          client.push_vault(vault_name, blob)

          if new_slots.key?(Config.inventlist_handle)
            SessionCache.set(vault_name, new_master_key)
          else
            SessionCache.clear(vault_name)
          end

          $stdout.puts "Removed @#{handle} from vault '#{vault_name}'."
          $stdout.puts "Vault re-encrypted with new master key (rotated)."
        else
          blob = SyncBundle.pack_v3(store, owner: owner, key_slots: key_slots)
          client.push_vault(vault_name, blob)
          $stdout.puts "Removed @#{handle} from vault '#{vault_name}'."
        end
      end

      def list_key_slots(vault_name, key_slots)
        my_handle = Config.inventlist_handle
        valid = key_slots.select { |_, v| v.is_a?(Hash) && v["pub"].is_a?(String) }

        if valid.empty?
          $stdout.puts "No key slots for vault '#{vault_name}'."
          return
        end

        $stdout.puts "Vault: #{vault_name} — #{valid.size} member(s)"
        $stdout.puts
        valid.sort.each do |handle, slot|
          marker = handle == my_handle ? " (you)" : ""
          $stdout.puts "  @#{handle}#{marker}"
        end
      end
    end
  end
end
