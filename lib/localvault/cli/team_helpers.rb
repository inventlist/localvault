require "json"
require "base64"
require "securerandom"

module LocalVault
  class CLI < Thor
    # Shared helpers for team-vault commands. Included by both CLI (for the
    # top-level `add`/`remove`/`verify` commands) and CLI::Team (for `init`/
    # `list`/`rotate` and the backward-compat delegators).
    module TeamHelpers
      private

      # Return the master key for +vault_name+, prompting for the passphrase
      # if the vault isn't already cached in the session. Returns +nil+ and
      # emits an error if the vault doesn't exist or the passphrase is wrong.
      #
      # This is what lets team init / rotate / add / remove "just work"
      # without a separate `localvault unlock` step. Delegates to
      # +Vault.open+ (the canonical passphrase-to-vault constructor) and
      # verifies the passphrase by calling +vault.all+ — +Vault.open+ alone
      # doesn't verify, it just derives the key.
      def ensure_master_key(vault_name)
        if (cached = SessionCache.get(vault_name))
          return cached
        end

        unless Store.new(vault_name).exists?
          $stderr.puts "Error: Vault '#{vault_name}' does not exist. Run: localvault init #{vault_name}"
          return nil
        end

        passphrase = prompt_passphrase("Passphrase for '#{vault_name}': ")
        return nil if passphrase.nil? || passphrase.empty?

        vault = Vault.open(name: vault_name, passphrase: passphrase)
        vault.all # raises Crypto::DecryptionError on wrong passphrase
        SessionCache.set(vault_name, vault.master_key)
        vault.master_key
      rescue Crypto::DecryptionError
        $stderr.puts "Error: Wrong passphrase for vault '#{vault_name}'."
        nil
      end

      def load_key_slots(client, vault_name)
        data = load_team_data(client, vault_name)
        data ? data[:key_slots] : nil
      end

      # Load full bundle data including owner. Returns nil if no remote or
      # not a team vault.
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
          master_key = ensure_master_key(vault_name)
          return unless master_key

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
