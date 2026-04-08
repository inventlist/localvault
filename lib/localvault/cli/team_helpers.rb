require "json"
require "base64"
require "securerandom"
require "yaml"
require "time"

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

      # Build everything a rotate needs in memory, without touching local disk.
      #
      # Returns a hash of in-memory bytes and derived state that the caller
      # can either push to the remote before committing locally
      # (+pack+ + +client.push_vault+), or discard without side effects if
      # the user interrupts or the push fails.
      #
      # This is the centerpiece of finding #5 (transactional rotate): by
      # producing everything in memory first, the caller can push + commit
      # atomically — no half-rotated local state if the network dies.
      #
      # It also fixes finding #6 (scoped-sharing inefficiency): the plaintext
      # secrets are decrypted exactly once and passed into +Vault#filter+
      # for each scoped member instead of being re-decrypted per member.
      #
      # @param secrets [Hash] plaintext secrets hash (from +vault.all+)
      # @param key_slots [Hash] existing key slots from the remote bundle
      # @param new_master_key [String] the rotation target master key
      # @param new_salt [String] raw salt bytes for the new meta.yml
      # @param owner [String] the owner's InventList handle
      # @param vault_name [String]
      # @param vault [Vault] a Vault instance (used only for its +filter+ helper)
      # @return [Hash] +{ new_slots:, new_secrets_bytes:, new_meta_bytes:, bundle_json: }+
      def build_rotated_bundle(secrets:, key_slots:, new_master_key:, new_salt:,
                               owner:, vault_name:, vault:)
        new_secrets_bytes = Crypto.encrypt(JSON.generate(secrets), new_master_key)
        new_meta_bytes    = YAML.dump(
          "name"       => vault_name,
          "created_at" => Store.new(vault_name).meta&.dig("created_at") || Time.now.utc.iso8601,
          "version"    => 1,
          "salt"       => Base64.strict_encode64(new_salt)
        )

        new_slots = {}
        key_slots.each do |h, slot|
          next unless slot.is_a?(Hash) && slot["pub"].is_a?(String)
          if slot["scopes"].is_a?(Array)
            # Scoped member — rebuild per-member blob. Pass the already-loaded
            # plaintext `secrets` into filter so we don't re-decrypt the whole
            # vault for every scoped member.
            filtered = vault.filter(slot["scopes"], from: secrets)
            member_key = RbNaCl::Random.random_bytes(32)
            encrypted_blob = Crypto.encrypt(JSON.generate(filtered), member_key)
            new_slots[h] = {
              "pub" => slot["pub"],
              "enc_key" => KeySlot.create(member_key, slot["pub"]),
              "scopes" => slot["scopes"],
              "blob" => Base64.strict_encode64(encrypted_blob)
            }
          else
            # Full-access member — enc_key wraps the new master key.
            new_slots[h] = {
              "pub" => slot["pub"],
              "enc_key" => KeySlot.create(new_master_key, slot["pub"]),
              "scopes" => nil,
              "blob" => nil
            }
          end
        end

        bundle_json = SyncBundle.pack_v3_bytes(
          meta_bytes:    new_meta_bytes,
          secrets_bytes: new_secrets_bytes,
          owner:         owner,
          key_slots:     new_slots
        )

        {
          new_slots:         new_slots,
          new_secrets_bytes: new_secrets_bytes,
          new_meta_bytes:    new_meta_bytes,
          bundle_json:       bundle_json
        }
      end

      # Commit a rotated bundle to local disk AFTER the remote push has
      # succeeded. Writes the new ciphertext + meta.yml atomically.
      def commit_rotated_bundle_locally(vault_name, new_secrets_bytes, new_meta_bytes)
        store = Store.new(vault_name)
        store.write_encrypted(new_secrets_bytes)
        File.write(store.meta_path, new_meta_bytes)
        File.chmod(0o600, store.meta_path)
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
        if remove_scopes
          slot = key_slots[handle]
          slot_scopes = slot.is_a?(Hash) ? slot["scopes"] : nil

          unless slot_scopes.is_a?(Array)
            # Member has full access (nil scopes) — --scope is a user error.
            # Falling through to full removal here used to silently delete
            # the member, which is surprising and destructive.
            $stderr.puts "Error: @#{handle} has full access to '#{vault_name}', not scoped. " \
                         "Use `localvault remove @#{handle}` without --scope to revoke access."
            return
          end

          remaining = slot_scopes - remove_scopes
          if remaining.empty?
            # Last scope removed — remove member entirely
            key_slots.delete(handle)
            $stdout.puts "Removed @#{handle} from vault '#{vault_name}' (last scope removed)."
          else
            # Rebuild blob with remaining scopes. Requires the vault to be
            # unlocked — previously this would silently no-op (print success,
            # push unchanged slot) when the session cache was empty.
            master_key = ensure_master_key(vault_name)
            return unless master_key

            vault = Vault.new(name: vault_name, master_key: master_key)
            filtered = vault.filter(remaining)
            member_key = RbNaCl::Random.random_bytes(32)
            encrypted_blob = Crypto.encrypt(JSON.generate(filtered), member_key)
            enc_key = KeySlot.create(member_key, slot["pub"])
            key_slots[handle] = {
              "pub" => slot["pub"],
              "enc_key" => enc_key,
              "scopes" => remaining,
              "blob" => Base64.strict_encode64(encrypted_blob)
            }
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

          # Decrypt with the CURRENT master key. After this point we must
          # not touch the store until the push has succeeded — see
          # finding #5 (transactional rotate).
          vault = Vault.new(name: vault_name, master_key: master_key)
          secrets = vault.all

          new_salt = Crypto.generate_salt
          new_master_key = Crypto.derive_master_key(passphrase, new_salt)

          bundle = build_rotated_bundle(
            secrets:        secrets,
            key_slots:      key_slots, # already has `handle` removed above
            new_master_key: new_master_key,
            new_salt:       new_salt,
            owner:          owner,
            vault_name:     vault_name,
            vault:          vault
          )

          # Push first. If this raises, nothing on local disk has changed.
          client.push_vault(vault_name, bundle[:bundle_json])

          # Push succeeded — commit locally.
          commit_rotated_bundle_locally(vault_name, bundle[:new_secrets_bytes], bundle[:new_meta_bytes])

          if bundle[:new_slots].key?(Config.inventlist_handle)
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
