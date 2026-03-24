require "thor"

module LocalVault
  class CLI
    class Team < Thor
      desc "list [VAULT]", "Show who has access to a vault"
      method_option :vault, type: :string, aliases: "-v"
      def list(vault_name = nil)
        unless Config.token
          $stderr.puts "Error: Not connected. Run: localvault connect --token TOKEN --handle HANDLE"
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

      desc "add HANDLE", "Add a teammate to a synced vault via key slot"
      method_option :vault, type: :string, aliases: "-v"
      def add(handle)
        unless Config.token
          $stderr.puts "Error: Not logged in. Run: localvault login TOKEN"
          return
        end

        unless Identity.exists?
          $stderr.puts "Error: No keypair found. Run: localvault keygen"
          return
        end

        handle = handle.delete_prefix("@")
        vault_name = options[:vault] || Config.default_vault

        # Need master key from session
        master_key = SessionCache.get(vault_name)
        unless master_key
          $stderr.puts "Error: Vault '#{vault_name}' is not unlocked. Run: localvault show -v #{vault_name}"
          return
        end

        # Fetch recipient's public key
        client = ApiClient.new(token: Config.token)
        result = client.get_public_key(handle)
        pub_key = result["public_key"]

        unless pub_key && !pub_key.empty?
          $stderr.puts "Error: @#{handle} has no public key published."
          return
        end

        # Load existing key slots from remote
        existing_blob = client.pull_vault(vault_name) rescue nil
        key_slots = if existing_blob.is_a?(String) && !existing_blob.empty?
                      data = SyncBundle.unpack(existing_blob)
                      data[:key_slots].is_a?(Hash) ? data[:key_slots] : {}
                    else
                      {}
                    end

        # Create key slot for recipient
        enc_key = KeySlot.create(master_key, pub_key)
        key_slots[handle] = { "pub" => pub_key, "enc_key" => enc_key }

        # Ensure owner slot exists too
        owner_handle = Config.inventlist_handle
        unless key_slots.key?(owner_handle)
          owner_pub = Identity.public_key
          key_slots[owner_handle] = { "pub" => owner_pub, "enc_key" => KeySlot.create(master_key, owner_pub) }
        end

        # Pack and push
        store = Store.new(vault_name)
        blob = SyncBundle.pack(store, key_slots: key_slots)
        client.push_vault(vault_name, blob)

        $stdout.puts "Added @#{handle} to vault '#{vault_name}'."
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
      def remove(handle)
        unless Config.token
          $stderr.puts "Error: Not connected. Run: localvault connect --token TOKEN --handle HANDLE"
          return
        end

        handle = handle.delete_prefix("@")
        vault_name = options[:vault] || Config.default_vault
        client = ApiClient.new(token: Config.token)

        # Try sync-based key slot removal first
        key_slots = load_key_slots(client, vault_name)
        if key_slots && !key_slots.empty?
          remove_key_slot(handle, vault_name, key_slots, client, rotate: options[:rotate])
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

      private

      def load_key_slots(client, vault_name)
        return nil unless client.respond_to?(:pull_vault)
        blob = client.pull_vault(vault_name)
        return nil unless blob.is_a?(String) && !blob.empty?
        data = SyncBundle.unpack(blob)
        slots = data[:key_slots]
        slots.is_a?(Hash) ? slots : nil
      rescue ApiClient::ApiError, SyncBundle::UnpackError, NoMethodError
        nil
      end

      def remove_key_slot(handle, vault_name, key_slots, client, rotate: false)
        unless key_slots.key?(handle)
          $stderr.puts "Error: @#{handle} has no slot in vault '#{vault_name}'."
          return
        end

        valid_slots = key_slots.select { |_, v| v.is_a?(Hash) && v["pub"].is_a?(String) }
        if handle == Config.inventlist_handle && valid_slots.size <= 1
          $stderr.puts "Error: Cannot remove yourself — you are the only member."
          return
        end

        key_slots.delete(handle)
        store = Store.new(vault_name)

        if rotate
          master_key = SessionCache.get(vault_name)
          unless master_key
            $stderr.puts "Error: Vault '#{vault_name}' is not unlocked. Run: localvault show -v #{vault_name}"
            return
          end

          # Decrypt current secrets, generate new master key, re-encrypt
          vault = Vault.new(name: vault_name, master_key: master_key)
          secrets = vault.all

          new_salt = Crypto.generate_salt
          new_master_key = Crypto.derive_master_key(SecureRandom.hex(32), new_salt)

          # Re-encrypt secrets with new master key
          new_json = JSON.generate(secrets)
          new_encrypted = Crypto.encrypt(new_json, new_master_key)
          store.write_encrypted(new_encrypted)
          store.create_meta!(salt: new_salt)

          # Re-create key slots for remaining members with new master key
          new_slots = {}
          key_slots.each do |h, slot|
            next unless slot.is_a?(Hash) && slot["pub"].is_a?(String)
            new_slots[h] = { "pub" => slot["pub"], "enc_key" => KeySlot.create(new_master_key, slot["pub"]) }
          end

          blob = SyncBundle.pack(store, key_slots: new_slots)
          client.push_vault(vault_name, blob)

          # Cache the new master key
          SessionCache.set(vault_name, new_master_key)

          $stdout.puts "Removed @#{handle} from vault '#{vault_name}'."
          $stdout.puts "Vault re-encrypted with new master key (rotated)."
        else
          blob = SyncBundle.pack(store, key_slots: key_slots)
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
