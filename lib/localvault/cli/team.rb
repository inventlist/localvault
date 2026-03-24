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
      def remove(handle)
        unless Config.token
          $stderr.puts "Error: Not connected. Run: localvault connect --token TOKEN --handle HANDLE"
          return
        end

        handle = handle.delete_prefix("@")
        vault_name = options[:vault] || Config.default_vault
        client = ApiClient.new(token: Config.token)

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
    end
  end
end
