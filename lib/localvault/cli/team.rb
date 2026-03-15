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
