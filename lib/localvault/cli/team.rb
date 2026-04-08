require "thor"
require "securerandom"

module LocalVault
  class CLI
    class Team < Thor
      include LocalVault::CLI::TeamHelpers

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
        $stdout.puts "\nNext: localvault add @handle -v #{vault_name}"
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

      # ── Backward-compat delegates ─────────────────────────────────
      # `add`, `remove`, and `verify` moved to the top-level CLI in v1.3.0
      # (the leading @ in the handle already signals a person operation).
      # The `team add/remove/verify` aliases keep existing scripts and muscle
      # memory working — they forward to the top-level commands with the same
      # options.

      desc "add HANDLE", "(alias) Add a teammate — prefer `localvault add @HANDLE`"
      method_option :vault, type: :string, aliases: "-v"
      method_option :scope, type: :array, desc: "Groups or keys to share (omit for full access)"
      def add(handle)
        LocalVault::CLI.new([], options, {}).add(handle)
      end

      desc "remove HANDLE", "(alias) Remove a teammate — prefer `localvault remove @HANDLE`"
      method_option :vault, type: :string, aliases: "-v"
      method_option :rotate, type: :boolean, default: false, desc: "Re-encrypt vault with new master key (full revocation)"
      method_option :scope, type: :array, desc: "Remove specific scopes only (keeps other scopes)"
      def remove(handle)
        LocalVault::CLI.new([], options, {}).remove(handle)
      end

      desc "verify HANDLE", "(alias) Verify a public key — prefer `localvault verify @HANDLE`"
      def verify(handle)
        LocalVault::CLI.new([], options, {}).verify(handle)
      end

      private

      def prompt_passphrase(msg = "Passphrase: ")
        IO.console&.getpass(msg) || $stdin.gets&.chomp || ""
      rescue Interrupt
        $stderr.puts
        ""
      end
    end
  end
end
