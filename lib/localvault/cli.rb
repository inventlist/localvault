require "thor"
require "io/console"
require "base64"
require "lipgloss"
require_relative "session_cache"

module LocalVault
  class CLI < Thor
    class_option :vault, aliases: "-v", type: :string, desc: "Vault name"

    desc "init [NAME]", "Create a new vault"
    def init(name = nil)
      vault_name = name || Config.default_vault
      passphrase = prompt_passphrase("Passphrase: ")

      if passphrase.empty?
        abort_with "Passphrase cannot be empty"
        return
      end

      confirm = prompt_passphrase("Confirm passphrase: ")
      if passphrase != confirm
        abort_with "Passphrases do not match"
        return
      end

      salt = Crypto.generate_salt
      master_key = Crypto.derive_master_key(passphrase, salt)
      Vault.create!(name: vault_name, master_key: master_key, salt: salt)
      $stdout.puts "Vault '#{vault_name}' created."
    rescue RuntimeError => e
      abort_with e.message
    end

    desc "set KEY VALUE", "Store a secret"
    def set(key, value)
      vault = open_vault!
      vault.set(key, value)
      $stdout.puts "Set #{key} in vault '#{vault.name}'"
    end

    desc "get KEY", "Retrieve a secret"
    def get(key)
      vault = open_vault!
      value = vault.get(key)
      if value.nil?
        abort_with "Key '#{key}' not found in vault '#{vault.name}'"
        return
      end
      $stdout.puts value
    end

    desc "list", "List all keys"
    def list
      vault = open_vault!
      vault.list.each { |key| $stdout.puts key }
    end

    desc "delete KEY", "Remove a secret"
    def delete(key)
      vault = open_vault!
      deleted = vault.delete(key)
      if deleted.nil?
        abort_with "Key '#{key}' not found in vault '#{vault.name}'"
        return
      end
      $stdout.puts "Deleted #{key} from vault '#{vault.name}'"
    end

    desc "env", "Export secrets as shell variables"
    method_option :project, aliases: "-p", type: :string, desc: "Export only this project group"
    def env
      vault = open_vault!
      $stdout.puts vault.export_env(project: options[:project])
    end

    desc "exec -- CMD", "Run command with secrets injected as env vars"
    method_option :project, aliases: "-p", type: :string, desc: "Inject only this project group"
    def exec(*cmd)
      vault = open_vault!
      env_vars = vault.env_hash(project: options[:project])
      Kernel.exec(env_vars, *cmd)
    end

    desc "vaults", "List all vaults with secret counts"
    def vaults
      names = Store.list_vaults
      if names.empty?
        $stdout.puts "No vaults found. Run: localvault init"
        return
      end

      default_name = Config.default_vault
      rows = names.map do |name|
        store = Store.new(name)
        default_marker = name == default_name ? "✓" : ""
        [name, store.count.to_s, default_marker]
      end

      table = Lipgloss::Table.new
        .headers(["Vault", "Secrets", "Default"])
        .rows(rows)
        .border(:rounded)
        .style_func(rows: rows.size, columns: 3) do |row, _col|
          if row == Lipgloss::Table::HEADER_ROW
            HEADER_STYLE
          else
            row.odd? ? ODD_STYLE : EVEN_STYLE
          end
        end
        .render

      $stdout.puts table
    end

    desc "unlock", "Output session token for passphrase-free access"
    def unlock
      vault_name = resolve_vault_name
      store = Store.new(vault_name)
      unless store.exists?
        abort_with "Vault '#{vault_name}' does not exist. Run: localvault init #{vault_name}"
        return
      end

      passphrase = prompt_passphrase("Passphrase: ")
      master_key = Crypto.derive_master_key(passphrase, store.salt)

      # Verify passphrase by attempting to decrypt
      vault = Vault.new(name: vault_name, master_key: master_key)
      vault.all

      SessionCache.set(vault_name, master_key)
      token = Base64.strict_encode64("#{vault_name}:#{Base64.strict_encode64(master_key)}")
      $stdout.puts "export LOCALVAULT_SESSION=\"#{token}\""
    rescue Crypto::DecryptionError
      abort_with "Wrong passphrase for vault '#{vault_name}'"
    end

    desc "show", "Display secrets in a table (masked by default)"
    method_option :group,   type: :boolean, default: false, desc: "Group by key prefix"
    method_option :reveal,  type: :boolean, default: false, desc: "Show full values instead of masking"
    method_option :project, aliases: "-p", type: :string,   desc: "Show only this project group"
    def show
      vault = open_vault!
      secrets = vault.all

      if secrets.empty?
        $stdout.puts "No secrets in vault '#{vault.name}'."
        return
      end

      if options[:project]
        group = secrets[options[:project]]
        unless group.is_a?(Hash)
          abort_with "No project '#{options[:project]}' in vault '#{vault.name}'"
          return
        end
        render_table(group.sort.to_h, "#{vault.name}/#{options[:project]}", reveal: options[:reveal])
      elsif options[:group] || secrets.values.any? { |v| v.is_a?(Hash) }
        render_grouped_table(secrets, vault.name, reveal: options[:reveal])
      else
        render_table(secrets.sort.to_h, vault.name, reveal: options[:reveal])
      end
    end

    desc "rekey [NAME]", "Change the passphrase for a vault (secrets are preserved)"
    def rekey(name = nil)
      vault_name = name || resolve_vault_name
      store = Store.new(vault_name)

      unless store.exists?
        abort_with "Vault '#{vault_name}' does not exist."
        return
      end

      current = prompt_passphrase("Current passphrase: ")
      vault   = Vault.open(name: vault_name, passphrase: current)
      vault.all  # verify

      new_pass = prompt_passphrase("New passphrase: ")
      if new_pass.empty?
        abort_with "Passphrase cannot be empty"
        return
      end

      confirm = prompt_passphrase("Confirm new passphrase: ")
      unless new_pass == confirm
        abort_with "Passphrases do not match"
        return
      end

      new_vault = vault.rekey(new_pass)
      SessionCache.set(vault_name, new_vault.master_key)
      $stdout.puts "Passphrase updated for vault '#{vault_name}'."
    rescue Crypto::DecryptionError
      abort_with "Wrong passphrase for vault '#{vault_name}'"
    rescue RuntimeError => e
      abort_with e.message
    end

    desc "reset [NAME]", "Destroy all secrets in a vault and reinitialize it"
    def reset(name = nil)
      vault_name = name || resolve_vault_name
      store = Store.new(vault_name)

      unless store.exists?
        abort_with "Vault '#{vault_name}' does not exist. Run: localvault init #{vault_name}"
        return
      end

      $stderr.puts "WARNING: This will permanently delete all secrets in vault '#{vault_name}'."
      $stderr.puts "This cannot be undone."
      $stderr.print "Type '#{vault_name}' to confirm: "

      confirmation = prompt_confirmation
      unless confirmation == vault_name
        abort_with "Cancelled."
        return
      end

      store.destroy!

      passphrase = prompt_passphrase("New passphrase: ")
      if passphrase.empty?
        abort_with "Passphrase cannot be empty"
        return
      end

      confirm = prompt_passphrase("Confirm passphrase: ")
      unless passphrase == confirm
        abort_with "Passphrases do not match"
        return
      end

      salt = Crypto.generate_salt
      master_key = Crypto.derive_master_key(passphrase, salt)
      Vault.create!(name: vault_name, master_key: master_key, salt: salt)
      $stdout.puts "Vault '#{vault_name}' has been reset."
    rescue RuntimeError => e
      abort_with e.message
    end

    desc "lock [NAME]", "Clear cached passphrase for a vault (or all vaults)"
    def lock(name = nil)
      if name
        SessionCache.clear(name)
        $stdout.puts "Session cleared for vault '#{name}'."
      else
        SessionCache.clear_all
        $stdout.puts "All vault sessions cleared."
      end
    end

    desc "mcp", "Start MCP server (stdio)"
    def mcp
      require "localvault/mcp/server"
      MCP::Server.new.start
    end

    desc "demo", "Create demo vaults with fake data for learning (passphrase: demo)"
    def demo
      names = Store.list_vaults
      unless names.empty?
        abort_with "Vaults already exist (#{names.join(", ")}). " \
                   "Run `localvault reset <name>` to clear one, or use a fresh LOCALVAULT_HOME."
        return
      end

      $stderr.puts "This creates DEMO vaults with fake data for learning purposes."
      $stderr.puts "These are NOT for real secrets. Passphrase for all vaults: \"demo\""
      $stderr.print "Type 'demo' to continue: "

      confirmation = prompt_confirmation
      unless confirmation == "demo"
        abort_with "Cancelled."
        return
      end

      DEMO_DATA.each do |vault_name, secrets|
        salt       = Crypto.generate_salt
        master_key = Crypto.derive_master_key("demo", salt)
        vault      = Vault.create!(name: vault_name, master_key: master_key, salt: salt)
        secrets.each { |k, v| vault.set(k, v) }
        $stdout.puts "  created vault '#{vault_name}' (#{secrets.size} secrets)"
      end

      $stdout.puts
      $stdout.puts "Done! All vaults use passphrase: demo"
      $stdout.puts
      $stdout.puts "Try:"
      $stdout.puts "  localvault vaults"
      $stdout.puts "  localvault show"
      $stdout.puts "  localvault show --vault x --group"
      $stdout.puts "  localvault show --vault production --reveal"
      $stdout.puts "  localvault exec -- env | grep -E 'DATABASE|REDIS'"
    end

    # ── Teams / sharing ──────────────────────────────────────────────

    require_relative "cli/keys"
    require_relative "cli/team"

    register(Keys, "keys", "keys SUBCOMMAND", "Manage your X25519 keypair for vault sharing")
    register(Team, "team", "team SUBCOMMAND", "Manage vault team access")

    desc "connect", "Connect to InventList for vault sharing"
    method_option :token,  required: true, type: :string, desc: "InventList API token"
    method_option :handle, required: true, type: :string, desc: "Your InventList handle"
    def connect
      Config.token              = options[:token]
      Config.inventlist_handle  = options[:handle]
      $stdout.puts "Connected as @#{options[:handle]}"
      $stdout.puts
      $stdout.puts "Next steps:"
      $stdout.puts "  localvault keys generate   # generate your X25519 keypair"
      $stdout.puts "  localvault keys publish    # upload your public key to InventList"
    end

    desc "share [VAULT]", "Share a vault with an InventList user, team, or crew"
    method_option :with, required: true, type: :string,
      desc: "Recipient: @handle, team:HANDLE, or crew:SLUG"
    def share(vault_name = nil)
      unless Config.token
        abort_with "Not connected. Run: localvault connect --token TOKEN --handle HANDLE"
        return
      end

      unless Identity.exists?
        abort_with "No keypair found. Run: localvault keys generate && localvault keys publish"
        return
      end

      vault_name ||= resolve_vault_name
      vault   = open_vault_by_name!(vault_name)
      secrets = vault.all

      if secrets.empty?
        abort_with "Vault '#{vault_name}' has no secrets to share."
        return
      end

      client     = ApiClient.new(token: Config.token)
      target     = options[:with]
      recipients = resolve_recipients(client, target)

      if recipients.empty?
        abort_with "No recipients with public keys found for '#{target}'"
        return
      end

      recipients.each do |handle, pub_key|
        encrypted = ShareCrypto.encrypt_for(secrets, pub_key)
        client.create_share(
          vault_name:        vault_name,
          recipient_handle:  handle,
          encrypted_payload: encrypted
        )
        $stdout.puts "Shared vault '#{vault_name}' with @#{handle}"
      end
    rescue ApiClient::ApiError => e
      abort_with e.message
    end

    desc "receive", "Fetch and import vaults shared with you"
    def receive
      unless Config.token
        abort_with "Not connected. Run: localvault connect --token TOKEN --handle HANDLE"
        return
      end

      unless Identity.private_key_bytes
        abort_with "No keypair found. Run: localvault keys generate"
        return
      end

      client  = ApiClient.new(token: Config.token)
      result  = client.pending_shares
      shares  = result["shares"] || []

      if shares.empty?
        $stdout.puts "No pending shares."
        return
      end

      $stdout.puts "Found #{shares.size} pending share(s):"
      $stdout.puts

      imported = 0
      shares.each do |share|
        vault_name = "#{share["vault_name"]}-from-#{share["sender_handle"]}"
        $stdout.puts "  [#{share["id"]}] vault '#{share["vault_name"]}' from @#{share["sender_handle"]}"

        begin
          secrets = ShareCrypto.decrypt_from(share["encrypted_payload"], Identity.private_key_bytes)
        rescue ShareCrypto::DecryptionError => e
          $stderr.puts "    Failed to decrypt: #{e.message}"
          next
        end

        if Store.new(vault_name).exists?
          $stdout.puts "    Vault '#{vault_name}' already exists, skipping."
          next
        end

        passphrase = prompt_passphrase("    Passphrase for new vault '#{vault_name}': ")
        if passphrase.empty?
          $stderr.puts "    Skipped (empty passphrase)."
          next
        end

        salt       = Crypto.generate_salt
        master_key = Crypto.derive_master_key(passphrase, salt)
        vault      = Vault.create!(name: vault_name, master_key: master_key, salt: salt)
        secrets.each { |k, v| vault.set(k, v.to_s) }

        $stdout.puts "    Imported #{secrets.size} secret(s) → vault '#{vault_name}'"
        client.accept_share(share["id"]) rescue nil
        imported += 1
      end

      $stdout.puts
      $stdout.puts "Done. #{imported} vault(s) imported."
    rescue ApiClient::ApiError => e
      abort_with e.message
    end

    desc "revoke SHARE_ID", "Revoke a vault share (stops future access)"
    def revoke(share_id)
      unless Config.token
        abort_with "Not connected. Run: localvault connect --token TOKEN --handle HANDLE"
        return
      end

      client = ApiClient.new(token: Config.token)
      client.revoke_share(share_id)
      $stdout.puts "Share #{share_id} revoked."
      $stdout.puts "Note: @recipient retains any secrets already received."
    rescue ApiClient::ApiError => e
      abort_with e.message
    end

    desc "switch [VAULT]", "Switch the default vault (or show current)"
    def switch(vault_name = nil)
      if vault_name.nil?
        current = Config.default_vault
        $stdout.puts "Current vault: #{current}"
        $stdout.puts
        $stdout.puts "Available vaults:"
        Store.list_vaults.each do |name|
          marker = name == current ? "  ← current" : ""
          $stdout.puts "  #{name}#{marker}"
        end
        return
      end

      unless Store.new(vault_name).exists?
        abort_with "Vault '#{vault_name}' does not exist. Run: localvault init #{vault_name}"
        return
      end

      Config.default_vault = vault_name
      $stdout.puts "Switched to vault '#{vault_name}'"
    end

    desc "version", "Print version"
    def version
      $stdout.puts "localvault #{VERSION}"
    end

    def self.exit_on_failure?
      true
    end

    no_commands do
      def prompt_confirmation(msg = "")
        $stdin.gets&.chomp || ""
      rescue Interrupt
        $stderr.puts
        exit 130
      end

      def prompt_passphrase(msg = "Passphrase: ")
        unless $stdin.respond_to?(:getpass) || ($stdin.respond_to?(:tty?) && $stdin.tty?)
          abort_with "Use LOCALVAULT_SESSION or run in a terminal"
          return ""
        end
        IO.console&.getpass(msg) || $stdin.gets&.chomp || ""
      rescue Interrupt
        $stderr.puts
        exit 130
      end
    end

    private

    # ── Demo data ──────────────────────────────────────────────────
    DEMO_DATA = {
      "default" => {
        "OPENAI_API_KEY"        => "sk-demo-openai-abc123",
        "ANTHROPIC_API_KEY"     => "sk-ant-demo-xyz789",
        "STRIPE_SECRET_KEY"     => "sk_test_demo_stripe",
        "STRIPE_WEBHOOK_SECRET" => "whsec_demo_webhook",
        "RESEND_API_KEY"        => "re_demo_resend_key",
        "GITHUB_TOKEN"          => "ghp_demo_github_token",
        "SENTRY_DSN"            => "https://demo@sentry.io/12345",
        "DATABASE_URL"          => "postgres://localhost/myapp_dev"
      },
      "x" => {
        "NAUMANTHANVI_API_KEY"         => "demo-api-key-personal",
        "NAUMANTHANVI_API_SECRET"      => "demo-api-secret-personal",
        "NAUMANTHANVI_ACCESS_TOKEN"    => "demo-access-token-personal",
        "NAUMANTHANVI_ACCESS_SECRET"   => "demo-access-secret-personal",
        "NAUMANTHANVI_BEARER_TOKEN"    => "demo-bearer-personal",
        "INVENT_LIST_API_KEY"          => "demo-api-key-brand",
        "INVENT_LIST_API_SECRET"       => "demo-api-secret-brand",
        "INVENT_LIST_ACCESS_TOKEN"     => "demo-access-token-brand",
        "INVENT_LIST_ACCESS_SECRET"    => "demo-access-secret-brand",
        "INVENT_LIST_BEARER_TOKEN"     => "demo-bearer-brand"
      },
      "production" => {
        "DATABASE_URL"            => "postgres://prod-db.example.com/myapp",
        "REDIS_URL"               => "redis://prod-redis.example.com:6379",
        "SECRET_KEY_BASE"         => "demo-secret-key-base-very-long-string",
        "RAILS_MASTER_KEY"        => "demo-master-key-32chars-exactly!",
        "AWS_ACCESS_KEY_ID"       => "AKIADEMO0000000000",
        "AWS_SECRET_ACCESS_KEY"   => "demo-aws-secret-access-key",
        "S3_BUCKET"               => "myapp-production",
        "CLOUDFLARE_API_TOKEN"    => "demo-cloudflare-token",
        "KAMAL_REGISTRY_PASSWORD" => "demo-registry-password"
      },
      "staging" => {
        "DATABASE_URL"            => "postgres://staging-db.example.com/myapp",
        "REDIS_URL"               => "redis://staging-redis.example.com:6379",
        "SECRET_KEY_BASE"         => "demo-staging-secret-key-base",
        "RAILS_MASTER_KEY"        => "demo-staging-master-key-32ch!",
        "STRIPE_SECRET_KEY"       => "sk_test_demo_staging_stripe",
        "STRIPE_WEBHOOK_SECRET"   => "whsec_demo_staging_webhook",
        "S3_BUCKET"               => "myapp-staging"
      }
    }.freeze

    # ── Lipgloss styles ────────────────────────────────────────────
    HEADER_STYLE  = Lipgloss::Style.new.bold(true).foreground("#FFFFFF").background("#5C4AE4").padding(0, 1)
    ODD_STYLE     = Lipgloss::Style.new.foreground("#E2E2E2").padding(0, 1)
    EVEN_STYLE    = Lipgloss::Style.new.foreground("#A0A0A0").padding(0, 1)
    MASKED_STYLE  = Lipgloss::Style.new.foreground("#6B7280").padding(0, 1)
    GROUP_STYLE   = Lipgloss::Style.new.bold(true).foreground("#A78BFA")
    VAULT_STYLE   = Lipgloss::Style.new.bold(true).foreground("#FFFFFF")
    COUNT_STYLE   = Lipgloss::Style.new.foreground("#6B7280")

    def mask_value(value, reveal:)
      return value if reveal
      return "(empty)" if value.to_s.empty?
      suffix = value.to_s.length > 4 ? value.to_s[-4..] : value.to_s
      "#{"•" * 6}  #{suffix}"
    end

    def lipgloss_table(secrets, reveal:)
      require "lipgloss"
      rows = secrets.sort.map { |k, v| [k, mask_value(v, reveal: reveal)] }
      Lipgloss::Table.new
        .headers(["Key", "Value"])
        .rows(rows)
        .border(:rounded)
        .style_func(rows: rows.size, columns: 2) do |row, _col|
          if row == Lipgloss::Table::HEADER_ROW
            HEADER_STYLE
          elsif reveal
            row.odd? ? ODD_STYLE : EVEN_STYLE
          else
            row.odd? ? MASKED_STYLE : EVEN_STYLE
          end
        end
        .render
    end

    def render_table(secrets, vault_name, reveal:, header: nil)
      unless header == false
        total = secrets.size
        label = "#{VAULT_STYLE.render("Vault: #{vault_name}")}  #{COUNT_STYLE.render("(#{total} secret#{total == 1 ? "" : "s"})")}"
        $stdout.puts label
      end
      $stdout.puts lipgloss_table(secrets, reveal: reveal)
    end

    def render_grouped_table(secrets, vault_name, reveal:)
      # Separate true nested groups (Hash values) from flat keys
      nested   = secrets.select { |_, v| v.is_a?(Hash) }
      flat     = secrets.reject { |_, v| v.is_a?(Hash) }

      # For flat keys, group by underscore prefix (legacy --group behaviour)
      prefix_groups = flat.group_by { |k, _| k.include?("_") ? k.split("_").first : nil }
      ungrouped     = prefix_groups.delete(nil) || []

      total = secrets.sum { |_, v| v.is_a?(Hash) ? v.size : 1 }
      $stdout.puts "#{VAULT_STYLE.render("Vault: #{vault_name}")}  #{COUNT_STYLE.render("(#{total} secret#{total == 1 ? "" : "s"})")}"
      $stdout.puts

      # Render nested project groups first
      nested.sort.each do |project, pairs|
        $stdout.puts "  #{GROUP_STYLE.render(project)}  #{COUNT_STYLE.render("(#{pairs.size})")}"
        $stdout.puts lipgloss_table(pairs.sort.to_h, reveal: reveal)
        $stdout.puts
      end

      # Render flat prefix groups
      prefix_groups.sort.each do |prefix, pairs|
        $stdout.puts "  #{GROUP_STYLE.render(prefix)}  #{COUNT_STYLE.render("(#{pairs.size})")}"
        $stdout.puts lipgloss_table(pairs.sort.to_h, reveal: reveal)
        $stdout.puts
      end

      unless ungrouped.empty?
        $stdout.puts "  #{GROUP_STYLE.render("ungrouped")}"
        $stdout.puts lipgloss_table(ungrouped.sort.to_h, reveal: reveal)
        $stdout.puts
      end
    end

    def resolve_vault_name
      options[:vault] || Config.default_vault
    end

    def open_vault_by_name!(vault_name)
      if (vault = vault_from_session(vault_name))
        return vault
      end

      store = Store.new(vault_name)
      unless store.exists?
        abort_with "Vault '#{vault_name}' does not exist. Run: localvault init #{vault_name}"
        raise SystemExit.new(1)
      end

      if (master_key = SessionCache.get(vault_name))
        begin
          vault = Vault.new(name: vault_name, master_key: master_key)
          vault.all
          return vault
        rescue Crypto::DecryptionError
          SessionCache.clear(vault_name)
        end
      end

      passphrase = prompt_passphrase("Passphrase for '#{vault_name}': ")
      vault = Vault.open(name: vault_name, passphrase: passphrase)
      vault.all
      SessionCache.set(vault_name, vault.master_key)
      vault
    rescue Crypto::DecryptionError
      abort_with "Wrong passphrase for vault '#{vault_name}'"
      raise SystemExit.new(1)
    end

    def resolve_recipients(client, target)
      if target.start_with?("team:")
        handle = target.delete_prefix("team:")
        result = client.team_public_keys(handle)
        (result["members"] || []).map { |m| [m["handle"], m["public_key"]] }
      elsif target.start_with?("crew:")
        slug   = target.delete_prefix("crew:")
        result = client.crew_public_keys(slug)
        (result["members"] || []).map { |m| [m["handle"], m["public_key"]] }
      else
        handle = target.delete_prefix("@")
        result = client.get_public_key(handle)
        [[result["handle"], result["public_key"]]]
      end
    rescue ApiClient::ApiError => e
      $stderr.puts "Warning: #{e.message}"
      []
    end

    def open_vault!
      vault_name = resolve_vault_name

      # 1. Try LOCALVAULT_SESSION env var
      if (vault = vault_from_session(vault_name))
        return vault
      end

      store = Store.new(vault_name)
      unless store.exists?
        abort_with "Vault '#{vault_name}' does not exist. Run: localvault init #{vault_name}"
        raise SystemExit.new(1)
      end

      # 2. Try Keychain session cache
      if (master_key = SessionCache.get(vault_name))
        begin
          vault = Vault.new(name: vault_name, master_key: master_key)
          vault.all  # verify key still valid
          return vault
        rescue Crypto::DecryptionError
          SessionCache.clear(vault_name)  # stale cache — clear and fall through
        end
      end

      # 3. Prompt passphrase and cache the result
      passphrase = prompt_passphrase("Passphrase: ")
      vault = Vault.open(name: vault_name, passphrase: passphrase)
      vault.all  # eager verification
      SessionCache.set(vault_name, vault.master_key)
      vault
    rescue Crypto::DecryptionError
      abort_with "Wrong passphrase for vault '#{vault_name}'"
      raise SystemExit.new(1)
    end

    def vault_from_session(vault_name)
      token = ENV["LOCALVAULT_SESSION"]
      return nil unless token

      decoded = Base64.strict_decode64(token)
      session_vault, key_b64 = decoded.split(":", 2)
      return nil unless session_vault == vault_name && key_b64

      master_key = Base64.strict_decode64(key_b64)
      vault = Vault.new(name: vault_name, master_key: master_key)
      vault.all # Verify the key works
      vault
    rescue ArgumentError, Crypto::DecryptionError
      nil
    end

    def abort_with(message)
      $stderr.puts "Error: #{message}"
    end
  end
end
