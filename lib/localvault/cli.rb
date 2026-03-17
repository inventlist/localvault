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

    desc "set KEY VALUE", "Store a secret (supports dot-notation for nested keys)"
    long_desc <<~DESC
      Store a secret in the current vault.

      FLAT KEY (simple):
\x05    localvault set DATABASE_URL postgres://localhost/myapp
\x05    localvault set STRIPE_KEY sk_live_abc123

      NESTED KEY (dot-notation for team/multi-project vaults):
\x05    localvault set platepose.DATABASE_URL postgres://...     -v intellectaco
\x05    localvault set platepose.SECRET_KEY_BASE abc123          -v intellectaco
\x05    localvault set inventlist.STRIPE_KEY sk_live_abc123      -v intellectaco

      The dot separates project from key name. One vault can hold many projects.
      Use `localvault show -p platepose -v vault` to view a single project.
      Use `localvault import` to bulk-load from a .env, .json, or .yml file.
    DESC
    def set(key, value)
      vault = open_vault!
      vault.set(key, value)
      $stdout.puts "Set #{key} in vault '#{vault.name}'"
    end

    desc "get KEY", "Retrieve a secret value by key"
    long_desc <<~DESC
      Print the value of a secret to stdout.

      FLAT KEY:
\x05    localvault get DATABASE_URL

      NESTED KEY (dot-notation):
\x05    localvault get platepose.DATABASE_URL     -v intellectaco
\x05    localvault get platepose.SECRET_KEY_BASE  -v intellectaco

      Output is the raw value — safe to use in scripts:
\x05    export DB=$(localvault get platepose.DATABASE_URL -v intellectaco)
    DESC
    def get(key)
      vault = open_vault!
      value = vault.get(key)

      if value.nil?
        # Fall back to case-insensitive substring match
        all_keys = vault.list
        matches  = all_keys.select { |k| k.downcase.include?(key.downcase) }

        if matches.size == 1
          value = vault.get(matches.first)
          $stdout.puts value
          return
        elsif matches.size > 1
          $stderr.puts "Error: Multiple keys match '#{key}'. Be more specific:"
          matches.sort.each { |k| $stderr.puts "  #{k}" }
          return
        else
          abort_with "Key '#{key}' not found in vault '#{vault.name}'"
          return
        end
      end

      $stdout.puts value
    end

    desc "list", "List all secret keys in the vault"
    long_desc <<~DESC
      Print all secret keys, one per line. Nested keys use dot-notation.

\x05    localvault list
\x05    localvault list -v intellectaco

      Example output for a team vault:
\x05    platepose.DATABASE_URL
\x05    platepose.SECRET_KEY_BASE
\x05    platepose.RAILS_MASTER_KEY
\x05    inventlist.DATABASE_URL
\x05    inventlist.STRIPE_KEY

      Use `localvault show` for a formatted table, or `localvault show -p PROJECT`
      to filter to a single project.
    DESC
    def list
      vault = open_vault!
      vault.list.each { |key| $stdout.puts key }
    end

    desc "delete KEY", "Remove a secret or entire project group"
    long_desc <<~DESC
      Delete a single key or an entire project group.

      DELETE ONE KEY:
\x05    localvault delete STRIPE_KEY
\x05    localvault delete platepose.DATABASE_URL  -v intellectaco

      DELETE AN ENTIRE PROJECT GROUP (removes all keys under project.*):
\x05    localvault delete platepose  -v intellectaco

      This is permanent — use `localvault show` to verify before deleting.
    DESC
    def delete(key)
      vault = open_vault!
      deleted = vault.delete(key)
      if deleted.nil?
        abort_with "Key '#{key}' not found in vault '#{vault.name}'"
        return
      end
      $stdout.puts "Deleted #{key} from vault '#{vault.name}'"
    end

    desc "env", "Export secrets as shell variable assignments"
    long_desc <<~DESC
      Print `export KEY=value` lines for use with eval or shell sourcing.

      FLAT VAULT:
\x05    eval $(localvault env)
\x05    eval $(localvault env -v staging)

      TEAM VAULT — one project (keys exported without prefix):
\x05    eval $(localvault env -p platepose -v intellectaco)
\x05    # → export DATABASE_URL=...  export SECRET_KEY_BASE=...

      TEAM VAULT — all projects (keys prefixed to avoid collisions):
\x05    eval $(localvault env -v intellectaco)
\x05    # → export PLATEPOSE__DATABASE_URL=...  export INVENTLIST__DATABASE_URL=...

      Use `localvault exec` to inject directly into a subprocess without eval.
    DESC
    method_option :project, aliases: "-p", type: :string, desc: "Export only this project group (no prefix)"
    def env
      vault = open_vault!
      skip_warn = ->(k) { $stderr.puts "Warning: skipping unsafe key '#{k}'" }
      $stdout.puts vault.export_env(project: options[:project], on_skip: skip_warn)
    end

    desc "exec -- CMD", "Run a command with secrets injected as environment variables"
    long_desc <<~DESC
      Run any command with vault secrets in its environment. The `--` separator
      is required to prevent localvault from consuming the command's own flags.

      FLAT VAULT:
\x05    localvault exec -- rails server
\x05    localvault exec -- bundle exec rspec

      TEAM VAULT — one project (keys injected without prefix):
\x05    localvault exec -p platepose -v intellectaco -- rails server
\x05    # → DATABASE_URL, SECRET_KEY_BASE, RAILS_MASTER_KEY in env

      TEAM VAULT — all projects (keys prefixed to avoid collisions):
\x05    localvault exec -v intellectaco -- your-script
\x05    # → PLATEPOSE__DATABASE_URL, INVENTLIST__DATABASE_URL, etc.
    DESC
    method_option :project, aliases: "-p", type: :string, desc: "Inject only this project group (no prefix)"
    def exec(*cmd)
      vault = open_vault!
      skip_warn = ->(k) { $stderr.puts "Warning: skipping unsafe key '#{k}'" }
      env_vars = vault.env_hash(project: options[:project], on_skip: skip_warn)
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

    desc "show", "Display secrets in a formatted table (masked by default)"
    long_desc <<~DESC
      Show secrets in the current vault. Values are masked by default.
      Running this command also caches your passphrase in Keychain for 8 hours.

      FLAT VAULT (simple keys):
\x05    localvault show
\x05    localvault show --reveal        # show full values
\x05    localvault show --group         # group by prefix: STRIPE_KEY, STRIPE_SECRET → STRIPE

      TEAM VAULT (dot-notation — grouped automatically):
\x05    localvault show -v intellectaco               # all projects
\x05    localvault show -p platepose -v intellectaco  # one project only
\x05    localvault show -p platepose -v intellectaco --reveal
    DESC
    method_option :group,   type: :boolean, default: false, desc: "Group flat keys by common prefix"
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

    desc "install-mcp [CLIENT]", "Configure localvault MCP server in your AI tool (default: claude-code)"
    long_desc <<~DESC
      Adds localvault as an MCP server so AI assistants can read and write your secrets.

      Supported clients:
        claude-code   Adds to ~/.claude/settings.json  (default)
        cursor        Adds to ~/.cursor/mcp.json
        windsurf      Adds to ~/.codeium/windsurf/mcp_config.json

      The MCP server uses whichever vault is your current default (localvault switch).
      Unlock the vault once with `localvault show`, then the AI tool picks it up via Keychain.
    DESC
    def install_mcp(client = "claude-code")
      case client.downcase
      when "claude-code"  then install_for_claude_code
      when "cursor"       then install_mcp_via_json("Cursor",   cursor_settings_path)
      when "windsurf"     then install_mcp_via_json("Windsurf", windsurf_settings_path)
      else
        abort_with "Unknown client '#{client}'. Supported: claude-code, cursor, windsurf"
      end
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
        vault.merge(secrets)
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

    # ── Teams / sharing / sync ────────────────────────────────────

    require_relative "cli/keys"
    require_relative "cli/team"
    require_relative "cli/sync"

    register(Keys, "keys", "keys SUBCOMMAND", "Manage your X25519 keypair for vault sharing")
    register(Team, "team", "team SUBCOMMAND", "Manage vault team access")
    register(Sync, "sync", "sync SUBCOMMAND", "Sync vaults to InventList cloud")

    desc "keygen", "Generate your identity keypair for vault sync"
    method_option :force, type: :boolean, default: false, desc: "Overwrite existing keypair"
    method_option :show,  type: :boolean, default: false, desc: "Print your existing public key"
    def keygen
      if options[:show]
        unless Identity.exists?
          $stdout.puts "No keypair found. Run: localvault keygen"
          return
        end
        $stdout.puts Identity.public_key
        return
      end

      if Identity.exists? && !options[:force]
        $stdout.puts "Keypair already exists. Use --force to regenerate."
        return
      end

      Config.ensure_directories!
      Identity.generate!(force: options[:force])
      $stdout.puts "Keypair generated."
      $stdout.puts "Public key: #{Identity.public_key}"
    end

    desc "login [TOKEN]", "Log in to InventList — validate token, auto-keygen, publish public key"
    method_option :status, type: :boolean, default: false, desc: "Show current login status"
    def login(token = nil)
      if options[:status]
        handle = Config.inventlist_handle
        if handle
          $stdout.puts "Logged in as @#{handle}"
        else
          $stdout.puts "Not logged in. Run: localvault login TOKEN"
        end
        return
      end

      unless token
        $stdout.puts "Usage: localvault login TOKEN"
        $stdout.puts "Get your token at: https://inventlist.com/settings"
        return
      end

      client = ApiClient.new(token: token)
      data   = client.me
      handle = data.dig("user", "handle")

      Config.token             = token
      Config.inventlist_handle = handle

      Config.ensure_directories!
      Identity.generate! unless Identity.exists?

      client.publish_public_key(Identity.public_key)

      $stdout.puts "Logged in as @#{handle}"
      $stdout.puts "Public key published to your InventList profile."
      $stdout.puts
      $stdout.puts "Next: localvault sync push   # sync your vault to the cloud"
    rescue ApiClient::ApiError => e
      if e.status == 401
        $stdout.puts "Invalid token. Check your token at: https://inventlist.com/settings"
      else
        $stdout.puts "Error connecting to InventList: #{e.message}"
      end
    end

    desc "logout", "Log out of InventList"
    def logout
      unless Config.token
        $stdout.puts "Not logged in."
        return
      end

      handle = Config.inventlist_handle
      Config.token             = nil
      Config.inventlist_handle = nil
      $stdout.puts "Logged out#{" @#{handle}" if handle}."
    end

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
        vault_name = sanitize_receive_vault_name(share["vault_name"], share["sender_handle"])
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
        vault.merge(secrets)

        count = secrets.sum { |_, v| v.is_a?(Hash) ? v.size : 1 }
        $stdout.puts "    Imported #{count} secret(s) → vault '#{vault_name}'"
        begin
          client.accept_share(share["id"])
        rescue ApiClient::ApiError => e
          $stderr.puts "    Warning: could not mark share as accepted: #{e.message}"
        end
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

    desc "import FILE", "Bulk-import secrets from a .env, .json, or .yml file"
    long_desc <<~DESC
      Import all secrets from a file into a vault. Supports .env, .json, and .yml.

      FLAT IMPORT (into default vault):
\x05    localvault import .env
\x05    localvault import secrets.json

      SCOPED IMPORT (into a project group in a team vault):
\x05    localvault import .env -p platepose -v intellectaco
\x05    # → stores each key as platepose.KEY

      NESTED JSON/YAML (auto-imported as project groups):
\x05    localvault import all-secrets.json -v intellectaco
\x05    # { "platepose": { "DB": "..." }, "inventlist": { "DB": "..." } }
\x05    # → platepose.DB, inventlist.DB

      FILE FORMATS:
\x05    .env    KEY=value lines, # comments ignored
\x05    .json   flat {"KEY":"val"} or nested {"project":{"KEY":"val"}}
\x05    .yml    flat KEY: value or nested project:\n  KEY: value
    DESC
    method_option :project, aliases: "-p", type: :string, desc: "Namespace all imported keys under this project"
    def import(file)
      unless File.exist?(file)
        abort_with "File not found: #{file}"
        return
      end

      data = parse_import_file(file)
      if data.nil? || data.empty?
        abort_with "No secrets found in #{file}"
        return
      end

      vault   = open_vault!
      project = options[:project]

      # Restructure data for bulk merge
      to_merge = {}
      data.each do |key, value|
        if value.is_a?(Hash)
          to_merge[key] = value
        elsif project
          to_merge[project] ||= {}
          to_merge[project][key] = value.to_s
        else
          to_merge[key] = value.to_s
        end
      end

      vault.merge(to_merge)
      count = to_merge.sum { |_, v| v.is_a?(Hash) ? v.size : 1 }

      $stdout.puts "Imported #{count} secret(s) into vault '#{vault.name}'" \
                   "#{project ? " / #{project}" : ""}."
    rescue RuntimeError => e
      abort_with e.message
    end

    desc "rename OLD NEW", "Rename a secret key (supports dot-notation)"
    long_desc <<~DESC
      Rename a key in-place. The value is preserved; only the key name changes.

      FLAT KEYS:
\x05    localvault rename OLD_NAME NEW_NAME

      NESTED KEYS:
\x05    localvault rename platepose.DB_URL platepose.DATABASE_URL -v intellectaco

      MOVE ACROSS PROJECTS:
\x05    localvault rename staging.SECRET_KEY_BASE production.SECRET_KEY_BASE -v intellectaco
    DESC
    def rename(old_key, new_key)
      vault = open_vault!
      value = vault.get(old_key)
      if value.nil?
        abort_with "Key '#{old_key}' not found in vault '#{vault.name}'"
        return
      end
      vault.set(new_key, value)
      vault.delete(old_key)
      $stdout.puts "Renamed '#{old_key}' → '#{new_key}' in vault '#{vault.name}'"
    end

    desc "copy KEY --to VAULT", "Copy a secret to another vault"
    long_desc <<~DESC
      Copy a secret from the current vault to a different vault.
      Great for promoting secrets from staging → production.

      COPY A FLAT KEY:
\x05    localvault copy STRIPE_KEY --to production

      COPY A NESTED KEY (key name preserved in destination):
\x05    localvault copy platepose.DATABASE_URL --to production -v intellectaco

      Use `localvault rename` afterwards if you need a different key name.
    DESC
    method_option :to, required: true, type: :string, desc: "Destination vault name"
    def copy(key)
      src_vault = open_vault!
      value     = src_vault.get(key)
      if value.nil?
        abort_with "Key '#{key}' not found in vault '#{src_vault.name}'"
        return
      end

      dst_vault = open_vault_by_name!(options[:to])
      dst_vault.set(key, value)
      $stdout.puts "Copied '#{key}' from '#{src_vault.name}' to '#{dst_vault.name}'"
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

    def parse_import_file(file)
      ext = File.extname(file).downcase
      case ext
      when ".json"
        require "json"
        JSON.parse(File.read(file))
      when ".yml", ".yaml"
        require "yaml"
        YAML.safe_load(File.read(file)) || {}
      else
        # Treat as .env regardless of extension
        File.readlines(file, chomp: true).each_with_object({}) do |line, h|
          next if line.strip.empty? || line.strip.start_with?("#")
          key, val = line.split("=", 2)
          h[key.strip] = val.to_s.strip if key
        end
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

      prompt_msg = vault_name == resolve_vault_name ? "Passphrase: " : "Passphrase for '#{vault_name}': "
      passphrase = prompt_passphrase(prompt_msg)
      vault = Vault.open(name: vault_name, passphrase: passphrase)
      vault.all
      SessionCache.set(vault_name, vault.master_key)
      vault
    rescue Crypto::DecryptionError
      abort_with "Wrong passphrase for vault '#{vault_name}'"
      raise SystemExit.new(1)
    end

    def resolve_recipients(client, target)
      raw = if target.start_with?("team:")
              handle = target.delete_prefix("team:")
              result = client.team_public_keys(handle)
              (result["members"] || []).map { |m| [m["handle"], m["public_key"]] }
            elsif target.start_with?("crew:")
              slug = target.delete_prefix("crew:")
              result = client.crew_public_keys(slug)
              (result["members"] || []).map { |m| [m["handle"], m["public_key"]] }
            else
              handle = target.delete_prefix("@")
              result = client.get_public_key(handle)
              [[result["handle"], result["public_key"]]]
            end
      raw.select { |h, pk| h && pk && !h.empty? && !pk.empty? }
    rescue ApiClient::ApiError => e
      $stderr.puts "Warning: #{e.message}"
      []
    end

    def open_vault!
      open_vault_by_name!(resolve_vault_name)
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

    def sanitize_receive_vault_name(vault_name, sender_handle)
      safe_vault  = vault_name.to_s.gsub(/[^a-zA-Z0-9_\-]/, "-")
      safe_handle = sender_handle.to_s.gsub(/[^a-zA-Z0-9_\-]/, "-")
      # Ensure it starts with alphanumeric (Store validation requirement)
      safe_vault  = "v-#{safe_vault}"  unless safe_vault.match?(/\A[a-zA-Z0-9]/)
      safe_handle = "u-#{safe_handle}" unless safe_handle.match?(/\A[a-zA-Z0-9]/)
      "#{safe_vault}-from-#{safe_handle}"[0, 64]
    end

    def abort_with(message)
      $stderr.puts "Error: #{message}"
    end

    # --- install-mcp helpers ---

    # Claude Code: use `claude mcp add --scope user` so the server is
    # registered globally (user scope) — not tied to a single project.
    def install_for_claude_code
      unless system_command_exists?("claude")
        abort_with "Claude Code CLI not found. Install it from https://claude.ai/code"
        return
      end

      localvault_bin = find_binary("localvault")
      if localvault_bin.nil?
        abort_with "localvault not found in PATH"
        return
      end

      # Remove existing entry first (idempotent)
      system("claude", "mcp", "remove", "localvault", "--scope", "user",
             out: File::NULL, err: File::NULL)

      success = system("claude", "mcp", "add", "--scope", "user",
                       "localvault", localvault_bin, "mcp")

      if success
        $stdout.puts "Added localvault MCP server to Claude Code (user scope — global)"
        print_next_steps("Claude Code")
      else
        abort_with "Failed to add MCP server. Try: claude mcp add --scope user localvault #{localvault_bin} mcp"
      end
    end

    # Cursor / Windsurf / others: write to their JSON config file directly.
    def install_mcp_via_json(client_name, config_path)
      require "json"
      require "fileutils"

      localvault_bin = find_binary("localvault")
      if localvault_bin.nil?
        abort_with "localvault not found in PATH"
        return
      end

      FileUtils.mkdir_p(File.dirname(config_path))

      settings = File.exist?(config_path) ? JSON.parse(File.read(config_path)) : {}
      existing = settings.dig("mcpServers", "localvault")

      settings["mcpServers"] ||= {}
      settings["mcpServers"]["localvault"] = {
        "command" => localvault_bin,
        "args"    => ["mcp"]
      }

      File.write(config_path, JSON.pretty_generate(settings) + "\n")

      verb = existing ? "Updated" : "Added"
      $stdout.puts "#{verb} localvault MCP server in #{client_name} (#{config_path})"
      print_next_steps(client_name)
    end

    def print_next_steps(client_name)
      $stdout.puts ""
      $stdout.puts "Next steps:"
      $stdout.puts "  1. Restart #{client_name}"
      $stdout.puts "  2. Unlock your vault once:  localvault show"
      $stdout.puts "  3. The AI can now access secrets from your default vault"
      $stdout.puts "     Switch vaults: localvault switch <vault>"
    end

    no_commands do
      def find_binary(name)
        path = `which #{name} 2>/dev/null`.strip
        path.empty? ? nil : path
      end

      def system_command_exists?(cmd)
        !find_binary(cmd).nil?
      end

      def cursor_settings_path
        File.expand_path("~/.cursor/mcp.json")
      end

      def windsurf_settings_path
        File.expand_path("~/.codeium/windsurf/mcp_config.json")
      end
    end
  end
end
