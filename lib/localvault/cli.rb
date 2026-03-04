require "thor"
require "io/console"
require "base64"
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

    desc "env", "Export all secrets as shell variables"
    def env
      vault = open_vault!
      $stdout.puts vault.export_env
    end

    desc "exec -- CMD", "Run command with secrets injected as env vars"
    def exec(*cmd)
      vault = open_vault!
      env_hash = vault.all
      Kernel.exec(env_hash, *cmd)
    end

    desc "vaults", "List all vault names"
    def vaults
      default_name = Config.default_vault
      Store.list_vaults.each do |name|
        marker = name == default_name ? " (default)" : ""
        $stdout.puts "#{name}#{marker}"
      end
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
    method_option :group,  type: :boolean, default: false, desc: "Group by key prefix"
    method_option :reveal, type: :boolean, default: false, desc: "Show full values instead of masking"
    def show
      vault = open_vault!
      secrets = vault.all

      if secrets.empty?
        $stdout.puts "No secrets in vault '#{vault.name}'."
        return
      end

      if options[:group]
        render_grouped_table(secrets, vault.name, reveal: options[:reveal])
      else
        render_table(secrets.sort.to_h, vault.name, reveal: options[:reveal])
      end
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

    def mask_value(value, reveal:)
      return value if reveal
      return "(empty)" if value.to_s.empty?
      suffix = value.to_s.length > 4 ? value.to_s[-4..] : value.to_s
      "#{"•" * 6}  #{suffix}"
    end

    def render_table(secrets, vault_name, reveal:, header: nil)
      key_width   = [secrets.keys.map(&:length).max || 0, 3].max
      val_width   = reveal ? [secrets.values.map { |v| v.to_s.length }.max || 0, 5].max : 14

      unless header == false
        total = secrets.size
        $stdout.puts header || "Vault: #{vault_name}  (#{total} secret#{total == 1 ? "" : "s"})"
      end
      divider = "┌#{"─" * (key_width + 2)}┬#{"─" * (val_width + 2)}┐"
      row_div = "├#{"─" * (key_width + 2)}┼#{"─" * (val_width + 2)}┤"
      bottom  = "└#{"─" * (key_width + 2)}┴#{"─" * (val_width + 2)}┘"

      $stdout.puts divider
      $stdout.puts "│ #{"Key".ljust(key_width)} │ #{"Value".ljust(val_width)} │"
      $stdout.puts row_div
      secrets.each do |key, value|
        display = mask_value(value, reveal: reveal).to_s.ljust(val_width)
        $stdout.puts "│ #{key.ljust(key_width)} │ #{display} │"
      end
      $stdout.puts bottom
    end

    def render_grouped_table(secrets, vault_name, reveal:)
      groups = secrets.group_by { |k, _| k.include?("_") ? k.split("_").first : nil }
      ungrouped = groups.delete(nil) || []

      total = secrets.size
      $stdout.puts "Vault: #{vault_name}  (#{total} secret#{total == 1 ? "" : "s"})"
      $stdout.puts

      groups.sort.each do |prefix, pairs|
        $stdout.puts "  #{prefix} (#{pairs.size})"
        render_table(pairs.sort.to_h, vault_name, reveal: reveal, header: false)
        $stdout.puts
      end

      unless ungrouped.empty?
        $stdout.puts "  (ungrouped)"
        render_table(ungrouped.sort.to_h, vault_name, reveal: reveal, header: false)
        $stdout.puts
      end
    end

    def resolve_vault_name
      options[:vault] || Config.default_vault
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
