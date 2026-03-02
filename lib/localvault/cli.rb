require "thor"
require "io/console"
require "base64"

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

      token = Base64.strict_encode64("#{vault_name}:#{Base64.strict_encode64(master_key)}")
      $stdout.puts "export LOCALVAULT_SESSION=\"#{token}\""
    rescue Crypto::DecryptionError
      abort_with "Wrong passphrase for vault '#{vault_name}'"
    end

    desc "version", "Print version"
    def version
      $stdout.puts "localvault #{VERSION}"
    end

    def self.exit_on_failure?
      true
    end

    no_commands do
      def prompt_passphrase(msg = "Passphrase: ")
        unless $stdin.respond_to?(:getpass) || ($stdin.respond_to?(:tty?) && $stdin.tty?)
          abort_with "Use LOCALVAULT_SESSION or run in a terminal"
          return ""
        end
        IO.console&.getpass(msg) || $stdin.gets&.chomp || ""
      end
    end

    private

    def resolve_vault_name
      options[:vault] || Config.default_vault
    end

    def open_vault!
      vault_name = resolve_vault_name

      # Try session cache first
      if (vault = vault_from_session(vault_name))
        return vault
      end

      store = Store.new(vault_name)
      unless store.exists?
        abort_with "Vault '#{vault_name}' does not exist. Run: localvault init #{vault_name}"
        raise SystemExit.new(1)
      end

      passphrase = prompt_passphrase("Passphrase: ")
      vault = Vault.open(name: vault_name, passphrase: passphrase)
      vault.all # Eager verification
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
