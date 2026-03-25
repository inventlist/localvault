require "base64"
require "fileutils"
require "shellwords"

module LocalVault
  # Caches derived master keys to avoid re-prompting passphrase on every command.
  #
  # On macOS, uses the system Keychain (service "localvault", account = vault name).
  # Falls back to file-based cache at +~/.localvault/.sessions/+ (mode 0600)
  # when Keychain is unavailable (CI, sandboxed, Linux).
  #
  # Entries expire after +DEFAULT_TTL_HOURS+ (8 hours). Expired entries are
  # cleaned up on read.
  #
  # Stored payload format: +"<base64_key>|<expiry_unix_ts>"+
  #
  # @example
  #   SessionCache.set("production", master_key)
  #   SessionCache.get("production")  # => master_key bytes (or nil if expired)
  #   SessionCache.clear("production")
  module SessionCache
    DEFAULT_TTL_HOURS = 8
    KEYCHAIN_SERVICE  = "localvault"

    def self.get(vault_name)
      payload = keychain_get(vault_name)
      return nil unless payload

      key_b64, expiry_str = payload.split("|", 2)
      return nil unless key_b64 && expiry_str

      expiry = expiry_str.to_i
      if Time.now.to_i >= expiry
        clear(vault_name)  # clean up expired entry
        return nil
      end

      Base64.strict_decode64(key_b64)
    rescue ArgumentError
      nil
    end

    def self.set(vault_name, master_key, ttl_hours: DEFAULT_TTL_HOURS)
      expiry  = Time.now.to_i + (ttl_hours * 3600).to_i
      payload = "#{Base64.strict_encode64(master_key)}|#{expiry}"
      keychain_set(vault_name, payload)
    end

    def self.clear(vault_name)
      keychain_delete(vault_name)
    end

    def self.clear_all
      Store.list_vaults.each { |name| clear(name) }
    end

    private

    def self.macos?
      RUBY_PLATFORM.include?("darwin")
    end

    def self.sessions_dir
      dir = File.join(
        ENV.fetch("LOCALVAULT_HOME", File.expand_path("~/.localvault")),
        ".sessions"
      )
      FileUtils.mkdir_p(dir, mode: 0o700)
      dir
    end

    def self.session_file(vault_name)
      File.join(sessions_dir, vault_name.gsub(/[^a-zA-Z0-9_\-]/, "_"))
    end

    def self.keychain_get(vault_name)
      if macos?
        out = `security find-generic-password -a #{Shellwords.escape(vault_name)} -s #{Shellwords.escape(KEYCHAIN_SERVICE)} -w 2>/dev/null`.chomp
        return out if $?.success? && !out.empty?
      end
      # File fallback (Linux, or macOS when Keychain unavailable)
      file = session_file(vault_name)
      File.exist?(file) ? File.read(file).strip : nil
    end

    def self.keychain_set(vault_name, payload)
      if macos?
        keychain_delete(vault_name)
        success = system(
          "security", "add-generic-password",
          "-a", vault_name,
          "-s", KEYCHAIN_SERVICE,
          "-w", payload,
          out: File::NULL, err: File::NULL
        )
        # Fall back to file store if Keychain fails (e.g., in CI or sandboxed env)
        unless success
          file = session_file(vault_name)
          File.write(file, payload)
          File.chmod(0o600, file)
        end
      else
        keychain_delete(vault_name)
        file = session_file(vault_name)
        File.write(file, payload)
        File.chmod(0o600, file)
      end
    end

    def self.keychain_delete(vault_name)
      if macos?
        system(
          "security", "delete-generic-password",
          "-a", vault_name,
          "-s", KEYCHAIN_SERVICE,
          out: File::NULL, err: File::NULL
        )
      end
      # Always clean file fallback
      FileUtils.rm_f(session_file(vault_name))
    end

  end
end
