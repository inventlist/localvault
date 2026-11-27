require "base64"
require "fileutils"
require "open3"
require "digest"

module LocalVault
  # Caches derived master keys to avoid re-prompting passphrase on every command.
  #
  # On macOS, uses the system Keychain (service +keychain_service+, account =
  # vault name). Falls back to a 0600 file when Keychain is unavailable (CI,
  # sandboxed, Linux): +$XDG_RUNTIME_DIR/localvault/+ (per-user tmpfs, cleared
  # at logout) when available, otherwise +~/.localvault/.sessions/+.
  #
  # Entries expire after Config.session_ttl_hours (default 8, configurable
  # 1–24). Expired entries are cleaned up on read.
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

    # Retrieve a cached master key for the given vault.
    #
    # Returns nil if no entry exists or the entry has expired. Expired entries
    # are automatically cleaned up.
    #
    # @param vault_name [String] the vault name to look up
    # @return [String, nil] raw master key bytes, or nil if not cached/expired
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

    # Cache a master key for the given vault with a time-to-live.
    #
    # @param vault_name [String] the vault name to cache
    # @param master_key [String] raw master key bytes to store
    # @param ttl_hours [Integer] hours until expiry (default: Config.session_ttl_hours)
    # @return [void]
    def self.set(vault_name, master_key, ttl_hours: Config.session_ttl_hours)
      expiry  = Time.now.to_i + (ttl_hours * 3600).to_i
      payload = "#{Base64.strict_encode64(master_key)}|#{expiry}"
      keychain_set(vault_name, payload)
    end

    # Remove the cached master key for a single vault.
    #
    # @param vault_name [String] the vault name to clear
    # @return [void]
    def self.clear(vault_name)
      keychain_delete(vault_name)
    end

    # Remove cached master keys for all known vaults.
    #
    # @return [void]
    def self.clear_all
      Store.list_vaults.each { |name| clear(name) }
      clear(Identity::CACHE_NAME)
    end

    # Keychain service name. The default home keeps "localvault" (unchanged
    # for existing installs). A custom LOCALVAULT_HOME gets its own service, so
    # two homes, including the test suite, never read each other's keys.
    #
    # @return [String]
    def self.keychain_service
      custom = ENV["LOCALVAULT_HOME"]
      return KEYCHAIN_SERVICE if custom.nil? || custom.empty?

      "#{KEYCHAIN_SERVICE}-#{Digest::SHA256.hexdigest(File.expand_path(custom))[0, 12]}"
    end

    # Directory for the file fallback, created 0700. Prefers the per-user
    # runtime dir (tmpfs on Linux) so cached keys stay off persistent disk.
    #
    # @return [String]
    def self.sessions_dir
      custom  = ENV["LOCALVAULT_HOME"]
      runtime = ENV["XDG_RUNTIME_DIR"]
      dir = if custom && !custom.empty?
              File.join(custom, ".sessions")
            elsif runtime && !runtime.empty? && File.directory?(runtime)
              File.join(runtime, "localvault")
            else
              File.join(File.expand_path("~/.localvault"), ".sessions")
            end
      FileUtils.mkdir_p(dir, mode: 0o700)
      dir
    end

    private

    def self.macos?
      RUBY_PLATFORM.include?("darwin")
    end

    def self.session_file(vault_name)
      File.join(sessions_dir, vault_name.gsub(/[^a-zA-Z0-9_\-]/, "_"))
    end

    def self.keychain_get(vault_name)
      if macos?
        out = run_command(
          ["security", "find-generic-password", "-a", vault_name, "-s", keychain_service, "-w"],
          timeout: 2
        )
        return out unless out.nil? || out.empty?
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
          "-s", keychain_service,
          "-w", payload,
          out: File::NULL, err: File::NULL
        )
        # Fall back to file store if Keychain fails (e.g., in CI or sandboxed env)
        unless success
          file = session_file(vault_name)
          File.write(file, payload)
          # chmod unconditionally: File.write's perm: only applies on creation,
          # so an existing looser-mode file would otherwise keep its perms and
          # leak the master key.
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
          "-s", keychain_service,
          out: File::NULL, err: File::NULL
        )
      end
      # Always clean file fallback
      FileUtils.rm_f(session_file(vault_name))
    end

    def self.run_command(argv, timeout:)
      output = nil
      Open3.popen3(*argv) do |stdin, stdout, stderr, wait_thread|
        stdin.close
        unless wait_thread.join(timeout)
          Process.kill("TERM", wait_thread.pid)
          unless wait_thread.join(0.1)
            Process.kill("KILL", wait_thread.pid)
            wait_thread.join
          end
          return nil
        end

        output = stdout.read.chomp if wait_thread.value.success?
        stderr.close
      rescue Errno::ESRCH
        return nil
      end
      output
    rescue Errno::ENOENT
      nil
    end

  end
end
