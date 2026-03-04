require "base64"
require "shellwords"

module LocalVault
  # Caches derived master keys in macOS Keychain (or a fallback file store).
  # Avoids re-prompting passphrase on every command.
  #
  # Stored payload: "<base64_key>|<expiry_unix_ts>"
  # Keychain service: "localvault", account: vault name
  module SessionCache
    DEFAULT_TTL_HOURS = 8
    KEYCHAIN_SERVICE  = "localvault"

    def self.get(vault_name)
      payload = keychain_get(vault_name)
      return nil unless payload

      key_b64, expiry_str = payload.split("|", 2)
      return nil unless key_b64 && expiry_str

      expiry = expiry_str.to_i
      return nil if Time.now.to_i >= expiry

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

    def self.keychain_get(vault_name)
      out = `security find-generic-password -a #{Shellwords.escape(vault_name)} -s #{Shellwords.escape(KEYCHAIN_SERVICE)} -w 2>/dev/null`.chomp
      $?.success? && !out.empty? ? out : nil
    end

    def self.keychain_set(vault_name, payload)
      # Delete existing entry first (update = delete + add)
      keychain_delete(vault_name)
      system(
        "security", "add-generic-password",
        "-a", vault_name,
        "-s", KEYCHAIN_SERVICE,
        "-w", payload,
        "-A",              # allow any app — no OS dialog on read (vault passphrase is the real security)
        out: File::NULL, err: File::NULL
      )
    end

    def self.keychain_delete(vault_name)
      system(
        "security", "delete-generic-password",
        "-a", vault_name,
        "-s", KEYCHAIN_SERVICE,
        out: File::NULL, err: File::NULL
      )
    end

  end
end
