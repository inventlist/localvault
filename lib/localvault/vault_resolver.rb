require "base64"

module LocalVault
  module VaultResolver
    Result = Struct.new(:vault, :active_vault, :active_vault_source, :session_vault, keyword_init: true)

    def self.resolve(name = nil)
      active_vault, source = active_vault_name(name)
      session_name, session_key = session_credentials

      if session_name == active_vault && session_key
        vault = build_vault(active_vault, session_key)
        return Result.new(vault: vault, active_vault: active_vault, active_vault_source: source, session_vault: session_name) if vault
      end

      if (master_key = SessionCache.get(active_vault))
        vault = build_vault(active_vault, master_key)
        return Result.new(vault: vault, active_vault: active_vault, active_vault_source: source, session_vault: session_name) if vault
      end

      Result.new(vault: nil, active_vault: active_vault, active_vault_source: source, session_vault: session_name)
    end

    def self.status(name = nil)
      result = resolve(name)
      {
        "localvault_home" => Config.root_path,
        "active_vault" => result.active_vault,
        "active_vault_source" => result.active_vault_source,
        "session_vault" => result.session_vault,
        "unlocked_vaults" => unlocked_vault_names,
        "active_vault_unlocked" => !result.vault.nil?
      }
    end

    def self.active_vault_name(name = nil)
      return [name, "argument"] if name && !name.empty?
      return [ENV["LOCALVAULT_VAULT"], "env"] if ENV["LOCALVAULT_VAULT"] && !ENV["LOCALVAULT_VAULT"].empty?

      [Config.default_vault, "config"]
    end

    def self.session_vault_name
      session_credentials.first
    end

    def self.unlocked_vault_names
      names = []
      session_name, session_key = session_credentials
      names << session_name if session_name && session_key && build_vault(session_name, session_key)

      Store.list_vaults.each do |vault_name|
        next if names.include?(vault_name)
        names << vault_name if SessionCache.get(vault_name)
      end

      names.sort
    end

    def self.session_credentials
      token = ENV["LOCALVAULT_SESSION"]
      return [nil, nil] unless token

      decoded = Base64.strict_decode64(token)
      vault_name, key_b64 = decoded.split(":", 2)
      return [nil, nil] unless vault_name && key_b64

      [vault_name, Base64.strict_decode64(key_b64)]
    rescue ArgumentError
      [nil, nil]
    end

    def self.build_vault(name, master_key)
      vault = Vault.new(name: name, master_key: master_key)
      vault.all
      vault
    rescue Crypto::DecryptionError, Store::InvalidVaultName
      nil
    end
  end
end
