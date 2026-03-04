require "json"

module LocalVault
  class Vault
    attr_reader :name, :master_key, :store

    def initialize(name:, master_key:)
      @name = name
      @master_key = master_key
      @store = Store.new(name)
    end

    def get(key)
      all[key]
    end

    def set(key, value)
      secrets = all
      secrets[key] = value
      write_secrets(secrets)
      value
    end

    def delete(key)
      secrets = all
      deleted = secrets.delete(key)
      write_secrets(secrets) if deleted
      deleted
    end

    def list
      all.keys.sort
    end

    def all
      encrypted = store.read_encrypted
      return {} unless encrypted && !encrypted.empty?

      json = Crypto.decrypt(encrypted, master_key)
      JSON.parse(json)
    end

    def export_env
      all.map { |k, v| "export #{k}=#{v.inspect}" }.join("\n")
    end

    def self.create!(name:, master_key:, salt:)
      store = Store.new(name)
      store.create!(salt: salt)

      # Write empty encrypted secrets
      empty_json = JSON.generate({})
      encrypted = Crypto.encrypt(empty_json, master_key)
      store.write_encrypted(encrypted)

      new(name: name, master_key: master_key)
    end

    def rekey(new_passphrase, new_salt: Crypto.generate_salt)
      secrets = all
      new_master_key = Crypto.derive_master_key(new_passphrase, new_salt)

      store.create_meta!(salt: new_salt)
      new_vault = self.class.new(name: name, master_key: new_master_key)
      new_vault.send(:write_secrets, secrets)
      new_vault
    end

    def self.open(name:, passphrase:)
      store = Store.new(name)
      raise "Vault '#{name}' does not exist" unless store.exists?

      salt = store.salt
      raise "Vault '#{name}' has no salt in metadata" unless salt

      master_key = Crypto.derive_master_key(passphrase, salt)
      new(name: name, master_key: master_key)
    end

    private

    def write_secrets(secrets)
      json = JSON.generate(secrets)
      encrypted = Crypto.encrypt(json, master_key)
      store.write_encrypted(encrypted)
      store.update_count!(secrets.size)
    end
  end
end
