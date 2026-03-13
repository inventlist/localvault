require "json"
require "shellwords"

module LocalVault
  class Vault
    attr_reader :name, :master_key, :store

    def initialize(name:, master_key:)
      @name = name
      @master_key = master_key
      @store = Store.new(name)
    end

    def get(key)
      if key.include?(".")
        group, subkey = key.split(".", 2)
        value = all[group]
        value.is_a?(Hash) ? value[subkey] : nil
      else
        all[key]
      end
    end

    def set(key, value)
      secrets = all
      if key.include?(".")
        group, subkey = key.split(".", 2)
        secrets[group] ||= {}
        raise "#{group} is a scalar value, not a group" unless secrets[group].is_a?(Hash)
        secrets[group][subkey] = value
      else
        secrets[key] = value
      end
      write_secrets(secrets)
      value
    end

    def delete(key)
      secrets = all
      if key.include?(".")
        group, subkey = key.split(".", 2)
        return nil unless secrets[group].is_a?(Hash)
        deleted = secrets[group].delete(subkey)
        secrets.delete(group) if secrets[group].empty?
        write_secrets(secrets) if deleted
        deleted
      else
        deleted = secrets.delete(key)
        write_secrets(secrets) if deleted
        deleted
      end
    end

    # Returns a flat list of all keys — nested keys use dot-notation.
    def list
      all.flat_map do |k, v|
        v.is_a?(Hash) ? v.keys.map { |sk| "#{k}.#{sk}" } : [k]
      end.sort
    end

    def all
      encrypted = store.read_encrypted
      return {} unless encrypted && !encrypted.empty?

      json = Crypto.decrypt(encrypted, master_key)
      JSON.parse(json)
    end

    # Export as shell variable assignments.
    # - With project: exports only that group's keys (no prefix).
    # - Without project: flat keys as-is, nested keys as GROUP__KEY.
    def export_env(project: nil)
      secrets = all
      if project
        group = secrets[project]
        return "" unless group.is_a?(Hash)
        group.map { |k, v| "export #{k}=#{Shellwords.escape(v.to_s)}" }.join("\n")
      else
        secrets.flat_map do |k, v|
          if v.is_a?(Hash)
            v.map { |sk, sv| "export #{k.upcase}__#{sk}=#{Shellwords.escape(sv.to_s)}" }
          else
            ["export #{k}=#{Shellwords.escape(v.to_s)}"]
          end
        end.join("\n")
      end
    end

    # Returns a flat hash suitable for env injection.
    # - With project: only that group's key-value pairs.
    # - Without project: flat keys + nested keys as GROUP__KEY.
    def env_hash(project: nil)
      secrets = all
      if project
        group = secrets[project]
        return {} unless group.is_a?(Hash)
        group.transform_values(&:to_s)
      else
        secrets.flat_map do |k, v|
          if v.is_a?(Hash)
            v.map { |sk, sv| ["#{k.upcase}__#{sk}", sv.to_s] }
          else
            [[k, v.to_s]]
          end
        end.to_h
      end
    end

    def self.create!(name:, master_key:, salt:)
      store = Store.new(name)
      store.create!(salt: salt)

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
      store.update_count!(count_leaves(secrets))
    end

    def count_leaves(hash)
      hash.sum { |_, v| v.is_a?(Hash) ? count_leaves(v) : 1 }
    end
  end
end
