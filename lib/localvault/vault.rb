require "json"
require "shellwords"

module LocalVault
  # Encrypted key-value store backed by a single JSON blob.
  #
  # Each vault has a name, a master key (derived from passphrase + salt),
  # and a Store that handles file I/O. Secrets are stored as a flat or
  # nested JSON hash, encrypted with XSalsa20-Poly1305.
  #
  # Supports dot-notation for nested keys: +"project.SECRET_KEY"+
  # groups secrets under a project namespace.
  #
  # @example Basic usage
  #   vault = Vault.create!(name: "default", master_key: key, salt: salt)
  #   vault.set("API_KEY", "sk-...")
  #   vault.get("API_KEY")    # => "sk-..."
  #   vault.list              # => ["API_KEY"]
  #   vault.export_env        # => "export API_KEY=sk-..."
  #
  # @example Nested keys
  #   vault.set("myapp.DB_URL", "postgres://...")
  #   vault.get("myapp.DB_URL")  # => "postgres://..."
  #   vault.env_hash(project: "myapp")  # => {"DB_URL" => "postgres://..."}
  class Vault
    # Raised when a key name contains invalid characters.
    class InvalidKeyName < StandardError; end

    # Shell-safe pattern: letters, digits, underscores. Must start with letter or underscore.
    KEY_SEGMENT_PATTERN = /\A[A-Za-z_][A-Za-z0-9_]*\z/

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
        value = all[key]
        value.is_a?(Hash) ? nil : value
      end
    end

    def set(key, value)
      validate_key!(key)
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
    # Keys that aren't valid shell identifiers are skipped. Pass on_skip: callable
    # to be notified (e.g., for warnings).
    def export_env(project: nil, on_skip: nil)
      secrets = all
      if project
        group = secrets[project]
        return "" unless group.is_a?(Hash)
        group.filter_map do |k, v|
          if shell_safe_key?(k)
            "export #{k}=#{Shellwords.escape(v.to_s)}"
          else
            on_skip&.call(k)
            nil
          end
        end.join("\n")
      else
        secrets.flat_map do |k, v|
          if v.is_a?(Hash)
            unless shell_safe_key?(k)
              on_skip&.call(k)
              next []
            end
            v.filter_map do |sk, sv|
              if shell_safe_key?(sk)
                "export #{k.upcase}__#{sk}=#{Shellwords.escape(sv.to_s)}"
              else
                on_skip&.call("#{k}.#{sk}")
                nil
              end
            end
          else
            if shell_safe_key?(k)
              ["export #{k}=#{Shellwords.escape(v.to_s)}"]
            else
              on_skip&.call(k)
              []
            end
          end
        end.join("\n")
      end
    end

    # Returns a flat hash suitable for env injection.
    # - With project: only that group's key-value pairs.
    # - Without project: flat keys + nested keys as GROUP__KEY.
    # Keys that aren't valid shell identifiers are skipped. Pass on_skip: callable
    # to be notified.
    def env_hash(project: nil, on_skip: nil)
      secrets = all
      if project
        group = secrets[project]
        return {} unless group.is_a?(Hash)
        group.each_with_object({}) do |(k, v), h|
          if shell_safe_key?(k)
            h[k] = v.to_s
          else
            on_skip&.call(k)
          end
        end
      else
        secrets.each_with_object({}) do |(k, v), h|
          if v.is_a?(Hash)
            unless shell_safe_key?(k)
              on_skip&.call(k)
              next
            end
            v.each do |sk, sv|
              if shell_safe_key?(sk)
                h["#{k.upcase}__#{sk}"] = sv.to_s
              else
                on_skip&.call("#{k}.#{sk}")
              end
            end
          else
            if shell_safe_key?(k)
              h[k] = v.to_s
            else
              on_skip&.call(k)
            end
          end
        end
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

    # Bulk-set: merges all key-value pairs in a single decrypt/encrypt cycle.
    # Supports nested hashes: { "app" => { "DB" => "..." } } merges into group "app".
    def merge(hash)
      secrets = all
      hash.each do |k, v|
        if v.is_a?(Hash)
          validate_key_segment!(k)
          secrets[k] ||= {}
          raise "#{k} is a scalar value, not a group" unless secrets[k].is_a?(Hash)
          v.each do |sk, sv|
            validate_key_segment!(sk)
            secrets[k][sk] = sv.to_s
          end
        else
          validate_key!(k)
          if k.include?(".")
            group, subkey = k.split(".", 2)
            secrets[group] ||= {}
            raise "#{group} is a scalar value, not a group" unless secrets[group].is_a?(Hash)
            secrets[group][subkey] = v.to_s
          else
            secrets[k] = v.to_s
          end
        end
      end
      write_secrets(secrets)
    end

    private

    def shell_safe_key?(key)
      key.is_a?(String) && key.match?(KEY_SEGMENT_PATTERN)
    end

    def validate_key!(key)
      raise InvalidKeyName, "Key name cannot be empty" if key.nil? || key.empty?
      if key.include?(".")
        group, subkey = key.split(".", 2)
        validate_key_segment!(group)
        validate_key_segment!(subkey)
      else
        validate_key_segment!(key)
      end
    end

    def validate_key_segment!(segment)
      raise InvalidKeyName, "Key segment cannot be empty" if segment.nil? || segment.empty?
      raise InvalidKeyName, "Key '#{segment}' contains invalid characters (allowed: A-Z, a-z, 0-9, underscore)" unless segment.match?(KEY_SEGMENT_PATTERN)
      raise InvalidKeyName, "Key '#{segment}' is too long (max 128)" if segment.length > 128
    end

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
