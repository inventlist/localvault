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

    # Initialize a vault instance for reading and writing secrets.
    #
    # @param name [String] the vault name
    # @param master_key [String] 32-byte derived master key
    def initialize(name:, master_key:)
      @name = name
      @master_key = master_key
      @store = Store.new(name)
    end

    # Retrieve a secret by key. Supports dot-notation for nested keys.
    #
    # @param key [String] the secret key, e.g. "API_KEY" or "myapp.DB_URL"
    # @return [String, nil] the secret value, or nil if not found
    # @example
    #   vault.get("myapp.DB_URL")  # => "postgres://..."
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

    # Store a secret. Supports dot-notation for nested keys.
    #
    # @param key [String] the secret key, e.g. "API_KEY" or "myapp.DB_URL"
    # @param value [String] the secret value
    # @return [String] the stored value
    # @raise [InvalidKeyName] when key contains invalid characters
    # @raise [RuntimeError] when a scalar key is used as a group, or when a
    #   scalar is being assigned to an existing group name
    def set(key, value)
      validate_key!(key)
      secrets = all
      if key.include?(".")
        group, subkey = key.split(".", 2)
        secrets[group] ||= {}
        raise "#{group} is a scalar value, not a group" unless secrets[group].is_a?(Hash)
        secrets[group][subkey] = value
      else
        # Refuse to silently clobber an existing group with a scalar. This
        # used to succeed: set("app", "oops") on a vault containing
        # {"app" => {"DB" => ...}} would replace the whole group and lose
        # every nested secret under it.
        if secrets[key].is_a?(Hash)
          raise "'#{key}' is a group containing #{secrets[key].size} secret(s), " \
                "not a scalar. Use `localvault delete #{key}` first if you " \
                "really want to replace the whole group."
        end
        secrets[key] = value
      end
      write_secrets(secrets)
      value
    end

    # Delete a secret by key. Supports dot-notation for nested keys.
    #
    # @param key [String] the secret key to delete
    # @return [String, nil] the deleted value, or nil if not found
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

    # Returns a sorted flat list of all keys. Nested keys use dot-notation.
    #
    # @return [Array<String>] sorted key names, e.g. ["API_KEY", "myapp.DB_URL"]
    def list
      all.flat_map do |k, v|
        v.is_a?(Hash) ? v.keys.map { |sk| "#{k}.#{sk}" } : [k]
      end.sort
    end

    # Decrypt and return all secrets as a hash.
    #
    # @return [Hash] the decrypted secrets hash (may contain nested hashes for groups)
    # @raise [Crypto::DecryptionError] when master key is wrong or data is corrupt
    def all
      encrypted = store.read_encrypted
      return {} unless encrypted && !encrypted.empty?

      json = Crypto.decrypt(encrypted, master_key)
      JSON.parse(json)
    end

    # Export secrets as shell variable assignments (export KEY=value).
    #
    # With +project+, exports only that group's keys without prefix.
    # Without +project+, flat keys export as-is, nested keys as GROUP__KEY.
    # Keys that are not valid shell identifiers are skipped.
    #
    # @param project [String, nil] optional group name to scope the export
    # @param on_skip [#call, nil] called with key name when a key is skipped
    # @return [String] newline-separated export statements
    # @example
    #   vault.export_env(project: "myapp")
    #   # => "export DB_URL=postgres%3A//..."
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
    #
    # With +project+, returns only that group's key-value pairs.
    # Without +project+, flat keys are kept as-is, nested keys become GROUP__KEY.
    # Keys that are not valid shell identifiers are skipped.
    #
    # @param project [String, nil] optional group name to scope the output
    # @param on_skip [#call, nil] called with key name when a key is skipped
    # @return [Hash{String => String}] flat hash of env variable names to values
    # @example
    #   vault.env_hash(project: "myapp")
    #   # => {"DB_URL" => "postgres://...", "SECRET" => "abc"}
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

    # Create a new vault with an empty secrets store.
    #
    # @param name [String] the vault name
    # @param master_key [String] 32-byte derived master key
    # @param salt [String] the salt used for key derivation (stored in metadata)
    # @return [Vault] the newly created vault instance
    # @raise [RuntimeError] when a vault with the same name already exists
    def self.create!(name:, master_key:, salt:)
      store = Store.new(name)
      store.create!(salt: salt)

      empty_json = JSON.generate({})
      encrypted = Crypto.encrypt(empty_json, master_key)
      store.write_encrypted(encrypted)

      new(name: name, master_key: master_key)
    end

    # Re-encrypt the vault with a new passphrase and salt.
    #
    # Decrypts all secrets with the current key, derives a new master key,
    # and re-encrypts everything. Returns a new Vault instance with the new key.
    #
    # @param new_passphrase [String] the new passphrase
    # @param new_salt [String] optional salt (generated if omitted)
    # @return [Vault] a new vault instance with the updated master key
    def rekey(new_passphrase, new_salt: Crypto.generate_salt)
      secrets = all
      new_master_key = Crypto.derive_master_key(new_passphrase, new_salt)

      store.create_meta!(salt: new_salt)
      new_vault = self.class.new(name: name, master_key: new_master_key)
      new_vault.send(:write_secrets, secrets)
      new_vault
    end

    # Open an existing vault by deriving the master key from a passphrase.
    #
    # @param name [String] the vault name
    # @param passphrase [String] the passphrase to derive the master key
    # @return [Vault] the opened vault instance
    # @raise [RuntimeError] when the vault does not exist or has no salt
    def self.open(name:, passphrase:)
      store = Store.new(name)
      raise "Vault '#{name}' does not exist" unless store.exists?

      salt = store.salt
      raise "Vault '#{name}' has no salt in metadata" unless salt

      master_key = Crypto.derive_master_key(passphrase, salt)
      new(name: name, master_key: master_key)
    end

    # Bulk-set key-value pairs in a single decrypt/encrypt cycle.
    #
    # Supports nested hashes: { "app" => { "DB" => "..." } } merges into group "app".
    # Dot-notation keys are also supported in the top-level hash.
    #
    # @param hash [Hash] key-value pairs to merge into the vault
    # @return [void]
    # @raise [InvalidKeyName] when any key contains invalid characters
    # @raise [RuntimeError] when a scalar key is used as a group, or when a
    #   scalar is being assigned to an existing group name
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
            # Same guard as Vault#set: don't silently clobber a group with
            # a scalar. This protects bulk `import` and `receive` flows.
            if secrets[k].is_a?(Hash)
              raise "'#{k}' is a group containing #{secrets[k].size} secret(s), " \
                    "not a scalar. Delete the group first if you really want " \
                    "to replace it with a scalar."
            end
            secrets[k] = v.to_s
          end
        end
      end
      write_secrets(secrets)
    end

    # Return a subset of secrets matching the given scopes.
    #
    # Scopes can be group names (returns entire nested hash) or flat key names.
    # +nil+ means full access (returns all). Empty array means nothing.
    #
    # @param scopes [Array<String>, nil] list of group/key names, or nil for all
    # @return [Hash] filtered secrets
    def filter(scopes)
      return all if scopes.nil?
      return {} if scopes.empty?

      secrets = all
      result = {}
      scopes.each do |scope|
        value = secrets[scope]
        result[scope] = value if value
      end
      result
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
