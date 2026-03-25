require "yaml"
require "fileutils"
require "tempfile"
require "base64"
require "time"

module LocalVault
  # File-system storage for a single vault's encrypted data and metadata.
  #
  # Each vault lives at +~/.localvault/vaults/<name>/+ with two files:
  # - +meta.yml+ — salt, creation date, version, secret count
  # - +secrets.enc+ — encrypted JSON blob (XSalsa20-Poly1305)
  #
  # Uses atomic writes (tempfile + rename) to prevent corruption.
  # All directories are created with mode 0700, all files with mode 0600.
  #
  # @example
  #   store = Store.new("production")
  #   store.create!(salt: Crypto.generate_salt)
  #   store.write_encrypted(ciphertext)
  #   store.read_encrypted  # => ciphertext bytes
  class Store
    # Raised when a vault name contains invalid characters or path traversal.
    class InvalidVaultName < StandardError; end

    # Letters, digits, underscore, dash. Must start with alphanumeric.
    VAULT_NAME_PATTERN = /\A[a-zA-Z0-9][a-zA-Z0-9_\-]*\z/

    attr_reader :vault_name

    def initialize(vault_name)
      validate_vault_name!(vault_name)
      @vault_name = vault_name
    end

    def vault_path
      File.join(Config.vaults_path, vault_name)
    end

    def secrets_path
      File.join(vault_path, "secrets.enc")
    end

    def meta_path
      File.join(vault_path, "meta.yml")
    end

    def exists?
      File.directory?(vault_path) && File.exist?(meta_path)
    end

    def create!(salt:)
      raise "Vault '#{vault_name}' already exists" if exists?

      FileUtils.mkdir_p(vault_path, mode: 0o700)
      new_meta = {
        "name"       => vault_name,
        "created_at" => Time.now.utc.iso8601,
        "version"    => 1,
        "salt"       => Base64.strict_encode64(salt),
        "count"      => 0
      }
      write_meta(new_meta)
    end

    def meta
      return nil unless File.exist?(meta_path)
      YAML.safe_load_file(meta_path)
    end

    def salt
      m = meta
      return nil unless m && m["salt"]
      Base64.strict_decode64(m["salt"])
    end

    def count
      meta&.dig("count") || 0
    end

    def update_count!(n)
      m = meta
      return unless m
      m["count"] = n
      write_meta(m)
    end

    def read_encrypted
      return nil unless File.exist?(secrets_path)
      File.binread(secrets_path)
    end

    def write_encrypted(bytes)
      FileUtils.mkdir_p(vault_path, mode: 0o700)

      # Atomic write: write to temp file, then rename
      tmp = Tempfile.new("localvault", vault_path)
      tmp.binmode
      tmp.write(bytes)
      tmp.close
      File.rename(tmp.path, secrets_path)
      File.chmod(0o600, secrets_path)
    rescue StandardError
      tmp&.close
      tmp&.unlink
      raise
    end

    def create_meta!(salt:)
      existing = meta
      new_meta = {
        "name"       => vault_name,
        "created_at" => existing&.dig("created_at") || Time.now.utc.iso8601,
        "version"    => 1,
        "salt"       => Base64.strict_encode64(salt)
      }
      write_meta(new_meta)
    end

    def destroy!
      FileUtils.rm_rf(vault_path)
    end

    private

    def write_meta(data)
      File.write(meta_path, YAML.dump(data))
      File.chmod(0o600, meta_path)
    end

    def validate_vault_name!(name)
      raise InvalidVaultName, "Vault name cannot be empty" if name.nil? || name.to_s.empty?
      name = name.to_s
      raise InvalidVaultName, "Vault name '#{name}' contains invalid characters (allowed: a-z, 0-9, dash, underscore)" unless name.match?(VAULT_NAME_PATTERN)
      raise InvalidVaultName, "Vault name '#{name}' is too long (max 64)" if name.length > 64
    end

    public

    def self.list_vaults
      vaults_dir = Config.vaults_path
      return [] unless File.directory?(vaults_dir)

      Dir.children(vaults_dir)
        .select { |name| File.directory?(File.join(vaults_dir, name)) }
        .sort
    end
  end
end
