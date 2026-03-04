require "yaml"
require "fileutils"
require "tempfile"
require "base64"

module LocalVault
  class Store
    attr_reader :vault_name

    def initialize(vault_name)
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

      FileUtils.mkdir_p(vault_path)
      meta = {
        "name" => vault_name,
        "created_at" => Time.now.utc.iso8601,
        "version" => 1,
        "salt" => Base64.strict_encode64(salt)
      }
      File.write(meta_path, YAML.dump(meta))
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

    def read_encrypted
      return nil unless File.exist?(secrets_path)
      File.binread(secrets_path)
    end

    def write_encrypted(bytes)
      FileUtils.mkdir_p(vault_path)

      # Atomic write: write to temp file, then rename
      tmp = Tempfile.new("localvault", vault_path)
      tmp.binmode
      tmp.write(bytes)
      tmp.close
      File.rename(tmp.path, secrets_path)
    rescue StandardError
      tmp&.close
      tmp&.unlink
      raise
    end

    def destroy!
      FileUtils.rm_rf(vault_path)
    end

    def self.list_vaults
      vaults_dir = Config.vaults_path
      return [] unless File.directory?(vaults_dir)

      Dir.children(vaults_dir)
        .select { |name| File.directory?(File.join(vaults_dir, name)) }
        .sort
    end
  end
end
