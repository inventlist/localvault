require "yaml"
require "digest"
require "time"

module LocalVault
  # Per-vault sync state tracking. Stores the checksum of secrets.enc at the
  # time of the last successful push or pull, so the next `localvault sync`
  # can determine whether local, remote, or both sides have changed.
  #
  # Stored as `~/.localvault/vaults/<name>/.sync_state` (YAML, mode 0600).
  # Separate from meta.yml because meta.yml is part of the SyncBundle and
  # including sync bookkeeping there would create a checksum feedback loop.
  class SyncState
    FILENAME = ".sync_state"

    attr_reader :vault_name

    def initialize(vault_name)
      @vault_name = vault_name
    end

    def path
      File.join(Config.vaults_path, vault_name, FILENAME)
    end

    def exists?
      File.exist?(path)
    end

    # @return [Hash, nil] parsed YAML data or nil
    def read
      return nil unless exists?
      YAML.safe_load_file(path)
    rescue Psych::SyntaxError
      nil
    end

    def last_synced_checksum
      read&.dig("last_synced_checksum")
    end

    def last_synced_at
      read&.dig("last_synced_at")
    end

    # Record a successful sync operation.
    #
    # @param checksum [String] SHA256 hex of the local secrets.enc
    # @param direction [String] "push" or "pull"
    def write!(checksum:, direction:)
      FileUtils.mkdir_p(File.dirname(path), mode: 0o700)
      data = {
        "last_synced_checksum" => checksum,
        "last_synced_at"       => Time.now.utc.iso8601,
        "direction"            => direction
      }
      File.write(path, YAML.dump(data))
      File.chmod(0o600, path)
    end

    # Compute the SHA256 hex digest of a vault's local secrets.enc.
    #
    # @param store [Store] vault store
    # @return [String, nil] hex digest or nil if no secrets file
    def self.local_checksum(store)
      bytes = store.read_encrypted
      return nil if bytes.nil? || bytes.empty?
      Digest::SHA256.hexdigest(bytes)
    end
  end
end
