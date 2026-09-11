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

    # Ciphertext snapshot of secrets.enc as of the last successful sync. This
    # is the common ancestor a three-way merge needs (see +SyncMerge+); the
    # checksum alone only says *that* both sides drifted, not *which keys*.
    # Same bytes and same file mode as secrets.enc, so it leaks nothing new.
    BASE_FILENAME = ".sync_base"

    attr_reader :vault_name

    def initialize(vault_name)
      @vault_name = vault_name
    end

    def path
      File.join(Config.vaults_path, vault_name, FILENAME)
    end

    def base_path
      File.join(Config.vaults_path, vault_name, BASE_FILENAME)
    end

    def exists?
      File.exist?(path)
    end

    # @return [String, nil] encrypted secrets bytes as of the last sync, or nil
    #   when no snapshot was recorded (older clients, or an empty vault).
    def read_base
      return nil unless File.exist?(base_path)
      bytes = File.binread(base_path)
      bytes.empty? ? nil : bytes
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
    # @param direction [String] "push", "pull", "adopt" or "merge"
    # @param base [String, nil] encrypted secrets bytes to snapshot as the
    #   merge ancestor. Pass the bytes that +checksum+ was computed from. nil
    #   (or empty) removes any previous snapshot.
    def write!(checksum:, direction:, base: nil)
      FileUtils.mkdir_p(File.dirname(path), mode: 0o700)
      data = {
        "last_synced_checksum" => checksum,
        "last_synced_at"       => Time.now.utc.iso8601,
        "direction"            => direction
      }
      File.write(path, YAML.dump(data))
      File.chmod(0o600, path)
      write_base!(base)
    end

    # Record both checksum and ancestor snapshot from a store in one call.
    #
    # @param store [Store] vault store whose current secrets.enc is now synced
    # @param direction [String] see +write!+
    def record!(store, direction:)
      bytes = store.read_encrypted
      write!(checksum: self.class.local_checksum(store), direction: direction, base: bytes)
    end

    def write_base!(bytes)
      if bytes.nil? || bytes.empty?
        FileUtils.rm_f(base_path)
        return
      end
      File.binwrite(base_path, bytes)
      File.chmod(0o600, base_path)
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
