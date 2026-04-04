require "base64"
require "fileutils"

module LocalVault
  # Manages the user's X25519 identity keypair for vault sharing and sync.
  #
  # The keypair is stored in +~/.localvault/keys/+:
  # - +identity.priv+ (mode 0600) — base64-encoded private key
  # - +identity.pub+ (mode 0644) — base64-encoded public key
  #
  # The public key is published to InventList so others can encrypt
  # key slots for you. The private key never leaves the local machine.
  #
  # @example
  #   Identity.generate!
  #   Identity.public_key       # => "base64..."
  #   Identity.private_key_bytes # => 32 raw bytes
  #   Identity.setup?           # => true (if keypair + token exist)
  module Identity
    # Path to the private key file.
    #
    # @return [String] absolute path to +identity.priv+
    def self.priv_key_path = File.join(Config.keys_path, "identity.priv")

    # Path to the public key file.
    #
    # @return [String] absolute path to +identity.pub+
    def self.pub_key_path  = File.join(Config.keys_path, "identity.pub")

    # Check whether both key files exist on disk.
    #
    # @return [Boolean] true if both +identity.priv+ and +identity.pub+ exist
    def self.exists?
      File.exist?(priv_key_path) && File.exist?(pub_key_path)
    end

    # Generate a new X25519 identity keypair and write to disk.
    #
    # @param force [Boolean] overwrite an existing keypair if true
    # @return [Hash{Symbol => String}] +:public_key+ and +:private_key+ as raw bytes
    # @raise [RuntimeError] when keypair exists and +force+ is false
    def self.generate!(force: false)
      raise "Keypair already exists. Use --force to overwrite." if exists? && !force

      Config.ensure_directories!
      kp = Crypto.generate_keypair

      File.write(priv_key_path, Base64.strict_encode64(kp[:private_key]))
      File.chmod(0o600, priv_key_path)
      File.write(pub_key_path, Base64.strict_encode64(kp[:public_key]))
      File.chmod(0o644, pub_key_path)
      kp
    end

    # Read the public key as a base64-encoded string.
    #
    # @return [String, nil] base64 public key, or nil if not generated
    def self.public_key
      return nil unless File.exist?(pub_key_path)
      File.read(pub_key_path).strip
    end

    # Read the private key as a base64-encoded string.
    #
    # @return [String, nil] base64 private key, or nil if not generated
    def self.private_key_b64
      return nil unless File.exist?(priv_key_path)
      File.read(priv_key_path).strip
    end

    # Read the private key as raw bytes (decoded from base64).
    #
    # @return [String, nil] 32 raw bytes, or nil if not generated
    def self.private_key_bytes
      b64 = private_key_b64
      b64 ? Base64.strict_decode64(b64) : nil
    end

    # Check whether identity is fully configured (keypair exists and token is set).
    #
    # @return [Boolean] true if keypair exists and an API token is configured
    def self.setup?
      exists? && !Config.token.nil? && !Config.token.empty?
    end
  end
end
