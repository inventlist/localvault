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
    def self.priv_key_path = File.join(Config.keys_path, "identity.priv")
    def self.pub_key_path  = File.join(Config.keys_path, "identity.pub")

    def self.exists?
      File.exist?(priv_key_path) && File.exist?(pub_key_path)
    end

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

    def self.public_key
      return nil unless File.exist?(pub_key_path)
      File.read(pub_key_path).strip
    end

    def self.private_key_b64
      return nil unless File.exist?(priv_key_path)
      File.read(priv_key_path).strip
    end

    def self.private_key_bytes
      b64 = private_key_b64
      b64 ? Base64.strict_decode64(b64) : nil
    end

    def self.setup?
      exists? && !Config.token.nil? && !Config.token.empty?
    end
  end
end
