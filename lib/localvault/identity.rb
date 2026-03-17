require "base64"
require "fileutils"

module LocalVault
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
