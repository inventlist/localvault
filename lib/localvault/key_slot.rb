require "rbnacl"
require "base64"

module LocalVault
  # Encrypts/decrypts a vault's master key for a specific user's X25519 public key.
  #
  # Key slots enable multi-user vault access via sync. Each authorized user
  # has a slot containing the vault's master key encrypted to their public key.
  # Uses an ephemeral sender keypair (X25519 Box) — same construction as ShareCrypto.
  #
  # @example Create and decrypt a key slot
  #   slot = KeySlot.create(master_key, recipient_pub_b64)
  #   recovered = KeySlot.decrypt(slot, recipient_priv_bytes)
  #   recovered == master_key  # => true
  module KeySlot
    # Raised when decryption fails (wrong key, tampered data, or invalid format).
    class DecryptionError < StandardError; end

    # Encrypt a master key for a recipient's X25519 public key.
    # Returns a base64-encoded ciphertext string.
    # Uses an ephemeral sender keypair (same Box construction as ShareCrypto).
    def self.create(master_key, recipient_pub_key_b64)
      recipient_pub = RbNaCl::PublicKey.new(Base64.strict_decode64(recipient_pub_key_b64))
      ephemeral_sk  = RbNaCl::PrivateKey.generate
      box           = RbNaCl::Box.new(recipient_pub, ephemeral_sk)
      nonce         = RbNaCl::Random.random_bytes(RbNaCl::Box.nonce_bytes)
      ciphertext    = box.box(nonce, master_key)

      payload = {
        "v"          => 1,
        "sender_pub" => Base64.strict_encode64(ephemeral_sk.public_key.to_bytes),
        "nonce"      => Base64.strict_encode64(nonce),
        "ciphertext" => Base64.strict_encode64(ciphertext)
      }
      Base64.strict_encode64(JSON.generate(payload))
    end

    # Decrypt a key slot using the recipient's private key.
    # Returns the raw master key bytes.
    def self.decrypt(slot_b64, my_private_key_bytes)
      raw        = Base64.strict_decode64(slot_b64)
      payload    = JSON.parse(raw)
      sender_pub = RbNaCl::PublicKey.new(Base64.strict_decode64(payload.fetch("sender_pub")))
      my_sk      = RbNaCl::PrivateKey.new(my_private_key_bytes)
      box        = RbNaCl::Box.new(sender_pub, my_sk)
      nonce      = Base64.strict_decode64(payload.fetch("nonce"))
      ciphertext = Base64.strict_decode64(payload.fetch("ciphertext"))
      box.open(nonce, ciphertext)
    rescue RbNaCl::CryptoError => e
      raise DecryptionError, "Failed to decrypt key slot: #{e.message}"
    rescue JSON::ParserError, KeyError => e
      raise DecryptionError, "Invalid key slot format: #{e.message}"
    rescue ArgumentError => e
      raise DecryptionError, "Invalid key slot encoding: #{e.message}"
    end
  end
end
