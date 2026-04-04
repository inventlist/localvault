require "rbnacl"
require "base64"
require "json"

module LocalVault
  # Asymmetric encryption for one-time vault sharing (direct share model).
  #
  # Encrypts a secrets hash for a recipient using their X25519 public key.
  # Uses an ephemeral sender keypair so the sender's identity key is never
  # transmitted. The recipient decrypts with their private key.
  #
  # This is used for the +localvault share --with @handle+ flow (one-time
  # handoff). For ongoing team access, see KeySlot.
  #
  # @example Encrypt and decrypt a share
  #   payload = ShareCrypto.encrypt_for({"KEY" => "val"}, recipient_pub_b64)
  #   secrets = ShareCrypto.decrypt_from(payload, recipient_priv_bytes)
  module ShareCrypto
    # Raised when decryption fails (wrong key, tampered payload, or invalid format).
    class DecryptionError < StandardError; end

    # Encrypt a secrets hash for a recipient using their X25519 public key.
    #
    # Uses an ephemeral sender keypair (NaCl Box construction) so the sender's
    # identity private key is never transmitted. The returned blob contains the
    # ephemeral public key, nonce, and ciphertext.
    #
    # @param secrets [Hash] key-value pairs to encrypt (e.g. {"API_KEY" => "sk-..."})
    # @param recipient_pub_key_b64 [String] recipient's X25519 public key, base64-encoded
    # @return [String] base64-encoded JSON payload containing sender_pub, nonce, and ciphertext
    def self.encrypt_for(secrets, recipient_pub_key_b64)
      recipient_pub = RbNaCl::PublicKey.new(Base64.strict_decode64(recipient_pub_key_b64))
      ephemeral_sk  = RbNaCl::PrivateKey.generate
      box           = RbNaCl::Box.new(recipient_pub, ephemeral_sk)
      nonce         = RbNaCl::Random.random_bytes(RbNaCl::Box.nonce_bytes)
      plaintext     = JSON.generate(secrets)
      ciphertext    = box.box(nonce, plaintext)

      payload = {
        "v"          => 1,
        "sender_pub" => Base64.strict_encode64(ephemeral_sk.public_key.to_bytes),
        "nonce"      => Base64.strict_encode64(nonce),
        "ciphertext" => Base64.strict_encode64(ciphertext)
      }
      Base64.strict_encode64(JSON.generate(payload))
    end

    # Decrypt a shared payload using the recipient's private key.
    #
    # Reverses the envelope produced by {.encrypt_for}, extracting the ephemeral
    # sender public key and using NaCl Box to decrypt.
    #
    # @param encrypted_payload_b64 [String] base64-encoded payload from {.encrypt_for}
    # @param my_private_key_bytes [String] recipient's raw X25519 private key bytes
    # @return [Hash] decrypted secrets (e.g. {"API_KEY" => "sk-..."})
    # @raise [DecryptionError] when the key is wrong, payload is tampered, or format is invalid
    def self.decrypt_from(encrypted_payload_b64, my_private_key_bytes)
      raw     = Base64.strict_decode64(encrypted_payload_b64)
      payload = JSON.parse(raw)
      sender_pub = RbNaCl::PublicKey.new(Base64.strict_decode64(payload.fetch("sender_pub")))
      my_sk      = RbNaCl::PrivateKey.new(my_private_key_bytes)
      box        = RbNaCl::Box.new(sender_pub, my_sk)
      nonce      = Base64.strict_decode64(payload.fetch("nonce"))
      ciphertext = Base64.strict_decode64(payload.fetch("ciphertext"))
      plaintext  = box.open(nonce, ciphertext)
      JSON.parse(plaintext)
    rescue RbNaCl::CryptoError => e
      raise DecryptionError, "Failed to decrypt share: #{e.message}"
    rescue JSON::ParserError, KeyError => e
      raise DecryptionError, "Invalid payload format: #{e.message}"
    rescue ArgumentError => e
      raise DecryptionError, "Invalid payload encoding: #{e.message}"
    end
  end
end
