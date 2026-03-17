require "rbnacl"
require "base64"
require "json"

module LocalVault
  module ShareCrypto
    class DecryptionError < StandardError; end

    # Encrypt a secrets hash for a recipient using their X25519 public key.
    # Uses an ephemeral sender keypair (Box construction) so the sender's
    # identity private key is never transmitted.
    # Returns a base64-encoded JSON blob.
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

    # Decrypt an encrypted_payload using the recipient's private key.
    # Returns the decrypted secrets hash { "KEY" => "value", ... }.
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
