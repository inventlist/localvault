require "rbnacl"

module LocalVault
  module Crypto
    class DecryptionError < StandardError; end

    SALT_BYTES = 16
    NONCE_BYTES = RbNaCl::SecretBoxes::XSalsa20Poly1305.nonce_bytes  # 24
    KEY_BYTES   = RbNaCl::SecretBoxes::XSalsa20Poly1305.key_bytes    # 32

    # Argon2id parameters (moderate — fast enough for CLI, strong enough for secrets)
    ARGON2_OPSLIMIT = 2
    ARGON2_MEMLIMIT = 67_108_864 # 64 MB

    def self.generate_salt
      RbNaCl::Random.random_bytes(SALT_BYTES)
    end

    def self.derive_master_key(passphrase, salt)
      RbNaCl::PasswordHash.argon2id(
        passphrase,
        salt,
        ARGON2_OPSLIMIT,
        ARGON2_MEMLIMIT,
        KEY_BYTES
      )
    end

    def self.encrypt(plaintext, key)
      box = RbNaCl::SecretBox.new(key)
      nonce = RbNaCl::Random.random_bytes(NONCE_BYTES)
      ciphertext = box.encrypt(nonce, plaintext)
      nonce + ciphertext
    end

    def self.decrypt(ciphertext_with_nonce, key)
      box = RbNaCl::SecretBox.new(key)
      nonce = ciphertext_with_nonce[0, NONCE_BYTES]
      ciphertext = ciphertext_with_nonce[NONCE_BYTES..]
      box.decrypt(nonce, ciphertext)
    rescue RbNaCl::CryptoError => e
      raise DecryptionError, "Decryption failed: #{e.message}"
    end

    def self.generate_keypair
      sk = RbNaCl::PrivateKey.generate
      {
        public_key: sk.public_key.to_bytes,
        private_key: sk.to_bytes
      }
    end

    def self.encrypt_private_key(private_key_bytes, master_key)
      encrypt(private_key_bytes, master_key)
    end

    def self.decrypt_private_key(encrypted_bytes, master_key)
      decrypt(encrypted_bytes, master_key)
    end
  end
end
