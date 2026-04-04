begin
  require "rbnacl"
rescue LoadError => e
  if e.message.include?("libsodium") || e.message.include?("sodium")
    $stderr.puts <<~MSG

      ERROR: libsodium is not installed.

      LocalVault requires libsodium for encryption. Install it for your platform:

        macOS:         brew install libsodium
        Ubuntu/Debian: sudo apt-get install libsodium-dev
        Fedora/RHEL:   sudo dnf install libsodium-devel
        Arch Linux:    sudo pacman -S libsodium
        Alpine:        apk add libsodium-dev

      Then retry: gem install localvault

    MSG
  end
  raise
end

module LocalVault
  # Cryptographic primitives for vault encryption and key derivation.
  #
  # Uses libsodium (via RbNaCl) exclusively:
  # - Argon2id for passphrase → master key derivation (memory-hard KDF)
  # - XSalsa20-Poly1305 for authenticated symmetric encryption
  # - X25519 for asymmetric keypair generation (used by Identity + KeySlot)
  #
  # @example Derive a master key and encrypt
  #   salt = Crypto.generate_salt
  #   key  = Crypto.derive_master_key("my passphrase", salt)
  #   ct   = Crypto.encrypt("secret data", key)
  #   Crypto.decrypt(ct, key)  # => "secret data"
  module Crypto
    # Raised when decryption fails (wrong key, tampered data, or corrupt ciphertext).
    class DecryptionError < StandardError; end

    SALT_BYTES = 16
    NONCE_BYTES = RbNaCl::SecretBoxes::XSalsa20Poly1305.nonce_bytes  # 24
    KEY_BYTES   = RbNaCl::SecretBoxes::XSalsa20Poly1305.key_bytes    # 32

    # Argon2id parameters (moderate — fast enough for CLI, strong enough for secrets)
    ARGON2_OPSLIMIT = 2
    ARGON2_MEMLIMIT = 67_108_864 # 64 MB

    # Generate a random salt for key derivation.
    #
    # @return [String] 16 random bytes
    def self.generate_salt
      RbNaCl::Random.random_bytes(SALT_BYTES)
    end

    # Derive a 32-byte master key from a passphrase using Argon2id.
    #
    # @param passphrase [String] the user's passphrase
    # @param salt [String] 16-byte salt
    # @return [String] 32-byte derived key
    def self.derive_master_key(passphrase, salt)
      RbNaCl::PasswordHash.argon2id(
        passphrase,
        salt,
        ARGON2_OPSLIMIT,
        ARGON2_MEMLIMIT,
        KEY_BYTES
      )
    end

    # Encrypt plaintext with XSalsa20-Poly1305. Prepends a random nonce.
    #
    # @param plaintext [String] data to encrypt
    # @param key [String] 32-byte symmetric key
    # @return [String] nonce (24 bytes) + ciphertext
    def self.encrypt(plaintext, key)
      box = RbNaCl::SecretBox.new(key)
      nonce = RbNaCl::Random.random_bytes(NONCE_BYTES)
      ciphertext = box.encrypt(nonce, plaintext)
      nonce + ciphertext
    end

    # Decrypt ciphertext produced by +encrypt+. Expects nonce prepended.
    #
    # @param ciphertext_with_nonce [String] nonce (24 bytes) + ciphertext
    # @param key [String] 32-byte symmetric key
    # @return [String] decrypted plaintext
    # @raise [DecryptionError] when the key is wrong or data is tampered
    def self.decrypt(ciphertext_with_nonce, key)
      box = RbNaCl::SecretBox.new(key)
      nonce = ciphertext_with_nonce[0, NONCE_BYTES]
      ciphertext = ciphertext_with_nonce[NONCE_BYTES..]
      box.decrypt(nonce, ciphertext)
    rescue RbNaCl::CryptoError => e
      raise DecryptionError, "Decryption failed: #{e.message}"
    end

    # Generate an X25519 keypair for asymmetric encryption.
    #
    # @return [Hash{Symbol => String}] +:public_key+ and +:private_key+ as raw bytes
    def self.generate_keypair
      sk = RbNaCl::PrivateKey.generate
      {
        public_key: sk.public_key.to_bytes,
        private_key: sk.to_bytes
      }
    end

    # Encrypt a private key with a master key (convenience wrapper around +encrypt+).
    #
    # @param private_key_bytes [String] raw private key bytes
    # @param master_key [String] 32-byte symmetric key
    # @return [String] nonce + ciphertext
    def self.encrypt_private_key(private_key_bytes, master_key)
      encrypt(private_key_bytes, master_key)
    end

    # Decrypt a private key with a master key (convenience wrapper around +decrypt+).
    #
    # @param encrypted_bytes [String] nonce + ciphertext from +encrypt_private_key+
    # @param master_key [String] 32-byte symmetric key
    # @return [String] raw private key bytes
    # @raise [DecryptionError] when the key is wrong or data is tampered
    def self.decrypt_private_key(encrypted_bytes, master_key)
      decrypt(encrypted_bytes, master_key)
    end
  end
end
