require_relative "test_helper"

class CryptoTest < Minitest::Test
  def test_generate_salt_returns_16_bytes
    salt = LocalVault::Crypto.generate_salt
    assert_equal 16, salt.bytesize
  end

  def test_generate_salt_is_random
    salt1 = LocalVault::Crypto.generate_salt
    salt2 = LocalVault::Crypto.generate_salt
    refute_equal salt1, salt2
  end

  def test_derive_master_key_returns_32_bytes
    salt = LocalVault::Crypto.generate_salt
    key = LocalVault::Crypto.derive_master_key("my-passphrase", salt)
    assert_equal 32, key.bytesize
  end

  def test_derive_master_key_deterministic
    salt = LocalVault::Crypto.generate_salt
    key1 = LocalVault::Crypto.derive_master_key("my-passphrase", salt)
    key2 = LocalVault::Crypto.derive_master_key("my-passphrase", salt)
    assert_equal key1, key2
  end

  def test_derive_master_key_different_passphrase_different_key
    salt = LocalVault::Crypto.generate_salt
    key1 = LocalVault::Crypto.derive_master_key("passphrase-one", salt)
    key2 = LocalVault::Crypto.derive_master_key("passphrase-two", salt)
    refute_equal key1, key2
  end

  def test_derive_master_key_different_salt_different_key
    salt1 = LocalVault::Crypto.generate_salt
    salt2 = LocalVault::Crypto.generate_salt
    key1 = LocalVault::Crypto.derive_master_key("same-passphrase", salt1)
    key2 = LocalVault::Crypto.derive_master_key("same-passphrase", salt2)
    refute_equal key1, key2
  end

  def test_encrypt_decrypt_roundtrip
    key = RbNaCl::Random.random_bytes(32)
    plaintext = "hello, secrets!"

    ciphertext = LocalVault::Crypto.encrypt(plaintext, key)
    decrypted = LocalVault::Crypto.decrypt(ciphertext, key)

    assert_equal plaintext, decrypted
  end

  def test_encrypt_produces_different_ciphertext_each_time
    key = RbNaCl::Random.random_bytes(32)
    plaintext = "same message"

    ct1 = LocalVault::Crypto.encrypt(plaintext, key)
    ct2 = LocalVault::Crypto.encrypt(plaintext, key)

    refute_equal ct1, ct2
  end

  def test_decrypt_with_wrong_key_raises
    key1 = RbNaCl::Random.random_bytes(32)
    key2 = RbNaCl::Random.random_bytes(32)
    ciphertext = LocalVault::Crypto.encrypt("secret", key1)

    assert_raises(LocalVault::Crypto::DecryptionError) do
      LocalVault::Crypto.decrypt(ciphertext, key2)
    end
  end

  def test_decrypt_with_tampered_data_raises
    key = RbNaCl::Random.random_bytes(32)
    ciphertext = LocalVault::Crypto.encrypt("secret", key)

    # Tamper with the last byte
    tampered = ciphertext.dup
    tampered[-1] = (tampered[-1].ord ^ 0xFF).chr

    assert_raises(LocalVault::Crypto::DecryptionError) do
      LocalVault::Crypto.decrypt(tampered, key)
    end
  end

  def test_encrypt_empty_string
    key = RbNaCl::Random.random_bytes(32)
    ciphertext = LocalVault::Crypto.encrypt("", key)
    assert_equal "", LocalVault::Crypto.decrypt(ciphertext, key)
  end

  def test_encrypt_large_payload
    key = RbNaCl::Random.random_bytes(32)
    plaintext = "x" * 100_000
    ciphertext = LocalVault::Crypto.encrypt(plaintext, key)
    assert_equal plaintext, LocalVault::Crypto.decrypt(ciphertext, key)
  end

  def test_generate_keypair
    keypair = LocalVault::Crypto.generate_keypair
    assert_equal 32, keypair[:public_key].bytesize
    assert_equal 32, keypair[:private_key].bytesize
  end

  def test_encrypt_decrypt_private_key_roundtrip
    master_key = RbNaCl::Random.random_bytes(32)
    keypair = LocalVault::Crypto.generate_keypair

    encrypted = LocalVault::Crypto.encrypt_private_key(keypair[:private_key], master_key)
    decrypted = LocalVault::Crypto.decrypt_private_key(encrypted, master_key)

    assert_equal keypair[:private_key], decrypted
  end

  def test_encrypt_private_key_with_wrong_master_key_raises
    master_key1 = RbNaCl::Random.random_bytes(32)
    master_key2 = RbNaCl::Random.random_bytes(32)
    keypair = LocalVault::Crypto.generate_keypair

    encrypted = LocalVault::Crypto.encrypt_private_key(keypair[:private_key], master_key1)

    assert_raises(LocalVault::Crypto::DecryptionError) do
      LocalVault::Crypto.decrypt_private_key(encrypted, master_key2)
    end
  end

  def test_ciphertext_format_includes_nonce
    key = RbNaCl::Random.random_bytes(32)
    ciphertext = LocalVault::Crypto.encrypt("test", key)

    # XSalsa20 nonce is 24 bytes, ciphertext is at least nonce + auth tag (16) + plaintext
    assert ciphertext.bytesize >= 24 + 16 + 4
  end
end
