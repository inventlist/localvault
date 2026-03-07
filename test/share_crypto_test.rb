require_relative "test_helper"
require "base64"

class ShareCryptoTest < Minitest::Test
  def setup
    @kp_sender    = RbNaCl::PrivateKey.generate
    @kp_recipient = RbNaCl::PrivateKey.generate
    @recipient_pub_b64 = Base64.strict_encode64(@kp_recipient.public_key.to_bytes)
    @recipient_priv_bytes = @kp_recipient.to_bytes
  end

  def test_encrypt_for_returns_base64_string
    payload = LocalVault::ShareCrypto.encrypt_for({ "FOO" => "bar" }, @recipient_pub_b64)
    refute_nil payload
    assert_kind_of String, payload
    # Must be valid base64
    Base64.strict_decode64(payload)
  end

  def test_round_trip_single_secret
    secrets = { "API_KEY" => "secret123" }
    payload = LocalVault::ShareCrypto.encrypt_for(secrets, @recipient_pub_b64)
    result  = LocalVault::ShareCrypto.decrypt_from(payload, @recipient_priv_bytes)
    assert_equal secrets, result
  end

  def test_round_trip_multiple_secrets
    secrets = { "DB_URL" => "postgres://localhost/app", "REDIS" => "redis://localhost" }
    payload = LocalVault::ShareCrypto.encrypt_for(secrets, @recipient_pub_b64)
    result  = LocalVault::ShareCrypto.decrypt_from(payload, @recipient_priv_bytes)
    assert_equal secrets, result
  end

  def test_each_encryption_is_unique
    secrets = { "KEY" => "val" }
    p1 = LocalVault::ShareCrypto.encrypt_for(secrets, @recipient_pub_b64)
    p2 = LocalVault::ShareCrypto.encrypt_for(secrets, @recipient_pub_b64)
    refute_equal p1, p2, "Each encryption should be unique due to random nonce/ephemeral key"
  end

  def test_decrypt_fails_with_wrong_private_key
    secrets  = { "KEY" => "val" }
    payload  = LocalVault::ShareCrypto.encrypt_for(secrets, @recipient_pub_b64)
    wrong_sk = RbNaCl::PrivateKey.generate.to_bytes

    assert_raises(LocalVault::ShareCrypto::DecryptionError) do
      LocalVault::ShareCrypto.decrypt_from(payload, wrong_sk)
    end
  end

  def test_decrypt_fails_with_tampered_payload
    secrets  = { "KEY" => "val" }
    payload  = LocalVault::ShareCrypto.encrypt_for(secrets, @recipient_pub_b64)
    tampered = payload[0..-3] + "XX"

    assert_raises(LocalVault::ShareCrypto::DecryptionError) do
      LocalVault::ShareCrypto.decrypt_from(tampered, @recipient_priv_bytes)
    end
  end

  def test_payload_contains_version_field
    payload = LocalVault::ShareCrypto.encrypt_for({ "K" => "v" }, @recipient_pub_b64)
    inner   = JSON.parse(Base64.strict_decode64(payload))
    assert_equal 1, inner["v"]
  end

  def test_empty_secrets_round_trip
    secrets = {}
    payload = LocalVault::ShareCrypto.encrypt_for(secrets, @recipient_pub_b64)
    result  = LocalVault::ShareCrypto.decrypt_from(payload, @recipient_priv_bytes)
    assert_equal secrets, result
  end
end
