require_relative "test_helper"
require "base64"
require "json"

# LV-029a: KeySlot module + SyncBundle v2 format
class KeySlotTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key("testpass", @salt)
    @recipient = RbNaCl::PrivateKey.generate
    @recipient_pub_b64 = Base64.strict_encode64(@recipient.public_key.to_bytes)
    @recipient_priv_bytes = @recipient.to_bytes
  end

  def teardown
    teardown_test_home
  end

  # ── KeySlot.create / KeySlot.decrypt round-trip ──

  def test_create_returns_base64_string
    slot = LocalVault::KeySlot.create(@master_key, @recipient_pub_b64)
    refute_nil slot
    assert_kind_of String, slot
    Base64.strict_decode64(slot) # should not raise
  end

  def test_round_trip_recovers_master_key
    slot = LocalVault::KeySlot.create(@master_key, @recipient_pub_b64)
    recovered = LocalVault::KeySlot.decrypt(slot, @recipient_priv_bytes)
    assert_equal @master_key, recovered
  end

  def test_each_slot_is_unique
    s1 = LocalVault::KeySlot.create(@master_key, @recipient_pub_b64)
    s2 = LocalVault::KeySlot.create(@master_key, @recipient_pub_b64)
    refute_equal s1, s2, "Each slot should use a unique ephemeral key"
  end

  def test_decrypt_with_wrong_key_raises
    slot = LocalVault::KeySlot.create(@master_key, @recipient_pub_b64)
    wrong_key = RbNaCl::PrivateKey.generate.to_bytes

    assert_raises(LocalVault::KeySlot::DecryptionError) do
      LocalVault::KeySlot.decrypt(slot, wrong_key)
    end
  end

  def test_decrypt_with_garbage_raises
    assert_raises(LocalVault::KeySlot::DecryptionError) do
      LocalVault::KeySlot.decrypt("not-valid", @recipient_priv_bytes)
    end
  end
end

class SyncBundleV2Test < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key("testpass", @salt)
  end

  def teardown
    teardown_test_home
  end

  # ── Pack produces version 2 ──

  def test_personal_pack_produces_version_1
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    store = LocalVault::Store.new("test")

    blob = LocalVault::SyncBundle.pack(store)
    data = JSON.parse(blob)
    assert_equal 1, data["version"]
    refute data.key?("key_slots")
  end

  def test_pack_v3_includes_key_slots
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    store = LocalVault::Store.new("test")

    blob = LocalVault::SyncBundle.pack_v3(store, owner: "test", key_slots: {})
    data = JSON.parse(blob)
    assert_equal({}, data["key_slots"])
    assert_equal 3, data["version"]
  end

  def test_pack_with_key_slots
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    store = LocalVault::Store.new("test")

    slots = { "alice" => { "pub" => "abc", "enc_key" => "xyz" } }
    blob = LocalVault::SyncBundle.pack_v3(store, owner: "test", key_slots: slots)
    data = JSON.parse(blob)
    assert_equal slots, data["key_slots"]
  end

  # ── Unpack version 2 ──

  def test_unpack_v2_returns_key_slots
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    store = LocalVault::Store.new("test")

    slots = { "alice" => { "pub" => "abc", "enc_key" => "xyz" } }
    blob = LocalVault::SyncBundle.pack_v3(store, owner: "test", key_slots: slots)
    result = LocalVault::SyncBundle.unpack(blob)

    assert_equal slots, result[:key_slots]
  end

  def test_unpack_v2_without_key_slots_defaults_to_empty
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    store = LocalVault::Store.new("test")

    blob = LocalVault::SyncBundle.pack(store)
    result = LocalVault::SyncBundle.unpack(blob)

    assert_equal({}, result[:key_slots])
  end

  # ── Backward compatibility: v1 bundles ──

  def test_unpack_v1_bundle_returns_empty_key_slots
    v1_blob = JSON.generate({
      "version" => 1,
      "meta"    => Base64.strict_encode64("name: test"),
      "secrets" => Base64.strict_encode64("encrypted")
    })

    result = LocalVault::SyncBundle.unpack(v1_blob)
    assert_equal({}, result[:key_slots])
    assert_equal "name: test", result[:meta]
    assert_equal "encrypted", result[:secrets]
  end

  def test_unpack_v1_bundle_still_works_with_expected_name
    v1_blob = JSON.generate({
      "version" => 1,
      "meta"    => Base64.strict_encode64(YAML.dump({ "name" => "test" })),
      "secrets" => Base64.strict_encode64("")
    })

    result = LocalVault::SyncBundle.unpack(v1_blob, expected_name: "test")
    assert_equal({}, result[:key_slots])
  end

  # ── Round-trip v2 ──

  def test_pack_unpack_v2_roundtrip_preserves_all_fields
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault.set("SECRET", "value")
    store = LocalVault::Store.new("test")

    slots = { "bob" => { "pub" => "pubkey", "enc_key" => "enckey" } }
    blob = LocalVault::SyncBundle.pack_v3(store, owner: "test", key_slots: slots)
    result = LocalVault::SyncBundle.unpack(blob)

    assert result[:meta].include?("test")
    refute result[:secrets].empty?
    assert_equal slots, result[:key_slots]
  end

  # ── Version 3+ rejected ──

  def test_unpack_rejects_future_version
    blob = JSON.generate({
      "version" => 99,
      "meta"    => Base64.strict_encode64("test"),
      "secrets" => Base64.strict_encode64("test"),
      "key_slots" => {}
    })

    assert_raises(LocalVault::SyncBundle::UnpackError) do
      LocalVault::SyncBundle.unpack(blob)
    end
  end
end
