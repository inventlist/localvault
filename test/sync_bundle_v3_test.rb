require_relative "test_helper"
require "json"
require "base64"
require "yaml"

class SyncBundleV3Test < Minitest::Test
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

  # ── pack_v3 ──

  def test_pack_v3_includes_owner
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    store = LocalVault::Store.new("test")

    blob = LocalVault::SyncBundle.pack_v3(store, owner: "alice", key_slots: {})
    data = JSON.parse(blob)

    assert_equal 3, data["version"]
    assert_equal "alice", data["owner"]
  end

  def test_pack_v3_includes_key_slots_with_scopes
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    store = LocalVault::Store.new("test")

    slots = {
      "alice" => { "pub" => "apub", "enc_key" => "akey", "scopes" => nil, "blob" => nil },
      "bob" => { "pub" => "bpub", "enc_key" => "bkey", "scopes" => ["myapp"], "blob" => "bblob" }
    }
    blob = LocalVault::SyncBundle.pack_v3(store, owner: "alice", key_slots: slots)
    data = JSON.parse(blob)

    assert_nil data["key_slots"]["alice"]["scopes"]
    assert_equal ["myapp"], data["key_slots"]["bob"]["scopes"]
    assert_equal "bblob", data["key_slots"]["bob"]["blob"]
  end

  # ── unpack v3 ──

  def test_unpack_v3_returns_owner
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    store = LocalVault::Store.new("test")

    blob = LocalVault::SyncBundle.pack_v3(store, owner: "alice", key_slots: {})
    result = LocalVault::SyncBundle.unpack(blob)

    assert_equal "alice", result[:owner]
  end

  def test_unpack_v3_returns_key_slots_with_scopes
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    store = LocalVault::Store.new("test")

    slots = { "bob" => { "pub" => "bp", "enc_key" => "bk", "scopes" => ["db"], "blob" => "bb" } }
    blob = LocalVault::SyncBundle.pack_v3(store, owner: "alice", key_slots: slots)
    result = LocalVault::SyncBundle.unpack(blob)

    assert_equal ["db"], result[:key_slots]["bob"]["scopes"]
    assert_equal "bb", result[:key_slots]["bob"]["blob"]
  end

  # ── backward compat ──

  def test_unpack_v1_returns_nil_owner
    v1 = JSON.generate({ "version" => 1, "meta" => Base64.strict_encode64("name: test"), "secrets" => Base64.strict_encode64("") })
    result = LocalVault::SyncBundle.unpack(v1)
    assert_nil result[:owner]
    assert_equal({}, result[:key_slots])
  end

  def test_unpack_v2_returns_nil_owner
    v2 = JSON.generate({ "version" => 2, "meta" => Base64.strict_encode64("name: test"), "secrets" => Base64.strict_encode64(""), "key_slots" => {} })
    result = LocalVault::SyncBundle.unpack(v2)
    assert_nil result[:owner]
  end

  # ── personal pack writes v1 ──

  def test_pack_personal_writes_v1
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    store = LocalVault::Store.new("test")

    blob = LocalVault::SyncBundle.pack(store)
    data = JSON.parse(blob)

    assert_equal 1, data["version"]
    refute data.key?("key_slots")
    refute data.key?("owner")
  end

  # ── v3 roundtrip ──

  def test_pack_unpack_v3_roundtrip
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault.set("SECRET", "value")
    store = LocalVault::Store.new("test")

    slots = { "bob" => { "pub" => "pubkey", "enc_key" => "enckey", "scopes" => ["myapp"], "blob" => "filtered" } }
    blob = LocalVault::SyncBundle.pack_v3(store, owner: "alice", key_slots: slots)
    result = LocalVault::SyncBundle.unpack(blob)

    assert result[:meta].include?("test")
    refute result[:secrets].empty?
    assert_equal slots, result[:key_slots]
    assert_equal "alice", result[:owner]
  end

  # ── version rejection ──

  def test_unpack_rejects_v99
    blob = JSON.generate({ "version" => 99, "meta" => Base64.strict_encode64("x"), "secrets" => Base64.strict_encode64("x") })
    assert_raises(LocalVault::SyncBundle::UnpackError) { LocalVault::SyncBundle.unpack(blob) }
  end
end
