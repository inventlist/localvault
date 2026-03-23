require_relative "test_helper"
require "minitest/mock"
require "localvault/cli"
require "yaml"
require "base64"
require "json"

# LV-029c: Key-slot-aware sync pull
class SyncPullKeySlotTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @passphrase = "test-pass"
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(@passphrase, @salt)
    @fake_client = FakePullClient.new
  end

  def teardown
    LocalVault::SessionCache.clear("myvault")
    teardown_test_home
  end

  # ── Pull with owner slot decrypts and caches master key ──

  def test_pull_with_matching_slot_caches_master_key
    setup_identity_and_login
    blob = build_v2_blob_with_owner_slot

    @fake_client.set_response(:pull_vault, blob)
    pull_and_capture("myvault")

    # The master key should now be in SessionCache
    cached = LocalVault::SessionCache.get("myvault")
    refute_nil cached, "Pull with matching key slot should cache the master key"
    assert_equal @master_key, cached
  end

  def test_pull_with_matching_slot_prints_unlocked_message
    setup_identity_and_login
    blob = build_v2_blob_with_owner_slot

    @fake_client.set_response(:pull_vault, blob)
    out, = pull_and_capture("myvault")

    assert_match(/pulled/i, out)
    # Should NOT say "Unlock it with" since we already unlocked via slot
    refute_match(/unlock it with/i, out)
  end

  # ── Pull with no matching slot — legacy behavior ──

  def test_pull_without_matching_slot_does_not_cache
    setup_identity_and_login
    # Build blob with a slot for someone else, not the current user
    blob = build_v2_blob_with_foreign_slot

    @fake_client.set_response(:pull_vault, blob)
    pull_and_capture("myvault")

    cached = LocalVault::SessionCache.get("myvault")
    assert_nil cached, "Pull without matching slot should not cache master key"
  end

  def test_pull_without_matching_slot_prints_unlock_hint
    setup_identity_and_login
    blob = build_v2_blob_with_foreign_slot

    @fake_client.set_response(:pull_vault, blob)
    out, = pull_and_capture("myvault")

    assert_match(/unlock it with/i, out)
  end

  def test_pull_v1_bundle_keeps_legacy_behavior
    setup_identity_and_login
    blob = build_v1_blob

    @fake_client.set_response(:pull_vault, blob)
    out, = pull_and_capture("myvault")

    cached = LocalVault::SessionCache.get("myvault")
    assert_nil cached
    assert_match(/unlock it with/i, out)
  end

  # ── Pull with malformed slot — clean error ──

  def test_pull_with_malformed_slot_does_not_crash
    setup_identity_and_login
    handle = LocalVault::Config.inventlist_handle
    blob = build_v2_blob_with_slots({
      handle => { "pub" => "garbage", "enc_key" => "not-valid-base64!!!" }
    })

    @fake_client.set_response(:pull_vault, blob)
    out, err = pull_and_capture("myvault")

    # Should still pull the files — just can't auto-unlock
    assert_match(/pulled/i, out)
    assert_match(/unlock it with/i, out)
    assert LocalVault::Store.new("myvault").exists?
  end

  def test_pull_with_wrong_private_key_falls_back
    # Generate identity but build slot for a different keypair
    setup_identity_and_login
    other_recipient = RbNaCl::PrivateKey.generate
    other_pub_b64 = Base64.strict_encode64(other_recipient.public_key.to_bytes)
    enc_key = LocalVault::KeySlot.create(@master_key, other_pub_b64)

    handle = LocalVault::Config.inventlist_handle
    blob = build_v2_blob_with_slots({
      handle => { "pub" => other_pub_b64, "enc_key" => enc_key }
    })

    @fake_client.set_response(:pull_vault, blob)
    out, = pull_and_capture("myvault")

    # Should fall back to manual unlock
    assert_match(/unlock it with/i, out)
    cached = LocalVault::SessionCache.get("myvault")
    assert_nil cached
  end

  # ── Pull with non-string enc_key does not crash ──

  def test_pull_with_integer_enc_key_falls_back
    setup_identity_and_login
    handle = LocalVault::Config.inventlist_handle
    blob = build_v2_blob_with_slots({
      handle => { "pub" => "abc", "enc_key" => 12345 }
    })

    @fake_client.set_response(:pull_vault, blob)
    out, = pull_and_capture("myvault")

    assert_match(/pulled/i, out)
    assert_match(/unlock it with/i, out)
  end

  def test_pull_with_hash_enc_key_falls_back
    setup_identity_and_login
    handle = LocalVault::Config.inventlist_handle
    blob = build_v2_blob_with_slots({
      handle => { "pub" => "abc", "enc_key" => { "nested" => "bad" } }
    })

    @fake_client.set_response(:pull_vault, blob)
    out, = pull_and_capture("myvault")

    assert_match(/pulled/i, out)
    assert_match(/unlock it with/i, out)
  end

  def test_pull_with_array_enc_key_falls_back
    setup_identity_and_login
    handle = LocalVault::Config.inventlist_handle
    blob = build_v2_blob_with_slots({
      handle => { "pub" => "abc", "enc_key" => [1, 2, 3] }
    })

    @fake_client.set_response(:pull_vault, blob)
    out, = pull_and_capture("myvault")

    assert_match(/pulled/i, out)
    assert_match(/unlock it with/i, out)
  end

  # ── Pull does not mutate or discard other slots ──

  def test_pull_preserves_key_slots_in_local_files
    setup_identity_and_login
    blob = build_v2_blob_with_owner_slot

    @fake_client.set_response(:pull_vault, blob)
    pull_and_capture("myvault")

    # The blob on disk should still be the original secrets.enc — slots are in the
    # bundle JSON, not in the local vault files. This test just verifies files exist.
    store = LocalVault::Store.new("myvault")
    assert store.exists?
    assert File.exist?(store.meta_path)
  end

  private

  def setup_identity_and_login
    LocalVault::Config.ensure_directories!
    LocalVault::Identity.generate!
    LocalVault::Config.token = "tok"
    LocalVault::Config.inventlist_handle = "nauman"
  end

  def pull_and_capture(vault_name)
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["sync", "pull", vault_name]) }
    end
  end

  # Build a v2 bundle with owner's key slot (matches current identity)
  def build_v2_blob_with_owner_slot
    handle = LocalVault::Config.inventlist_handle || "nauman"
    pub_b64 = LocalVault::Identity.public_key
    enc_key = LocalVault::KeySlot.create(@master_key, pub_b64)
    build_v2_blob_with_slots({
      handle => { "pub" => pub_b64, "enc_key" => enc_key }
    })
  end

  # Build a v2 bundle with a slot for someone else
  def build_v2_blob_with_foreign_slot
    other = RbNaCl::PrivateKey.generate
    other_pub = Base64.strict_encode64(other.public_key.to_bytes)
    enc_key = LocalVault::KeySlot.create(@master_key, other_pub)
    build_v2_blob_with_slots({
      "someone_else" => { "pub" => other_pub, "enc_key" => enc_key }
    })
  end

  def build_v2_blob_with_slots(slots)
    meta = YAML.dump({
      "name" => "myvault",
      "created_at" => Time.now.utc.iso8601,
      "version" => 1,
      "salt" => Base64.strict_encode64(@salt),
      "count" => 1
    })
    secrets = LocalVault::Crypto.encrypt(JSON.generate({ "KEY" => "value" }), @master_key)
    JSON.generate({
      "version" => 2,
      "meta" => Base64.strict_encode64(meta),
      "secrets" => Base64.strict_encode64(secrets),
      "key_slots" => slots
    })
  end

  def build_v1_blob
    meta = YAML.dump({
      "name" => "myvault",
      "created_at" => Time.now.utc.iso8601,
      "version" => 1,
      "salt" => Base64.strict_encode64(@salt),
      "count" => 0
    })
    JSON.generate({
      "version" => 1,
      "meta" => Base64.strict_encode64(meta),
      "secrets" => Base64.strict_encode64("")
    })
  end
end

class FakePullClient
  attr_reader :calls

  def initialize
    @calls     = []
    @responses = {}
  end

  def set_response(method, r) = @responses[method] = r

  def respond_to?(name, include_private = false)
    return false if name == :call
    super
  end

  def method_missing(name, *args, **kwargs)
    @calls << { method: name, args: args, kwargs: kwargs }
    @responses.fetch(name, {})
  end

  def respond_to_missing?(name, include_private = false)
    name != :call
  end
end
