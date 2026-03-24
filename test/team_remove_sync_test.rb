require_relative "test_helper"
require "minitest/mock"
require "localvault/cli"
require "yaml"
require "base64"
require "json"

# LV-030: localvault team remove @handle -v vault (sync-based)
class TeamRemoveSyncTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @passphrase = "test-pass"
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(@passphrase, @salt)
    create_test_vault("production")

    LocalVault::Identity.generate!
    LocalVault::Config.token = "tok"
    LocalVault::Config.inventlist_handle = "alice"
    LocalVault::SessionCache.set("production", @master_key)

    @bob_kp = RbNaCl::PrivateKey.generate
    @bob_pub = Base64.strict_encode64(@bob_kp.public_key.to_bytes)

    @fake_client = FakeTeamRemoveClient.new
  end

  def teardown
    LocalVault::SessionCache.clear("production")
    teardown_test_home
  end

  # ── Remove without rotate ──

  def test_remove_deletes_slot_and_pushes
    blob = build_blob_with_slots({
      "alice" => slot_for(LocalVault::Identity.public_key),
      "bob"   => slot_for(@bob_pub)
    })
    @fake_client.set_pull_response(blob)

    out, = run_team_remove("@bob", "production")

    assert_match(/removed.*bob/i, out)
    pushed = last_pushed_blob
    slots = JSON.parse(pushed)["key_slots"]
    assert slots.key?("alice"), "Owner slot should remain"
    refute slots.key?("bob"), "Bob's slot should be removed"
  end

  def test_remove_preserves_other_members
    carol_kp = RbNaCl::PrivateKey.generate
    carol_pub = Base64.strict_encode64(carol_kp.public_key.to_bytes)
    blob = build_blob_with_slots({
      "alice" => slot_for(LocalVault::Identity.public_key),
      "bob"   => slot_for(@bob_pub),
      "carol" => slot_for(carol_pub)
    })
    @fake_client.set_pull_response(blob)

    run_team_remove("@bob", "production")

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert slots.key?("alice")
    assert slots.key?("carol")
    refute slots.key?("bob")
    assert_equal 2, slots.size
  end

  def test_remove_fails_if_handle_not_in_slots
    blob = build_blob_with_slots({
      "alice" => slot_for(LocalVault::Identity.public_key)
    })
    @fake_client.set_pull_response(blob)

    _, err = run_team_remove("@bob", "production")

    assert_match(/not found|no slot/i, err)
  end

  def test_remove_cannot_remove_self_if_only_member
    blob = build_blob_with_slots({
      "alice" => slot_for(LocalVault::Identity.public_key)
    })
    @fake_client.set_pull_response(blob)

    _, err = run_team_remove("@alice", "production")

    assert_match(/cannot remove.*only/i, err)
  end

  def test_remove_can_remove_self_if_others_exist
    blob = build_blob_with_slots({
      "alice" => slot_for(LocalVault::Identity.public_key),
      "bob"   => slot_for(@bob_pub)
    })
    @fake_client.set_pull_response(blob)

    out, = run_team_remove("@alice", "production")

    assert_match(/removed.*alice/i, out)
    slots = JSON.parse(last_pushed_blob)["key_slots"]
    refute slots.key?("alice")
    assert slots.key?("bob")
  end

  def test_remove_requires_login
    LocalVault::Config.token = nil

    _, err = capture_io { LocalVault::CLI.start(["team", "remove", "@bob", "--vault", "production"]) }

    assert_match(/not connected|not logged/i, err)
  end

  # ── Self-remove with --rotate clears local access ──

  def test_rotate_self_remove_clears_session_cache
    blob = build_blob_with_slots({
      "alice" => slot_for(LocalVault::Identity.public_key),
      "bob"   => slot_for(@bob_pub)
    })
    @fake_client.set_pull_response(blob)

    run_team_remove_rotate("@alice", "production")

    cached = LocalVault::SessionCache.get("production")
    assert_nil cached, "Self-remove with --rotate should clear local session cache"
  end

  # ── Remove with --rotate ──

  def test_rotate_reencrypts_and_pushes_new_slots
    blob = build_blob_with_slots({
      "alice" => slot_for(LocalVault::Identity.public_key),
      "bob"   => slot_for(@bob_pub)
    })
    @fake_client.set_pull_response(blob)

    out, = run_team_remove_rotate("@bob", "production")

    assert_match(/removed.*bob/i, out)
    assert_match(/rotated|re-encrypted/i, out)

    pushed = last_pushed_blob
    slots = JSON.parse(pushed)["key_slots"]

    # Bob should be gone
    refute slots.key?("bob")
    # Alice should have a NEW enc_key (re-encrypted with new master key)
    assert slots.key?("alice")

    # The old master key should no longer decrypt the new secrets
    new_secrets_b64 = JSON.parse(pushed)["secrets"]
    new_secrets_enc = Base64.strict_decode64(new_secrets_b64)

    assert_raises(LocalVault::Crypto::DecryptionError) do
      LocalVault::Crypto.decrypt(new_secrets_enc, @master_key)
    end
  end

  def test_rotate_preserves_remaining_members_slots
    carol_kp = RbNaCl::PrivateKey.generate
    carol_pub = Base64.strict_encode64(carol_kp.public_key.to_bytes)

    blob = build_blob_with_slots({
      "alice" => slot_for(LocalVault::Identity.public_key),
      "bob"   => slot_for(@bob_pub),
      "carol" => slot_for(carol_pub)
    })
    @fake_client.set_pull_response(blob)

    run_team_remove_rotate("@bob", "production")

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert slots.key?("alice")
    assert slots.key?("carol")
    refute slots.key?("bob")
    assert_equal 2, slots.size

    # Carol's new slot should decrypt the new master key
    new_master = LocalVault::KeySlot.decrypt(slots["carol"]["enc_key"], carol_kp.to_bytes)
    refute_equal @master_key, new_master, "New master key should differ from old"
    assert_equal 32, new_master.bytesize
  end

  private

  def create_test_vault(name)
    vault = LocalVault::Vault.create!(name: name, master_key: @master_key, salt: @salt)
    vault.set("SECRET", "value")
  end

  def slot_for(pub_b64)
    { "pub" => pub_b64, "enc_key" => LocalVault::KeySlot.create(@master_key, pub_b64) }
  end

  def build_blob_with_slots(slots)
    store = LocalVault::Store.new("production")
    LocalVault::SyncBundle.pack(store, key_slots: slots)
  end

  def run_team_remove(handle, vault_name)
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["team", "remove", handle, "--vault", vault_name]) }
    end
  end

  def run_team_remove_rotate(handle, vault_name)
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["team", "remove", handle, "--vault", vault_name, "--rotate"]) }
    end
  end

  def last_pushed_blob
    call = @fake_client.calls.select { |c| c[:method] == :push_vault }.last
    call[:args][1]
  end
end

class FakeTeamRemoveClient
  attr_reader :calls

  def initialize
    @calls = []
    @pull_response = ""
    @responses = {}
  end

  def set_pull_response(blob) = @pull_response = blob

  def pull_vault(_name)
    @pull_response
  end

  def push_vault(*args)
    @calls << { method: :push_vault, args: args }
    {}
  end

  def sent_shares(**_) = { "shares" => [] }
  def revoke_share(_id) = {}

  def method_missing(name, *args, **kwargs)
    @calls << { method: name, args: args, kwargs: kwargs }
    @responses.fetch(name, {})
  end

  def respond_to_missing?(name, _) = name != :call
end
