require_relative "test_helper"
require "minitest/mock"
require "localvault/cli"
require "yaml"
require "base64"
require "json"

# LV-029d: localvault team add @handle -v vault
class TeamAddTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @passphrase = "test-pass"
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(@passphrase, @salt)
    @vault = create_test_vault("production", @passphrase)

    # Set up owner identity + login + session
    LocalVault::Identity.generate!
    LocalVault::Config.token = "tok"
    LocalVault::Config.inventlist_handle = "alice"
    cache_master_key("production")

    @fake_client = FakeTeamAddClient.new
  end

  def teardown
    LocalVault::SessionCache.clear("production")
    teardown_test_home
  end

  # ── Happy path ──

  def test_team_add_creates_key_slot_for_recipient
    bob_kp = RbNaCl::PrivateKey.generate
    bob_pub = Base64.strict_encode64(bob_kp.public_key.to_bytes)
    @fake_client.set_public_key("bob", bob_pub)
    @fake_client.set_pull_response(current_blob_with_owner_slot)

    out, = run_team_add("@bob", "production")

    assert_match(/added.*bob/i, out)

    # Verify the pushed blob has bob's slot
    pushed = last_pushed_blob
    slots = JSON.parse(pushed)["key_slots"]
    assert slots.key?("bob"), "Bob's key slot should be in the pushed bundle"
    assert slots["bob"]["enc_key"].is_a?(String)
    assert slots["bob"]["pub"].is_a?(String)
  end

  def test_team_add_preserves_owner_slot
    bob_kp = RbNaCl::PrivateKey.generate
    bob_pub = Base64.strict_encode64(bob_kp.public_key.to_bytes)
    @fake_client.set_public_key("bob", bob_pub)
    @fake_client.set_pull_response(current_blob_with_owner_slot)

    run_team_add("@bob", "production")

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert slots.key?("alice"), "Owner's slot should still be present"
    assert slots.key?("bob"), "Bob's slot should be added"
    assert_equal 2, slots.size
  end

  def test_team_add_recipient_can_decrypt_master_key
    bob_kp = RbNaCl::PrivateKey.generate
    bob_pub = Base64.strict_encode64(bob_kp.public_key.to_bytes)
    @fake_client.set_public_key("bob", bob_pub)
    @fake_client.set_pull_response(current_blob_with_owner_slot)

    run_team_add("@bob", "production")

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    recovered = LocalVault::KeySlot.decrypt(slots["bob"]["enc_key"], bob_kp.to_bytes)
    assert_equal @master_key, recovered
  end

  # ── Error cases ──

  def test_team_add_fails_if_not_logged_in
    LocalVault::Config.token = nil

    _, err = run_team_add("@bob", "production")

    assert_match(/not logged in/i, err)
  end

  def test_team_add_fails_if_no_identity
    # Remove identity files
    FileUtils.rm_f(LocalVault::Identity.priv_key_path)
    FileUtils.rm_f(LocalVault::Identity.pub_key_path)

    _, err = run_team_add("@bob", "production")

    assert_match(/keypair|identity|keygen/i, err)
  end

  def test_team_add_fails_if_vault_not_unlocked
    LocalVault::SessionCache.clear("production")

    _, err = run_team_add("@bob", "production")

    assert_match(/unlock/i, err)
  end

  def test_team_add_fails_if_recipient_has_no_public_key
    @fake_client.set_public_key_error("bob", 404)
    @fake_client.set_pull_response(current_blob_with_owner_slot)

    _, err = run_team_add("@bob", "production")

    assert_match(/no public key|not found/i, err)
  end

  def test_team_add_strips_at_prefix_from_handle
    bob_kp = RbNaCl::PrivateKey.generate
    bob_pub = Base64.strict_encode64(bob_kp.public_key.to_bytes)
    @fake_client.set_public_key("bob", bob_pub)
    @fake_client.set_pull_response(current_blob_with_owner_slot)

    run_team_add("@bob", "production")

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert slots.key?("bob"), "Should strip @ from handle"
    refute slots.key?("@bob")
  end

  private

  def create_test_vault(name, passphrase)
    salt = LocalVault::Crypto.generate_salt
    master_key = LocalVault::Crypto.derive_master_key(passphrase, salt)
    @salt = salt
    @master_key = master_key
    vault = LocalVault::Vault.create!(name: name, master_key: master_key, salt: salt)
    vault.set("SECRET", "value")
    vault
  end

  def cache_master_key(vault_name)
    LocalVault::SessionCache.set(vault_name, @master_key)
  end

  def current_blob_with_owner_slot
    store = LocalVault::Store.new("production")
    pub_b64 = LocalVault::Identity.public_key
    enc_key = LocalVault::KeySlot.create(@master_key, pub_b64)
    owner_slots = { "alice" => { "pub" => pub_b64, "enc_key" => enc_key } }
    LocalVault::SyncBundle.pack(store, key_slots: owner_slots)
  end

  def run_team_add(handle, vault_name)
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["team", "add", handle, "--vault", vault_name]) }
    end
  end

  def last_pushed_blob
    call = @fake_client.calls.select { |c| c[:method] == :push_vault }.last
    call[:args][1]
  end
end

class FakeTeamAddClient
  attr_reader :calls

  def initialize
    @calls = []
    @public_keys = {}
    @public_key_errors = {}
    @responses = {}
  end

  def set_public_key(handle, pub_b64)
    @public_keys[handle] = pub_b64
  end

  def set_public_key_error(handle, status)
    @public_key_errors[handle] = status
  end

  def set_pull_response(blob)
    @responses[:pull_vault] = blob
  end

  def get_public_key(handle)
    if @public_key_errors[handle]
      raise LocalVault::ApiClient::ApiError.new("Not found", status: @public_key_errors[handle])
    end
    { "handle" => handle, "public_key" => @public_keys[handle] }
  end

  def pull_vault(_name)
    @responses[:pull_vault] || ""
  end

  def push_vault(*args)
    @calls << { method: :push_vault, args: args }
    {}
  end

  def method_missing(name, *args, **kwargs)
    @calls << { method: name, args: args, kwargs: kwargs }
    @responses.fetch(name, {})
  end

  def respond_to_missing?(name, include_private = false)
    name != :call
  end
end
