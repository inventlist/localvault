require_relative "test_helper"
require "minitest/mock"
require "localvault/cli"
require "yaml"
require "base64"
require "json"

# LV-029b: Owner key slot bootstrap on sync push
class SyncPushKeySlotTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @passphrase = "test-pass"
    @vault = create_test_vault("default", @passphrase)
    @fake_client = FakePushClient.new
    @fake_client.set_response(:push_vault, { "name" => "default" })
  end

  def teardown
    teardown_test_home
  end

  # ── First push creates owner slot ──

  def test_first_push_creates_owner_key_slot
    setup_identity_and_login

    push_and_capture("default")

    blob = last_pushed_blob
    data = JSON.parse(blob)
    slots = data["key_slots"]

    refute slots.empty?, "First push should create owner key slot"
    assert_equal 1, slots.size
  end

  def test_owner_slot_is_keyed_by_handle
    setup_identity_and_login

    push_and_capture("default")

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert slots.key?(LocalVault::Config.inventlist_handle),
      "Owner slot should be keyed by InventList handle"
  end

  def test_owner_slot_contains_pub_and_enc_key
    setup_identity_and_login

    push_and_capture("default")

    slot = JSON.parse(last_pushed_blob)["key_slots"][LocalVault::Config.inventlist_handle]
    assert slot["pub"], "Slot should contain pub (owner's public key)"
    assert slot["enc_key"], "Slot should contain enc_key (encrypted master key)"
  end

  # ── Subsequent push does not duplicate ──

  def test_second_push_does_not_duplicate_owner_slot
    setup_identity_and_login

    push_and_capture("default")
    push_and_capture("default")

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert_equal 1, slots.size, "Should not duplicate owner slot on second push"
  end

  def test_second_push_preserves_same_owner_slot_pub
    setup_identity_and_login

    push_and_capture("default")
    first_pub = JSON.parse(last_pushed_blob)["key_slots"][LocalVault::Config.inventlist_handle]["pub"]

    push_and_capture("default")
    second_pub = JSON.parse(last_pushed_blob)["key_slots"][LocalVault::Config.inventlist_handle]["pub"]

    assert_equal first_pub, second_pub, "Owner pub key should not change across pushes"
  end

  # ── Preserves existing key slots ──

  def test_push_preserves_existing_teammate_slots
    setup_identity_and_login

    # Simulate a prior blob with an existing teammate slot
    store = LocalVault::Store.new("default")
    existing_slots = {
      "teammate" => { "pub" => "their_pub_key", "enc_key" => "their_enc_key" }
    }
    prior_blob = LocalVault::SyncBundle.pack(store, key_slots: existing_slots)
    @fake_client.set_response(:pull_vault, prior_blob)

    push_and_capture("default")

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert slots.key?("teammate"), "Existing teammate slot should be preserved"
    assert slots.key?(LocalVault::Config.inventlist_handle), "Owner slot should be added"
    assert_equal 2, slots.size
  end

  # ── Malformed remote key_slots ──

  def test_push_survives_malformed_key_slots_string
    setup_identity_and_login

    # Remote has key_slots as a string instead of hash
    store = LocalVault::Store.new("default")
    bad_blob = JSON.generate({
      "version" => 2,
      "meta" => Base64.strict_encode64(File.read(store.meta_path)),
      "secrets" => Base64.strict_encode64(store.read_encrypted || ""),
      "key_slots" => "oops"
    })
    @fake_client.set_response(:pull_vault, bad_blob)

    push_and_capture("default")

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert slots.is_a?(Hash), "Should recover to valid hash"
    assert slots.key?(LocalVault::Config.inventlist_handle), "Owner slot should still be created"
  end

  def test_push_survives_malformed_key_slots_array
    setup_identity_and_login

    store = LocalVault::Store.new("default")
    bad_blob = JSON.generate({
      "version" => 2,
      "meta" => Base64.strict_encode64(File.read(store.meta_path)),
      "secrets" => Base64.strict_encode64(store.read_encrypted || ""),
      "key_slots" => [1, 2, 3]
    })
    @fake_client.set_response(:pull_vault, bad_blob)

    push_and_capture("default")

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert slots.is_a?(Hash)
  end

  # ── Push without identity — no key slots ──

  def test_push_without_identity_has_no_key_slots
    # No identity set up — no keygen, no login
    LocalVault::Config.token = "tok"

    push_and_capture("default")

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert_equal({}, slots, "Push without identity should have empty key slots")
  end

  def test_push_without_login_has_no_key_slots
    # Identity exists but no login
    LocalVault::Config.ensure_directories!
    LocalVault::Identity.generate!
    # No Config.token set

    # Can't push without login — logged_in? returns false
    # This test verifies the guard works
    _, err = capture_io do
      LocalVault::CLI.start(%w[sync push default])
    end
    assert_match(/not logged in/i, err)
  end

  private

  def setup_identity_and_login
    LocalVault::Config.ensure_directories!
    LocalVault::Identity.generate!
    LocalVault::Config.token = "tok"
    LocalVault::Config.inventlist_handle = "nauman"
    # Cache master key so bootstrap_owner_slot can encrypt
    store = LocalVault::Store.new("default")
    master_key = LocalVault::Crypto.derive_master_key(@passphrase, store.salt)
    LocalVault::SessionCache.set("default", master_key)
  end

  def create_test_vault(name, passphrase)
    salt = LocalVault::Crypto.generate_salt
    master_key = LocalVault::Crypto.derive_master_key(passphrase, salt)
    vault = LocalVault::Vault.create!(name: name, master_key: master_key, salt: salt)
    vault.set("TEST_KEY", "test_value")
    vault
  end

  def push_and_capture(vault_name)
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["sync", "push", vault_name]) }
    end
  end

  def last_pushed_blob
    push_call = @fake_client.calls.select { |c| c[:method] == :push_vault }.last
    push_call[:args][1]
  end
end

# Minimal fake that records calls
class FakePushClient
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
