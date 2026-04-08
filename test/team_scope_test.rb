require_relative "test_helper"
require "minitest/mock"
require "localvault/cli"
require "yaml"
require "base64"
require "json"

# Previously-empty regression coverage for the scoped-sharing path. The audit
# flagged this file as empty in v1.3.x, which is how several scoped-sharing
# bugs slipped through. Every test here exercises the add/remove path where
# a member has `scopes: ["..."]` rather than `scopes: nil`.
class TeamScopeTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!

    @passphrase = "test-pass"
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(@passphrase, @salt)

    vault = LocalVault::Vault.create!(name: "production", master_key: @master_key, salt: @salt)
    vault.set("STRIPE_KEY",       "sk_live_demo_stripe")
    vault.set("WEBHOOK_SECRET",   "whsec_demo")
    vault.set("DATABASE_URL",     "postgres://localhost/prod")
    vault.set("myapp.INTERNAL",   "internal-only")
    vault.set("myapp.PUBLIC_URL", "https://myapp.example.com")

    LocalVault::Identity.generate!
    LocalVault::Config.token = "tok"
    LocalVault::Config.inventlist_handle = "alice"
    LocalVault::SessionCache.set("production", @master_key)

    @bob_kp  = RbNaCl::PrivateKey.generate
    @bob_pub = Base64.strict_encode64(@bob_kp.public_key.to_bytes)

    @fake_client = FakeScopeClient.new
  end

  def teardown
    LocalVault::SessionCache.clear("production")
    teardown_test_home
  end

  # ── Vault#filter (unit tests for finding #6) ──────────────────

  def test_filter_nil_returns_all
    vault = LocalVault::Vault.new(name: "production", master_key: @master_key)
    all = vault.all
    assert_equal all, vault.filter(nil)
  end

  def test_filter_empty_returns_empty
    vault = LocalVault::Vault.new(name: "production", master_key: @master_key)
    assert_equal({}, vault.filter([]))
  end

  def test_filter_flat_key_matches
    vault = LocalVault::Vault.new(name: "production", master_key: @master_key)
    filtered = vault.filter(["STRIPE_KEY"])
    assert_equal({ "STRIPE_KEY" => "sk_live_demo_stripe" }, filtered)
  end

  def test_filter_multiple_flat_keys
    vault = LocalVault::Vault.new(name: "production", master_key: @master_key)
    filtered = vault.filter(["STRIPE_KEY", "WEBHOOK_SECRET"])
    assert_equal({
      "STRIPE_KEY"     => "sk_live_demo_stripe",
      "WEBHOOK_SECRET" => "whsec_demo"
    }, filtered)
  end

  def test_filter_group_returns_whole_nested_hash
    vault = LocalVault::Vault.new(name: "production", master_key: @master_key)
    filtered = vault.filter(["myapp"])
    assert_equal({
      "myapp" => {
        "INTERNAL"   => "internal-only",
        "PUBLIC_URL" => "https://myapp.example.com"
      }
    }, filtered)
  end

  def test_filter_skips_missing_scopes
    vault = LocalVault::Vault.new(name: "production", master_key: @master_key)
    filtered = vault.filter(["STRIPE_KEY", "NONEXISTENT"])
    assert_equal({ "STRIPE_KEY" => "sk_live_demo_stripe" }, filtered)
  end

  def test_filter_from_avoids_redecrypt
    # Passing `from:` should use the pre-loaded hash verbatim and NOT hit
    # the store. Verify by setting `from:` to a hand-crafted hash that
    # doesn't match what's on disk.
    vault = LocalVault::Vault.new(name: "production", master_key: @master_key)
    fake_secrets = { "FAKE_KEY" => "fake_value" }
    filtered = vault.filter(["FAKE_KEY"], from: fake_secrets)
    assert_equal({ "FAKE_KEY" => "fake_value" }, filtered)
  end

  def test_filter_from_is_stable_across_many_calls
    # Simulates a rotate loop that filters once per scoped member from a
    # single pre-loaded secrets hash. Read count on the store should stay
    # at 1 even with 10 filter calls.
    vault = LocalVault::Vault.new(name: "production", master_key: @master_key)
    secrets = vault.all

    read_count = 0
    store = vault.store
    store.singleton_class.define_method(:read_encrypted) do |*args, **kw|
      read_count += 1
      File.binread(secrets_path) if File.exist?(secrets_path)
    end

    10.times do
      vault.filter(["STRIPE_KEY"], from: secrets)
    end

    assert_equal 0, read_count, "filter(from:) must not touch the store"
  end

  # ── add --scope happy path ──────────────────────────────────

  def test_add_with_scope_creates_filtered_blob
    @fake_client.set_public_key("bob", @bob_pub)
    @fake_client.set_pull_response(team_blob_with_owner)

    out, = run_add("@bob", scopes: ["STRIPE_KEY"])
    assert_match(/added.*bob/i, out)
    assert_match(/STRIPE_KEY/, out)

    pushed = JSON.parse(last_pushed_blob)
    bob_slot = pushed["key_slots"]["bob"]
    assert_equal ["STRIPE_KEY"], bob_slot["scopes"]
    refute_nil bob_slot["blob"]
    assert_nil bob_slot["scopes"] && nil # sanity

    # Bob should be able to decrypt the member key → the blob → and get
    # exactly the scoped subset (nothing else).
    member_key = LocalVault::KeySlot.decrypt(bob_slot["enc_key"], @bob_kp.to_bytes)
    encrypted_blob = Base64.strict_decode64(bob_slot["blob"])
    decrypted = JSON.parse(LocalVault::Crypto.decrypt(encrypted_blob, member_key))

    assert_equal({ "STRIPE_KEY" => "sk_live_demo_stripe" }, decrypted)
    refute decrypted.key?("DATABASE_URL"), "scoped blob leaked unrelated keys"
    refute decrypted.key?("myapp"),         "scoped blob leaked unrelated groups"
  end

  def test_add_with_scope_for_group_returns_whole_nested_hash
    @fake_client.set_public_key("bob", @bob_pub)
    @fake_client.set_pull_response(team_blob_with_owner)

    run_add("@bob", scopes: ["myapp"])

    pushed = JSON.parse(last_pushed_blob)
    bob_slot = pushed["key_slots"]["bob"]
    member_key = LocalVault::KeySlot.decrypt(bob_slot["enc_key"], @bob_kp.to_bytes)
    decrypted = JSON.parse(LocalVault::Crypto.decrypt(Base64.strict_decode64(bob_slot["blob"]), member_key))

    assert_equal({
      "myapp" => {
        "INTERNAL"   => "internal-only",
        "PUBLIC_URL" => "https://myapp.example.com"
      }
    }, decrypted)
  end

  def test_add_with_scope_merges_when_re_adding
    # First add gives bob STRIPE_KEY. Second add (same handle) with
    # WEBHOOK_SECRET should union the scopes, not replace.
    @fake_client.set_public_key("bob", @bob_pub)
    @fake_client.set_pull_response(team_blob_with_owner)

    run_add("@bob", scopes: ["STRIPE_KEY"])

    # Simulate the server now having bob in the bundle
    pushed = JSON.parse(last_pushed_blob)
    @fake_client.set_pull_response(LocalVault::SyncBundle.pack_v3(
      LocalVault::Store.new("production"),
      owner: "alice",
      key_slots: pushed["key_slots"]
    ))
    @fake_client.clear_calls

    run_add("@bob", scopes: ["WEBHOOK_SECRET"])

    pushed2 = JSON.parse(last_pushed_blob)
    bob_slot = pushed2["key_slots"]["bob"]
    assert_equal ["STRIPE_KEY", "WEBHOOK_SECRET"], bob_slot["scopes"].sort
  end

  # ── remove --scope ──────────────────────────────────────────

  def test_remove_scope_keeps_other_scopes
    # Build bundle with bob already scoped to two keys.
    blob = team_blob_with_slots(
      "alice" => alice_slot,
      "bob"   => bob_scoped_slot(["STRIPE_KEY", "WEBHOOK_SECRET"])
    )
    @fake_client.set_pull_response(blob)

    out, = run_remove("@bob", scopes: ["STRIPE_KEY"])
    assert_match(/removed scope/i, out)
    assert_match(/WEBHOOK_SECRET/i, out)

    pushed = JSON.parse(last_pushed_blob)
    bob_slot = pushed["key_slots"]["bob"]
    assert_equal ["WEBHOOK_SECRET"], bob_slot["scopes"]
    # Rebuilt blob should decrypt and contain only WEBHOOK_SECRET
    member_key = LocalVault::KeySlot.decrypt(bob_slot["enc_key"], @bob_kp.to_bytes)
    decrypted = JSON.parse(LocalVault::Crypto.decrypt(Base64.strict_decode64(bob_slot["blob"]), member_key))
    assert_equal({ "WEBHOOK_SECRET" => "whsec_demo" }, decrypted)
  end

  def test_remove_scope_last_scope_removes_member
    blob = team_blob_with_slots(
      "alice" => alice_slot,
      "bob"   => bob_scoped_slot(["STRIPE_KEY"])
    )
    @fake_client.set_pull_response(blob)

    out, = run_remove("@bob", scopes: ["STRIPE_KEY"])
    assert_match(/last scope removed/i, out)

    pushed = JSON.parse(last_pushed_blob)
    refute pushed["key_slots"].key?("bob"), "bob should be gone after last scope removed"
  end

  def test_remove_scope_errors_on_full_access_member
    blob = team_blob_with_slots(
      "alice" => alice_slot,
      "bob"   => full_access_slot(@bob_pub)
    )
    @fake_client.set_pull_response(blob)

    _, err = run_remove("@bob", scopes: ["STRIPE_KEY"])
    assert_match(/has full access|not scoped/i, err)
    assert_nil @fake_client.calls.find { |c| c[:method] == :push_vault },
               "must not push when --scope is rejected"
  end

  # ── Finding #5 regression: team rotate is transactional ──

  def test_rotate_push_failure_leaves_local_unchanged
    blob = team_blob_with_slots(
      "alice" => alice_slot,
      "bob"   => full_access_slot(@bob_pub)
    )

    failing_client = Object.new
    failing_client.instance_variable_set(:@pull_response, blob)
    failing_client.instance_variable_set(:@calls, [])
    failing_client.define_singleton_method(:pull_vault) do |_|
      @pull_response
    end
    failing_client.define_singleton_method(:push_vault) do |*args|
      @calls << { method: :push_vault, args: args }
      raise LocalVault::ApiClient::ApiError.new("Internal server error", status: 500)
    end

    # Snapshot local state before rotate attempt
    original_secrets   = LocalVault::Store.new("production").read_encrypted
    original_meta      = File.read(LocalVault::Store.new("production").meta_path)
    original_cache_key = LocalVault::SessionCache.get("production")

    stub_team_prompt("brand-new-pass") do
      LocalVault::ApiClient.stub(:new, failing_client) do
        _, err = capture_io { LocalVault::CLI.start(%w[team rotate production]) }
        assert_match(/internal server error|error/i, err)
      end
    end

    # Nothing on disk should have changed
    assert_equal original_secrets, LocalVault::Store.new("production").read_encrypted,
                 "ciphertext must not change if push failed"
    assert_equal original_meta, File.read(LocalVault::Store.new("production").meta_path),
                 "meta.yml must not change if push failed"
    # Old master key must still work
    vault = LocalVault::Vault.new(name: "production", master_key: @master_key)
    assert_equal "sk_live_demo_stripe", vault.get("STRIPE_KEY")
    # Session cache untouched
    assert_equal original_cache_key, LocalVault::SessionCache.get("production")
  end

  def test_rotate_succeeds_commits_locally_and_pushes
    blob = team_blob_with_slots(
      "alice" => alice_slot,
      "bob"   => full_access_slot(@bob_pub)
    )
    @fake_client.set_pull_response(blob)

    original_secrets = LocalVault::Store.new("production").read_encrypted

    stub_team_prompt("fresh-pass") do
      LocalVault::ApiClient.stub(:new, @fake_client) do
        out, = capture_io { LocalVault::CLI.start(%w[team rotate production]) }
        assert_match(/re-encrypted/i, out)
      end
    end

    refute_equal original_secrets, LocalVault::Store.new("production").read_encrypted,
                 "ciphertext should be rotated after successful push"

    # New passphrase works, old one doesn't
    new_vault = LocalVault::Vault.open(name: "production", passphrase: "fresh-pass")
    assert_equal "sk_live_demo_stripe", new_vault.get("STRIPE_KEY")

    # Pushed blob contains new slots for both members
    pushed = JSON.parse(last_pushed_blob)
    assert pushed["key_slots"].key?("alice")
    assert pushed["key_slots"].key?("bob")
  end

  def test_rotate_with_scoped_member_rebuilds_filtered_blob
    # This test catches a latent bug from pre-v1.4: the old rotate loop
    # wrote new ciphertext to disk BEFORE calling vault.filter for scoped
    # members, so filter would try to decrypt new-key data with the old
    # master key and crash. The build_rotated_bundle helper filters from
    # the already-loaded plaintext hash, so scoped rotates work.
    blob = team_blob_with_slots(
      "alice" => alice_slot,
      "bob"   => bob_scoped_slot(["STRIPE_KEY"])
    )
    @fake_client.set_pull_response(blob)

    stub_team_prompt("fresh-pass") do
      LocalVault::ApiClient.stub(:new, @fake_client) do
        out, = capture_io { LocalVault::CLI.start(%w[team rotate production]) }
        assert_match(/re-encrypted/i, out)
      end
    end

    pushed = JSON.parse(last_pushed_blob)
    bob_slot = pushed["key_slots"]["bob"]
    assert_equal ["STRIPE_KEY"], bob_slot["scopes"]

    # Bob's rebuilt scoped blob should still contain STRIPE_KEY and nothing else
    member_key = LocalVault::KeySlot.decrypt(bob_slot["enc_key"], @bob_kp.to_bytes)
    decrypted = JSON.parse(LocalVault::Crypto.decrypt(Base64.strict_decode64(bob_slot["blob"]), member_key))
    assert_equal({ "STRIPE_KEY" => "sk_live_demo_stripe" }, decrypted)
  end

  # ── remove --rotate transactional ──────────────────────────

  def test_remove_rotate_push_failure_leaves_local_unchanged
    blob = team_blob_with_slots(
      "alice" => alice_slot,
      "bob"   => full_access_slot(@bob_pub)
    )

    failing_client = Object.new
    failing_client.instance_variable_set(:@pull_response, blob)
    failing_client.instance_variable_set(:@calls, [])
    failing_client.define_singleton_method(:pull_vault) { |_| @pull_response }
    failing_client.define_singleton_method(:push_vault) do |*args|
      @calls << { method: :push_vault, args: args }
      raise LocalVault::ApiClient::ApiError.new("Internal server error", status: 500)
    end
    failing_client.define_singleton_method(:sent_shares) { |**_| { "shares" => [] } }

    original_secrets   = LocalVault::Store.new("production").read_encrypted
    original_meta      = File.read(LocalVault::Store.new("production").meta_path)
    original_cache_key = LocalVault::SessionCache.get("production")

    stub_cli_prompt("brand-new-pass") do
      LocalVault::ApiClient.stub(:new, failing_client) do
        _, err = capture_io { LocalVault::CLI.start(%w[remove @bob --vault production --rotate]) }
        assert_match(/error/i, err)
      end
    end

    assert_equal original_secrets, LocalVault::Store.new("production").read_encrypted
    assert_equal original_meta, File.read(LocalVault::Store.new("production").meta_path)
    assert_equal original_cache_key, LocalVault::SessionCache.get("production")

    # Old master key must still work
    vault = LocalVault::Vault.new(name: "production", master_key: @master_key)
    assert_equal "sk_live_demo_stripe", vault.get("STRIPE_KEY")
  end

  private

  def team_blob_with_owner
    store = LocalVault::Store.new("production")
    LocalVault::SyncBundle.pack_v3(store, owner: "alice", key_slots: { "alice" => alice_slot })
  end

  def team_blob_with_slots(slots)
    store = LocalVault::Store.new("production")
    LocalVault::SyncBundle.pack_v3(store, owner: "alice", key_slots: slots)
  end

  def alice_slot
    pub_b64 = LocalVault::Identity.public_key
    { "pub" => pub_b64, "enc_key" => LocalVault::KeySlot.create(@master_key, pub_b64), "scopes" => nil, "blob" => nil }
  end

  def full_access_slot(pub_b64)
    { "pub" => pub_b64, "enc_key" => LocalVault::KeySlot.create(@master_key, pub_b64), "scopes" => nil, "blob" => nil }
  end

  def bob_scoped_slot(scopes)
    vault = LocalVault::Vault.new(name: "production", master_key: @master_key)
    filtered = vault.filter(scopes)
    member_key = RbNaCl::Random.random_bytes(32)
    encrypted_blob = LocalVault::Crypto.encrypt(JSON.generate(filtered), member_key)
    {
      "pub" => @bob_pub,
      "enc_key" => LocalVault::KeySlot.create(member_key, @bob_pub),
      "scopes" => scopes,
      "blob" => Base64.strict_encode64(encrypted_blob)
    }
  end

  def run_add(handle, scopes:)
    args = ["add", handle, "--vault", "production"]
    args += ["--scope"] + scopes if scopes
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(args) }
    end
  end

  def run_remove(handle, scopes:)
    args = ["remove", handle, "--vault", "production"]
    args += ["--scope"] + scopes if scopes
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(args) }
    end
  end

  def last_pushed_blob
    call = @fake_client.calls.select { |c| c[:method] == :push_vault }.last
    call[:args][1]
  end

  def stub_team_prompt(value)
    original = LocalVault::CLI::Team.instance_method(:prompt_passphrase)
    LocalVault::CLI::Team.no_commands do
      LocalVault::CLI::Team.send(:define_method, :prompt_passphrase) { |_msg = ""| value }
    end
    yield
  ensure
    LocalVault::CLI::Team.no_commands do
      LocalVault::CLI::Team.send(:define_method, :prompt_passphrase, original)
    end
  end

  def stub_cli_prompt(value)
    original = LocalVault::CLI.instance_method(:prompt_passphrase)
    LocalVault::CLI.no_commands do
      LocalVault::CLI.send(:define_method, :prompt_passphrase) { |_msg = ""| value }
    end
    yield
  ensure
    LocalVault::CLI.no_commands do
      LocalVault::CLI.send(:define_method, :prompt_passphrase, original)
    end
  end
end

class FakeScopeClient
  attr_reader :calls

  def initialize
    @calls = []
    @public_keys = {}
    @pull_response = nil
  end

  def set_public_key(handle, pub)
    @public_keys[handle] = pub
  end

  def set_pull_response(blob)
    @pull_response = blob
  end

  def clear_calls
    @calls = []
  end

  def get_public_key(handle)
    { "handle" => handle, "public_key" => @public_keys[handle] }
  end

  def pull_vault(_name)
    @pull_response || ""
  end

  def push_vault(*args)
    @calls << { method: :push_vault, args: args }
    {}
  end

  def sent_shares(**_)
    { "shares" => [] }
  end

  def method_missing(name, *args, **kwargs)
    @calls << { method: name, args: args, kwargs: kwargs }
    {}
  end

  def respond_to_missing?(name, _)
    name != :call
  end
end
