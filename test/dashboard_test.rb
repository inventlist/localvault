require_relative "test_helper"
require "minitest/mock"
require "localvault/cli"
require "base64"
require "json"
require "yaml"

# Regression coverage for `localvault dashboard` — the aggregate view of
# who has access to which vaults and which vaults are shared with you.
# See v1.5.0 design notes in the session log.
class DashboardTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    LocalVault::Config.token = "tok"
    LocalVault::Config.inventlist_handle = "alice"

    @passphrase = "test-pass"
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(@passphrase, @salt)

    LocalVault::Identity.generate!

    @bob_kp  = RbNaCl::PrivateKey.generate
    @bob_pub = Base64.strict_encode64(@bob_kp.public_key.to_bytes)

    @fake_client = FakeDashboardClient.new
  end

  def teardown
    teardown_test_home
  end

  # ── auth ──────────────────────────────────────────────────

  def test_dashboard_requires_login
    LocalVault::Config.token = nil
    _, err = run_dashboard
    assert_match(/not logged in/i, err)
  end

  # ── empty state ───────────────────────────────────────────

  def test_dashboard_empty_state
    @fake_client.set_vaults([])
    @fake_client.set_sent_shares([])
    @fake_client.set_pending_shares([])

    out, = run_dashboard
    assert_match(/no vaults/i, out)
  end

  # ── owned vaults ──────────────────────────────────────────

  def test_dashboard_shows_owned_vault_with_full_members
    create_local_vault("production")

    slots = {
      "alice" => slot_for(LocalVault::Identity.public_key),
      "carol" => slot_for(@bob_pub) # pretend carol has bob's pub key
    }
    @fake_client.set_vaults([
      { "name" => "production", "owner_handle" => "alice", "shared" => false }
    ])
    @fake_client.set_vault_bundle("production", team_blob_with_slots("production", "alice", slots))

    out, = run_dashboard
    assert_match(/OWNED BY YOU/i, out)
    assert_match(/production/, out)
    assert_match(/alice/,      out)
    assert_match(/carol/,      out)
    assert_match(/\(you\)/,    out)
  end

  def test_dashboard_shows_scoped_members_with_their_scopes
    create_local_vault_with_secrets("production")

    scoped_slot = bob_scoped_slot("production", ["STRIPE_KEY", "WEBHOOK_SECRET"])
    slots = {
      "alice" => slot_for(LocalVault::Identity.public_key),
      "bob"   => scoped_slot
    }
    @fake_client.set_vaults([
      { "name" => "production", "owner_handle" => "alice", "shared" => false }
    ])
    @fake_client.set_vault_bundle("production", team_blob_with_slots("production", "alice", slots))

    out, = run_dashboard
    assert_match(/bob/, out)
    assert_match(/STRIPE_KEY/, out)
    assert_match(/WEBHOOK_SECRET/, out)
    assert_match(/scoped/i, out)
  end

  def test_dashboard_shows_all_members_in_table
    create_local_vault("production")
    slots = {
      "alice" => slot_for(LocalVault::Identity.public_key),
      "carol" => slot_for(@bob_pub)
    }
    @fake_client.set_vaults([
      { "name" => "production", "owner_handle" => "alice", "shared" => false }
    ])
    @fake_client.set_vault_bundle("production", team_blob_with_slots("production", "alice", slots))

    out, = run_dashboard
    # Both members should appear as rows in the table
    assert_match(/alice.*full/i, out)
    assert_match(/carol.*full/i, out)
  end

  def test_dashboard_handles_multiple_owned_vaults
    create_local_vault("production")
    create_local_vault("staging")

    @fake_client.set_vaults([
      { "name" => "production", "owner_handle" => "alice", "shared" => false },
      { "name" => "staging",    "owner_handle" => "alice", "shared" => false }
    ])
    @fake_client.set_vault_bundle("production",
      team_blob_with_slots("production", "alice", { "alice" => slot_for(LocalVault::Identity.public_key) }))
    @fake_client.set_vault_bundle("staging",
      team_blob_with_slots("staging", "alice", { "alice" => slot_for(LocalVault::Identity.public_key) }))

    out, = run_dashboard
    assert_match(/production/, out)
    assert_match(/staging/,    out)
  end

  # ── shared with you ───────────────────────────────────────

  def test_dashboard_shows_shared_with_you_vault
    # A vault where someone else is the owner and alice is just a member.
    alice_pub = LocalVault::Identity.public_key
    slots = {
      "mustafa" => { "pub" => @bob_pub,  "enc_key" => LocalVault::KeySlot.create(@master_key, @bob_pub), "scopes" => nil, "blob" => nil },
      "alice"   => { "pub" => alice_pub, "enc_key" => LocalVault::KeySlot.create(@master_key, alice_pub), "scopes" => nil, "blob" => nil }
    }
    create_local_vault("marketing") # the local store exists because alice has pulled it
    @fake_client.set_vaults([
      { "name" => "marketing", "owner_handle" => "mustafa", "shared" => true }
    ])
    @fake_client.set_vault_bundle("marketing", team_blob_with_slots("marketing", "mustafa", slots))

    out, = run_dashboard
    assert_match(/SHARED WITH YOU/i, out)
    assert_match(/marketing/, out)
    assert_match(/@mustafa/,  out)
  end

  def test_dashboard_shows_scope_when_you_are_scoped_member
    alice_pub = LocalVault::Identity.public_key
    create_local_vault_with_secrets("marketing")
    owner_slot = { "pub" => @bob_pub, "enc_key" => LocalVault::KeySlot.create(@master_key, @bob_pub), "scopes" => nil, "blob" => nil }
    alice_scoped = alice_scoped_slot("marketing", ["ANALYTICS_KEY"], alice_pub)
    slots = { "mustafa" => owner_slot, "alice" => alice_scoped }
    @fake_client.set_vaults([
      { "name" => "marketing", "owner_handle" => "mustafa", "shared" => true }
    ])
    @fake_client.set_vault_bundle("marketing", team_blob_with_slots("marketing", "mustafa", slots))

    out, = run_dashboard
    assert_match(/marketing/, out)
    assert_match(/ANALYTICS_KEY/, out)
    assert_match(/scoped/i, out)
  end

  # ── mixed ─────────────────────────────────────────────────

  def test_dashboard_shows_owned_and_shared_sections
    create_local_vault("production")
    create_local_vault("marketing")

    @fake_client.set_vaults([
      { "name" => "production", "owner_handle" => "alice",   "shared" => false },
      { "name" => "marketing",  "owner_handle" => "mustafa", "shared" => true  }
    ])
    @fake_client.set_vault_bundle("production",
      team_blob_with_slots("production", "alice", { "alice" => slot_for(LocalVault::Identity.public_key) }))
    @fake_client.set_vault_bundle("marketing",
      team_blob_with_slots("marketing", "mustafa",
        { "mustafa" => { "pub" => @bob_pub, "enc_key" => LocalVault::KeySlot.create(@master_key, @bob_pub), "scopes" => nil, "blob" => nil },
          "alice"   => { "pub" => LocalVault::Identity.public_key, "enc_key" => LocalVault::KeySlot.create(@master_key, LocalVault::Identity.public_key), "scopes" => nil, "blob" => nil } }))

    out, = run_dashboard
    assert_match(/OWNED BY YOU/i,    out)
    assert_match(/SHARED WITH YOU/i, out)
    assert_match(/production/, out)
    assert_match(/marketing/,  out)
  end

  # ── graceful failures ─────────────────────────────────────

  def test_dashboard_skips_vault_when_pull_fails
    create_local_vault("production")
    create_local_vault("broken")

    @fake_client.set_vaults([
      { "name" => "production", "owner_handle" => "alice", "shared" => false },
      { "name" => "broken",     "owner_handle" => "alice", "shared" => false }
    ])
    @fake_client.set_vault_bundle("production",
      team_blob_with_slots("production", "alice", { "alice" => slot_for(LocalVault::Identity.public_key) }))
    @fake_client.set_vault_error("broken", LocalVault::ApiClient::ApiError.new("boom", status: 500))

    out, err = run_dashboard
    assert_match(/production/, out, "healthy vault should still render")
    assert_match(/broken/, out + err, "broken vault should be mentioned somewhere")
    # but the command must not crash
  end

  def test_dashboard_handles_legacy_v1_bundle_gracefully
    create_local_vault("personal")

    # v1 personal bundle — no owner, no key_slots
    store = LocalVault::Store.new("personal")
    v1_blob = LocalVault::SyncBundle.pack(store)

    @fake_client.set_vaults([
      { "name" => "personal", "owner_handle" => nil, "shared" => false }
    ])
    @fake_client.set_vault_bundle("personal", v1_blob)

    out, = run_dashboard
    assert_match(/personal/, out)
    # v1 vaults have no team data — rendered under a "personal" section or flagged
    refute_match(/error/i, out.downcase.gsub("error handling", ""))
  end

  # ── sync status ────────────────────────────────────────────

  def test_dashboard_shows_synced_status_with_date
    create_local_vault("production")
    @fake_client.set_vaults([
      { "name" => "production", "owner_handle" => "alice", "shared" => false,
        "synced_at" => "2026-04-12T10:00:00Z", "size_bytes" => 4821 }
    ])
    @fake_client.set_vault_bundle("production",
      team_blob_with_slots("production", "alice", { "alice" => slot_for(LocalVault::Identity.public_key) }))

    out, = run_dashboard
    assert_match(/synced.*2026-04-12/i, out)
    assert_match(/4\.7 KB/, out)
  end

  def test_dashboard_shows_remote_only_status
    # Vault exists on server but NOT locally
    @fake_client.set_vaults([
      { "name" => "remote-only-vault", "owner_handle" => "alice", "shared" => false,
        "synced_at" => "2026-04-10T08:00:00Z" }
    ])
    @fake_client.set_vault_bundle("remote-only-vault",
      team_blob_with_slots_no_store("remote-only-vault", "alice", { "alice" => slot_for(LocalVault::Identity.public_key) }))

    out, = run_dashboard
    assert_match(/remote only/i, out)
  end

  def test_dashboard_shows_local_only_status
    # Vault exists locally but NOT on server
    create_local_vault("offline-vault")
    @fake_client.set_vaults([])

    out, = run_dashboard
    assert_match(/offline-vault/, out)
    assert_match(/local only/i, out)
  end

  # ── legacy direct shares section ──────────────────────────

  def test_dashboard_shows_legacy_direct_shares_in_table
    @fake_client.set_vaults([])
    @fake_client.set_sent_shares([
      { "id" => 1, "recipient_handle" => "bob",   "status" => "accepted" },
      { "id" => 2, "recipient_handle" => "carol", "status" => "pending" }
    ])
    @fake_client.set_pending_shares([
      { "id" => 9, "sender_handle" => "dan", "vault_name" => "inbox" }
    ])

    out, = run_dashboard
    assert_match(/LEGACY DIRECT SHARES/i, out)
    # Each share is a row in the table now
    assert_match(/@bob.*accepted.*outgoing/i, out)
    assert_match(/@carol.*pending.*outgoing/i, out)
    assert_match(/@dan.*pending.*incoming/i, out)
  end

  private

  def run_dashboard
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["dashboard"]) }
    end
  end

  def create_local_vault(name)
    salt = LocalVault::Crypto.generate_salt
    master_key = LocalVault::Crypto.derive_master_key(@passphrase, salt)
    @salt = salt
    @master_key = master_key
    LocalVault::Vault.create!(name: name, master_key: master_key, salt: salt)
  end

  def create_local_vault_with_secrets(name)
    create_local_vault(name)
    vault = LocalVault::Vault.new(name: name, master_key: @master_key)
    vault.set("STRIPE_KEY",     "sk_live_demo")
    vault.set("WEBHOOK_SECRET", "whsec_demo")
    vault.set("ANALYTICS_KEY",  "ua_demo")
    vault
  end

  def slot_for(pub_b64)
    { "pub" => pub_b64, "enc_key" => LocalVault::KeySlot.create(@master_key, pub_b64), "scopes" => nil, "blob" => nil }
  end

  def bob_scoped_slot(vault_name, scopes)
    vault = LocalVault::Vault.new(name: vault_name, master_key: @master_key)
    filtered = vault.filter(scopes)
    member_key = RbNaCl::Random.random_bytes(32)
    encrypted_blob = LocalVault::Crypto.encrypt(JSON.generate(filtered), member_key)
    {
      "pub"     => @bob_pub,
      "enc_key" => LocalVault::KeySlot.create(member_key, @bob_pub),
      "scopes"  => scopes,
      "blob"    => Base64.strict_encode64(encrypted_blob)
    }
  end

  def alice_scoped_slot(vault_name, scopes, pub_b64)
    vault = LocalVault::Vault.new(name: vault_name, master_key: @master_key)
    filtered = vault.filter(scopes)
    member_key = RbNaCl::Random.random_bytes(32)
    encrypted_blob = LocalVault::Crypto.encrypt(JSON.generate(filtered), member_key)
    {
      "pub"     => pub_b64,
      "enc_key" => LocalVault::KeySlot.create(member_key, pub_b64),
      "scopes"  => scopes,
      "blob"    => Base64.strict_encode64(encrypted_blob)
    }
  end

  def team_blob_with_slots(vault_name, owner, slots)
    store = LocalVault::Store.new(vault_name)
    LocalVault::SyncBundle.pack_v3(store, owner: owner, key_slots: slots)
  end

  # Build a v3 blob without requiring a local store (for remote-only tests)
  def team_blob_with_slots_no_store(vault_name, owner, slots)
    meta_bytes    = YAML.dump("name" => vault_name, "version" => 1, "salt" => Base64.strict_encode64("x" * 16))
    secrets_bytes = ""
    LocalVault::SyncBundle.pack_v3_bytes(
      meta_bytes:    meta_bytes,
      secrets_bytes: secrets_bytes,
      owner:         owner,
      key_slots:     slots
    )
  end
end

class FakeDashboardClient
  attr_reader :calls

  def initialize
    @calls = []
    @vaults = []
    @bundles = {}
    @bundle_errors = {}
    @sent_shares = []
    @pending_shares = []
  end

  def set_vaults(vaults)
    @vaults = vaults
  end

  def set_vault_bundle(name, blob)
    @bundles[name] = blob
  end

  def set_vault_error(name, error)
    @bundle_errors[name] = error
  end

  def set_sent_shares(list)
    @sent_shares = list
  end

  def set_pending_shares(list)
    @pending_shares = list
  end

  def list_vaults
    @calls << { method: :list_vaults }
    { "vaults" => @vaults }
  end

  def pull_vault(name)
    @calls << { method: :pull_vault, args: [name] }
    raise @bundle_errors[name] if @bundle_errors.key?(name)
    @bundles[name] || ""
  end

  def sent_shares(vault_name: nil)
    @calls << { method: :sent_shares, kwargs: { vault_name: vault_name } }
    { "shares" => @sent_shares }
  end

  def pending_shares
    @calls << { method: :pending_shares }
    { "shares" => @pending_shares }
  end

  def method_missing(name, *args, **kwargs)
    @calls << { method: name, args: args, kwargs: kwargs }
    {}
  end

  def respond_to_missing?(name, _)
    name != :call
  end
end
