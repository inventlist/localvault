require_relative "test_helper"
require "localvault/cli"
require "json"
require "base64"
require "yaml"
require "digest"

# Integration tests for `localvault sync diff` / `sync merge` and the
# key-level conflict guidance in bare `localvault sync`.
class CLISyncMergeTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    LocalVault::Config.token = "tok"
    LocalVault::Config.inventlist_handle = "alice"
    @passphrase = "test-pass"
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(@passphrase, @salt)
    @client = FakeMergeClient.new
  end

  def teardown
    LocalVault::SessionCache.clear("devops") rescue nil
    teardown_test_home
  end

  # Set up the canonical conflict: base {SHARED, KEEP}, local edits SHARED and
  # adds LOCAL_ONLY, remote edits SHARED differently and adds REMOTE_ONLY.
  def setup_conflict(prefer_same: false)
    vault = LocalVault::Vault.create!(name: "devops", master_key: @master_key, salt: @salt)
    vault.set("SHARED", "v-base-1")
    vault.set("KEEP", "v-same-1")
    vault.set("app.TOKEN", "v-tok-1")
    store = LocalVault::Store.new("devops")
    LocalVault::SyncState.new("devops").record!(store, direction: "push")

    remote_secrets = { "SHARED" => prefer_same ? "v-base-1" : "v-remote-1", "KEEP" => "v-same-1",
                       "REMOTE_ONLY" => "v-r-1", "app" => { "TOKEN" => "v-tok-2" } }
    @client.set_vault_blob("devops", build_blob("devops", remote_secrets))
    @client.set_list_response({ "vaults" => [{ "name" => "devops", "checksum" => "x", "shared" => false }] })

    vault.set("SHARED", "v-local-1")
    vault.set("LOCAL_ONLY", "v-l-1")
    LocalVault::SessionCache.set("devops", @master_key)
    vault
  end

  # ── sync all conflict guidance ──────────────────────────

  def test_sync_all_lists_conflicting_keys_without_values
    setup_conflict
    out, err = run_cli("sync")
    assert_match(/devops.*CONFLICT/i, out)
    assert_match(/CONFLICT.*changed on both sides.*SHARED/, err)
    assert_match(/cloud.*added.*REMOTE_ONLY/, err)
    assert_match(/cloud.*modified.*app\.TOKEN/, err)
    assert_match(/local.*added.*LOCAL_ONLY/, err)
    assert_match(/sync merge devops --prefer local/, err)
    assert_match(/sync merge devops --local SHARED$/, err)
    refute_match(/v-/, err, "a secret value leaked")
    refute @client.calls.any? { |c| c[:method] == :push_vault }
  end

  def test_sync_all_points_to_diff_when_vault_locked
    setup_conflict
    LocalVault::SessionCache.clear("devops")
    _, err = run_cli("sync")
    assert_match(/sync diff devops/, err)
    assert_match(/sync merge devops/, err)
    refute_match(/SHARED/, err)
  end

  # ── sync diff ───────────────────────────────────────────

  def test_diff_shows_keys_only
    setup_conflict
    out, = run_cli("sync", "diff", "devops")
    assert_match(/values never shown/, out)
    assert_match(/CONFLICT.*SHARED/, out)
    assert_match(/REMOTE_ONLY/, out)
    assert_match(/LOCAL_ONLY/, out)
    refute_match(/KEEP/, out, "unchanged keys are not listed")
    refute_match(/v-/, out, "a secret value leaked")
  end

  def test_diff_reports_in_sync
    vault = LocalVault::Vault.create!(name: "devops", master_key: @master_key, salt: @salt)
    vault.set("A", "1")
    store = LocalVault::Store.new("devops")
    LocalVault::SyncState.new("devops").record!(store, direction: "push")
    @client.set_vault_blob("devops", LocalVault::SyncBundle.pack(store))
    LocalVault::SessionCache.set("devops", @master_key)
    out, = run_cli("sync", "diff", "devops")
    assert_match(/same secrets/, out)
  end

  # ── sync merge ──────────────────────────────────────────

  def test_merge_refuses_without_choice_and_changes_nothing
    vault = setup_conflict
    before = LocalVault::Store.new("devops").read_encrypted
    _, err = run_cli("sync", "merge", "devops")
    assert_match(/changed on both sides/, err)
    assert_match(/--prefer local/, err)
    assert_equal before, LocalVault::Store.new("devops").read_encrypted
    refute @client.calls.any? { |c| c[:method] == :push_vault }
    assert_equal "v-local-1", vault.get("SHARED")
  end

  def test_merge_prefer_remote_merges_and_pushes
    vault = setup_conflict
    out, = run_cli("sync", "merge", "devops", "--prefer", "remote")
    assert_match(/merged devops locally/, out)
    assert_match(/pushed devops/, out)
    assert_equal "v-remote-1", vault.get("SHARED")
    assert_equal "v-l-1", vault.get("LOCAL_ONLY")
    assert_equal "v-r-1", vault.get("REMOTE_ONLY")
    assert_equal "v-tok-2", vault.get("app.TOKEN")
    assert_equal "v-same-1", vault.get("KEEP")

    push = @client.calls.find { |c| c[:method] == :push_vault }
    refute_nil push
    pushed_secrets = JSON.parse(LocalVault::Crypto.decrypt(
      LocalVault::SyncBundle.unpack(push[:args][1])[:secrets], @master_key))
    assert_equal vault.all, pushed_secrets

    ss = LocalVault::SyncState.new("devops")
    assert_equal "push", ss.read["direction"]
    assert_equal LocalVault::Store.new("devops").read_encrypted, ss.read_base
  end

  def test_merge_per_key_pick
    vault = setup_conflict
    run_cli("sync", "merge", "devops", "--local", "SHARED")
    assert_equal "v-local-1", vault.get("SHARED")
    assert_equal "v-r-1", vault.get("REMOTE_ONLY")
  end

  def test_merge_clean_needs_no_flags
    vault = setup_conflict(prefer_same: true)
    out, = run_cli("sync", "merge", "devops")
    assert_match(/pushed devops/, out)
    assert_equal "v-local-1", vault.get("SHARED")
    assert_equal "v-r-1", vault.get("REMOTE_ONLY")
  end

  def test_merge_dry_run_changes_nothing
    setup_conflict(prefer_same: true)
    before = LocalVault::Store.new("devops").read_encrypted
    out, = run_cli("sync", "merge", "devops", "--dry-run")
    assert_match(/Dry run/, out)
    assert_equal before, LocalVault::Store.new("devops").read_encrypted
    refute @client.calls.any? { |c| c[:method] == :push_vault }
  end

  def test_merge_no_push_keeps_local_only
    vault = setup_conflict(prefer_same: true)
    out, = run_cli("sync", "merge", "devops", "--no-push")
    assert_match(/not pushed/, out)
    assert_equal "v-r-1", vault.get("REMOTE_ONLY")
    refute @client.calls.any? { |c| c[:method] == :push_vault }
  end

  def test_merge_without_base_snapshot_is_union
    vault = LocalVault::Vault.create!(name: "devops", master_key: @master_key, salt: @salt)
    vault.set("A", "1")
    # Old-style state: checksum only, no .sync_base
    LocalVault::SyncState.new("devops").write!(checksum: "stale", direction: "push")
    @client.set_vault_blob("devops", build_blob("devops", { "A" => "1", "B" => "2" }))
    LocalVault::SessionCache.set("devops", @master_key)
    out, = run_cli("sync", "merge", "devops")
    assert_match(/pushed devops/, out)
    assert_equal "2", vault.get("B")
  end

  def test_merge_with_different_key_explains
    LocalVault::Vault.create!(name: "devops", master_key: @master_key, salt: @salt).set("A", "1")
    other_key = LocalVault::Crypto.derive_master_key("other", @salt)
    @client.set_vault_blob("devops", build_blob("devops", { "A" => "2" }, key: other_key))
    LocalVault::SessionCache.set("devops", @master_key)
    _, err = run_cli("sync", "merge", "devops")
    assert_match(/different key/, err)
    assert_match(/sync pull devops --force/, err)
  end

  def test_merge_rejects_key_on_both_sides
    setup_conflict
    _, err = run_cli("sync", "merge", "devops", "--local", "SHARED", "--remote", "SHARED")
    assert_match(/both --local and --remote/, err)
    refute @client.calls.any? { |c| c[:method] == :push_vault }
  end

  def test_merge_warns_on_pick_not_in_conflict
    vault = setup_conflict
    out, err = run_cli("sync", "merge", "devops", "--prefer", "remote", "--local", "NOPE")
    assert_match(/NOPE is not in conflict/, err)
    assert_match(/pushed devops/, out)
    assert_equal "v-remote-1", vault.get("SHARED")
  end

  def test_merge_corrupt_plaintext_gives_fixed_message
    LocalVault::Vault.create!(name: "devops", master_key: @master_key, salt: @salt).set("A", "1")
    meta = YAML.dump("name" => "devops", "version" => 1, "salt" => Base64.strict_encode64(@salt))
    enc  = LocalVault::Crypto.encrypt("{not json v-leak", @master_key)
    @client.set_vault_blob("devops", JSON.generate("version" => 1, "meta" => Base64.strict_encode64(meta), "secrets" => Base64.strict_encode64(enc)))
    LocalVault::SessionCache.set("devops", @master_key)
    _, err = run_cli("sync", "merge", "devops")
    assert_match(/not valid JSON/, err)
    refute_match(/v-leak/, err)
  end

  # ── team vaults ─────────────────────────────────────────

  def test_member_cannot_merge_team_vault
    vault = LocalVault::Vault.create!(name: "devops", master_key: @master_key, salt: @salt)
    vault.set("A", "1")
    LocalVault::SessionCache.set("devops", @master_key)
    alice_pub = Base64.strict_encode64(RbNaCl::PrivateKey.generate.public_key.to_bytes)
    slots = { "alice" => { "pub" => alice_pub, "enc_key" => "x", "scopes" => ["app"], "blob" => "y" } }
    @client.set_vault_blob("devops", build_v3_blob("devops", { "A" => "2" }, owner: "bob", key_slots: slots))
    _, err = run_cli("sync", "merge", "devops", "--prefer", "remote")
    assert_match(/owned by @bob; you have scoped access/, err)
    assert_match(/sync pull devops --force/, err)
    assert_equal "1", vault.get("A")
    refute @client.calls.any? { |c| c[:method] == :push_vault }
  end

  def test_owner_merge_refreshes_scoped_member_blob
    vault = LocalVault::Vault.create!(name: "devops", master_key: @master_key, salt: @salt)
    vault.set("app.TOKEN", "v-tok-1")
    store = LocalVault::Store.new("devops")
    LocalVault::SyncState.new("devops").record!(store, direction: "push")
    LocalVault::SessionCache.set("devops", @master_key)

    bob_kp  = RbNaCl::PrivateKey.generate
    bob_pub = Base64.strict_encode64(bob_kp.public_key.to_bytes)
    old_member_key = RbNaCl::Random.random_bytes(32)
    old_blob = LocalVault::Crypto.encrypt(JSON.generate({ "app" => { "TOKEN" => "v-tok-1" } }), old_member_key)
    slots = {
      "bob" => { "pub" => bob_pub, "enc_key" => LocalVault::KeySlot.create(old_member_key, bob_pub),
                 "scopes" => ["app"], "blob" => Base64.strict_encode64(old_blob) }
    }
    # Remote: owner alice, TOKEN changed in cloud; local unchanged → clean merge takes cloud.
    @client.set_vault_blob("devops", build_v3_blob("devops", { "app" => { "TOKEN" => "v-tok-2" } }, owner: "alice", key_slots: slots))

    out, = run_cli("sync", "merge", "devops")
    assert_match(/pushed devops/, out)
    assert_equal "v-tok-2", vault.get("app.TOKEN")

    push = @client.calls.find { |c| c[:method] == :push_vault }
    data = LocalVault::SyncBundle.unpack(push[:args][1])
    bob_slot = data[:key_slots]["bob"]
    member_key = LocalVault::KeySlot.decrypt(bob_slot["enc_key"], bob_kp.to_bytes)
    bob_view = JSON.parse(LocalVault::Crypto.decrypt(Base64.strict_decode64(bob_slot["blob"]), member_key))
    assert_equal({ "app" => { "TOKEN" => "v-tok-2" } }, bob_view)
  end

  def test_locked_owner_push_with_scoped_members_is_refused
    vault = LocalVault::Vault.create!(name: "devops", master_key: @master_key, salt: @salt)
    vault.set("app.TOKEN", "v-tok-1")
    LocalVault::SessionCache.clear("devops")
    bob_pub = Base64.strict_encode64(RbNaCl::PrivateKey.generate.public_key.to_bytes)
    slots = { "bob" => { "pub" => bob_pub, "enc_key" => "x", "scopes" => ["app"], "blob" => "y" } }
    @client.set_vault_blob("devops", build_v3_blob("devops", { "app" => { "TOKEN" => "v-tok-0" } }, owner: "alice", key_slots: slots))

    _, err = run_cli("sync", "push", "devops")
    assert_match(/scoped members.*locked/, err)
    assert_match(/localvault unlock devops/, err)
    refute @client.calls.any? { |c| c[:method] == :push_vault }
    refute LocalVault::SyncState.new("devops").exists?, "no baseline recorded for a refused push"
  end

  def test_diff_with_corrupt_local_plaintext_gives_fixed_message
    LocalVault::Vault.create!(name: "devops", master_key: @master_key, salt: @salt)
    store = LocalVault::Store.new("devops")
    store.write_encrypted(LocalVault::Crypto.encrypt("{ malformed v-leak", @master_key))
    LocalVault::SessionCache.clear("devops")
    @client.set_vault_blob("devops", build_blob("devops", { "A" => "1" }))
    _, err = with_passphrase(@passphrase) { run_cli("sync", "diff", "devops") }
    assert_match(/not valid JSON/, err)
    refute_match(/v-leak/, err)
  end

  # ── snapshot bookkeeping ────────────────────────────────

  def test_push_and_pull_record_base_snapshot
    vault = LocalVault::Vault.create!(name: "devops", master_key: @master_key, salt: @salt)
    vault.set("A", "1")
    run_cli("sync", "push", "devops")
    ss = LocalVault::SyncState.new("devops")
    assert_equal LocalVault::Store.new("devops").read_encrypted, ss.read_base
    assert_equal "600", File.stat(ss.base_path).mode.to_s(8)[-3..]

    @client.set_vault_blob("devops", build_blob("devops", { "A" => "9" }))
    run_cli("sync", "pull", "devops", "--force")
    assert_equal LocalVault::Store.new("devops").read_encrypted, ss.read_base
  end

  private

  def with_passphrase(value)
    klass = LocalVault::CLI::Sync
    original = klass.instance_method(:prompt_passphrase)
    klass.no_commands { klass.send(:define_method, :prompt_passphrase) { |_msg = ""| value } }
    yield
  ensure
    klass.no_commands { klass.send(:define_method, :prompt_passphrase, original) }
  end

  def run_cli(*args)
    LocalVault::ApiClient.stub(:new, @client) do
      capture_io { LocalVault::CLI.start(args) }
    end
  end

  def build_v3_blob(name, secrets, owner:, key_slots:)
    meta = YAML.dump("name" => name, "version" => 1, "salt" => Base64.strict_encode64(@salt))
    enc  = LocalVault::Crypto.encrypt(JSON.generate(secrets), @master_key)
    LocalVault::SyncBundle.pack_v3_bytes(meta_bytes: meta, secrets_bytes: enc, owner: owner, key_slots: key_slots)
  end

  def build_blob(name, secrets, key: @master_key)
    meta = YAML.dump("name" => name, "version" => 1, "salt" => Base64.strict_encode64(@salt))
    enc  = LocalVault::Crypto.encrypt(JSON.generate(secrets), key)
    JSON.generate("version" => 1, "meta" => Base64.strict_encode64(meta), "secrets" => Base64.strict_encode64(enc))
  end
end

class FakeMergeClient
  attr_reader :calls

  def initialize
    @calls = []
    @list_response = { "vaults" => [] }
    @blobs = {}
  end

  def set_list_response(r) = @list_response = r
  def set_vault_blob(name, blob) = @blobs[name] = blob

  def list_vaults
    @calls << { method: :list_vaults }
    @list_response
  end

  def pull_vault(name)
    @calls << { method: :pull_vault, args: [name] }
    blob = @blobs[name]
    raise LocalVault::ApiClient::ApiError.new("not found", status: 404) unless blob
    blob
  end

  def push_vault(name, blob)
    @calls << { method: :push_vault, args: [name, blob] }
    @blobs[name] = blob
    { "ok" => true }
  end
end
