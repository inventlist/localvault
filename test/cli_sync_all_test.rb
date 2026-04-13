require_relative "test_helper"
require "localvault/cli"
require "json"
require "base64"
require "yaml"
require "digest"

# Integration tests for `localvault sync` (bare command — bidirectional sync).
class CLISyncAllTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    LocalVault::Config.token = "tok"
    LocalVault::Config.inventlist_handle = "alice"
    @passphrase = "test-pass"
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(@passphrase, @salt)
    @fake_client = FakeSyncAllClient.new
  end

  def teardown
    teardown_test_home
  end

  # ── Auth ──────────────────────────────────────────────────

  def test_sync_requires_login
    LocalVault::Config.token = nil
    _, err = run_sync
    assert_match(/not logged in/i, err)
  end

  # ── Empty state ───────────────────────────────────────────

  def test_sync_no_vaults
    @fake_client.set_list_response({ "vaults" => [] })
    out, = run_sync
    assert_match(/no vaults to sync/i, out)
  end

  # ── Local-only → push ────────────────────────────────────

  def test_sync_pushes_local_only_vault
    create_test_vault("production")
    @fake_client.set_list_response({ "vaults" => [] })

    out, = run_sync
    assert_match(/production.*push.*local only/i, out)
    assert_match(/pushed production/i, out)

    push_call = @fake_client.calls.find { |c| c[:method] == :push_vault && c[:args][0] == "production" }
    refute_nil push_call, "Expected push_vault to be called for production"
  end

  def test_sync_writes_sync_state_after_push
    create_test_vault("production")
    @fake_client.set_list_response({ "vaults" => [] })

    run_sync

    ss = LocalVault::SyncState.new("production")
    assert ss.exists?, ".sync_state should be written after push"
    assert_equal "push", ss.read["direction"]
  end

  # ── Remote-only → pull ───────────────────────────────────

  def test_sync_pulls_remote_only_vault
    blob = build_v1_blob("work")
    @fake_client.set_list_response({ "vaults" => [
      { "name" => "work", "checksum" => Digest::SHA256.hexdigest(blob), "shared" => false }
    ] })
    @fake_client.set_vault_blob("work", blob)

    out, = run_sync
    assert_match(/work.*pull.*remote only/i, out)
    assert_match(/pulled work/i, out)

    assert LocalVault::Store.new("work").exists?, "work vault should exist locally after pull"
  end

  def test_sync_writes_sync_state_after_pull
    blob = build_v1_blob("work")
    @fake_client.set_list_response({ "vaults" => [
      { "name" => "work", "checksum" => Digest::SHA256.hexdigest(blob), "shared" => false }
    ] })
    @fake_client.set_vault_blob("work", blob)

    run_sync

    ss = LocalVault::SyncState.new("work")
    assert ss.exists?, ".sync_state should be written after pull"
    assert_equal "pull", ss.read["direction"]
  end

  # ── Both exist, up to date → skip ───────────────────────

  def test_sync_skips_up_to_date_vault
    vault = create_test_vault("production")
    store = LocalVault::Store.new("production")
    local_cs = LocalVault::SyncState.local_checksum(store)

    # Write sync state matching current local state
    LocalVault::SyncState.new("production").write!(checksum: local_cs, direction: "push")

    @fake_client.set_list_response({ "vaults" => [
      { "name" => "production", "checksum" => local_cs, "shared" => false }
    ] })

    out, = run_sync
    assert_match(/production.*skip.*up to date/i, out)

    # No push or pull should have happened
    refute @fake_client.calls.any? { |c| c[:method] == :push_vault },
           "should not push when up to date"
  end

  # ── Both exist, local changed → push ────────────────────

  def test_sync_pushes_when_local_changed
    vault = create_test_vault("production")
    store = LocalVault::Store.new("production")

    # Record baseline before editing
    baseline = LocalVault::SyncState.local_checksum(store)
    LocalVault::SyncState.new("production").write!(checksum: baseline, direction: "push")

    # Edit a secret locally → local checksum changes
    vault.set("NEW_KEY", "new_value")
    new_local_cs = LocalVault::SyncState.local_checksum(store)
    refute_equal baseline, new_local_cs

    @fake_client.set_list_response({ "vaults" => [
      { "name" => "production", "checksum" => baseline, "shared" => false }
    ] })

    out, = run_sync
    assert_match(/production.*push.*local changes/i, out)
    assert_match(/pushed production/i, out)
  end

  # ── Both exist, remote changed → pull ───────────────────

  def test_sync_pulls_when_remote_changed
    create_test_vault("production")
    store = LocalVault::Store.new("production")
    baseline = LocalVault::SyncState.local_checksum(store)
    LocalVault::SyncState.new("production").write!(checksum: baseline, direction: "push")

    # Remote has a different checksum (someone else pushed)
    new_remote_cs = "deadbeef" * 8  # 64 chars, different from baseline
    blob = build_v1_blob_from_store("production")
    @fake_client.set_list_response({ "vaults" => [
      { "name" => "production", "checksum" => new_remote_cs, "shared" => false }
    ] })
    @fake_client.set_vault_blob("production", blob)

    out, = run_sync
    assert_match(/production.*pull.*remote changes/i, out)
    assert_match(/pulled production/i, out)
  end

  # ── Both changed → conflict ─────────────────────────────

  def test_sync_detects_conflict
    vault = create_test_vault("production")
    store = LocalVault::Store.new("production")
    baseline = LocalVault::SyncState.local_checksum(store)
    LocalVault::SyncState.new("production").write!(checksum: baseline, direction: "push")

    # Edit locally
    vault.set("LOCAL_CHANGE", "yes")

    # Remote also changed
    new_remote_cs = "cafebabe" * 8
    @fake_client.set_list_response({ "vaults" => [
      { "name" => "production", "checksum" => new_remote_cs, "shared" => false }
    ] })

    out, err = run_sync
    assert_match(/production.*CONFLICT.*both.*changed/i, out)
    assert_match(/sync push production|sync pull production/i, err)

    # No push or pull should have happened
    refute @fake_client.calls.any? { |c| c[:method] == :push_vault },
           "should not push on conflict"
  end

  # ── Shared vault (pull-only) ────────────────────────────

  def test_sync_skips_push_for_shared_vault
    create_test_vault("marketing")
    store = LocalVault::Store.new("marketing")
    baseline = LocalVault::SyncState.local_checksum(store)
    LocalVault::SyncState.new("marketing").write!(checksum: baseline, direction: "pull")

    # Edit locally, but vault is shared (not ours)
    vault = LocalVault::Vault.new(name: "marketing", master_key: @master_key)
    vault.set("LOCAL_EDIT", "yes")

    @fake_client.set_list_response({ "vaults" => [
      { "name" => "marketing", "owner_handle" => "mustafa", "shared" => true, "checksum" => baseline }
    ] })

    out, = run_sync
    assert_match(/marketing.*skip.*shared/i, out)
    refute @fake_client.calls.any? { |c| c[:method] == :push_vault },
           "should not push shared vault"
  end

  def test_sync_pulls_shared_vault_when_remote_changed
    create_test_vault("marketing")
    store = LocalVault::Store.new("marketing")
    baseline = LocalVault::SyncState.local_checksum(store)
    LocalVault::SyncState.new("marketing").write!(checksum: baseline, direction: "pull")

    new_remote_cs = "newremote" * 8
    blob = build_v1_blob_from_store("marketing")
    @fake_client.set_list_response({ "vaults" => [
      { "name" => "marketing", "owner_handle" => "mustafa", "shared" => true, "checksum" => new_remote_cs }
    ] })
    @fake_client.set_vault_blob("marketing", blob)

    out, = run_sync
    assert_match(/marketing.*pull.*remote changes/i, out)
  end

  # ── Dry run ─────────────────────────────────────────────

  def test_sync_dry_run_makes_no_changes
    create_test_vault("production")
    @fake_client.set_list_response({ "vaults" => [] })

    out, = run_sync("--dry-run")
    assert_match(/production.*push.*local only/i, out)
    assert_match(/dry run/i, out)

    refute @fake_client.calls.any? { |c| c[:method] == :push_vault },
           "dry run should not push"
  end

  # ── First sync, matching checksums → skip ───────────────

  def test_sync_first_time_matching_checksums_skips
    create_test_vault("production")
    store = LocalVault::Store.new("production")
    local_cs = LocalVault::SyncState.local_checksum(store)

    # No .sync_state yet, but checksums match
    @fake_client.set_list_response({ "vaults" => [
      { "name" => "production", "checksum" => local_cs, "shared" => false }
    ] })

    out, = run_sync
    assert_match(/production.*skip.*already in sync/i, out)
  end

  # ── First sync, mismatched checksums → conflict ─────────

  def test_sync_first_time_mismatched_checksums_conflicts
    create_test_vault("production")

    @fake_client.set_list_response({ "vaults" => [
      { "name" => "production", "checksum" => "different" * 8, "shared" => false }
    ] })

    out, = run_sync
    assert_match(/production.*CONFLICT.*no sync baseline/i, out)
  end

  # ── Error isolation ─────────────────────────────────────

  def test_sync_continues_on_single_vault_error
    create_test_vault("good")
    create_test_vault("bad")

    @fake_client.set_list_response({ "vaults" => [] })
    @fake_client.set_push_error("bad", LocalVault::ApiClient::ApiError.new("server error", status: 500))

    out, err = run_sync
    assert_match(/pushed good/i, out)
    assert_match(/error.*bad/i, err)
  end

  # ── Summary ─────────────────────────────────────────────

  def test_sync_shows_summary
    create_test_vault("local-vault")
    @fake_client.set_list_response({ "vaults" => [] })

    out, = run_sync
    assert_match(/summary/i, out)
    assert_match(/1 pushed/i, out)
  end

  # ── Existing push/pull also write sync state ────────────

  def test_existing_push_writes_sync_state
    create_test_vault("production")
    LocalVault::Config.token = "tok"

    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync push production]) }
    end

    ss = LocalVault::SyncState.new("production")
    assert ss.exists?, "sync push should write .sync_state"
    assert_equal "push", ss.read["direction"]
  end

  def test_existing_pull_writes_sync_state
    blob = build_v1_blob("restored")
    @fake_client.set_vault_blob("restored", blob)

    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync pull restored]) }
    end

    ss = LocalVault::SyncState.new("restored")
    assert ss.exists?, "sync pull should write .sync_state"
    assert_equal "pull", ss.read["direction"]
  end

  private

  def run_sync(*extra_args)
    args = ["sync"] + extra_args
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(args) }
    end
  end

  def create_test_vault(name)
    vault = LocalVault::Vault.create!(name: name, master_key: @master_key, salt: @salt)
    vault.set("SECRET", "value")
    vault
  end

  def build_v1_blob(name)
    # Build a minimal v1 bundle without requiring a local store
    meta = YAML.dump("name" => name, "version" => 1, "salt" => Base64.strict_encode64(@salt))
    secrets = LocalVault::Crypto.encrypt(JSON.generate({ "SECRET" => "remote-value" }), @master_key)
    JSON.generate(
      "version" => 1,
      "meta"    => Base64.strict_encode64(meta),
      "secrets" => Base64.strict_encode64(secrets)
    )
  end

  def build_v1_blob_from_store(name)
    store = LocalVault::Store.new(name)
    LocalVault::SyncBundle.pack(store)
  end
end

class FakeSyncAllClient
  attr_reader :calls

  def initialize
    @calls = []
    @list_response = { "vaults" => [] }
    @vault_blobs = {}
    @push_errors = {}
  end

  def set_list_response(r)
    @list_response = r
  end

  def set_vault_blob(name, blob)
    @vault_blobs[name] = blob
  end

  def set_push_error(name, error)
    @push_errors[name] = error
  end

  def list_vaults
    @calls << { method: :list_vaults }
    @list_response
  end

  def pull_vault(name)
    @calls << { method: :pull_vault, args: [name] }
    raise LocalVault::ApiClient::ApiError.new("Not found", status: 404) unless @vault_blobs.key?(name)
    @vault_blobs[name]
  end

  def push_vault(name, blob)
    @calls << { method: :push_vault, args: [name, blob] }
    raise @push_errors[name] if @push_errors.key?(name)
    { "name" => name, "checksum" => Digest::SHA256.hexdigest(blob) }
  end

  def method_missing(name, *args, **kwargs)
    @calls << { method: name, args: args, kwargs: kwargs }
    {}
  end

  def respond_to_missing?(name, _)
    name != :call
  end
end
