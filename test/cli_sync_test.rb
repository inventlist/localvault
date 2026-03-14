require_relative "test_helper"
require "minitest/mock"
require "localvault/cli"

class FakeSyncApiClient
  attr_reader :calls

  def initialize
    @calls     = []
    @responses = {}
    @error     = nil
  end

  def set_response(method, r) = @responses[method] = r
  def set_error(e)            = @error = e

  def respond_to?(name, include_private = false)
    return false if name == :call
    super
  end

  def method_missing(name, *args, **kwargs)
    @calls << { method: name, args: args, kwargs: kwargs }
    raise @error if @error
    @responses.fetch(name, {})
  end

  def respond_to_missing?(name, include_private = false)
    name != :call
  end
end

class CLISyncTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @fake_client = FakeSyncApiClient.new
    create_test_vault("default", "test-pass")
  end

  def teardown
    teardown_test_home
  end

  def create_test_vault(name, passphrase)
    salt = LocalVault::Crypto.generate_salt
    master_key = LocalVault::Crypto.derive_master_key(passphrase, salt)
    vault = LocalVault::Vault.create!(name: name, master_key: master_key, salt: salt)
    vault.set("TEST_KEY", "test_value")
    vault
  end

  def stub_api_client(client)
    LocalVault::ApiClient.stub(:new, client) { yield }
  end

  def capture_io
    out_r, out_w = IO.pipe
    err_r, err_w = IO.pipe
    orig_stdout, orig_stderr = $stdout, $stderr
    $stdout, $stderr = out_w, err_w
    yield
    out_w.close; err_w.close
    [out_r.read, err_r.read]
  ensure
    $stdout, $stderr = orig_stdout, orig_stderr
    [out_w, err_w].each { |io| io.close rescue nil }
  end

  # ── sync push ──────────────────────────────────────────────────

  def test_sync_push_requires_login
    _, err = capture_io { LocalVault::CLI.start(%w[sync push]) }
    assert_match(/Not logged in/, err)
  end

  def test_sync_push_fails_if_vault_missing
    LocalVault::Config.token = "tok"
    _, err = capture_io { LocalVault::CLI.start(%w[sync push nonexistent]) }
    assert_match(/does not exist/, err)
  end

  def test_sync_push_calls_api_with_vault_name
    LocalVault::Config.token = "tok"
    @fake_client.set_response(:push_vault, { "name" => "default", "checksum" => "abc" })
    stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync push]) }
    end
    push_call = @fake_client.calls.find { |c| c[:method] == :push_vault }
    refute_nil push_call, "Expected push_vault to be called"
    assert_equal "default", push_call[:args][0]
  end

  def test_sync_push_bundle_is_valid_json
    LocalVault::Config.token = "tok"
    @fake_client.set_response(:push_vault, { "name" => "default" })
    stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync push]) }
    end
    push_call = @fake_client.calls.find { |c| c[:method] == :push_vault }
    blob   = push_call[:args][1]
    parsed = JSON.parse(blob)
    assert_equal 1, parsed["version"]
    assert parsed.key?("meta"),    "bundle should contain meta"
    assert parsed.key?("secrets"), "bundle should contain secrets"
  end

  def test_sync_push_prints_confirmation
    LocalVault::Config.token = "tok"
    @fake_client.set_response(:push_vault, { "name" => "default" })
    out, = stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync push]) }
    end
    assert_match(/Synced vault 'default'/, out)
  end

  def test_sync_push_uses_named_vault
    LocalVault::Config.token = "tok"
    create_test_vault("work", "pass2")
    @fake_client.set_response(:push_vault, { "name" => "work" })
    stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync push work]) }
    end
    push_call = @fake_client.calls.find { |c| c[:method] == :push_vault }
    assert_equal "work", push_call[:args][0]
  end

  # ── sync pull ──────────────────────────────────────────────────

  def test_sync_pull_requires_login
    _, err = capture_io { LocalVault::CLI.start(%w[sync pull newvault]) }
    assert_match(/Not logged in/, err)
  end

  def test_sync_pull_aborts_if_vault_exists_without_force
    LocalVault::Config.token = "tok"
    _, err = stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync pull default]) }
    end
    assert_match(/already exists/, err)
  end

  def test_sync_pull_restores_vault_files
    LocalVault::Config.token = "tok"
    store = LocalVault::Store.new("default")
    blob  = LocalVault::SyncBundle.pack(store)
    @fake_client.set_response(:pull_vault, blob)
    stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync pull restored]) }
    end
    assert LocalVault::Store.new("restored").exists?, "Vault 'restored' should have been created"
  end

  def test_sync_pull_prints_confirmation
    LocalVault::Config.token = "tok"
    store = LocalVault::Store.new("default")
    blob  = LocalVault::SyncBundle.pack(store)
    @fake_client.set_response(:pull_vault, blob)
    out, = stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync pull restored]) }
    end
    assert_match(/Pulled vault 'restored'/, out)
  end

  def test_sync_pull_with_force_overwrites_existing
    LocalVault::Config.token = "tok"
    store = LocalVault::Store.new("default")
    blob  = LocalVault::SyncBundle.pack(store)
    @fake_client.set_response(:pull_vault, blob)
    out, err = stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync pull default --force]) }
    end
    assert_empty err
    assert_match(/Pulled vault 'default'/, out)
  end

  def test_sync_pull_404_shows_clean_error
    LocalVault::Config.token = "tok"
    @fake_client.set_error(LocalVault::ApiClient::ApiError.new("Not found", status: 404))
    _, err = stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync pull ghostvault]) }
    end
    assert_match(/not found in cloud/, err)
  end

  # ── sync status ────────────────────────────────────────────────

  def test_sync_status_requires_login
    _, err = capture_io { LocalVault::CLI.start(%w[sync status]) }
    assert_match(/Not logged in/, err)
  end

  def test_sync_status_shows_local_only_vault
    LocalVault::Config.token = "tok"
    @fake_client.set_response(:list_vaults, { "vaults" => [] })
    out, = stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync status]) }
    end
    assert_match(/local only/, out)
    assert_match(/default/, out)
  end

  def test_sync_status_shows_remote_only_vault
    LocalVault::Config.token = "tok"
    @fake_client.set_response(:list_vaults, {
      "vaults" => [{ "name" => "remote-only", "checksum" => "abc", "synced_at" => "2026-03-15T10:00:00Z" }]
    })
    out, = stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync status]) }
    end
    assert_match(/remote only/, out)
    assert_match(/remote-only/, out)
  end

  def test_sync_status_shows_synced_vault
    LocalVault::Config.token = "tok"
    @fake_client.set_response(:list_vaults, {
      "vaults" => [{ "name" => "default", "checksum" => "abc", "synced_at" => "2026-03-15T10:00:00Z" }]
    })
    out, = stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync status]) }
    end
    assert_match(/synced/, out)
    assert_match(/default/, out)
  end

  def test_sync_status_empty_when_no_vaults
    LocalVault::Config.token = "tok"
    LocalVault::Store.new("default").destroy!
    @fake_client.set_response(:list_vaults, { "vaults" => [] })
    out, = stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[sync status]) }
    end
    assert_match(/No vaults/, out)
  end
end
