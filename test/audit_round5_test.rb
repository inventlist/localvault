require_relative "test_helper"
require_relative "../lib/localvault/cli"
require "base64"
require "json"
require "yaml"

# Audit round 5 — integration gaps where hardening exists but isn't wired in.
class AuditRound5Test < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(test_passphrase, @salt)
  end

  def teardown
    teardown_test_home
  end

  # ── Finding 1: sync pull must pass expected_name to unpack ──

  def test_sync_pull_rejects_mismatched_meta_name
    LocalVault::Config.token = "tok"

    # Create a vault named "default" and pack it
    vault = LocalVault::Vault.create!(name: "default", master_key: @master_key, salt: @salt)
    vault.set("KEY", "val")
    store = LocalVault::Store.new("default")
    blob = LocalVault::SyncBundle.pack(store)

    # Tamper: change meta name to "evil"
    data = JSON.parse(blob)
    meta = YAML.safe_load(Base64.strict_decode64(data["meta"]))
    meta["name"] = "evil"
    data["meta"] = Base64.strict_encode64(YAML.dump(meta))
    tampered_blob = JSON.generate(data)

    fake = FakeSyncClient.new
    fake.set_pull_response(tampered_blob)

    stub_sync_client(fake) do
      _, err = capture_io { LocalVault::CLI.start(%w[sync pull default --force]) }
      assert_match(/does not match|mismatch|error/i, err,
        "sync pull should reject blob with mismatched meta name")
    end
  end

  # ── Finding 2: sync pull must rescue UnpackError ──

  def test_sync_pull_rescues_unpack_error
    LocalVault::Config.token = "tok"

    fake = FakeSyncClient.new
    fake.set_pull_response("not json at all")

    stub_sync_client(fake) do
      _, err = capture_io { LocalVault::CLI.start(%w[sync pull myvault]) }
      assert_match(/error/i, err, "sync pull should handle malformed blob gracefully")
    end
    # Should not raise — the error is caught and printed
  end

  # ── Finding 3: Config.save must create root_path with 0700 ──

  def test_config_save_creates_root_dir_with_0700
    # Use a fresh LOCALVAULT_HOME that doesn't exist yet
    fresh_home = File.join(@test_home, "fresh")
    ENV["LOCALVAULT_HOME"] = fresh_home

    refute File.exist?(fresh_home)
    LocalVault::Config.save("token" => "test")
    assert File.directory?(fresh_home)

    mode = File.stat(fresh_home).mode & 0o777
    assert_equal 0o700, mode, "root dir should be 0700 on first write, got #{format("%04o", mode)}"
  end

  private

  def stub_sync_client(fake)
    original_new = LocalVault::ApiClient.method(:new)
    LocalVault::ApiClient.define_singleton_method(:new) { |**_| fake }
    yield
  ensure
    LocalVault::ApiClient.define_singleton_method(:new, original_new)
  end
end

class FakeSyncClient
  def initialize
    @pull_response = ""
  end

  def set_pull_response(blob) = @pull_response = blob
  def pull_vault(_name) = @pull_response
  def list_vaults = { "vaults" => [] }
end
