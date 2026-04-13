require_relative "test_helper"
require "localvault/sync_state"

class SyncStateTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @passphrase = "test-pass"
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(@passphrase, @salt)
  end

  def teardown
    teardown_test_home
  end

  def test_path_returns_correct_location
    ss = LocalVault::SyncState.new("production")
    assert ss.path.end_with?("production/.sync_state")
  end

  def test_exists_false_when_no_file
    ss = LocalVault::SyncState.new("production")
    refute ss.exists?
  end

  def test_write_and_read_roundtrip
    ss = LocalVault::SyncState.new("production")
    # Need the vault directory to exist
    FileUtils.mkdir_p(File.dirname(ss.path))

    ss.write!(checksum: "abc123", direction: "push")

    assert ss.exists?
    data = ss.read
    assert_equal "abc123", data["last_synced_checksum"]
    assert_equal "push",   data["direction"]
    assert data["last_synced_at"].is_a?(String)
  end

  def test_last_synced_checksum
    ss = LocalVault::SyncState.new("production")
    FileUtils.mkdir_p(File.dirname(ss.path))

    assert_nil ss.last_synced_checksum

    ss.write!(checksum: "deadbeef", direction: "pull")
    assert_equal "deadbeef", ss.last_synced_checksum
  end

  def test_local_checksum_returns_sha256
    vault = LocalVault::Vault.create!(name: "production", master_key: @master_key, salt: @salt)
    vault.set("SECRET", "value")

    store = LocalVault::Store.new("production")
    checksum = LocalVault::SyncState.local_checksum(store)

    refute_nil checksum
    assert_equal 64, checksum.length  # SHA256 hex is 64 chars
  end

  def test_local_checksum_returns_nil_for_empty_vault
    # Create vault directory with meta but no secrets.enc
    store = LocalVault::Store.new("production")
    FileUtils.mkdir_p(store.vault_path, mode: 0o700)
    store.create_meta!(salt: @salt)

    checksum = LocalVault::SyncState.local_checksum(store)
    assert_nil checksum
  end

  def test_local_checksum_is_deterministic
    vault = LocalVault::Vault.create!(name: "production", master_key: @master_key, salt: @salt)
    vault.set("SECRET", "value")

    store = LocalVault::Store.new("production")
    c1 = LocalVault::SyncState.local_checksum(store)
    c2 = LocalVault::SyncState.local_checksum(store)
    assert_equal c1, c2
  end

  def test_local_checksum_changes_when_secrets_change
    vault = LocalVault::Vault.create!(name: "production", master_key: @master_key, salt: @salt)
    vault.set("SECRET", "value1")

    store = LocalVault::Store.new("production")
    c1 = LocalVault::SyncState.local_checksum(store)

    vault.set("SECRET", "value2")
    c2 = LocalVault::SyncState.local_checksum(store)

    refute_equal c1, c2
  end

  def test_file_permissions_are_restrictive
    ss = LocalVault::SyncState.new("production")
    FileUtils.mkdir_p(File.dirname(ss.path))
    ss.write!(checksum: "test", direction: "push")

    mode = File.stat(ss.path).mode & 0o777
    assert_equal 0o600, mode
  end
end
