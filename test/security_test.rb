require_relative "test_helper"
require "base64"

# Tests for security findings #1–#7.
# Each test documents the vulnerability and expected behavior after the fix.
class SecurityTest < Minitest::Test
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

  # ── Finding #1: Path traversal via vault names ───────────────────

  def test_store_rejects_path_traversal_dotdot
    assert_raises(LocalVault::Store::InvalidVaultName) do
      LocalVault::Store.new("../../../tmp/owned")
    end
  end

  def test_store_rejects_path_traversal_slashes
    assert_raises(LocalVault::Store::InvalidVaultName) do
      LocalVault::Store.new("foo/bar")
    end
  end

  def test_store_rejects_dot_only_names
    assert_raises(LocalVault::Store::InvalidVaultName) do
      LocalVault::Store.new(".")
    end
    assert_raises(LocalVault::Store::InvalidVaultName) do
      LocalVault::Store.new("..")
    end
  end

  def test_store_rejects_empty_vault_name
    assert_raises(LocalVault::Store::InvalidVaultName) do
      LocalVault::Store.new("")
    end
  end

  def test_store_rejects_nil_vault_name
    assert_raises(LocalVault::Store::InvalidVaultName) do
      LocalVault::Store.new(nil)
    end
  end

  def test_store_accepts_valid_vault_names
    %w[default staging my-vault my_vault vault123 A].each do |name|
      store = LocalVault::Store.new(name)
      assert_equal name, store.vault_name
    end
  end

  def test_store_rejects_names_with_spaces
    assert_raises(LocalVault::Store::InvalidVaultName) do
      LocalVault::Store.new("my vault")
    end
  end

  def test_store_rejects_names_starting_with_dash
    assert_raises(LocalVault::Store::InvalidVaultName) do
      LocalVault::Store.new("-vault")
    end
  end

  def test_store_vault_path_stays_inside_vaults_dir
    store = LocalVault::Store.new("default")
    vaults_dir = LocalVault::Config.vaults_path
    assert store.vault_path.start_with?(vaults_dir),
      "vault_path should be inside vaults directory"
  end

  # ── Finding #2: Shell injection via key names in export_env ──────

  def test_vault_set_rejects_shell_metacharacters_in_key
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    assert_raises(LocalVault::Vault::InvalidKeyName) do
      vault.set("$(touch /tmp/pwned)", "value")
    end
  end

  def test_vault_set_rejects_semicolon_in_key
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    assert_raises(LocalVault::Vault::InvalidKeyName) do
      vault.set("FOO;rm -rf /", "value")
    end
  end

  def test_vault_set_rejects_spaces_in_key
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    assert_raises(LocalVault::Vault::InvalidKeyName) do
      vault.set("MY KEY", "value")
    end
  end

  def test_vault_set_rejects_empty_key
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    assert_raises(LocalVault::Vault::InvalidKeyName) do
      vault.set("", "value")
    end
  end

  def test_vault_set_rejects_empty_group_in_dotted_key
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    assert_raises(LocalVault::Vault::InvalidKeyName) do
      vault.set(".KEY", "value")
    end
  end

  def test_vault_set_rejects_empty_subkey_in_dotted_key
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    assert_raises(LocalVault::Vault::InvalidKeyName) do
      vault.set("group.", "value")
    end
  end

  def test_vault_set_accepts_valid_keys
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    %w[DATABASE_URL API_KEY _PRIVATE STRIPE_SECRET_KEY app.DB_URL myapp.SECRET_KEY_BASE].each do |key|
      vault.set(key, "value")
      assert_equal "value", vault.get(key)
    end
  end

  def test_export_env_keys_are_shell_safe
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault.set("SAFE_KEY", "safe_value")
    output = vault.export_env
    # Every line must match: export IDENTIFIER=escaped_value
    output.each_line do |line|
      assert_match(/\Aexport [A-Za-z_][A-Za-z0-9_]*=/, line.strip,
        "export_env line is not shell-safe: #{line}")
    end
  end

  # ── Finding #3: Nested vault corruption in receive ───────────────

  def test_vault_merge_preserves_nested_hashes
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    secrets = { "app" => { "DB" => "postgres://localhost", "KEY" => "secret" }, "FLAT" => "value" }
    vault.merge(secrets)

    assert_equal "postgres://localhost", vault.get("app.DB")
    assert_equal "secret", vault.get("app.KEY")
    assert_equal "value", vault.get("FLAT")
  end

  def test_vault_merge_does_not_stringify_hashes
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    nested = { "myapp" => { "DATABASE_URL" => "postgres://localhost" } }
    vault.merge(nested)

    raw = vault.all
    assert_kind_of Hash, raw["myapp"], "Nested hash should be preserved, not stringified"
    assert_equal "postgres://localhost", raw["myapp"]["DATABASE_URL"]
  end

  def test_vault_merge_single_encrypt_cycle
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    secrets = { "A" => "1", "B" => "2", "C" => "3" }
    vault.merge(secrets)
    assert_equal 3, vault.store.count
  end

  # ── Finding #4: SessionCache macOS Keychain flags ────────────────
  # (Tested via the existing session_cache_test.rb — the fix changes
  #  the Keychain flags and adds error checking. Tests verify set/get
  #  round-trip works after the fix.)

  # ── Finding #5: Config file permissions ──────────────────────────

  def test_config_save_creates_file_with_restricted_permissions
    LocalVault::Config.save("token" => "secret-token")
    mode = File.stat(LocalVault::Config.config_path).mode & 0o777
    assert_equal 0o600, mode, "config.yml should be mode 0600, got #{format("%04o", mode)}"
  end

  # ── Finding #6: Malformed payload error handling ─────────────────

  def test_share_crypto_decrypt_invalid_base64_raises_decryption_error
    assert_raises(LocalVault::ShareCrypto::DecryptionError) do
      LocalVault::ShareCrypto.decrypt_from("not-valid-base64!!!", RbNaCl::Random.random_bytes(32))
    end
  end

  def test_share_crypto_decrypt_garbage_json_raises_decryption_error
    garbage = Base64.strict_encode64("not json at all")
    assert_raises(LocalVault::ShareCrypto::DecryptionError) do
      LocalVault::ShareCrypto.decrypt_from(garbage, RbNaCl::Random.random_bytes(32))
    end
  end

  def test_sync_bundle_unpack_invalid_base64_raises_controlled_error
    blob = '{"version":1,"meta":"!!!invalid!!!","secrets":"!!!invalid!!!"}'
    assert_raises(LocalVault::SyncBundle::UnpackError) do
      LocalVault::SyncBundle.unpack(blob)
    end
  end

  def test_sync_bundle_unpack_invalid_json_raises_controlled_error
    assert_raises(LocalVault::SyncBundle::UnpackError) do
      LocalVault::SyncBundle.unpack("not json")
    end
  end

  def test_sync_bundle_unpack_missing_keys_raises_controlled_error
    blob = '{"version":1}'
    assert_raises(LocalVault::SyncBundle::UnpackError) do
      LocalVault::SyncBundle.unpack(blob)
    end
  end

  # ── Finding #7: Bulk import uses merge (single cycle) ────────────
  # (Tested via test_vault_merge_single_encrypt_cycle above)
end
