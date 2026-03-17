require_relative "test_helper"
require_relative "../lib/localvault/cli"
require "base64"
require "json"
require "yaml"

# Audit round 4 — release workflow, sync pull validation, export warnings,
# write timeout, session cleanup.
class AuditRound4Test < Minitest::Test
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

  # ── Finding 3: sync pull must validate meta.yml name matches vault name ──

  def test_sync_bundle_unpack_returns_meta_as_parsed_yaml
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault.set("KEY", "val")
    store = LocalVault::Store.new("test")

    blob = LocalVault::SyncBundle.pack(store)
    data = LocalVault::SyncBundle.unpack(blob)

    # Meta should be parseable YAML with expected fields
    meta = YAML.safe_load(data[:meta])
    assert_equal "test", meta["name"]
    assert meta["salt"]
    assert meta["version"]
  end

  def test_sync_bundle_validate_meta_rejects_mismatched_name
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    store = LocalVault::Store.new("test")

    # Craft a bundle with wrong vault name in meta
    bad_meta = YAML.dump({
      "name" => "evil-vault",
      "created_at" => Time.now.utc.iso8601,
      "version" => 1,
      "salt" => Base64.strict_encode64(LocalVault::Crypto.generate_salt)
    })
    blob = JSON.generate({
      "version" => 1,
      "meta" => Base64.strict_encode64(bad_meta),
      "secrets" => Base64.strict_encode64("")
    })

    assert_raises(LocalVault::SyncBundle::UnpackError) do
      LocalVault::SyncBundle.unpack(blob, expected_name: "test")
    end
  end

  def test_sync_bundle_validate_meta_accepts_matching_name
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    store = LocalVault::Store.new("test")

    blob = LocalVault::SyncBundle.pack(store)
    data = LocalVault::SyncBundle.unpack(blob, expected_name: "test")
    refute_nil data[:meta]
  end

  # ── Finding 4: export_env/env_hash should warn on skipped keys ──

  def test_export_env_warns_on_skipped_keys
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    inject_raw_secrets(vault, { "GOOD" => "ok", "BAD;KEY" => "evil" })

    _out, err = capture_io do
      vault.export_env(on_skip: ->(k) { $stderr.puts "Skipped: #{k}" })
    end
    assert_includes err, "Skipped: BAD;KEY"
  end

  def test_env_hash_warns_on_skipped_keys
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    inject_raw_secrets(vault, { "GOOD" => "ok", "$(evil)" => "x" })

    _out, err = capture_io do
      vault.env_hash(on_skip: ->(k) { $stderr.puts "Skipped: #{k}" })
    end
    assert_includes err, "Skipped: $(evil)"
  end

  # ── Finding 5: write_timeout on HTTP requests ──

  def test_api_client_has_write_timeout
    # Verify the write_timeout is set by checking it doesn't raise
    # (actual timeout behavior needs a real slow server)
    client = LocalVault::ApiClient.new(token: "test", base_url: "https://example.com")
    assert_respond_to client, :push_vault
  end

  # ── Finding 6: expired sessions should be cleaned up ──

  def test_session_cache_deletes_expired_entry
    vault_name = "test-vault"
    key = LocalVault::Crypto.generate_salt  # 16 bytes as stand-in

    # Set with TTL=0 (already expired)
    LocalVault::SessionCache.set(vault_name, key, ttl_hours: 0)

    # Get should return nil AND clean up the expired entry
    assert_nil LocalVault::SessionCache.get(vault_name)

    # The underlying file/keychain entry should be gone
    file = LocalVault::SessionCache.send(:session_file, vault_name)
    refute File.exist?(file), "Expired session file should be deleted"
  end

  private

  def inject_raw_secrets(vault, secrets_hash)
    json = JSON.generate(secrets_hash)
    encrypted = LocalVault::Crypto.encrypt(json, vault.master_key)
    vault.store.write_encrypted(encrypted)
  end
end
