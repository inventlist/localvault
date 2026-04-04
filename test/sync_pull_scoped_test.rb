require_relative "test_helper"
require "localvault/cli"
require "json"
require "base64"
require "yaml"

class SyncPullScopedTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @passphrase = "test-pass"
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(@passphrase, @salt)
    @fake_client = FakeScopedPullClient.new

    LocalVault::Identity.generate!
    LocalVault::Config.token = "tok"
    LocalVault::Config.inventlist_handle = "bob"
  end

  def teardown
    LocalVault::SessionCache.clear("production")
    teardown_test_home
  end

  def test_scoped_pull_decrypts_filtered_blob
    blob = build_v3_with_scoped_bob(["platepose"])
    @fake_client.set_pull_response(blob)

    out, = pull_and_capture("production")

    assert_match(/pulled/i, out)
    assert_match(/unlocked via/i, out)

    cached = LocalVault::SessionCache.get("production")
    refute_nil cached, "Scoped pull should cache the per-member key"

    vault = LocalVault::Vault.new(name: "production", master_key: cached)
    secrets = vault.all

    assert secrets.key?("platepose")
    assert_equal "postgres://pp", secrets.dig("platepose", "DB_URL")
    refute secrets.key?("inventlist")
    refute secrets.key?("DATABASE_URL")
  end

  def test_full_access_pull_decrypts_full_blob
    LocalVault::Config.inventlist_handle = "carol"
    LocalVault::Identity.generate!(force: true)
    blob = build_v3_with_full_access_carol
    @fake_client.set_pull_response(blob)

    out, = pull_and_capture("production")

    assert_match(/unlocked via/i, out)
    cached = LocalVault::SessionCache.get("production")
    vault = LocalVault::Vault.new(name: "production", master_key: cached)
    secrets = vault.all

    assert secrets.key?("platepose")
    assert secrets.key?("inventlist")
    assert secrets.key?("DATABASE_URL")
  end

  def test_no_matching_slot_falls_back
    blob = build_v3_without_bob
    @fake_client.set_pull_response(blob)

    out, = pull_and_capture("production")

    assert_match(/pulled/i, out)
    assert_match(/unlock it with/i, out)
    assert_nil LocalVault::SessionCache.get("production")
  end

  private

  def build_v3_with_scoped_bob(scopes)
    all_secrets = {
      "platepose" => { "DB_URL" => "postgres://pp", "SECRET_KEY" => "sk-pp" },
      "inventlist" => { "STRIPE_KEY" => "sk-il" },
      "DATABASE_URL" => "postgres://main"
    }

    filtered = {}
    scopes.each { |s| filtered[s] = all_secrets[s] if all_secrets[s] }

    member_key = RbNaCl::Random.random_bytes(32)
    encrypted_blob = LocalVault::Crypto.encrypt(JSON.generate(filtered), member_key)

    bob_pub = LocalVault::Identity.public_key
    enc_key = LocalVault::KeySlot.create(member_key, bob_pub)

    full_encrypted = LocalVault::Crypto.encrypt(JSON.generate(all_secrets), @master_key)
    meta = YAML.dump({ "name" => "production", "created_at" => Time.now.utc.iso8601, "version" => 1, "salt" => Base64.strict_encode64(@salt), "count" => 4 })

    JSON.generate({
      "version" => 3, "owner" => "alice",
      "meta" => Base64.strict_encode64(meta),
      "secrets" => Base64.strict_encode64(full_encrypted),
      "key_slots" => {
        "bob" => { "pub" => bob_pub, "enc_key" => enc_key, "scopes" => scopes, "blob" => Base64.strict_encode64(encrypted_blob) }
      }
    })
  end

  def build_v3_with_full_access_carol
    all_secrets = { "platepose" => { "DB_URL" => "postgres://pp" }, "inventlist" => { "STRIPE_KEY" => "sk-il" }, "DATABASE_URL" => "postgres://main" }
    full_encrypted = LocalVault::Crypto.encrypt(JSON.generate(all_secrets), @master_key)
    meta = YAML.dump({ "name" => "production", "created_at" => Time.now.utc.iso8601, "version" => 1, "salt" => Base64.strict_encode64(@salt) })
    carol_pub = LocalVault::Identity.public_key
    enc_key = LocalVault::KeySlot.create(@master_key, carol_pub)

    JSON.generate({
      "version" => 3, "owner" => "alice",
      "meta" => Base64.strict_encode64(meta),
      "secrets" => Base64.strict_encode64(full_encrypted),
      "key_slots" => { "carol" => { "pub" => carol_pub, "enc_key" => enc_key, "scopes" => nil, "blob" => nil } }
    })
  end

  def build_v3_without_bob
    meta = YAML.dump({ "name" => "production", "created_at" => Time.now.utc.iso8601, "version" => 1, "salt" => Base64.strict_encode64(@salt) })
    JSON.generate({ "version" => 3, "owner" => "alice", "meta" => Base64.strict_encode64(meta), "secrets" => Base64.strict_encode64(""), "key_slots" => {} })
  end

  def pull_and_capture(vault_name)
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["sync", "pull", vault_name]) }
    end
  end
end

class FakeScopedPullClient
  def initialize; @pull_response = ""; end
  def set_pull_response(blob) = @pull_response = blob
  def pull_vault(_) = @pull_response
  def method_missing(name, *args, **kw) = {}
  def respond_to_missing?(name, _) = name != :call
end
