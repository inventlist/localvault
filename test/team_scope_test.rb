require_relative "test_helper"
require "localvault/cli"
require "json"
require "base64"
require "yaml"

class TeamScopeTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @passphrase = "test-pass"
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(@passphrase, @salt)
    @vault = create_test_vault("production")
    @vault.set("platepose.DB_URL", "postgres://pp")
    @vault.set("platepose.SECRET_KEY", "sk-pp")
    @vault.set("inventlist.STRIPE_KEY", "sk-il")
    @vault.set("DATABASE_URL", "postgres://main")

    LocalVault::Identity.generate!
    LocalVault::Config.token = "tok"
    LocalVault::Config.inventlist_handle = "alice"
    LocalVault::SessionCache.set("production", @master_key)

    @bob_kp = RbNaCl::PrivateKey.generate
    @bob_pub = Base64.strict_encode64(@bob_kp.public_key.to_bytes)
    @fake_client = FakeScopeClient.new
  end

  def teardown
    LocalVault::SessionCache.clear("production")
    teardown_test_home
  end

  def test_scoped_add_sets_scopes_in_key_slot
    @fake_client.set_public_key("bob", @bob_pub)
    @fake_client.set_pull_response(v3_blob_owner_only)

    run_team_add("@bob", "production", scope: ["platepose", "DATABASE_URL"])

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert_equal ["platepose", "DATABASE_URL"], slots["bob"]["scopes"]
  end

  def test_scoped_add_creates_per_member_blob
    @fake_client.set_public_key("bob", @bob_pub)
    @fake_client.set_pull_response(v3_blob_owner_only)

    run_team_add("@bob", "production", scope: ["platepose"])

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    refute_nil slots["bob"]["blob"]
  end

  def test_scoped_blob_contains_only_scoped_keys
    @fake_client.set_public_key("bob", @bob_pub)
    @fake_client.set_pull_response(v3_blob_owner_only)

    run_team_add("@bob", "production", scope: ["platepose"])

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    blob_encrypted = Base64.strict_decode64(slots["bob"]["blob"])
    member_key = LocalVault::KeySlot.decrypt(slots["bob"]["enc_key"], @bob_kp.to_bytes)
    secrets_json = LocalVault::Crypto.decrypt(blob_encrypted, member_key)
    secrets = JSON.parse(secrets_json)

    assert secrets.key?("platepose")
    assert_equal "postgres://pp", secrets["platepose"]["DB_URL"]
    refute secrets.key?("inventlist")
    refute secrets.key?("DATABASE_URL")
  end

  def test_full_access_add_has_nil_scopes
    @fake_client.set_public_key("bob", @bob_pub)
    @fake_client.set_pull_response(v3_blob_owner_only)

    run_team_add("@bob", "production", scope: nil)

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert_nil slots["bob"]["scopes"]
    assert_nil slots["bob"]["blob"]
  end

  def test_add_scope_accumulates
    @fake_client.set_public_key("bob", @bob_pub)

    @fake_client.set_pull_response(v3_blob_owner_only)
    run_team_add("@bob", "production", scope: ["platepose"])

    @fake_client.set_pull_response(last_pushed_blob)
    run_team_add("@bob", "production", scope: ["DATABASE_URL"])

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert_includes slots["bob"]["scopes"], "platepose"
    assert_includes slots["bob"]["scopes"], "DATABASE_URL"
  end

  def test_scope_on_full_access_member_ignored
    @fake_client.set_public_key("bob", @bob_pub)
    @fake_client.set_pull_response(v3_blob_owner_only)
    run_team_add("@bob", "production", scope: nil)

    @fake_client.set_pull_response(last_pushed_blob)
    out, = run_team_add("@bob", "production", scope: ["platepose"])

    assert_match(/already has full vault access/i, out)
  end

  def test_team_add_on_personal_vault_errors
    personal = LocalVault::SyncBundle.pack(LocalVault::Store.new("production"))
    @fake_client.set_pull_response(personal)
    @fake_client.set_public_key("bob", @bob_pub)

    _, err = run_team_add("@bob", "production", scope: nil)
    assert_match(/not a team vault|team init/i, err)
  end

  private

  def create_test_vault(name)
    LocalVault::Vault.create!(name: name, master_key: @master_key, salt: @salt)
  end

  def v3_blob_owner_only
    store = LocalVault::Store.new("production")
    pub_b64 = LocalVault::Identity.public_key
    enc_key = LocalVault::KeySlot.create(@master_key, pub_b64)
    slots = { "alice" => { "pub" => pub_b64, "enc_key" => enc_key, "scopes" => nil, "blob" => nil } }
    LocalVault::SyncBundle.pack_v3(store, owner: "alice", key_slots: slots)
  end

  def run_team_add(handle, vault_name, scope: nil)
    args = ["team", "add", handle, "--vault", vault_name]
    args += ["--scope"] + scope if scope
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(args) }
    end
  end

  def last_pushed_blob
    call = @fake_client.calls.select { |c| c[:method] == :push_vault }.last
    call[:args][1]
  end
end

class FakeScopeClient
  attr_reader :calls
  def initialize
    @calls = []
    @public_keys = {}
    @pull_response = ""
  end
  def set_public_key(handle, pub) = @public_keys[handle] = pub
  def set_pull_response(blob) = @pull_response = blob
  def get_public_key(handle) = { "handle" => handle, "public_key" => @public_keys[handle] }
  def pull_vault(_) = @pull_response
  def push_vault(*args) = @calls << { method: :push_vault, args: args }
  def method_missing(name, *args, **kw) = @calls << { method: name, args: args, kwargs: kw }
  def respond_to_missing?(name, _) = name != :call
end

class TeamVerifyTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    LocalVault::Config.token = "tok"
    @fake_client = FakeVerifyClient.new
  end

  def teardown
    teardown_test_home
  end

  def test_verify_shows_public_key_info
    @fake_client.set_response({ "handle" => "bob", "public_key" => "abcdefghijklmnop" })

    out, = LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["team", "verify", "@bob"]) }
    end

    assert_match(/@bob.*public key published/i, out)
    assert_match(/fingerprint/i, out)
    assert_match(/team add @bob/i, out)
  end

  def test_verify_shows_no_key_warning
    @fake_client.set_response({ "handle" => "bob", "public_key" => nil })

    _, err = LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["team", "verify", "@bob"]) }
    end

    assert_match(/no public key/i, err)
    assert_match(/localvault login/i, err)
  end

  def test_verify_shows_not_found
    @fake_client.set_error(404)

    _, err = LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["team", "verify", "@nobody"]) }
    end

    assert_match(/not found/i, err)
  end

  def test_verify_requires_login
    LocalVault::Config.token = nil

    _, err = capture_io { LocalVault::CLI.start(["team", "verify", "@bob"]) }

    assert_match(/not logged in/i, err)
  end
end

class FakeVerifyClient
  def initialize; @response = {}; @error = nil; end
  def set_response(r) = @response = r
  def set_error(status) = @error = status
  def get_public_key(_handle)
    raise LocalVault::ApiClient::ApiError.new("Not found", status: @error) if @error
    @response
  end
end
