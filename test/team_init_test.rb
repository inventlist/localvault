require_relative "test_helper"
require "localvault/cli"
require "json"
require "base64"
require "yaml"

class TeamInitTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @passphrase = "test-pass"
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(@passphrase, @salt)
    create_test_vault("production")
    LocalVault::Identity.generate!
    LocalVault::Config.token = "tok"
    LocalVault::Config.inventlist_handle = "alice"
    LocalVault::SessionCache.set("production", @master_key)
    @fake_client = FakeInitClient.new
  end

  def teardown
    LocalVault::SessionCache.clear("production")
    teardown_test_home
  end

  def test_init_creates_v3_bundle_with_owner
    @fake_client.set_pull_response(personal_v1_blob)

    out, = run_team_init("production")

    assert_match(/team vault/, out)
    assert_match(/alice/, out)

    pushed = last_pushed_blob
    data = JSON.parse(pushed)
    assert_equal 3, data["version"]
    assert_equal "alice", data["owner"]
    assert data["key_slots"].key?("alice")
  end

  def test_init_owner_slot_has_nil_scopes
    @fake_client.set_pull_response(personal_v1_blob)

    run_team_init("production")

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert_nil slots["alice"]["scopes"]
    assert_nil slots["alice"]["blob"]
  end

  def test_init_requires_login
    LocalVault::Config.token = nil
    _, err = capture_io { LocalVault::CLI.start(["team", "init", "--vault", "production"]) }
    assert_match(/not logged in/i, err)
  end

  def test_init_requires_synced_vault
    @fake_client.set_pull_error(404)

    _, err = run_team_init("production")
    assert_match(/not been synced|not found/i, err)
  end

  def test_init_rejects_already_initialized
    v3_blob = JSON.generate({
      "version" => 3, "owner" => "alice",
      "meta" => Base64.strict_encode64(YAML.dump({ "name" => "production" })),
      "secrets" => Base64.strict_encode64(""),
      "key_slots" => {}
    })
    @fake_client.set_pull_response(v3_blob)

    _, err = run_team_init("production")
    assert_match(/already.*team/i, err)
  end

  # ── Positional VAULT arg ──

  def test_init_accepts_positional_vault_name
    @fake_client.set_pull_response(personal_v1_blob)

    out, = LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["team", "init", "production"]) }
    end

    assert_match(/team vault/, out)
    pushed = last_pushed_blob
    data = JSON.parse(pushed)
    assert_equal 3, data["version"]
    assert_equal "alice", data["owner"]
  end

  def test_init_positional_vault_overrides_default
    # Flip the default to a different vault so we can verify the positional
    # arg wins over Config.default_vault fallback.
    LocalVault::Config.default_vault = "somewhere-else"
    @fake_client.set_pull_response(personal_v1_blob)

    out, = LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["team", "init", "production"]) }
    end

    assert_match(/Vault 'production' is now a team vault/, out)
  ensure
    LocalVault::Config.default_vault = "default"
  end

  def test_init_auto_prompts_for_passphrase_when_not_unlocked
    # Clear session cache — team init should prompt for passphrase itself
    # instead of erroring out with "not unlocked".
    LocalVault::SessionCache.clear("production")
    @fake_client.set_pull_response(personal_v1_blob)

    # Stub prompt_passphrase on CLI::Team (the TeamHelpers method resolves
    # there because Team is the class currently handling the command).
    stub_team_prompt(@passphrase) do
      out, err = run_team_init("production")
      assert_match(/team vault/, out)
      assert_empty err
    end

    # Verify the session cache was populated as a side effect
    assert_equal @master_key, LocalVault::SessionCache.get("production")
  end

  def test_init_errors_on_wrong_passphrase
    LocalVault::SessionCache.clear("production")
    @fake_client.set_pull_response(personal_v1_blob)

    stub_team_prompt("wrong-pass") do
      _, err = run_team_init("production")
      assert_match(/wrong passphrase/i, err)
    end

    assert_nil LocalVault::SessionCache.get("production")
  end

  def test_init_errors_when_vault_does_not_exist
    LocalVault::SessionCache.clear("production")
    LocalVault::Store.new("production").destroy!

    _, err = run_team_init("production")

    assert_match(/does not exist/i, err)
  end

  def stub_team_prompt(value)
    original = LocalVault::CLI::Team.instance_method(:prompt_passphrase)
    LocalVault::CLI::Team.no_commands do
      LocalVault::CLI::Team.send(:define_method, :prompt_passphrase) { |_msg = ""| value }
    end
    yield
  ensure
    LocalVault::CLI::Team.no_commands do
      LocalVault::CLI::Team.send(:define_method, :prompt_passphrase, original)
    end
  end

  def test_init_preserves_existing_v2_members
    # Simulate a v2 bundle with an existing member
    store = LocalVault::Store.new("production")
    pub_b64 = LocalVault::Identity.public_key
    enc_key = LocalVault::KeySlot.create(@master_key, pub_b64)
    v2_blob = JSON.generate({
      "version" => 2,
      "meta" => Base64.strict_encode64(File.read(store.meta_path)),
      "secrets" => Base64.strict_encode64(store.read_encrypted || ""),
      "key_slots" => { "bob" => { "pub" => "bobpub", "enc_key" => "bobkey" } }
    })
    @fake_client.set_pull_response(v2_blob)

    run_team_init("production")

    slots = JSON.parse(last_pushed_blob)["key_slots"]
    assert slots.key?("alice"), "Owner slot should be created"
    assert slots.key?("bob"), "Existing member should be preserved"
    assert_nil slots["bob"]["scopes"], "Preserved members get full access"
  end

  private

  def create_test_vault(name)
    vault = LocalVault::Vault.create!(name: name, master_key: @master_key, salt: @salt)
    vault.set("SECRET", "value")
  end

  def personal_v1_blob
    store = LocalVault::Store.new("production")
    LocalVault::SyncBundle.pack(store)
  end

  def run_team_init(vault_name)
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["team", "init", "--vault", vault_name]) }
    end
  end

  def last_pushed_blob
    call = @fake_client.calls.select { |c| c[:method] == :push_vault }.last
    call[:args][1]
  end
end

class FakeInitClient
  attr_reader :calls
  def initialize
    @calls = []
    @pull_response = ""
    @pull_error = nil
  end
  def set_pull_response(blob) = @pull_response = blob
  def set_pull_error(status) = @pull_error = status
  def pull_vault(_name)
    raise LocalVault::ApiClient::ApiError.new("Not found", status: @pull_error) if @pull_error
    @pull_response
  end
  def push_vault(*args) = @calls << { method: :push_vault, args: args }
  def method_missing(name, *args, **kw) = @calls << { method: name, args: args, kwargs: kw }
  def respond_to_missing?(name, _) = name != :call
end
