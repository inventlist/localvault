require_relative "test_helper"
require "localvault/cli"
require "json"
require "base64"
require "yaml"

class TeamRotateTest < Minitest::Test
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
    @fake_client = FakeRotateClient.new
  end

  def teardown
    LocalVault::SessionCache.clear("production")
    teardown_test_home
  end

  def test_rotate_rejects_non_owner
    LocalVault::Config.inventlist_handle = "bob"
    blob = build_v3_blob(owner: "alice")
    @fake_client.set_pull_response(blob)

    _, err = run_rotate("production")

    assert_match(/only.*owner/i, err)
    assert_nil @fake_client.calls.find { |c| c[:method] == :push_vault }
  end

  def test_rotate_rejects_v2_vault
    v2_blob = JSON.generate({
      "version" => 2,
      "meta" => Base64.strict_encode64(YAML.dump({ "name" => "production" })),
      "secrets" => Base64.strict_encode64(""),
      "key_slots" => { "alice" => { "pub" => "apub", "enc_key" => "akey" } }
    })
    @fake_client.set_pull_response(v2_blob)

    _, err = run_rotate("production")

    assert_match(/not a team vault|team init/i, err)
    assert_nil @fake_client.calls.find { |c| c[:method] == :push_vault }
  end

  def test_rotate_succeeds_for_owner
    blob = build_v3_blob(owner: "alice")
    @fake_client.set_pull_response(blob)

    out, = run_rotate("production")

    assert_match(/re-encrypted/i, out)
    assert @fake_client.calls.any? { |c| c[:method] == :push_vault }
  end

  def test_rotate_accepts_positional_vault_name
    blob = build_v3_blob(owner: "alice")
    @fake_client.set_pull_response(blob)

    out, = run_rotate_positional("production")

    assert_match(/re-encrypted/i, out)
    assert @fake_client.calls.any? { |c| c[:method] == :push_vault }
  end

  private

  def create_test_vault(name)
    vault = LocalVault::Vault.create!(name: name, master_key: @master_key, salt: @salt)
    vault.set("SECRET", "value")
  end

  def build_v3_blob(owner:)
    store = LocalVault::Store.new("production")
    pub_b64 = LocalVault::Identity.public_key
    enc_key = LocalVault::KeySlot.create(@master_key, pub_b64)
    slots = { "alice" => { "pub" => pub_b64, "enc_key" => enc_key, "scopes" => nil, "blob" => nil } }
    LocalVault::SyncBundle.pack_v3(store, owner: owner, key_slots: slots)
  end

  def run_rotate(vault_name)
    original = LocalVault::CLI::Team.instance_method(:prompt_passphrase)
    LocalVault::CLI::Team.send(:define_method, :prompt_passphrase) { |_msg = ""| "newpass" }
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["team", "rotate", "--vault", vault_name]) }
    end
  ensure
    LocalVault::CLI::Team.send(:define_method, :prompt_passphrase, original)
  end

  def run_rotate_positional(vault_name)
    original = LocalVault::CLI::Team.instance_method(:prompt_passphrase)
    LocalVault::CLI::Team.send(:define_method, :prompt_passphrase) { |_msg = ""| "newpass" }
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["team", "rotate", vault_name]) }
    end
  ensure
    LocalVault::CLI::Team.send(:define_method, :prompt_passphrase, original)
  end
end

class FakeRotateClient
  attr_reader :calls
  def initialize; @calls = []; @pull_response = ""; end
  def set_pull_response(blob) = @pull_response = blob
  def pull_vault(_) = @pull_response
  def push_vault(*args) = @calls << { method: :push_vault, args: args }
  def method_missing(name, *args, **kw) = @calls << { method: name, args: args, kwargs: kw }
  def respond_to_missing?(name, _) = name != :call
end
