require_relative "test_helper"
require "localvault/cli"
require "json"
require "base64"

class SyncPushAuthTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key("testpass", @salt)
    create_test_vault("production")
    LocalVault::Identity.generate!
    LocalVault::Config.token = "tok"
    LocalVault::SessionCache.set("production", @master_key)
    @fake_client = FakePushAuthClient.new
    @fake_client.set_response(:push_vault, {})
  end

  def teardown
    LocalVault::SessionCache.clear("production")
    teardown_test_home
  end

  def test_personal_vault_push_writes_v1
    LocalVault::Config.inventlist_handle = "alice"
    @fake_client.set_pull_response("")

    push_and_capture("production")

    data = JSON.parse(last_pushed_blob)
    assert_equal 1, data["version"]
    refute data.key?("owner")
  end

  def test_collaborative_team_allows_non_owner_push
    LocalVault::Config.inventlist_handle = "bob"
    v3 = build_v3(owner: "alice", slots: {
      "alice" => { "pub" => "ap", "enc_key" => "ak", "scopes" => nil, "blob" => nil },
      "bob" => { "pub" => "bp", "enc_key" => "bk", "scopes" => nil, "blob" => nil }
    })
    @fake_client.set_pull_response(v3)

    out, = push_and_capture("production")

    assert @fake_client.calls.any? { |c| c[:method] == :push_vault }
  end

  def test_scoped_vault_blocks_non_owner_push
    LocalVault::Config.inventlist_handle = "carol"
    v3 = build_v3(owner: "alice", slots: {
      "alice" => { "pub" => "ap", "enc_key" => "ak", "scopes" => nil, "blob" => nil },
      "bob" => { "pub" => "bp", "enc_key" => "bk", "scopes" => ["myapp"], "blob" => "bb" },
      "carol" => { "pub" => "cp", "enc_key" => "ck", "scopes" => nil, "blob" => nil }
    })
    @fake_client.set_pull_response(v3)

    _, err = push_and_capture("production")

    assert_match(/owner.*push|only.*owner/i, err)
  end

  def test_scoped_member_cannot_push
    LocalVault::Config.inventlist_handle = "bob"
    v3 = build_v3(owner: "alice", slots: {
      "alice" => { "pub" => "ap", "enc_key" => "ak", "scopes" => nil, "blob" => nil },
      "bob" => { "pub" => "bp", "enc_key" => "bk", "scopes" => ["myapp"], "blob" => "bb" }
    })
    @fake_client.set_pull_response(v3)

    _, err = push_and_capture("production")

    assert_match(/cannot push|read-only|owner/i, err)
  end

  def test_owner_can_push_scoped_vault
    LocalVault::Config.inventlist_handle = "alice"
    v3 = build_v3(owner: "alice", slots: {
      "alice" => { "pub" => "ap", "enc_key" => "ak", "scopes" => nil, "blob" => nil },
      "bob" => { "pub" => "bp", "enc_key" => "bk", "scopes" => ["myapp"], "blob" => "bb" }
    })
    @fake_client.set_pull_response(v3)

    push_and_capture("production")

    assert @fake_client.calls.any? { |c| c[:method] == :push_vault }
  end

  private

  def create_test_vault(name)
    LocalVault::Vault.create!(name: name, master_key: @master_key, salt: @salt).tap { |v| v.set("KEY", "val") }
  end

  def build_v3(owner:, slots:)
    store = LocalVault::Store.new("production")
    LocalVault::SyncBundle.pack_v3(store, owner: owner, key_slots: slots)
  end

  def push_and_capture(vault_name)
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["sync", "push", vault_name]) }
    end
  end

  def last_pushed_blob
    call = @fake_client.calls.select { |c| c[:method] == :push_vault }.last
    call&.dig(:args, 1)
  end
end

class FakePushAuthClient
  attr_reader :calls
  def initialize
    @calls = []
    @responses = {}
    @pull_response = ""
  end
  def set_response(method, r) = @responses[method] = r
  def set_pull_response(blob) = @pull_response = blob
  def pull_vault(_) = @pull_response
  def push_vault(*args) = (@calls << { method: :push_vault, args: args }; @responses[:push_vault] || {})
  def method_missing(name, *args, **kw) = (@calls << { method: name, args: args, kwargs: kw }; @responses[name] || {})
  def respond_to_missing?(name, _) = name != :call
end
