require_relative "test_helper"
require "localvault/cli"

# Fake ApiClient for identity/login tests.
class FakeIdentityApiClient
  attr_reader :calls

  def initialize
    @calls    = []
    @response = {}
    @error    = nil
  end

  def set_response(r) = @response = r
  def set_error(e)    = @error    = e

  def respond_to?(name, include_private = false)
    return false if name == :call
    super
  end

  def method_missing(name, *args, **kwargs)
    @calls << { method: name, args: args, kwargs: kwargs }
    raise @error if @error
    @response
  end

  def respond_to_missing?(name, include_private = false)
    name != :call
  end
end

class CLIIdentityTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @fake_client = FakeIdentityApiClient.new
  end

  def teardown
    teardown_test_home
  end

  def stub_api_client(client)
    LocalVault::ApiClient.define_singleton_method(:new) { |**_| client }
    yield
  ensure
    LocalVault::ApiClient.singleton_class.send(:remove_method, :new)
  end

  # ── keygen ──────────────────────────────────────────────────────

  def test_keygen_generates_keypair
    capture_io { LocalVault::CLI.start(%w[keygen]) }
    assert LocalVault::Identity.exists?
  end

  def test_keygen_prints_public_key
    out, = capture_io { LocalVault::CLI.start(%w[keygen]) }
    assert_match LocalVault::Identity.public_key, out
  end

  def test_keygen_fails_if_keypair_already_exists
    LocalVault::Identity.generate!
    out, = capture_io { LocalVault::CLI.start(%w[keygen]) }
    assert_match(/already exists/, out)
  end

  def test_keygen_force_regenerates_keypair
    LocalVault::Identity.generate!
    first_key = LocalVault::Identity.public_key
    capture_io { LocalVault::CLI.start(%w[keygen --force]) }
    refute_equal first_key, LocalVault::Identity.public_key
  end

  def test_keygen_show_prints_key_without_regenerating
    LocalVault::Identity.generate!
    original_key = LocalVault::Identity.public_key
    out, = capture_io { LocalVault::CLI.start(%w[keygen --show]) }
    assert_match original_key, out
    assert_equal original_key, LocalVault::Identity.public_key
  end

  def test_keygen_show_errors_if_no_keypair
    out, = capture_io { LocalVault::CLI.start(%w[keygen --show]) }
    assert_match(/No keypair/, out)
  end

  # ── login ───────────────────────────────────────────────────────

  def test_login_stores_token_and_handle
    @fake_client.set_response({ "user" => { "handle" => "nauman" } })
    stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[login mytoken123]) }
    end
    assert_equal "mytoken123", LocalVault::Config.token
    assert_equal "nauman",     LocalVault::Config.inventlist_handle
  end

  def test_login_prints_logged_in_handle
    @fake_client.set_response({ "user" => { "handle" => "nauman" } })
    stub_api_client(@fake_client) do
      out, = capture_io { LocalVault::CLI.start(%w[login mytoken123]) }
      assert_match(/Logged in as @nauman/, out)
    end
  end

  def test_login_auto_generates_keypair_if_none_exists
    @fake_client.set_response({ "user" => { "handle" => "nauman" } })
    refute LocalVault::Identity.exists?
    stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[login mytoken123]) }
    end
    assert LocalVault::Identity.exists?
  end

  def test_login_publishes_public_key_to_inventlist
    @fake_client.set_response({ "user" => { "handle" => "nauman" } })
    stub_api_client(@fake_client) do
      capture_io { LocalVault::CLI.start(%w[login mytoken123]) }
    end
    pub_call = @fake_client.calls.find { |c| c[:method] == :publish_public_key }
    refute_nil pub_call, "Expected publish_public_key to be called"
    assert_equal LocalVault::Identity.public_key, pub_call[:args].first
  end

  def test_login_invalid_token_shows_clean_error
    @fake_client.set_error(LocalVault::ApiClient::ApiError.new("Unauthorized", status: 401))
    stub_api_client(@fake_client) do
      out, = capture_io { LocalVault::CLI.start(%w[login badtoken]) }
      assert_match(/Invalid token/, out)
    end
  end

  def test_login_status_when_logged_in
    LocalVault::Config.token              = "tok"
    LocalVault::Config.inventlist_handle  = "nauman"
    out, = capture_io { LocalVault::CLI.start(%w[login --status]) }
    assert_match(/@nauman/, out)
  end

  def test_login_status_when_not_logged_in
    out, = capture_io { LocalVault::CLI.start(%w[login --status]) }
    assert_match(/Not logged in/, out)
  end

  # ── logout ──────────────────────────────────────────────────────

  def test_logout_clears_token_and_handle
    LocalVault::Config.token             = "tok"
    LocalVault::Config.inventlist_handle = "nauman"
    capture_io { LocalVault::CLI.start(%w[logout]) }
    assert_nil LocalVault::Config.token
    assert_nil LocalVault::Config.inventlist_handle
  end

  def test_logout_prints_confirmation
    LocalVault::Config.token             = "tok"
    LocalVault::Config.inventlist_handle = "nauman"
    out, = capture_io { LocalVault::CLI.start(%w[logout]) }
    assert_match(/Logged out/, out)
  end

  def test_logout_when_not_logged_in_shows_message
    out, = capture_io { LocalVault::CLI.start(%w[logout]) }
    assert_match(/Not logged in/, out)
  end
end
