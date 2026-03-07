require_relative "test_helper"
require "minitest/mock"
require "localvault/cli"

# Minimal fake ApiClient used in team CLI tests.
# NOTE: respond_to? intentionally excludes :call so Minitest's stub
# doesn't mistake this object for a callable.
class FakeTeamsApiClient
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

class CLITeamsTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @fake_client = FakeTeamsApiClient.new
  end

  def teardown
    teardown_test_home
  end

  # ── connect ────────────────────────────────────────────────────

  def test_connect_stores_token_and_handle
    cli = LocalVault::CLI.new([], { token: "tok123", handle: "alice" }, {})
    out = capture_io { cli.connect }.first
    assert_equal "tok123", LocalVault::Config.token
    assert_equal "alice",  LocalVault::Config.inventlist_handle
    assert_includes out, "Connected as @alice"
  end

  def test_connect_shows_next_steps
    cli = LocalVault::CLI.new([], { token: "t", handle: "h" }, {})
    out = capture_io { cli.connect }.first
    assert_includes out, "localvault keys generate"
    assert_includes out, "localvault keys publish"
  end

  # ── keys generate ──────────────────────────────────────────────

  def test_keys_generate_creates_keypair
    cli = LocalVault::CLI::Keys.new([], { force: false }, {})
    capture_io { cli.generate }
    assert LocalVault::Identity.exists?
  end

  def test_keys_generate_skips_if_exists_without_force
    LocalVault::Identity.generate!
    first_pub = LocalVault::Identity.public_key
    cli = LocalVault::CLI::Keys.new([], { force: false }, {})
    capture_io { cli.generate }
    assert_equal first_pub, LocalVault::Identity.public_key
  end

  def test_keys_generate_with_force_overwrites
    LocalVault::Identity.generate!
    first_pub = LocalVault::Identity.public_key
    cli = LocalVault::CLI::Keys.new([], { force: true }, {})
    capture_io { cli.generate }
    refute_equal first_pub, LocalVault::Identity.public_key
  end

  # ── keys show ──────────────────────────────────────────────────

  def test_keys_show_prints_public_key
    LocalVault::Identity.generate!
    cli = LocalVault::CLI::Keys.new([], {}, {})
    out = capture_io { cli.show }.first
    assert_equal LocalVault::Identity.public_key, out.strip
  end

  # ── revoke ─────────────────────────────────────────────────────

  def test_revoke_requires_token
    cli = LocalVault::CLI.new([], {}, {})
    err = capture_io { cli.revoke("99") }.last
    assert_includes err, "Not connected"
  end

  def test_revoke_calls_api
    LocalVault::Config.token = "tok"
    called_id = nil
    cli = LocalVault::CLI.new([], {}, {})
    cli.define_singleton_method(:api_client) { @fake_client }

    # Patch ApiClient.new to return fake
    LocalVault::ApiClient.stub(:new, @fake_client) do
      @fake_client.set_response({ "id" => 5, "status" => "revoked" })
      out = capture_io { cli.revoke("5") }.first
      assert_includes out, "Share 5 revoked"
      assert_equal :revoke_share, @fake_client.calls.last[:method]
    end
  end

  # ── team list ──────────────────────────────────────────────────

  def test_team_list_requires_token
    cli = LocalVault::CLI::Team.new([], {}, {})
    err = capture_io { cli.list }.last
    assert_includes err, "Not connected"
  end

  def test_team_list_shows_no_shares
    LocalVault::Config.token = "tok"
    @fake_client.set_response({ "shares" => [] })

    LocalVault::ApiClient.stub(:new, @fake_client) do
      cli = LocalVault::CLI::Team.new([], {}, {})
      out = capture_io { cli.list }.first
      assert_includes out, "No active shares"
    end
  end

  def test_team_list_shows_active_shares
    LocalVault::Config.token = "tok"
    @fake_client.set_response({
      "shares" => [
        { "id" => 7, "recipient_handle" => "bob",
          "status" => "accepted", "created_at" => "2026-03-06T10:00:00Z" }
      ]
    })

    LocalVault::ApiClient.stub(:new, @fake_client) do
      cli = LocalVault::CLI::Team.new([], {}, {})
      out = capture_io { cli.list }.first
      assert_includes out, "bob"
      assert_includes out, "accepted"
    end
  end

  # ── share (no network) ─────────────────────────────────────────

  def test_share_requires_token
    cli = LocalVault::CLI.new([], { with: "@bob" }, {})
    err = capture_io { cli.share }.last
    assert_includes err, "Not connected"
  end

  def test_share_requires_keypair
    LocalVault::Config.token = "tok"
    cli = LocalVault::CLI.new([], { with: "@bob" }, {})
    err = capture_io { cli.share }.last
    assert_includes err, "No keypair"
  end

  # ── receive (no network) ───────────────────────────────────────

  def test_receive_requires_token
    cli = LocalVault::CLI.new([], {}, {})
    err = capture_io { cli.receive }.last
    assert_includes err, "Not connected"
  end

  def test_receive_requires_keypair
    LocalVault::Config.token = "tok"
    cli = LocalVault::CLI.new([], {}, {})
    err = capture_io { cli.receive }.last
    assert_includes err, "No keypair"
  end

  def test_receive_shows_no_pending_message
    LocalVault::Config.token = "tok"
    LocalVault::Identity.generate!
    @fake_client.set_response({ "shares" => [] })

    LocalVault::ApiClient.stub(:new, @fake_client) do
      cli = LocalVault::CLI.new([], {}, {})
      out = capture_io { cli.receive }.first
      assert_includes out, "No pending shares"
    end
  end

  private

  def capture_io
    out_r, out_w = IO.pipe
    err_r, err_w = IO.pipe

    orig_stdout = $stdout
    orig_stderr = $stderr
    $stdout = out_w
    $stderr = err_w

    yield

    out_w.close
    err_w.close
    [out_r.read, err_r.read]
  ensure
    $stdout = orig_stdout
    $stderr = orig_stderr
    out_w.close rescue nil
    err_w.close rescue nil
  end
end
