require_relative "test_helper"
require "localvault/cli"

class CLIConfigServerTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
  end

  def teardown
    teardown_test_home
  end

  def test_config_get_defaults_to_inventlist
    out, = capture_io { LocalVault::CLI.start(%w[config get server]) }
    assert_match %r{server: https://inventlist\.com}, out
  end

  def test_config_set_server_persists
    out, = capture_io { LocalVault::CLI.start(%w[config set server https://vaulthost.example]) }
    assert_match %r{server set to https://vaulthost\.example}, out
    assert_equal "https://vaulthost.example", LocalVault::Config.api_url
  end

  def test_config_set_rejects_non_url
    _, err = capture_io { LocalVault::CLI.start(%w[config set server nope]) }
    assert_match(/http\(s\) URL/, err)
    assert_equal "https://inventlist.com", LocalVault::Config.api_url
  end

  def test_config_unset_restores_default
    LocalVault::Config.api_url = "https://vaulthost.example"
    capture_io { LocalVault::CLI.start(%w[config unset server]) }
    assert_equal "https://inventlist.com", LocalVault::Config.api_url
  end

  def test_config_rejects_unknown_field
    _, err = capture_io { LocalVault::CLI.start(%w[config set color blue]) }
    assert_match(/Unknown config field/, err)
  end

  def test_login_server_option_persists_url
    capture_io { LocalVault::CLI.start(%w[login --status --server https://vaulthost.example]) }
    assert_equal "https://vaulthost.example", LocalVault::Config.api_url
  end

  def test_login_without_token_offers_both_paths_and_key_setup
    out, = capture_io { LocalVault::CLI.start(%w[login]) }
    assert_match(/own host/i, out)
    assert_match(/config set server/, out)
    assert_match(/inventlist\.com/, out)
    assert_match(/keys generate/, out)
    assert_match(/keys publish/, out)
    assert_match %r{kuickr\.co/localvault/series}, out
  end
end
