require_relative "test_helper"
require "localvault/cli"

class CLIIdentityAliasTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
  end

  def teardown
    teardown_test_home
  end

  def test_set_alias_stores_value
    out, = capture_io { LocalVault::CLI.start(%w[identity set alias nauman]) }
    assert_match(/Alias set to 'nauman'/, out)
    assert_equal "nauman", LocalVault::Config.identity_alias
  end

  def test_set_rejects_unknown_field
    _, err = capture_io do
      assert_raises(SystemExit) { LocalVault::CLI.start(%w[identity set color blue]) }
    end
    assert_match(/Unknown field 'color'/, err)
  end

  def test_set_rejects_invalid_alias
    _, err = capture_io do
      assert_raises(SystemExit) { LocalVault::CLI.start(["identity", "set", "alias", "bad alias!"]) }
    end
    assert_match(/Alias must be/, err)
    assert_nil LocalVault::Config.identity_alias
  end

  def test_show_displays_alias_and_placeholders
    LocalVault::Config.identity_alias = "nauman"
    out, = capture_io { LocalVault::CLI.start(%w[identity show]) }
    assert_match(/Alias:\s+nauman/, out)
    assert_match(/Handle:\s+-/, out)
  end

  def test_identity_defaults_to_show
    out, = capture_io { LocalVault::CLI.start(%w[identity]) }
    assert_match(/Alias:\s+-/, out)
  end

  def test_unset_clears_alias
    LocalVault::Config.identity_alias = "nauman"
    out, = capture_io { LocalVault::CLI.start(%w[identity unset alias]) }
    assert_match(/cleared/, out)
    assert_nil LocalVault::Config.identity_alias
  end
end
