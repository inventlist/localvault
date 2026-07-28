require_relative "../test_helper"
require "open3"
require "rbconfig"

class ContextualHelpTest < Minitest::Test
  BIN = File.expand_path("../../bin/localvault", __dir__)

  def run_cli(*arguments)
    Open3.capture3(RbConfig.ruby, BIN, *arguments)
  end

  def test_incomplete_set_explains_group_save_combinations
    _out, err, status = run_cli("set", "--group", "STRIPE", "API_KEY")

    assert_equal 1, status.exitstatus
    assert_includes err, "localvault set --group GROUP KEY VALUE"
    assert_includes err, "localvault set GROUP.KEY VALUE"
    assert_includes err, "localvault groups [QUERY]"
    refute_includes err, "STRIPE"
    refute_includes err, "API_KEY"
  end

  def test_half_written_set_command_still_teaches_group_saving
    _out, err, status = run_cli("set", "group")

    assert_equal 1, status.exitstatus
    assert_includes err, "localvault set KEY VALUE"
    assert_includes err, "localvault set --group GROUP KEY VALUE"
    assert_includes err, "localvault set GROUP.KEY VALUE"
    refute_includes err, '"group"'
  end

  def test_misspelled_group_option_suggests_group_workflows
    _out, err, status = run_cli("show", "--group-by")

    assert_equal 1, status.exitstatus
    assert_includes err, "Did you mean `--group`?"
    assert_includes err, "localvault show --group GROUP"
    assert_includes err, "localvault groups [QUERY]"
  end

  def test_unknown_option_is_found_after_a_valid_option
    _out, err, status = run_cli("show", "--reveal", "--group-by")

    assert_equal 1, status.exitstatus
    assert_includes err, "unknown option `--group-by`"
    assert_includes err, "Did you mean `--group`?"
  end

  def test_unknown_option_is_found_after_a_class_option_and_its_value
    _out, err, status = run_cli("show", "--vault", "default", "--group-by")

    assert_equal 1, status.exitstatus
    assert_includes err, "unknown option `--group-by`"
    refute_includes err, "unknown option `--vault`"
  end

  def test_class_option_is_not_reported_as_unknown
    _out, err, status = run_cli("set", "--vault", "default", "one")

    assert_equal 1, status.exitstatus
    refute_includes err, "unknown option `--vault`"
  end

  def test_partial_group_command_suggests_groups
    _out, err, status = run_cli("grup")

    assert_equal 1, status.exitstatus
    assert_includes err, "localvault groups [QUERY]"
  end

  def test_nested_command_error_shows_valid_combinations
    _out, err, status = run_cli("team", "add")

    assert_equal 1, status.exitstatus
    assert_includes err, "localvault add HANDLE"
    assert_includes err, "localvault team add HANDLE"
  end
end
