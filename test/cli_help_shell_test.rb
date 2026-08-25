require_relative "test_helper"
require "localvault/cli"
require "localvault/cli/help_shell"
require "stringio"

class CLIHelpShellTest < Minitest::Test
  # Thor decides on color by asking the shell; force it on to test decoration
  # without a real TTY.
  class ColorShell < LocalVault::CLI::HelpShell
    def can_display_colors? = true
  end

  def setup
    @out   = StringIO.new
    @shell = ColorShell.new
    @shell.instance_variable_set(:@base, nil)
    @shell.define_singleton_method(:stdout) { @stdout_override }
    @shell.instance_variable_set(:@stdout_override, @out)
  end

  def test_labels_are_colored
    @shell.say "Usage:"
    assert_match(/\e\[1m\e\[36mUsage:\e\[0m/, @out.string)
  end

  def test_all_caps_headings_are_colored
    @shell.say "GETTING STARTED"
    assert_match(/\e\[1m\e\[36mGETTING STARTED\e\[0m/, @out.string)
  end

  def test_ordinary_prose_is_untouched
    @shell.say "Discover the groups in a vault."
    refute_includes @out.string, "\e["
  end

  def test_example_lines_keep_their_alignment
    @shell.print_wrapped("EXAMPLES:\n\x05    localvault set K V        # aligned comment\n", indent: 2)
    assert_includes @out.string, "localvault set K V        # aligned comment"
    refute_includes @out.string, "\x05"
  end

  def test_plain_shell_emits_no_ansi
    plain = LocalVault::CLI::HelpShell.new  # not a TTY under test
    plain.define_singleton_method(:stdout) { @stdout_override }
    plain.instance_variable_set(:@stdout_override, @out)
    plain.say "Usage:"
    refute_includes @out.string, "\e["
  end
end
