require_relative "test_helper"
require "localvault/cli"
require "fileutils"

class CLIUpgradeTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    @bin = File.join(@test_home, "bin")
    FileUtils.mkdir_p(@bin)
    @original_path = ENV["PATH"]
    ENV["PATH"] = @bin
  end

  def teardown
    ENV["PATH"] = @original_path
    teardown_test_home
  end

  def write_wrapper(contents)
    path = File.join(@bin, "localvault")
    File.write(path, contents)
    FileUtils.chmod(0o755, path)
    path
  end

  # Homebrew and install.sh both land in /usr/local/bin, so the path alone
  # cannot tell them apart — the wrapper's gem prefix can.
  def test_detects_homebrew_from_cellar_prefix
    write_wrapper("#!/bin/bash\nexport GEM_HOME=\"/opt/homebrew/Cellar/localvault/1.12.3/libexec/gems\"\n")
    out, = capture_io { LocalVault::CLI.start(%w[upgrade --check]) }

    assert_match(/Installed via brew/, out)
    assert_match(%r{brew upgrade inventlist/tap/localvault}, out)
    assert_match(/nothing was run/, out)
  end

  def test_detects_install_script_from_runtime_prefix
    write_wrapper("#!/bin/sh\nexport GEM_HOME=\"#{Dir.home}/.localvault/runtime\"\n")
    out, = capture_io { LocalVault::CLI.start(%w[upgrade --check]) }

    assert_match(/Installed via script/, out)
    assert_match(%r{install\.sh}, out)
  end

  def test_unknown_install_lists_every_option
    write_wrapper("#!/bin/sh\necho hi\n")
    _, err = capture_io { LocalVault::CLI.start(%w[upgrade --check]) }

    assert_match(/cannot tell how localvault was installed/, err)
    assert_match(/brew upgrade/, err)
    assert_match(/gem update localvault/, err)
  end

  # A stale copy earlier on PATH makes an upgrade look like a no-op.
  def test_refuses_when_multiple_copies_are_on_path
    write_wrapper("#!/bin/bash\nexport GEM_HOME=\"/opt/homebrew/Cellar/localvault/1.0.0/libexec/gems\"\n")
    second = File.join(@test_home, "bin2")
    FileUtils.mkdir_p(second)
    File.write(File.join(second, "localvault"), "#!/bin/sh\n")
    FileUtils.chmod(0o755, File.join(second, "localvault"))
    ENV["PATH"] = "#{@bin}#{File::PATH_SEPARATOR}#{second}"

    _, err = capture_io { LocalVault::CLI.start(%w[upgrade --check]) }

    assert_match(/multiple localvault executables/, err)
    assert_match(/doctor/, err)
  end

  def test_check_never_runs_the_command
    write_wrapper("#!/bin/bash\nexport GEM_HOME=\"/opt/homebrew/Cellar/localvault/1.12.3/libexec/gems\"\n")
    ran = false
    cli = LocalVault::CLI.new
    cli.options = Thor::CoreExt::HashWithIndifferentAccess.new("check" => true)
    cli.define_singleton_method(:system) { |*| ran = true }

    capture_io { cli.upgrade }

    refute ran, "--check must not execute anything"
  end
end
