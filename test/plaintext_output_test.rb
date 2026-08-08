require_relative "test_helper"
require "stringio"

class PlaintextOutputTest < Minitest::Test
  def setup
    @original_assume = LocalVault::PlaintextOutput.assume_tty
    LocalVault::PlaintextOutput.assume_tty = false
  end

  def teardown
    LocalVault::PlaintextOutput.assume_tty = @original_assume
    LocalVault::PlaintextOutput.tty_override = nil
  end

  def test_permitted_when_assume_tty_is_set
    LocalVault::PlaintextOutput.assume_tty = true
    assert LocalVault::PlaintextOutput.permitted?(out: StringIO.new)
  end

  def test_permitted_when_stdout_is_a_tty
    tty_like = Object.new
    def tty_like.tty? = true
    assert LocalVault::PlaintextOutput.permitted?(out: tty_like)
  end

  def test_captured_stream_confirmed_with_y_on_tty
    with_fake_tty("y\n") do
      assert LocalVault::PlaintextOutput.permitted?(out: StringIO.new)
    end
  end

  def test_captured_stream_confirmed_with_yes_on_tty
    with_fake_tty("YES\n") do
      assert LocalVault::PlaintextOutput.permitted?(out: StringIO.new)
    end
  end

  def test_captured_stream_refused_with_n_on_tty
    with_fake_tty("n\n") do
      refute LocalVault::PlaintextOutput.permitted?(out: StringIO.new)
    end
  end

  def test_captured_stream_refused_on_empty_tty_input
    with_fake_tty("") do
      refute LocalVault::PlaintextOutput.permitted?(out: StringIO.new)
    end
  end

  def test_captured_stream_refused_when_no_tty_exists
    # No override, stdout not a tty, and /dev/tty unopenable in this state is
    # simulated by pointing the override at closed IOs raising IOError.
    input = StringIO.new
    input.close
    LocalVault::PlaintextOutput.tty_override = { input: input, output: StringIO.new }
    refute LocalVault::PlaintextOutput.permitted?(out: StringIO.new)
  rescue IOError
    # reading a closed StringIO raises; the production path rescues at
    # with_tty level only for real IO — assert the rescue covers it instead
    flunk "IOError escaped the gate"
  end

  def test_prompt_names_the_purpose
    output = StringIO.new
    with_fake_tty("y\n", output: output) do
      LocalVault::PlaintextOutput.permitted?(out: StringIO.new, purpose: "Reveal plaintext values")
    end
    assert_includes output.string, "Reveal plaintext values? [y/N]"
  end

  private

  def with_fake_tty(input, output: StringIO.new)
    LocalVault::PlaintextOutput.tty_override = { input: StringIO.new(input), output: output }
    yield
  ensure
    LocalVault::PlaintextOutput.tty_override = nil
  end
end
