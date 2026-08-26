require_relative "test_helper"
require "localvault/cli"

# `reveal` is the verb people reach for; before it existed, `localvault reveal
# --group X` failed and did_you_mean suggested `revoke` — a destructive
# neighbour — as the closest match.
class CLIRevealTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    salt = LocalVault::Crypto.generate_salt
    key  = LocalVault::Crypto.derive_master_key("pw", salt)
    LocalVault::Vault.create!(name: "default", master_key: key, salt: salt)
    vault = LocalVault::Vault.open(name: "default", passphrase: "pw")
    vault.set("cloudflare.API_TOKEN", "cf_secret_value")
    LocalVault::SessionCache.set("default", vault.master_key)
  end

  def teardown
    teardown_test_home
  end

  def test_reveal_is_a_real_command
    assert_includes LocalVault::CLI.all_commands.keys, "reveal"
  end

  def test_reveal_accepts_group_flag
    out, err = capture_io { LocalVault::CLI.start(%w[reveal --group cloudflare]) }
    refute_match(/unknown option/i, err)
    refute_match(/revoke/, err)
    assert_match(/API_TOKEN/, out)
  end

  def test_reveal_accepts_bare_group_argument
    out, = capture_io { LocalVault::CLI.start(%w[reveal cloudflare]) }
    assert_match(/API_TOKEN/, out)
  end

  # The suite sets assume_tty globally; drop it so the real gate runs.
  def test_reveal_masks_when_stdout_is_not_a_tty
    LocalVault::PlaintextOutput.assume_tty = false
    out, err = capture_io { LocalVault::CLI.start(%w[reveal --group cloudflare]) }

    refute_includes out, "cf_secret_value", "plaintext gate must still apply to reveal"
    assert_match(/Masking values/, err)
  ensure
    LocalVault::PlaintextOutput.assume_tty = true
  end
end
