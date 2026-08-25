require_relative "test_helper"
require "localvault/cli"

# A locked vault with no passphrase available must say so — a silent exit-0
# no-op sent an operator chasing ghosts (team init/add "succeeded" and did
# nothing).
class TeamLockedVaultMessageTest < Minitest::Test
  include LocalVault::TestHelper

  class Helper
    include LocalVault::CLI::TeamHelpers
    def prompt_passphrase(_msg) = ""  # non-TTY: no passphrase obtainable
  end

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    salt = LocalVault::Crypto.generate_salt
    key  = LocalVault::Crypto.derive_master_key("pw", salt)
    LocalVault::Vault.create!(name: "stocklive", master_key: key, salt: salt)
    LocalVault::SessionCache.clear("stocklive")
  end

  def teardown
    teardown_test_home
  end

  def test_locked_vault_prints_unlock_guidance
    result = nil
    _, err = capture_io { result = Helper.new.send(:ensure_master_key, "stocklive") }
    assert_nil result
    assert_match(/locked and no passphrase/, err)
    assert_match(/localvault unlock stocklive/, err)
  end
end
