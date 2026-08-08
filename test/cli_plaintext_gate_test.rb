require_relative "test_helper"
require_relative "../lib/localvault/cli"
require "stringio"

class CLIPlaintextGateTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @original_session = ENV["LOCALVAULT_SESSION"]
    ENV.delete("LOCALVAULT_SESSION")
    LocalVault::PlaintextOutput.assume_tty = false
  end

  def teardown
    LocalVault::PlaintextOutput.assume_tty = true
    LocalVault::PlaintextOutput.tty_override = nil
    if @original_session
      ENV["LOCALVAULT_SESSION"] = @original_session
    else
      ENV.delete("LOCALVAULT_SESSION")
    end
    teardown_test_home
  end

  def test_get_refuses_plaintext_on_captured_stream_without_confirmation
    seed_vault("API_TOKEN" => "supersecrettoken")
    deny_on_tty
    out, err = with_session { capture_io { LocalVault::CLI.start(%w[get API_TOKEN]) } }
    assert_empty out
    assert_includes err, "refusing to print plaintext for 'API_TOKEN'"
    assert_includes err, "localvault exec --map API_TOKEN=API_TOKEN"
    refute_includes err, "supersecrettoken"
  end

  def test_get_prints_after_tty_confirmation
    seed_vault("API_TOKEN" => "supersecrettoken")
    allow_on_tty
    out, = with_session { capture_io { LocalVault::CLI.start(%w[get API_TOKEN]) } }
    assert_equal "supersecrettoken", out.strip
  end

  def test_env_refuses_plaintext_on_captured_stream
    seed_vault("API_TOKEN" => "supersecrettoken")
    deny_on_tty
    out, err = with_session { capture_io { LocalVault::CLI.start(%w[env]) } }
    assert_empty out
    assert_includes err, "refusing to print plaintext env exports"
    assert_includes err, "localvault exec"
    refute_includes err, "supersecrettoken"
  end

  def test_show_reveal_downgrades_to_masked_on_captured_stream
    seed_vault("API_TOKEN" => "supersecrettoken")
    deny_on_tty
    out, err = with_session { capture_io { LocalVault::CLI.start(%w[show --reveal]) } }
    refute_includes out, "supersecrettoken"
    assert_includes err, "Masking values"
  end

  private

  def seed_vault(secrets, name = "default")
    salt = LocalVault::Crypto.generate_salt
    master_key = LocalVault::Crypto.derive_master_key(test_passphrase, salt)
    vault = LocalVault::Vault.create!(name: name, master_key: master_key, salt: salt)
    secrets.each { |k, v| vault.set(k, v) }
    vault
  end

  def with_session(vault_name = "default")
    store = LocalVault::Store.new(vault_name)
    master_key = LocalVault::Crypto.derive_master_key(test_passphrase, store.salt)
    ENV["LOCALVAULT_SESSION"] =
      Base64.strict_encode64("#{vault_name}:#{Base64.strict_encode64(master_key)}")
    yield
  ensure
    ENV.delete("LOCALVAULT_SESSION")
  end

  def allow_on_tty
    LocalVault::PlaintextOutput.tty_override = { input: StringIO.new("y\n"), output: StringIO.new }
  end

  def deny_on_tty
    LocalVault::PlaintextOutput.tty_override = { input: StringIO.new(""), output: StringIO.new }
  end
end
