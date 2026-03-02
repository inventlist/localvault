require_relative "test_helper"
require_relative "../lib/localvault/cli"
require "rbconfig"

class CLITest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @original_session = ENV["LOCALVAULT_SESSION"]
    ENV.delete("LOCALVAULT_SESSION")
  end

  def teardown
    if @original_session
      ENV["LOCALVAULT_SESSION"] = @original_session
    else
      ENV.delete("LOCALVAULT_SESSION")
    end
    teardown_test_home
  end

  # --- version ---

  def test_version
    out, = capture_io { LocalVault::CLI.start(%w[version]) }
    assert_equal "localvault #{LocalVault::VERSION}\n", out
  end

  # --- init ---

  def test_init_creates_default_vault
    stub_passphrase("secret123") do
      out, = capture_io { LocalVault::CLI.start(%w[init]) }
      assert_match(/Vault 'default' created/, out)
      assert LocalVault::Store.new("default").exists?
    end
  end

  def test_init_creates_named_vault
    stub_passphrase("secret123") do
      out, = capture_io { LocalVault::CLI.start(%w[init staging]) }
      assert_match(/Vault 'staging' created/, out)
      assert LocalVault::Store.new("staging").exists?
    end
  end

  def test_init_rejects_empty_passphrase
    stub_passphrase("") do
      _, err = capture_io { LocalVault::CLI.start(%w[init]) }
      assert_match(/Passphrase cannot be empty/, err)
    end
  end

  def test_init_rejects_mismatched_confirmation
    call_count = 0
    passphrases = ["secret123", "wrong456"]
    stub_getpass(-> { passphrases[call_count].tap { call_count += 1 } }) do
      _, err = capture_io { LocalVault::CLI.start(%w[init]) }
      assert_match(/Passphrases do not match/, err)
    end
  end

  def test_init_errors_if_vault_exists
    create_test_vault("default")
    stub_passphrase("secret123") do
      _, err = capture_io { LocalVault::CLI.start(%w[init]) }
      assert_match(/already exists/, err)
    end
  end

  # --- set ---

  def test_set_stores_secret
    create_test_vault("default")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[set DB_URL postgres://localhost]) }
      assert_match(/Set DB_URL/, out)

      vault = open_test_vault("default")
      assert_equal "postgres://localhost", vault.get("DB_URL")
    end
  end

  # --- get ---

  def test_get_outputs_raw_value
    vault = create_test_vault("default")
    vault.set("API_KEY", "sk-12345")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[get API_KEY]) }
      assert_equal "sk-12345\n", out
    end
  end

  def test_get_missing_key_errors
    create_test_vault("default")
    with_session("default") do
      _, err = capture_io { LocalVault::CLI.start(%w[get NOPE]) }
      assert_match(/Key 'NOPE' not found/, err)
    end
  end

  # --- list ---

  def test_list_outputs_sorted_keys
    vault = create_test_vault("default")
    vault.set("ZEBRA", "z")
    vault.set("ALPHA", "a")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[list]) }
      assert_equal "ALPHA\nZEBRA\n", out
    end
  end

  def test_list_empty_vault
    create_test_vault("default")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[list]) }
      assert_equal "", out
    end
  end

  # --- delete ---

  def test_delete_removes_key
    vault = create_test_vault("default")
    vault.set("OLD_KEY", "value")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[delete OLD_KEY]) }
      assert_match(/Deleted OLD_KEY/, out)

      vault = open_test_vault("default")
      assert_nil vault.get("OLD_KEY")
    end
  end

  def test_delete_missing_key_errors
    create_test_vault("default")
    with_session("default") do
      _, err = capture_io { LocalVault::CLI.start(%w[delete NOPE]) }
      assert_match(/Key 'NOPE' not found/, err)
    end
  end

  # --- env ---

  def test_env_outputs_export_lines
    vault = create_test_vault("default")
    vault.set("DB_URL", "postgres://localhost/mydb")
    vault.set("API_KEY", "sk-123")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[env]) }
      assert_includes out, 'export API_KEY="sk-123"'
      assert_includes out, 'export DB_URL="postgres://localhost/mydb"'
    end
  end

  # --- vaults ---

  def test_vaults_lists_all_with_default_marker
    create_test_vault("default")
    create_test_vault("staging")
    out, = capture_io { LocalVault::CLI.start(%w[vaults]) }
    assert_includes out, "default (default)"
    assert_includes out, "staging"
    refute_includes out, "staging (default)"
  end

  # --- unlock ---

  def test_unlock_outputs_session_export
    create_test_vault("default")
    stub_passphrase(test_passphrase) do
      out, = capture_io { LocalVault::CLI.start(%w[unlock]) }
      assert_match(/export LOCALVAULT_SESSION=/, out)

      # Parse the token and verify it works
      token = out.match(/LOCALVAULT_SESSION="([^"]+)"/)[1]
      decoded = Base64.strict_decode64(token)
      vault_name, key_b64 = decoded.split(":", 2)
      assert_equal "default", vault_name
      assert_equal 32, Base64.strict_decode64(key_b64).bytesize
    end
  end

  # --- session caching ---

  def test_session_skips_passphrase_prompt
    vault = create_test_vault("default")
    vault.set("SECRET", "cached")
    with_session("default") do
      # Should NOT prompt for passphrase — session provides the key
      out, = capture_io { LocalVault::CLI.start(%w[get SECRET]) }
      assert_equal "cached\n", out
    end
  end

  def test_session_invalid_falls_through_to_prompt
    vault = create_test_vault("default")
    vault.set("KEY", "value")
    ENV["LOCALVAULT_SESSION"] = Base64.strict_encode64("default:#{Base64.strict_encode64('x' * 32)}")
    stub_passphrase(test_passphrase) do
      out, = capture_io { LocalVault::CLI.start(%w[get KEY]) }
      assert_equal "value\n", out
    end
  end

  # --- vault option ---

  def test_vault_option_selects_vault
    create_test_vault("staging")
    with_session("staging") do
      out, = capture_io { LocalVault::CLI.start(%w[set TOKEN abc123 --vault staging]) }
      assert_match(/Set TOKEN in vault 'staging'/, out)
    end
  end

  # --- error: missing vault ---

  def test_error_missing_vault
    stub_passphrase(test_passphrase) do
      _, err = capture_io do
        assert_raises(SystemExit) { LocalVault::CLI.start(%w[list]) }
      end
      assert_match(/Vault 'default' does not exist/, err)
      assert_match(/localvault init/, err)
    end
  end

  # --- exec ---

  def test_exec_injects_env_vars
    vault = create_test_vault("default")
    vault.set("MY_VAR", "hello_from_vault")
    with_session("default") do
      # Test via real subprocess using the bin script
      bin_path = File.expand_path("../../bin/localvault", __FILE__)
      env = {
        "LOCALVAULT_HOME" => @test_home,
        "LOCALVAULT_SESSION" => ENV["LOCALVAULT_SESSION"]
      }
      output = IO.popen(env, [RbConfig.ruby, bin_path, "exec", "--", RbConfig.ruby, "-e", 'puts ENV["MY_VAR"]']) { |io| io.read }
      assert_equal "hello_from_vault\n", output
    end
  end

  private

  def create_test_vault(name, passphrase = test_passphrase)
    salt = LocalVault::Crypto.generate_salt
    master_key = LocalVault::Crypto.derive_master_key(passphrase, salt)
    LocalVault::Vault.create!(name: name, master_key: master_key, salt: salt)
  end

  def open_test_vault(name, passphrase = test_passphrase)
    LocalVault::Vault.open(name: name, passphrase: passphrase)
  end

  def session_token_for(vault_name, passphrase = test_passphrase)
    store = LocalVault::Store.new(vault_name)
    master_key = LocalVault::Crypto.derive_master_key(passphrase, store.salt)
    Base64.strict_encode64("#{vault_name}:#{Base64.strict_encode64(master_key)}")
  end

  def with_session(vault_name, passphrase = test_passphrase)
    token = session_token_for(vault_name, passphrase)
    ENV["LOCALVAULT_SESSION"] = token
    yield
  ensure
    ENV.delete("LOCALVAULT_SESSION")
  end

  def stub_passphrase(passphrase)
    stub_getpass(-> { passphrase }) { yield }
  end

  def stub_getpass(callable)
    original = LocalVault::CLI.instance_method(:prompt_passphrase)
    LocalVault::CLI.send(:define_method, :prompt_passphrase) { |_msg = "Passphrase: "| callable.call }
    yield
  ensure
    LocalVault::CLI.send(:define_method, :prompt_passphrase, original)
  end
end
