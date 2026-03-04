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

  # --- rekey ---

  def test_rekey_changes_passphrase_and_preserves_secrets
    vault = create_test_vault("default")
    vault.set("API_KEY", "sk-abc123")
    vault.set("DB_URL",  "postgres://localhost/myapp")

    call_count = 0
    inputs = [test_passphrase, "newpass", "newpass"]
    stub_rekey_inputs(inputs) do
      out, = capture_io { LocalVault::CLI.start(%w[rekey]) }
      assert_match(/Passphrase updated/, out)
    end

    # old passphrase fails
    assert_raises(LocalVault::Crypto::DecryptionError) do
      LocalVault::Vault.open(name: "default", passphrase: test_passphrase).all
    end

    # new passphrase works and secrets preserved
    new_vault = LocalVault::Vault.open(name: "default", passphrase: "newpass")
    assert_equal "sk-abc123",           new_vault.get("API_KEY")
    assert_equal "postgres://localhost/myapp", new_vault.get("DB_URL")
  end

  def test_rekey_rejects_wrong_current_passphrase
    create_test_vault("default")
    inputs = ["wrongpass", "newpass", "newpass"]
    stub_rekey_inputs(inputs) do
      _, err = capture_io { LocalVault::CLI.start(%w[rekey]) }
      assert_match(/Wrong passphrase/, err)
    end
  end

  def test_rekey_rejects_empty_new_passphrase
    create_test_vault("default")
    inputs = [test_passphrase, "", ""]
    stub_rekey_inputs(inputs) do
      _, err = capture_io { LocalVault::CLI.start(%w[rekey]) }
      assert_match(/Passphrase cannot be empty/, err)
    end
  end

  def test_rekey_rejects_mismatched_new_passphrase
    create_test_vault("default")
    inputs = [test_passphrase, "newpass", "different"]
    stub_rekey_inputs(inputs) do
      _, err = capture_io { LocalVault::CLI.start(%w[rekey]) }
      assert_match(/Passphrases do not match/, err)
    end
  end

  def test_rekey_named_vault
    vault = create_test_vault("staging")
    vault.set("TOKEN", "tok-xyz")

    inputs = [test_passphrase, "newpass", "newpass"]
    stub_rekey_inputs(inputs) do
      out, = capture_io { LocalVault::CLI.start(%w[rekey staging]) }
      assert_match(/Passphrase updated/, out)
    end

    new_vault = LocalVault::Vault.open(name: "staging", passphrase: "newpass")
    assert_equal "tok-xyz", new_vault.get("TOKEN")
  end

  # --- show ---

  def test_show_renders_table_with_masked_values
    vault = create_test_vault("default")
    vault.set("OPENAI_API_KEY", "sk-proj-abc123")
    vault.set("STRIPE_SECRET_KEY", "sk_live_xyz789")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[show]) }
      assert_includes out, "OPENAI_API_KEY"
      assert_includes out, "STRIPE_SECRET_KEY"
      assert_includes out, "123"   # last chars of sk-proj-abc123
      assert_includes out, "789"   # last chars of sk_live_xyz789
      refute_includes out, "sk-proj-abc123"
      refute_includes out, "sk_live_xyz789"
    end
  end

  def test_show_empty_vault
    create_test_vault("default")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[show]) }
      assert_match(/No secrets/, out)
    end
  end

  def test_show_group_splits_by_prefix
    vault = create_test_vault("default")
    vault.set("MYHANDLE_API_KEY", "key-aaa111")
    vault.set("MYHANDLE_ACCESS_TOKEN", "tok-bbb222")
    vault.set("MYBRAND_API_KEY", "key-ccc333")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[show --group]) }
      assert out.index("MYBRAND") < out.index("MYHANDLE")  # alphabetical groups
      assert_includes out, "MYHANDLE_API_KEY"
      assert_includes out, "MYBRAND_API_KEY"
    end
  end

  def test_show_group_ungrouped_keys_shown_last
    vault = create_test_vault("default")
    vault.set("PLAIN", "value123")
    vault.set("MYHANDLE_API_KEY", "key-aaa111")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[show --group]) }
      assert_includes out, "PLAIN"
      assert_includes out, "MYHANDLE_API_KEY"
    end
  end

  def test_show_named_vault
    vault = create_test_vault("x")
    vault.set("MYHANDLE_API_KEY", "key-abc789")
    with_session("x") do
      out, = capture_io { LocalVault::CLI.start(%w[show --vault x]) }
      assert_includes out, "MYHANDLE_API_KEY"
      assert_includes out, "789"
      refute_includes out, "key-abc789"
    end
  end

  def test_show_reveal_exposes_full_values
    vault = create_test_vault("default")
    vault.set("OPENAI_API_KEY", "sk-proj-abc123")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[show --reveal]) }
      assert_includes out, "sk-proj-abc123"
    end
  end

  def test_show_reveal_with_group
    vault = create_test_vault("default")
    vault.set("MYHANDLE_API_KEY", "key-full-value")
    vault.set("MYHANDLE_ACCESS_TOKEN", "tok-full-value")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[show --group --reveal]) }
      assert_includes out, "key-full-value"
      assert_includes out, "tok-full-value"
    end
  end

  # --- reset ---

  def test_reset_destroys_vault_and_reinitializes
    vault = create_test_vault("default")
    vault.set("SECRET", "gone")

    call_count = 0
    inputs = ["default", "newpass", "newpass"]
    stub_reset_inputs(inputs) do
      out, = capture_io { LocalVault::CLI.start(%w[reset]) }
      assert_match(/Vault 'default' has been reset/, out)
    end

    new_vault = LocalVault::Vault.open(name: "default", passphrase: "newpass")
    assert_nil new_vault.get("SECRET")
  end

  def test_reset_requires_vault_name_confirmation
    create_test_vault("default")

    inputs = ["wrong", "newpass", "newpass"]
    stub_reset_inputs(inputs) do
      _, err = capture_io { LocalVault::CLI.start(%w[reset]) }
      assert_match(/Cancelled/, err)
      assert LocalVault::Store.new("default").exists?
    end
  end

  def test_reset_errors_if_vault_does_not_exist
    _, err = capture_io { LocalVault::CLI.start(%w[reset]) }
    assert_match(/does not exist/, err)
  end

  def test_reset_named_vault
    create_test_vault("staging")

    inputs = ["staging", "newpass", "newpass"]
    stub_reset_inputs(inputs) do
      out, = capture_io { LocalVault::CLI.start(%w[reset staging]) }
      assert_match(/Vault 'staging' has been reset/, out)
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

  # Stubs rekey: all three inputs are passphrase prompts (current, new, confirm)
  def stub_rekey_inputs(inputs)
    idx = 0
    orig = LocalVault::CLI.instance_method(:prompt_passphrase)
    LocalVault::CLI.send(:define_method, :prompt_passphrase) { |_msg = ""| inputs[idx].tap { idx += 1 } }
    yield
  ensure
    LocalVault::CLI.send(:define_method, :prompt_passphrase, orig)
  end

  # Stubs reset: first input is confirmation (via $stdin), rest are passphrase prompts
  def stub_reset_inputs(inputs)
    input_index = 0
    original_gets = LocalVault::CLI.instance_method(:prompt_confirmation)
    original_pass = LocalVault::CLI.instance_method(:prompt_passphrase)
    LocalVault::CLI.send(:define_method, :prompt_confirmation) { |_msg = ""| inputs[input_index].tap { input_index += 1 } }
    LocalVault::CLI.send(:define_method, :prompt_passphrase) { |_msg = ""| inputs[input_index].tap { input_index += 1 } }
    yield
  ensure
    LocalVault::CLI.send(:define_method, :prompt_confirmation, original_gets)
    LocalVault::CLI.send(:define_method, :prompt_passphrase, original_pass)
  end

  def stub_getpass(callable)
    original = LocalVault::CLI.instance_method(:prompt_passphrase)
    LocalVault::CLI.send(:define_method, :prompt_passphrase) { |_msg = "Passphrase: "| callable.call }
    yield
  ensure
    LocalVault::CLI.send(:define_method, :prompt_passphrase, original)
  end
end
