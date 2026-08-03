require_relative "test_helper"
require_relative "../lib/localvault/cli"
require "open3"
require "rbconfig"
require "stringio"

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

  def test_groups_searches_names_without_revealing_values
    vault = create_test_vault("default")
    vault.set("STRIPE.API_KEY", "sk-secret")
    vault.set("STRATUS_URL", "https://secret.example")
    vault.set("AWS_KEY", "akia-secret")

    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[groups str]) }
      assert_includes out, "STRATUS"
      assert_includes out, "STRIPE"
      refute_includes out, "sk-secret"
      refute_includes out, "https://secret.example"
    end
  end

  def test_show_group_resolves_unique_prefix
    vault = create_test_vault("default")
    vault.set("STRIPE.API_KEY", "sk-secret")
    vault.set("AWS_KEY", "akia-secret")

    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[show --group str]) }
      assert_includes out, "STRIPE"
      assert_includes out, "API_KEY"
      refute_includes out, "AWS_KEY"
      refute_includes out, "sk-secret"
    end
  end

  def test_show_group_can_select_names_that_match_old_internal_sentinels
    vault = create_test_vault("default")
    vault.set("__all__.KEY", "all-secret")
    vault.set("__off__.KEY", "off-secret")

    with_session("default") do
      all_out, = capture_io { LocalVault::CLI.start(%w[show --group __all__]) }
      off_out, = capture_io { LocalVault::CLI.start(%w[show --group __off__]) }

      assert_includes all_out, "__all__"
      assert_includes all_out, "KEY"
      refute_includes all_out, "__off__"
      assert_includes off_out, "__off__"
      assert_includes off_out, "KEY"
      refute_includes off_out, "__all__"
    end
  end

  def test_show_group_ambiguity_returns_candidates_and_nonzero_status
    vault = create_test_vault("default")
    vault.set("STRIPE.API_KEY", "never-print-one")
    vault.set("STRATUS_URL", "never-print-two")

    with_session("default") do
      _out, err = capture_io do
        status = LocalVault::CLI.start(%w[show --group str])
        assert_equal 1, status
      end
      assert_includes err, "Multiple groups match `str`"
      assert_includes err, "STRATUS"
      assert_includes err, "STRIPE"
      assert_includes err, "localvault show --group STRIPE"
      refute_includes err, "never-print"
    end
  end

  def test_show_group_absence_returns_search_hint_and_nonzero_status
    create_test_vault("default")

    with_session("default") do
      _out, err = capture_io do
        status = LocalVault::CLI.start(%w[show --group missing])
        assert_equal 1, status
      end
      assert_includes err, "No group matches `missing`"
      assert_includes err, "localvault groups missing"
    end
  end

  def test_set_group_saves_using_dot_notation
    vault = create_test_vault("default")

    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[set --group STRIPE API_KEY sk-secret]) }
      assert_equal "sk-secret", vault.get("STRIPE.API_KEY")
      assert_includes out, "Stored as:"
      refute_includes out, "sk-secret"
    end
  end

  def test_set_group_rejects_invalid_segments_without_reflecting_inputs
    create_test_vault("default")

    with_session("default") do
      _out, err = capture_io do
        status = LocalVault::CLI.start(["set", "--group", "bad-group", "API_KEY", "never-print-this"])
        assert_equal 1, status
      end
      assert_includes err, "letters, digits, and underscores"
      refute_includes err, "bad-group"
      refute_includes err, "API_KEY"
      refute_includes err, "never-print-this"
    end
  end

  def test_set_group_rejects_scalar_collision_without_reflecting_inputs
    vault = create_test_vault("default")
    vault.set("STRIPE", "occupied")

    with_session("default") do
      _out, err = capture_io do
        status = LocalVault::CLI.start(%w[set --group STRIPE API_KEY never-print-this])
        assert_equal 1, status
      end
      assert_includes err, "that name is already used by a secret key"
      refute_includes err, "STRIPE"
      refute_includes err, "API_KEY"
      refute_includes err, "never-print-this"
    end
  end

  def test_set_group_rejects_case_ambiguous_existing_names
    vault = create_test_vault("default")
    vault.set("Stripe.KEY", "one")
    vault.set("STRIPE.KEY", "two")

    with_session("default") do
      _out, err = capture_io do
        status = LocalVault::CLI.start(%w[set --group stripe API_KEY never-print-this])
        assert_equal 1, status
      end
      assert_includes err, "group name is ambiguous"
      assert_includes err, "Stripe"
      assert_includes err, "STRIPE"
      refute_includes err, "never-print-this"
    end
  end

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

  def test_set_stdin_stores_secret_without_printing_value
    create_test_vault("default")

    with_session("default") do
      out, err = with_stdin(StringIO.new("super-secret\n")) do
        capture_io do
          status = LocalVault::CLI.start(%w[set API_KEY --stdin])
          assert_equal 0, status
        end
      end

      vault = open_test_vault("default")
      assert_equal "super-secret\n", vault.get("API_KEY")
      refute_includes out, "super-secret"
      refute_includes err, "super-secret"
    end
  end

  def test_set_stdin_preserves_empty_and_crlf_values
    create_test_vault("default")

    with_session("default") do
      with_stdin(StringIO.new("")) do
        capture_io { LocalVault::CLI.start(%w[set EMPTY --stdin]) }
      end
      with_stdin(StringIO.new("line1\r\nline2\r\n")) do
        capture_io { LocalVault::CLI.start(%w[set WINDOWS --stdin]) }
      end

      vault = open_test_vault("default")
      assert_equal "", vault.get("EMPTY")
      assert_equal "line1\r\nline2\r\n", vault.get("WINDOWS")
    end
  end

  def test_set_stdin_preserves_crlf_from_real_pipe
    create_test_vault("default")

    with_session("default") do
      bin_path = File.expand_path("../../bin/localvault", __FILE__)
      env = {
        "LOCALVAULT_HOME" => @test_home,
        "LOCALVAULT_SESSION" => ENV["LOCALVAULT_SESSION"]
      }

      _out, err, status = Open3.capture3(env, RbConfig.ruby, bin_path, "set", "PIPE_CRLF", "--stdin",
        stdin_data: "line1\r\nline2\r\n")

      assert status.success?, err
      vault = open_test_vault("default")
      assert_equal "line1\r\nline2\r\n", vault.get("PIPE_CRLF")
    end
  end

  def test_set_stdin_works_with_group_and_vault_options
    create_test_vault("staging")

    with_session("staging") do
      with_stdin(StringIO.new("group-secret")) do
        capture_io { LocalVault::CLI.start(%w[set --group STRIPE API_KEY --stdin --vault staging]) }
      end

      vault = open_test_vault("staging")
      assert_equal "group-secret", vault.get("STRIPE.API_KEY")
    end
  end

  def test_set_stdin_rejects_multiple_value_sources_without_storing_or_reflecting_value
    vault = create_test_vault("default")

    with_session("default") do
      _out, err = with_stdin(StringIO.new("stdin-secret")) do
        capture_io do
          status = LocalVault::CLI.start(%w[set TOKEN argv-secret --stdin])
          assert_equal 1, status
        end
      end

      assert_nil vault.get("TOKEN")
      assert_includes err, "Use either a positional VALUE or --stdin"
      refute_includes err, "argv-secret"
      refute_includes err, "stdin-secret"
    end
  end

  def test_set_stdin_rejects_interactive_tty_without_reading
    vault = create_test_vault("default")
    tty_input = Object.new
    def tty_input.tty?
      true
    end
    def tty_input.read
      raise "stdin should not be read"
    end

    with_session("default") do
      _out, err = with_stdin(tty_input) do
        capture_io do
          status = LocalVault::CLI.start(%w[set TOKEN --stdin])
          assert_equal 1, status
        end
      end

      assert_nil vault.get("TOKEN")
      assert_includes err, "Refusing to read secret from interactive stdin"
      assert_includes err, "printf '%s' \"$SECRET\" | localvault set KEY --stdin"
    end
  end

  def test_set_stdin_rejects_invalid_utf8
    vault = create_test_vault("default")

    with_session("default") do
      _out, err = with_stdin(StringIO.new("\xFF".b)) do
        capture_io do
          status = LocalVault::CLI.start(%w[set TOKEN --stdin])
          assert_equal 1, status
        end
      end

      assert_nil vault.get("TOKEN")
      assert_includes err, "valid UTF-8"
    end
  end

  def test_set_literal_dash_and_stdin_token_remain_positional_values
    create_test_vault("default")

    with_session("default") do
      capture_io { LocalVault::CLI.start(%w[set DASH -]) }
      capture_io { LocalVault::CLI.start(%w[set FLAG -- --stdin]) }

      vault = open_test_vault("default")
      assert_equal "-", vault.get("DASH")
      assert_equal "--stdin", vault.get("FLAG")
    end
  end

  def test_set_missing_value_shows_safe_stdin_usage
    create_test_vault("default")

    with_session("default") do
      _out, err = capture_io do
        status = LocalVault::CLI.start(%w[set TOKEN])
        assert_equal 1, status
      end

      assert_includes err, "Usage: localvault set KEY [VALUE]"
      assert_includes err, "printf '%s' \"$SECRET\" | localvault set KEY --stdin"
      refute_includes err, "TOKEN"
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

  def test_get_partial_match_single_result
    vault = create_test_vault("default")
    vault.set("CLOUDFLARE_API_TOKEN", "cf-abc123")
    vault.set("OPENAI_API_KEY", "sk-xyz")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[get CLOUDFLARE]) }
      assert_equal "cf-abc123\n", out
    end
  end

  def test_get_partial_match_case_insensitive
    vault = create_test_vault("default")
    vault.set("OPENAI_API_KEY", "sk-xyz")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[get openai]) }
      assert_equal "sk-xyz\n", out
    end
  end

  def test_get_partial_match_multiple_results
    vault = create_test_vault("default")
    vault.set("STRIPE_KEY", "sk_live_1")
    vault.set("STRIPE_SECRET", "sk_live_2")
    with_session("default") do
      _, err = capture_io { LocalVault::CLI.start(%w[get STRIPE]) }
      assert_match(/Multiple keys match 'STRIPE'/, err)
      assert_match(/STRIPE_KEY/, err)
      assert_match(/STRIPE_SECRET/, err)
    end
  end

  def test_get_exact_match_takes_priority_over_partial
    vault = create_test_vault("default")
    vault.set("API", "exact-value")
    vault.set("API_KEY", "partial-value")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[get API]) }
      assert_equal "exact-value\n", out
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
      assert_includes out, "export API_KEY="
      assert_includes out, "export DB_URL="
    end
  end

  def test_env_only_filters_by_exact_key_and_namespace
    vault = create_test_vault("default")
    vault.set("AWS_IAM.access_key_id", "akia")
    vault.set("AWS_IAM.secret_access_key", "secret")
    vault.set("AWS_SES.smtp_password", "smtp")
    vault.set("OPENAI_API_KEY", "sk")

    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(["env", "--only", "AWS_IAM.*,OPENAI_API_KEY"]) }
      assert_includes out, "AWS_IAM__access_key_id"
      assert_includes out, "AWS_IAM__secret_access_key"
      assert_includes out, "OPENAI_API_KEY"
      refute_includes out, "AWS_SES__smtp_password"
    end
  end

  def test_env_except_removes_matching_keys_after_only
    vault = create_test_vault("default")
    vault.set("AWS_IAM.access_key_id", "akia")
    vault.set("AWS_IAM.secret_access_key", "secret")
    vault.set("AWS_SES.smtp_password", "smtp")

    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(["env", "--only", "AWS_IAM.*,AWS_SES.*", "--except", "AWS_SES.*"]) }
      assert_includes out, "AWS_IAM__access_key_id"
      assert_includes out, "AWS_IAM__secret_access_key"
      refute_includes out, "AWS_SES__smtp_password"
    end
  end

  def test_env_map_renames_selected_key
    vault = create_test_vault("default")
    vault.set("AWS_IAM.access_key_id", "akia")

    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(["env", "--map", "AWS_IAM.access_key_id=AWS_ACCESS_KEY_ID"]) }
      assert_includes out, "export AWS_ACCESS_KEY_ID="
      refute_includes out, "AWS_IAM__access_key_id"
    end
  end

  def test_env_profile_aws_maps_canonical_aws_names_and_scopes_to_aws_iam
    vault = create_test_vault("default")
    vault.set("AWS_IAM.access_key_id", "akia")
    vault.set("AWS_IAM.secret_access_key", "secret")
    vault.set("AWS_IAM.session_token", "token")
    vault.set("AWS_SES.smtp_password", "smtp")

    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[env --profile aws]) }
      assert_includes out, "export AWS_ACCESS_KEY_ID="
      assert_includes out, "export AWS_SECRET_ACCESS_KEY="
      assert_includes out, "export AWS_SESSION_TOKEN="
      refute_includes out, "AWS_IAM__access_key_id"
      refute_includes out, "AWS_SES__smtp_password"
    end
  end

  def test_env_explicit_map_overrides_profile_map
    vault = create_test_vault("default")
    vault.set("AWS_IAM.access_key_id", "akia")
    vault.set("AWS_IAM.secret_access_key", "secret")

    with_session("default") do
      out, = capture_io do
        LocalVault::CLI.start(["env", "--profile", "aws", "--map", "AWS_IAM.access_key_id=CUSTOM_AWS_KEY"])
      end
      assert_includes out, "export CUSTOM_AWS_KEY="
      assert_includes out, "export AWS_SECRET_ACCESS_KEY="
      refute_includes out, "AWS_ACCESS_KEY_ID"
    end
  end

  # --- vaults ---

  def test_vaults_lists_all_vault_names
    create_test_vault("default")
    create_test_vault("staging")
    out, = capture_io { LocalVault::CLI.start(%w[vaults]) }
    assert_includes out, "default"
    assert_includes out, "staging"
  end

  def test_vaults_marks_default_vault
    create_test_vault("default")
    create_test_vault("staging")
    out, = capture_io { LocalVault::CLI.start(%w[vaults]) }
    assert_includes out, "✓"       # default marker present
    # staging is not the default, so no marker on that row only
    lines = out.lines.select { |l| l.include?("staging") }
    assert lines.none? { |l| l.include?("✓") }
  end

  def test_vaults_shows_secret_count
    vault = create_test_vault("default")
    vault.set("KEY_A", "val1")
    vault.set("KEY_B", "val2")
    out, = capture_io { LocalVault::CLI.start(%w[vaults]) }
    assert_includes out, "2"
  end

  def test_vaults_shows_zero_count_for_empty_vault
    create_test_vault("default")
    out, = capture_io { LocalVault::CLI.start(%w[vaults]) }
    assert_includes out, "0"
  end

  def test_vaults_shows_no_vaults_message_when_empty
    out, = capture_io { LocalVault::CLI.start(%w[vaults]) }
    assert_match(/no vaults/i, out)
  end

  # --- switch ---

  def test_switch_changes_default_vault
    create_test_vault("default")
    create_test_vault("intellectaco")
    capture_io { LocalVault::CLI.start(%w[switch intellectaco]) }
    assert_equal "intellectaco", LocalVault::Config.default_vault
  end

  def test_switch_shows_confirmation
    create_test_vault("default")
    create_test_vault("staging")
    out, = capture_io { LocalVault::CLI.start(%w[switch staging]) }
    assert_includes out, "staging"
  end

  def test_switch_errors_if_vault_does_not_exist
    _, err = capture_io { LocalVault::CLI.start(%w[switch nonexistent]) }
    assert_includes err, "nonexistent"
  end

  def test_switch_no_arg_shows_current_vault
    create_test_vault("default")
    LocalVault::Config.default_vault = "default"
    out, = capture_io { LocalVault::CLI.start(%w[switch]) }
    assert_includes out, "default"
  end

  # --- import ---

  def test_import_env_file
    vault = create_test_vault("default")
    env_file = File.join(@test_home, "test.env")
    File.write(env_file, "SECRET_KEY=abc123\nDATABASE_URL=postgres://localhost\n")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(["import", env_file]) }
      assert_includes out, "2"
    end
    assert_equal "abc123", vault.get("SECRET_KEY")
    assert_equal "postgres://localhost", vault.get("DATABASE_URL")
  end

  def test_import_env_file_with_project
    vault = create_test_vault("default")
    env_file = File.join(@test_home, "test.env")
    File.write(env_file, "SECRET_KEY=abc123\n")
    with_session("default") do
      capture_io { LocalVault::CLI.start(["import", env_file, "--project", "myapp"]) }
    end
    assert_equal "abc123", vault.get("myapp.SECRET_KEY")
  end

  def test_import_json_file
    vault = create_test_vault("default")
    json_file = File.join(@test_home, "secrets.json")
    File.write(json_file, JSON.generate({ "API_KEY" => "xyz", "TOKEN" => "tok" }))
    with_session("default") do
      capture_io { LocalVault::CLI.start(["import", json_file]) }
    end
    assert_equal "xyz", vault.get("API_KEY")
  end

  def test_import_nested_json
    vault = create_test_vault("default")
    json_file = File.join(@test_home, "secrets.json")
    File.write(json_file, JSON.generate({ "platepose" => { "DB" => "postgres://localhost" } }))
    with_session("default") do
      capture_io { LocalVault::CLI.start(["import", json_file]) }
    end
    assert_equal "postgres://localhost", vault.get("platepose.DB")
  end

  def test_import_yaml_file
    vault = create_test_vault("default")
    yaml_file = File.join(@test_home, "secrets.yml")
    File.write(yaml_file, "SECRET: mysecret\n")
    with_session("default") do
      capture_io { LocalVault::CLI.start(["import", yaml_file]) }
    end
    assert_equal "mysecret", vault.get("SECRET")
  end

  def test_import_skips_comments_and_blanks_in_env
    vault = create_test_vault("default")
    env_file = File.join(@test_home, "test.env")
    File.write(env_file, "# comment\n\nKEY=value\n")
    with_session("default") do
      capture_io { LocalVault::CLI.start(["import", env_file]) }
    end
    assert_equal "value", vault.get("KEY")
    assert_nil vault.get("# comment")
  end

  def test_import_errors_on_missing_file
    create_test_vault("default")
    with_session("default") do
      _, err = capture_io { LocalVault::CLI.start(["import", "/nonexistent/file.env"]) }
      assert_includes err, "not found"
    end
  end

  # --- rename ---

  def test_rename_key
    vault = create_test_vault("default")
    vault.set("OLD_KEY", "myvalue")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[rename OLD_KEY NEW_KEY]) }
      assert_includes out, "NEW_KEY"
    end
    assert_equal "myvalue", vault.get("NEW_KEY")
    assert_nil vault.get("OLD_KEY")
  end

  def test_rename_nested_key
    vault = create_test_vault("default")
    vault.set("app.OLD", "val")
    with_session("default") do
      capture_io { LocalVault::CLI.start(%w[rename app.OLD app.NEW]) }
    end
    assert_equal "val", vault.get("app.NEW")
    assert_nil vault.get("app.OLD")
  end

  def test_rename_errors_if_key_not_found
    create_test_vault("default")
    with_session("default") do
      _, err = capture_io { LocalVault::CLI.start(%w[rename MISSING NEW_KEY]) }
      assert_includes err, "MISSING"
    end
  end

  # --- copy ---

  def test_copy_key_to_another_vault
    src = create_test_vault("default")
    dst = create_test_vault("staging")
    src.set("API_KEY", "secret")
    cache_vault_session("staging")
    with_session("default") do
      out, = capture_io { LocalVault::CLI.start(%w[copy API_KEY --to staging]) }
      assert_includes out, "API_KEY"
    end
    assert_equal "secret", dst.get("API_KEY")
  end

  def test_copy_nested_key_to_another_vault
    src = create_test_vault("default")
    dst = create_test_vault("staging")
    src.set("app.DB", "postgres://localhost")
    cache_vault_session("staging")
    with_session("default") do
      capture_io { LocalVault::CLI.start(%w[copy app.DB --to staging]) }
    end
    assert_equal "postgres://localhost", dst.get("app.DB")
  end

  def test_copy_errors_if_source_key_missing
    create_test_vault("default")
    create_test_vault("staging")
    cache_vault_session("staging")
    with_session("default") do
      _, err = capture_io { LocalVault::CLI.start(%w[copy MISSING --to staging]) }
      assert_includes err, "MISSING"
    end
  end

  # --- demo ---

  def test_demo_creates_four_vaults
    stub_demo_confirm("demo") do
      capture_io { LocalVault::CLI.start(%w[demo]) }
    end
    assert LocalVault::Store.new("default").exists?
    assert LocalVault::Store.new("x").exists?
    assert LocalVault::Store.new("production").exists?
    assert LocalVault::Store.new("staging").exists?
  end

  def test_demo_populates_secrets
    stub_demo_confirm("demo") do
      capture_io { LocalVault::CLI.start(%w[demo]) }
    end
    store = LocalVault::Store.new("default")
    assert store.count > 0
  end

  def test_demo_vaults_openable_with_demo_passphrase
    stub_demo_confirm("demo") do
      capture_io { LocalVault::CLI.start(%w[demo]) }
    end
    vault = LocalVault::Vault.open(name: "default", passphrase: "demo")
    assert vault.get("OPENAI_API_KEY")
  end

  def test_demo_cancelled_when_wrong_confirmation
    stub_demo_confirm("nope") do
      _, err = capture_io { LocalVault::CLI.start(%w[demo]) }
      assert_match(/cancelled/i, err)
    end
    refute LocalVault::Store.new("default").exists?
  end

  def test_demo_aborts_if_vaults_already_exist
    create_test_vault("default")
    stub_demo_confirm("demo") do
      _, err = capture_io { LocalVault::CLI.start(%w[demo]) }
      assert_match(/already exist/i, err)
    end
  end

  def test_demo_outputs_next_steps
    stub_demo_confirm("demo") do
      out, = capture_io { LocalVault::CLI.start(%w[demo]) }
      assert_match(/localvault vaults/, out)
      assert_match(/localvault show/, out)
    end
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

  def test_unlock_accepts_positional_vault_name
    create_test_vault("intellectaco")
    stub_passphrase(test_passphrase) do
      out, = capture_io { LocalVault::CLI.start(%w[unlock intellectaco]) }
      assert_match(/export LOCALVAULT_SESSION=/, out)

      token = out.match(/LOCALVAULT_SESSION="([^"]+)"/)[1]
      decoded = Base64.strict_decode64(token)
      vault_name, = decoded.split(":", 2)
      assert_equal "intellectaco", vault_name
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

  # Regression for audit finding 2 (v1.3.4): reset must validate the new
  # passphrase BEFORE destroying the existing vault. Previously, an empty
  # or mismatched passphrase (or Ctrl-C between destroy and prompt) left
  # the user with a destroyed vault and no way to recover.
  def test_reset_preserves_vault_on_empty_passphrase
    vault = create_test_vault("default")
    vault.set("KEEP_ME", "important_data")

    inputs = ["default", "", ""]
    stub_reset_inputs(inputs) do
      _, err = capture_io { LocalVault::CLI.start(%w[reset]) }
      assert_match(/passphrase cannot be empty/i, err)
    end

    # Original vault must still exist with its original contents
    assert LocalVault::Store.new("default").exists?
    surviving = LocalVault::Vault.open(name: "default", passphrase: test_passphrase)
    assert_equal "important_data", surviving.get("KEEP_ME")
  end

  def test_reset_preserves_vault_on_mismatched_passphrase
    vault = create_test_vault("default")
    vault.set("KEEP_ME", "important_data")

    inputs = ["default", "first-pass", "second-pass"]
    stub_reset_inputs(inputs) do
      _, err = capture_io { LocalVault::CLI.start(%w[reset]) }
      assert_match(/do not match/i, err)
    end

    assert LocalVault::Store.new("default").exists?
    surviving = LocalVault::Vault.open(name: "default", passphrase: test_passphrase)
    assert_equal "important_data", surviving.get("KEEP_ME")
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

  def test_exec_applies_env_dsl_options
    vault = create_test_vault("default")
    vault.set("AWS_IAM.access_key_id", "akia")
    vault.set("AWS_IAM.secret_access_key", "secret")
    vault.set("AWS_SES.smtp_password", "smtp")
    with_session("default") do
      bin_path = File.expand_path("../../bin/localvault", __FILE__)
      env = {
        "LOCALVAULT_HOME" => @test_home,
        "LOCALVAULT_SESSION" => ENV["LOCALVAULT_SESSION"]
      }
      script = 'puts [ENV["AWS_ACCESS_KEY_ID"], ENV["AWS_SECRET_ACCESS_KEY"], ENV.key?("AWS_SES__smtp_password")].join("|")'
      output = IO.popen(env, [
        RbConfig.ruby, bin_path,
        "exec", "--profile", "aws", "--except", "AWS_SES.*", "--",
        RbConfig.ruby, "-e", script
      ]) { |io| io.read }

      assert_equal "akia|secret|false\n", output
    end
  end

  # --- install-mcp ---

  def test_mcp_help_explains_install_check_and_injection_first_use
    out, = capture_io { LocalVault::CLI.start(%w[help mcp]) }

    assert_includes out, "localvault install-mcp"
    assert_includes out, "localvault mcp --check"
    assert_includes out, "localvault_build_exec"
    assert_includes out, "Do not run `localvault mcp` directly"
  end

  def test_set_help_teaches_both_group_save_forms
    out, = capture_io { LocalVault::CLI.start(%w[help set]) }

    assert_includes out, "localvault set --group GROUP KEY VALUE"
    assert_includes out, "localvault set GROUP.KEY VALUE"
    assert_includes out, "localvault groups [QUERY]"
  end

  def test_mcp_check_reports_ready_without_starting_stdio_server
    create_test_vault("default")

    with_session("default") do
      status = nil
      out, = capture_io { status = LocalVault::CLI.start(%w[mcp --check]) }
      assert_equal 0, status
      assert_includes out, "MCP readiness: ready"
      assert_includes out, "LocalVault #{LocalVault::VERSION}"
      assert_includes out, "Home: #{@test_home}"
      assert_includes out, "Active vault: default"
      assert_includes out, "MCP tools:"
      assert_includes out, "list_secrets"
      assert_includes out, "localvault_build_exec"
      assert_includes out, "Plaintext gate: enabled"
      assert_includes out, "Server instructions: enabled"
    end
  end

  def test_mcp_check_returns_nonzero_when_active_vault_is_locked
    create_test_vault("default")

    out, = capture_io do
      status = LocalVault::CLI.start(%w[mcp --check])
      assert_equal 1, status
    end
    assert_includes out, "MCP readiness: locked"
    assert_includes out, "localvault show"
  end

  def test_mcp_check_only_checks_the_active_vault
    create_test_vault("default")
    create_test_vault("other")
    calls = []
    original = LocalVault::SessionCache.method(:get)
    LocalVault::SessionCache.define_singleton_method(:get) { |name| calls << name; nil }

    capture_io { LocalVault::CLI.start(%w[mcp --check]) }

    assert_equal ["default"], calls
  ensure
    LocalVault::SessionCache.define_singleton_method(:get, original) if original
  end

  # Claude Code delegates to `claude mcp add --scope user` — test via stub
  def test_install_mcp_claude_code_calls_cli
    commands_run = []
    stub_system_calls(commands_run) do
      out, = capture_io { LocalVault::CLI.start(%w[install-mcp claude-code]) }
      assert_match(/Added localvault MCP server.*user scope/, out)
      assert commands_run.any? { |cmd| cmd.include?("mcp") && cmd.include?("add") && cmd.include?("user") }
    end
  end

  def test_install_mcp_cursor_writes_json
    config_path = File.join(@test_home, ".cursor", "mcp.json")
    stub_cursor_path(config_path) do
      capture_io { LocalVault::CLI.start(%w[install-mcp cursor]) }
      assert File.exist?(config_path)
      settings = JSON.parse(File.read(config_path))
      assert_equal ["mcp"], settings.dig("mcpServers", "localvault", "args")
    end
  end

  def test_install_mcp_cursor_merges_existing_settings
    config_path = File.join(@test_home, ".cursor", "mcp.json")
    FileUtils.mkdir_p(File.dirname(config_path))
    File.write(config_path, JSON.generate({ "mcpServers" => { "other" => { "command" => "other" } } }))

    stub_cursor_path(config_path) do
      capture_io { LocalVault::CLI.start(%w[install-mcp cursor]) }
      settings = JSON.parse(File.read(config_path))
      assert settings.dig("mcpServers", "other"), "existing servers preserved"
      assert settings.dig("mcpServers", "localvault"), "localvault added"
    end
  end

  def test_install_mcp_windsurf_writes_json
    config_path = File.join(@test_home, ".codeium", "windsurf", "mcp_config.json")
    stub_windsurf_path(config_path) do
      capture_io { LocalVault::CLI.start(%w[install-mcp windsurf]) }
      assert File.exist?(config_path)
      settings = JSON.parse(File.read(config_path))
      assert settings.dig("mcpServers", "localvault")
    end
  end

  def test_install_mcp_default_is_claude_code
    commands_run = []
    stub_system_calls(commands_run) do
      out, = capture_io { LocalVault::CLI.start(%w[install-mcp]) }
      assert_match(/Claude Code/, out)
    end
  end

  def test_install_mcp_unknown_client_errors
    _, err = capture_io { LocalVault::CLI.start(%w[install-mcp unknown-client]) }
    assert_match(/Unknown client/, err)
  end

  def test_doctor_warns_when_asdf_shim_shadows_homebrew_localvault
    paths = [
      "/Users/example/.asdf/shims/localvault",
      "/opt/homebrew/bin/localvault"
    ]

    stub_localvault_paths(paths) do
      out, = capture_io do
        status = LocalVault::CLI.start(%w[doctor])
        assert_equal 1, status
      end

      assert_includes out, "PATH selects an asdf shim before Homebrew localvault"
      assert_includes out, "/Users/example/.asdf/shims/localvault"
      assert_includes out, "/opt/homebrew/bin/localvault"
      assert_includes out, "asdf reshim"
      assert_includes out, "which -a localvault"
    end
  end

  def test_doctor_reports_ok_for_single_localvault_on_path
    stub_localvault_paths(["/opt/homebrew/bin/localvault"]) do
      out, = capture_io do
        status = LocalVault::CLI.start(%w[doctor])
        assert_equal 0, status
      end

      assert_includes out, "PATH: ok"
      refute_includes out, "Warning:"
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

  def cache_vault_session(vault_name, passphrase = test_passphrase)
    store = LocalVault::Store.new(vault_name)
    master_key = LocalVault::Crypto.derive_master_key(passphrase, store.salt)
    LocalVault::SessionCache.set(vault_name, master_key)
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

  def stub_demo_confirm(input)
    original = LocalVault::CLI.instance_method(:prompt_confirmation)
    LocalVault::CLI.send(:define_method, :prompt_confirmation) { |_msg = ""| input }
    yield
  ensure
    LocalVault::CLI.send(:define_method, :prompt_confirmation, original)
  end

  # Stub find_binary + system for claude-code tests.
  # commands_run is populated with each array passed to system().
  def stub_system_calls(commands_run)
    cli = LocalVault::CLI
    orig_find  = cli.instance_method(:find_binary)
    orig_sys   = cli.instance_method(:system_command_exists?)
    orig_sys2  = cli.instance_method(:system)

    cli.send(:define_method, :find_binary) { |_name| "/usr/local/bin/localvault" }
    cli.send(:define_method, :system_command_exists?) { |_cmd| true }
    cli.send(:define_method, :system) { |*args, **_kw| commands_run << args; true }

    yield
  ensure
    cli.send(:define_method, :find_binary, orig_find)
    cli.send(:define_method, :system_command_exists?, orig_sys)
    cli.send(:define_method, :system, orig_sys2)
  end

  def stub_cursor_path(path)
    cli = LocalVault::CLI
    orig_find = cli.instance_method(:find_binary)
    orig_path = cli.instance_method(:cursor_settings_path)

    cli.send(:define_method, :find_binary) { |_| "/usr/local/bin/localvault" }
    cli.send(:define_method, :cursor_settings_path) { path }

    yield
  ensure
    cli.send(:define_method, :find_binary, orig_find)
    cli.send(:define_method, :cursor_settings_path, orig_path)
  end

  def stub_windsurf_path(path)
    cli = LocalVault::CLI
    orig_find = cli.instance_method(:find_binary)
    orig_path = cli.instance_method(:windsurf_settings_path)

    cli.send(:define_method, :find_binary) { |_| "/usr/local/bin/localvault" }
    cli.send(:define_method, :windsurf_settings_path) { path }

    yield
  ensure
    cli.send(:define_method, :find_binary, orig_find)
    cli.send(:define_method, :windsurf_settings_path, orig_path)
  end

  def with_stdin(input)
    original_stdin = $stdin
    $stdin = input
    yield
  ensure
    $stdin = original_stdin
  end

  def stub_localvault_paths(paths)
    cli = LocalVault::CLI
    original = cli.instance_method(:localvault_paths)
    cli.no_commands { cli.send(:define_method, :localvault_paths) { paths } }

    yield
  ensure
    cli.no_commands { cli.send(:define_method, :localvault_paths, original) }
  end
end
