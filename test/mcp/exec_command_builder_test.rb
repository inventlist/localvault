require_relative "../test_helper"
require_relative "../../lib/localvault/mcp/exec_command_builder"

class MCPExecCommandBuilderTest < Minitest::Test
  def test_builds_shell_safe_localvault_exec_command_without_secret_values
    result = LocalVault::MCP::ExecCommandBuilder.new(
      command: ["aws", "sts", "get-caller-identity"],
      vault: "production",
      only: ["AWS_IAM.*"],
      map: {
        "AWS_IAM.secret_access_key" => "AWS_SECRET_ACCESS_KEY",
        "AWS_IAM.access_key_id" => "AWS_ACCESS_KEY_ID"
      }
    ).build

    assert_equal(
      "localvault exec -v production --only AWS_IAM.\\* " \
      "--map AWS_IAM.access_key_id\\=AWS_ACCESS_KEY_ID,AWS_IAM.secret_access_key\\=AWS_SECRET_ACCESS_KEY " \
      "-- aws sts get-caller-identity",
      result.fetch("command")
    )
    assert_equal false, result.fetch("exposes_plaintext")
    assert_equal false, result.fetch("executes_command")
    assert_includes result.fetch("next_action"), "normal shell tool"
  end

  def test_rejects_empty_or_non_string_command_arguments
    error = assert_raises(LocalVault::InputValidation::InvalidInput) do
      LocalVault::MCP::ExecCommandBuilder.new(command: ["curl", 123]).build
    end
    assert_includes error.message, "command"
  end

  def test_rejects_option_injection_in_localvault_values
    error = assert_raises(LocalVault::InputValidation::InvalidInput) do
      LocalVault::MCP::ExecCommandBuilder.new(
        command: ["env"],
        vault: "--help"
      ).build
    end

    assert_includes error.message, "vault"
  end

  def test_rejects_invalid_selector_and_unknown_profile
    assert_raises(LocalVault::InputValidation::InvalidInput) do
      LocalVault::MCP::ExecCommandBuilder.new(command: ["env"], only: ["--help"]).build
    end
    assert_raises(LocalVault::InputValidation::InvalidInput) do
      LocalVault::MCP::ExecCommandBuilder.new(command: ["env"], profile: "bogus").build
    end
  end
end
