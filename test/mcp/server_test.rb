require_relative "../test_helper"
require_relative "../../lib/localvault/cli"

class MCPServerTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @original_session = ENV["LOCALVAULT_SESSION"]
    @original_vault   = ENV["LOCALVAULT_VAULT"]
    ENV.delete("LOCALVAULT_SESSION")
    ENV.delete("LOCALVAULT_VAULT")
  end

  def teardown
    if @original_session
      ENV["LOCALVAULT_SESSION"] = @original_session
    else
      ENV.delete("LOCALVAULT_SESSION")
    end
    if @original_vault
      ENV["LOCALVAULT_VAULT"] = @original_vault
    else
      ENV.delete("LOCALVAULT_VAULT")
    end
    teardown_test_home
  end

  # --- initialize ---

  def test_initialize_returns_server_info
    with_vault_session do
      response = send_request("initialize", {
        "protocolVersion" => "2025-11-25",
        "capabilities" => {},
        "clientInfo" => { "name" => "test", "version" => "1.0" }
      })
      assert_equal "2.0", response["jsonrpc"]
      assert_equal "localvault", response.dig("result", "serverInfo", "name")
      assert_equal LocalVault::VERSION, response.dig("result", "serverInfo", "version")
      assert_equal "2025-11-25", response.dig("result", "protocolVersion")
      assert response.dig("result", "capabilities", "tools")
    end
  end

  # --- notifications/initialized ---

  def test_notification_gets_no_response
    with_vault_session do
      server = build_server('{"jsonrpc":"2.0","method":"notifications/initialized"}' + "\n")
      output = StringIO.new
      server.instance_variable_set(:@output, output)
      server.start
      assert_equal "", output.string
    end
  end

  # --- tools/list ---

  def test_tools_list_returns_five_tools
    with_vault_session do
      response = send_request("tools/list", {})
      tools = response.dig("result", "tools")
      assert_equal 5, tools.size
      names = tools.map { |t| t["name"] }.sort
      assert_equal %w[delete_secret get_secret list_secrets localvault_whoami set_secret], names
    end
  end

  def test_tools_list_includes_vault_parameter
    with_vault_session do
      response = send_request("tools/list", {})
      get_tool = response.dig("result", "tools").find { |t| t["name"] == "get_secret" }
      assert get_tool.dig("inputSchema", "properties", "vault"), "get_secret should have vault param"
      # vault is optional
      refute_includes get_tool.dig("inputSchema", "required"), "vault"
    end
  end

  def test_tools_list_includes_input_schemas
    with_vault_session do
      response = send_request("tools/list", {})
      get_tool = response.dig("result", "tools").find { |t| t["name"] == "get_secret" }
      assert_equal "object", get_tool.dig("inputSchema", "type")
      assert_includes get_tool.dig("inputSchema", "required"), "key"
    end
  end

  # --- tools/call get_secret ---

  def test_get_secret_returns_value
    with_vault_session do |vault|
      vault.set("API_KEY", "sk-12345")
      response = send_request("tools/call", { "name" => "get_secret", "arguments" => { "key" => "API_KEY" } })
      content = response.dig("result", "content")
      assert_equal 1, content.size
      assert_equal "text", content[0]["type"]
      assert_equal "sk-12345", content[0]["text"]
      refute response.dig("result", "isError")
    end
  end

  def test_get_secret_uses_session_when_it_matches_resolved_default
    vault_a = create_test_vault("vaultA")
    vault_a.set("KEY", "from_a")
    LocalVault::Config.default_vault = "vaultA"
    ENV["LOCALVAULT_SESSION"] = session_token_for("vaultA")

    response = send_request("tools/call", { "name" => "get_secret", "arguments" => { "key" => "KEY" } })
    assert_equal "from_a", response.dig("result", "content", 0, "text")
  end

  def test_get_secret_uses_default_vault_instead_of_unrelated_session_vault
    default_vault = create_test_vault("devops")
    session_vault = create_test_vault("intellectaco")
    default_vault.set("KEY", "from_devops")
    session_vault.set("KEY", "from_intellectaco")
    LocalVault::Config.default_vault = "devops"

    master_default = LocalVault::Crypto.derive_master_key(test_passphrase, LocalVault::Store.new("devops").salt)
    ENV["LOCALVAULT_SESSION"] = session_token_for("intellectaco")

    stub_keychain(->(name) { name == "devops" ? master_default : nil }) do
      response = send_request("tools/call", { "name" => "get_secret", "arguments" => { "key" => "KEY" } })
      assert_equal "from_devops", response.dig("result", "content", 0, "text")
    end
  end

  def test_lock_revokes_cached_mcp_access_without_restart
    vault = create_test_vault("default")
    vault.set("KEY", "value")
    master_key = LocalVault::Crypto.derive_master_key(test_passphrase, LocalVault::Store.new("default").salt)

    calls = 0
    stub_keychain(->(_name) { calls += 1; calls == 1 ? master_key : nil }) do
      require "localvault/mcp/server"
      server = LocalVault::MCP::Server.new(input: StringIO.new, output: StringIO.new)

      ok = server_call(server, "tools/call", { "name" => "get_secret", "arguments" => { "key" => "KEY" } })
      assert_equal "value", ok.dig("result", "content", 0, "text")

      locked = server_call(server, "tools/call", { "name" => "get_secret", "arguments" => { "key" => "KEY" } })
      assert locked.dig("result", "isError")
      assert_match(/No unlocked vault session/, locked.dig("result", "content", 0, "text"))
    end
  end

  def test_get_secret_missing_key_returns_error
    with_vault_session do
      response = send_request("tools/call", { "name" => "get_secret", "arguments" => { "key" => "NOPE" } })
      assert response.dig("result", "isError")
      assert_match(/not found/, response.dig("result", "content", 0, "text"))
    end
  end

  # --- tools/call list_secrets ---

  def test_list_secrets_returns_sorted_keys
    with_vault_session do |vault|
      vault.set("ZEBRA", "z")
      vault.set("ALPHA", "a")
      response = send_request("tools/call", { "name" => "list_secrets", "arguments" => {} })
      text = response.dig("result", "content", 0, "text")
      assert_equal "ALPHA\nZEBRA", text
      refute response.dig("result", "isError")
    end
  end

  def test_list_secrets_empty_vault
    with_vault_session do
      response = send_request("tools/call", { "name" => "list_secrets", "arguments" => {} })
      text = response.dig("result", "content", 0, "text")
      assert_equal "No secrets stored", text
    end
  end

  def test_list_secrets_filters_by_prefix_and_query
    with_vault_session do |vault|
      vault.set("AWS_IAM.access_key_id", "akia")
      vault.set("AWS_IAM.secret_access_key", "super-private-value")
      vault.set("AWS_SES.smtp_password", "smtp")
      vault.set("OPENAI_API_KEY", "sk")

      by_prefix = send_request("tools/call", {
        "name" => "list_secrets",
        "arguments" => { "prefix" => "AWS_IAM." }
      })
      assert_equal "AWS_IAM.access_key_id\nAWS_IAM.secret_access_key", by_prefix.dig("result", "content", 0, "text")

      by_query = send_request("tools/call", {
        "name" => "list_secrets",
        "arguments" => { "query" => "smtp" }
      })
      assert_equal "AWS_SES.smtp_password", by_query.dig("result", "content", 0, "text")
    end
  end

  def test_get_secret_partial_match_returns_candidates_not_value
    with_vault_session do |vault|
      vault.set("AWS_IAM.access_key_id", "akia")
      vault.set("AWS_IAM.secret_access_key", "secret")

      response = send_request("tools/call", { "name" => "get_secret", "arguments" => { "key" => "AWS_IAM" } })
      text = response.dig("result", "content", 0, "text")
      assert response.dig("result", "isError")
      assert_match(/Multiple keys match 'AWS_IAM'/, text)
      assert_match(/AWS_IAM.access_key_id/, text)
      assert_match(/AWS_IAM.secret_access_key/, text)
      refute_match(/akia|super-private-value/, text)
    end
  end

  def test_get_secret_single_partial_match_returns_candidate_not_value
    with_vault_session do |vault|
      vault.set("CLOUDFLARE_API_TOKEN", "cf-secret")

      response = send_request("tools/call", { "name" => "get_secret", "arguments" => { "key" => "cloudflare" } })
      text = response.dig("result", "content", 0, "text")
      assert response.dig("result", "isError")
      assert_match(/Key 'cloudflare' not found/, text)
      assert_match(/CLOUDFLARE_API_TOKEN/, text)
      refute_match(/cf-secret/, text)
    end
  end

  def test_get_secret_missing_key_argument_returns_tool_error
    with_vault_session do
      response = send_request("tools/call", { "name" => "get_secret", "arguments" => {} })

      assert response.dig("result", "isError")
      assert_match(/Missing required argument 'key'/, response.dig("result", "content", 0, "text"))
    end
  end

  def test_get_secret_non_object_arguments_return_tool_error
    with_vault_session do
      response = send_request("tools/call", { "name" => "get_secret", "arguments" => "not-an-object" })

      assert response.dig("result", "isError")
      assert_match(/Invalid arguments/, response.dig("result", "content", 0, "text"))
    end
  end

  def test_list_secrets_rejects_non_string_filters
    with_vault_session do
      response = send_request("tools/call", {
        "name" => "list_secrets",
        "arguments" => { "prefix" => 123 }
      })

      assert response.dig("result", "isError")
      assert_match(/prefix/, response.dig("result", "content", 0, "text"))
    end
  end

  # --- tools/call set_secret ---

  def test_set_secret_stores_value
    with_vault_session do |vault|
      response = send_request("tools/call", { "name" => "set_secret", "arguments" => { "key" => "NEW_KEY", "value" => "new_value" } })
      refute response.dig("result", "isError")
      assert_match(/Stored NEW_KEY/, response.dig("result", "content", 0, "text"))
      assert_equal "new_value", vault.get("NEW_KEY")
    end
  end

  def test_set_secret_supports_dot_notation
    with_vault_session do |vault|
      response = send_request("tools/call", {
        "name" => "set_secret",
        "arguments" => { "key" => "platepose.DATABASE_URL", "value" => "postgres://localhost/test" }
      })
      refute response.dig("result", "isError")
      assert_equal "postgres://localhost/test", vault.get("platepose.DATABASE_URL")
    end
  end

  def test_set_secret_group_scalar_conflict_returns_tool_error
    with_vault_session do |vault|
      vault.set("app.DB", "postgres")

      response = send_request("tools/call", {
        "name" => "set_secret",
        "arguments" => { "key" => "app", "value" => "oops" }
      })

      assert response.dig("result", "isError")
      assert_match(/group containing 1 secret/, response.dig("result", "content", 0, "text"))
    end
  end

  def test_set_secret_missing_value_argument_returns_tool_error
    with_vault_session do
      response = send_request("tools/call", { "name" => "set_secret", "arguments" => { "key" => "NEW_KEY" } })

      assert response.dig("result", "isError")
      assert_match(/Missing required argument 'value'/, response.dig("result", "content", 0, "text"))
    end
  end

  # --- tools/call delete_secret ---

  def test_delete_secret_removes_key
    with_vault_session do |vault|
      vault.set("OLD_KEY", "gone")
      response = send_request("tools/call", { "name" => "delete_secret", "arguments" => { "key" => "OLD_KEY" } })
      refute response.dig("result", "isError")
      assert_match(/Deleted OLD_KEY/, response.dig("result", "content", 0, "text"))
      assert_nil vault.get("OLD_KEY")
    end
  end

  def test_delete_secret_missing_key_returns_error
    with_vault_session do
      response = send_request("tools/call", { "name" => "delete_secret", "arguments" => { "key" => "NOPE" } })
      assert response.dig("result", "isError")
      assert_match(/not found/, response.dig("result", "content", 0, "text"))
    end
  end

  def test_delete_secret_missing_key_argument_returns_tool_error
    with_vault_session do
      response = send_request("tools/call", { "name" => "delete_secret", "arguments" => {} })

      assert response.dig("result", "isError")
      assert_match(/Missing required argument 'key'/, response.dig("result", "content", 0, "text"))
    end
  end

  # --- multi-vault: named vault via argument ---

  def test_get_secret_from_explicit_vault_via_keychain
    vault_a = create_test_vault("teamA")
    vault_b = create_test_vault("teamB")
    vault_a.set("SECRET", "a_value")
    vault_b.set("SECRET", "b_value")

    master_b = LocalVault::Crypto.derive_master_key(test_passphrase, LocalVault::Store.new("teamB").salt)

    # Default session = teamA
    LocalVault::Config.default_vault = "teamA"
    ENV["LOCALVAULT_SESSION"] = session_token_for("teamA")

    # Stub Keychain: only return master_b for "teamB"
    stub_keychain(->(name) { name == "teamB" ? master_b : nil }) do
      require "localvault/mcp/server"
      server = LocalVault::MCP::Server.new(input: StringIO.new, output: StringIO.new)

      response_a = server_call(server, "tools/call", { "name" => "get_secret", "arguments" => { "key" => "SECRET" } })
      assert_equal "a_value", response_a.dig("result", "content", 0, "text")

      response_b = server_call(server, "tools/call", { "name" => "get_secret", "arguments" => { "key" => "SECRET", "vault" => "teamB" } })
      assert_equal "b_value", response_b.dig("result", "content", 0, "text")
    end
  end

  def test_named_vault_not_unlocked_returns_helpful_error
    with_vault_session do
      stub_keychain(->(_) { nil }) do
        response = send_request("tools/call", {
          "name" => "get_secret",
          "arguments" => { "key" => "X", "vault" => "other_team" }
        })
        assert response.dig("result", "isError")
        assert_match(/other_team/, response.dig("result", "content", 0, "text"))
      end
    end
  end

  # --- JSON-RPC errors ---

  def test_unknown_tool_returns_invalid_params
    with_vault_session do
      response = send_request("tools/call", { "name" => "bogus_tool", "arguments" => {} })
      assert_equal(-32602, response.dig("error", "code"))
      assert_match(/Unknown tool/, response.dig("error", "message"))
    end
  end

  def test_unknown_method_returns_method_not_found
    with_vault_session do
      response = send_request("bogus/method", {})
      assert_equal(-32601, response.dig("error", "code"))
      assert_match(/Method not found/, response.dig("error", "message"))
    end
  end

  def test_invalid_json_returns_parse_error
    with_vault_session do
      server = build_server("not valid json\n")
      output = StringIO.new
      server.instance_variable_set(:@output, output)
      server.start
      response = JSON.parse(output.string.strip)
      assert_equal(-32700, response.dig("error", "code"))
    end
  end

  # --- missing session ---

  def test_missing_session_returns_helpful_error
    stub_keychain(->(_) { nil }) do
      response = send_request("tools/call", { "name" => "get_secret", "arguments" => { "key" => "X" } })
      assert response.dig("result", "isError")
      assert_match(/localvault show/, response.dig("result", "content", 0, "text"))
    end
  end

  # --- tools/call localvault_whoami ---

  def test_whoami_reports_active_session_and_unlocked_vaults
    create_test_vault("devops")
    create_test_vault("intellectaco")
    LocalVault::Config.default_vault = "devops"
    ENV["LOCALVAULT_SESSION"] = session_token_for("intellectaco")

    master_default = LocalVault::Crypto.derive_master_key(test_passphrase, LocalVault::Store.new("devops").salt)

    stub_keychain(->(name) { name == "devops" ? master_default : nil }) do
      response = send_request("tools/call", { "name" => "localvault_whoami", "arguments" => {} })
      structured = response.dig("result", "structuredContent")
      text = response.dig("result", "content", 0, "text")

      assert_equal "devops", structured["active_vault"]
      assert_equal "config", structured["active_vault_source"]
      assert_equal "intellectaco", structured["session_vault"]
      assert_includes structured["unlocked_vaults"], "devops"
      assert_includes structured["unlocked_vaults"], "intellectaco"
      assert_match(/Active vault: devops/, text)
    end
  end

  private

  def create_test_vault(name, passphrase = test_passphrase)
    salt = LocalVault::Crypto.generate_salt
    master_key = LocalVault::Crypto.derive_master_key(passphrase, salt)
    LocalVault::Vault.create!(name: name, master_key: master_key, salt: salt)
  end

  def session_token_for(vault_name, passphrase = test_passphrase)
    store = LocalVault::Store.new(vault_name)
    master_key = LocalVault::Crypto.derive_master_key(passphrase, store.salt)
    Base64.strict_encode64("#{vault_name}:#{Base64.strict_encode64(master_key)}")
  end

  def with_vault_session(name = "default", passphrase = test_passphrase)
    vault = create_test_vault(name, passphrase)
    token = session_token_for(name, passphrase)
    ENV["LOCALVAULT_SESSION"] = token
    yield vault if block_given?
  ensure
    ENV.delete("LOCALVAULT_SESSION")
  end

  def build_server(input_string)
    require "localvault/mcp/server"
    input = StringIO.new(input_string)
    output = StringIO.new
    LocalVault::MCP::Server.new(input: input, output: output)
  end

  def server_call(server, method, params, id: 1)
    message = JSON.generate({ "jsonrpc" => "2.0", "id" => id, "method" => method, "params" => params })
    server.handle_message(message)
  end

  # Temporarily replaces SessionCache.get with a callable for the duration of the block.
  def stub_keychain(callable)
    original = LocalVault::SessionCache.method(:get)
    LocalVault::SessionCache.define_singleton_method(:get) { |name| callable.call(name) }
    yield
  ensure
    LocalVault::SessionCache.define_singleton_method(:get, original)
  end

  def send_request(method, params, id: 1)
    require "localvault/mcp/server"
    message = JSON.generate({ "jsonrpc" => "2.0", "id" => id, "method" => method, "params" => params })
    input = StringIO.new(message + "\n")
    output = StringIO.new
    server = LocalVault::MCP::Server.new(input: input, output: output)
    server.start
    JSON.parse(output.string.strip)
  end
end
