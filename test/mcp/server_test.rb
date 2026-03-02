require_relative "../test_helper"
require_relative "../../lib/localvault/cli"

class MCPServerTest < Minitest::Test
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

  def test_tools_list_returns_four_tools
    with_vault_session do
      response = send_request("tools/list", {})
      tools = response.dig("result", "tools")
      assert_equal 4, tools.size
      names = tools.map { |t| t["name"] }.sort
      assert_equal %w[delete_secret get_secret list_secrets set_secret], names
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

  # --- tools/call set_secret ---

  def test_set_secret_stores_value
    with_vault_session do |vault|
      response = send_request("tools/call", { "name" => "set_secret", "arguments" => { "key" => "NEW_KEY", "value" => "new_value" } })
      refute response.dig("result", "isError")
      assert_match(/Stored NEW_KEY/, response.dig("result", "content", 0, "text"))
      assert_equal "new_value", vault.get("NEW_KEY")
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
    # No session set
    response = send_request("tools/call", { "name" => "get_secret", "arguments" => { "key" => "X" } })
    assert response.dig("result", "isError")
    assert_match(/localvault unlock/, response.dig("result", "content", 0, "text"))
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
