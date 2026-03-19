require_relative "test_helper"
require "net/http"

# Audit round 6 — timeout exceptions must be wrapped as ApiError.
class AuditRound6Test < Minitest::Test
  def test_request_wraps_open_timeout
    client = LocalVault::ApiClient.new(token: "tok", base_url: "https://example.com")
    Net::HTTP.stub(:new, ->(*_) { raise Net::OpenTimeout, "timed out" }) do
      err = assert_raises(LocalVault::ApiClient::ApiError) { client.me }
      assert_match(/timed out/i, err.message)
    end
  end

  def test_request_wraps_read_timeout
    client = LocalVault::ApiClient.new(token: "tok", base_url: "https://example.com")
    Net::HTTP.stub(:new, ->(*_) { raise Net::ReadTimeout, "read timed out" }) do
      err = assert_raises(LocalVault::ApiClient::ApiError) { client.me }
      assert_match(/timed out/i, err.message)
    end
  end

  def test_request_binary_wraps_write_timeout
    client = LocalVault::ApiClient.new(token: "tok", base_url: "https://example.com")
    Net::HTTP.stub(:new, ->(*_) { raise Net::WriteTimeout, "write timed out" }) do
      err = assert_raises(LocalVault::ApiClient::ApiError) { client.push_vault("test", "blob") }
      assert_match(/timed out/i, err.message)
    end
  end

  def test_request_raw_wraps_read_timeout
    client = LocalVault::ApiClient.new(token: "tok", base_url: "https://example.com")
    Net::HTTP.stub(:new, ->(*_) { raise Net::ReadTimeout, "read timed out" }) do
      err = assert_raises(LocalVault::ApiClient::ApiError) { client.pull_vault("test") }
      assert_match(/timed out/i, err.message)
    end
  end

  # ── MCP server handles Ctrl-C gracefully ──

  def test_mcp_server_handles_interrupt_gracefully
    require "localvault/mcp/server"

    # Create an input that raises Interrupt when read
    interrupt_input = Object.new
    interrupt_input.define_singleton_method(:each_line) { raise Interrupt }
    output = StringIO.new

    server = LocalVault::MCP::Server.new(input: interrupt_input, output: output)

    # Should NOT raise Interrupt — should exit cleanly
    _, err = capture_io { server.start }
    assert_match(/stopped/, err)
  end
end
