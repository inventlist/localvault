require "json"
require "base64"
require_relative "../version"
require_relative "../crypto"
require_relative "../config"
require_relative "../store"
require_relative "../vault"
require_relative "../session_cache"
require_relative "../vault_resolver"
require_relative "tools"

module LocalVault
  module MCP
    class Server
      # Create an MCP server reading JSON-RPC from input, writing responses to output.
      #
      # @param input [IO] input stream for JSON-RPC messages (default: $stdin)
      # @param output [IO] output stream for JSON-RPC responses (default: $stdout)
      def initialize(input: $stdin, output: $stdout)
        @input  = input
        @output = output
      end

      # Start the MCP server loop, reading JSON-RPC messages line-by-line.
      #
      # Logs available unlocked vaults to stderr on startup. Blocks until
      # input is exhausted or interrupted (Ctrl-C).
      #
      # @return [void]
      def start
        unlocked = VaultResolver.unlocked_vault_names
        label = unlocked.empty? ? "no unlocked vaults (run: localvault show)" : "vaults=#{unlocked.join(', ')}"
        $stderr.puts "[localvault-mcp] started  v#{LocalVault::VERSION}  #{label}"
        $stderr.flush

        @input.each_line do |line|
          line = line.strip
          next if line.empty?

          response = handle_message(line)
          if response
            @output.puts(JSON.generate(response))
            @output.flush
          end
        end
      rescue Interrupt
        # Clean shutdown on Ctrl-C
      ensure
        $stderr.puts "[localvault-mcp] stopped"
        $stderr.flush
      end

      # Parse and dispatch a single JSON-RPC message.
      #
      # Handles +initialize+, +tools/list+, and +tools/call+ methods.
      # Notifications (no "id" field) return nil.
      #
      # @param json_string [String] raw JSON-RPC message
      # @return [Hash, nil] JSON-RPC response hash, or nil for notifications
      def handle_message(json_string)
        message = JSON.parse(json_string)

        # Notifications have no id — no response
        return nil unless message.key?("id")

        id     = message["id"]
        method = message["method"]
        params = message["params"] || {}

        case method
        when "initialize"
          success_response(id, {
            "protocolVersion" => "2025-11-25",
            "capabilities"    => { "tools" => {} },
            "serverInfo"      => { "name" => "localvault", "version" => LocalVault::VERSION }
          })
        when "tools/list"
          success_response(id, { "tools" => Tools::DEFINITIONS })
        when "tools/call"
          tool_name  = params["name"]
          arguments  = params["arguments"] || {}

          unless Tools::DEFINITIONS.any? { |t| t["name"] == tool_name }
            return error_response(id, -32602, "Unknown tool: #{tool_name}")
          end

          result = Tools.call(tool_name, arguments, method(:vault_for), method(:vault_status))
          success_response(id, result)
        else
          error_response(id, -32601, "Method not found: #{method}")
        end
      rescue JSON::ParserError
        error_response(nil, -32700, "Parse error")
      end

      private

      # Resolve vault by name, lazily — tries session token, then Keychain.
      # Returns nil if vault is not unlocked.
      def vault_for(name = nil)
        VaultResolver.resolve(name).vault
      end

      def vault_status(name = nil)
        VaultResolver.status(name)
      end

      def success_response(id, result)
        { "jsonrpc" => "2.0", "id" => id, "result" => result }
      end

      def error_response(id, code, message)
        { "jsonrpc" => "2.0", "id" => id, "error" => { "code" => code, "message" => message } }
      end
    end
  end
end
