require "json"
require "base64"
require_relative "../version"
require_relative "../crypto"
require_relative "../config"
require_relative "../store"
require_relative "../vault"
require_relative "tools"

module LocalVault
  module MCP
    class Server
      def initialize(input: $stdin, output: $stdout)
        @input = input
        @output = output
        @vault = open_vault_from_session
      end

      def start
        @input.each_line do |line|
          line = line.strip
          next if line.empty?

          response = handle_message(line)
          if response
            @output.puts(JSON.generate(response))
            @output.flush
          end
        end
      end

      def handle_message(json_string)
        message = JSON.parse(json_string)

        # Notifications have no id — no response
        return nil unless message.key?("id")

        id = message["id"]
        method = message["method"]
        params = message["params"] || {}

        case method
        when "initialize"
          success_response(id, {
            "protocolVersion" => "2025-11-25",
            "capabilities" => { "tools" => {} },
            "serverInfo" => { "name" => "localvault", "version" => LocalVault::VERSION }
          })
        when "tools/list"
          success_response(id, { "tools" => Tools::DEFINITIONS })
        when "tools/call"
          tool_name = params["name"]
          arguments = params["arguments"] || {}

          unless Tools::DEFINITIONS.any? { |t| t["name"] == tool_name }
            return error_response(id, -32602, "Unknown tool: #{tool_name}")
          end

          result = Tools.call(tool_name, arguments, @vault)
          success_response(id, result)
        else
          error_response(id, -32601, "Method not found: #{method}")
        end
      rescue JSON::ParserError
        error_response(nil, -32700, "Parse error")
      end

      private

      def open_vault_from_session
        token = ENV["LOCALVAULT_SESSION"]
        return nil unless token

        decoded = Base64.strict_decode64(token)
        vault_name, key_b64 = decoded.split(":", 2)
        return nil unless vault_name && key_b64

        master_key = Base64.strict_decode64(key_b64)
        vault = Vault.new(name: vault_name, master_key: master_key)
        vault.all # Verify decryption works
        vault
      rescue ArgumentError, Crypto::DecryptionError
        nil
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
