require "json"
require "base64"
require_relative "../version"
require_relative "../crypto"
require_relative "../config"
require_relative "../store"
require_relative "../vault"
require_relative "../session_cache"
require_relative "tools"

module LocalVault
  module MCP
    class Server
      def initialize(input: $stdin, output: $stdout)
        @input        = input
        @output       = output
        @vault_cache  = {}  # name => Vault — lazily populated per-call
        @session_vault = load_session_vault  # LOCALVAULT_SESSION fast-path
      end

      def start
        unlocked = unlocked_vault_names
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

        $stderr.puts "[localvault-mcp] stopped"
        $stderr.flush
      end

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

          result = Tools.call(tool_name, arguments, method(:vault_for))
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
        # No specific vault requested: session vault takes priority over default
        if name.nil? && @session_vault
          @vault_cache[@session_vault.name] ||= @session_vault
          return @session_vault
        end

        vault_name = name || default_vault_name

        return @vault_cache[vault_name] if @vault_cache.key?(vault_name)

        # Fast-path: LOCALVAULT_SESSION matches by name
        if @session_vault && @session_vault.name == vault_name
          @vault_cache[vault_name] = @session_vault
          return @session_vault
        end

        # Keychain lookup
        if (master_key = SessionCache.get(vault_name))
          vault = Vault.new(name: vault_name, master_key: master_key)
          vault.all  # verify decryption
          @vault_cache[vault_name] = vault
          return vault
        end

        nil
      rescue Crypto::DecryptionError
        nil
      end

      def default_vault_name
        ENV["LOCALVAULT_VAULT"] || Config.default_vault
      end

      # Parse LOCALVAULT_SESSION on startup (single-vault legacy path).
      def load_session_vault
        token = ENV["LOCALVAULT_SESSION"]
        return nil unless token

        decoded     = Base64.strict_decode64(token)
        vault_name, key_b64 = decoded.split(":", 2)
        return nil unless vault_name && key_b64

        master_key = Base64.strict_decode64(key_b64)
        vault = Vault.new(name: vault_name, master_key: master_key)
        vault.all  # verify decryption
        vault
      rescue ArgumentError, Crypto::DecryptionError
        nil
      end

      # List vault names that are currently unlocked (for the startup log).
      def unlocked_vault_names
        names = []

        # From LOCALVAULT_SESSION
        names << @session_vault.name if @session_vault

        # From Keychain — check all known vaults
        Store.list_vaults.each do |n|
          next if names.include?(n)
          names << n if SessionCache.get(n)
        end

        names
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
