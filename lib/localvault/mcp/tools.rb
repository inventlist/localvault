require "json"

module LocalVault
  module MCP
    module Tools
      VAULT_PARAM = {
        "vault" => {
          "type" => "string",
          "description" => "Vault name to use (uses default vault if omitted)"
        }
      }.freeze

      # MCP tool definitions conforming to the MCP tools/list schema.
      # Each entry specifies a tool name, description, and JSON Schema for input.
      DEFINITIONS = [
        {
          "name" => "get_secret",
          "description" => "Retrieve a secret value by key from a localvault vault",
          "inputSchema" => {
            "type" => "object",
            "properties" => {
              "key"   => { "type" => "string", "description" => "The secret key to retrieve" },
              **VAULT_PARAM
            },
            "required" => ["key"]
          }
        },
        {
          "name" => "list_secrets",
          "description" => "List all secret keys in a localvault vault",
          "inputSchema" => {
            "type" => "object",
            "properties" => { **VAULT_PARAM },
            "required" => []
          }
        },
        {
          "name" => "set_secret",
          "description" => "Store a secret key-value pair in a localvault vault. Use dot-notation (project.KEY) for namespaced secrets.",
          "inputSchema" => {
            "type" => "object",
            "properties" => {
              "key"   => { "type" => "string", "description" => "The secret key (supports dot-notation: project.KEY)" },
              "value" => { "type" => "string", "description" => "The secret value" },
              **VAULT_PARAM
            },
            "required" => ["key", "value"]
          }
        },
        {
          "name" => "delete_secret",
          "description" => "Delete a secret by key from a localvault vault",
          "inputSchema" => {
            "type" => "object",
            "properties" => {
              "key"   => { "type" => "string", "description" => "The secret key to delete" },
              **VAULT_PARAM
            },
            "required" => ["key"]
          }
        }
      ].freeze

      # Dispatch an MCP tool call by name.
      #
      # Resolves the target vault via the provided callable, then executes the
      # requested tool (get_secret, list_secrets, set_secret, or delete_secret).
      #
      # @param name [String] tool name (must match a DEFINITIONS entry)
      # @param arguments [Hash] tool arguments (e.g. {"key" => "API_KEY", "vault" => "prod"})
      # @param vault_resolver [#call] callable that accepts a vault name (String or nil)
      #   and returns a Vault instance or nil
      # @return [Hash] MCP content result with "content" array and optional "isError"
      # @raise [ArgumentError] if the tool name is unknown
      def self.call(name, arguments, vault_resolver)
        unless DEFINITIONS.any? { |t| t["name"] == name }
          raise ArgumentError, "Unknown tool: #{name}"
        end

        vault_name = arguments["vault"]
        vault = vault_resolver.call(vault_name)

        unless vault
          hint = vault_name ? "localvault show -v #{vault_name}" : "localvault show"
          return error_result("No unlocked vault session. Run: #{hint}")
        end

        case name
        when "get_secret"    then get_secret(arguments["key"], vault)
        when "list_secrets"  then list_secrets(vault)
        when "set_secret"    then set_secret(arguments["key"], arguments["value"], vault)
        when "delete_secret" then delete_secret(arguments["key"], vault)
        end
      end

      def self.get_secret(key, vault)
        value = vault.get(key)
        value.nil? ? error_result("Key '#{key}' not found") : text_result(value)
      end

      def self.list_secrets(vault)
        keys = vault.list
        keys.empty? ? text_result("No secrets stored") : text_result(keys.join("\n"))
      end

      def self.set_secret(key, value, vault)
        vault.set(key, value)
        text_result("Stored #{key}")
      rescue Vault::InvalidKeyName => e
        error_result("Invalid key name: #{e.message}")
      end

      def self.delete_secret(key, vault)
        deleted = vault.delete(key)
        deleted.nil? ? error_result("Key '#{key}' not found") : text_result("Deleted #{key}")
      end

      def self.text_result(text)
        { "content" => [{ "type" => "text", "text" => text }] }
      end

      def self.error_result(text)
        { "content" => [{ "type" => "text", "text" => text }], "isError" => true }
      end

      private_class_method :get_secret, :list_secrets, :set_secret, :delete_secret, :text_result, :error_result
    end
  end
end
