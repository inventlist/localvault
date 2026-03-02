require "json"

module LocalVault
  module MCP
    module Tools
      DEFINITIONS = [
        {
          "name" => "get_secret",
          "description" => "Retrieve a secret value by key",
          "inputSchema" => {
            "type" => "object",
            "properties" => {
              "key" => { "type" => "string", "description" => "The secret key to retrieve" }
            },
            "required" => ["key"]
          }
        },
        {
          "name" => "list_secrets",
          "description" => "List all secret keys in the vault",
          "inputSchema" => {
            "type" => "object",
            "properties" => {},
            "required" => []
          }
        },
        {
          "name" => "set_secret",
          "description" => "Store a secret key-value pair",
          "inputSchema" => {
            "type" => "object",
            "properties" => {
              "key" => { "type" => "string", "description" => "The secret key" },
              "value" => { "type" => "string", "description" => "The secret value" }
            },
            "required" => ["key", "value"]
          }
        },
        {
          "name" => "delete_secret",
          "description" => "Delete a secret by key",
          "inputSchema" => {
            "type" => "object",
            "properties" => {
              "key" => { "type" => "string", "description" => "The secret key to delete" }
            },
            "required" => ["key"]
          }
        }
      ].freeze

      def self.call(name, arguments, vault)
        unless vault
          return error_result("No vault session. Run: eval $(localvault unlock)")
        end

        case name
        when "get_secret"
          get_secret(arguments["key"], vault)
        when "list_secrets"
          list_secrets(vault)
        when "set_secret"
          set_secret(arguments["key"], arguments["value"], vault)
        when "delete_secret"
          delete_secret(arguments["key"], vault)
        end
      end

      def self.get_secret(key, vault)
        value = vault.get(key)
        if value.nil?
          error_result("Key '#{key}' not found")
        else
          text_result(value)
        end
      end

      def self.list_secrets(vault)
        keys = vault.list
        if keys.empty?
          text_result("No secrets stored")
        else
          text_result(keys.join("\n"))
        end
      end

      def self.set_secret(key, value, vault)
        vault.set(key, value)
        text_result("Stored #{key}")
      end

      def self.delete_secret(key, vault)
        deleted = vault.delete(key)
        if deleted.nil?
          error_result("Key '#{key}' not found")
        else
          text_result("Deleted #{key}")
        end
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
