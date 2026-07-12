require "json"
require_relative "../key_lookup"
require_relative "../version"

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
            "properties" => {
              "prefix" => { "type" => "string", "description" => "Only return keys starting with this prefix" },
              "query" => { "type" => "string", "description" => "Case-insensitive substring filter for key names" },
              **VAULT_PARAM
            },
            "required" => []
          }
        },
        {
          "name" => "localvault_whoami",
          "description" => "Show which localvault home, vault, and unlocked sessions the MCP server can see",
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
      def self.call(name, arguments, vault_resolver, status_resolver = nil)
        unless DEFINITIONS.any? { |t| t["name"] == name }
          raise ArgumentError, "Unknown tool: #{name}"
        end

        return error_result("Invalid arguments; expected object") unless arguments.is_a?(Hash)

        vault_name = arguments["vault"]
        return whoami(status_resolver.call(vault_name)) if name == "localvault_whoami"

        vault = vault_resolver.call(vault_name)

        unless vault
          hint = vault_name ? "localvault show -v #{vault_name}" : "localvault show"
          return error_result("No unlocked vault session. Run: #{hint}")
        end

        case name
        when "get_secret"    then get_secret(arguments["key"], vault)
        when "list_secrets"  then list_secrets(vault, prefix: arguments["prefix"], query: arguments["query"])
        when "set_secret"    then set_secret(arguments["key"], arguments["value"], vault)
        when "delete_secret" then delete_secret(arguments["key"], vault)
        end
      rescue StandardError => e
        error_result(e.message)
      end

      def self.get_secret(key, vault)
        return required_argument_error("key") unless present_string?(key)

        lookup = KeyLookup.lookup(vault, key)
        return text_result(lookup.value) if lookup.exact?

        if lookup.multiple_matches?
          return error_result(candidate_message("Multiple keys match '#{key}'. Be more specific:", lookup.matches))
        end

        if lookup.single_match?
          return error_result(candidate_message("Key '#{key}' not found. Did you mean:", lookup.matches))
        end

        error_result("Key '#{key}' not found")
      end

      def self.list_secrets(vault, prefix: nil, query: nil)
        return string_argument_error("prefix") unless optional_string?(prefix)
        return string_argument_error("query") unless optional_string?(query)

        keys = vault.list
        keys = keys.select { |key| key.start_with?(prefix) } if prefix && !prefix.empty?
        keys = keys.select { |key| key.downcase.include?(query.downcase) } if query && !query.empty?
        keys.empty? ? text_result("No secrets stored") : text_result(keys.join("\n"))
      end

      def self.set_secret(key, value, vault)
        return required_argument_error("key") unless present_string?(key)
        return required_argument_error("value") unless value.is_a?(String)

        vault.set(key, value)
        text_result("Stored #{key}")
      rescue Vault::InvalidKeyName, RuntimeError => e
        error_result(e.message)
      end

      def self.delete_secret(key, vault)
        return required_argument_error("key") unless present_string?(key)

        deleted = vault.delete(key)
        deleted.nil? ? error_result("Key '#{key}' not found") : text_result("Deleted #{key}")
      end

      def self.text_result(text)
        { "content" => [{ "type" => "text", "text" => text }] }
      end

      def self.error_result(text)
        { "content" => [{ "type" => "text", "text" => text }], "isError" => true }
      end

      def self.whoami(status)
        structured = status.merge("version" => LocalVault::VERSION)
        text = [
          "LocalVault #{LocalVault::VERSION}",
          "Home: #{structured["localvault_home"]}",
          "Active vault: #{structured["active_vault"]} (#{structured["active_vault_source"]})",
          "Active vault unlocked: #{structured["active_vault_unlocked"] ? "yes" : "no"}",
          "Session vault: #{structured["session_vault"] || "-"}",
          "Unlocked vaults: #{structured["unlocked_vaults"].empty? ? "-" : structured["unlocked_vaults"].join(", ")}"
        ].join("\n")

        text_result(text).merge("structuredContent" => structured)
      end

      def self.candidate_message(header, matches)
        ([header] + matches.map { |match| "  #{match}" }).join("\n")
      end

      def self.present_string?(value)
        value.is_a?(String) && !value.empty?
      end

      def self.optional_string?(value)
        value.nil? || value.is_a?(String)
      end

      def self.required_argument_error(name)
        error_result("Missing required argument '#{name}'")
      end

      def self.string_argument_error(name)
        error_result("Argument '#{name}' must be a string")
      end

      private_class_method :get_secret, :list_secrets, :set_secret, :delete_secret,
        :text_result, :error_result, :whoami, :candidate_message,
        :present_string?, :optional_string?, :required_argument_error, :string_argument_error
    end
  end
end
