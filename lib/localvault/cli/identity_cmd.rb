require "thor"

module LocalVault
  class CLI
    class IdentityCommand < Thor
      ALIAS_PATTERN = /\A[a-zA-Z0-9][a-zA-Z0-9_-]{0,31}\z/

      desc "show", "Show your identity — alias, InventList handle, public key"
      # Print the local identity summary: the configured alias, the
      # InventList handle (if logged in), and the sync public key (if any).
      def show
        $stdout.puts "Alias:      #{Config.identity_alias || "-"}"
        $stdout.puts "Handle:     #{Config.inventlist_handle ? "@#{Config.inventlist_handle}" : "-"}"
        $stdout.puts "Public key: #{Identity.exists? ? Identity.public_key : "- (run: localvault keygen)"}"
      end
      default_task :show

      desc "set FIELD VALUE", "Set an identity field (currently: alias)"
      long_desc <<~DESC
        Set a local identity field.

        SET YOUR ALIAS (a local display name, independent of InventList login):
        \x05    localvault identity set alias nauman

        The alias is stored in ~/.localvault/config.yml and never leaves
        your machine.
      DESC
      # Set an identity field. Only +alias+ is supported today.
      def set(field, value)
        unless field == "alias"
          $stderr.puts "Error: Unknown field '#{field}'. Supported: alias"
          exit 1
        end
        unless value.match?(ALIAS_PATTERN)
          $stderr.puts "Error: Alias must be 1-32 characters: letters, digits, '-' or '_', starting with a letter or digit."
          exit 1
        end
        Config.identity_alias = value
        $stdout.puts "Alias set to '#{value}'."
      end

      desc "unset FIELD", "Clear an identity field (currently: alias)"
      # Clear an identity field. Only +alias+ is supported today.
      def unset(field)
        unless field == "alias"
          $stderr.puts "Error: Unknown field '#{field}'. Supported: alias"
          exit 1
        end
        previous = Config.identity_alias
        Config.identity_alias = nil
        $stdout.puts(previous ? "Alias '#{previous}' cleared." : "No alias set.")
      end
    end
  end
end
