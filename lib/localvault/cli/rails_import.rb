module LocalVault
  class CLI
    # Finds a Rails app's credentials keys so they can be stored in the vault
    # and injected as RAILS_MASTER_KEY instead of living in a file.
    #
    # Reads only. Removing the key files is the operator's call — this reports
    # what is still on disk and leaves it alone.
    class RailsImport
      Key = Struct.new(:environment, :path, :vault_key, :value, keyword_init: true)

      MASTER_KEY_PATH = "config/master.key".freeze
      CREDENTIALS_PATH = "config/credentials.yml.enc".freeze

      def initialize(root = Dir.pwd)
        @root = root
      end

      def rails_app?
        File.exist?(File.join(@root, CREDENTIALS_PATH)) ||
          File.exist?(File.join(@root, MASTER_KEY_PATH)) ||
          Dir.exist?(File.join(@root, "config/credentials"))
      end

      # Every key file this app has: the default master key plus one per
      # environment (config/credentials/production.key).
      def keys
        [master_key, *environment_keys].compact
      end

      private

      def master_key
        path = File.join(@root, MASTER_KEY_PATH)
        return nil unless File.exist?(path)

        value = File.read(path).strip
        return nil if value.empty?

        Key.new(environment: nil, path: MASTER_KEY_PATH, vault_key: "rails.master_key", value: value)
      end

      def environment_keys
        Dir.glob(File.join(@root, "config/credentials/*.key")).sort.filter_map do |path|
          environment = File.basename(path, ".key")
          value = File.read(path).strip
          next if value.empty?

          Key.new(
            environment: environment,
            path: "config/credentials/#{environment}.key",
            vault_key: "rails.#{environment}_key",
            value: value
          )
        end
      end
    end
  end
end
