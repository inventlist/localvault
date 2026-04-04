require "yaml"
require "fileutils"

module LocalVault
  # Global configuration — paths, default vault, API credentials.
  #
  # Reads/writes +~/.localvault/config.yml+ (mode 0600).
  # All directories are created with mode 0700.
  # Override the root path with +LOCALVAULT_HOME+ env var.
  #
  # @example
  #   Config.root_path        # => "~/.localvault"
  #   Config.default_vault    # => "default"
  #   Config.token = "tok-..."
  #   Config.inventlist_handle = "nauman"
  module Config
    CONFIG_FILE = "config.yml"

    # Root directory for all LocalVault data. Honors +LOCALVAULT_HOME+ env var.
    #
    # @return [String] absolute path, defaults to +~/.localvault+
    def self.root_path
      ENV.fetch("LOCALVAULT_HOME") { File.join(Dir.home, ".localvault") }
    end

    # Path to the global config file.
    #
    # @return [String] absolute path to +config.yml+
    def self.config_path
      File.join(root_path, CONFIG_FILE)
    end

    # Path to the directory containing all vaults.
    #
    # @return [String] absolute path to +vaults/+ directory
    def self.vaults_path
      File.join(root_path, "vaults")
    end

    # Path to the directory containing identity keys.
    #
    # @return [String] absolute path to +keys/+ directory
    def self.keys_path
      File.join(root_path, "keys")
    end

    # Load the config file as a hash.
    #
    # @return [Hash] parsed config, or empty hash if file is missing
    def self.load
      return {} unless File.exist?(config_path)
      YAML.safe_load_file(config_path, permitted_classes: [Symbol]) || {}
    end

    # Write config data to disk (mode 0600).
    #
    # @param data [Hash] the config hash to persist
    # @return [void]
    def self.save(data)
      FileUtils.mkdir_p(root_path, mode: 0o700)
      File.write(config_path, YAML.dump(data))
      File.chmod(0o600, config_path)
    end

    # Name of the default vault.
    #
    # @return [String] vault name, defaults to "default"
    def self.default_vault
      load.fetch("default_vault", "default")
    end

    # Set the default vault name.
    #
    # @param name [String] the vault name to use as default
    # @return [void]
    def self.default_vault=(name)
      data = load
      data["default_vault"] = name
      save(data)
    end

    # Create the root, vaults, and keys directories if they don't exist (mode 0700).
    #
    # @return [void]
    def self.ensure_directories!
      FileUtils.mkdir_p(root_path, mode: 0o700)
      FileUtils.mkdir_p(vaults_path, mode: 0o700)
      FileUtils.mkdir_p(keys_path, mode: 0o700)
    end

    # Read the API authentication token.
    #
    # @return [String, nil] the stored token, or nil
    def self.token
      load["token"]
    end

    # Set the API authentication token.
    #
    # @param t [String] the token to store
    # @return [void]
    def self.token=(t)
      data = load
      data["token"] = t
      save(data)
    end

    # Read the InventList user handle.
    #
    # @return [String, nil] the stored handle, or nil
    def self.inventlist_handle
      load["inventlist_handle"]
    end

    # Set the InventList user handle.
    #
    # @param h [String] the handle to store
    # @return [void]
    def self.inventlist_handle=(h)
      data = load
      data["inventlist_handle"] = h
      save(data)
    end

    # Read the InventList API base URL.
    #
    # @return [String] the API URL, defaults to "https://inventlist.com"
    def self.api_url
      load.fetch("api_url", "https://inventlist.com")
    end

    # Set the InventList API base URL.
    #
    # @param url [String] the API URL to store
    # @return [void]
    def self.api_url=(url)
      data = load
      data["api_url"] = url
      save(data)
    end
  end
end
