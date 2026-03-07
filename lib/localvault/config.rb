require "yaml"
require "fileutils"

module LocalVault
  module Config
    CONFIG_FILE = "config.yml"

    def self.root_path
      ENV.fetch("LOCALVAULT_HOME") { File.join(Dir.home, ".localvault") }
    end

    def self.config_path
      File.join(root_path, CONFIG_FILE)
    end

    def self.vaults_path
      File.join(root_path, "vaults")
    end

    def self.keys_path
      File.join(root_path, "keys")
    end

    def self.load
      return {} unless File.exist?(config_path)
      YAML.safe_load_file(config_path, permitted_classes: [Symbol]) || {}
    end

    def self.save(data)
      FileUtils.mkdir_p(root_path)
      File.write(config_path, YAML.dump(data))
    end

    def self.default_vault
      load.fetch("default_vault", "default")
    end

    def self.default_vault=(name)
      data = load
      data["default_vault"] = name
      save(data)
    end

    def self.ensure_directories!
      FileUtils.mkdir_p(root_path)
      FileUtils.mkdir_p(vaults_path)
      FileUtils.mkdir_p(keys_path)
    end

    def self.token
      load["token"]
    end

    def self.token=(t)
      data = load
      data["token"] = t
      save(data)
    end

    def self.inventlist_handle
      load["inventlist_handle"]
    end

    def self.inventlist_handle=(h)
      data = load
      data["inventlist_handle"] = h
      save(data)
    end

    def self.api_url
      load.fetch("api_url", "https://inventlist.com")
    end

    def self.api_url=(url)
      data = load
      data["api_url"] = url
      save(data)
    end
  end
end
