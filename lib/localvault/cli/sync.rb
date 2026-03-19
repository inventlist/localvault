require "thor"
require "fileutils"

module LocalVault
  class CLI
    class Sync < Thor
      desc "push [NAME]", "Push a vault to InventList cloud sync"
      def push(vault_name = nil)
        return unless logged_in?

        vault_name ||= Config.default_vault
        store = Store.new(vault_name)

        unless store.exists?
          $stderr.puts "Error: Vault '#{vault_name}' does not exist. Run: localvault init #{vault_name}"
          return
        end

        blob   = SyncBundle.pack(store)
        client = ApiClient.new(token: Config.token)
        client.push_vault(vault_name, blob)

        $stdout.puts "Synced vault '#{vault_name}' (#{blob.bytesize} bytes)"
      rescue ApiClient::ApiError => e
        $stderr.puts "Error: #{e.message}"
      end

      desc "pull [NAME]", "Pull a vault from InventList cloud sync"
      method_option :force, type: :boolean, default: false, desc: "Overwrite existing local vault"
      def pull(vault_name = nil)
        return unless logged_in?

        vault_name ||= Config.default_vault
        store  = Store.new(vault_name)

        if store.exists? && !options[:force]
          $stderr.puts "Error: Vault '#{vault_name}' already exists locally. Use --force to overwrite."
          return
        end

        client = ApiClient.new(token: Config.token)
        blob   = client.pull_vault(vault_name)
        data   = SyncBundle.unpack(blob, expected_name: vault_name)

        FileUtils.mkdir_p(store.vault_path, mode: 0o700)
        File.write(store.meta_path, data[:meta])
        File.chmod(0o600, store.meta_path)
        if data[:secrets].empty?
          FileUtils.rm_f(store.secrets_path)
        else
          store.write_encrypted(data[:secrets])
        end

        $stdout.puts "Pulled vault '#{vault_name}'."
        $stdout.puts "Unlock it with: localvault unlock -v #{vault_name}"
      rescue SyncBundle::UnpackError => e
        $stderr.puts "Error: #{e.message}"
      rescue ApiClient::ApiError => e
        if e.status == 404
          $stderr.puts "Error: Vault '#{vault_name}' not found in cloud."
        else
          $stderr.puts "Error: #{e.message}"
        end
      end

      desc "status", "Show sync status for all vaults"
      def status
        return unless logged_in?

        client    = ApiClient.new(token: Config.token)
        result    = client.list_vaults
        remote    = (result["vaults"] || []).each_with_object({}) { |v, h| h[v["name"]] = v }
        local_set = Store.list_vaults.to_set
        all_names = (remote.keys + local_set.to_a).uniq.sort

        if all_names.empty?
          $stdout.puts "No vaults found locally or in cloud."
          return
        end

        rows = all_names.map do |name|
          r         = remote[name]
          l_exists  = local_set.include?(name)
          row_status = if r && l_exists then "synced"
                       elsif r          then "remote only"
                       else                  "local only"
                       end
          synced_at = r ? (r["synced_at"]&.slice(0, 10) || "—") : "—"
          [name, row_status, synced_at]
        end

        max_name   = (["Vault"] + rows.map { |r| r[0] }).map(&:length).max
        max_status = (["Status"] + rows.map { |r| r[1] }).map(&:length).max

        $stdout.puts "#{"Vault".ljust(max_name)}  #{"Status".ljust(max_status)}  Synced At"
        $stdout.puts "#{"─" * max_name}  #{"─" * max_status}  ─────────"
        rows.each do |name, row_status, synced_at|
          $stdout.puts "#{name.ljust(max_name)}  #{row_status.ljust(max_status)}  #{synced_at}"
        end
      rescue ApiClient::ApiError => e
        $stderr.puts "Error: #{e.message}"
      end

      def self.exit_on_failure?
        true
      end

      private

      def logged_in?
        return true if Config.token

        $stderr.puts "Error: Not logged in. Run: localvault login TOKEN"
        false
      end
    end
  end
end
