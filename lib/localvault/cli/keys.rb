require "thor"

module LocalVault
  class CLI
    class Keys < Thor
      desc "generate", "Generate an X25519 keypair for vault sharing"
      method_option :force, type: :boolean, default: false, desc: "Overwrite existing keypair"
      # Generate a new X25519 keypair for vault sharing.
      #
      # Creates a private/public key pair in the LocalVault config directory.
      # Refuses to overwrite an existing keypair unless +--force+ is passed.
      # After generating, run +localvault keys publish+ to upload the public key.
      def generate
        if Identity.exists? && !options[:force]
          $stdout.puts "Keypair already exists at #{Config.keys_path}"
          $stdout.puts "Use --force to overwrite."
          return
        end

        Config.ensure_directories!
        Identity.generate!(force: options[:force])
        $stdout.puts "Keypair generated:"
        $stdout.puts "  Private: #{Identity.priv_key_path}"
        $stdout.puts "  Public:  #{Identity.pub_key_path}"
        $stdout.puts
        $stdout.puts "Run 'localvault keys publish' to upload your public key to InventList."
      rescue RuntimeError => e
        $stderr.puts "Error: #{e.message}"
      end

      desc "publish", "Upload your public key to InventList"
      # Publish your X25519 public key to InventList.
      #
      # Requires a keypair (run +localvault keys generate+ first) and an active
      # connection (run +localvault connect+ first). Once published, other users
      # can share vaults with you.
      def publish
        unless Identity.exists?
          $stderr.puts "Error: No keypair found. Run: localvault keys generate"
          return
        end

        unless Config.token
          $stderr.puts "Error: Not connected. Run: localvault connect --token TOKEN --handle HANDLE"
          return
        end

        client = ApiClient.new(token: Config.token)
        client.publish_public_key(Identity.public_key)
        $stdout.puts "Public key published to InventList (@#{Config.inventlist_handle})."
        $stdout.puts "Others can now share vaults with you."
      rescue ApiClient::ApiError => e
        $stderr.puts "Error: #{e.message}"
      end

      desc "show", "Display your public key"
      # Print your base64-encoded X25519 public key to stdout.
      #
      # Useful for manual key exchange or verification. Requires a keypair
      # to exist (run +localvault keys generate+ first).
      def show
        unless Identity.exists?
          $stderr.puts "Error: No keypair found. Run: localvault keys generate"
          return
        end
        $stdout.puts Identity.public_key
      end
    end
  end
end
