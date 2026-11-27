require "thor"
require "io/console"
require_relative "identity_prompts"

module LocalVault
  class CLI
    class Keys < Thor
      include IdentityPrompts

      desc "generate", "Generate a passphrase-protected X25519 keypair for vault sharing"
      method_option :force, type: :boolean, default: false, desc: "Overwrite existing keypair"
      # Generate a new X25519 keypair for vault sharing.
      #
      # The private key is encrypted with an identity passphrase (Argon2id +
      # XSalsa20-Poly1305) before it touches disk. Refuses to overwrite an
      # existing keypair unless +--force+ is passed.
      def generate
        if Identity.exists? && !options[:force]
          $stdout.puts "Keypair already exists at #{Config.keys_path}"
          $stdout.puts "Use --force to overwrite."
          return
        end

        passphrase = choose_new_passphrase("identity")
        return unless passphrase

        Config.ensure_directories!
        Identity.generate!(force: options[:force], passphrase: passphrase)
        $stdout.puts "Keypair generated (private key passphrase-protected):"
        $stdout.puts "  Private: #{Identity.priv_key_path}"
        $stdout.puts "  Public:  #{Identity.pub_key_path}"
        $stdout.puts
        $stdout.puts "Run 'localvault keys publish' to upload your public key to InventList."
      rescue RuntimeError => e
        $stderr.puts "Error: #{e.message}"
      end

      desc "protect", "Encrypt your identity private key with a passphrase (or change it)"
      # Upgrade a legacy plaintext identity key to a passphrase-protected one,
      # or change the passphrase of an already protected key. The keypair
      # itself does not change, so published public keys and key slots stay valid.
      def protect
        unless Identity.exists?
          $stderr.puts "Error: No keypair found. Run: localvault keys generate"
          return
        end

        current = nil
        if Identity.protected?
          current = prompt_passphrase("Current identity passphrase: ")
        end

        passphrase = choose_new_passphrase("identity")
        return unless passphrase

        was_legacy = current.nil?
        Identity.protect!(new_passphrase: passphrase, current_passphrase: current)
        $stdout.puts(was_legacy ? "Identity key is now passphrase-protected." : "Identity passphrase changed. Key stays protected.")
      rescue Identity::WrongPassphrase => e
        $stderr.puts "Error: #{e.message}"
      end

      desc "unlock", "Unlock your identity key for this session"
      # Decrypt the identity key once and cache it (Keychain on macOS) for the
      # session TTL, so sync and receive don't prompt again.
      def unlock
        unless Identity.protected?
          $stderr.puts(Identity.exists? ? "Identity key is not passphrase-protected. Run: localvault keys protect" : "Error: No keypair found. Run: localvault keys generate")
          return
        end

        Identity.unlock(prompt_passphrase("Identity passphrase: "))
        $stdout.puts "Identity key unlocked for #{Config.session_ttl_hours}h. Run 'localvault lock' to forget it sooner."
      rescue Identity::WrongPassphrase
        $stderr.puts "Error: Wrong identity passphrase"
      end

      desc "status", "Show whether your identity key is protected (never prints key material)"
      def status
        state = if !Identity.exists? then "missing — run: localvault keys generate"
                elsif Identity.legacy? then "legacy (unprotected) — run: localvault keys protect"
                elsif Identity.locked? then "protected, locked"
                else "protected, unlocked this session"
                end
        $stdout.puts "Identity key: #{state}"
      end

      desc "publish", "Upload your public key to InventList"
      # Publish your X25519 public key to InventList.
      #
      # Requires a keypair (run +localvault keys generate+ first) and an active
      # login session (run +localvault login+ first). Once published, other users
      # can share vaults with you.
      def publish
        unless Identity.exists?
          $stderr.puts "Error: No keypair found. Run: localvault keys generate"
          return
        end

        unless Config.token
          $stderr.puts "Error: Not logged in. Run: localvault login"
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
      def show
        unless Identity.exists?
          $stderr.puts "Error: No keypair found. Run: localvault keys generate"
          return
        end
        $stdout.puts Identity.public_key
      end

      private

      def prompt_passphrase(msg = "Passphrase: ")
        IO.console&.getpass(msg) || $stdin.gets&.chomp || ""
      rescue Interrupt
        $stderr.puts
        ""
      end
    end
  end
end
