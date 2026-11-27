module LocalVault
  class CLI < Thor
    # Prompts shared by every command that chooses a new passphrase or needs
    # the identity private key (plan 13). The host class supplies
    # +prompt_passphrase+.
    module IdentityPrompts
      private

      # Ask for a new passphrase twice and apply PassphrasePolicy.
      #
      # @param label [String] what the passphrase protects, used in prompts
      # @return [String, nil] the passphrase, or nil after printing why it was refused
      def choose_new_passphrase(label)
        passphrase = prompt_passphrase("New #{label} passphrase: ")
        if (problem = PassphrasePolicy.check(passphrase))
          $stderr.puts "Error: #{problem}"
          return nil
        end

        unless prompt_passphrase("Confirm #{label} passphrase: ") == passphrase
          $stderr.puts "Error: Passphrases do not match"
          return nil
        end

        passphrase
      end

      # The identity private key, unlocking it with a prompt when needed.
      #
      # @return [String, nil] raw key bytes, or nil (with a message) when there
      #   is no keypair or the passphrase is wrong or not given
      def identity_private_key
        return nil unless Identity.exists?
        return Identity.private_key_bytes unless Identity.locked?

        passphrase = prompt_passphrase("Identity passphrase: ")
        return nil if passphrase.nil? || passphrase.empty?

        Identity.unlock(passphrase)
      rescue Identity::WrongPassphrase => e
        $stderr.puts "Error: #{e.message}"
        nil
      end
    end
  end
end
