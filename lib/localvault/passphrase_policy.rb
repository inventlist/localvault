module LocalVault
  # The floor every NEW passphrase must clear: vault passphrases (init, rekey,
  # reset, receive, team rotate) and the identity passphrase.
  #
  # Argon2id makes each guess expensive, but it cannot rescue a passphrase an
  # attacker guesses in the first few thousand tries. Opening an existing vault
  # is never checked here, so older vaults keep working.
  module PassphrasePolicy
    MIN_LENGTH = 12

    COMMON = %w[
      password passwordpassword password1234 passphrase localvault
      123456789012 1234567890123 qwertyuiopas qwertyqwerty iloveyouiloveyou
      letmeinletmein changemechangeme adminadminadmin secretsecret
    ].freeze

    # @param passphrase [String, nil]
    # @return [String, nil] a human-readable reason it is refused, or nil when it is acceptable
    def self.check(passphrase)
      value = passphrase.to_s
      return "Passphrase cannot be empty" if value.empty?
      return "Passphrase must be at least #{MIN_LENGTH} characters (a few unrelated words work well)" if value.length < MIN_LENGTH
      return "Passphrase cannot be one character repeated" if value.chars.uniq.size == 1
      return "Passphrase is too common — pick something an attacker would not try first" if COMMON.include?(value.downcase)

      nil
    end
  end
end
