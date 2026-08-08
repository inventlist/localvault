module LocalVault
  # Gate for printing plaintext secret values.
  #
  # Plaintext may flow to an interactive terminal (a human is watching). When
  # stdout is captured (pipe, command substitution, agent shell), a human can
  # confirm with one keystroke on /dev/tty. An agent's shell has no /dev/tty,
  # and there is deliberately no flag, environment variable, or config bypass:
  # anything discoverable from the binary would be discovered by an agent.
  module PlaintextOutput
    TTY_PATH = "/dev/tty".freeze

    class << self
      # In-process overrides for tests only — unreachable from the installed
      # binary, unlike an env var or CLI flag would be.
      attr_accessor :assume_tty
      attr_accessor :tty_override # {input: IO, output: IO}
    end

    # @param out [IO] the stream plaintext would be written to
    # @param purpose [String] short description used in the /dev/tty prompt
    # @return [Boolean] whether plaintext may be printed to +out+
    def self.permitted?(out: $stdout, purpose: "Print plaintext")
      return true if assume_tty
      return true if out.respond_to?(:tty?) && out.tty?

      confirm("#{purpose}? [y/N] ")
    end

    def self.confirm(prompt)
      with_tty do |input, output|
        output.write(prompt)
        output.flush
        answer = input.gets
        !answer.nil? && %w[y yes].include?(answer.strip.downcase)
      end
    end

    def self.with_tty(&block)
      if tty_override
        return yield(tty_override[:input], tty_override[:output])
      end

      File.open(TTY_PATH, "r+") { |tty| yield(tty, tty) }
    rescue SystemCallError, IOError
      false
    end
  end
end
