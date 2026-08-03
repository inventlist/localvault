module LocalVault
  class StdinSecretInput
    class InteractiveInput < StandardError; end
    class InvalidEncoding < StandardError; end

    PIPE_EXAMPLE = %(printf '%s' "$SECRET" | localvault set KEY --stdin).freeze

    def self.read(input = $stdin)
      if input.respond_to?(:tty?) && input.tty?
        raise InteractiveInput, "Refusing to read secret from interactive stdin. " \
          "Pipe it instead: #{PIPE_EXAMPLE}"
      end

      input.binmode if input.respond_to?(:binmode)
      value = input.read || ""
      value = value.dup.force_encoding(Encoding::UTF_8)
      raise InvalidEncoding, "Secret value must be valid UTF-8" unless value.valid_encoding?

      value
    end
  end
end
