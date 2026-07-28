module LocalVault
  module InputValidation
    class InvalidInput < StandardError; end

    SEGMENT_PATTERN = /\A[A-Za-z_][A-Za-z0-9_]*\z/
    VAULT_PATTERN = /\A[A-Za-z0-9][A-Za-z0-9_-]{0,63}\z/
    PROFILES = %w[aws].freeze

    module_function

    def selector!(value)
      string!(value, "selector")
      reject_delimiters!(value, "selector")
      parts = value.split(".", -1)
      valid = parts.length == 1 ? segment?(parts.first) :
        parts.length == 2 && segment?(parts.first) && (segment?(parts.last) || parts.last == "*")
      raise InvalidInput, "selector must be KEY, GROUP.KEY, or GROUP.*" unless valid

      value
    end

    def mapping!(source, target)
      selector!(source)
      raise InvalidInput, "mapping source must be an exact key" if source.end_with?(".*")
      string!(target, "mapping target")
      reject_delimiters!(target, "mapping target")
      raise InvalidInput, "mapping target must be an environment variable name" unless segment?(target)

      [source, target]
    end

    def project!(value)
      string!(value, "project")
      reject_delimiters!(value, "project")
      raise InvalidInput, "project must be one key segment" unless segment?(value)

      value
    end

    def vault_name!(value)
      string!(value, "vault")
      raise InvalidInput, "vault must be a valid vault name" unless value.match?(VAULT_PATTERN)

      value
    end

    def argv!(value)
      unless value.is_a?(Array) && !value.empty? &&
          value.all? { |token| token.is_a?(String) && !token.empty? && !token.include?("\0") }
        raise InvalidInput, "command must be a non-empty array of non-empty NUL-free strings"
      end

      value
    end

    def profile!(value)
      string!(value, "profile")
      raise InvalidInput, "profile must be one of: #{PROFILES.join(", ")}" unless PROFILES.include?(value)

      value
    end

    def segment?(value)
      value.is_a?(String) && value.match?(SEGMENT_PATTERN)
    end

    def string!(value, label)
      raise InvalidInput, "#{label} must be a non-empty string" unless value.is_a?(String) && !value.empty?
      raise InvalidInput, "#{label} must not contain NUL bytes" if value.include?("\0")
    end

    def reject_delimiters!(value, label)
      if value.include?(",") || value.include?("=")
        raise InvalidInput, "#{label} must not contain commas or equals signs"
      end
    end

    private_class_method :string!, :reject_delimiters!
  end
end
