module LocalVault
  module KeyLookup
    Result = Struct.new(:key, :value, :matches, keyword_init: true) do
      def exact?
        !value.nil?
      end

      def single_match?
        matches.size == 1
      end

      def multiple_matches?
        matches.size > 1
      end
    end

    def self.lookup(vault, key)
      value = vault.get(key)
      return Result.new(key: key, value: value, matches: []) unless value.nil?

      matches = candidates(vault, key)
      Result.new(key: key, value: nil, matches: matches)
    end

    def self.candidates(vault, key)
      query = key.to_s.downcase
      vault.list.select { |candidate| candidate.downcase.include?(query) }.sort
    end
  end
end
