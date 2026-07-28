module LocalVault
  class GroupCatalog
    Entry = Data.define(:label, :value, :source_kind)
    Group = Data.define(:name, :kind, :entries) do
      def count
        entries.length
      end
    end
    Match = Data.define(:kind, :query, :groups) do
      def group
        groups.one? ? groups.first : nil
      end
    end

    attr_reader :groups

    def initialize(secrets)
      grouped = {}

      secrets.each do |name, value|
        if value.is_a?(Hash)
          append_namespace(grouped, name, value)
        elsif name.include?("_")
          append_entry(grouped, name.split("_", 2).first, Entry.new(name, value, :prefix))
        end
      end

      @groups = grouped.map do |name, entries|
        kinds = entries.map(&:source_kind).uniq
        kind = kinds.length > 1 ? :mixed : kinds.first
        Group.new(name, kind, entries.sort_by(&:label).freeze)
      end.sort_by { |group| [group.name.downcase, group.name] }.freeze
    end

    def search(query = nil)
      return groups if query.nil? || query.empty?

      needle = query.downcase
      groups.select { |group| group.name.downcase.start_with?(needle) }
    end

    def resolve(query)
      exact = groups.select { |group| group.name == query }
      return Match.new(:exact, query, exact) if exact.one?

      insensitive = groups.select { |group| group.name.casecmp?(query) }
      return Match.new(:unique, query, insensitive) if insensitive.one?
      return Match.new(:ambiguous, query, insensitive) if insensitive.length > 1

      matches = search(query)
      kind = matches.one? ? :unique : (matches.empty? ? :absent : :ambiguous)
      Match.new(kind, query, matches)
    end

    private

    def append_namespace(grouped, name, values)
      values.each do |label, value|
        append_entry(grouped, name, Entry.new(label, value, :namespace))
      end
    end

    def append_entry(grouped, name, entry)
      (grouped[name] ||= []) << entry
    end
  end
end
