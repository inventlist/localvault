module LocalVault
  module EnvProjection
    class InvalidMapping < StandardError; end
    class UnknownProfile < StandardError; end

    Entry = Struct.new(:key, :env_name, :value, keyword_init: true)

    ENV_NAME_PATTERN = /\A[A-Za-z_][A-Za-z0-9_]*\z/

    PROFILES = {
      "aws" => {
        only: ["AWS_IAM.*"],
        map: {
          "AWS_IAM.access_key_id" => "AWS_ACCESS_KEY_ID",
          "AWS_IAM.secret_access_key" => "AWS_SECRET_ACCESS_KEY",
          "AWS_IAM.session_token" => "AWS_SESSION_TOKEN"
        }
      }
    }.freeze

    def self.entries(secrets, project: nil, only: nil, except: nil, map: nil, profile: nil, on_skip: nil)
      profile_config = profile_config(profile)
      selectors = parse_selectors(only) || profile_config[:only]
      exclusions = parse_selectors(except) || []
      mappings = profile_config[:map].merge(parse_map(map))

      flatten(secrets, project: project, on_skip: on_skip)
        .select { |entry| include_entry?(entry.key, selectors) }
        .reject { |entry| selector_match?(entry.key, exclusions) }
        .map { |entry| apply_mapping(entry, mappings, on_skip: on_skip) }
        .compact
    end

    def self.parse_selectors(value)
      values = Array(value).compact.flat_map { |v| v.to_s.split(",") }
      selectors = values.map(&:strip).reject(&:empty?)
      selectors.empty? ? nil : selectors
    end

    def self.parse_map(value)
      Array(value).compact.flat_map { |v| v.to_s.split(",") }.each_with_object({}) do |pair, hash|
        next if pair.strip.empty?

        key, env_name = pair.split("=", 2).map(&:strip)
        raise InvalidMapping, "Invalid map '#{pair}'. Use KEY=ENV_NAME" if key.to_s.empty? || env_name.to_s.empty?
        raise InvalidMapping, "Invalid environment variable name '#{env_name}'" unless safe_env_name?(env_name)

        hash[key] = env_name
      end
    end

    def self.profile_config(profile)
      return { only: nil, map: {} } if profile.nil? || profile.to_s.empty?

      PROFILES.fetch(profile.to_s) do
        raise UnknownProfile, "Unknown env profile '#{profile}'"
      end
    end

    def self.flatten(secrets, project:, on_skip:)
      if project
        group = secrets[project]
        return [] unless group.is_a?(Hash)

        group.filter_map do |key, value|
          if safe_env_name?(key)
            Entry.new(key: key, env_name: key, value: value.to_s)
          else
            on_skip&.call(key)
            nil
          end
        end
      else
        secrets.flat_map do |key, value|
          if value.is_a?(Hash)
            flatten_group(key, value, on_skip: on_skip)
          elsif safe_env_name?(key)
            [Entry.new(key: key, env_name: key, value: value.to_s)]
          else
            on_skip&.call(key)
            []
          end
        end
      end
    end

    def self.flatten_group(group, pairs, on_skip:)
      unless safe_env_name?(group)
        on_skip&.call(group)
        return []
      end

      pairs.filter_map do |key, value|
        if safe_env_name?(key)
          Entry.new(key: "#{group}.#{key}", env_name: "#{group.upcase}__#{key}", value: value.to_s)
        else
          on_skip&.call("#{group}.#{key}")
          nil
        end
      end
    end

    def self.include_entry?(key, selectors)
      selectors.nil? || selector_match?(key, selectors)
    end

    def self.selector_match?(key, selectors)
      selectors.any? do |selector|
        if selector.end_with?(".*")
          key.start_with?("#{selector.delete_suffix(".*")}.")
        else
          key == selector
        end
      end
    end

    def self.apply_mapping(entry, mappings, on_skip:)
      mapped_name = mappings.fetch(entry.key, entry.env_name)
      unless safe_env_name?(mapped_name)
        on_skip&.call(entry.key)
        return nil
      end

      Entry.new(key: entry.key, env_name: mapped_name, value: entry.value)
    end

    def self.safe_env_name?(name)
      name.is_a?(String) && name.match?(ENV_NAME_PATTERN)
    end
  end
end
