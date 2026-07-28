require "shellwords"
require_relative "../input_validation"

module LocalVault
  module MCP
    class ExecCommandBuilder
      def initialize(command:, vault: nil, project: nil, only: nil, except: nil, map: nil, profile: nil)
        @command = command
        @vault = vault
        @project = project
        @only = only
        @except = except
        @map = map
        @profile = profile
      end

      def build
        validate!
        argv = ["localvault", "exec"]
        append(argv, "-v", @vault)
        append(argv, "--project", @project)
        append(argv, "--only", serialize_selectors(@only))
        append(argv, "--except", serialize_selectors(@except))
        append(argv, "--map", serialize_map)
        append(argv, "--profile", @profile)
        argv.concat(["--", *@command])

        {
          "command" => Shellwords.join(argv),
          "exposes_plaintext" => false,
          "executes_command" => false,
          "next_action" => "Run this command through your normal shell tool."
        }.freeze
      end

      private

      def validate!
        InputValidation.argv!(@command)
        InputValidation.vault_name!(@vault) if @vault
        InputValidation.project!(@project) if @project
        InputValidation.profile!(@profile) if @profile
        validate_selectors!(@only, "only")
        validate_selectors!(@except, "except")
        validate_map!
      end

      def validate_selectors!(selectors, label)
        return if selectors.nil?
        unless selectors.is_a?(Array) && !selectors.empty?
          raise InputValidation::InvalidInput, "#{label} must be a non-empty array of selectors"
        end
        selectors.each { |selector| InputValidation.selector!(selector) }
      end

      def validate_map!
        return if @map.nil?
        unless @map.is_a?(Hash) && !@map.empty?
          raise InputValidation::InvalidInput, "map must be a non-empty object"
        end
        @map.each { |source, target| InputValidation.mapping!(source, target) }
      end

      def append(argv, flag, value)
        argv.concat([flag, value]) if value
      end

      def serialize_selectors(selectors)
        selectors&.join(",")
      end

      def serialize_map
        @map&.sort_by { |source, _target| source }&.map { |source, target| "#{source}=#{target}" }&.join(",")
      end
    end
  end
end
