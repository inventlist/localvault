require "did_you_mean"

module LocalVault
  class CLI
    class ErrorPresenter
      Context = Data.define(:command_class, :namespace, :token, :command)

      def initialize(root_class, argv)
        @root_class = root_class
        @argv = argv.map(&:to_s)
      end

      def render(error, io: $stderr)
        @error = error
        context = @context = resolve_context
        io.puts error_heading(context)
        io.puts "Usage: #{usage_for(context)}"
        render_option_hint(context, io)
        io.puts
        io.puts "Try:"
        suggestions_for(context).first(5).each { |suggestion| io.puts "  #{suggestion}" }
      end

      private

      def resolve_context
        command_class = @root_class
        namespace = []
        token = @argv.first
        command = resolve_command(command_class, token)

        if command && command_class.subcommand_classes.key?(command.name)
          namespace << command.name
          command_class = command_class.subcommand_classes.fetch(command.name)
          token = @argv[1]
          command = resolve_command(command_class, token)
        end

        Context.new(command_class, namespace, token, command)
      end

      def resolve_command(command_class, token)
        return nil unless token && !token.start_with?("-")
        return command_class.all_commands[token] if command_class.all_commands.key?(token)

        matches = command_class.all_commands.keys.select { |name| name.start_with?(token) }
        matches.one? ? command_class.all_commands[matches.first] : nil
      end

      def error_heading(context)
        if @error.is_a?(CLI::GroupSelectionError)
          if @error.kind == :ambiguous
            "Error: Multiple groups match `#{@error.query}`."
          else
            "Error: No group matches `#{@error.query}`."
          end
        elsif @error.is_a?(CLI::GroupSaveError)
          case @error.kind
          when :collision then "Error: cannot create group: that name is already used by a secret key."
          when :ambiguous then "Error: group name is ambiguous. Existing groups: #{@error.candidates.join(", ")}."
          else "Error: group and key names may contain letters, digits, and underscores only."
          end
        elsif @error.is_a?(CLI::SetValueSourceError) && @error.kind == :multiple
          "Error: #{@error.message}"
        elsif group_save_attempt?
          "Error: saving in a group needs GROUP, KEY, and VALUE."
        elsif @error.is_a?(CLI::SetValueSourceError)
          "Error: #{@error.message}"
        elsif unknown_option
          "Error: unknown option `#{unknown_option}`."
        elsif context.command.nil?
          "Error: unknown or ambiguous command."
        else
          "Error: this command needs a different combination of arguments."
        end
      end

      def usage_for(context)
        if @error.is_a?(CLI::GroupSelectionError)
          "localvault show --group GROUP"
        elsif group_save_attempt?
          "localvault set --group GROUP KEY VALUE"
        elsif context.command
          ["localvault", *context.namespace, context.command.usage].join(" ")
        else
          ["localvault", *context.namespace, "COMMAND"].join(" ")
        end
      end

      def render_option_hint(context, io)
        return unless unknown_option

        correction = DidYouMean::SpellChecker.new(dictionary: option_names(context)).correct(unknown_option).first
        io.puts "\nDid you mean `#{correction}`?" if correction
      end

      def suggestions_for(context)
        if @error.is_a?(CLI::GroupSelectionError)
          return @error.candidates.map { |name| "localvault show --group #{name}" } if @error.kind == :ambiguous
          return ["localvault groups #{@error.query}", "localvault groups"]
        end

        return group_save_suggestions if group_save_attempt?
        return set_suggestions if context.command&.name == "set"
        return show_group_suggestions if context.command&.name == "show" || unknown_option == "--group-by"
        return ["localvault add HANDLE", "localvault team add HANDLE"] if context.namespace == ["team"] && context.command&.name == "add"

        if context.command
          examples = curated_examples(context.command)
          examples.empty? ? [usage_for(context)] : examples
        else
          command_suggestions(context)
        end
      end

      def group_save_suggestions
        [
          "localvault set --group GROUP KEY VALUE",
          "localvault set GROUP.KEY VALUE",
          "localvault groups [QUERY]"
        ]
      end

      def set_suggestions
        [
          %(printf '%s' "$SECRET" | localvault set KEY --stdin),
          "localvault set KEY VALUE",
          *group_save_suggestions
        ]
      end

      def show_group_suggestions
        [
          "localvault show --group GROUP",
          "localvault groups [QUERY]",
          "localvault show --project PROJECT"
        ]
      end

      def command_suggestions(context)
        names = context.command_class.all_commands.keys.reject { |name| name == "help" }
        matches = prefix_or_spelling_matches(names, context.token.to_s)
        items = matches.map do |name|
          command = context.command_class.all_commands.fetch(name)
          ["localvault", *context.namespace, command.usage, "  # #{command.description}"].join(" ")
        end
        items.empty? ? ["localvault help"] : items
      end

      def prefix_or_spelling_matches(names, token)
        prefix = names.select { |name| name.start_with?(token) }
        return prefix.sort unless prefix.empty?

        DidYouMean::SpellChecker.new(dictionary: names).correct(token).first(5)
      end

      def curated_examples(command)
        command.long_description.to_s.lines.filter_map do |line|
          example = line.delete("\u0005").strip
          example if example.start_with?("localvault ")
        end.uniq
      end

      def option_names(context)
        options = context.command_class.class_options.values
        options += context.command.options.values if context.command

        options.flat_map do |option|
          ["--#{option.name.to_s.tr("_", "-")}", *Array(option.aliases)]
        end.uniq
      end

      def unknown_option
        return @unknown_option if defined?(@unknown_option)

        known = option_names(@context)
        @unknown_option = @argv.find do |argument|
          next false unless argument.start_with?("--") && argument != "--"

          !known.include?(argument.split("=", 2).first)
        end
      end

      def group_save_attempt?
        @argv.first == "set" && @argv.include?("--group")
      end
    end
  end
end
