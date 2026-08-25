require "thor"

module LocalVault
  class CLI
    # Colors every help surface — the main screen, `help COMMAND`, and
    # subcommand namespaces — by hooking the shell Thor already routes all
    # help output through, rather than colorizing at each call site.
    #
    # Thor disables color itself when stdout is not a TTY, so piped output
    # stays plain.
    class HelpShell < Thor::Shell::Color
      # "Usage:", "Options:", "Description:", "Runtime options:"
      LABEL = /\A([A-Z][A-Za-z ]*:)\s*\z/
      # A leading run of caps: "GETTING STARTED", "NESTED KEY (dot-notation)"
      HEADING = /\A(\s*)([A-Z][A-Z0-9'\/\-]*(?: [A-Z0-9'\/\-]+)*)(?=\z|[\s(:])/

      def say(message = "", color = nil, force_new_line = (message.to_s !~ /( |\t)\Z/))
        if color.nil? && message.is_a?(String)
          message = message.lines.map { |line| decorate(line.chomp) }.join("\n")
        end
        super
      end

      # Thor word-wraps long descriptions, which collapses the alignment of
      # example blocks (`localvault set K V     # comment` loses its spacing).
      # Lines flagged with \x05 — Thor's no-wrap marker, which every example in
      # our long_desc blocks already carries — are printed verbatim instead, so
      # examples stay aligned while prose still wraps to the terminal.
      def print_wrapped(message, options = {})
        indent = options[:indent] || 0
        prose  = []

        message.to_s.lines.each do |line|
          line = line.chomp
          if line.lstrip.start_with?("\x05")
            wrap_prose(prose, options)
            stdout.puts("#{" " * indent}#{decorate(line.sub("\x05", ''))}")
          elsif line.strip.empty?
            wrap_prose(prose, options)
            stdout.puts
          else
            prose << line
          end
        end

        wrap_prose(prose, options)
      end

      # Option tables: green the flag column ("-v, [--vault=VAULT]").
      def print_table(array, options = {})
        array = array.map do |row|
          first, *rest = row
          first.is_a?(String) && first.strip.start_with?("-") ? [set_color(first, :green), *rest] : row
        end
        super
      end

      private

      # Hand a run of prose lines back to Thor's wrapper, then reset the buffer.
      def wrap_prose(lines, options)
        return if lines.empty?
        text = lines.join("\n")
        lines.clear
        return if text.strip.empty?
        Thor::Shell::Basic.instance_method(:print_wrapped)
          .bind_call(self, text.lines.map { |l| decorate(l.chomp) }.join("\n"), options)
      end

      def decorate(line)
        return line unless can_display_colors?

        if (match = LABEL.match(line))
          return line.sub(match[1], set_color(match[1], :cyan, true))
        end

        match = HEADING.match(line)
        return line unless match && match[2].length >= 4

        "#{match[1]}#{set_color(match[2], :cyan, true)}#{line[(match[1].length + match[2].length)..]}"
      end
    end
  end
end
