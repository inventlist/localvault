require "thor"
require "json"
require "fileutils"
require_relative "../guard"

module LocalVault
  class CLI
    class Guard < Thor
      desc "hook", "Claude Code hook entrypoint (reads hook JSON on stdin)"
      long_desc <<~DESC
        Reads a Claude Code PreToolUse/PostToolUse event on stdin. Blocks tool
        calls whose input contains a stored plaintext secret value from any
        session-unlocked vault, naming the key by fingerprint — never by value.
        Fails open on any error so a broken guard cannot block all work.
      DESC
      def hook
        event = JSON.parse($stdin.read)
        result = LocalVault::Guard.evaluate(event)
        if result[:exit] != 0
          $stderr.puts result[:message]
          exit result[:exit]
        end
      rescue StandardError
        # fail open
      end

      desc "install", "Install the guard hooks into Claude Code settings"
      method_option :project, type: :boolean, default: false,
        desc: "Install into ./.claude/settings.json instead of ~/.claude/settings.json"
      def install
        path = settings_path(options[:project])
        settings = File.exist?(path) ? JSON.parse(File.read(path)) : {}
        if LocalVault::Guard.merge_hooks!(settings)
          FileUtils.mkdir_p(File.dirname(path))
          File.write(path, JSON.pretty_generate(settings) + "\n")
          $stdout.puts "Installed LocalVault guard hooks in #{path}"
          $stdout.puts "Restart Claude Code sessions to pick up hook changes."
        else
          $stdout.puts "LocalVault guard hooks already installed in #{path}"
        end
        warn_if_path_binary_lacks_guard
      rescue JSON::ParserError
        $stderr.puts "Error: #{path} is not valid JSON; fix it before installing."
      end

      desc "status", "Show guard hook installation status"
      def status
        { "user" => settings_path(false), "project" => settings_path(true) }.each do |label, path|
          state = if !File.exist?(path)
            "not installed"
          else
            begin
              LocalVault::Guard.installed?(JSON.parse(File.read(path))) ? "installed" : "not installed"
            rescue JSON::ParserError
              "unreadable JSON"
            end
          end
          $stdout.puts "#{label} (#{path}): #{state}"
        end
      end

      no_commands do
        # The installed hook wraps the entrypoint to fail open, so an old or
        # missing PATH binary never breaks the user's sessions — but it also
        # silently guards nothing, which deserves a loud note at install time.
        def warn_if_path_binary_lacks_guard
          help_output = `localvault help 2>/dev/null`
          return if help_output.include?("guard")

          $stderr.puts "Note: the `localvault` on your PATH does not support `guard hook` " \
                       "(old version or different install). The hook fails open and guards " \
                       "nothing until you upgrade: brew upgrade localvault"
        rescue StandardError
          nil
        end

        def settings_path(project)
          if project
            File.join(Dir.pwd, ".claude", "settings.json")
          else
            File.join(Dir.home, ".claude", "settings.json")
          end
        end
      end
    end
  end
end
