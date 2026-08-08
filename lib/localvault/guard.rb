require "json"
require "digest"
require_relative "store"
require_relative "session_cache"

module LocalVault
  # Scans agent tool traffic (Claude Code hook events) for stored plaintext
  # secret values, so a value already in an agent's context — retrieved or
  # freshly generated, once stored — can never pass through a command line
  # unnoticed.
  #
  # Failure posture is fail-open: locked vaults, unreadable stores, and
  # malformed events all allow the tool call. A locked vault cannot have fed
  # values into the session, and a guard that blocks all work when it cannot
  # check gets uninstalled.
  module Guard
    MIN_VALUE_LENGTH = 8
    HOOK_COMMAND = "localvault guard hook".freeze
    HOOK_EVENTS = %w[PreToolUse PostToolUse].freeze
    ALLOW = { exit: 0, message: nil }.freeze

    Match = Struct.new(:vault, :key, :fingerprint, keyword_init: true)

    # Plaintext values from every session-unlocked vault.
    #
    # @return [Array<Hash>] entries with :vault, :key, :value
    def self.unlocked_secrets
      Store.list_vaults.flat_map do |name|
        master_key = SessionCache.get(name)
        next [] unless master_key

        begin
          vault = Vault.new(name: name, master_key: master_key)
          flatten(vault.all).map { |key, value| { vault: name, key: key, value: value } }
        rescue StandardError
          []
        end
      end
    end

    def self.flatten(hash, prefix = nil)
      hash.each_with_object({}) do |(k, v), out|
        key = prefix ? "#{prefix}.#{k}" : k.to_s
        if v.is_a?(Hash)
          out.merge!(flatten(v, key))
        else
          out[key] = v.to_s
        end
      end
    end

    # @return [Array<Match>] stored secret values appearing in +text+
    def self.scan(text, secrets = unlocked_secrets)
      return [] if text.nil? || text.empty?

      secrets.filter_map do |entry|
        value = entry[:value]
        next if value.nil? || value.length < MIN_VALUE_LENGTH
        next unless text.include?(value)

        Match.new(vault: entry[:vault], key: entry[:key], fingerprint: fingerprint(value))
      end
    end

    def self.fingerprint(value)
      Digest::SHA256.hexdigest(value)[0, 12]
    end

    def self.strings_in(node)
      case node
      when String then [node]
      when Hash then node.values.flat_map { |v| strings_in(v) }
      when Array then node.flat_map { |v| strings_in(v) }
      else []
      end
    end

    # Evaluate a parsed Claude Code hook event.
    #
    # @return [Hash] +{exit: Integer, message: String|nil}+ — exit 2 blocks a
    #   PreToolUse call / surfaces a PostToolUse warning to the agent
    def self.evaluate(event, secrets = unlocked_secrets)
      case event["hook_event_name"]
      when "PreToolUse"
        matches = scan(strings_in(event["tool_input"]).join("\n"), secrets)
        matches.empty? ? ALLOW : { exit: 2, message: deny_message(matches) }
      when "PostToolUse"
        matches = scan(strings_in(event["tool_response"]).join("\n"), secrets)
        matches.empty? ? ALLOW : { exit: 2, message: exposure_message(matches) }
      else
        ALLOW
      end
    rescue StandardError
      ALLOW
    end

    def self.deny_message(matches)
      first = matches.first
      env_name = first.key.split(".").last.upcase
      <<~MSG.strip
        LocalVault guard: blocked — this tool input contains the plaintext value of #{name_list(matches)}.
        Never place secret values in commands or arguments. Inject them instead:
          localvault exec --map #{first.key}=#{env_name} -- your-command
        or pipe a new value with: printf '%s' "$VALUE" | localvault set KEY --stdin
      MSG
    end

    def self.exposure_message(matches)
      <<~MSG.strip
        LocalVault guard: this command's output contained the plaintext value of #{name_list(matches)} and has entered the transcript.
        Treat the value as exposed: rotate it, then store the replacement via --stdin.
        Avoid commands that print secrets; use scoped injection (localvault exec --only/--map).
      MSG
    end

    def self.name_list(matches)
      matches.map { |m| "#{m.vault}/#{m.key} (sha256:#{m.fingerprint})" }.join(", ")
    end

    # Idempotently add the guard hook entries to a Claude Code settings hash.
    #
    # @return [Boolean] whether the settings were modified
    def self.merge_hooks!(settings)
      changed = false
      hooks = settings["hooks"] ||= {}
      HOOK_EVENTS.each do |event|
        entries = hooks[event] ||= []
        next if entries.any? { |e| (e["hooks"] || []).any? { |h| h["command"] == HOOK_COMMAND } }

        entries << { "matcher" => "Bash", "hooks" => [{ "type" => "command", "command" => HOOK_COMMAND }] }
        changed = true
      end
      changed
    end

    def self.installed?(settings)
      hooks = settings["hooks"] || {}
      HOOK_EVENTS.all? do |event|
        (hooks[event] || []).any? { |e| (e["hooks"] || []).any? { |h| h["command"] == HOOK_COMMAND } }
      end
    end
  end
end
