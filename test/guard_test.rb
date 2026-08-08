require_relative "test_helper"

class GuardTest < Minitest::Test
  SECRETS = [
    { vault: "default", key: "STRIPE.private_key", value: "sk_live_abcdef1234567890" },
    { vault: "default", key: "SHORT", value: "tiny" },
    { vault: "work", key: "DB_URL", value: "postgres://user:pass@host/db" }
  ].freeze

  def test_flatten_walks_nested_groups
    flat = LocalVault::Guard.flatten({ "A" => "1", "G" => { "B" => "2", "H" => { "C" => "3" } } })
    assert_equal({ "A" => "1", "G.B" => "2", "G.H.C" => "3" }, flat)
  end

  def test_scan_finds_embedded_value
    matches = LocalVault::Guard.scan("curl -H 'Authorization: sk_live_abcdef1234567890'", SECRETS)
    assert_equal 1, matches.size
    assert_equal "STRIPE.private_key", matches.first.key
    assert_equal "default", matches.first.vault
  end

  def test_scan_ignores_short_values
    assert_empty LocalVault::Guard.scan("echo tiny", SECRETS)
  end

  def test_scan_ignores_clean_text
    assert_empty LocalVault::Guard.scan("localvault exec --profile aws -- aws s3 ls", SECRETS)
  end

  def test_fingerprint_is_stable_and_not_the_value
    fp = LocalVault::Guard.fingerprint("sk_live_abcdef1234567890")
    assert_equal 12, fp.length
    refute_includes "sk_live_abcdef1234567890", fp
  end

  def test_pre_tool_use_with_secret_is_denied_without_leaking_value
    event = {
      "hook_event_name" => "PreToolUse",
      "tool_name" => "Bash",
      "tool_input" => { "command" => "curl -u sk_live_abcdef1234567890 https://api.stripe.com" }
    }
    result = LocalVault::Guard.evaluate(event, SECRETS)
    assert_equal 2, result[:exit]
    assert_includes result[:message], "default/STRIPE.private_key"
    assert_includes result[:message], "localvault exec --map STRIPE.private_key=PRIVATE_KEY"
    refute_includes result[:message], "sk_live_abcdef1234567890"
  end

  def test_pre_tool_use_scans_nested_input_structures
    event = {
      "hook_event_name" => "PreToolUse",
      "tool_input" => { "args" => ["--url", "postgres://user:pass@host/db"] }
    }
    result = LocalVault::Guard.evaluate(event, SECRETS)
    assert_equal 2, result[:exit]
    assert_includes result[:message], "work/DB_URL"
  end

  def test_clean_pre_tool_use_is_allowed
    event = {
      "hook_event_name" => "PreToolUse",
      "tool_input" => { "command" => "bundle exec rake test" }
    }
    assert_equal 0, LocalVault::Guard.evaluate(event, SECRETS)[:exit]
  end

  def test_post_tool_use_exposure_warns
    event = {
      "hook_event_name" => "PostToolUse",
      "tool_response" => { "stdout" => "value is sk_live_abcdef1234567890\n" }
    }
    result = LocalVault::Guard.evaluate(event, SECRETS)
    assert_equal 2, result[:exit]
    assert_includes result[:message], "entered the transcript"
    assert_includes result[:message], "rotate"
    refute_includes result[:message], "sk_live_abcdef1234567890"
  end

  def test_unknown_event_is_allowed
    assert_equal 0, LocalVault::Guard.evaluate({ "hook_event_name" => "SessionStart" }, SECRETS)[:exit]
  end

  def test_malformed_event_fails_open
    assert_equal 0, LocalVault::Guard.evaluate({}, SECRETS)[:exit]
    assert_equal 0, LocalVault::Guard.evaluate({ "hook_event_name" => "PreToolUse" }, SECRETS)[:exit]
    assert_equal 0, LocalVault::Guard.evaluate({ "hook_event_name" => "PreToolUse", "tool_input" => 42 }, SECRETS)[:exit]
  end

  def test_merge_hooks_installs_both_events_idempotently
    settings = {}
    assert LocalVault::Guard.merge_hooks!(settings)
    assert LocalVault::Guard.installed?(settings)

    %w[PreToolUse PostToolUse].each do |event|
      entry = settings["hooks"][event].first
      assert_equal "Bash", entry["matcher"]
      assert_equal "localvault guard hook", entry["hooks"].first["command"]
    end

    refute LocalVault::Guard.merge_hooks!(settings), "second install should be a no-op"
    assert_equal 1, settings["hooks"]["PreToolUse"].size
  end

  def test_merge_hooks_preserves_existing_hooks
    settings = {
      "hooks" => {
        "PreToolUse" => [
          { "matcher" => "Bash", "hooks" => [{ "type" => "command", "command" => "other-tool check" }] }
        ]
      }
    }
    assert LocalVault::Guard.merge_hooks!(settings)
    commands = settings["hooks"]["PreToolUse"].flat_map { |e| e["hooks"].map { |h| h["command"] } }
    assert_includes commands, "other-tool check"
    assert_includes commands, "localvault guard hook"
  end

  def test_installed_is_false_when_only_one_event_is_wired
    settings = {
      "hooks" => {
        "PreToolUse" => [
          { "matcher" => "Bash", "hooks" => [{ "type" => "command", "command" => "localvault guard hook" }] }
        ]
      }
    }
    refute LocalVault::Guard.installed?(settings)
  end
end
