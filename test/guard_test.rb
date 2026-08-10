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

  # A bucket name, region, hostname or account id is a public identifier, not a
  # credential. Storing one alongside real secrets used to make the guard
  # unusable: a value like a project slug appears in ordinary paths, so every
  # `cd` into that project was denied. Non-secret keys are scanned past.
  def test_scan_ignores_conventionally_public_keys
    public_keys = [
      { vault: "acme", key: "CLOUDFLARE.r2_bucket", value: "my-project-assets" },
      { vault: "acme", key: "AWS.region",           value: "eu-west-2" },
      { vault: "acme", key: "STRIPE.account_id",    value: "acct_1234567890" }
    ]

    text = "cd ~/Code/my-project-assets && aws --region eu-west-2 s3 ls"

    assert_empty LocalVault::Guard.scan(text, public_keys)
  end

  # A connection string embeds a password, so a key ending in url/uri/endpoint/dsn
  # must NEVER be exempt however public the noun sounds. The first draft of the
  # exemption list included `url` and silently unguarded this value.
  def test_scan_never_exempts_connection_strings
    keys = [
      { vault: "acme", key: "DB.url",         value: "postgres://user:pass@host/db" },
      { vault: "acme", key: "REDIS.uri",      value: "redis://:hunter2@10.0.0.5:6379" },
      { vault: "acme", key: "SENTRY.dsn",     value: "https://abc123@o1.ingest.io/42" },
      { vault: "acme", key: "VAULT.endpoint", value: "https://tok:xyz789@vault.internal" }
    ]

    text = keys.map { |k| k[:value] }.join(" ")

    assert_equal 4, LocalVault::Guard.scan(text, keys).size
  end

  # The exemption is by key NAME only. A key that merely contains a public-ish
  # word must still be guarded when it names an actual credential.
  def test_scan_still_guards_secrets_whose_key_resembles_a_public_one
    secrets = [ { vault: "acme", key: "CLOUDFLARE.r2_bucket_secret_key", value: "sk_live_abcdef1234567890" } ]

    matches = LocalVault::Guard.scan("curl -H 'Authorization: sk_live_abcdef1234567890'", secrets)

    assert_equal [ "CLOUDFLARE.r2_bucket_secret_key" ], matches.map(&:key)
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
      command = entry["hooks"].first["command"]
      assert_includes command, "localvault guard hook"
      assert_includes command, "exit 0", "installed command must fail open on old/missing binaries"
      assert_includes command, "-eq 2", "installed command must pass a genuine deny through"
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
    assert(commands.any? { |c| c.include?("localvault guard hook") })
  end

  def test_merge_hooks_recognizes_wrapped_and_bare_commands_as_installed
    settings = {
      "hooks" => {
        "PreToolUse" => [
          { "matcher" => "Bash", "hooks" => [{ "type" => "command", "command" => "localvault guard hook" }] },
          { "matcher" => "Bash", "hooks" => [{ "type" => "command", "command" => LocalVault::Guard::HOOK_COMMAND }] }
        ],
        "PostToolUse" => [
          { "matcher" => "Bash", "hooks" => [{ "type" => "command", "command" => LocalVault::Guard::HOOK_COMMAND }] }
        ]
      }
    }
    refute LocalVault::Guard.merge_hooks!(settings), "existing entries (wrapped or bare) must not be duplicated"
    assert LocalVault::Guard.installed?(settings)
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
