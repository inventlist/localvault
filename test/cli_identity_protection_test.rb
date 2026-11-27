require_relative "test_helper"
require_relative "sync_pull_key_slot_test" # FakePullClient + bundle builders
require "localvault/cli"

# Plan 13 A5–A8: CLI surface for the passphrase-protected identity key.
class CLIIdentityProtectionTest < Minitest::Test
  include LocalVault::TestHelper

  PASS = "correct horse battery staple"

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
  end

  def teardown
    LocalVault::Identity.lock!
    LocalVault::SessionCache.clear("myvault")
    teardown_test_home
  end

  # Replace prompt_passphrase on +klass+ with a queue of answers.
  def with_prompts(klass, answers)
    queue = answers.dup
    original = klass.instance_method(:prompt_passphrase)
    klass.send(:define_method, :prompt_passphrase) { |_msg = ""| queue.shift.to_s }
    yield
  ensure
    klass.send(:define_method, :prompt_passphrase, original)
  end

  # A6 — keys generate
  def test_keys_generate_writes_protected_identity
    with_prompts(LocalVault::CLI::Keys, [PASS, PASS]) do
      capture_io { LocalVault::CLI.start(%w[keys generate]) }
    end
    assert LocalVault::Identity.protected?
  end

  def test_keys_generate_refuses_weak_identity_passphrase
    _, err = with_prompts(LocalVault::CLI::Keys, ["short", "short"]) do
      capture_io { LocalVault::CLI.start(%w[keys generate]) }
    end
    assert_match(/at least 12 characters/, err)
    refute LocalVault::Identity.exists?
  end

  def test_keys_generate_refuses_mismatched_confirmation
    _, err = with_prompts(LocalVault::CLI::Keys, [PASS, "#{PASS}!"]) do
      capture_io { LocalVault::CLI.start(%w[keys generate]) }
    end
    assert_match(/do not match/, err)
    refute LocalVault::Identity.exists?
  end

  # A6 — keys protect
  def test_keys_protect_migrates_legacy_identity
    kp = LocalVault::Identity.generate!
    out, = with_prompts(LocalVault::CLI::Keys, [PASS, PASS]) do
      capture_io { LocalVault::CLI.start(%w[keys protect]) }
    end
    assert_match(/protected/i, out)
    assert LocalVault::Identity.protected?
    LocalVault::Identity.lock!
    assert_equal kp[:private_key], LocalVault::Identity.unlock(PASS)
  end

  def test_keys_protect_changes_passphrase_of_protected_identity
    LocalVault::Identity.generate!(passphrase: PASS)
    LocalVault::Identity.lock!
    new_pass = "a different long passphrase"
    with_prompts(LocalVault::CLI::Keys, [PASS, new_pass, new_pass]) do
      capture_io { LocalVault::CLI.start(%w[keys protect]) }
    end
    LocalVault::Identity.lock!
    LocalVault::Identity.unlock(new_pass)
  end

  # A6 — keys unlock / status
  def test_keys_unlock_caches_identity
    LocalVault::Identity.generate!(passphrase: PASS)
    LocalVault::Identity.lock!
    with_prompts(LocalVault::CLI::Keys, [PASS]) do
      capture_io { LocalVault::CLI.start(%w[keys unlock]) }
    end
    refute LocalVault::Identity.locked?
  end

  def test_keys_unlock_wrong_passphrase_reports_error
    LocalVault::Identity.generate!(passphrase: PASS)
    LocalVault::Identity.lock!
    _, err = with_prompts(LocalVault::CLI::Keys, ["wrong wrong wrong"]) do
      capture_io { LocalVault::CLI.start(%w[keys unlock]) }
    end
    assert_match(/Wrong identity passphrase/, err)
    assert LocalVault::Identity.locked?
  end

  def test_keys_status_reports_each_state_without_key_material
    out, = capture_io { LocalVault::CLI.start(%w[keys status]) }
    assert_match(/missing/, out)

    kp = LocalVault::Identity.generate!
    out, = capture_io { LocalVault::CLI.start(%w[keys status]) }
    assert_match(/legacy/i, out)
    refute_includes out, Base64.strict_encode64(kp[:private_key])

    LocalVault::Identity.protect!(new_passphrase: PASS)
    out, = capture_io { LocalVault::CLI.start(%w[keys status]) }
    assert_match(/protected/, out)
  end

  # A5 — lock clears identity
  def test_lock_without_name_clears_identity
    LocalVault::Identity.generate!(passphrase: PASS)
    refute LocalVault::Identity.locked?
    capture_io { LocalVault::CLI.start(%w[lock]) }
    assert LocalVault::Identity.locked?
  end

  # A7 — sync pull key-slot path
  def test_sync_pull_unlocks_key_slot_with_protected_identity_via_prompt
    pull = SyncPullKeySlotTest.new("x")
    pull.instance_variable_set(:@salt, LocalVault::Crypto.generate_salt)
    master = RbNaCl::Random.random_bytes(32)
    pull.instance_variable_set(:@master_key, master)

    LocalVault::Identity.generate!(passphrase: PASS)
    LocalVault::Identity.lock!
    LocalVault::Config.token = "tok"
    LocalVault::Config.inventlist_handle = "nauman"

    client = FakePullClient.new
    client.set_response(:pull_vault, pull.send(:build_v2_blob_with_owner_slot))

    with_prompts(LocalVault::CLI::Sync, [PASS]) do
      LocalVault::ApiClient.stub(:new, client) do
        capture_io { LocalVault::CLI.start(%w[sync pull myvault]) }
      end
    end
    assert_equal master, LocalVault::SessionCache.get("myvault")
  end

  def test_legacy_identity_warns_once_when_used
    LocalVault::Identity.generate!
    LocalVault::Identity.reset_legacy_warning!
    _, err = capture_io do
      LocalVault::Identity.private_key_bytes
      LocalVault::Identity.private_key_bytes
    end
    assert_equal 1, err.scan(/localvault keys protect/).size
  end

  # A8 — CLI applies the passphrase policy to new vault passphrases
  def test_init_refuses_weak_passphrase
    _, err = with_prompts(LocalVault::CLI, ["secret123", "secret123"]) do
      capture_io { LocalVault::CLI.start(%w[init]) }
    end
    assert_match(/at least 12 characters/, err)
    refute LocalVault::Store.new("default").exists?
  end

  def test_rekey_refuses_weak_new_passphrase
    with_prompts(LocalVault::CLI, [test_passphrase, test_passphrase]) do
      capture_io { LocalVault::CLI.start(%w[init]) }
    end
    _, err = with_prompts(LocalVault::CLI, [test_passphrase, "tiny", "tiny"]) do
      capture_io { LocalVault::CLI.start(%w[rekey]) }
    end
    assert_match(/at least 12 characters/, err)
  ensure
    LocalVault::SessionCache.clear("default")
  end
end
