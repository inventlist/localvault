require_relative "test_helper"
require "localvault/cli"

# Plan 13 A9: session TTL is configurable; the file fallback avoids persistent
# disk when a runtime dir exists; a custom LOCALVAULT_HOME never shares the
# default Keychain entries.
class SessionCacheHardeningTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @saved_env = ENV.to_h.slice("LOCALVAULT_SESSION_TTL_HOURS", "XDG_RUNTIME_DIR")
    ENV.delete("LOCALVAULT_SESSION_TTL_HOURS")
  end

  def teardown
    %w[LOCALVAULT_SESSION_TTL_HOURS XDG_RUNTIME_DIR].each { |k| @saved_env.key?(k) ? ENV[k] = @saved_env[k] : ENV.delete(k) }
    teardown_test_home
  end

  def test_ttl_defaults_to_eight_hours
    assert_equal 8, LocalVault::Config.session_ttl_hours
  end

  def test_ttl_reads_config_then_env_and_clamps
    LocalVault::Config.session_ttl_hours = 2
    assert_equal 2, LocalVault::Config.session_ttl_hours

    ENV["LOCALVAULT_SESSION_TTL_HOURS"] = "1"
    assert_equal 1, LocalVault::Config.session_ttl_hours

    ENV["LOCALVAULT_SESSION_TTL_HOURS"] = "500"
    assert_equal 24, LocalVault::Config.session_ttl_hours

    ENV["LOCALVAULT_SESSION_TTL_HOURS"] = "junk"
    assert_equal 2, LocalVault::Config.session_ttl_hours
  end

  def test_set_uses_configured_ttl
    LocalVault::Config.session_ttl_hours = 1
    LocalVault::SessionCache.set("ttlvault", "k" * 32)
    payload = LocalVault::SessionCache.send(:keychain_get, "ttlvault")
    expiry = payload.split("|", 2).last.to_i
    assert_in_delta Time.now.to_i + 3600, expiry, 5
  ensure
    LocalVault::SessionCache.clear("ttlvault")
  end

  def test_config_cli_sets_session_ttl
    out, = capture_io { LocalVault::CLI.start(%w[config set session-ttl 3]) }
    assert_match(/session-ttl set to 3/, out)
    assert_equal 3, LocalVault::Config.session_ttl_hours
  end

  def test_custom_home_uses_its_own_keychain_service
    refute_equal "localvault", LocalVault::SessionCache.keychain_service
    assert_match(/\Alocalvault-[0-9a-f]{12}\z/, LocalVault::SessionCache.keychain_service)
  end

  def test_default_home_keeps_the_original_keychain_service
    home = ENV.delete("LOCALVAULT_HOME")
    assert_equal "localvault", LocalVault::SessionCache.keychain_service
  ensure
    ENV["LOCALVAULT_HOME"] = home
  end

  def test_file_fallback_prefers_runtime_dir_for_default_home
    runtime = Dir.mktmpdir("xdg-runtime")
    home = ENV.delete("LOCALVAULT_HOME")
    ENV["XDG_RUNTIME_DIR"] = runtime
    assert_equal File.join(runtime, "localvault"), LocalVault::SessionCache.sessions_dir
  ensure
    ENV["LOCALVAULT_HOME"] = home
    FileUtils.rm_rf(runtime)
  end

  def test_file_fallback_stays_in_explicit_home
    ENV["XDG_RUNTIME_DIR"] = Dir.tmpdir
    assert_equal File.join(@test_home, ".sessions"), LocalVault::SessionCache.sessions_dir
  end
end
