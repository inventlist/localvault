require_relative "test_helper"
require_relative "../lib/localvault"
require_relative "../lib/localvault/session_cache"

class SessionCacheTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    @vault_name = "default"
    @master_key = LocalVault::Crypto.generate_salt  # 16 random bytes as a stand-in key
  end

  def teardown
    LocalVault::SessionCache.clear(@vault_name)
    teardown_test_home
  end

  def test_set_and_get_returns_master_key
    LocalVault::SessionCache.set(@vault_name, @master_key)
    result = LocalVault::SessionCache.get(@vault_name)
    assert_equal @master_key, result
  end

  def test_get_returns_nil_when_not_set
    assert_nil LocalVault::SessionCache.get("nonexistent")
  end

  def test_clear_removes_cached_key
    LocalVault::SessionCache.set(@vault_name, @master_key)
    LocalVault::SessionCache.clear(@vault_name)
    assert_nil LocalVault::SessionCache.get(@vault_name)
  end

  def test_expired_entry_returns_nil
    LocalVault::SessionCache.set(@vault_name, @master_key, ttl_hours: 0)
    # TTL of 0 hours means already expired
    assert_nil LocalVault::SessionCache.get(@vault_name)
  end

  def test_set_overwrites_existing_entry
    other_key = LocalVault::Crypto.generate_salt
    LocalVault::SessionCache.set(@vault_name, @master_key)
    LocalVault::SessionCache.set(@vault_name, other_key)
    assert_equal other_key, LocalVault::SessionCache.get(@vault_name)
  end

  def test_separate_vaults_cached_independently
    other_key = LocalVault::Crypto.generate_salt
    LocalVault::SessionCache.set("default", @master_key)
    LocalVault::SessionCache.set("x", other_key)

    assert_equal @master_key, LocalVault::SessionCache.get("default")
    assert_equal other_key,   LocalVault::SessionCache.get("x")

    LocalVault::SessionCache.clear("x")
    assert_equal @master_key, LocalVault::SessionCache.get("default")
    assert_nil                LocalVault::SessionCache.get("x")
  end
end
