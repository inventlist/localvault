require_relative "test_helper"

class VaultFilterTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key("testpass", @salt)
    @vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    @vault.set("DATABASE_URL", "postgres://localhost")
    @vault.set("REDIS_URL", "redis://localhost")
    @vault.set("platepose.DB_URL", "postgres://pp")
    @vault.set("platepose.SECRET_KEY", "sk-pp")
    @vault.set("inventlist.DB_URL", "postgres://il")
    @vault.set("inventlist.STRIPE_KEY", "sk-il")
  end

  def teardown
    teardown_test_home
  end

  def test_filter_by_group_returns_all_group_keys
    result = @vault.filter(["platepose"])
    assert_equal({"platepose" => {"DB_URL" => "postgres://pp", "SECRET_KEY" => "sk-pp"}}, result)
  end

  def test_filter_by_flat_key_returns_single_key
    result = @vault.filter(["DATABASE_URL"])
    assert_equal({"DATABASE_URL" => "postgres://localhost"}, result)
  end

  def test_filter_by_multiple_scopes
    result = @vault.filter(["platepose", "DATABASE_URL"])
    assert_equal({
      "platepose" => {"DB_URL" => "postgres://pp", "SECRET_KEY" => "sk-pp"},
      "DATABASE_URL" => "postgres://localhost"
    }, result)
  end

  def test_filter_excludes_unscoped_keys
    result = @vault.filter(["platepose"])
    refute result.key?("inventlist")
    refute result.key?("DATABASE_URL")
    refute result.key?("REDIS_URL")
  end

  def test_filter_nil_returns_all
    result = @vault.filter(nil)
    assert_equal @vault.all, result
  end

  def test_filter_empty_array_returns_empty
    result = @vault.filter([])
    assert_equal({}, result)
  end

  def test_filter_nonexistent_scope_returns_empty
    result = @vault.filter(["nope"])
    assert_equal({}, result)
  end
end
