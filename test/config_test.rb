require_relative "test_helper"

class ConfigTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
  end

  def teardown
    teardown_test_home
  end

  def test_root_path_defaults_to_home_localvault
    ENV.delete("LOCALVAULT_HOME")
    assert_equal File.join(Dir.home, ".localvault"), LocalVault::Config.root_path
  end

  def test_root_path_uses_localvault_home_env
    assert_equal @test_home, LocalVault::Config.root_path
  end

  def test_vaults_path
    assert_equal File.join(@test_home, "vaults"), LocalVault::Config.vaults_path
  end

  def test_keys_path
    assert_equal File.join(@test_home, "keys"), LocalVault::Config.keys_path
  end

  def test_load_returns_empty_hash_when_no_config
    assert_equal({}, LocalVault::Config.load)
  end

  def test_save_and_load_roundtrip
    data = { "default_vault" => "work", "handle" => "@nauman" }
    LocalVault::Config.save(data)
    assert_equal data, LocalVault::Config.load
  end

  def test_default_vault_returns_default_when_not_set
    assert_equal "default", LocalVault::Config.default_vault
  end

  def test_default_vault_setter
    LocalVault::Config.default_vault = "work"
    assert_equal "work", LocalVault::Config.default_vault
  end

  def test_ensure_directories_creates_all_dirs
    LocalVault::Config.ensure_directories!
    assert File.directory?(@test_home)
    assert File.directory?(File.join(@test_home, "vaults"))
    assert File.directory?(File.join(@test_home, "keys"))
  end

  def test_config_file_is_yaml
    LocalVault::Config.save("key" => "value")
    content = File.read(LocalVault::Config.config_path)
    assert_match(/key.*value/, content)
  end
end
