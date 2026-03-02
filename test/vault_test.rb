require_relative "test_helper"

class VaultTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(test_passphrase, @salt)
  end

  def teardown
    teardown_test_home
  end

  def test_create_initializes_empty_vault
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    assert_equal({}, vault.all)
    assert_equal [], vault.list
  end

  def test_set_and_get
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault.set("DB_URL", "postgres://localhost/mydb")

    assert_equal "postgres://localhost/mydb", vault.get("DB_URL")
  end

  def test_set_overwrites_existing
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault.set("KEY", "old")
    vault.set("KEY", "new")

    assert_equal "new", vault.get("KEY")
  end

  def test_get_nonexistent_returns_nil
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    assert_nil vault.get("NOPE")
  end

  def test_delete_removes_key
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault.set("KEY", "value")
    vault.delete("KEY")

    assert_nil vault.get("KEY")
    assert_equal [], vault.list
  end

  def test_delete_returns_deleted_value
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault.set("KEY", "value")
    assert_equal "value", vault.delete("KEY")
  end

  def test_delete_nonexistent_returns_nil
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    assert_nil vault.delete("NOPE")
  end

  def test_list_returns_sorted_keys
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault.set("ZEBRA", "z")
    vault.set("ALPHA", "a")
    vault.set("MIDDLE", "m")

    assert_equal %w[ALPHA MIDDLE ZEBRA], vault.list
  end

  def test_all_returns_full_hash
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault.set("A", "1")
    vault.set("B", "2")

    assert_equal({ "A" => "1", "B" => "2" }, vault.all)
  end

  def test_export_env_format
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault.set("DB_URL", "postgres://localhost/mydb")

    output = vault.export_env
    assert_includes output, 'export DB_URL="postgres://localhost/mydb"'
  end

  def test_open_with_correct_passphrase
    LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault = LocalVault::Vault.open(name: "test", passphrase: test_passphrase)

    vault.set("SECRET", "works")
    assert_equal "works", vault.get("SECRET")
  end

  def test_open_with_wrong_passphrase_raises
    vault = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault.set("SECRET", "data")

    wrong_vault = LocalVault::Vault.open(name: "test", passphrase: "wrong-passphrase")
    assert_raises(LocalVault::Crypto::DecryptionError) { wrong_vault.all }
  end

  def test_open_nonexistent_raises
    assert_raises(RuntimeError) do
      LocalVault::Vault.open(name: "ghost", passphrase: test_passphrase)
    end
  end

  def test_persistence_across_instances
    vault1 = LocalVault::Vault.create!(name: "test", master_key: @master_key, salt: @salt)
    vault1.set("PERSIST", "value")

    vault2 = LocalVault::Vault.new(name: "test", master_key: @master_key)
    assert_equal "value", vault2.get("PERSIST")
  end

  def test_multiple_vaults_independent
    vault_a = LocalVault::Vault.create!(name: "a", master_key: @master_key, salt: @salt)
    salt_b = LocalVault::Crypto.generate_salt
    key_b = LocalVault::Crypto.derive_master_key("other-pass", salt_b)
    vault_b = LocalVault::Vault.create!(name: "b", master_key: key_b, salt: salt_b)

    vault_a.set("KEY", "from-a")
    vault_b.set("KEY", "from-b")

    assert_equal "from-a", vault_a.get("KEY")
    assert_equal "from-b", vault_b.get("KEY")
  end
end
