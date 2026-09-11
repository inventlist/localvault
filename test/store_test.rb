require_relative "test_helper"

class StoreTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @salt = LocalVault::Crypto.generate_salt
  end

  def teardown
    teardown_test_home
  end

  def test_vault_path
    store = LocalVault::Store.new("default")
    expected = File.join(@test_home, "vaults", "default")
    assert_equal expected, store.vault_path
  end

  def test_exists_false_when_no_vault
    store = LocalVault::Store.new("nonexistent")
    refute store.exists?
  end

  def test_create_and_exists
    store = LocalVault::Store.new("test-vault")
    store.create!(salt: @salt)
    assert store.exists?
  end

  def test_create_raises_if_already_exists
    store = LocalVault::Store.new("test-vault")
    store.create!(salt: @salt)

    assert_raises(RuntimeError) { store.create!(salt: @salt) }
  end

  def test_meta_returns_vault_metadata
    store = LocalVault::Store.new("test-vault")
    store.create!(salt: @salt)

    meta = store.meta
    assert_equal "test-vault", meta["name"]
    assert_equal 1, meta["version"]
    assert meta["created_at"]
    assert meta["salt"]
  end

  def test_salt_roundtrip
    store = LocalVault::Store.new("test-vault")
    store.create!(salt: @salt)

    assert_equal @salt, store.salt
  end

  def test_read_encrypted_returns_nil_when_no_file
    store = LocalVault::Store.new("test-vault")
    store.create!(salt: @salt)
    assert_nil store.read_encrypted
  end

  def test_write_and_read_encrypted_roundtrip
    store = LocalVault::Store.new("test-vault")
    store.create!(salt: @salt)

    data = ("\x00\x01\x02\xFF" * 100).b
    store.write_encrypted(data)

    assert_equal data, store.read_encrypted
  end

  def test_write_encrypted_is_atomic
    store = LocalVault::Store.new("test-vault")
    store.create!(salt: @salt)

    # Write initial data
    store.write_encrypted("first")

    # Write again — should overwrite atomically
    store.write_encrypted("second")
    assert_equal "second", store.read_encrypted
  end

  def test_list_vaults_empty
    assert_equal [], LocalVault::Store.list_vaults
  end

  def test_list_vaults_returns_sorted_names
    LocalVault::Store.new("beta").create!(salt: @salt)
    LocalVault::Store.new("alpha").create!(salt: @salt)
    LocalVault::Store.new("gamma").create!(salt: @salt)

    assert_equal %w[alpha beta gamma], LocalVault::Store.list_vaults
  end

  def test_list_vaults_ignores_non_vault_entries
    LocalVault::Store.new("ok").create!(salt: @salt)
    vaults_dir = LocalVault::Config.vaults_path
    FileUtils.mkdir_p(File.join(vaults_dir, "Bad Name!"))   # invalid name
    FileUtils.mkdir_p(File.join(vaults_dir, "no-meta"))     # valid name, not a vault
    FileUtils.mkdir_p(File.join(vaults_dir, ".hidden"))
    File.write(File.join(vaults_dir, "stray.txt"), "")

    assert_equal %w[ok], LocalVault::Store.list_vaults
    assert_equal ["Bad Name!", "no-meta", "stray.txt"], LocalVault::Store.stray_entries
    LocalVault::Store.list_vaults.each { |n| LocalVault::Store.new(n) } # never raises
  end
end
