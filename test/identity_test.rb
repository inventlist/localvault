require_relative "test_helper"

class IdentityTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
  end

  def teardown
    teardown_test_home
  end

  def test_exists_returns_false_when_no_keypair
    refute LocalVault::Identity.exists?
  end

  def test_generate_creates_keypair_files
    LocalVault::Identity.generate!
    assert File.exist?(LocalVault::Identity.priv_key_path)
    assert File.exist?(LocalVault::Identity.pub_key_path)
  end

  def test_exists_returns_true_after_generate
    LocalVault::Identity.generate!
    assert LocalVault::Identity.exists?
  end

  def test_generate_sets_private_key_permissions
    LocalVault::Identity.generate!
    mode = File.stat(LocalVault::Identity.priv_key_path).mode & 0o777
    assert_equal 0o600, mode
  end

  def test_generate_raises_if_keypair_exists_without_force
    LocalVault::Identity.generate!
    assert_raises(RuntimeError) { LocalVault::Identity.generate! }
  end

  def test_generate_with_force_overwrites
    LocalVault::Identity.generate!
    first_pub = LocalVault::Identity.public_key
    LocalVault::Identity.generate!(force: true)
    refute_equal first_pub, LocalVault::Identity.public_key
  end

  def test_public_key_returns_nil_when_no_keypair
    assert_nil LocalVault::Identity.public_key
  end

  def test_public_key_returns_base64_string
    LocalVault::Identity.generate!
    key = LocalVault::Identity.public_key
    refute_nil key
    decoded = Base64.strict_decode64(key)
    assert_equal 32, decoded.bytesize
  end

  def test_private_key_bytes_returns_nil_when_no_keypair
    assert_nil LocalVault::Identity.private_key_bytes
  end

  def test_private_key_bytes_returns_32_bytes
    LocalVault::Identity.generate!
    bytes = LocalVault::Identity.private_key_bytes
    refute_nil bytes
    assert_equal 32, bytes.bytesize
  end

  def test_setup_false_when_no_keypair_or_token
    refute LocalVault::Identity.setup?
  end

  def test_setup_false_when_keypair_but_no_token
    LocalVault::Identity.generate!
    refute LocalVault::Identity.setup?
  end

  def test_setup_true_when_keypair_and_token_set
    LocalVault::Identity.generate!
    LocalVault::Config.token = "abc123"
    assert LocalVault::Identity.setup?
  end
end
