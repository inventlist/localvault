require_relative "test_helper"
require "json"
require "base64"

# Plan 13 A1–A5: the identity private key is passphrase-encrypted at rest.
class IdentityProtectionTest < Minitest::Test
  include LocalVault::TestHelper

  PASS = "correct horse battery staple"

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
  end

  def teardown
    LocalVault::Identity.lock!
    teardown_test_home
  end

  def priv_file = File.read(LocalVault::Identity.priv_key_path)

  # A1
  def test_generate_with_passphrase_writes_v2_envelope_without_raw_key
    kp = LocalVault::Identity.generate!(passphrase: PASS)
    envelope = JSON.parse(priv_file)

    assert_equal 2, envelope["v"]
    assert_equal "argon2id", envelope["kdf"]
    assert envelope["salt"] && envelope["box"]
    refute_includes priv_file, Base64.strict_encode64(kp[:private_key])
    assert_equal 0o600, File.stat(LocalVault::Identity.priv_key_path).mode & 0o777
    assert LocalVault::Identity.protected?
    refute LocalVault::Identity.legacy?
  end

  # A2
  def test_unlock_returns_raw_key_and_wrong_passphrase_raises
    kp = LocalVault::Identity.generate!(passphrase: PASS)
    LocalVault::Identity.lock!

    assert_raises(LocalVault::Identity::WrongPassphrase) { LocalVault::Identity.unlock("nope nope nope") }
    assert_equal kp[:private_key], LocalVault::Identity.unlock(PASS)
  end

  def test_tampered_envelope_is_refused
    LocalVault::Identity.generate!(passphrase: PASS)
    LocalVault::Identity.lock!
    envelope = JSON.parse(priv_file)
    box = Base64.strict_decode64(envelope["box"])
    box.setbyte(box.bytesize - 1, box.getbyte(box.bytesize - 1) ^ 0x01)
    envelope["box"] = Base64.strict_encode64(box)
    File.write(LocalVault::Identity.priv_key_path, JSON.generate(envelope))

    assert_raises(LocalVault::Identity::WrongPassphrase) { LocalVault::Identity.unlock(PASS) }
  end

  def test_locked_protected_key_raises_locked_instead_of_returning_bytes
    LocalVault::Identity.generate!(passphrase: PASS)
    LocalVault::Identity.lock!

    assert LocalVault::Identity.locked?
    assert_raises(LocalVault::Identity::Locked) { LocalVault::Identity.private_key_bytes }
  end

  # A3
  def test_legacy_file_still_decrypts_key_slots
    kp = LocalVault::Identity.generate! # no passphrase → legacy format
    master = RbNaCl::Random.random_bytes(32)
    slot = LocalVault::KeySlot.create(master, Base64.strict_encode64(kp[:public_key]))

    assert LocalVault::Identity.legacy?
    refute LocalVault::Identity.locked?
    assert_equal master, LocalVault::KeySlot.decrypt(slot, LocalVault::Identity.private_key_bytes)
  end

  # A4
  def test_protect_migrates_legacy_to_v2_with_same_key
    kp = LocalVault::Identity.generate!
    LocalVault::Identity.protect!(new_passphrase: PASS)

    assert LocalVault::Identity.protected?
    LocalVault::Identity.lock!
    assert_equal kp[:private_key], LocalVault::Identity.unlock(PASS)
    assert_equal Base64.strict_encode64(kp[:public_key]), LocalVault::Identity.public_key
  end

  def test_protect_changes_v2_passphrase_and_requires_current
    kp = LocalVault::Identity.generate!(passphrase: PASS)
    LocalVault::Identity.lock!

    assert_raises(LocalVault::Identity::WrongPassphrase) do
      LocalVault::Identity.protect!(new_passphrase: "another long passphrase", current_passphrase: "wrong wrong wrong")
    end
    LocalVault::Identity.protect!(new_passphrase: "another long passphrase", current_passphrase: PASS)
    LocalVault::Identity.lock!

    assert_raises(LocalVault::Identity::WrongPassphrase) { LocalVault::Identity.unlock(PASS) }
    assert_equal kp[:private_key], LocalVault::Identity.unlock("another long passphrase")
  end

  # A5
  def test_unlock_caches_under_reserved_name_and_lock_clears
    kp = LocalVault::Identity.generate!(passphrase: PASS)
    LocalVault::Identity.lock!
    LocalVault::Identity.unlock(PASS)

    assert_equal kp[:private_key], LocalVault::SessionCache.get(LocalVault::Identity::CACHE_NAME)
    refute LocalVault::Identity.locked?
    assert_equal kp[:private_key], LocalVault::Identity.private_key_bytes

    LocalVault::Identity.lock!
    assert_nil LocalVault::SessionCache.get(LocalVault::Identity::CACHE_NAME)
  end

  def test_clear_all_sessions_also_clears_identity
    LocalVault::Identity.generate!(passphrase: PASS)
    LocalVault::SessionCache.clear_all
    assert LocalVault::Identity.locked?
  end

  def test_reserved_cache_name_cannot_be_a_vault_name
    refute LocalVault::Identity::CACHE_NAME.match?(LocalVault::Store::VAULT_NAME_PATTERN)
  end
end
