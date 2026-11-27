require_relative "test_helper"

# Plan 13 A8: every new passphrase meets a floor.
class PassphrasePolicyTest < Minitest::Test
  def check(p) = LocalVault::PassphrasePolicy.check(p)

  def test_accepts_long_passphrase
    assert_nil check("correct horse battery staple")
    assert_nil check("test-passphrase-for-testing")
  end

  def test_rejects_short
    assert_match(/at least 12 characters/, check("secret123"))
  end

  def test_rejects_empty
    assert_match(/cannot be empty/, check(""))
    assert_match(/cannot be empty/, check(nil))
  end

  def test_rejects_single_repeated_character
    assert_match(/repeat/, check("aaaaaaaaaaaaaaaa"))
  end

  def test_rejects_common_passphrase_case_insensitively
    assert_match(/common/, check("PasswordPassword"))
    assert_match(/common/, check("123456789012"))
  end
end
