require_relative "test_helper"
require_relative "../lib/localvault/input_validation"

class InputValidationTest < Minitest::Test
  def test_accepts_valid_env_dsl_inputs
    assert_equal "AWS_IAM.*", LocalVault::InputValidation.selector!("AWS_IAM.*")
    assert_equal ["A.B", "ENV_NAME"], LocalVault::InputValidation.mapping!("A.B", "ENV_NAME")
    assert_equal "payments", LocalVault::InputValidation.project!("payments")
    assert_equal "production", LocalVault::InputValidation.vault_name!("production")
    assert_equal ["ruby", "-e", "puts 1"], LocalVault::InputValidation.argv!(["ruby", "-e", "puts 1"])
    assert_equal "aws", LocalVault::InputValidation.profile!("aws")
  end

  def test_rejects_reserved_delimiters_wildcard_mappings_and_nul
    invalid = [
      -> { LocalVault::InputValidation.selector!("A,B") },
      -> { LocalVault::InputValidation.selector!("A=B") },
      -> { LocalVault::InputValidation.mapping!("A.*", "ENV_NAME") },
      -> { LocalVault::InputValidation.mapping!("A.B", "BAD-NAME") },
      -> { LocalVault::InputValidation.argv!(["ruby", "bad\0token"]) },
      -> { LocalVault::InputValidation.profile!("bogus") }
    ]

    invalid.each { |call| assert_raises(LocalVault::InputValidation::InvalidInput, &call) }
  end
end
