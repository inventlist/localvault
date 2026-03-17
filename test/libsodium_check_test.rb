require_relative "test_helper"

class LibsodiumCheckTest < Minitest::Test
  def test_missing_libsodium_shows_install_instructions
    # Simulate what happens when rbnacl can't find libsodium
    # by loading crypto.rb in a subprocess with a broken library path
    output = `DYLD_LIBRARY_PATH=/nonexistent LD_LIBRARY_PATH=/nonexistent ruby -e '
      # Override rbnacl to simulate libsodium missing
      module Kernel
        alias_method :original_require, :require
        def require(name)
          if name == "rbnacl"
            raise LoadError, "Could not open library libsodium"
          end
          original_require(name)
        end
      end
      load "#{File.expand_path("../../lib/localvault/crypto.rb", __FILE__)}"
    ' 2>&1`

    assert_includes output, "libsodium is not installed"
    assert_includes output, "brew install libsodium"
    assert_includes output, "apt-get install libsodium-dev"
    assert_includes output, "dnf install libsodium-devel"
    assert_includes output, "pacman -S libsodium"
    assert_includes output, "apk add libsodium-dev"
  end

  def test_libsodium_present_loads_normally
    # This test confirms rbnacl loads fine in the current environment
    require "rbnacl"
    assert defined?(RbNaCl::SecretBox), "rbnacl should load when libsodium is present"
  end
end
