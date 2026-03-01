require "minitest/autorun"
require "tmpdir"
require "fileutils"
require_relative "../lib/localvault"

module LocalVault
  module TestHelper
    def setup_test_home
      @original_home = ENV["LOCALVAULT_HOME"]
      @test_home = Dir.mktmpdir("localvault-test")
      ENV["LOCALVAULT_HOME"] = @test_home
    end

    def teardown_test_home
      FileUtils.rm_rf(@test_home) if @test_home && File.exist?(@test_home)
      if @original_home
        ENV["LOCALVAULT_HOME"] = @original_home
      else
        ENV.delete("LOCALVAULT_HOME")
      end
    end

    def test_passphrase
      "test-passphrase-for-testing"
    end
  end
end
