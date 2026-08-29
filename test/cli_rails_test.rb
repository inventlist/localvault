require_relative "test_helper"
require "localvault/cli"
require "localvault/cli/rails_import"
require "fileutils"

class CLIRailsTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    salt = LocalVault::Crypto.generate_salt
    key  = LocalVault::Crypto.derive_master_key("pw", salt)
    LocalVault::Vault.create!(name: "default", master_key: key, salt: salt)
    LocalVault::SessionCache.set("default", key)

    @app = File.join(@test_home, "app")
    FileUtils.mkdir_p(File.join(@app, "config/credentials"))
    File.write(File.join(@app, "config/credentials.yml.enc"), "encrypted")
    @pwd = Dir.pwd
  end

  def teardown
    Dir.chdir(@pwd)
    teardown_test_home
  end

  def test_finds_master_key_and_environment_keys
    File.write(File.join(@app, "config/master.key"), "aaaa1111\n")
    File.write(File.join(@app, "config/credentials/production.key"), "bbbb2222\n")

    keys = LocalVault::CLI::RailsImport.new(@app).keys

    assert_equal %w[rails.master_key rails.production_key], keys.map(&:vault_key)
    assert_equal "aaaa1111", keys.first.value, "trailing newline must be stripped"
    assert_equal "production", keys.last.environment
  end

  def test_import_stores_keys_and_leaves_files_alone
    File.write(File.join(@app, "config/master.key"), "aaaa1111")
    Dir.chdir(@app)

    out, = capture_io { LocalVault::CLI.start(%w[rails]) }

    vault = LocalVault::Vault.open(name: "default", passphrase: "pw")
    assert_equal "aaaa1111", vault.all.dig("rails", "master_key")
    assert File.exist?(File.join(@app, "config/master.key")), "must not delete the key file"
    assert_match(/still on disk/, out)
    assert_match(/your call/, out)
  end

  def test_check_writes_nothing
    File.write(File.join(@app, "config/master.key"), "aaaa1111")
    Dir.chdir(@app)

    out, = capture_io { LocalVault::CLI.start(%w[rails --check]) }

    vault = LocalVault::Vault.open(name: "default", passphrase: "pw")
    assert_nil vault.all["rails"]
    assert_match(/Would import/, out)
  end

  def test_outside_a_rails_app_it_says_so
    Dir.chdir(@test_home)
    _, err = capture_io { LocalVault::CLI.start(%w[rails]) }

    assert_match(/No Rails app here/, err)
  end

  # Rails reads no variable other than RAILS_MASTER_KEY, so the profile has to
  # land the key under exactly that name.
  def test_rails_profile_maps_master_key_to_rails_master_key
    entries = LocalVault::EnvProjection.entries(
      { "rails" => { "master_key" => "aaaa1111" }, "OTHER" => "x" },
      profile: "rails"
    )

    assert_equal ["RAILS_MASTER_KEY"], entries.map(&:env_name)
    assert_equal "aaaa1111", entries.first.value
  end

  def test_environment_mapping_targets_rails_master_key
    assert_equal({ "rails.production_key" => "RAILS_MASTER_KEY" },
                 LocalVault::EnvProjection.rails_environment_mapping("production"))
  end
end
