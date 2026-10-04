require_relative "test_helper"
require_relative "../lib/localvault/child_env"

# The Homebrew and install.sh wrappers point GEM_HOME/GEM_PATH at localvault's
# private gem dir so localvault can load its own gems. Children started by
# `localvault exec` must get the caller's values back, not localvault's.
class ChildEnvTest < Minitest::Test
  def test_no_overrides_without_the_wrapper_marker
    env = { "GEM_HOME" => "/my/gems", "GEM_PATH" => "/my/gems" }
    assert_equal({}, LocalVault::ChildEnv.overrides(env))
  end

  def test_unsets_wrapper_gem_vars_when_the_caller_had_none
    env = {
      "LOCALVAULT_WRAPPED" => "1",
      "GEM_HOME" => "/opt/homebrew/Cellar/localvault/1.15.0/libexec/gems",
      "GEM_PATH" => "/opt/homebrew/Cellar/localvault/1.15.0/libexec/gems"
    }
    overrides = LocalVault::ChildEnv.overrides(env)

    assert overrides.key?("GEM_HOME")
    assert_nil overrides["GEM_HOME"]
    assert overrides.key?("GEM_PATH")
    assert_nil overrides["GEM_PATH"]
  end

  def test_restores_the_callers_original_gem_vars
    env = {
      "LOCALVAULT_WRAPPED" => "1",
      "LOCALVAULT_ORIG_GEM_HOME" => "/Users/me/.asdf/gems",
      "LOCALVAULT_ORIG_GEM_PATH" => "/Users/me/.asdf/gems:/other",
      "GEM_HOME" => "/opt/homebrew/Cellar/localvault/1.15.0/libexec/gems",
      "GEM_PATH" => "/opt/homebrew/Cellar/localvault/1.15.0/libexec/gems"
    }
    overrides = LocalVault::ChildEnv.overrides(env)

    assert_equal "/Users/me/.asdf/gems", overrides["GEM_HOME"]
    assert_equal "/Users/me/.asdf/gems:/other", overrides["GEM_PATH"]
  end

  def test_restores_an_originally_empty_value_as_empty
    env = { "LOCALVAULT_WRAPPED" => "1", "LOCALVAULT_ORIG_GEM_PATH" => "", "GEM_PATH" => "/lv" }
    assert_equal "", LocalVault::ChildEnv.overrides(env)["GEM_PATH"]
  end

  def test_strips_its_own_bookkeeping_vars
    env = {
      "LOCALVAULT_WRAPPED" => "1",
      "LOCALVAULT_ORIG_GEM_HOME" => "/a",
      "LOCALVAULT_ORIG_GEM_PATH" => "/b"
    }
    overrides = LocalVault::ChildEnv.overrides(env)

    %w[LOCALVAULT_WRAPPED LOCALVAULT_ORIG_GEM_HOME LOCALVAULT_ORIG_GEM_PATH].each do |var|
      assert overrides.key?(var), "expected #{var} to be unset"
      assert_nil overrides[var]
    end
  end

  def test_for_exec_lets_vault_values_win_over_restored_gem_vars
    env = { "LOCALVAULT_WRAPPED" => "1", "GEM_HOME" => "/lv" }
    child = LocalVault::ChildEnv.for_exec({ "GEM_HOME" => "/from/vault", "API_KEY" => "k" }, env)

    assert_equal "/from/vault", child["GEM_HOME"]
    assert_equal "k", child["API_KEY"]
  end

  def test_for_exec_never_lets_the_vault_inject_bookkeeping_vars
    vault_env = {
      "LOCALVAULT_WRAPPED" => "1",
      "LOCALVAULT_ORIG_GEM_HOME" => "/evil",
      "LOCALVAULT_ORIG_GEM_PATH" => "/evil"
    }
    [{}, { "LOCALVAULT_WRAPPED" => "1" }].each do |env|
      child = LocalVault::ChildEnv.for_exec(vault_env, env)
      vault_env.each_key do |var|
        assert child.key?(var), "expected #{var} to be unset"
        assert_nil child[var]
      end
    end
  end

  def test_for_exec_warns_when_it_drops_a_reserved_vault_key
    skipped = []
    LocalVault::ChildEnv.for_exec({ "LOCALVAULT_WRAPPED" => "1", "API_KEY" => "k" }, {}, on_skip: ->(k) { skipped << k })

    assert_equal ["LOCALVAULT_WRAPPED"], skipped
  end

  def test_install_script_wrapper_records_the_callers_gem_env
    script = File.read(File.expand_path("../install.sh", __dir__), encoding: "UTF-8")
    assert_includes script, "export LOCALVAULT_WRAPPED=1"
    assert_includes script, 'export LOCALVAULT_ORIG_GEM_HOME="\$GEM_HOME"'
    assert_includes script, 'export LOCALVAULT_ORIG_GEM_PATH="\$GEM_PATH"'
  end
end
