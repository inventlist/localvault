module LocalVault
  # The Homebrew and install.sh wrappers point GEM_HOME/GEM_PATH at
  # localvault's private gem dir so localvault loads its own gems. Before
  # doing that they set LOCALVAULT_WRAPPED=1 and save the caller's values as
  # LOCALVAULT_ORIG_<VAR> (left unset when the caller had none).
  #
  # Children started by `localvault exec` must see the caller's Ruby
  # environment, not localvault's, or Bundler in the child resolves the app's
  # gems against localvault's libexec. `overrides` returns the env-hash
  # entries for Kernel.exec that hand those values back (nil unsets).
  module ChildEnv
    MARKER = "LOCALVAULT_WRAPPED".freeze
    WRAPPER_VARS = %w[GEM_HOME GEM_PATH].freeze
    BOOKKEEPING_VARS = [MARKER, *WRAPPER_VARS.map { |var| "LOCALVAULT_ORIG_#{var}" }].freeze

    # The full env hash for Kernel.exec: caller's gem vars restored, vault
    # values on top, and the wrapper's bookkeeping vars always unset — a vault
    # key must not be able to plant them for a nested localvault.
    def self.for_exec(vault_env, env = ENV, on_skip: nil)
      (vault_env.keys & BOOKKEEPING_VARS).each { |var| on_skip&.call(var) }
      overrides(env).merge(vault_env).merge(BOOKKEEPING_VARS.to_h { |var| [var, nil] })
    end

    def self.overrides(env = ENV)
      return {} unless env[MARKER]

      WRAPPER_VARS.each_with_object(MARKER => nil) do |var, result|
        saved = "LOCALVAULT_ORIG_#{var}"
        result[var] = env[saved]
        result[saved] = nil
      end
    end
  end
end
