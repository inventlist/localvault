require "base64"
require "fileutils"
require "json"
require "tempfile"

module LocalVault
  # The user's X25519 identity keypair, used for vault sharing and sync.
  #
  # Stored in +~/.localvault/keys/+:
  # - +identity.pub+ (0644): base64 public key, published so others can
  #   encrypt key slots for you.
  # - +identity.priv+ (0600): the private key. It never leaves this machine.
  #
  # == Private key at rest (plan 13)
  #
  # The private key is encrypted with an identity passphrase, separate from
  # every vault passphrase. The file is a JSON envelope:
  #
  #   { "v": 2, "kdf": "argon2id", "opslimit": 2, "memlimit": 67108864,
  #     "salt": "<b64>", "box": "<b64 nonce + XSalsa20-Poly1305 ciphertext>" }
  #
  # Files written before plan 13 hold the bare base64 key ("legacy"). They
  # still work, print a one-time warning, and are upgraded with
  # +localvault keys protect+.
  #
  # An unlocked key is cached in SessionCache under CACHE_NAME, which can
  # never be a vault name, and +localvault lock+ clears it.
  module Identity
    class Locked < StandardError; end
    class WrongPassphrase < StandardError; end

    CACHE_NAME = ".identity"
    ENVELOPE_VERSION = 2

    def self.priv_key_path = File.join(Config.keys_path, "identity.priv")
    def self.pub_key_path  = File.join(Config.keys_path, "identity.pub")

    # @return [Boolean] true if both key files exist on disk
    def self.exists?
      File.exist?(priv_key_path) && File.exist?(pub_key_path)
    end

    # Generate a new keypair and write it to disk.
    #
    # @param force [Boolean] overwrite an existing keypair
    # @param passphrase [String, nil] identity passphrase. Every CLI path passes
    #   one; nil writes the legacy unprotected format, kept only for
    #   compatibility with older callers and fixtures.
    # @return [Hash{Symbol => String}] +:public_key+ and +:private_key+ raw bytes
    def self.generate!(force: false, passphrase: nil)
      raise "Keypair already exists. Use --force to overwrite." if exists? && !force

      Config.ensure_directories!
      kp = Crypto.generate_keypair
      contents = passphrase ? seal(kp[:private_key], passphrase) : Base64.strict_encode64(kp[:private_key])
      atomic_write(priv_key_path, contents, 0o600)
      atomic_write(pub_key_path, Base64.strict_encode64(kp[:public_key]), 0o644)
      SessionCache.clear(CACHE_NAME)
      SessionCache.set(CACHE_NAME, kp[:private_key]) if passphrase
      kp
    end

    # @return [String, nil] base64 public key, or nil if not generated
    def self.public_key
      return nil unless File.exist?(pub_key_path)
      File.read(pub_key_path).strip
    end

    # @return [Boolean] the private key file is a passphrase-protected envelope
    def self.protected?
      !envelope.nil?
    end

    # @return [Boolean] the private key file exists in the legacy plaintext form
    def self.legacy?
      File.exist?(priv_key_path) && envelope.nil?
    end

    # @return [Boolean] protected and not currently unlocked in the session cache
    def self.locked?
      protected? && SessionCache.get(CACHE_NAME).nil?
    end

    # Raw private key bytes for decrypting key slots and shares.
    #
    # @return [String, nil] 32 raw bytes, or nil when no keypair exists
    # @raise [Locked] when the key is protected and not unlocked this session
    def self.private_key_bytes
      return nil unless File.exist?(priv_key_path)

      if protected?
        cached = SessionCache.get(CACHE_NAME)
        raise Locked, "Identity key is locked. Run: localvault keys unlock" unless cached
        return cached
      end

      warn_legacy_once
      Base64.strict_decode64(File.read(priv_key_path).strip)
    end

    # Decrypt the protected key with +passphrase+ and cache it for the session.
    #
    # @return [String] raw private key bytes
    # @raise [WrongPassphrase] wrong passphrase or tampered file
    def self.unlock(passphrase)
      env = envelope
      raise WrongPassphrase, "Identity key is not passphrase-protected" unless env

      key = open_envelope(env, passphrase)
      SessionCache.set(CACHE_NAME, key)
      key
    end

    # Forget the unlocked key for this session.
    def self.lock!
      SessionCache.clear(CACHE_NAME)
    end

    # Protect a legacy key, or change the passphrase of a protected one.
    #
    # The new file is verified by decrypting it before it atomically replaces
    # the old one, so a failure never leaves you without a usable key.
    #
    # @param new_passphrase [String]
    # @param current_passphrase [String, nil] required when already protected
    # @raise [WrongPassphrase] when the current passphrase does not open the key
    def self.protect!(new_passphrase:, current_passphrase: nil)
      raw = if protected?
              open_envelope(envelope, current_passphrase.to_s)
            else
              Base64.strict_decode64(File.read(priv_key_path).strip)
            end

      sealed = seal(raw, new_passphrase)
      raise "Verification of the re-encrypted identity key failed" unless open_envelope(JSON.parse(sealed), new_passphrase) == raw

      atomic_write(priv_key_path, sealed, 0o600)
      SessionCache.set(CACHE_NAME, raw)
      true
    end

    # @return [Boolean] true if keypair exists and an API token is configured
    def self.setup?
      exists? && !Config.token.nil? && !Config.token.empty?
    end

    # Test hook: allow the legacy warning to print again.
    def self.reset_legacy_warning!
      @legacy_warned = false
    end

    # ── internals ───────────────────────────────────────────────

    def self.seal(raw_private_key, passphrase)
      salt = Crypto.generate_salt
      key = Crypto.derive_master_key(passphrase, salt)
      JSON.generate(
        "v"        => ENVELOPE_VERSION,
        "kdf"      => "argon2id",
        "opslimit" => Crypto::ARGON2_OPSLIMIT,
        "memlimit" => Crypto::ARGON2_MEMLIMIT,
        "salt"     => Base64.strict_encode64(salt),
        "box"      => Base64.strict_encode64(Crypto.encrypt(raw_private_key, key))
      )
    end
    private_class_method :seal

    def self.open_envelope(env, passphrase)
      salt = Base64.strict_decode64(env.fetch("salt"))
      key = RbNaCl::PasswordHash.argon2id(
        passphrase.to_s, salt,
        Integer(env.fetch("opslimit")), Integer(env.fetch("memlimit")),
        Crypto::KEY_BYTES
      )
      Crypto.decrypt(Base64.strict_decode64(env.fetch("box")), key)
    rescue Crypto::DecryptionError, KeyError, ArgumentError, TypeError
      raise WrongPassphrase, "Wrong identity passphrase (or the key file is damaged)"
    end
    private_class_method :open_envelope

    def self.envelope
      return nil unless File.exist?(priv_key_path)
      parsed = JSON.parse(File.read(priv_key_path))
      parsed.is_a?(Hash) && parsed["v"] == ENVELOPE_VERSION ? parsed : nil
    rescue JSON::ParserError
      nil
    end
    private_class_method :envelope

    def self.warn_legacy_once
      return if @legacy_warned
      @legacy_warned = true
      $stderr.puts "Warning: your identity private key is stored without a passphrase. " \
                   "Run: localvault keys protect"
    end
    private_class_method :warn_legacy_once

    def self.atomic_write(path, contents, mode)
      dir = File.dirname(path)
      tmp = Tempfile.create([".#{File.basename(path)}", ".tmp"], dir)
      tmp.write(contents)
      tmp.flush
      tmp.fsync
      tmp.close
      File.chmod(mode, tmp.path)
      File.rename(tmp.path, path)
    ensure
      FileUtils.rm_f(tmp.path) if tmp && File.exist?(tmp.path)
    end
    private_class_method :atomic_write
  end
end
