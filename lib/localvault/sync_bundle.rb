require "json"
require "base64"
require "yaml"

module LocalVault
  # Packs and unpacks vault data for cloud sync via InventList + R2.
  #
  # A bundle is a JSON blob containing:
  # - +version+ — bundle format version (currently 2)
  # - +meta+ — base64-encoded meta.yml (salt, name, timestamps)
  # - +secrets+ — base64-encoded secrets.enc (already encrypted)
  # - +key_slots+ — hash of per-user encrypted master keys (v2+)
  #
  # The server never sees plaintext — the bundle is opaque ciphertext.
  # v1 bundles (no key_slots) are supported for backward compatibility.
  #
  # @example Pack and unpack
  #   blob = SyncBundle.pack(store, key_slots: {"alice" => {...}})
  #   data = SyncBundle.unpack(blob, expected_name: "myvault")
  #   data[:meta]      # => YAML string
  #   data[:secrets]   # => encrypted bytes
  #   data[:key_slots] # => {"alice" => {...}}
  module SyncBundle
    # Raised when unpacking fails (bad JSON, missing fields, wrong version, invalid encoding).
    class UnpackError < StandardError; end

    VERSION = 2
    SUPPORTED_VERSIONS = [1, 2].freeze

    # Pack a vault's meta.yml + secrets.enc into a single JSON blob.
    # The secrets.enc is already encrypted — this bundle is opaque to the server.
    # key_slots: optional hash of { "handle" => { "pub" => b64, "enc_key" => b64 }, ... }
    def self.pack(store, key_slots: {})
      meta_content    = File.read(store.meta_path)
      secrets_content = store.read_encrypted || ""
      JSON.generate(
        "version"   => VERSION,
        "meta"      => Base64.strict_encode64(meta_content),
        "secrets"   => Base64.strict_encode64(secrets_content),
        "key_slots" => key_slots
      )
    end

    # Unpack a blob back into {meta:, secrets:, key_slots:}.
    # Pass expected_name: to validate the meta.yml name matches the vault being pulled.
    # v1 bundles return empty key_slots for backward compatibility.
    def self.unpack(blob, expected_name: nil)
      data = JSON.parse(blob)
      version = data["version"]
      raise UnpackError, "Unsupported bundle version: #{version}" if version && !SUPPORTED_VERSIONS.include?(version)

      meta_raw    = Base64.strict_decode64(data.fetch("meta"))
      secrets_raw = Base64.strict_decode64(data.fetch("secrets"))
      key_slots   = data["key_slots"].is_a?(Hash) ? data["key_slots"] : {}

      if expected_name
        meta_parsed = YAML.safe_load(meta_raw)
        actual_name = meta_parsed&.dig("name")
        if actual_name && actual_name != expected_name
          raise UnpackError, "Bundle meta name '#{actual_name}' does not match expected vault '#{expected_name}'"
        end
      end

      { meta: meta_raw, secrets: secrets_raw, key_slots: key_slots }
    rescue JSON::ParserError => e
      raise UnpackError, "Invalid sync bundle format: #{e.message}"
    rescue KeyError => e
      raise UnpackError, "Sync bundle missing required field: #{e.message}"
    rescue ArgumentError => e
      raise UnpackError, "Sync bundle has invalid encoding: #{e.message}"
    end
  end
end
