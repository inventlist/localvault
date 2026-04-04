require "json"
require "base64"
require "yaml"

module LocalVault
  # Packs and unpacks vault data for cloud sync via InventList + R2.
  #
  # Bundle versions:
  # - v1: personal sync — +{ version, meta, secrets }+
  # - v2: legacy team — +{ version, meta, secrets, key_slots }+
  # - v3: team with ownership — +{ version, owner, meta, secrets, key_slots }+
  #
  # The server never sees plaintext — the bundle is opaque ciphertext.
  #
  # @example Personal sync (v1)
  #   blob = SyncBundle.pack(store)
  #
  # @example Team sync (v3)
  #   blob = SyncBundle.pack_v3(store, owner: "alice", key_slots: slots)
  #   data = SyncBundle.unpack(blob)
  #   data[:owner]     # => "alice"
  #   data[:key_slots] # => {"alice" => {...}, "bob" => {...}}
  module SyncBundle
    # Raised when unpacking fails (bad JSON, missing fields, wrong version, invalid encoding).
    class UnpackError < StandardError; end

    SUPPORTED_VERSIONS = [1, 2, 3].freeze

    # Pack a personal vault — v1 format, no key_slots, no owner.
    #
    # @param store [Store] the vault store to pack
    # @return [String] JSON string ready for upload
    def self.pack(store)
      meta_content    = File.read(store.meta_path)
      secrets_content = store.read_encrypted || ""
      JSON.generate(
        "version" => 1,
        "meta"    => Base64.strict_encode64(meta_content),
        "secrets" => Base64.strict_encode64(secrets_content)
      )
    end

    # Pack a team vault — v3 format with owner, key_slots, and per-member blobs.
    #
    # @param store [Store] the vault store to pack
    # @param owner [String] the owner's InventList handle
    # @param key_slots [Hash] per-user key slot data
    # @return [String] JSON string ready for upload
    def self.pack_v3(store, owner:, key_slots: {})
      meta_content    = File.read(store.meta_path)
      secrets_content = store.read_encrypted || ""
      JSON.generate(
        "version"   => 3,
        "owner"     => owner,
        "meta"      => Base64.strict_encode64(meta_content),
        "secrets"   => Base64.strict_encode64(secrets_content),
        "key_slots" => key_slots
      )
    end

    # Unpack any version bundle into its component parts.
    #
    # @param blob [String] JSON string from ApiClient#pull_vault
    # @param expected_name [String, nil] if set, validates the meta.yml vault name matches
    # @return [Hash] +{meta:, secrets:, key_slots:, owner:}+
    # @raise [UnpackError] on invalid format, unsupported version, or name mismatch
    def self.unpack(blob, expected_name: nil)
      data = JSON.parse(blob)
      version = data["version"]
      raise UnpackError, "Unsupported bundle version: #{version}" if version && !SUPPORTED_VERSIONS.include?(version)

      meta_raw    = Base64.strict_decode64(data.fetch("meta"))
      secrets_raw = Base64.strict_decode64(data.fetch("secrets"))
      key_slots   = data["key_slots"].is_a?(Hash) ? data["key_slots"] : {}
      owner       = data["owner"]

      if expected_name
        meta_parsed = YAML.safe_load(meta_raw)
        actual_name = meta_parsed&.dig("name")
        if actual_name && actual_name != expected_name
          raise UnpackError, "Bundle meta name '#{actual_name}' does not match expected vault '#{expected_name}'"
        end
      end

      { meta: meta_raw, secrets: secrets_raw, key_slots: key_slots, owner: owner }
    rescue JSON::ParserError => e
      raise UnpackError, "Invalid sync bundle format: #{e.message}"
    rescue KeyError => e
      raise UnpackError, "Sync bundle missing required field: #{e.message}"
    rescue ArgumentError => e
      raise UnpackError, "Sync bundle has invalid encoding: #{e.message}"
    end
  end
end
