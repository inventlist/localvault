require "json"
require "base64"
require "digest"

module LocalVault
  module SyncBundle
    VERSION = 1

    # Pack a vault's meta.yml + secrets.enc into a single JSON blob.
    # The secrets.enc is already encrypted — this bundle is opaque to the server.
    def self.pack(store)
      meta_content    = File.read(store.meta_path)
      secrets_content = store.read_encrypted || ""
      JSON.generate(
        "version" => VERSION,
        "meta"    => Base64.strict_encode64(meta_content),
        "secrets" => Base64.strict_encode64(secrets_content)
      )
    end

    # Unpack a blob back into {meta:, secrets:} strings.
    def self.unpack(blob)
      data = JSON.parse(blob)
      {
        meta:    Base64.strict_decode64(data.fetch("meta")),
        secrets: Base64.strict_decode64(data.fetch("secrets"))
      }
    end
  end
end
