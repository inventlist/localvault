require "net/http"
require "uri"
require "json"

module LocalVault
  # HTTP client for the InventList API (vault sync, sharing, public keys).
  #
  # All requests use Bearer token auth. Timeouts: 10s open, 30s read/write.
  # Network and timeout errors are wrapped as ApiError so callers get a
  # consistent exception type.
  #
  # @example
  #   client = ApiClient.new(token: "tok-...", base_url: "https://inventlist.com")
  #   client.me                         # => {"user" => {"handle" => "nauman"}}
  #   client.push_vault("prod", blob)   # => {"name" => "prod", ...}
  #   client.pull_vault("prod")         # => raw binary blob
  class ApiClient
    # Raised on HTTP errors, network failures, and timeouts.
    class ApiError < StandardError
      attr_reader :status

      def initialize(msg, status: nil)
        super(msg)
        @status = status
      end
    end

    BASE_PATH = "/api/v1"

    # Create a new API client.
    #
    # @param token [String] Bearer token for authentication
    # @param base_url [String, nil] API base URL (defaults to Config.api_url)
    def initialize(token:, base_url: nil)
      @token    = token
      @base_url = base_url || Config.api_url
    end

    # Fetch the authenticated user's profile.
    #
    # @return [Hash] user data (e.g. {"user" => {"handle" => "nauman"}})
    # @raise [ApiError] on HTTP or network failure
    def me
      get("/me")
    end

    # Fetch a user's X25519 public key by handle.
    #
    # @param handle [String] the user's InventList handle
    # @return [Hash] key data (e.g. {"public_key" => "base64..."})
    # @raise [ApiError] on HTTP or network failure
    def get_public_key(handle)
      get("/users/#{URI.encode_uri_component(handle)}/public_key")
    end

    # Upload the current user's X25519 public key to InventList.
    #
    # @param public_key_b64 [String] base64-encoded X25519 public key
    # @return [Hash] confirmation response
    # @raise [ApiError] on HTTP or network failure
    def publish_public_key(public_key_b64)
      put("/profile/public_key", { public_key: public_key_b64 })
    end

    # List vault shares pending acceptance by the current user.
    #
    # @return [Hash] shares data (e.g. {"shares" => [...]})
    # @raise [ApiError] on HTTP or network failure
    def pending_shares
      get("/vault_shares/pending")
    end

    # List vault shares sent by the current user, optionally filtered by vault.
    #
    # @param vault_name [String, nil] filter by vault name (all shares if nil)
    # @return [Hash] shares data (e.g. {"shares" => [...]})
    # @raise [ApiError] on HTTP or network failure
    def sent_shares(vault_name: nil)
      path = "/vault_shares/sent"
      path += "?vault_name=#{URI.encode_uri_component(vault_name)}" if vault_name
      get(path)
    end

    # Create a new vault share for a recipient.
    #
    # @param vault_name [String] name of the vault being shared
    # @param recipient_handle [String] InventList handle of the recipient
    # @param encrypted_payload [String] base64-encoded encrypted secrets from ShareCrypto
    # @return [Hash] created share data
    # @raise [ApiError] on HTTP or network failure
    def create_share(vault_name:, recipient_handle:, encrypted_payload:)
      post("/vault_shares", {
        vault_name:        vault_name,
        recipient_handle:  recipient_handle,
        encrypted_payload: encrypted_payload
      })
    end

    # Accept a pending vault share.
    #
    # @param id [Integer, String] the share ID to accept
    # @return [Hash] updated share data
    # @raise [ApiError] on HTTP or network failure
    def accept_share(id)
      patch("/vault_shares/#{URI.encode_uri_component(id.to_s)}/accept", {})
    end

    # Revoke (delete) a vault share.
    #
    # @param id [Integer, String] the share ID to revoke
    # @return [Hash] confirmation response
    # @raise [ApiError] on HTTP or network failure
    def revoke_share(id)
      delete("/vault_shares/#{URI.encode_uri_component(id.to_s)}")
    end

    # Fetch public keys for all members of a team.
    #
    # @param team_handle [String] the team's InventList handle
    # @return [Hash] member keys (e.g. {"members" => [{"handle" => "...", "public_key" => "..."}]})
    # @raise [ApiError] on HTTP or network failure
    def team_public_keys(team_handle)
      get("/teams/#{URI.encode_uri_component(team_handle)}/members/public_keys")
    end

    # Fetch public keys for all crew members of a site.
    #
    # @param site_slug [String] the site's slug
    # @return [Hash] crew keys (e.g. {"members" => [{"handle" => "...", "public_key" => "..."}]})
    # @raise [ApiError] on HTTP or network failure
    def crew_public_keys(site_slug)
      get("/sites/#{URI.encode_uri_component(site_slug)}/crew/public_keys")
    end

    # List all vaults stored in the cloud for the authenticated user.
    #
    # @return [Hash] vaults data (e.g. {"vaults" => [{"name" => "prod", ...}]})
    # @raise [ApiError] on HTTP or network failure
    def list_vaults
      get("/vaults")
    end

    # Upload a vault bundle to the cloud (raw binary).
    #
    # @param name [String] vault name
    # @param blob [String] packed SyncBundle binary blob
    # @return [Hash] confirmation with vault metadata
    # @raise [ApiError] on HTTP or network failure
    def push_vault(name, blob)
      request_binary(:put, "/vaults/#{URI.encode_uri_component(name)}", blob)
    end

    # Download a vault bundle from the cloud (raw binary).
    #
    # @param name [String] vault name
    # @return [String] raw binary blob for SyncBundle.unpack
    # @raise [ApiError] on HTTP or network failure (404 if vault not found)
    def pull_vault(name)
      request_raw(:get, "/vaults/#{URI.encode_uri_component(name)}")
    end

    # Delete a vault from the cloud.
    #
    # @param name [String] vault name to delete
    # @return [Hash] confirmation response
    # @raise [ApiError] on HTTP or network failure
    def delete_vault(name)
      delete("/vaults/#{URI.encode_uri_component(name)}")
    end

    private

    def get(path)
      request(:get, path)
    end

    def post(path, body)
      request(:post, path, body)
    end

    def put(path, body)
      request(:put, path, body)
    end

    def patch(path, body = nil)
      request(:patch, path, body)
    end

    def delete(path)
      request(:delete, path)
    end

    def request(method, path, body = nil)
      uri  = URI("#{@base_url}#{BASE_PATH}#{path}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout  = 10
      http.read_timeout  = 30
      http.write_timeout = 30

      req_class = {
        get:    Net::HTTP::Get,
        post:   Net::HTTP::Post,
        put:    Net::HTTP::Put,
        patch:  Net::HTTP::Patch,
        delete: Net::HTTP::Delete
      }.fetch(method)

      req = req_class.new(uri.request_uri)
      req["Authorization"] = "Bearer #{@token}"
      req["Content-Type"]  = "application/json"
      req["Accept"]        = "application/json"
      req.body = JSON.generate(body) if body

      res = http.request(req)
      unless res.is_a?(Net::HTTPSuccess)
        err = begin JSON.parse(res.body)["error"] rescue nil end
        raise ApiError.new(err || "HTTP #{res.code}", status: res.code.to_i)
      end
      JSON.parse(res.body)
    rescue Errno::ECONNREFUSED, SocketError, Net::OpenTimeout, Net::ReadTimeout, Net::WriteTimeout => e
      raise ApiError.new("Cannot connect to #{@base_url}: #{e.message}")
    end

    # PUT /api/v1/vaults/:name — sends raw binary body, expects JSON response
    def request_binary(method, path, blob)
      uri  = URI("#{@base_url}#{BASE_PATH}#{path}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout  = 10
      http.read_timeout  = 30
      http.write_timeout = 30

      req_class = { put: Net::HTTP::Put }.fetch(method)
      req = req_class.new(uri.request_uri)
      req["Authorization"] = "Bearer #{@token}"
      req["Content-Type"]  = "application/octet-stream"
      req["Accept"]        = "application/json"
      req.body = blob

      res = http.request(req)
      unless res.is_a?(Net::HTTPSuccess)
        err = begin JSON.parse(res.body)["error"] rescue nil end
        raise ApiError.new(err || "HTTP #{res.code}", status: res.code.to_i)
      end
      JSON.parse(res.body)
    rescue Errno::ECONNREFUSED, SocketError, Net::OpenTimeout, Net::ReadTimeout, Net::WriteTimeout => e
      raise ApiError.new("Cannot connect to #{@base_url}: #{e.message}")
    end

    # GET /api/v1/vaults/:name — returns raw binary body
    def request_raw(method, path)
      uri  = URI("#{@base_url}#{BASE_PATH}#{path}")
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == "https"
      http.open_timeout  = 10
      http.read_timeout  = 30
      http.write_timeout = 30

      req_class = { get: Net::HTTP::Get }.fetch(method)
      req = req_class.new(uri.request_uri)
      req["Authorization"] = "Bearer #{@token}"
      req["Accept"]        = "application/octet-stream"

      res = http.request(req)
      unless res.is_a?(Net::HTTPSuccess)
        err = begin JSON.parse(res.body)["error"] rescue nil end
        raise ApiError.new(err || "HTTP #{res.code}", status: res.code.to_i)
      end
      res.body
    rescue Errno::ECONNREFUSED, SocketError, Net::OpenTimeout, Net::ReadTimeout, Net::WriteTimeout => e
      raise ApiError.new("Cannot connect to #{@base_url}: #{e.message}")
    end
  end
end
