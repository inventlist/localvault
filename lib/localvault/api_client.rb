require "net/http"
require "uri"
require "json"

module LocalVault
  class ApiClient
    class ApiError < StandardError
      attr_reader :status

      def initialize(msg, status: nil)
        super(msg)
        @status = status
      end
    end

    BASE_PATH = "/api/v1"

    def initialize(token:, base_url: nil)
      @token    = token
      @base_url = base_url || Config.api_url
    end

    # GET /api/v1/users/:handle/public_key
    def get_public_key(handle)
      get("/users/#{handle}/public_key")
    end

    # PUT /api/v1/profile/public_key
    def publish_public_key(public_key_b64)
      put("/profile/public_key", { public_key: public_key_b64 })
    end

    # GET /api/v1/vault_shares/pending
    def pending_shares
      get("/vault_shares/pending")
    end

    # GET /api/v1/vault_shares/sent?vault_name=NAME
    def sent_shares(vault_name: nil)
      path = "/vault_shares/sent"
      path += "?vault_name=#{URI.encode_uri_component(vault_name)}" if vault_name
      get(path)
    end

    # POST /api/v1/vault_shares
    def create_share(vault_name:, recipient_handle:, encrypted_payload:)
      post("/vault_shares", {
        vault_name:        vault_name,
        recipient_handle:  recipient_handle,
        encrypted_payload: encrypted_payload
      })
    end

    # PATCH /api/v1/vault_shares/:id/accept
    def accept_share(id)
      patch("/vault_shares/#{id}/accept", {})
    end

    # DELETE /api/v1/vault_shares/:id
    def revoke_share(id)
      delete("/vault_shares/#{id}")
    end

    # GET /api/v1/teams/:handle/members/public_keys
    def team_public_keys(team_handle)
      get("/teams/#{team_handle}/members/public_keys")
    end

    # GET /api/v1/sites/:slug/crew/public_keys
    def crew_public_keys(site_slug)
      get("/sites/#{site_slug}/crew/public_keys")
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
    rescue Errno::ECONNREFUSED, SocketError => e
      raise ApiError.new("Cannot connect to #{@base_url}: #{e.message}")
    end
  end
end
