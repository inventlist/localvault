require_relative "test_helper"

# FakeApiClient overrides the low-level request method so tests
# never hit the network.
class FakeApiClient < LocalVault::ApiClient
  attr_reader :last_method, :last_path, :last_body

  def initialize(token: "fake-token", base_url: "http://test.local")
    super(token: token, base_url: base_url)
    @response = {}
    @error    = nil
  end

  def set_response(data)   = @response = data
  def set_error(msg, status: 422) = @error = LocalVault::ApiClient::ApiError.new(msg, status: status)

  private

  def request(method, path, body = nil)
    @last_method = method
    @last_path   = path
    @last_body   = body
    raise @error if @error
    @response
  end
end

class ApiClientTest < Minitest::Test
  def setup
    @client = FakeApiClient.new
  end

  def test_get_public_key_calls_correct_path
    @client.set_response({ "handle" => "bob", "public_key" => "abc123" })
    result = @client.get_public_key("bob")
    assert_equal :get, @client.last_method
    assert_equal "/users/bob/public_key", @client.last_path
    assert_equal "bob", result["handle"]
  end

  def test_publish_public_key_sends_put
    @client.set_response({ "handle" => "alice", "public_key" => "xyz" })
    @client.publish_public_key("xyz")
    assert_equal :put, @client.last_method
    assert_equal "/profile/public_key", @client.last_path
    assert_equal({ public_key: "xyz" }, @client.last_body)
  end

  def test_pending_shares_calls_correct_path
    @client.set_response({ "shares" => [] })
    result = @client.pending_shares
    assert_equal :get, @client.last_method
    assert_equal "/vault_shares/pending", @client.last_path
    assert_equal [], result["shares"]
  end

  def test_sent_shares_without_vault_name
    @client.set_response({ "shares" => [] })
    @client.sent_shares
    assert_equal "/vault_shares/sent", @client.last_path
  end

  def test_sent_shares_with_vault_name
    @client.set_response({ "shares" => [] })
    @client.sent_shares(vault_name: "production")
    assert_includes @client.last_path, "vault_name=production"
  end

  def test_create_share_sends_post
    @client.set_response({ "id" => 1 })
    @client.create_share(vault_name: "work", recipient_handle: "bob", encrypted_payload: "enc")
    assert_equal :post, @client.last_method
    assert_equal "/vault_shares", @client.last_path
    assert_equal "work",  @client.last_body[:vault_name]
    assert_equal "bob",   @client.last_body[:recipient_handle]
    assert_equal "enc",   @client.last_body[:encrypted_payload]
  end

  def test_accept_share_sends_patch
    @client.set_response({ "id" => 5, "status" => "accepted" })
    @client.accept_share(5)
    assert_equal :patch, @client.last_method
    assert_equal "/vault_shares/5/accept", @client.last_path
  end

  def test_revoke_share_sends_delete
    @client.set_response({ "id" => 3, "status" => "revoked" })
    @client.revoke_share(3)
    assert_equal :delete, @client.last_method
    assert_equal "/vault_shares/3", @client.last_path
  end

  def test_team_public_keys_calls_correct_path
    @client.set_response({ "members" => [], "missing_count" => 0 })
    @client.team_public_keys("acme")
    assert_equal :get, @client.last_method
    assert_equal "/teams/acme/members/public_keys", @client.last_path
  end

  def test_crew_public_keys_calls_correct_path
    @client.set_response({ "members" => [], "missing_count" => 0 })
    @client.crew_public_keys("my-site")
    assert_equal :get, @client.last_method
    assert_equal "/sites/my-site/crew/public_keys", @client.last_path
  end

  def test_api_error_raised_on_set_error
    @client.set_error("Recipient not found", status: 404)
    err = assert_raises(LocalVault::ApiClient::ApiError) { @client.get_public_key("nobody") }
    assert_equal "Recipient not found", err.message
    assert_equal 404, err.status
  end
end
