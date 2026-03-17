require_relative "test_helper"
require_relative "../lib/localvault/cli"
require "base64"
require "json"

# Audit round 3 — resolve_recipients nil check + receive vault name sanitization.
class AuditRound3Test < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key(test_passphrase, @salt)
  end

  def teardown
    teardown_test_home
  end

  # ── Finding 1: resolve_recipients must reject nil public keys ──

  def test_resolve_recipients_skips_nil_public_key
    cli = LocalVault::CLI.new
    fake = FakeRecipientsClient.new
    fake.set_response({ "handle" => "bob", "public_key" => nil })

    recipients = cli.send(:resolve_recipients, fake, "@bob")
    assert_empty recipients, "Should skip recipient with nil public_key"
  end

  def test_resolve_recipients_skips_nil_handle
    cli = LocalVault::CLI.new
    fake = FakeRecipientsClient.new
    fake.set_response({ "handle" => nil, "public_key" => "abc123" })

    recipients = cli.send(:resolve_recipients, fake, "@bob")
    assert_empty recipients, "Should skip recipient with nil handle"
  end

  def test_resolve_recipients_passes_valid_response
    cli = LocalVault::CLI.new
    fake = FakeRecipientsClient.new
    fake.set_response({ "handle" => "bob", "public_key" => "validkey" })

    recipients = cli.send(:resolve_recipients, fake, "@bob")
    assert_equal [["bob", "validkey"]], recipients
  end

  def test_resolve_recipients_team_skips_members_without_keys
    cli = LocalVault::CLI.new
    fake = FakeRecipientsClient.new
    fake.set_team_response({
      "members" => [
        { "handle" => "alice", "public_key" => "key1" },
        { "handle" => "bob", "public_key" => nil },
        { "handle" => nil, "public_key" => "key3" }
      ]
    })

    recipients = cli.send(:resolve_recipients, fake, "team:acme")
    assert_equal 1, recipients.size
    assert_equal "alice", recipients[0][0]
  end

  # ── Finding 2: receive vault name must be safe even with untrusted API data ──

  def test_receive_vault_name_sanitizes_sender_handle
    # A sender handle with characters that would fail Store validation
    # should be sanitized, not crash
    name = build_receive_vault_name("production", "evil/../../admin")
    assert_match(/\A[a-zA-Z0-9][a-zA-Z0-9_\-]*\z/, name,
      "Constructed vault name must pass Store validation")
  end

  def test_receive_vault_name_sanitizes_vault_name_from_api
    name = build_receive_vault_name("../traversal", "bob")
    assert_match(/\A[a-zA-Z0-9][a-zA-Z0-9_\-]*\z/, name,
      "Constructed vault name must pass Store validation")
  end

  def test_receive_vault_name_normal_case
    name = build_receive_vault_name("default", "nauman")
    assert_equal "default-from-nauman", name
  end

  private

  # Simulate the vault name construction from receive command
  def build_receive_vault_name(vault_name, sender_handle)
    LocalVault::CLI.new.send(:sanitize_receive_vault_name, vault_name, sender_handle)
  end
end

# Fake client for testing resolve_recipients
class FakeRecipientsClient
  def initialize
    @response = {}
    @team_response = { "members" => [] }
  end

  def set_response(data) = @response = data
  def set_team_response(data) = @team_response = data

  def get_public_key(_handle) = @response
  def team_public_keys(_handle) = @team_response
  def crew_public_keys(_slug) = @team_response
end
