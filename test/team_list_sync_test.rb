require_relative "test_helper"
require "minitest/mock"
require "localvault/cli"
require "yaml"
require "base64"
require "json"

# LV-031: localvault team list -v vault (sync-based key slots)
class TeamListSyncTest < Minitest::Test
  include LocalVault::TestHelper

  def setup
    setup_test_home
    LocalVault::Config.ensure_directories!
    @salt = LocalVault::Crypto.generate_salt
    @master_key = LocalVault::Crypto.derive_master_key("test-pass", @salt)
    create_test_vault("production")
    LocalVault::Identity.generate!
    LocalVault::Config.token = "tok"
    LocalVault::Config.inventlist_handle = "alice"
    @fake_client = FakeTeamListClient.new
  end

  def teardown
    teardown_test_home
  end

  # ── Normal multi-member output ──

  def test_list_shows_all_slot_holders
    blob = build_blob_with_slots({
      "alice" => slot_entry(LocalVault::Identity.public_key),
      "bob"   => slot_entry("bob_pub_key")
    })
    @fake_client.set_pull_response(blob)

    out, = run_team_list("production")

    assert_match(/alice/, out)
    assert_match(/bob/, out)
  end

  def test_list_marks_current_user
    blob = build_blob_with_slots({
      "alice" => slot_entry(LocalVault::Identity.public_key),
      "bob"   => slot_entry("bob_pub_key")
    })
    @fake_client.set_pull_response(blob)

    out, = run_team_list("production")

    assert_match(/alice.*\(you\)/i, out)
    refute_match(/bob.*\(you\)/i, out)
  end

  # ── Empty slots ──

  def test_list_empty_slots_falls_back_to_shares
    blob = build_blob_with_slots({})
    @fake_client.set_pull_response(blob)

    out, = run_team_list("production")

    # Falls back to shares view — no shares either
    assert_match(/no active shares|no key slots/i, out)
  end

  # ── v1 bundle (no slots) ──

  def test_list_v1_bundle_falls_back_to_shares
    blob = build_v1_blob
    @fake_client.set_pull_response(blob)

    out, = run_team_list("production")

    # v1 has no key_slots — falls back to shares view
    assert_match(/no active shares|no key slots/i, out)
  end

  # ── Malformed slot entries ──

  def test_list_skips_malformed_slot_entries
    blob = build_blob_with_slots({
      "alice"   => slot_entry(LocalVault::Identity.public_key),
      "broken"  => "not a hash",
      "broken2" => 42,
      "broken3" => { "no_pub" => true }
    })
    @fake_client.set_pull_response(blob)

    out, = run_team_list("production")

    assert_match(/alice/, out)
    refute_match(/broken/, out)
  end

  # ── Works offline (reads local bundle) ──
  # The current impl pulls from remote — this test verifies it works
  # even when the remote returns the blob.

  def test_list_shows_slot_count
    blob = build_blob_with_slots({
      "alice" => slot_entry("a_pub"),
      "bob"   => slot_entry("b_pub"),
      "carol" => slot_entry("c_pub")
    })
    @fake_client.set_pull_response(blob)

    out, = run_team_list("production")

    assert_match(/3/, out)
  end

  # ── Not logged in ──

  def test_list_requires_login
    LocalVault::Config.token = nil

    _, err = capture_io do
      LocalVault::CLI.start(["team", "list", "--vault", "production"])
    end

    assert_match(/not connected|not logged/i, err)
  end

  private

  def create_test_vault(name)
    vault = LocalVault::Vault.create!(name: name, master_key: @master_key, salt: @salt)
    vault.set("SECRET", "value")
  end

  def slot_entry(pub_b64)
    { "pub" => pub_b64, "enc_key" => "fake_enc_key_b64" }
  end

  def build_blob_with_slots(slots)
    store = LocalVault::Store.new("production")
    LocalVault::SyncBundle.pack_v3(store, owner: "test", key_slots: slots)
  end

  def build_v1_blob
    store = LocalVault::Store.new("production")
    meta = File.read(store.meta_path)
    secrets = store.read_encrypted || ""
    JSON.generate({
      "version" => 1,
      "meta"    => Base64.strict_encode64(meta),
      "secrets" => Base64.strict_encode64(secrets)
    })
  end

  def run_team_list(vault_name)
    LocalVault::ApiClient.stub(:new, @fake_client) do
      capture_io { LocalVault::CLI.start(["team", "list", "--vault", vault_name]) }
    end
  end
end

class FakeTeamListClient
  def initialize
    @pull_response = ""
    @responses = {}
  end

  def set_pull_response(blob) = @pull_response = blob

  def pull_vault(_name) = @pull_response

  def sent_shares(**_) = { "shares" => [] }

  def method_missing(name, *args, **kwargs) = @responses.fetch(name, {})
  def respond_to_missing?(name, _) = name != :call
end
