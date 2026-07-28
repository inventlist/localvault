require_relative "test_helper"
require_relative "../lib/localvault/group_catalog"

class GroupCatalogTest < Minitest::Test
  def test_derives_namespace_prefix_and_mixed_groups
    catalog = LocalVault::GroupCatalog.new(
      "STRIPE" => { "API_KEY" => "nested" },
      "STRIPE_SECRET" => "flat",
      "STRATUS_URL" => "url",
      "UNGROUPED" => "value"
    )

    assert_equal %w[STRATUS STRIPE], catalog.groups.map(&:name)

    stripe = catalog.groups.last
    assert_equal :mixed, stripe.kind
    assert_equal ["API_KEY", "STRIPE_SECRET"], stripe.entries.map(&:label)
    assert_equal 2, stripe.count
  end

  def test_resolves_exact_then_case_insensitive_then_prefix_matches
    catalog = LocalVault::GroupCatalog.new(
      "Stripe" => { "KEY" => "one" },
      "STRIPE" => { "KEY" => "two" },
      "STRATUS_URL" => "url"
    )

    assert_equal "Stripe", catalog.resolve("Stripe").group.name
    assert_equal :ambiguous, catalog.resolve("stripe").kind
    assert_equal :unique, catalog.resolve("stra").kind
    assert_equal :ambiguous, catalog.resolve("str").kind
    assert_equal :absent, catalog.resolve("aws").kind
  end

  def test_search_is_case_insensitive_prefix_matching
    catalog = LocalVault::GroupCatalog.new(
      "STRIPE" => { "KEY" => "one" },
      "STRATUS_URL" => "url",
      "AWS_KEY" => "key"
    )

    assert_equal %w[STRATUS STRIPE], catalog.search("str").map(&:name)
    assert_equal [], catalog.search("missing")
  end
end
