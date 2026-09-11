require_relative "test_helper"
require "localvault/sync_merge"

class SyncMergeTest < Minitest::Test
  M = LocalVault::SyncMerge

  def keys(changes)
    changes.map { |c| [c.key, c.kind] }
  end

  def test_no_changes
    r = M.merge({ "A" => "1" }, { "A" => "1" }, { "A" => "1" })
    assert r.clean?
    assert_equal({ "A" => "1" }, r.merged)
    assert_empty r.local_changes
    assert_empty r.remote_changes
  end

  def test_local_only_changes_apply
    base   = { "A" => "1", "B" => "2", "C" => "3" }
    local  = { "A" => "1x", "C" => "3", "D" => "4" }   # modify A, delete B, add D
    remote = base.dup
    r = M.merge(base, local, remote)
    assert r.clean?
    assert_equal({ "A" => "1x", "C" => "3", "D" => "4" }, r.merged)
    assert_equal [["A", :modified], ["B", :deleted], ["D", :added]], keys(r.local_changes)
    assert_empty r.remote_changes
  end

  def test_remote_only_changes_apply
    base   = { "A" => "1", "B" => "2" }
    local  = base.dup
    remote = { "A" => "1", "B" => "2y", "E" => "5" }
    r = M.merge(base, local, remote)
    assert r.clean?
    assert_equal({ "A" => "1", "B" => "2y", "E" => "5" }, r.merged)
    assert_equal [["B", :modified], ["E", :added]], keys(r.remote_changes)
  end

  def test_both_sides_different_keys_merge_cleanly
    base   = { "A" => "1" }
    local  = { "A" => "1", "L" => "l" }
    remote = { "A" => "1", "R" => "r" }
    r = M.merge(base, local, remote)
    assert r.clean?
    assert_equal({ "A" => "1", "L" => "l", "R" => "r" }, r.merged)
  end

  def test_same_change_both_sides_is_not_conflict
    base   = { "A" => "1" }
    r = M.merge(base, { "A" => "2" }, { "A" => "2" })
    assert r.clean?
    assert_equal [["A", :modified]], keys(r.same_changes)
  end

  def test_conflict_when_both_modify_differently
    base   = { "A" => "1", "B" => "2" }
    local  = { "A" => "L", "B" => "2" }
    remote = { "A" => "R", "B" => "2" }
    r = M.merge(base, local, remote)
    refute r.clean?
    assert_equal [["A", :both_modified]], keys(r.conflicts)
    # Unresolved conflict keeps local so nothing is lost
    assert_equal "L", r.merged["A"]
  end

  def test_conflict_delete_vs_modify
    base = { "A" => "1" }
    r = M.merge(base, {}, { "A" => "2" })
    assert_equal [["A", :local_deleted]], keys(r.conflicts)
    r = M.merge(base, { "A" => "2" }, {})
    assert_equal [["A", :remote_deleted]], keys(r.conflicts)
  end

  def test_prefer_local_resolves
    base = { "A" => "1" }
    r = M.merge(base, { "A" => "L" }, { "A" => "R" }, prefer: :local)
    assert r.clean?
    assert_equal "L", r.merged["A"]
  end

  def test_prefer_remote_resolves_including_delete
    base = { "A" => "1" }
    r = M.merge(base, { "A" => "L" }, {}, prefer: :remote)
    assert r.clean?
    refute r.merged.key?("A")
  end

  def test_per_key_picks_override_prefer
    base   = { "A" => "1", "B" => "1" }
    local  = { "A" => "AL", "B" => "BL" }
    remote = { "A" => "AR", "B" => "BR" }
    r = M.merge(base, local, remote, prefer: :remote, picks: { "A" => :local })
    assert r.clean?
    assert_equal({ "A" => "AL", "B" => "BR" }, r.merged)
  end

  def test_groups_flatten_and_unflatten
    base   = { "app" => { "DB" => "1", "KEY" => "k" }, "TOP" => "t" }
    local  = { "app" => { "DB" => "2", "KEY" => "k" }, "TOP" => "t" }
    remote = { "app" => { "DB" => "1", "KEY" => "k", "NEW" => "n" }, "TOP" => "t2" }
    r = M.merge(base, local, remote)
    assert r.clean?
    assert_equal({ "app" => { "DB" => "2", "KEY" => "k", "NEW" => "n" }, "TOP" => "t2" }, r.merged)
    assert_equal [["app.DB", :modified]], keys(r.local_changes)
    assert_equal [["TOP", :modified], ["app.NEW", :added]], keys(r.remote_changes)
  end

  def test_group_deleted_entirely_on_one_side
    base  = { "app" => { "DB" => "1" } }
    r = M.merge(base, {}, base)
    assert r.clean?
    assert_equal({}, r.merged)
  end

  def test_no_base_is_union_with_conflicts_on_shared_keys
    local  = { "A" => "1", "L" => "l" }
    remote = { "A" => "2", "R" => "r" }
    r = M.merge(nil, local, remote)
    assert_equal [["A", :both_modified]], keys(r.conflicts)
    assert_equal [["L", :added]], keys(r.local_changes)
    assert_equal [["R", :added]], keys(r.remote_changes)
    assert_equal({ "A" => "1", "L" => "l", "R" => "r" }, r.merged)
  end

  def test_no_base_identical_shared_keys_are_fine
    r = M.merge(nil, { "A" => "1" }, { "A" => "1" })
    assert r.clean?
    assert_empty r.local_changes + r.remote_changes
  end

  def test_scalar_to_group_by_remote_while_local_deletes_is_structural_conflict
    base   = { "app" => "old" }
    local  = {}
    remote = { "app" => { "X" => "new" } }
    r = M.merge(base, local, remote)
    assert_equal [["app", :structure]], keys(r.conflicts)
    assert_equal({}, r.merged, "unresolved keeps local side")

    r = M.merge(base, local, remote, prefer: :remote)
    assert r.clean?
    assert_equal({ "app" => { "X" => "new" } }, r.merged)

    r = M.merge(base, local, remote, picks: { "app" => :local })
    assert r.clean?
    assert_equal({}, r.merged)
  end

  def test_group_to_scalar_by_remote_while_local_deletes_is_structural_conflict
    base   = { "app" => { "X" => "1" } }
    r = M.merge(base, {}, { "app" => "s" })
    assert_equal [["app", :structure]], keys(r.conflicts)
  end

  def test_scalar_to_group_on_one_side_only_is_clean
    base   = { "app" => "old", "K" => "1" }
    local  = base.dup
    remote = { "app" => { "X" => "new" }, "K" => "1" }
    r = M.merge(base, local, remote)
    assert r.clean?
    assert_equal({ "app" => { "X" => "new" }, "K" => "1" }, r.merged)
  end

  def test_no_base_shape_disagreement_is_structural_conflict
    r = M.merge(nil, { "app" => "s" }, { "app" => { "X" => "1" } })
    assert_equal [["app", :structure]], keys(r.conflicts)
    r = M.merge(nil, { "app" => "s" }, { "app" => { "X" => "1" } }, prefer: :local)
    assert_equal({ "app" => "s" }, r.merged)
  end

  def test_unflatten_collision_raises
    assert_raises(M::StructureError) { M.unflatten({ "app" => "s", "app.X" => "1" }) }
    assert_raises(M::StructureError) { M.unflatten({ "app.X" => "1", "app" => "s" }) }
  end

  def test_report_never_carries_values
    r = M.merge({ "A" => "1" }, { "A" => "L" }, { "A" => "R" })
    (r.local_changes + r.remote_changes + r.conflicts + r.same_changes).each do |c|
      assert_equal [:key, :kind], c.to_h.keys
    end
  end
end
