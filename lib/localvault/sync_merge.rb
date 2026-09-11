require "json"

module LocalVault
  # Three-way merge of vault secrets: base (last synced), local, remote.
  #
  # Works on flattened dot-notation keys (+"app.DB_URL"+) so groups and
  # scalars compare uniformly. Values never leave this module in any report —
  # callers get key names plus change kinds, which is all a human needs to
  # decide, and all that is safe to print.
  #
  # Rules per key:
  # - unchanged on both sides                    → keep
  # - changed on one side only                   → take that side
  # - changed on both sides to the same value    → keep
  # - changed on both sides to different values  → conflict
  #
  # "changed" covers add, modify and delete relative to base. With no base
  # (first sync between two pre-existing vaults) nothing can be proven
  # deleted, so the merge is a union: keys on one side only are added, keys
  # on both sides with different values are conflicts.
  module SyncMerge
    # Raised when merged keys cannot coexist in one nested hash, e.g. a scalar
    # +app+ from one side and a group +app.X+ from the other.
    class StructureError < StandardError; end

    Change = Struct.new(:key, :kind, keyword_init: true)

    # Result of a merge. +merged+ is the nested secrets hash ready to write;
    # +conflicts+ is a list of keys that still need a human choice.
    Result = Struct.new(:merged, :local_changes, :remote_changes, :conflicts, :same_changes,
                        :conflict_keys_before_picks, keyword_init: true) do
      def clean?
        conflicts.empty?
      end
    end

    # @param base [Hash, nil] nested secrets at last sync, nil if unknown
    # @param local [Hash] nested secrets on disk
    # @param remote [Hash] nested secrets in the cloud bundle
    # @param prefer [Symbol, nil] +:local+ or +:remote+ — resolves every conflict
    # @param picks [Hash{String => Symbol}] per-key resolution, key => :local | :remote
    # @return [Result]
    def self.merge(base, local, remote, prefer: nil, picks: {})
      b = base ? flatten(base) : nil
      l = flatten(local)
      r = flatten(remote)

      merged         = {}
      local_changes  = []
      remote_changes = []
      same_changes   = []
      conflicts      = []

      structural = structural_conflicts(base, local, remote)
      structural.each do |root|
        side = picks[root] || prefer
        source = side == :remote ? r : l
        source.each { |k, v| merged[k] = v if root_of(k) == root }
        conflicts << Change.new(key: root, kind: :structure) unless %i[local remote].include?(side)
      end

      (l.keys | r.keys | (b ? b.keys : [])).sort.each do |key|
        next if structural.include?(root_of(key))
        bv = b && b[key]
        lv = l[key]
        rv = r[key]

        local_changed  = b ? lv != bv : false
        remote_changed = b ? rv != bv : false

        if b.nil?
          # No ancestor: union, conflict only when both present and different.
          if lv && rv && lv != rv
            resolve_conflict(key, lv, rv, prefer, picks, merged, conflicts)
          elsif lv.nil?
            merged[key] = rv
            remote_changes << Change.new(key: key, kind: :added)
          elsif rv.nil?
            merged[key] = lv
            local_changes << Change.new(key: key, kind: :added)
          else
            merged[key] = lv
          end
          next
        end

        if !local_changed && !remote_changed
          merged[key] = lv unless lv.nil?
        elsif local_changed && !remote_changed
          merged[key] = lv unless lv.nil?
          local_changes << Change.new(key: key, kind: kind_of(bv, lv))
        elsif !local_changed && remote_changed
          merged[key] = rv unless rv.nil?
          remote_changes << Change.new(key: key, kind: kind_of(bv, rv))
        elsif lv == rv
          merged[key] = lv unless lv.nil?
          same_changes << Change.new(key: key, kind: kind_of(bv, lv))
        else
          resolve_conflict(key, lv, rv, prefer, picks, merged, conflicts)
        end
      end

      Result.new(
        merged:         unflatten(merged),
        local_changes:  local_changes,
        remote_changes: remote_changes,
        same_changes:   same_changes,
        conflicts:      conflicts
      )
    end

    # Flatten one level of grouping into dot keys. Values are stringified so
    # comparison is by content, matching how +Vault#set+ stores them.
    #
    # @param hash [Hash] nested secrets
    # @return [Hash{String => String}]
    def self.flatten(hash)
      out = {}
      hash.each do |k, v|
        if v.is_a?(Hash)
          v.each { |sk, sv| out["#{k}.#{sk}"] = sv.to_s }
        else
          out[k.to_s] = v.to_s
        end
      end
      out
    end

    # Inverse of +flatten+. Raises +StructureError+ when a scalar and a group
    # share a name.
    #
    # @param flat [Hash{String => String}]
    # @return [Hash]
    def self.unflatten(flat)
      out = {}
      flat.each do |key, value|
        if key.include?(".")
          group, sub = key.split(".", 2)
          out[group] ||= {}
          raise StructureError, "'#{group}' is both a secret and a group" unless out[group].is_a?(Hash)
          out[group][sub] = value
        else
          raise StructureError, "'#{key}' is both a secret and a group" if out[key].is_a?(Hash)
          out[key] = value
        end
      end
      out
    end

    # Roots whose shape (scalar / group / absent) differs between local and
    # remote, with both sides having moved away from base. With no base, only
    # a present-on-both scalar-vs-group disagreement is structural; a key
    # missing on one side is an ordinary addition.
    def self.structural_conflicts(base, local, remote)
      roots = local.keys | remote.keys | (base ? base.keys : [])
      roots.select do |root|
        lk = shape(local[root])
        rk = shape(remote[root])
        next false if lk == rk
        next(lk != :absent && rk != :absent) if base.nil?
        bk = shape(base[root])
        lk != bk && rk != bk
      end
    end

    def self.shape(value)
      return :absent if value.nil?
      value.is_a?(Hash) ? :group : :scalar
    end

    def self.root_of(key)
      key.split(".", 2).first
    end

    def self.kind_of(before, after)
      return :deleted if after.nil?
      return :added   if before.nil?
      :modified
    end

    def self.resolve_conflict(key, lv, rv, prefer, picks, merged, conflicts)
      side = picks[key] || prefer
      case side
      when :local
        merged[key] = lv unless lv.nil?
      when :remote
        merged[key] = rv unless rv.nil?
      else
        # Leave local in place so an unresolved merge never drops a key.
        merged[key] = lv unless lv.nil?
        conflicts << Change.new(key: key, kind: conflict_kind(lv, rv))
      end
    end

    # Describe a conflict without values: which side deleted, or both modified.
    def self.conflict_kind(lv, rv)
      return :local_deleted  if lv.nil?
      return :remote_deleted if rv.nil?
      :both_modified
    end

    private_class_method :kind_of, :resolve_conflict, :conflict_kind, :structural_conflicts, :shape, :root_of
  end
end
