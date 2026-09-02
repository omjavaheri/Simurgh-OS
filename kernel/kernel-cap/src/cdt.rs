//! ============================================================================
//! cdt.rs
//!
//! Purpose: the Capability Derivation Tree (CDT) and its backing storage.
//! Tracks the parent/child relationships between capabilities so that
//! revoking one capability also invalidates every capability derived from
//! it, including a capability that was `CapGrant`ed into a DIFFERENT
//! capability space than the one it was derived in — the mechanism behind
//! 02-Microkernel-Layer.md's requirement (line 65) that "the kernel must be
//! able to invalidate a capability and all of its derivatives... similar to
//! seL4".
//!
//! Architecture reference: 02-Microkernel-Layer.md §2 (Capability model, CDT,
//! revocation — explicitly modelled on seL4, not a custom design) and §1.1
//! (grant/revoke carry structured pre/post-condition comments intended to
//! become proof annotations for Kani/Prusti later).
//!
//! Position in the system: owned by `kernel-core`'s `KernelState`, one
//! `CapTable` per `CapabilitySpace`. The syscall dispatcher calls
//! `derive_child`/`derive_child_cross_space` for `CapGrant`/duplicate and
//! `revoke_cross_space` for `CapRevoke` (02-Microkernel-Layer.md §6). Never
//! reachable from user space except through those syscalls.
//!
//! Cross-space design: a CDT parent link is a `GlobalCapId` (space + slot),
//! not a bare `CapId` — so a derivation edge can point into a capability
//! space other than the one holding the child. This means a granted
//! capability, once moved into the grantee's space, is STILL a real CDT
//! child of the capability it was derived from, and `revoke_cross_space`
//! (which scans every table handed to it, not just one) reaches it. There is
//! deliberately no `first_child`/sibling list any more — parent pointers can
//! now span tables, so maintaining a doubly-linked child list would require
//! mutating a THIRD table's slot on every insert/remove (whichever table
//! holds the old first child). Revocation instead does a bounded, allocation-
//! free, two-pass scan over the tables it is given (see `revoke_cross_space`).
//!
//! Safety/invariants (hold between every public call):
//!   1. A slot is "occupied" iff `cap.is_some()`; "free" otherwise.
//!   2. Free slots form a singly linked list from `free_head`; occupied
//!      slots are never on that list.
//!   3. For every occupied slot `c` with `parent == Some(p)`: `p.cap` names
//!      an occupied slot in the `CapTable` for `p.space` (possibly a
//!      DIFFERENT table than the one holding `c`).
//!   4. `c.cap.rights` is a subset of `parent.cap.rights` for every
//!      non-root `c` (rights never escalate along a derivation edge).
//!   5. The parent links contain no cycles: following `parent` from any
//!      node reaches a root (`parent == None`) in finitely many steps.
//! ============================================================================

use crate::{CapId, CapSpaceId, Capability, CapabilityRights};

/// Errors returned by `CapTable` operations. Flat and `Copy`, matching
/// `hal_core::HalError`'s rationale: the caller (the syscall dispatcher)
/// turns any of these into a `SyscallError` and returns it to user space;
/// there is no rich recovery to dispatch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapTableError {
    /// No free slot remains in this capability space. User space must
    /// `revoke` something (or the Root Task must `retype` a larger
    /// `CapabilitySpace`) before another capability can be created.
    Full,
    /// The referenced `CapId` is outside this table, or names a free slot.
    EmptySlot,
    /// A derive requested rights not held by the parent capability
    /// (invariant 4 would be violated).
    RightsEscalation,
    /// A derive requested a badge that conflicts with the parent's
    /// write-once badge (parent already badged with a different value).
    BadgeConflict,
}

/// A capability identified by which capability space it lives in plus its
/// slot within that space. CDT `parent` links are `GlobalCapId`s (not bare
/// `CapId`s) precisely so a derivation edge can point into a different
/// space than the child it labels — see the module doc comment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GlobalCapId {
    /// The capability space the referenced slot lives in.
    pub space: CapSpaceId,
    /// The slot within that space.
    pub cap: CapId,
}

impl GlobalCapId {
    /// Constructs a `GlobalCapId`. `const` so boot-time wiring can build
    /// one without a runtime call.
    pub const fn new(space: CapSpaceId, cap: CapId) -> Self {
        Self { space, cap }
    }
}

/// One capability-table slot: a capability plus its CDT parent link.
/// `Copy` so a `[CapSlot; N]` can be constructed from `CapSlot::EMPTY`
/// without `unsafe` zeroing or an allocator.
#[derive(Debug, Clone, Copy)]
pub struct CapSlot {
    /// The capability held here, or `None` if this slot is free.
    pub cap: Option<Capability>,
    /// Parent in the derivation tree, or `None` for a root capability
    /// (one seeded by boot-time wiring in `kernel-core`, §8.1). May name a
    /// slot in a different `CapTable` than this one (see module doc).
    pub parent: Option<GlobalCapId>,
    /// Free-list link: the next free slot's id, while this slot is free.
    /// Meaningless (and left `None`) while the slot is occupied — this is
    /// purely allocator bookkeeping, not a CDT link, so it stays private.
    free_next: Option<CapId>,
}

impl CapSlot {
    /// A free slot with no capability and no links.
    pub const EMPTY: Self = Self {
        cap: None,
        parent: None,
        free_next: None,
    };
}

/// A fixed-capacity capability space: `N` slots, an intrusive CDT, and a
/// free list. One of these backs each `CapabilitySpace` kernel object
/// (02-Microkernel-Layer.md §3). `N` is chosen per space by `kernel-core`
/// when it `retype`s the space object (IMPLEMENTATION-PLAN.md D2).
pub struct CapTable<const N: usize> {
    slots: [CapSlot; N],
    /// Head of the free-slot list, or `None` when the table is full.
    free_head: Option<CapId>,
    /// Number of occupied slots — cheap `is_empty`/`len` and a loop-free
    /// fullness check.
    occupied: usize,
    /// Which capability space this table backs. Stamped into every child's
    /// `parent` link this table produces via `derive_child`, so the link
    /// remains resolvable even after the child capability is later granted
    /// into a different table (`derive_child_cross_space`'s `dst`).
    space_id: CapSpaceId,
}

impl<const N: usize> CapTable<N> {
    /// Creates an empty table with every slot on the free list, stamped as
    /// backing capability space `space_id`.
    ///
    /// Postcondition: `len() == 0`; `lookup(c)` is `None` for all `c`;
    /// the free list threads slots `0..N` in order.
    pub fn new(space_id: CapSpaceId) -> Self {
        let mut slots = [CapSlot::EMPTY; N];
        // Thread the free list: slot i points at slot i+1, last points at
        // nothing. Done once here so allocation is a single pop.
        let mut i = 0;
        while i < N {
            slots[i].free_next = if i + 1 < N {
                Some(CapId::new((i + 1) as u32))
            } else {
                None
            };
            i += 1;
        }
        Self {
            slots,
            free_head: if N > 0 { Some(CapId::new(0)) } else { None },
            occupied: 0,
            space_id,
        }
    }

    /// The capability space this table backs (see the `space_id` field doc).
    pub fn space_id(&self) -> CapSpaceId {
        self.space_id
    }

    /// Number of occupied slots.
    pub fn len(&self) -> usize {
        self.occupied
    }

    /// True if no capability is stored.
    pub fn is_empty(&self) -> bool {
        self.occupied == 0
    }

    /// True if no free slot remains.
    pub fn is_full(&self) -> bool {
        self.free_head.is_none()
    }

    /// Borrows the capability at `id`, or `None` if `id` is out of range or
    /// names a free slot.
    pub fn lookup(&self, id: CapId) -> Option<&Capability> {
        self.slots.get(id.as_usize()).and_then(|s| s.cap.as_ref())
    }

    /// Mutably borrows the capability at `id`. Only the `badge`/`rights`
    /// fields should ever be touched through this, and only by
    /// `kernel-core` — never to widen rights (invariant 4).
    pub fn lookup_mut(&mut self, id: CapId) -> Option<&mut Capability> {
        self.slots.get_mut(id.as_usize()).and_then(|s| s.cap.as_mut())
    }

    /// The CDT parent link stored at `id`, or `None` if `id` is out of
    /// range, free, or a root. Used by `revoke_cross_space`'s ancestry
    /// walk, which may be looking at a slot in a different table than the
    /// one it started from.
    fn parent_of(&self, id: CapId) -> Option<GlobalCapId> {
        self.slots.get(id.as_usize()).and_then(|s| s.parent)
    }

    // ------------------------------------------------------------------
    // Slot allocation (private): pop the free list head.
    // ------------------------------------------------------------------
    fn alloc_slot(&mut self) -> Result<CapId, CapTableError> {
        let id = self.free_head.ok_or(CapTableError::Full)?;
        let slot = &mut self.slots[id.as_usize()];
        // The freed slot's `free_next` is the next free entry.
        self.free_head = slot.free_next.take();
        *slot = CapSlot::EMPTY;
        self.occupied += 1;
        Ok(id)
    }

    // ------------------------------------------------------------------
    // Slot release (private): push onto the free list. The caller (either
    // `revoke_cross_space` or a future same-table op) is responsible for
    // having already decided `id` should be freed — this does no CDT
    // bookkeeping of its own, since parent links are look-up-only, not a
    // maintained list.
    // ------------------------------------------------------------------
    fn free_slot(&mut self, id: CapId) {
        let old_head = self.free_head;
        let slot = &mut self.slots[id.as_usize()];
        *slot = CapSlot::EMPTY;
        slot.free_next = old_head;
        self.free_head = Some(id);
        self.occupied -= 1;
    }

    /// Inserts a root capability (no parent). Used only by `kernel-core`
    /// boot wiring to seed a fresh `CapabilitySpace` with the initial
    /// `UntypedMemory` / object capabilities the Root Task starts with
    /// (02-Microkernel-Layer.md §3, §8.1).
    ///
    /// Precondition: none beyond "table not full".
    /// Postcondition on `Ok(c)`: slot `c` occupied with `cap`, `parent ==
    /// None`; `len()` increased by one.
    pub fn insert_root(&mut self, cap: Capability) -> Result<CapId, CapTableError> {
        let id = self.alloc_slot()?;
        self.slots[id.as_usize()].cap = Some(cap);
        Ok(id)
    }

    // ------------------------------------------------------------------
    // Shared derive logic for both the same-table (`derive_child`) and
    // cross-table (`derive_child_cross_space`) entry points: validate
    // rights/badge against an already-looked-up parent capability, then
    // allocate the child slot in `dst` and stamp its `parent` link.
    // ------------------------------------------------------------------
    fn insert_derived(
        dst: &mut Self,
        parent_cap: Capability,
        parent_global: GlobalCapId,
        rights: CapabilityRights,
        badge: u64,
    ) -> Result<CapId, CapTableError> {
        if !rights.is_subset_of(parent_cap.rights) {
            return Err(CapTableError::RightsEscalation);
        }

        let effective_badge = if parent_cap.badge != 0 {
            // Parent already badged: child must not ask for a different one.
            if badge != 0 && badge != parent_cap.badge {
                return Err(CapTableError::BadgeConflict);
            }
            parent_cap.badge
        } else {
            badge
        };

        let child = dst.alloc_slot()?;
        let slot = &mut dst.slots[child.as_usize()];
        slot.cap = Some(Capability {
            object: parent_cap.object,
            rights,
            badge: effective_badge,
        });
        slot.parent = Some(parent_global);
        Ok(child)
    }

    /// Derives a child capability from `parent` (in this same table),
    /// narrowing rights to `rights` and (optionally) stamping `badge`. Used
    /// for same-space duplication (02-Microkernel-Layer.md §2, §6) — a
    /// `CapGrant` into a different space uses `derive_child_cross_space`
    /// instead.
    ///
    /// Preconditions:
    ///   - `parent` names an occupied slot (else `EmptySlot`).
    ///   - `rights.is_subset_of(parent.rights)` (else `RightsEscalation`)
    ///     — enforces invariant 4.
    ///   - `badge` is `0`, or equals the parent's badge, or the parent is
    ///     unbadged (`badge == 0` on the parent). Otherwise `BadgeConflict`
    ///     — badges are write-once (02-Microkernel-Layer.md §2).
    ///   - the table is not full (else `Full`).
    ///
    /// Postconditions on `Ok(child)`:
    ///   - slot `child` is occupied; `child.cap.object == parent.object`;
    ///     `child.cap.rights == rights`; `child.cap.badge` is the effective
    ///     badge (see below).
    ///   - `child.parent == Some(GlobalCapId::new(self.space_id(), parent))`.
    ///   - all five table invariants still hold.
    ///
    /// Effective badge: the parent's badge if the parent is badged,
    /// otherwise `badge`.
    pub fn derive_child(
        &mut self,
        parent: CapId,
        rights: CapabilityRights,
        badge: u64,
    ) -> Result<CapId, CapTableError> {
        let parent_cap = *self.lookup(parent).ok_or(CapTableError::EmptySlot)?;
        let parent_global = GlobalCapId::new(self.space_id, parent);
        Self::insert_derived(self, parent_cap, parent_global, rights, badge)
    }
}

impl<const N: usize> Default for CapTable<N> {
    fn default() -> Self {
        Self::new(CapSpaceId::new(0))
    }
}

/// Derives a child capability from `parent` in `src` (backing space
/// `src_space`) directly into `dst`, a `CapTable` in a DIFFERENT capability
/// space — the mechanism behind `CapGrant`
/// (02-Microkernel-Layer.md §2, §6). Unlike the MVP's earlier
/// derive-then-move sequence, this creates exactly one slot (in `dst`) and
/// never touches `src` at all: `parent` remains occupied and unaffected in
/// `src`, and the new slot's CDT `parent` link points AT `parent`'s
/// `GlobalCapId`, so it is genuinely a child of it — not merely a copy — and
/// `revoke_cross_space` on `parent` (or any of its ancestors) will reach and
/// free it even though it lives in a different table.
///
/// Preconditions: identical to `derive_child`'s, checked against the
/// capability at `parent` in `src`; `dst` must not be full (else `Full`).
///
/// Postconditions on `Ok(child)`: slot `child` in `dst` is occupied with
/// the narrowed/badged capability; `child.parent ==
/// Some(GlobalCapId::new(src_space, parent))`; `src` is completely
/// unmodified; all table invariants still hold in both tables.
pub fn derive_child_cross_space<const N: usize>(
    src: &CapTable<N>,
    src_space: CapSpaceId,
    parent: CapId,
    dst: &mut CapTable<N>,
    rights: CapabilityRights,
    badge: u64,
) -> Result<CapId, CapTableError> {
    let parent_cap = *src.lookup(parent).ok_or(CapTableError::EmptySlot)?;
    let parent_global = GlobalCapId::new(src_space, parent);
    CapTable::<N>::insert_derived(dst, parent_cap, parent_global, rights, badge)
}

// ------------------------------------------------------------------
// Ancestry walk used by `revoke_cross_space`: does following `cur`'s
// `parent` link, zero or more times, ever reach `target`? Starts by
// reading `cur`'s OWN parent (not `cur` itself), so a slot IS its own
// ancestor's descendant, not its own. Bounded by `M * N + 1` steps — the
// total slot count across every table plus one — so an invariant-
// violating cycle cannot spin forever; every real (acyclic) chain reaches
// a root (`parent == None`) in far fewer steps than that.
// ------------------------------------------------------------------
fn is_descendant_of<const N: usize, const M: usize>(
    tables: &[Option<CapTable<N>>; M],
    mut cur: GlobalCapId,
    target: GlobalCapId,
) -> bool {
    for _ in 0..(M * N + 1) {
        let parent = tables
            .get(cur.space.as_usize())
            .and_then(|t| t.as_ref())
            .and_then(|t| t.parent_of(cur.cap));
        match parent {
            Some(p) if p == target => return true,
            Some(p) => cur = p,
            None => return false,
        }
    }
    false
}

/// Revokes the capability at `target` and every capability derived from it
/// — its entire CDT subtree — freeing all their slots, in ANY of the
/// capability spaces in `tables` (not just `target`'s own space). This is
/// `CapRevoke` (02-Microkernel-Layer.md §2, §6, line 65): "invalidate a
/// capability and all of its derivatives... similar to seL4" — now
/// genuinely satisfied across a `CapGrant`, since a granted capability's
/// `parent` link still points back at the capability it was derived from
/// even after living in a different table (see `derive_child_cross_space`).
///
/// `tables` is indexed by `CapSpaceId`: `kernel-core`'s `cap_spaces` array
/// keys each `CapTable` by the same index it hands out as that space's
/// `CapSpaceId` (`KernelState::alloc_cap_space`), so `tables[space.as_usize()]`
/// is always the right table for a `GlobalCapId` naming that space.
///
/// Precondition: `target.space` names a populated `tables` entry, and
/// `target.cap` names an occupied slot within it (else `EmptySlot`).
///
/// Postconditions on `Ok(n)`: `target` and every transitive descendant, in
/// every table, are freed; `n` is the total freed (>= 1); every table
/// invariant still holds in every table touched. Tables not containing
/// `target` or any of its descendants are completely unmodified.
///
/// Implementation: two allocation-free, non-recursive passes over `tables`
/// (kernel stack safety — no per-node recursion depth to bound). Pass one
/// marks every occupied slot, in every table, that is `target` or a
/// descendant of it (`is_descendant_of`'s parent-chain walk); this must
/// finish before any freeing happens, because freeing a slot clears its
/// `parent` link, which would corrupt the ancestry walk for a
/// not-yet-checked slot deeper in the same subtree. Pass two frees every
/// marked slot — order no longer matters once marking is complete. Cost is
/// bounded by `(M * N)²`, cheap for this kernel's small fixed table sizes
/// and acceptable for an administrative operation that is never on a
/// syscall fast path.
pub fn revoke_cross_space<const N: usize, const M: usize>(
    tables: &mut [Option<CapTable<N>>; M],
    target: GlobalCapId,
) -> Result<u32, CapTableError> {
    {
        let t = tables
            .get(target.space.as_usize())
            .and_then(|t| t.as_ref())
            .ok_or(CapTableError::EmptySlot)?;
        if t.lookup(target.cap).is_none() {
            return Err(CapTableError::EmptySlot);
        }
    }

    // Pass 1: mark (without mutating anything) every occupied slot that is
    // `target` itself or a descendant of it.
    let mut marked = [[false; N]; M];
    for si in 0..M {
        let Some(tbl) = tables[si].as_ref() else {
            continue;
        };
        for i in 0..N {
            if tbl.slots[i].cap.is_none() {
                continue;
            }
            let cand = GlobalCapId::new(CapSpaceId::new(si as u32), CapId::new(i as u32));
            if cand == target || is_descendant_of(tables, cand, target) {
                marked[si][i] = true;
            }
        }
    }

    // Pass 2: free every marked slot.
    let mut freed: u32 = 0;
    for si in 0..M {
        let Some(tbl) = tables[si].as_mut() else {
            continue;
        };
        for i in 0..N {
            if marked[si][i] {
                tbl.free_slot(CapId::new(i as u32));
                freed += 1;
            }
        }
    }

    Ok(freed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KernelObjectKind, ObjectId, ObjectRef};

    const N: usize = 16;

    fn root_cap() -> Capability {
        Capability::full(ObjectRef::new(
            KernelObjectKind::UntypedMemory,
            ObjectId::new(0),
        ))
    }

    fn sid(i: u32) -> CapSpaceId {
        CapSpaceId::new(i)
    }

    #[test]
    fn new_table_is_empty_and_lookups_miss() {
        let t: CapTable<N> = CapTable::new(sid(0));
        assert!(t.is_empty());
        assert!(t.lookup(CapId::new(0)).is_none());
    }

    #[test]
    fn insert_root_then_lookup() {
        let mut t: CapTable<N> = CapTable::new(sid(0));
        let id = t.insert_root(root_cap()).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t.lookup(id).unwrap().rights, CapabilityRights::all());
    }

    #[test]
    fn derive_narrows_rights_and_rejects_escalation() {
        let mut t: CapTable<N> = CapTable::new(sid(0));
        let root = t.insert_root(root_cap()).unwrap();
        let child = t
            .derive_child(root, CapabilityRights::RO, 0)
            .unwrap();
        assert_eq!(t.lookup(child).unwrap().rights, CapabilityRights::RO);
        // A grandchild cannot regain WRITE that its parent lacks.
        assert_eq!(
            t.derive_child(child, CapabilityRights::RW, 0),
            Err(CapTableError::RightsEscalation)
        );
    }

    #[test]
    fn badge_is_write_once() {
        let mut t: CapTable<N> = CapTable::new(sid(0));
        let root = t.insert_root(root_cap()).unwrap();
        let badged = t.derive_child(root, CapabilityRights::RW, 0x1111).unwrap();
        assert_eq!(t.lookup(badged).unwrap().badge, 0x1111);
        // A child of a badged cap inherits the badge; asking for another fails.
        assert_eq!(
            t.derive_child(badged, CapabilityRights::RW, 0x2222),
            Err(CapTableError::BadgeConflict)
        );
        let inherit = t.derive_child(badged, CapabilityRights::RW, 0).unwrap();
        assert_eq!(t.lookup(inherit).unwrap().badge, 0x1111);
    }

    #[test]
    fn revoke_frees_whole_subtree() {
        let mut tables: [Option<CapTable<N>>; 1] = [Some(CapTable::new(sid(0)))];
        let t = tables[0].as_mut().unwrap();
        let root = t.insert_root(root_cap()).unwrap();
        let a = t.derive_child(root, CapabilityRights::RW, 0).unwrap();
        let b = t.derive_child(a, CapabilityRights::RW, 0).unwrap();
        let c = t.derive_child(a, CapabilityRights::RO, 0).unwrap();
        let d = t.derive_child(b, CapabilityRights::RO, 0).unwrap();
        assert_eq!(t.len(), 5);

        let freed = revoke_cross_space(&mut tables, GlobalCapId::new(sid(0), a)).unwrap();
        assert_eq!(freed, 4); // a, b, c, d
        let t = tables[0].as_ref().unwrap();
        assert_eq!(t.len(), 1);
        assert!(t.lookup(a).is_none());
        assert!(t.lookup(b).is_none());
        assert!(t.lookup(c).is_none());
        assert!(t.lookup(d).is_none());
        // Root survives.
        assert!(t.lookup(root).is_some());
    }

    #[test]
    fn revoke_root_empties_table_and_slots_are_reusable() {
        let mut tables: [Option<CapTable<N>>; 1] = [Some(CapTable::new(sid(0)))];
        let t = tables[0].as_mut().unwrap();
        let root = t.insert_root(root_cap()).unwrap();
        for _ in 0..5 {
            t.derive_child(root, CapabilityRights::RO, 0).unwrap();
        }
        revoke_cross_space(&mut tables, GlobalCapId::new(sid(0), root)).unwrap();
        let t = tables[0].as_mut().unwrap();
        assert!(t.is_empty());
        // All slots came back: we can refill to capacity.
        let r2 = t.insert_root(root_cap()).unwrap();
        for _ in 0..(N - 1) {
            t.derive_child(r2, CapabilityRights::RO, 0).unwrap();
        }
        assert!(t.is_full());
        assert_eq!(
            t.derive_child(r2, CapabilityRights::RO, 0),
            Err(CapTableError::Full)
        );
    }

    #[test]
    fn revoke_empty_slot_errors() {
        let mut tables: [Option<CapTable<N>>; 1] = [Some(CapTable::new(sid(0)))];
        assert_eq!(
            revoke_cross_space(&mut tables, GlobalCapId::new(sid(0), CapId::new(3))),
            Err(CapTableError::EmptySlot)
        );
    }

    // ------------------------------------------------------------------
    // Cross-space CDT: the whole point of this rewrite. A capability
    // granted into another process's table must still be reachable from a
    // `CapRevoke` issued against the ORIGINAL (granter-side) capability it
    // was derived from — 02-Microkernel-Layer.md line 65.
    // ------------------------------------------------------------------

    #[test]
    fn grant_into_another_space_then_revoke_source_reaches_it() {
        let mut tables: [Option<CapTable<N>>; 2] =
            [Some(CapTable::new(sid(0))), Some(CapTable::new(sid(1)))];

        let root = tables[0].as_mut().unwrap().insert_root(root_cap()).unwrap();

        // Grant a narrowed copy of `root` (space 0) directly into space 1 —
        // no intermediate same-space derive, no move.
        let granted = {
            let (left, right) = tables.split_at_mut(1);
            let src = left[0].as_ref().unwrap();
            let dst = right[0].as_mut().unwrap();
            derive_child_cross_space(src, sid(0), root, dst, CapabilityRights::RO, 0).unwrap()
        };
        assert_eq!(
            tables[1].as_ref().unwrap().lookup(granted).unwrap().rights,
            CapabilityRights::RO
        );
        // The source capability is completely untouched by the grant.
        assert!(tables[0].as_ref().unwrap().lookup(root).is_some());

        // Revoking `root` in space 0 must free the granted copy in space 1.
        let freed = revoke_cross_space(&mut tables, GlobalCapId::new(sid(0), root)).unwrap();
        assert_eq!(freed, 2); // root itself + the cross-space grandchild in space 1
        assert!(tables[0].as_ref().unwrap().lookup(root).is_none());
        assert!(tables[1].as_ref().unwrap().lookup(granted).is_none());
    }

    #[test]
    fn revoke_reaches_a_grant_chained_through_a_third_space() {
        // space 0 --derive--> a (space 0) --grant--> b (space 1) --grant--> c (space 2)
        let mut tables: [Option<CapTable<N>>; 3] = [
            Some(CapTable::new(sid(0))),
            Some(CapTable::new(sid(1))),
            Some(CapTable::new(sid(2))),
        ];

        let root = tables[0].as_mut().unwrap().insert_root(root_cap()).unwrap();
        let a = tables[0]
            .as_mut()
            .unwrap()
            .derive_child(root, CapabilityRights::all(), 0)
            .unwrap();

        let b = {
            let (left, right) = tables.split_at_mut(1);
            let src = left[0].as_ref().unwrap();
            let dst = right[0].as_mut().unwrap();
            derive_child_cross_space(src, sid(0), a, dst, CapabilityRights::all(), 0).unwrap()
        };
        let c = {
            let (left, right) = tables.split_at_mut(2);
            let src = left[1].as_ref().unwrap();
            let dst = right[0].as_mut().unwrap();
            derive_child_cross_space(src, sid(1), b, dst, CapabilityRights::RO, 0).unwrap()
        };
        assert!(tables[2].as_ref().unwrap().lookup(c).is_some());

        // Revoking `a` (space 0) must reach through `b` (space 1) all the
        // way to `c` (space 2), but must NOT touch `root`.
        let freed = revoke_cross_space(&mut tables, GlobalCapId::new(sid(0), a)).unwrap();
        assert_eq!(freed, 3); // a, b, c
        assert!(tables[0].as_ref().unwrap().lookup(root).is_some());
        assert!(tables[0].as_ref().unwrap().lookup(a).is_none());
        assert!(tables[1].as_ref().unwrap().lookup(b).is_none());
        assert!(tables[2].as_ref().unwrap().lookup(c).is_none());
    }

    #[test]
    fn revoking_only_one_grant_leaves_a_sibling_grant_untouched() {
        // `root` is granted independently into both space 1 and space 2;
        // revoking the space-1 copy must not affect the space-2 copy or
        // `root` itself (they are siblings under `root`, not a chain).
        let mut tables: [Option<CapTable<N>>; 3] = [
            Some(CapTable::new(sid(0))),
            Some(CapTable::new(sid(1))),
            Some(CapTable::new(sid(2))),
        ];
        let root = tables[0].as_mut().unwrap().insert_root(root_cap()).unwrap();

        let g1 = {
            let (left, right) = tables.split_at_mut(1);
            derive_child_cross_space(
                left[0].as_ref().unwrap(),
                sid(0),
                root,
                right[0].as_mut().unwrap(),
                CapabilityRights::RO,
                0,
            )
            .unwrap()
        };
        let g2 = {
            let (left, right) = tables.split_at_mut(2);
            derive_child_cross_space(
                left[0].as_ref().unwrap(),
                sid(0),
                root,
                right[0].as_mut().unwrap(),
                CapabilityRights::RO,
                0,
            )
            .unwrap()
        };

        let freed = revoke_cross_space(&mut tables, GlobalCapId::new(sid(1), g1)).unwrap();
        assert_eq!(freed, 1);
        assert!(tables[1].as_ref().unwrap().lookup(g1).is_none());
        assert!(tables[2].as_ref().unwrap().lookup(g2).is_some());
        assert!(tables[0].as_ref().unwrap().lookup(root).is_some());
    }
}
