//! ============================================================================
//! cdt.rs
//!
//! Purpose: the Capability Derivation Tree (CDT) and its backing storage.
//! Tracks the parent/child relationships between capabilities so that
//! revoking one capability also invalidates every capability derived from
//! it — the mechanism behind 02-Microkernel-Layer.md §2's requirement that
//! "the kernel must be able to invalidate a capability and all of its
//! derivatives".
//!
//! Architecture reference: 02-Microkernel-Layer.md §2 (Capability model, CDT,
//! revocation — explicitly modelled on seL4, not a custom design) and §1.1
//! (grant/revoke carry structured pre/post-condition comments intended to
//! become proof annotations for Kani/Prusti later).
//!
//! Position in the system: owned by `kernel-core`'s `KernelState`, one
//! `CapTable` per `CapabilitySpace`. The syscall dispatcher calls
//! `derive_child` for `CapGrant`/duplicate and `revoke` for `CapRevoke`
//! (02-Microkernel-Layer.md §6). Never reachable from user space except
//! through those syscalls.
//!
//! Safety/invariants (hold between every public call):
//!   1. A slot is "occupied" iff `cap.is_some()`; "free" otherwise.
//!   2. Free slots form a singly linked list from `free_head` via
//!      `next_sibling`; occupied slots are never on that list.
//!   3. For every occupied slot `c` with `parent == Some(p)`: `p` is
//!      occupied and `c` appears exactly once in `p`'s child list.
//!   4. `c.cap.rights` is a subset of `parent.cap.rights` for every
//!      non-root `c` (rights never escalate along a derivation edge).
//!   5. The parent/child/sibling links contain no cycles: following
//!      `parent` from any node reaches a root (`parent == None`) in
//!      finitely many steps.
//! ============================================================================

use crate::{CapId, Capability, CapabilityRights};

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

/// One capability-table slot: a capability plus its CDT links. `Copy` so a
/// `[CapSlot; N]` can be constructed from `CapSlot::EMPTY` without `unsafe`
/// zeroing or an allocator.
#[derive(Debug, Clone, Copy)]
pub struct CapSlot {
    /// The capability held here, or `None` if this slot is free.
    pub cap: Option<Capability>,
    /// Parent in the derivation tree, or `None` for a root capability
    /// (one seeded by boot-time wiring in `kernel-core`, §8.1).
    pub parent: Option<CapId>,
    /// First child in the derivation tree (most-recently-derived; the
    /// child list is a LIFO stack, which is all revocation needs).
    pub first_child: Option<CapId>,
    /// Next sibling under the same parent. Doubles as the `free_head`
    /// linked-list pointer while this slot is free (invariant 2).
    pub next_sibling: Option<CapId>,
    /// Previous sibling under the same parent, so unlinking a node during
    /// `revoke` is O(1) and does not need a walk from the parent.
    pub prev_sibling: Option<CapId>,
}

impl CapSlot {
    /// A free slot with no capability and no links.
    pub const EMPTY: Self = Self {
        cap: None,
        parent: None,
        first_child: None,
        next_sibling: None,
        prev_sibling: None,
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
}

impl<const N: usize> CapTable<N> {
    /// Creates an empty table with every slot on the free list.
    ///
    /// Postcondition: `len() == 0`; `lookup(c)` is `None` for all `c`;
    /// the free list threads slots `0..N` in order.
    pub fn new() -> Self {
        let mut slots = [CapSlot::EMPTY; N];
        // Thread the free list: slot i points at slot i+1, last points at
        // nothing. Done once here so allocation is a single pop.
        let mut i = 0;
        while i < N {
            slots[i].next_sibling = if i + 1 < N {
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
        }
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

    // ------------------------------------------------------------------
    // Slot allocation (private): pop the free list head.
    // ------------------------------------------------------------------
    fn alloc_slot(&mut self) -> Result<CapId, CapTableError> {
        let id = self.free_head.ok_or(CapTableError::Full)?;
        let slot = &mut self.slots[id.as_usize()];
        // The freed slot's `next_sibling` is the next free entry.
        self.free_head = slot.next_sibling.take();
        *slot = CapSlot::EMPTY;
        self.occupied += 1;
        Ok(id)
    }

    // ------------------------------------------------------------------
    // Slot release (private): push onto the free list. Caller must have
    // already unlinked `id` from the CDT.
    // ------------------------------------------------------------------
    fn free_slot(&mut self, id: CapId) {
        let old_head = self.free_head;
        let slot = &mut self.slots[id.as_usize()];
        *slot = CapSlot::EMPTY;
        slot.next_sibling = old_head;
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
    /// None`, no children; `len()` increased by one.
    pub fn insert_root(&mut self, cap: Capability) -> Result<CapId, CapTableError> {
        let id = self.alloc_slot()?;
        self.slots[id.as_usize()].cap = Some(cap);
        Ok(id)
    }

    /// Derives a child capability from `parent`, narrowing rights to
    /// `rights` and (optionally) stamping `badge`. This is the single
    /// mechanism behind both `CapGrant` (the child is then moved into the
    /// target thread's space) and same-space duplication
    /// (02-Microkernel-Layer.md §2, §6).
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
    ///   - `child.parent == Some(parent)`; `child` is the new head of
    ///     `parent`'s child list; the previous head (if any) is now
    ///     `child.next_sibling` with its `prev_sibling` set to `child`.
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

        let child = self.alloc_slot()?;

        // Link `child` as the new first child of `parent`.
        let old_first = self.slots[parent.as_usize()].first_child;
        if let Some(sib) = old_first {
            self.slots[sib.as_usize()].prev_sibling = Some(child);
        }
        self.slots[parent.as_usize()].first_child = Some(child);

        let slot = &mut self.slots[child.as_usize()];
        slot.cap = Some(Capability {
            object: parent_cap.object,
            rights,
            badge: effective_badge,
        });
        slot.parent = Some(parent);
        slot.next_sibling = old_first;
        slot.prev_sibling = None;

        Ok(child)
    }

    /// Moves the capability at `src` in this table to slot `dst` in
    /// `other` table, preserving the derivation edge conceptually by
    /// re-rooting it (the moved capability becomes a root in `other`,
    /// since a CDT does not span capability spaces in this MVP model — a
    /// cross-space revoke walks the granting space's tree, and a granted
    /// capability is revoked by revoking the parent it was derived from
    /// *before* the move). Used by `CapGrant` after `derive_child`.
    ///
    /// This is intentionally minimal for the MVP: full cross-space CDT
    /// tracking (so a `CapRevoke` in the granter's space reaches into the
    /// grantee's space) is a `feat:` follow-up.
    // TODO(omid): cross-space CDT — a granted capability should remain a
    // CDT child of the capability it was derived from even after moving to
    // another space, so revoke reaches it. Needs the object tables in
    // kernel-core to key CDT nodes by (space, slot) rather than slot alone.
    pub fn take(&mut self, src: CapId) -> Result<Capability, CapTableError> {
        let cap = *self.lookup(src).ok_or(CapTableError::EmptySlot)?;
        // Unlink `src` from its parent/siblings, orphaning its children up
        // to their own new roots is not desired — instead reject taking a
        // capability that still has derived children, so the caller must
        // revoke or move the subtree explicitly.
        if self.slots[src.as_usize()].first_child.is_some() {
            return Err(CapTableError::RightsEscalation); // reused: "has dependents"
        }
        self.unlink_from_parent(src);
        self.free_slot(src);
        Ok(cap)
    }

    // ------------------------------------------------------------------
    // Unlink `id` from its parent's child list (O(1) thanks to the
    // doubly-linked sibling pointers). Does NOT free the slot.
    // ------------------------------------------------------------------
    fn unlink_from_parent(&mut self, id: CapId) {
        let (parent, prev, next) = {
            let s = &self.slots[id.as_usize()];
            (s.parent, s.prev_sibling, s.next_sibling)
        };
        match prev {
            Some(p) => self.slots[p.as_usize()].next_sibling = next,
            None => {
                // `id` was the first child: promote its next sibling.
                if let Some(par) = parent {
                    self.slots[par.as_usize()].first_child = next;
                }
            }
        }
        if let Some(n) = next {
            self.slots[n.as_usize()].prev_sibling = prev;
        }
        let s = &mut self.slots[id.as_usize()];
        s.parent = None;
        s.prev_sibling = None;
        s.next_sibling = None;
    }

    /// Revokes the capability at `target` and every capability derived from
    /// it (its entire CDT subtree), freeing all their slots. This is
    /// `CapRevoke` (02-Microkernel-Layer.md §2, §6): "invalidate a
    /// capability and all of its derivatives".
    ///
    /// Precondition: `target` names an occupied slot (else `EmptySlot`).
    ///
    /// Postconditions on `Ok(n)`:
    ///   - slot `target` and every slot that was a descendant of `target`
    ///     are now free; `n` is how many slots were freed (≥ 1).
    ///   - `target` no longer appears in its former parent's child list.
    ///   - `len()` decreased by exactly `n`.
    ///   - all five table invariants still hold.
    ///
    /// Implementation: repeatedly descend from `target` to a leaf and free
    /// that leaf, then finally free `target`. Allocation-free and with no
    /// recursion (kernel stack safety, and a shape that is
    /// straightforward to prove terminating: each iteration strictly
    /// reduces the number of occupied slots in `target`'s subtree).
    pub fn revoke(&mut self, target: CapId) -> Result<u32, CapTableError> {
        if self.lookup(target).is_none() {
            return Err(CapTableError::EmptySlot);
        }

        let mut freed: u32 = 0;

        // Free all descendants, leaf by leaf.
        loop {
            // Walk down from `target` following `first_child` until a node
            // with no children is found.
            let mut cursor = target;
            let leaf = loop {
                match self.slots[cursor.as_usize()].first_child {
                    Some(child) => cursor = child,
                    None => break cursor,
                }
            };
            if leaf == target {
                break; // `target` itself has no children left.
            }
            self.unlink_from_parent(leaf);
            self.free_slot(leaf);
            freed += 1;
        }

        // Finally, unlink and free `target`.
        self.unlink_from_parent(target);
        self.free_slot(target);
        freed += 1;

        Ok(freed)
    }
}

impl<const N: usize> Default for CapTable<N> {
    fn default() -> Self {
        Self::new()
    }
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

    #[test]
    fn new_table_is_empty_and_lookups_miss() {
        let t: CapTable<N> = CapTable::new();
        assert!(t.is_empty());
        assert!(t.lookup(CapId::new(0)).is_none());
    }

    #[test]
    fn insert_root_then_lookup() {
        let mut t: CapTable<N> = CapTable::new();
        let id = t.insert_root(root_cap()).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t.lookup(id).unwrap().rights, CapabilityRights::all());
    }

    #[test]
    fn derive_narrows_rights_and_rejects_escalation() {
        let mut t: CapTable<N> = CapTable::new();
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
        let mut t: CapTable<N> = CapTable::new();
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
        let mut t: CapTable<N> = CapTable::new();
        let root = t.insert_root(root_cap()).unwrap();
        let a = t.derive_child(root, CapabilityRights::RW, 0).unwrap();
        let b = t.derive_child(a, CapabilityRights::RW, 0).unwrap();
        let c = t.derive_child(a, CapabilityRights::RO, 0).unwrap();
        let d = t.derive_child(b, CapabilityRights::RO, 0).unwrap();
        assert_eq!(t.len(), 5);

        let freed = t.revoke(a).unwrap();
        assert_eq!(freed, 4); // a, b, c, d
        assert_eq!(t.len(), 1);
        assert!(t.lookup(a).is_none());
        assert!(t.lookup(b).is_none());
        assert!(t.lookup(c).is_none());
        assert!(t.lookup(d).is_none());
        // Root survives and its child list is now empty.
        assert!(t.lookup(root).is_some());
    }

    #[test]
    fn revoke_root_empties_table_and_slots_are_reusable() {
        let mut t: CapTable<N> = CapTable::new();
        let root = t.insert_root(root_cap()).unwrap();
        for _ in 0..5 {
            t.derive_child(root, CapabilityRights::RO, 0).unwrap();
        }
        t.revoke(root).unwrap();
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
        let mut t: CapTable<N> = CapTable::new();
        assert_eq!(t.revoke(CapId::new(3)), Err(CapTableError::EmptySlot));
    }
}
