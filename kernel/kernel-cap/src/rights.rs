//! ============================================================================
//! rights.rs
//!
//! Purpose: the `CapabilityRights` bitset — what a holder of a capability is
//! permitted to do with the object it names.
//!
//! Architecture reference: 02-Microkernel-Layer.md §2 (the `CapabilityRights`
//! bitflags block, plus the surrounding prose which additionally names
//! `REVOKE` as a key right).
//!
//! Position in the system: checked by the `kernel-core` syscall dispatcher
//! before every privileged operation; narrowed (never widened) by
//! `kernel-cap::CapTable::derive_child` when a capability is copied to a
//! child slot or granted to another process.
//!
//! Safety/invariants: rights are monotonically non-increasing along any path
//! from a CDT root to a leaf. There is no operation that adds a right to an
//! existing capability.
//! ============================================================================

use bitflags::bitflags;

bitflags! {
    /// The rights carried by a `Capability` (02-Microkernel-Layer.md §2).
    ///
    /// Possible bits and their effect:
    /// - `READ`: read the object's contents / receive from it. For an
    ///   `Endpoint`, permits `Recv`; for `UntypedMemory` / a frame, permits
    ///   mapping it readable; for a `Notification`, permits waiting on it.
    /// - `WRITE`: modify the object / send to it. For an `Endpoint`,
    ///   permits `Send`/`Call`; for a frame, permits a writable mapping;
    ///   for a `Notification`, permits `Signal`.
    /// - `EXECUTE`: for a memory frame, permits an executable mapping
    ///   (kept distinct from `WRITE` so W^X can be enforced by never
    ///   granting both to the same mapping capability).
    /// - `GRANT`: permits transferring this capability (or a derived,
    ///   no-wider copy of it) to another process via `CapGrant`
    ///   (02-Microkernel-Layer.md §6). Without `GRANT`, a capability is
    ///   usable but not shareable.
    /// - `DUPLICATE`: permits creating another copy of this capability in
    ///   the *same* cap space (a CDT sibling), e.g. to hand different
    ///   badges to different clients. Without it, only a single instance
    ///   may exist per space.
    /// - `REVOKE`: permits calling `CapRevoke` on this capability, which
    ///   invalidates it and every capability derived from it (the CDT
    ///   subtree — 02-Microkernel-Layer.md §2: "کرنل باید بتواند یک
    ///   Capability و تمام مشتقات آن ... را باطل کند"). The §2 code snippet
    ///   omits this bit while the surrounding text calls revocation a key
    ///   requirement; it is included here so revoke authority is itself a
    ///   capability-gated right rather than implicit.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CapabilityRights: u32 {
        /// Read / receive.
        const READ      = 0b0000_0001;
        /// Write / send / signal.
        const WRITE     = 0b0000_0010;
        /// Executable mapping (memory frames only).
        const EXECUTE   = 0b0000_0100;
        /// May be transferred to another process (`CapGrant`).
        const GRANT     = 0b0000_1000;
        /// May be duplicated within the same cap space.
        const DUPLICATE = 0b0001_0000;
        /// May be the target of `CapRevoke`.
        const REVOKE    = 0b0010_0000;
    }
}

impl CapabilityRights {
    /// Rights suitable for a read-only mapping / receive-only endpoint.
    pub const RO: Self = Self::READ;

    /// Read + write, no execute — the default for data frames and for a
    /// bidirectional endpoint capability. Deliberately excludes `EXECUTE`
    /// to keep W^X the easy path.
    pub const RW: Self = Self::READ.union(Self::WRITE);

    /// Read + execute, no write — for code frames.
    pub const RX: Self = Self::READ.union(Self::EXECUTE);

    /// True if `self` is no wider than `parent` in every bit — the
    /// precondition `derive_child` enforces so rights never escalate.
    pub fn is_subset_of(self, parent: Self) -> bool {
        parent.contains(self)
    }
}
