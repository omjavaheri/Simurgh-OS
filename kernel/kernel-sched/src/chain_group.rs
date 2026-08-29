//! ============================================================================
//! chain_group.rs
//!
//! Purpose: `ChainGroup` — the set of threads participating in one
//! synchronous IPC chain (app → VFS → driver), which share a single
//! `vruntime` account (02-Microkernel-Layer.md §4.3: "تمام تردهای درگیر در
//! یک زنجیره‌ی synchronous IPC یک Chain Group ID مشترک می‌گیرند و vruntime
//! به سطح گروه انباشته می‌شود").
//!
//! Architecture reference: 02-Microkernel-Layer.md §4.1 (the scheduling
//! unit is the chain, not the thread) and §4.3 (`ChainGroup` struct,
//! shared `group_vruntime`).
//!
//! Position in the system: `kernel-core` creates a `ChainGroup` when a
//! synchronous `Call` chain forms and dissolves it when the chain
//! completes; `kernel-sched` charges run time to the group instead of the
//! individual thread when the running thread is a member.
//!
//! Safety/invariants: `member_threads` is a fixed-capacity array (§4.3's
//! `Vec<ThreadId>` becomes `[ThreadId; MAX] + len` per
//! IMPLEMENTATION-PLAN.md D1); membership has no duplicates;
//! `group_vruntime` is monotonically non-decreasing.
//! ============================================================================

use kernel_cap::{ChainGroupId, ThreadId};

/// Maximum threads in one synchronous IPC chain. Chains in this
/// architecture are short by design (client → one or two servers → a
/// driver); 8 is generous headroom.
pub const MAX_CHAIN_MEMBERS: usize = 8;

/// Errors from chain-group membership changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainGroupError {
    /// The chain already has `MAX_CHAIN_MEMBERS` members.
    Full,
    /// `remove_member` was given a thread that is not in the group.
    NotAMember,
}

/// One IPC chain's shared scheduling account.
#[derive(Debug, Clone, Copy)]
pub struct ChainGroup {
    /// This group's id (index into `kernel-core`'s chain-group table).
    pub id: ChainGroupId,
    member_threads: [ThreadId; MAX_CHAIN_MEMBERS],
    len: usize,
    /// The `vruntime` accumulated by the whole chain — the value the
    /// scheduler compares against other runnable entities for a
    /// `Throughput`-mode member (§4.3).
    pub group_vruntime: u64,
}

impl ChainGroup {
    /// A new, empty chain group with zero accumulated `vruntime`.
    pub const fn new(id: ChainGroupId) -> Self {
        Self {
            id,
            member_threads: [ThreadId::new(0); MAX_CHAIN_MEMBERS],
            len: 0,
            group_vruntime: 0,
        }
    }

    /// Current members, in join order.
    pub fn members(&self) -> &[ThreadId] {
        &self.member_threads[..self.len]
    }

    /// Number of members.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if the group has no members (ready to be recycled).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// True if `thread` is a member.
    pub fn contains(&self, thread: ThreadId) -> bool {
        self.members().contains(&thread)
    }

    /// Adds `thread` to the chain. No-op (still `Ok`) if it is already a
    /// member. Errors `Full` at capacity.
    pub fn add_member(&mut self, thread: ThreadId) -> Result<(), ChainGroupError> {
        if self.contains(thread) {
            return Ok(());
        }
        if self.len >= MAX_CHAIN_MEMBERS {
            return Err(ChainGroupError::Full);
        }
        self.member_threads[self.len] = thread;
        self.len += 1;
        Ok(())
    }

    /// Removes `thread` from the chain, preserving the order of the rest.
    /// Errors `NotAMember` if it was not present.
    pub fn remove_member(&mut self, thread: ThreadId) -> Result<(), ChainGroupError> {
        let idx = self
            .members()
            .iter()
            .position(|&t| t == thread)
            .ok_or(ChainGroupError::NotAMember)?;
        for i in idx + 1..self.len {
            self.member_threads[i - 1] = self.member_threads[i];
        }
        self.len -= 1;
        Ok(())
    }

    /// Charges `increment` (already weight-adjusted by
    /// `weight::vruntime_next`) to the whole chain. Saturating.
    pub fn charge(&mut self, increment: u64) {
        self.group_vruntime = self.group_vruntime.saturating_add(increment);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g() -> ChainGroup {
        ChainGroup::new(ChainGroupId::new(0))
    }

    #[test]
    fn add_dedupes_and_tracks_order() {
        let mut c = g();
        c.add_member(ThreadId::new(1)).unwrap();
        c.add_member(ThreadId::new(2)).unwrap();
        c.add_member(ThreadId::new(1)).unwrap(); // dup: no-op
        assert_eq!(c.members(), &[ThreadId::new(1), ThreadId::new(2)]);
    }

    #[test]
    fn remove_preserves_order() {
        let mut c = g();
        for i in 1..=4 {
            c.add_member(ThreadId::new(i)).unwrap();
        }
        c.remove_member(ThreadId::new(2)).unwrap();
        assert_eq!(
            c.members(),
            &[ThreadId::new(1), ThreadId::new(3), ThreadId::new(4)]
        );
        assert_eq!(
            c.remove_member(ThreadId::new(9)),
            Err(ChainGroupError::NotAMember)
        );
    }

    #[test]
    fn full_is_reported() {
        let mut c = g();
        for i in 0..MAX_CHAIN_MEMBERS as u32 {
            c.add_member(ThreadId::new(i)).unwrap();
        }
        assert_eq!(
            c.add_member(ThreadId::new(100)),
            Err(ChainGroupError::Full)
        );
    }

    #[test]
    fn charge_accumulates() {
        let mut c = g();
        c.charge(100);
        c.charge(50);
        assert_eq!(c.group_vruntime, 150);
    }
}
