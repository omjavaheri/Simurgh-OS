//! ============================================================================
//! untyped.rs
//!
//! Purpose: `UntypedMemory` — a contiguous physical memory range that has
//! not yet been given a type, and the `retype` operation that carves typed
//! kernel objects (or smaller untyped regions) out of it.
//!
//! Architecture reference: 02-Microkernel-Layer.md §3 (UntypedMemory,
//! retype) and §2 (memory-as-capability, seL4 model).
//!
//! Position in the system: `kernel-core` builds the initial pool of
//! `UntypedMemory` from the boot `HardwareManifestRaw`'s usable regions
//! (minus the kernel image and boot-reserved ranges) and hands
//! capabilities to them to the Root Task (§3, §8.1). The `Retype` syscall
//! (§6) calls `retype` here.
//!
//! Safety/invariants:
//!   - `watermark` only ever moves forward. A region never re-hands-out
//!     space it has already handed out. Reclaiming untyped memory means
//!     revoking every capability derived from the region and resetting it
//!     wholesale — there is no per-object free here (matches seL4 / §3).
//!   - Every value returned by `alloc` / `retype` lies fully within
//!     `[base, base + size_bytes)` and is aligned as requested.
//! ============================================================================

use crate::object_type::{object_size_bytes, KernelObjectType};
use crate::MmError;
use hal_core::PhysAddr;

/// A physical memory range awaiting `retype`. `Copy` is intentionally NOT
/// derived: an `UntypedMemory` has moving interior state (`watermark`) and
/// duplicating it would let two holders hand out the same physical space.
#[derive(Debug, Clone)]
pub struct UntypedMemory {
    base: u64,
    size_bytes: u64,
    /// Bytes already handed out, measured from `base`. Monotonically
    /// non-decreasing.
    watermark: u64,
}

/// The result of a successful `retype`: which physical range was consumed,
/// and for what. `kernel-core` uses this to record the new object(s) in
/// the matching static table and to build the backing frame list for
/// `PageTable` / TCB objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetypeGrant {
    /// What the range was retyped into.
    pub kind: KernelObjectType,
    /// How many objects of `kind` this grant covers.
    pub count: u32,
    /// First physical address of the consumed range.
    pub phys_base: PhysAddr,
    /// Length of the consumed range in bytes (`count * per-object size`,
    /// rounded up to alignment).
    pub phys_len: u64,
}

impl UntypedMemory {
    /// Wraps a raw physical range. `base` and `size_bytes` come from a
    /// `hal_manifest::raw::MemoryRegionRaw` classified `Usable`, already
    /// trimmed by `kernel-core` to exclude the kernel image / boot-reserved
    /// sub-ranges.
    pub const fn new(base: PhysAddr, size_bytes: u64) -> Self {
        Self {
            base: base.as_usize() as u64,
            size_bytes,
            watermark: 0,
        }
    }

    /// First physical address of the region.
    pub const fn base(&self) -> PhysAddr {
        PhysAddr::new(self.base as usize)
    }

    /// Total size of the region in bytes.
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    /// Bytes not yet handed out.
    pub const fn remaining(&self) -> u64 {
        self.size_bytes - self.watermark
    }

    /// Hands out `bytes` of space aligned to `align`, advancing the
    /// watermark. Used internally by `retype`; also directly usable by
    /// `kernel-core` when it needs a raw frame (e.g. the initial page
    /// table root for the Root Task's address space).
    ///
    /// Errors: `BadAlignment` if `align` is 0 or not a power of two;
    /// `Overflow` on address arithmetic overflow; `OutOfMemory` if the
    /// aligned request does not fit in `remaining()`.
    pub fn alloc(&mut self, align: u64, bytes: u64) -> Result<PhysAddr, MmError> {
        if align == 0 || !align.is_power_of_two() {
            return Err(MmError::BadAlignment);
        }
        let cur = self
            .base
            .checked_add(self.watermark)
            .ok_or(MmError::Overflow)?;
        // Round `cur` up to `align`.
        let aligned = cur
            .checked_add(align - 1)
            .ok_or(MmError::Overflow)?
            & !(align - 1);
        let end = aligned.checked_add(bytes).ok_or(MmError::Overflow)?;
        let region_end = self.base.checked_add(self.size_bytes).ok_or(MmError::Overflow)?;
        if end > region_end {
            return Err(MmError::OutOfMemory);
        }
        self.watermark = end - self.base;
        Ok(PhysAddr::new(aligned as usize))
    }

    /// Retypes part of this region into `count` objects of `kind`.
    ///
    /// Precondition: `count >= 1` (else `ZeroCount`).
    ///
    /// Behaviour: reserves `count * object_size_bytes(kind)` bytes,
    /// page-aligned, from this region (advancing the watermark), and
    /// returns a `RetypeGrant` describing the consumed range. This does
    /// NOT create the Rust-level object structures — that is `kernel-core`'s
    /// job (it allocates slots in the relevant static table and associates
    /// them with `grant.phys_base ..`). Per 02-Microkernel-Layer.md §3 the
    /// kernel only provides the mechanism.
    ///
    /// Postcondition on `Ok(grant)`: `remaining()` decreased by
    /// `grant.phys_len`; `grant.phys_base` is page-aligned and
    /// `[grant.phys_base, grant.phys_base + grant.phys_len)` lies within
    /// this region.
    pub fn retype(&mut self, kind: KernelObjectType, count: u32) -> Result<RetypeGrant, MmError> {
        if count == 0 {
            return Err(MmError::ZeroCount);
        }
        let per = object_size_bytes(kind) as u64;
        let total = per.checked_mul(count as u64).ok_or(MmError::Overflow)?;
        let phys_base = self.alloc(crate::PAGE_SIZE as u64, total)?;
        Ok(RetypeGrant {
            kind,
            count,
            phys_base,
            phys_len: total,
        })
    }

    /// Sub-divides this region into `count` child `UntypedMemory` regions
    /// of `child_size` bytes each (rounded up to a page). A convenience
    /// wrapper the Root Task uses to partition the RAM it received before
    /// distributing it to services (02-Microkernel-Layer.md §3).
    ///
    /// Returns the physical base of the first child; children are
    /// contiguous at `child_size` (page-rounded) stride. `kernel-core`
    /// creates the `UntypedMemory` capabilities for each.
    pub fn retype_untyped(
        &mut self,
        count: u32,
        child_size: u64,
    ) -> Result<RetypeGrant, MmError> {
        if count == 0 {
            return Err(MmError::ZeroCount);
        }
        let page = crate::PAGE_SIZE as u64;
        let child = child_size.checked_add(page - 1).ok_or(MmError::Overflow)? & !(page - 1);
        if child == 0 {
            return Err(MmError::ZeroCount);
        }
        let total = child.checked_mul(count as u64).ok_or(MmError::Overflow)?;
        let phys_base = self.alloc(page, total)?;
        Ok(RetypeGrant {
            kind: KernelObjectType::Untyped,
            count,
            phys_base,
            phys_len: total,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region() -> UntypedMemory {
        // 1 MiB starting at 16 MiB.
        UntypedMemory::new(PhysAddr::new(0x100_0000), 0x10_0000)
    }

    #[test]
    fn alloc_is_aligned_and_advances_watermark() {
        let mut u = region();
        let a = u.alloc(0x1000, 0x800).unwrap();
        assert_eq!(a.as_usize() & 0xFFF, 0);
        assert_eq!(a.as_usize(), 0x100_0000);
        let b = u.alloc(0x1000, 0x800).unwrap();
        // Second alloc is re-aligned up to the next page (0x1000 into the
        // region), leaving a 0x800 gap after `a`.
        assert_eq!(b.as_usize(), 0x100_1000);
        // The watermark tracks the true end (`b + 0x800`), not a
        // page-rounded value — the alignment gap is not reclaimed.
        assert_eq!(u.remaining(), 0x10_0000 - 0x1800);
    }

    #[test]
    fn alloc_rejects_bad_alignment() {
        let mut u = region();
        assert_eq!(u.alloc(0, 8), Err(MmError::BadAlignment));
        assert_eq!(u.alloc(3, 8), Err(MmError::BadAlignment));
    }

    #[test]
    fn alloc_out_of_memory() {
        let mut u = region();
        assert_eq!(u.alloc(0x1000, 0x20_0000), Err(MmError::OutOfMemory));
    }

    #[test]
    fn retype_reserves_count_times_object_size() {
        let mut u = region();
        let g = u.retype(KernelObjectType::PageTable, 4).unwrap();
        assert_eq!(g.count, 4);
        assert_eq!(g.phys_len, 4 * crate::PAGE_SIZE as u64);
        assert_eq!(g.phys_base.as_usize(), 0x100_0000);
        assert_eq!(u.remaining(), 0x10_0000 - 4 * crate::PAGE_SIZE as u64);
    }

    #[test]
    fn retype_zero_count_errors() {
        let mut u = region();
        assert_eq!(
            u.retype(KernelObjectType::Endpoint, 0),
            Err(MmError::ZeroCount)
        );
    }

    #[test]
    fn retype_untyped_partitions_region() {
        let mut u = region();
        let g = u.retype_untyped(8, 0x1_0000).unwrap();
        assert_eq!(g.kind, KernelObjectType::Untyped);
        assert_eq!(g.phys_len, 8 * 0x1_0000);
    }
}
