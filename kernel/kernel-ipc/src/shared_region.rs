//! ============================================================================
//! shared_region.rs
//!
//! Purpose: `SharedRegion` — a physical memory range that two (or more)
//! processes map into their own address spaces for bulk zero-copy transfer
//! (02-Microkernel-Layer.md §5.2: "به‌جای کپی، Capability به یک ناحیه‌ی
//! حافظه‌ی مشترک منتقل می‌شود؛ گیرنده فقط آن را در فضای آدرس خودش map
//! می‌کند. کپی صفر است").
//!
//! Architecture reference: 02-Microkernel-Layer.md §5.2
//! (`create_shared_region`, `map_shared_region`), §8.4 (MVP: zero-copy
//! proven copy-free), and 03-Kernel-Subsystems-Layer.md §2.2 (VFS page
//! cache as a shared region) / §2.4 (compositor frame buffers).
//!
//! Position in the system: a `SharedRegion` is created by `retype`-ing
//! `UntypedMemory` and is named by a capability. `kernel-core` records the
//! physical range; each peer's `Map` syscall maps it (or a sub-range) into
//! that peer's `AddressSpace` (`kernel-mm`). The kernel never copies the
//! bytes — it only hands out mappings.
//!
//! Safety/invariants: `SharedRegion` is pure description (base + size +
//! max rights). It performs no mapping itself; enforcing that a peer's
//! mapping does not exceed `rights` or `size` is the syscall dispatcher's
//! job.
//! ============================================================================

use hal_core::PhysAddr;
use kernel_cap::CapabilityRights;

/// A shareable physical memory range. `Copy` — it is small description
/// data carried alongside the capability that names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedRegion {
    /// Physical base address (page-aligned; comes from an `UntypedMemory`
    /// `retype`).
    pub phys_base: PhysAddr,
    /// Size in bytes (multiple of the page size).
    pub size: usize,
    /// The widest rights any mapping of this region may be granted. A
    /// peer that receives a capability to this region can be given a
    /// mapping no wider than this (e.g. a producer maps it `RW`, a
    /// consumer gets a derived capability restricted to `RO`).
    pub max_rights: CapabilityRights,
}

impl SharedRegion {
    /// Describes a shared region.
    pub const fn new(phys_base: PhysAddr, size: usize, max_rights: CapabilityRights) -> Self {
        Self {
            phys_base,
            size,
            max_rights,
        }
    }

    /// True if `[offset, offset + len)` lies within this region — the
    /// check the syscall dispatcher runs before mapping a sub-range.
    pub fn contains(&self, offset: usize, len: usize) -> bool {
        match offset.checked_add(len) {
            Some(end) => end <= self.size,
            None => false,
        }
    }

    /// The physical address of `offset` bytes into the region, if in
    /// range.
    pub fn phys_at(&self, offset: usize) -> Option<PhysAddr> {
        if offset < self.size {
            Some(PhysAddr::new(self.phys_base.as_usize() + offset))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_and_phys_at() {
        let r = SharedRegion::new(PhysAddr::new(0x20_0000), 0x4000, CapabilityRights::RW);
        assert!(r.contains(0, 0x4000));
        assert!(!r.contains(0x2000, 0x3000));
        assert_eq!(r.phys_at(0x1000).unwrap().as_usize(), 0x20_1000);
        assert!(r.phys_at(0x4000).is_none());
    }

    #[test]
    fn contains_rejects_overflow() {
        let r = SharedRegion::new(PhysAddr::new(0), 0x1000, CapabilityRights::RO);
        assert!(!r.contains(usize::MAX, 1));
    }
}
