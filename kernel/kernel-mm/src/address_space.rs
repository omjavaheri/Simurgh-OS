//! ============================================================================
//! address_space.rs
//!
//! Purpose: the per-process virtual address space bookkeeping the `Map` /
//! `unmap` syscalls (02-Microkernel-Layer.md §6) operate on. Tracks which
//! virtual ranges map to which physical frames with which permissions, and
//! enforces non-overlap and W^X.
//!
//! Architecture reference: 02-Microkernel-Layer.md §3 ("راه‌اندازی کامل
//! virtual memory مسئولیت لایه ۲ است") and §6 (`Map { page_table, frame,
//! vaddr, perms }`).
//!
//! Position in the system: one `AddressSpace` per `PageTable`
//! (address-space-root) kernel object in `kernel-core`. The syscall
//! dispatcher validates the frame/page-table capabilities, then calls
//! `map`/`unmap` here.
//!
//! Safety/invariants:
//!   - no two `Mapping`s in one `AddressSpace` have overlapping virtual
//!     ranges;
//!   - no `Mapping` is simultaneously writable and executable;
//!   - all addresses and lengths are multiples of `PAGE_SIZE`.
//!
//! MVP scope: `AddressSpace` itself stays a pure software model with no
//! HAL dependency (matches its test suite: plain unit tests, no mock
//! hardware needed) — it is `syscall::do_map` (kernel-core), not this
//! type, that walks a successful `map()` into real architecture PTEs via
//! `hal_core::HalInterface::map_range`, then rolls this model's mapping
//! back with `unmap()` if that hardware walk fails, so the two can never
//! drift out of sync. This module remains the source of truth the
//! syscall layer reasons about (`translate`, overlap/W^X checks) whether
//! or not the current architecture has a working `map_range`.
//! ============================================================================

use crate::{MmError, PAGE_SIZE};
use hal_core::{MapPermissions, PhysAddr, VirtAddr};

/// One virtual→physical mapping of `len` bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// Virtual base (page-aligned).
    pub vaddr: VirtAddr,
    /// Physical base (page-aligned).
    pub paddr: PhysAddr,
    /// Length in bytes (multiple of `PAGE_SIZE`).
    pub len: usize,
    /// Permissions for the whole range.
    pub perms: MapPermissions,
}

impl Mapping {
    fn end(&self) -> usize {
        self.vaddr.as_usize() + self.len
    }

    fn overlaps(&self, vaddr: VirtAddr, len: usize) -> bool {
        let a0 = self.vaddr.as_usize();
        let a1 = self.end();
        let b0 = vaddr.as_usize();
        let b1 = b0 + len;
        a0 < b1 && b0 < a1
    }
}

/// A fixed-capacity virtual address space. `M` is the maximum number of
/// distinct mappings (IMPLEMENTATION-PLAN.md D1 — no heap). `kernel-core`
/// picks `M` per address space.
pub struct AddressSpace<const M: usize> {
    /// Physical address of this space's page-table root (the frame a
    /// `PageTable` object was retyped onto). Recorded for the eventual
    /// hardware-PTE walk; not dereferenced by this model.
    root_phys: PhysAddr,
    mappings: [Option<Mapping>; M],
    count: usize,
}

impl<const M: usize> AddressSpace<M> {
    /// Creates an empty address space rooted at `root_phys`.
    pub const fn new(root_phys: PhysAddr) -> Self {
        Self {
            root_phys,
            mappings: [None; M],
            count: 0,
        }
    }

    /// Physical address of the page-table root.
    pub const fn root_phys(&self) -> PhysAddr {
        self.root_phys
    }

    /// Rebinds this space's recorded page-table root — for when the REAL
    /// hardware root frame is only known/allocated after this
    /// `AddressSpace` was constructed. The Root Task's own space, in
    /// particular, is created from `BootInfo::initial_page_table_phys`
    /// (whatever was active at HAL handoff — often `0`/Bare mode) long
    /// before `kernel-arch-glue::enter` allocates and activates the real
    /// Sv39 (or architecture-equivalent) root; without rebinding it here
    /// once that happens, `syscall::do_map`'s hardware walk would target
    /// the wrong (stale) root frame and always fail.
    pub fn set_root_phys(&mut self, root_phys: PhysAddr) {
        self.root_phys = root_phys;
    }

    /// Number of live mappings.
    pub fn len(&self) -> usize {
        self.count
    }

    /// True if nothing is mapped.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Adds a mapping of `[vaddr, vaddr + len)` → `[paddr, paddr + len)`
    /// with `perms`.
    ///
    /// Preconditions / errors:
    ///   - `vaddr`, `paddr`, `len` all page-aligned and `len != 0` (else
    ///     `Unaligned`);
    ///   - `perms` not both writable and executable (else `WriteExecute`);
    ///   - no overlap with an existing mapping (else `MappingOverlap`);
    ///   - free mapping slot available (else `AddressSpaceFull`).
    ///
    /// Postcondition on `Ok`: `translate(v)` returns `(paddr + (v -
    /// vaddr), perms)` for every page `v` in the new range; `len()`
    /// increased by one.
    pub fn map(
        &mut self,
        vaddr: VirtAddr,
        paddr: PhysAddr,
        len: usize,
        perms: MapPermissions,
    ) -> Result<(), MmError> {
        if len == 0
            || vaddr.as_usize() % PAGE_SIZE != 0
            || paddr.as_usize() % PAGE_SIZE != 0
            || len % PAGE_SIZE != 0
        {
            return Err(MmError::Unaligned);
        }
        if perms.writable && perms.executable {
            return Err(MmError::WriteExecute);
        }
        for m in self.mappings.iter().flatten() {
            if m.overlaps(vaddr, len) {
                return Err(MmError::MappingOverlap);
            }
        }
        let slot = self
            .mappings
            .iter_mut()
            .find(|s| s.is_none())
            .ok_or(MmError::AddressSpaceFull)?;
        *slot = Some(Mapping {
            vaddr,
            paddr,
            len,
            perms,
        });
        self.count += 1;
        // The real hardware PTE walk (`hal_core::HalInterface::map_range`)
        // is `syscall::do_map`'s job, run right after this call succeeds —
        // see this module's doc comment.
        Ok(())
    }

    /// Removes the mapping whose virtual base is exactly `vaddr` and
    /// returns it. Errors `NotMapped` if no mapping starts there.
    ///
    /// Note: this MVP model only supports unmapping a whole mapping by its
    /// base address, not splitting one. Partial unmap is a `feat:`
    /// follow-up.
    pub fn unmap(&mut self, vaddr: VirtAddr) -> Result<Mapping, MmError> {
        let slot = self
            .mappings
            .iter_mut()
            .find(|s| matches!(s, Some(m) if m.vaddr == vaddr))
            .ok_or(MmError::NotMapped)?;
        let m = slot.take().unwrap();
        self.count -= 1;
        Ok(m)
    }

    /// Resolves `vaddr` to its physical address and the permissions of the
    /// containing mapping, or `None` if unmapped.
    pub fn translate(&self, vaddr: VirtAddr) -> Option<(PhysAddr, MapPermissions)> {
        let v = vaddr.as_usize();
        for m in self.mappings.iter().flatten() {
            let base = m.vaddr.as_usize();
            if v >= base && v < base + m.len {
                return Some((PhysAddr::new(m.paddr.as_usize() + (v - base)), m.perms));
            }
        }
        None
    }

    /// Iterates the live mappings (for the eventual hardware-PTE sync and
    /// for debugging / test assertions).
    pub fn iter(&self) -> impl Iterator<Item = &Mapping> {
        self.mappings.iter().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const M: usize = 8;
    const P: usize = PAGE_SIZE;

    fn space() -> AddressSpace<M> {
        AddressSpace::new(PhysAddr::new(0x1000))
    }

    #[test]
    fn map_then_translate() {
        let mut s = space();
        s.map(
            VirtAddr::new(0x40_0000),
            PhysAddr::new(0x80_0000),
            2 * P,
            MapPermissions::KERNEL_DATA,
        )
        .unwrap();
        let (p, perms) = s.translate(VirtAddr::new(0x40_0000 + 0x10)).unwrap();
        assert_eq!(p.as_usize(), 0x80_0000 + 0x10);
        assert!(perms.writable && !perms.executable);
        assert!(s.translate(VirtAddr::new(0x40_0000 + 2 * P)).is_none());
    }

    #[test]
    fn map_rejects_unaligned() {
        let mut s = space();
        assert_eq!(
            s.map(
                VirtAddr::new(0x40_0001),
                PhysAddr::new(0x80_0000),
                P,
                MapPermissions::KERNEL_RODATA
            ),
            Err(MmError::Unaligned)
        );
    }

    #[test]
    fn map_rejects_write_execute() {
        let mut s = space();
        let wx = MapPermissions {
            readable: true,
            writable: true,
            executable: true,
            device_uncached: false,
        };
        assert_eq!(
            s.map(VirtAddr::new(0), PhysAddr::new(0), P, wx),
            Err(MmError::WriteExecute)
        );
    }

    #[test]
    fn map_rejects_overlap() {
        let mut s = space();
        s.map(
            VirtAddr::new(0x1000_0000),
            PhysAddr::new(0),
            4 * P,
            MapPermissions::KERNEL_RODATA,
        )
        .unwrap();
        assert_eq!(
            s.map(
                VirtAddr::new(0x1000_0000 + 2 * P),
                PhysAddr::new(0x50_0000),
                4 * P,
                MapPermissions::KERNEL_RODATA
            ),
            Err(MmError::MappingOverlap)
        );
    }

    #[test]
    fn unmap_removes_mapping() {
        let mut s = space();
        s.map(
            VirtAddr::new(0x2000_0000),
            PhysAddr::new(0),
            P,
            MapPermissions::KERNEL_CODE,
        )
        .unwrap();
        let m = s.unmap(VirtAddr::new(0x2000_0000)).unwrap();
        assert_eq!(m.len, P);
        assert!(s.is_empty());
        assert_eq!(s.unmap(VirtAddr::new(0x2000_0000)), Err(MmError::NotMapped));
    }

    #[test]
    fn address_space_full() {
        let mut s = space();
        for i in 0..M {
            s.map(
                VirtAddr::new(0x1_0000_0000 + i * 0x10_0000),
                PhysAddr::new(0),
                P,
                MapPermissions::KERNEL_RODATA,
            )
            .unwrap();
        }
        assert_eq!(
            s.map(
                VirtAddr::new(0x9_0000_0000),
                PhysAddr::new(0),
                P,
                MapPermissions::KERNEL_RODATA
            ),
            Err(MmError::AddressSpaceFull)
        );
    }
}
