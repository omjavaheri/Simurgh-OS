//! ============================================================================
//! state.rs
//!
//! Purpose: `KernelState` — the aggregate of every kernel object table
//! plus the scheduler, and `from_boot_info`, which builds the initial
//! state (first `UntypedMemory` objects + the Root Task) from the HAL
//! `BootInfo` (02-Microkernel-Layer.md §8.1: "بوت روی هر سه معماری با
//! تحویل کنترل از HAL و ساخت اولین UntypedMemory objects").
//!
//! Architecture reference: 02-Microkernel-Layer.md §3 (object model,
//! UntypedMemory), §8.1/§8.2 (boot acceptance), §1.1 (bounded tables), and
//! `hal_core::BootInfo` / `hal_manifest::raw::HardwareManifestRaw` for the
//! handoff shape.
//!
//! Position in the system: constructed once by `kernel-arch-glue`
//! immediately after `BootInfo::validate`; then every syscall goes through
//! `syscall::dispatch`, which is implemented as `impl KernelState`.
//!
//! Safety/invariants: table slot `i` is "occupied" iff the `Option` at `i`
//! is `Some`; every id returned by an `alloc_*` helper indexes an occupied
//! slot; capacities are the `config` constants.
//! ============================================================================

use crate::config::*;
use crate::tcb::{Tcb, ThreadState};
use hal_core::{BootInfo, VirtAddr};
use hal_manifest::raw::{MemoryRegionKindRaw, PeripheralKindRaw};
use kernel_cap::{
    CapId, CapSpaceId, CapTable, Capability, EndpointId, KernelObjectKind, MmioRegionId,
    NotificationId, ObjectId, ObjectRef, PageTableId, SharedRegionId, ThreadId, UntypedId,
};
use kernel_ipc::{Endpoint, Notification, SharedRegion};
use kernel_mm::{AddressSpace, UntypedMemory};
use kernel_sched::{Scheduler, SchedulerMode};

/// Reasons `KernelState::from_boot_info` can fail. Distinct from
/// `SyscallError` because these are one-time boot failures, not user
/// syscall results.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelInitError {
    /// `BootInfo::validate` rejected the structure HAL handed over.
    BadBootInfo,
    /// The manifest reported no usable memory region to seed
    /// `UntypedMemory` from (should be impossible past `validate`, kept
    /// as a defensive distinct case).
    NoUsableMemory,
    /// A capacity constant in `config` is too small to build even the
    /// minimal Root Task (cap space / addr space / TCB / one untyped).
    CapacityExhausted,
    /// `init_global` was called more than once.
    AlreadyInitialised,
}

/// Concrete table types (the `config` capacities applied).
type RootCapTable = CapTable<CAP_SLOTS_PER_SPACE>;
type RootAddressSpace = AddressSpace<MAPPINGS_PER_SPACE>;
type KEndpoint = Endpoint<ENDPOINT_QUEUE>;
type KNotification = Notification<NOTIF_WAITERS>;
type KScheduler = Scheduler<MAX_THREADS, MAX_CHAIN_GROUPS>;

/// One device's physical MMIO transport window + IRQ line (03
/// §2.1, §5.1) — plain data describing an `MmioRegion` object.
/// Unlike `SharedRegion`, never carved from `UntypedMemory`: `phys_base`
/// is a fixed hardware fact the boot-time HAL peripheral scan reports
/// (`hal_manifest::raw::PeripheralDeviceRaw`), not RAM from a general
/// pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioRegionDescriptor {
    /// Physical base address of the MMIO window.
    pub phys_base: u64,
    /// Size of the window in bytes.
    pub size: u64,
    /// The device's IRQ line, in this platform's own `IrqId` numbering
    /// (as reported by `hal_manifest::raw::PeripheralDeviceRaw::irq` —
    /// the HAL discovery code, not this crate, is responsible for that
    /// translation).
    pub irq: u32,
    /// See `hal_manifest::raw::PeripheralDeviceRaw::config_space_base`'s
    /// own doc comment — `0` for a device with no PCI config space
    /// (e.g. riscv64's virtio-mmio transport).
    pub config_space_base: u64,
}

/// The entire mutable kernel state. One instance for the life of the
/// system.
pub struct KernelState {
    cap_spaces: [Option<RootCapTable>; MAX_CAP_SPACES],
    untyped: [Option<UntypedMemory>; MAX_UNTYPED],
    addr_spaces: [Option<RootAddressSpace>; MAX_ADDR_SPACES],
    endpoints: [Option<KEndpoint>; MAX_ENDPOINTS],
    notifications: [Option<KNotification>; MAX_NOTIFICATIONS],
    shared_regions: [Option<SharedRegion>; MAX_SHARED_REGIONS],
    mmio_regions: [Option<MmioRegionDescriptor>; MAX_MMIO_REGIONS],
    /// IRQ line -> bound `Notification` (03 §2.1). Sparse, linear-scanned
    /// (`MAX_IRQ_BINDINGS` is small): a hardware interrupt firing looks
    /// up its bound notification here and signals it — see
    /// `notification_for_irq` / `bind_irq`.
    irq_bindings: [Option<(u32, NotificationId)>; MAX_IRQ_BINDINGS],
    tcbs: [Option<Tcb>; MAX_THREADS],
    /// The scheduler.
    pub sched: KScheduler,

    /// The Root Task's thread id (02-Microkernel-Layer.md §8.1).
    pub root_thread: ThreadId,
    /// The Root Task's capability space.
    pub root_cap_space: CapSpaceId,
    /// The Root Task's address space.
    pub root_addr_space: PageTableId,
    /// The capability, in the Root Task's own cap space, naming
    /// `root_addr_space` — the `page_table` argument it passes to
    /// `SyscallOp::Map` for its own space. `CapId::new(u32::MAX)` if
    /// seeding it at boot failed (cap space full — see
    /// `populate_from_boot_info`'s Step 3b); `Map` into the Root Task's
    /// own space then always fails with `BadCap`, matching what an
    /// absent capability should do.
    pub root_page_table_cap: CapId,
    /// The capability, in the Root Task's own cap space, naming the
    /// FIRST `Block`-kind `MmioRegion` the boot-time HAL peripheral scan
    /// discovered (`populate_from_boot_info`'s Step 3c) — MVP scope: this
    /// project's only driver so far is virtio-blk, so only the block
    /// device gets a boot-seeded capability; other kinds sit in the
    /// manifest unused until a driver for them exists.
    /// `CapId::new(u32::MAX)` if none was found or the cap space was
    /// full, exactly mirroring `root_page_table_cap`'s own sentinel.
    pub root_mmio_blk_cap: CapId,
    /// The capability, in the Root Task's own cap space, naming the FIRST
    /// `Network`-kind `MmioRegion` the boot-time HAL peripheral scan
    /// discovered (`populate_from_boot_info`'s Step 3d) — same rationale
    /// as `root_mmio_blk_cap`'s own doc comment, one driver kind later
    /// (`driver-virtio-net`, 03-Kernel-Subsystems-Layer.md §2.3/§5.4).
    /// `CapId::new(u32::MAX)` if none was found or the cap space was
    /// full.
    pub root_mmio_net_cap: CapId,
    /// How many `UntypedMemory` objects the boot path created.
    pub untyped_count: u32,

    // ---- `Map` syscall hardware page-table pool (see `install_map_pool`) ----
    //
    // The physical, pre-zeroed scratch frames `hal_core::HalInterface::
    // map_range` draws missing L1/L0 (or architecture-equivalent)
    // intermediate table nodes from when `do_map` walks a mapping into
    // real hardware PTEs. `kernel-core` only tracks WHICH frames of this
    // pool are already spoken for (plain integers — no raw-pointer
    // access, no `unsafe`); the pool's actual physical memory is carved
    // and zeroed by `kernel-arch-glue` at boot (`install_map_pool`),
    // exactly as it already does for the boot-time `.user_text`/
    // `.user_stack` mappings — kernel-core never touches physical memory
    // directly.
    /// Physical base of the pool, or `0` if none has been installed yet
    /// (the architecture has no working `map_range`, or boot hasn't
    /// reached that point) — `do_map` then skips the hardware walk
    /// entirely and stays software-model-only.
    map_pool_base: usize,
    /// Total frames in the pool.
    map_pool_len: u32,
    /// Frames already consumed (the high-water mark `do_map` advances).
    map_pool_used: u32,
}

impl KernelState {
    // ---- slot allocation helpers ---------------------------------

    /// Allocates a fresh (empty) `CapabilitySpace`, returning its id.
    pub fn alloc_cap_space(&mut self) -> Option<CapSpaceId> {
        let i = self.cap_spaces.iter().position(|s| s.is_none())?;
        let id = CapSpaceId::new(i as u32);
        self.cap_spaces[i] = Some(CapTable::new(id));
        Some(id)
    }

    /// Allocates an address space (`PageTable` root) rooted at
    /// `root_phys`, returning its id.
    pub fn alloc_addr_space(&mut self, root_phys: u64) -> Option<PageTableId> {
        let i = self.addr_spaces.iter().position(|s| s.is_none())?;
        self.addr_spaces[i] = Some(AddressSpace::new(hal_core::PhysAddr::new(root_phys as usize)));
        Some(PageTableId::new(i as u32))
    }

    /// Allocates an `UntypedMemory` object covering `[base, base + size)`,
    /// returning its id.
    pub fn alloc_untyped(&mut self, base: u64, size: u64) -> Option<UntypedId> {
        let i = self.untyped.iter().position(|s| s.is_none())?;
        self.untyped[i] = Some(UntypedMemory::new(
            hal_core::PhysAddr::new(base as usize),
            size,
        ));
        Some(UntypedId::new(i as u32))
    }

    /// Allocates an `Inactive` TCB bound to `cap_space` / `addr_space`,
    /// returning its `ThreadId`.
    pub fn alloc_tcb(&mut self, cap_space: CapSpaceId, addr_space: PageTableId) -> Option<ThreadId> {
        let i = self.tcbs.iter().position(|s| s.is_none())?;
        let id = ThreadId::new(i as u32);
        self.tcbs[i] = Some(Tcb::new_inactive(id, cap_space, addr_space));
        Some(id)
    }

    /// Allocates an `Endpoint` object, returning its id.
    pub fn alloc_endpoint(&mut self) -> Option<EndpointId> {
        let i = self.endpoints.iter().position(|s| s.is_none())?;
        self.endpoints[i] = Some(Endpoint::new());
        Some(EndpointId::new(i as u32))
    }

    /// Allocates a `Notification` object, returning its id.
    pub fn alloc_notification(&mut self) -> Option<NotificationId> {
        let i = self.notifications.iter().position(|s| s.is_none())?;
        self.notifications[i] = Some(Notification::new());
        Some(NotificationId::new(i as u32))
    }

    /// Allocates a `SharedRegion` object describing `region`, returning
    /// its id.
    pub fn alloc_shared_region(&mut self, region: SharedRegion) -> Option<SharedRegionId> {
        let i = self.shared_regions.iter().position(|s| s.is_none())?;
        self.shared_regions[i] = Some(region);
        Some(SharedRegionId::new(i as u32))
    }

    /// Directly seeds an `MmioRegion` object describing `descriptor`,
    /// returning its id. Not a `Retype` target (see `MmioRegionDescriptor`'s
    /// own doc comment) — called only from `populate_from_boot_info`'s
    /// Step 3c, exactly as `root_addr_space` is `alloc_addr_space`d
    /// directly rather than retyped.
    pub fn alloc_mmio_region_direct(
        &mut self,
        descriptor: MmioRegionDescriptor,
    ) -> Option<MmioRegionId> {
        let i = self.mmio_regions.iter().position(|s| s.is_none())?;
        self.mmio_regions[i] = Some(descriptor);
        Some(MmioRegionId::new(i as u32))
    }

    /// Binds hardware `irq` to `notification` — a hardware interrupt on
    /// this line signals that `Notification` object (03 §2.1). Called by
    /// `SyscallOp::IrqBind`. Overwrites an existing binding for the same
    /// `irq` (re-binding is the caller's choice to make, not an error
    /// this table enforces — `hal_core::interrupt::InterruptController::
    /// register_irq`'s own `IrqAlreadyRegistered` is the actual
    /// one-handler-per-line enforcement point). Returns `false` if the
    /// table is full and `irq` is not already bound.
    pub fn bind_irq(&mut self, irq: u32, notification: NotificationId) -> bool {
        if let Some(slot) = self.irq_bindings.iter_mut().find(|s| matches!(s, Some((i, _)) if *i == irq)) {
            *slot = Some((irq, notification));
            return true;
        }
        match self.irq_bindings.iter().position(|s| s.is_none()) {
            Some(i) => {
                self.irq_bindings[i] = Some((irq, notification));
                true
            }
            None => false,
        }
    }

    /// The `Notification` bound to hardware `irq`, if any. Called from
    /// the kernel-arch-glue-level IRQ trampoline registered via
    /// `HalInterface::register_irq` to find who to `signal()`.
    pub fn notification_for_irq(&self, irq: u32) -> Option<NotificationId> {
        self.irq_bindings
            .iter()
            .find_map(|s| s.and_then(|(i, nid)| (i == irq).then_some(nid)))
    }

    // ---- table accessors (used by syscall::dispatch) -------------

    /// Borrows a capability space.
    pub fn cap_space(&self, id: CapSpaceId) -> Option<&RootCapTable> {
        self.cap_spaces.get(id.as_usize()).and_then(|s| s.as_ref())
    }

    /// Borrows a capability space mutably.
    pub fn cap_space_mut(&mut self, id: CapSpaceId) -> Option<&mut RootCapTable> {
        self.cap_spaces.get_mut(id.as_usize()).and_then(|s| s.as_mut())
    }

    /// Borrows `src` (read-only) and `dst` (mutably) at the same time —
    /// needed by `kernel_cap::cdt::derive_child_cross_space`, whose
    /// signature takes exactly that shape. `None` if `src == dst` (granting
    /// a capability into your own space is not a supported operation — and
    /// would alias the same table as both `&` and `&mut`), either id is out
    /// of range, or either space is unallocated.
    pub fn cap_space_pair_mut(
        &mut self,
        src: CapSpaceId,
        dst: CapSpaceId,
    ) -> Option<(&RootCapTable, &mut RootCapTable)> {
        let si = src.as_usize();
        let di = dst.as_usize();
        if si == di || si >= self.cap_spaces.len() || di >= self.cap_spaces.len() {
            return None;
        }
        // Split the backing array at the larger index so `src` and `dst`
        // land in disjoint halves the borrow checker can see are
        // non-overlapping, then re-borrow whichever half holds `src` as
        // shared and the one holding `dst` as exclusive.
        if si < di {
            let (left, right) = self.cap_spaces.split_at_mut(di);
            Some((left[si].as_ref()?, right[0].as_mut()?))
        } else {
            let (left, right) = self.cap_spaces.split_at_mut(si);
            Some((right[0].as_ref()?, left[di].as_mut()?))
        }
    }

    /// Borrows every capability space at once — needed by
    /// `kernel_cap::cdt::revoke_cross_space`, which must be able to reach
    /// into any table a `CapGrant` may have placed a descendant in, not
    /// just the revoke target's own space.
    pub fn cap_spaces_mut(&mut self) -> &mut [Option<RootCapTable>; MAX_CAP_SPACES] {
        &mut self.cap_spaces
    }

    /// Borrows an `UntypedMemory` object mutably.
    pub fn untyped_mut(&mut self, id: UntypedId) -> Option<&mut UntypedMemory> {
        self.untyped.get_mut(id.as_usize()).and_then(|s| s.as_mut())
    }

    /// Borrows an address space mutably.
    pub fn addr_space_mut(&mut self, id: PageTableId) -> Option<&mut RootAddressSpace> {
        self.addr_spaces.get_mut(id.as_usize()).and_then(|s| s.as_mut())
    }

    /// Borrows an `Endpoint` object mutably.
    pub fn endpoint_mut(&mut self, id: EndpointId) -> Option<&mut KEndpoint> {
        self.endpoints.get_mut(id.as_usize()).and_then(|s| s.as_mut())
    }

    /// Borrows a `Notification` object mutably.
    pub fn notification_mut(&mut self, id: NotificationId) -> Option<&mut KNotification> {
        self.notifications
            .get_mut(id.as_usize())
            .and_then(|s| s.as_mut())
    }

    /// Borrows a `SharedRegion` object.
    pub fn shared_region(&self, id: SharedRegionId) -> Option<&SharedRegion> {
        self.shared_regions.get(id.as_usize()).and_then(|s| s.as_ref())
    }

    /// Borrows an `MmioRegion` descriptor.
    pub fn mmio_region(&self, id: MmioRegionId) -> Option<&MmioRegionDescriptor> {
        self.mmio_regions.get(id.as_usize()).and_then(|s| s.as_ref())
    }

    /// Borrows a TCB mutably.
    pub fn tcb_mut(&mut self, id: ThreadId) -> Option<&mut Tcb> {
        self.tcbs.get_mut(id.as_usize()).and_then(|s| s.as_mut())
    }

    /// Borrows a TCB.
    pub fn tcb(&self, id: ThreadId) -> Option<&Tcb> {
        self.tcbs.get(id.as_usize()).and_then(|s| s.as_ref())
    }

    /// Element pointer of the TCB table, for `preempt.rs` to form
    /// non-aliasing raw pointers into two distinct `Tcb::user_context`
    /// buffers during a preemptive switch (the borrow checker cannot see
    /// that two different indices don't overlap).
    pub(crate) fn tcbs_mut_ptr(&mut self) -> *mut Option<Tcb> {
        self.tcbs.as_mut_ptr()
    }

    // ---- boot construction -------------------------------------

    /// Builds the initial kernel state from the HAL handoff.
    ///
    /// Steps (02-Microkernel-Layer.md §8.1):
    ///   1. re-run `BootInfo::validate` (defence in depth — arch-glue also
    ///      validates before calling this);
    ///   2. create the Root Task's capability space, address space (rooted
    ///      at `boot.initial_page_table_phys`), and TCB;
    ///   3. for every `Usable` memory region in the manifest that does not
    ///      overlap the kernel image or boot-reserved ranges, create one
    ///      `UntypedMemory` object and insert a full capability to it as a
    ///      CDT root in the Root Task's capability space (§3 — "کل حافظه‌ی
    ///      فیزیکی ... به شکل چند شیء UntypedMemory به اولین پروسه داده
    ///      می‌شود");
    ///   4. admit the Root Task to the scheduler (Interactive mode, top
    ///      priority) and mark it runnable.
    ///
    /// Postcondition on `Ok`: `root_thread` names a `Runnable` TCB whose
    /// capability space holds `untyped_count >= 1` untyped capabilities.
    pub fn from_boot_info(boot: &BootInfo) -> Result<Self, KernelInitError> {
        // Host / test path: `KernelState` is ~0.25 MB, which is fine on a
        // host thread stack. On the real kernel's 64 KiB boot stack this
        // by-value construction overflows — the bare-metal path must use
        // `init_global` instead (see its docs).
        let mut st = Self::EMPTY;
        st.populate_from_boot_info(boot)?;
        Ok(st)
    }

    /// A fully-empty `KernelState`: every object table `None`, the
    /// scheduler freshly constructed, the Root Task ids left at `0` until
    /// `populate_from_boot_info` fills them.
    ///
    /// This is a `const` so `init_global` can place the whole (large)
    /// structure directly in a `static` — no stack temporary, no move.
    pub const EMPTY: Self = KernelState {
        cap_spaces: [const { None }; MAX_CAP_SPACES],
        untyped: [const { None }; MAX_UNTYPED],
        addr_spaces: [const { None }; MAX_ADDR_SPACES],
        endpoints: [const { None }; MAX_ENDPOINTS],
        notifications: [const { None }; MAX_NOTIFICATIONS],
        shared_regions: [const { None }; MAX_SHARED_REGIONS],
        mmio_regions: [const { None }; MAX_MMIO_REGIONS],
        irq_bindings: [const { None }; MAX_IRQ_BINDINGS],
        tcbs: [const { None }; MAX_THREADS],
        sched: Scheduler::new(INTERACTIVE_QUANTUM_NS),
        root_thread: ThreadId::new(0),
        root_cap_space: CapSpaceId::new(0),
        root_addr_space: PageTableId::new(0),
        root_page_table_cap: CapId::new(u32::MAX),
        root_mmio_blk_cap: CapId::new(u32::MAX),
        root_mmio_net_cap: CapId::new(u32::MAX),
        untyped_count: 0,
        map_pool_base: 0,
        map_pool_len: 0,
        map_pool_used: 0,
    };

    /// Installs the physical scratch-frame pool `do_map` draws from to
    /// walk a `Map` syscall into real hardware page-table entries.
    /// `base` must be a page-aligned, pre-zeroed physical range of `len`
    /// pages that `kernel-arch-glue` carved from untyped RAM and that
    /// stays identity-addressable for the life of the system (the same
    /// contract `map_user_page`'s pool already relies on). Resets the
    /// high-water mark to `0`.
    ///
    /// Called once, at boot, after the architecture's Sv39-equivalent
    /// paging is up. Never called (pool stays `0`/absent) on an
    /// architecture with no working `map_range` yet — `do_map` then
    /// silently stays software-model-only for `Map` (see `MmError::
    /// HardwareMapFailed`'s doc comment).
    pub fn install_map_pool(&mut self, base: usize, len: u32) {
        self.map_pool_base = base;
        self.map_pool_len = len;
        self.map_pool_used = 0;
    }

    /// Physical base of the pool, or `0` if none is installed — `do_map`
    /// (`syscall.rs`) checks this to decide whether to attempt the
    /// hardware walk at all.
    pub fn map_pool_base(&self) -> usize {
        self.map_pool_base
    }

    /// `(pool_base_for_next_call, frames_still_free)` — where `do_map`'s
    /// next `hal.map_range` call should draw from, and how many frames it
    /// may still consume.
    pub fn map_pool_remaining(&self) -> (usize, usize) {
        (
            self.map_pool_base + self.map_pool_used as usize * kernel_mm::PAGE_SIZE,
            (self.map_pool_len - self.map_pool_used) as usize,
        )
    }

    /// Advances the pool's high-water mark by `consumed` frames (the
    /// count `hal.map_range` returned).
    pub fn map_pool_advance(&mut self, consumed: u32) {
        self.map_pool_used += consumed;
    }

    /// Fills an `EMPTY` `KernelState` in place from the HAL handoff —
    /// same work as `from_boot_info`, minus the by-value construction.
    ///
    /// Precondition: `self` is `KernelState::EMPTY` (never been populated).
    /// Postcondition on `Ok`: `self.root_thread` names a `Runnable` TCB
    /// whose capability space holds `self.untyped_count >= 1` untyped
    /// capabilities.
    pub fn populate_from_boot_info(&mut self, boot: &BootInfo) -> Result<(), KernelInitError> {
        boot.validate().map_err(|_| KernelInitError::BadBootInfo)?;

        // Step 2: Root Task cap space / addr space / TCB.
        let root_cs = self
            .alloc_cap_space()
            .ok_or(KernelInitError::CapacityExhausted)?;
        let root_as = self
            .alloc_addr_space(boot.initial_page_table_phys)
            .ok_or(KernelInitError::CapacityExhausted)?;
        let root_tid = self
            .alloc_tcb(root_cs, root_as)
            .ok_or(KernelInitError::CapacityExhausted)?;

        // Step 3: seed UntypedMemory from usable RAM. A `Usable` region
        // typically *contains* the kernel image and the boot-reserved
        // range (on QEMU virt there is one big RAM region), so those
        // sub-ranges are carved OUT and only the remaining fragments
        // become `UntypedMemory` (§3 / `BootInfo::overlaps_*`).
        let holes = [
            (boot.kernel_image_phys_start, boot.kernel_image_phys_end),
            (boot.boot_reserved_phys_start, boot.boot_reserved_phys_end),
            // Everything below where the kernel image was loaded: on
            // RISC-V/QEMU this is the OpenSBI firmware, which is PMP-
            // protected against S/U access — handing it out as
            // `UntypedMemory` produces access faults the moment anything
            // touches it. On UEFI targets this conservatively drops a
            // few MiB of low RAM, which is acceptable for the MVP.
            // TODO(omid): have the HAL memory discovery classify the
            // firmware region as `Reserved` so this blanket hole is
            // unnecessary.
            (0, boot.kernel_image_phys_start),
        ];
        let page = kernel_mm::PAGE_SIZE as u64;
        let manifest = &boot.hardware_manifest;
        let mut untyped_made: u32 = 0;
        'regions: for region in manifest.memory_regions() {
            if region.kind != MemoryRegionKindRaw::Usable || region.length_bytes < page {
                continue;
            }
            let start = region.base_addr;
            let end = region.base_addr.saturating_add(region.length_bytes);

            let mut frags = [(0u64, 0u64); 8];
            let nfrags = subtract_holes(start, end, &holes, &mut frags);
            for &(fs, fe) in &frags[..nfrags] {
                if fe.saturating_sub(fs) < page {
                    continue;
                }
                let Some(uid) = self.alloc_untyped(fs, fe - fs) else {
                    break 'regions; // MAX_UNTYPED reached: keep what we have.
                };
                let cap = Capability::full(ObjectRef::new(
                    KernelObjectKind::UntypedMemory,
                    ObjectId::new(uid.as_u32()),
                ));
                let cs = self.cap_space_mut(root_cs).expect("root cap space exists");
                match cs.insert_root(cap) {
                    Ok(_) => untyped_made += 1,
                    Err(_) => break 'regions, // cap space full
                }
            }
        }
        if untyped_made == 0 {
            return Err(KernelInitError::NoUsableMemory);
        }

        // Step 3b: seed a `PageTable` capability naming the Root Task's
        // OWN address space (`root_as`) into its cap space. Unlike every
        // other kernel object, `root_as` was created directly via
        // `alloc_addr_space` above, not through a `Retype` — so without
        // this, the Root Task would have no capability satisfying
        // `SyscallOp::Map`'s `page_table` argument for its own space,
        // even though it plainly has authority over it. Best-effort: a
        // full cap-space or a duplicate slot is not fatal to boot (the
        // Root Task just cannot `Map` into its own space via the real
        // syscall in that case — the untyped-exhaustion path above is the
        // only genuinely fatal one, since untyped memory is what every
        // other object is retyped from).
        let pt_cap = Capability::full(ObjectRef::new(
            KernelObjectKind::PageTable,
            ObjectId::new(root_as.as_u32()),
        ));
        let root_page_table_cap = self
            .cap_space_mut(root_cs)
            .expect("root cap space exists")
            .insert_root(pt_cap)
            .unwrap_or(CapId::new(u32::MAX));

        // Step 3c: mint an `MmioRegion` capability for the first
        // `Block`-kind device the boot-time HAL peripheral scan
        // discovered (`hardware_manifest.peripheral_devices()` — see
        // `MmioRegionDescriptor`'s own doc comment for why this bypasses
        // `Retype` exactly like Step 3b's `PageTable` capability does).
        // MVP scope: only the first Block device, matching this
        // project's only driver (virtio-blk) so far; best-effort, same
        // as Step 3b — a full cap space or no Block device present is
        // not fatal to boot.
        let root_mmio_blk_cap = boot
            .hardware_manifest
            .peripheral_devices()
            .iter()
            .find(|d| d.kind == PeripheralKindRaw::Block)
            .and_then(|d| {
                self.alloc_mmio_region_direct(MmioRegionDescriptor {
                    phys_base: d.mmio_base,
                    size: d.mmio_size,
                    irq: d.irq,
                    config_space_base: d.config_space_base,
                })
            })
            .and_then(|mmio_id| {
                let cap = Capability::full(ObjectRef::new(
                    KernelObjectKind::MmioRegion,
                    ObjectId::new(mmio_id.as_u32()),
                ));
                self.cap_space_mut(root_cs)
                    .expect("root cap space exists")
                    .insert_root(cap)
                    .ok()
            })
            .unwrap_or(CapId::new(u32::MAX));

        // Step 3d: same as Step 3c, for the first `Network`-kind device
        // — `root_mmio_net_cap`'s own doc comment covers the rationale
        // (unblocks `driver-virtio-net`, 03-Kernel-Subsystems-Layer.md
        // §2.3/§5.4).
        let root_mmio_net_cap = boot
            .hardware_manifest
            .peripheral_devices()
            .iter()
            .find(|d| d.kind == PeripheralKindRaw::Network)
            .and_then(|d| {
                self.alloc_mmio_region_direct(MmioRegionDescriptor {
                    phys_base: d.mmio_base,
                    size: d.mmio_size,
                    irq: d.irq,
                    config_space_base: d.config_space_base,
                })
            })
            .and_then(|mmio_id| {
                let cap = Capability::full(ObjectRef::new(
                    KernelObjectKind::MmioRegion,
                    ObjectId::new(mmio_id.as_u32()),
                ));
                self.cap_space_mut(root_cs)
                    .expect("root cap space exists")
                    .insert_root(cap)
                    .ok()
            })
            .unwrap_or(CapId::new(u32::MAX));

        // Step 4: schedule the Root Task.
        self.sched
            .admit(root_tid, SchedulerMode::Interactive, kernel_sched::MAX_PRIORITY, None)
            .map_err(|_| KernelInitError::CapacityExhausted)?;
        self.sched
            .note_ready(root_tid, 0)
            .map_err(|_| KernelInitError::CapacityExhausted)?;
        if let Some(tcb) = self.tcb_mut(root_tid) {
            tcb.entry = VirtAddr::new(0); // set by whoever loads the Root Task image
            tcb.state = ThreadState::Runnable;
        }

        self.root_thread = root_tid;
        self.root_cap_space = root_cs;
        self.root_addr_space = root_as;
        self.root_page_table_cap = root_page_table_cap;
        self.root_mmio_blk_cap = root_mmio_blk_cap;
        self.root_mmio_net_cap = root_mmio_net_cap;
        self.untyped_count = untyped_made;
        Ok(())
    }

    /// Bare-metal entry: constructs the kernel state in a `static` (no
    /// stack temporary) and populates it from `boot`. Returns a
    /// `'static` mutable reference for `kernel-arch-glue` to drive.
    ///
    /// # Safety / contract
    /// Must be called exactly once, on the boot core, before anything
    /// else touches kernel state. A second call returns
    /// `Err(KernelInitError::AlreadyInitialised)`.
    pub fn init_global(boot: &BootInfo) -> Result<&'static mut KernelState, KernelInitError> {
        // Single instance for the life of the system, living in `.bss`
        // (mostly zeros) so it never transits the boot stack.
        static mut KERNEL_STATE: KernelState = KernelState::EMPTY;
        static mut INITIALISED: bool = false;

        // SAFETY: single-core boot, called once. `addr_of_mut!` avoids
        // forming an intermediate reference to the `static mut`.
        let already = unsafe { core::ptr::addr_of!(INITIALISED).read() };
        if already {
            return Err(KernelInitError::AlreadyInitialised);
        }
        // SAFETY: as above; exclusive access during single-core boot.
        let st: &'static mut KernelState = unsafe { &mut *core::ptr::addr_of_mut!(KERNEL_STATE) };
        st.populate_from_boot_info(boot)?;
        // SAFETY: as above.
        unsafe { core::ptr::addr_of_mut!(INITIALISED).write(true) };
        Ok(st)
    }

    /// Total `UntypedMemory` byte capacity currently held across all
    /// untyped objects (diagnostic — the boot report prints it).
    pub fn total_untyped_bytes(&self) -> u64 {
        self.untyped
            .iter()
            .flatten()
            .map(|u| u.size_bytes())
            .sum()
    }
}

/// Fills `out` with the sub-ranges of `[start, end)` NOT covered by any
/// interval in `holes`, in ascending order, and returns how many were
/// written. Holes are clamped to `[start, end)` and may overlap each
/// other or be adjacent. `out` should have room for `holes.len() + 1`
/// entries (extra holes past capacity 8 are ignored).
///
/// This is how `populate_from_boot_info` turns "one big RAM region that
/// contains the kernel image + boot stack" into the free fragments that
/// become `UntypedMemory` (02-Microkernel-Layer.md §3).
fn subtract_holes(start: u64, end: u64, holes: &[(u64, u64)], out: &mut [(u64, u64)]) -> usize {
    // Clamp, drop empty/non-overlapping holes, insertion-sort by start.
    let mut hs: [(u64, u64); 8] = [(0, 0); 8];
    let mut n = 0usize;
    for &(a, b) in holes {
        let a = a.max(start);
        let b = b.min(end);
        if a >= b || n >= hs.len() {
            continue;
        }
        let mut i = n;
        while i > 0 && hs[i - 1].0 > a {
            hs[i] = hs[i - 1];
            i -= 1;
        }
        hs[i] = (a, b);
        n += 1;
    }

    let mut cur = start;
    let mut k = 0usize;
    for &(a, b) in &hs[..n] {
        if a > cur && k < out.len() {
            out[k] = (cur, a);
            k += 1;
        }
        if b > cur {
            cur = b;
        }
    }
    if cur < end && k < out.len() {
        out[k] = (cur, end);
        k += 1;
    }
    k
}

#[cfg(test)]
mod subtract_holes_tests {
    use super::subtract_holes;

    fn run(start: u64, end: u64, holes: &[(u64, u64)]) -> Frags {
        let mut out = [(0u64, 0u64); 8];
        let n = subtract_holes(start, end, holes, &mut out);
        Frags { out, n }
    }
    struct Frags {
        out: [(u64, u64); 8],
        n: usize,
    }
    impl Frags {
        fn as_slice(&self) -> &[(u64, u64)] {
            &self.out[..self.n]
        }
    }

    #[test]
    fn no_holes_returns_whole_range() {
        assert_eq!(run(0, 100, &[]).as_slice(), &[(0, 100)]);
    }

    #[test]
    fn one_interior_hole_splits_in_two() {
        assert_eq!(run(0, 100, &[(40, 60)]).as_slice(), &[(0, 40), (60, 100)]);
    }

    #[test]
    fn two_holes_produce_three_fragments() {
        assert_eq!(
            run(0, 100, &[(60, 70), (20, 30)]).as_slice(),
            &[(0, 20), (30, 60), (70, 100)]
        );
    }

    #[test]
    fn overlapping_holes_merge() {
        assert_eq!(
            run(0, 100, &[(20, 50), (40, 70)]).as_slice(),
            &[(0, 20), (70, 100)]
        );
    }

    #[test]
    fn hole_at_start_and_end_clamps() {
        assert_eq!(
            run(100, 200, &[(0, 120), (180, 999)]).as_slice(),
            &[(120, 180)]
        );
    }

    #[test]
    fn hole_covering_everything_yields_nothing() {
        assert_eq!(run(0, 100, &[(0, 100)]).as_slice(), &[] as &[(u64, u64)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_core::BootProtocol;
    use hal_manifest::raw::{
        HardwareManifestRaw, MemoryRegionKindRaw, MemoryRegionRaw, TimerInfoRaw, TimerKindRaw,
    };

    fn boot_with_ram(mb: u64) -> BootInfo {
        let mut m = HardwareManifestRaw::zeroed();
        m.cpu_core_count = 2;
        m.push_memory_region(MemoryRegionRaw::new(
            0x100_0000,
            mb * 1024 * 1024,
            MemoryRegionKindRaw::Usable,
            false,
        ))
        .unwrap();
        m.timer = TimerInfoRaw::new(TimerKindRaw::Tsc, 1_000_000_000, false);
        BootInfo::new(
            BootProtocol::Uefi,
            m,
            0x1000,
            (0x10_0000, 0x20_0000),
            (0x20_0000, 0x21_0000),
            0,
        )
    }

    #[test]
    fn from_boot_info_creates_root_task_and_untyped() {
        let boot = boot_with_ram(64);
        let st = KernelState::from_boot_info(&boot).unwrap();
        assert_eq!(st.untyped_count, 1);
        assert_eq!(st.total_untyped_bytes(), 64 * 1024 * 1024);
        // Root Task is runnable and is the only ready thread.
        assert_eq!(st.sched.pick_next(0), Some(st.root_thread));
        assert_eq!(
            st.tcb(st.root_thread).unwrap().state,
            ThreadState::Runnable
        );
        // Its cap space holds exactly one (untyped) capability.
        // (Immutable check via a fresh construction is enough here.)
    }

    #[test]
    fn rejects_manifest_with_no_memory() {
        // A manifest with a live timer but zero memory regions fails
        // `BootInfo::validate` first.
        let mut m = HardwareManifestRaw::zeroed();
        m.timer = TimerInfoRaw::new(TimerKindRaw::Tsc, 1_000_000_000, false);
        let boot = BootInfo::new(
            BootProtocol::Uefi,
            m,
            0x1000,
            (0x10_0000, 0x20_0000),
            (0x20_0000, 0x21_0000),
            0,
        );
        // `KernelState` is a large struct that intentionally derives
        // neither `Debug` nor `PartialEq`, so match on the error rather
        // than `assert_eq!` the whole `Result`.
        assert!(matches!(
            KernelState::from_boot_info(&boot),
            Err(KernelInitError::BadBootInfo)
        ));
    }
}
