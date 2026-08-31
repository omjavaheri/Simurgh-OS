//! ============================================================================
//! driver-virtio-blk
//!
//! Purpose: the MVP block driver — virtio-blk over MMIO on QEMU
//! (03-Kernel-Subsystems-Layer.md §5.1). Runs as its own isolated process,
//! implements `driver_framework::DeviceDriver`, and serves
//! `DriverRequest::{ReadBlocks,WriteBlocks}` by driving a virtio virtqueue.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.1 (driver
//! process model), §5.1 (virtio-blk on QEMU is the named acceptance
//! device), §5.2 (an injected panic must trigger a Device Manager
//! restart — so this driver deliberately does not swallow its own faults).
//!
//! Position in the system: layer-3 process, spawned by
//! `kernel_arch_glue::spawn_virtio_blk_driver`. Its virtio-mmio window
//! (discovered by the HAL peripheral scan, `hal_core::peripheral`) is
//! pre-mapped directly into its address space at boot-glue time (like
//! `.user_text`/stack — trusted setup, not a runtime `Map` syscall this
//! process issues itself); its virtqueue/data buffer lives in a real
//! `SharedRegion` capability, also pre-mapped.
//!
//! MVP scope: `do_probe` runs the full virtio 1.x device-init handshake
//! and `submit_request`/`ack_completion` drive a real 3-descriptor
//! split-ring chain (header/data/status) for exactly one request in
//! flight at a time, one sector per request. TWO completion strategies
//! coexist, deliberately kept separate:
//!   - `wait_for_completion` (private, used by `handle_request`'s own
//!     `ReadBlocks`/`WriteBlocks` arms): a bounded busy-poll on the
//!     used ring, host-testable, no ecall access needed. The original
//!     MVP path; kept as a documented, still-correct alternative (e.g.
//!     a future platform with no usable IRQ line).
//!   - The REAL, production path: `subsystem_entry.rs` (which alone can
//!     issue ecalls) calls `submit_request` directly, then a real
//!     `SyscallOp::Wait` on the `Notification` its own `IrqBind`
//!     capability grant bound to the device's IRQ line, genuinely
//!     idling the core (`hal_riscv64::cpu::wfi`, driven from `kernel/
//!     src/main.rs`'s own `DRV_IRQ_WAIT` ecall) until the interrupt
//!     actually fires, then `ack_completion`. `handle_request` is
//!     bypassed entirely for `ReadBlocks`/`WriteBlocks` in this path —
//!     see `subsystem_entry.rs`'s own doc comment.
//!
//! Safety/invariants: every MMIO/virtqueue-memory access goes through
//! `read_volatile`/`write_volatile` with a `// SAFETY:` note tying it to
//! the caller's "already mapped" contract (`self.ready` — set only once
//! `probe` has mapped and verified both regions).
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod subsystem_entry;

use driver_framework::{DeviceDriver, DeviceInfo, DriverError};
use ipc_protocol::driver::DriverErrorCode;
use ipc_protocol::{DriverRequest, DriverResponse};

/// virtio-mmio register offsets (virtio 1.x spec §4.2.2, "modern"/
/// version-2 transport — this project's HAL peripheral discovery only
/// ever reports a device whose `MAGIC_VALUE`/`VERSION` already passed,
/// so this driver never needs to handle the legacy version-1 layout).
/// Only the ones this driver needs.
pub mod mmio {
    /// `0x74726976` ("virt" LE) if a virtio-mmio device is present.
    pub const MAGIC_VALUE: usize = 0x000;
    /// Device version (2 for virtio 1.x / "modern").
    pub const VERSION: usize = 0x004;
    /// Device type (2 = block device).
    pub const DEVICE_ID: usize = 0x008;
    /// Device feature bits, 32 at a time — which 32 selected by
    /// `DEVICE_FEATURES_SEL`.
    pub const DEVICE_FEATURES: usize = 0x010;
    /// Selects which 32-bit word of `DEVICE_FEATURES` is visible.
    pub const DEVICE_FEATURES_SEL: usize = 0x014;
    /// Driver feature bits accepted, 32 at a time — which 32 selected by
    /// `DRIVER_FEATURES_SEL`.
    pub const DRIVER_FEATURES: usize = 0x020;
    /// Selects which 32-bit word `DRIVER_FEATURES` writes.
    pub const DRIVER_FEATURES_SEL: usize = 0x024;
    /// Driver status register.
    pub const STATUS: usize = 0x070;
    /// Selected queue index.
    pub const QUEUE_SEL: usize = 0x030;
    /// Max size of the selected queue (0 = unavailable).
    pub const QUEUE_NUM_MAX: usize = 0x034;
    /// Size to use for the selected queue.
    pub const QUEUE_NUM: usize = 0x038;
    /// Queue ready flag: write 1 once the queue's addresses below are
    /// set, to tell the device this queue is live.
    pub const QUEUE_READY: usize = 0x044;
    /// Notify the device that the selected queue has new buffers.
    pub const QUEUE_NOTIFY: usize = 0x050;
    /// Interrupt status (bit 0: used-ring update).
    pub const INTERRUPT_STATUS: usize = 0x060;
    /// Acknowledge handled interrupts.
    pub const INTERRUPT_ACK: usize = 0x064;
    /// Descriptor table physical address, low/high 32 bits (modern/
    /// version-2 transport: each virtqueue part has its OWN physical
    /// address register pair, unlike legacy virtio's single aligned
    /// block — spec §4.2.3.2).
    pub const QUEUE_DESC_LOW: usize = 0x080;
    /// High 32 bits of the descriptor table physical address.
    pub const QUEUE_DESC_HIGH: usize = 0x084;
    /// Driver (avail) ring physical address, low 32 bits.
    pub const QUEUE_DRIVER_LOW: usize = 0x090;
    /// High 32 bits of the avail ring physical address.
    pub const QUEUE_DRIVER_HIGH: usize = 0x094;
    /// Device (used) ring physical address, low 32 bits.
    pub const QUEUE_DEVICE_LOW: usize = 0x0a0;
    /// High 32 bits of the used ring physical address.
    pub const QUEUE_DEVICE_HIGH: usize = 0x0a4;
    /// Device-specific config space (block capacity lives here).
    pub const CONFIG: usize = 0x100;
}

/// `STATUS` register bits (virtio 1.x spec §2.1) — the driver
/// initialization handshake this driver's `probe` drives through in
/// order: ACKNOWLEDGE -> DRIVER -> (negotiate features) -> FEATURES_OK
/// -> (verify FEATURES_OK stuck) -> (set up virtqueue) -> DRIVER_OK.
pub mod status {
    /// Guest OS has found the device and recognized it as valid.
    pub const ACKNOWLEDGE: u32 = 1;
    /// Guest OS knows how to drive the device.
    pub const DRIVER: u32 = 2;
    /// Something went wrong; the driver has given up.
    pub const FAILED: u32 = 128;
    /// The driver has acknowledged the negotiated feature set.
    pub const FEATURES_OK: u32 = 8;
    /// The driver is set up and ready to drive the device.
    pub const DRIVER_OK: u32 = 4;
}

/// `VIRTIO_F_VERSION_1` (feature bit 32) — mandatory for the modern
/// transport this driver speaks (spec §6: a legacy-unaware driver MUST
/// accept this bit or the device will refuse `FEATURES_OK`). This
/// driver negotiates ONLY this bit — no queue-size/indirect/event-idx
/// extensions — matching its own fixed `QUEUE_SIZE` MVP scope below.
pub const VIRTIO_F_VERSION_1: u32 = 1 << (32 - 32); // bit 32, word index 1

/// Fixed virtqueue size this driver sets up — the next power of 2 above
/// the smallest legal size that can hold one full virtio-blk request
/// chain (header + data + status = 3 descriptors). The virtio 1.x spec
/// itself does not require a power-of-2 queue size for the modern
/// split-virtqueue layout, but real device backends (QEMU's virtio-mmio
/// included) commonly compute ring-index wraparound as `idx &
/// (QUEUE_SIZE - 1)` internally, which is only correct for a power-of-2
/// size — `QUEUE_SIZE = 3` silently produced a device that never
/// completed a request (confirmed via QEMU: `probe()`'s own MMIO
/// handshake, including reading real config-space capacity, succeeded
/// completely, but the used ring never advanced after `submit_request`
/// rang the doorbell). One slot goes unused per chain; MVP scope is
/// still exactly one request in flight at a time, so this costs nothing.
pub const QUEUE_SIZE: u16 = 4;

/// virtio-blk request-queue index (the only queue this device type
/// exposes — spec §5.2.2).
pub const REQUEST_QUEUE: u32 = 0;

/// virtio-blk request type (first 4 bytes of the request header).
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlkReqType {
    /// Read sectors from the device.
    In = 0,
    /// Write sectors to the device.
    Out = 1,
    /// Flush the device write cache.
    Flush = 4,
}

/// The virtio-blk 16-byte request header that precedes the data buffer in
/// a virtqueue descriptor chain (virtio spec §5.2.6).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BlkReqHeader {
    /// `BlkReqType`.
    pub req_type: u32,
    /// Reserved, must be zero.
    pub reserved: u32,
    /// Starting sector (512-byte units regardless of logical block size).
    pub sector: u64,
}

/// The virtqueue split-ring layout this driver builds inside its own
/// granted `queue_base` region (03 §5.1's own "DMA-capable SharedRegion"
/// — one page, matching `kernel_mm::object_size_bytes(SharedRegion)`).
/// Modern (version-2) virtio-mmio transport: descriptor table, avail
/// (driver) ring, and used (device) ring each get their OWN physical
/// address register pair (spec §4.2.3.2), so — unlike legacy virtio —
/// there is no single combined alignment rule to satisfy, only each
/// sub-structure's own natural alignment; laying all three out inside
/// one page-aligned region trivially satisfies every one of them.
///
/// Byte layout (all offsets from `queue_base`):
///   `0..8`     `queue_phys_base` (u64 LE) — the region's own physical
///              base address, written by `kernel_arch_glue` before this
///              process's first instruction runs (this process has no
///              other way to learn its own physical mapping — no
///              VA-to-PA translation syscall exists for a non-root
///              thread).
///   `16..80`   descriptor table (`QUEUE_SIZE` * 16 bytes = 64 bytes).
///   `80..94`   avail (driver) ring.
///   `128..158` used (device) ring.
///   `256..272` `BlkReqHeader` (request header buffer, descriptor 0).
///   `272..273` status byte (device-written, descriptor 2).
///   `512..1024` sector data buffer (descriptor 1) — one `SECTOR_SIZE`
///              sector; MVP scope is one request in flight, one sector
///              per request (`DriverRequest::{Read,Write}Blocks`'s own
///              `sector_count` beyond 1 is rejected, see
///              `handle_request`).
///   `1024..1080` the `DriverRequest`/`DriverResponse` `SmallMessage`
///              marshaling area — this driver's own `subsystem_entry`
///              reads/writes it exactly like `fs-native`'s
///              `FS_SHARED_VA` page, reusing this SAME region rather
///              than requesting a second capability grant.
pub mod layout {
    /// The region's own physical base address, as a little-endian `u64`.
    pub const PHYS_BASE_OFFSET: usize = 0;
    /// The descriptor table (`QUEUE_SIZE` * 16 bytes).
    pub const DESC_OFFSET: usize = 16;
    /// The avail (driver) ring — `DESC_OFFSET + QUEUE_SIZE * 16`
    /// (`driver_virtio_blk::QUEUE_SIZE` = 4, so the descriptor table
    /// spans `16..80`).
    pub const AVAIL_OFFSET: usize = 80;
    /// The used (device) ring.
    pub const USED_OFFSET: usize = 128;
    /// The `BlkReqHeader` request-header buffer (descriptor 0).
    pub const HEADER_OFFSET: usize = 256;
    /// The device-written status byte (descriptor 2).
    pub const STATUS_OFFSET: usize = 272;
    /// The one-sector data buffer (descriptor 1).
    pub const DATA_OFFSET: usize = 512;
    /// Small-message (`DriverRequest`/`DriverResponse`) marshaling area
    /// — see `subsystem_entry.rs`'s own `read_shared_message`/
    /// `write_shared_message`, which use this same offset.
    pub const MESSAGE_OFFSET: usize = 1024;
}

/// Sentinel `wait_for_completion` returns when the used ring never
/// advances within its own bounded spin — see that function's own doc
/// comment.
const STATUS_TIMEOUT: u8 = 0xFE;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// Reads a `u16` from `queue_base + offset` (the virtqueue lives in
/// ordinary, non-MMIO RAM — the granted `SharedRegion` — so a plain
/// volatile access is enough; no MMIO side effects to order against).
///
/// # Safety
/// `queue_base + offset + 2` must be within the mapped `SharedRegion`.
unsafe fn q_read_u16(queue_base: usize, offset: usize) -> u16 {
    // SAFETY: forwarded from this function's own contract.
    unsafe { ((queue_base + offset) as *const u16).read_volatile() }
}

/// # Safety
/// `queue_base + offset + 2` must be within the mapped `SharedRegion`.
unsafe fn q_write_u16(queue_base: usize, offset: usize, value: u16) {
    // SAFETY: forwarded from this function's own contract.
    unsafe { ((queue_base + offset) as *mut u16).write_volatile(value) };
}

/// The virtio-blk driver state.
pub struct VirtioBlk {
    /// Mapped MMIO base of the virtio-mmio transport (0 until granted).
    mmio_base: usize,
    /// Mapped virtual base of this driver's own virtqueue/data
    /// `SharedRegion` (0 until granted) — see `layout`'s own doc
    /// comment for the byte layout inside it.
    queue_base: usize,
    /// Device capacity in 512-byte sectors, read from config space in
    /// `probe`.
    capacity_sectors: u64,
    /// Whether `probe` has completed.
    ready: bool,
    /// The `avail.idx`/`used.idx` value after the last request this
    /// driver published — both start at 0 and only ever increase by 1
    /// per request (MVP scope: exactly one chain in flight at a time,
    /// so there is never more than one outstanding avail/used entry to
    /// track).
    next_idx: u16,
}

impl VirtioBlk {
    /// Creates the driver bound to a virtio-mmio window mapped at
    /// `mmio_base` and a virtqueue/data region mapped at `queue_base`
    /// (pass 0/0 in tests, before either grant exists).
    pub const fn new(mmio_base: usize, queue_base: usize) -> Self {
        Self {
            mmio_base,
            queue_base,
            capacity_sectors: 0,
            ready: false,
            next_idx: 0,
        }
    }

    /// Sector size this driver reports (virtio-blk is always 512-byte
    /// sectors at the transport level).
    pub const SECTOR_SIZE: u32 = 512;

    /// Reads a 32-bit virtio-mmio register.
    ///
    /// # Safety
    /// `self.mmio_base` must be a real, mapped virtio-mmio transport
    /// window at least `reg + 4` bytes long.
    unsafe fn reg_read(&self, reg: usize) -> u32 {
        // SAFETY: forwarded from this function's own contract.
        unsafe { ((self.mmio_base + reg) as *const u32).read_volatile() }
    }

    /// Writes a 32-bit virtio-mmio register.
    ///
    /// # Safety
    /// Same contract as `reg_read`.
    unsafe fn reg_write(&self, reg: usize, value: u32) {
        // SAFETY: forwarded from this function's own contract.
        unsafe { ((self.mmio_base + reg) as *mut u32).write_volatile(value) };
    }

    /// The physical address of `queue_base + offset`, derived from the
    /// header word `kernel_arch_glue` wrote at `layout::PHYS_BASE_OFFSET`
    /// (see `layout`'s own doc comment on why this driver has no other
    /// way to learn it).
    ///
    /// # Safety
    /// `self.queue_base` must be mapped and its header word populated
    /// (true from the moment this process is first scheduled — see
    /// `layout`'s own doc comment).
    unsafe fn queue_phys(&self, offset: usize) -> u64 {
        // SAFETY: forwarded from this function's own contract.
        let base = unsafe {
            ((self.queue_base + layout::PHYS_BASE_OFFSET) as *const u64).read_volatile()
        };
        base + offset as u64
    }

    /// Runs the virtio 1.x device-initialization handshake (spec §3.1)
    /// and sets up the request virtqueue. Real MMIO reads/writes
    /// throughout — see each field access's own `# Safety`.
    fn do_probe(&mut self) -> Result<(), DriverError> {
        // SAFETY: `self.mmio_base` is trusted per this method's own
        // contract (verified non-zero by the caller, `probe`).
        let magic = unsafe { self.reg_read(mmio::MAGIC_VALUE) };
        // SAFETY: same contract.
        let device_id = unsafe { self.reg_read(mmio::DEVICE_ID) };
        // SAFETY: same contract.
        let version = unsafe { self.reg_read(mmio::VERSION) };
        const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;
        const VIRTIO_BLOCK_DEVICE: u32 = 2;
        const VIRTIO_MMIO_VERSION_MODERN: u32 = 2;
        if magic != VIRTIO_MMIO_MAGIC || device_id != VIRTIO_BLOCK_DEVICE {
            return Err(DriverError::ProbeFailed);
        }
        // This driver's whole register map (`QUEUE_DESC_LOW` etc.) is
        // the modern/version-2 transport's own separate-address-per-
        // part layout (spec §4.2.3.2) — a version-1 (legacy) device
        // uses a completely different single `QUEUE_PFN` + implicit
        // page-alignment scheme these registers do not correspond to
        // at all, so treat anything else as a probe failure rather
        // than silently writing to registers the device does not
        // interpret the way this driver assumes.
        if version != VIRTIO_MMIO_VERSION_MODERN {
            return Err(DriverError::ProbeFailed);
        }

        // SAFETY: every register access below shares `reg_read`/
        // `reg_write`'s own contract, already established above.
        unsafe {
            // Reset, then the driver-presence handshake (spec §3.1
            // steps 1-2).
            self.reg_write(mmio::STATUS, 0);
            self.reg_write(mmio::STATUS, status::ACKNOWLEDGE);
            self.reg_write(mmio::STATUS, status::ACKNOWLEDGE | status::DRIVER);

            // Feature negotiation (spec §3.1 steps 3-6): this driver
            // accepts ONLY VIRTIO_F_VERSION_1 (bit 32, feature word 1)
            // — mandatory for the modern transport — and negotiates no
            // optional extensions (indirect descriptors, event index,
            // etc.), matching its own fixed `QUEUE_SIZE`/single-
            // in-flight-request MVP scope.
            self.reg_write(mmio::DEVICE_FEATURES_SEL, 1);
            let dev_features_hi = self.reg_read(mmio::DEVICE_FEATURES);
            self.reg_write(mmio::DRIVER_FEATURES_SEL, 0);
            self.reg_write(mmio::DRIVER_FEATURES, 0);
            self.reg_write(mmio::DRIVER_FEATURES_SEL, 1);
            self.reg_write(
                mmio::DRIVER_FEATURES,
                dev_features_hi & VIRTIO_F_VERSION_1,
            );
            self.reg_write(
                mmio::STATUS,
                status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK,
            );
            let after_features = self.reg_read(mmio::STATUS);
            if after_features & status::FEATURES_OK == 0 {
                self.reg_write(mmio::STATUS, status::FAILED);
                return Err(DriverError::ProbeFailed);
            }

            // Queue setup (spec §3.1 step 7, §4.2.3.2): queue 0 is
            // virtio-blk's only request queue.
            self.reg_write(mmio::QUEUE_SEL, REQUEST_QUEUE);
            let max = self.reg_read(mmio::QUEUE_NUM_MAX);
            if max == 0 || (max as u16) < QUEUE_SIZE {
                self.reg_write(mmio::STATUS, status::FAILED);
                return Err(DriverError::ProbeFailed);
            }
            self.reg_write(mmio::QUEUE_NUM, QUEUE_SIZE as u32);

            let desc_phys = self.queue_phys(layout::DESC_OFFSET);
            let avail_phys = self.queue_phys(layout::AVAIL_OFFSET);
            let used_phys = self.queue_phys(layout::USED_OFFSET);
            self.reg_write(mmio::QUEUE_DESC_LOW, desc_phys as u32);
            self.reg_write(mmio::QUEUE_DESC_HIGH, (desc_phys >> 32) as u32);
            self.reg_write(mmio::QUEUE_DRIVER_LOW, avail_phys as u32);
            self.reg_write(mmio::QUEUE_DRIVER_HIGH, (avail_phys >> 32) as u32);
            self.reg_write(mmio::QUEUE_DEVICE_LOW, used_phys as u32);
            self.reg_write(mmio::QUEUE_DEVICE_HIGH, (used_phys >> 32) as u32);
            self.reg_write(mmio::QUEUE_READY, 1);

            self.reg_write(
                mmio::STATUS,
                status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK,
            );

            // virtio-blk config space: `capacity` (u64 sectors) is the
            // struct's first field (spec §5.2.4).
            let cap_lo = self.reg_read(mmio::CONFIG) as u64;
            let cap_hi = self.reg_read(mmio::CONFIG + 4) as u64;
            self.capacity_sectors = cap_lo | (cap_hi << 32);
        }

        Ok(())
    }

    /// Publishes one request's descriptor chain (header -> data ->
    /// status, spec §5.2.6) and rings the doorbell. MVP scope: always
    /// uses descriptor slots `0,1,2` and avail/used index `self.
    /// next_idx` — safe because a caller (`handle_request`'s own
    /// polling path, or `subsystem_entry.rs`'s real interrupt-driven
    /// one) never issues a second request before this one's completion
    /// is observed (single in-flight chain).
    ///
    /// `pub`: `subsystem_entry.rs` (a different crate — the driver's
    /// own process entry point) calls this directly for the real
    /// interrupt-driven I/O path, since only IT can issue the actual
    /// `Wait` ecall in between submission and completion — see this
    /// module's own doc comment.
    ///
    /// # Safety
    /// `self.mmio_base`/`self.queue_base` must both be mapped (`probe`
    /// already succeeded — every caller checks `self.ready`/`is_ready`
    /// first).
    pub unsafe fn submit_request(&mut self, req_type: BlkReqType, sector: u64, data_len: usize) {
        let header = BlkReqHeader {
            req_type: req_type as u32,
            reserved: 0,
            sector,
        };
        // SAFETY: `layout::HEADER_OFFSET..+16` is within the mapped
        // `SharedRegion` (forwarded from this function's own contract).
        unsafe {
            ((self.queue_base + layout::HEADER_OFFSET) as *mut BlkReqHeader).write_volatile(header)
        };
        // SAFETY: `layout::STATUS_OFFSET` is within the mapped region;
        // 0xFF is a sentinel no real virtio-blk status code uses (valid
        // codes are 0/1/2 — spec §5.2.6), so `wait_for_completion` can
        // detect "device has not written a status yet" if ever needed.
        unsafe { ((self.queue_base + layout::STATUS_OFFSET) as *mut u8).write_volatile(0xFF) };

        let header_phys = unsafe { self.queue_phys(layout::HEADER_OFFSET) };
        let data_phys = unsafe { self.queue_phys(layout::DATA_OFFSET) };
        let status_phys = unsafe { self.queue_phys(layout::STATUS_OFFSET) };
        let write_to_device = req_type == BlkReqType::Out; // Out = driver->device

        // SAFETY: descriptor slots 0/1/2 are within the mapped region's
        // `DESC_OFFSET..+64` (`QUEUE_SIZE` = 4 slots, 16 bytes each —
        // this chain only ever uses the first 3).
        unsafe {
            let desc = |i: usize| (self.queue_base + layout::DESC_OFFSET + i * 16) as *mut VirtqDescRaw;
            desc(0).write_volatile(VirtqDescRaw {
                addr: header_phys,
                len: core::mem::size_of::<BlkReqHeader>() as u32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            });
            desc(1).write_volatile(VirtqDescRaw {
                addr: data_phys,
                len: data_len as u32,
                // The DATA buffer's own direction is the OPPOSITE of the
                // header's: an `In` (read) request has the DEVICE write
                // sector bytes into it (`F_WRITE` set); an `Out` (write)
                // request has the DRIVER's already-written bytes read
                // BY the device (`F_WRITE` clear) — `write_to_device`
                // names which direction THIS driver moved the bytes,
                // hence the negation here.
                flags: VIRTQ_DESC_F_NEXT | if write_to_device { 0 } else { VIRTQ_DESC_F_WRITE },
                next: 2,
            });
            desc(2).write_volatile(VirtqDescRaw {
                addr: status_phys,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            });
        }

        // Publish the chain via the avail ring (spec §2.6.6): ring[idx
        // % QUEUE_SIZE] = head descriptor (0), THEN idx++ (this order
        // matters — the device must never observe an incremented idx
        // pointing at a not-yet-written ring slot).
        // SAFETY: `q_read_u16`/`q_write_u16`'s own contract — every
        // offset here is within the mapped region.
        unsafe {
            let ring_slot = layout::AVAIL_OFFSET + 4 + (self.next_idx as usize % QUEUE_SIZE as usize) * 2;
            q_write_u16(self.queue_base, ring_slot, 0); // head descriptor index
            self.next_idx = self.next_idx.wrapping_add(1);
            q_write_u16(self.queue_base, layout::AVAIL_OFFSET + 2, self.next_idx); // avail.idx
        }

        // SAFETY: `reg_write`'s own contract (forwarded).
        unsafe { self.reg_write(mmio::QUEUE_NOTIFY, REQUEST_QUEUE) };
    }

    /// Acknowledges the interrupt at the device and returns the status
    /// byte it wrote — the tail end of completion handling, common to
    /// BOTH completion strategies this driver supports (see this
    /// module's own doc comment): the caller must already know a
    /// completion is ready (the used ring's `idx` reached `self.
    /// next_idx`) before calling this — it does not itself wait or
    /// poll for anything.
    ///
    /// `pub`: `subsystem_entry.rs` calls this after its own real
    /// `Wait` ecall reports completion — see `submit_request`'s own
    /// doc comment for why that split is necessary.
    ///
    /// # Safety
    /// Same contract as `submit_request`.
    pub unsafe fn ack_completion(&mut self) -> u8 {
        // SAFETY: `reg_read`/`reg_write` share `reg_read`'s own
        // contract (forwarded).
        unsafe {
            let cause = self.reg_read(mmio::INTERRUPT_STATUS);
            self.reg_write(mmio::INTERRUPT_ACK, cause);
        }
        // SAFETY: `layout::STATUS_OFFSET` is within the mapped region.
        unsafe { ((self.queue_base + layout::STATUS_OFFSET) as *const u8).read_volatile() }
    }

    /// Busy-polls the used ring until it has a new entry, then calls
    /// `ack_completion`. This driver's ORIGINAL completion strategy —
    /// still used by `handle_request`'s own `ReadBlocks`/`WriteBlocks`
    /// arms (host-testable, no ecall access needed) — kept alongside
    /// the real interrupt-driven path `subsystem_entry.rs` now uses in
    /// production (`submit_request` + a real `Wait` ecall +
    /// `ack_completion`, orchestrated there since only that crate can
    /// issue ecalls) as a documented, still-correct alternative: e.g.
    /// a future platform without a usable IRQ line, or the reference
    /// behavior these host tests exercise.
    ///
    /// # Safety
    /// Same contract as `submit_request`.
    unsafe fn wait_for_completion(&mut self) -> u8 {
        // Bounded, not an infinite spin: a real device that never
        // completes a request (misconfigured queue, wrong physical
        // address) must not wedge the whole driver process forever —
        // `STATUS_TIMEOUT` (0xFE, distinct from the 0xFF "not written
        // yet" sentinel `submit_request` seeds and every real virtio-blk
        // status code 0/1/2) tells the caller this happened.
        const MAX_SPINS: u32 = 20_000_000;
        let mut completed = false;
        for _ in 0..MAX_SPINS {
            // SAFETY: `q_read_u16`'s own contract.
            let used_idx = unsafe { q_read_u16(self.queue_base, layout::USED_OFFSET + 2) };
            if used_idx == self.next_idx {
                completed = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !completed {
            // SAFETY: `reg_read`/`reg_write` share `reg_read`'s own
            // contract (forwarded) — still ack whatever's pending so a
            // later request is not stuck behind a stale cause.
            unsafe {
                let cause = self.reg_read(mmio::INTERRUPT_STATUS);
                self.reg_write(mmio::INTERRUPT_ACK, cause);
            }
            return STATUS_TIMEOUT;
        }
        // SAFETY: forwarded from this function's own contract.
        unsafe { self.ack_completion() }
    }

    /// Whether `probe` has completed successfully — `subsystem_entry.
    /// rs`'s own real I/O path checks this itself (mirroring
    /// `handle_request`'s own `self.ready` check) before ever calling
    /// `submit_request`.
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    /// Validates a `ReadBlocks`/`WriteBlocks` request's `sector_count`/
    /// `lba` — the SAME bounds-checking `handle_request`'s own arms
    /// apply, extracted so `subsystem_entry.rs`'s real I/O path can
    /// reuse it without duplicating the logic (and so `handle_request`'s
    /// own arms stay exactly as host-tested).
    pub fn validate_io(&self, sector_count: u32, lba: u64) -> Result<(), DriverErrorCode> {
        if sector_count != 1 {
            // MVP scope: exactly one sector per request (see `layout`'s
            // own doc comment on the fixed one-sector data buffer).
            return Err(DriverErrorCode::Unsupported);
        }
        if self.capacity_sectors != 0 && lba + 1 > self.capacity_sectors {
            return Err(DriverErrorCode::OutOfRange);
        }
        Ok(())
    }
}

/// `#[repr(C)]` mirror of the virtio spec §2.6.5 `struct virtq_desc` — a
/// private wire-layout type distinct from `driver_framework`'s public
/// API, never exposed outside this module.
#[repr(C)]
struct VirtqDescRaw {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

impl DeviceDriver for VirtioBlk {
    fn probe(&mut self) -> Result<DeviceInfo, DriverError> {
        if self.mmio_base == 0 || self.queue_base == 0 {
            return Err(DriverError::ProbeFailed);
        }
        self.do_probe()?;
        self.ready = true;
        Ok(DeviceInfo {
            sector_size: Self::SECTOR_SIZE,
            sector_count: self.capacity_sectors,
        })
    }

    fn handle_irq(&mut self, _line: u32) {
        // Real completion handling happens synchronously inside
        // `wait_for_completion` (this MVP has exactly one thread of
        // control and one in-flight request, so there is no separate
        // async-notify path to drive here) — kept as a no-op to satisfy
        // the trait; `DriverRequest::Irq` below still routes through it
        // for interface completeness.
    }

    fn handle_request(&mut self, req: DriverRequest) -> DriverResponse {
        if !self.ready {
            return DriverResponse::Failed {
                code: DriverErrorCode::ProbeFailed,
            };
        }
        match req {
            DriverRequest::Probe => DriverResponse::Ready {
                sector_size: Self::SECTOR_SIZE,
                sector_count: self.capacity_sectors,
            },
            DriverRequest::ReadBlocks {
                lba, sector_count, ..
            } => {
                if let Err(code) = self.validate_io(sector_count, lba) {
                    return DriverResponse::Failed { code };
                }
                // SAFETY: `self.ready` (checked above) means `probe`
                // already mapped both regions.
                unsafe { self.submit_request(BlkReqType::In, lba, Self::SECTOR_SIZE as usize) };
                // SAFETY: same contract; the busy-poll closure is a
                // pure spin with no unsafe access of its own.
                let status = unsafe { self.wait_for_completion() };
                if status == 0 {
                    DriverResponse::Completed { sectors: 1 }
                } else {
                    DriverResponse::Failed { code: DriverErrorCode::DeviceIo }
                }
            }
            DriverRequest::WriteBlocks {
                lba, sector_count, ..
            } => {
                if let Err(code) = self.validate_io(sector_count, lba) {
                    return DriverResponse::Failed { code };
                }
                // SAFETY: same contract as the `ReadBlocks` arm above.
                unsafe { self.submit_request(BlkReqType::Out, lba, Self::SECTOR_SIZE as usize) };
                // SAFETY: same contract.
                let status = unsafe { self.wait_for_completion() };
                if status == 0 {
                    DriverResponse::Completed { sectors: 1 }
                } else {
                    DriverResponse::Failed { code: DriverErrorCode::DeviceIo }
                }
            }
            DriverRequest::Irq { line } => {
                self.handle_irq(line);
                DriverResponse::Completed { sectors: 0 }
            }
            DriverRequest::Quiesce => DriverResponse::Ready {
                sector_size: Self::SECTOR_SIZE,
                sector_count: self.capacity_sectors,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_io_checks_sector_count_then_bounds() {
        let mut d = VirtioBlk::new(0x1000_0000, 0x2000_0000);
        d.capacity_sectors = 100;
        assert_eq!(d.validate_io(1, 0), Ok(()));
        assert_eq!(d.validate_io(1, 99), Ok(()));
        assert_eq!(d.validate_io(2, 0), Err(DriverErrorCode::Unsupported));
        assert_eq!(d.validate_io(1, 100), Err(DriverErrorCode::OutOfRange));
    }

    #[test]
    fn probe_without_mmio_fails() {
        // Both regions absent (0/0): `probe`'s own early-return check
        // catches this BEFORE `do_probe` ever touches real memory — the
        // only `probe` path this host test suite can safely exercise,
        // since `do_probe` itself does genuine volatile MMIO/virtqueue
        // reads/writes that need real, QEMU-mapped hardware (verified
        // via the QEMU boot log, not a host unit test — same split every
        // other real-hardware-touching path in this workspace already
        // draws, e.g. `hal-<arch>`'s own `target_os = "none"`-gated
        // boot assembly).
        let mut d = VirtioBlk::new(0, 0);
        assert_eq!(d.probe(), Err(DriverError::ProbeFailed));
    }

    #[test]
    fn requests_before_ready_are_rejected() {
        // `ready` stays false without a real `probe` call — `handle_
        // request`'s own `self.ready` check must reject before ever
        // reaching `submit_request`'s real memory access, so this is
        // safe to construct with non-zero-but-fake addresses.
        let mut d = VirtioBlk::new(0x1000_0000, 0x2000_0000);
        let r = d.handle_request(DriverRequest::ReadBlocks {
            lba: 0,
            sector_count: 1,
            shared_cap: 1,
        });
        assert!(matches!(
            r,
            DriverResponse::Failed {
                code: DriverErrorCode::ProbeFailed
            }
        ));
    }

    #[test]
    fn out_of_range_read_is_rejected_without_touching_hardware() {
        // Sets `ready`/`capacity_sectors` directly (same-module private-
        // field access) INSTEAD of calling `probe()` — `probe` now does
        // genuine volatile hardware access (see `probe_without_mmio_
        // fails`'s own doc comment), which a host unit test cannot do
        // safely against a fake address. This test exercises exactly
        // the bounds-check logic in `handle_request`, independent of
        // `do_probe`'s own real-hardware handshake.
        let mut d = VirtioBlk::new(0x1000_0000, 0x2000_0000);
        d.ready = true;
        d.capacity_sectors = 100;
        let r = d.handle_request(DriverRequest::ReadBlocks {
            lba: 100,
            sector_count: 1,
            shared_cap: 1,
        });
        assert!(matches!(
            r,
            DriverResponse::Failed {
                code: DriverErrorCode::OutOfRange
            }
        ));
    }

    #[test]
    fn multi_sector_request_is_unsupported_in_this_mvp() {
        // `sector_count != 1` is rejected before any bounds/hardware
        // check — see `layout`'s own doc comment on the fixed one-
        // sector data buffer.
        let mut d = VirtioBlk::new(0x1000_0000, 0x2000_0000);
        d.ready = true;
        d.capacity_sectors = 100;
        let r = d.handle_request(DriverRequest::WriteBlocks {
            lba: 0,
            sector_count: 2,
            shared_cap: 1,
        });
        assert!(matches!(
            r,
            DriverResponse::Failed {
                code: DriverErrorCode::Unsupported
            }
        ));
    }
}
