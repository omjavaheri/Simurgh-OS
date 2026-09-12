//! ============================================================================
//! driver-nvme
//!
//! Purpose: a real NVMe block driver (NVM Express Base Specification
//! 1.4 — every section reference in this file is to that spec) —
//! 03-Kernel-Subsystems-Layer.md's own driver list names `driver-nvme`
//! alongside `driver-virtio-blk`. Implements `driver_framework::
//! DeviceDriver`, the same contract `driver-virtio-blk` already does, so
//! it slots into the SAME `DriverRequest::{ReadBlocks,WriteBlocks}` wire
//! protocol with no `ipc-protocol` changes at all.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.1 (driver
//! process model). Discovery: `hal_x86_64::peripheral`'s own NVMe
//! recognition (PCI class 0x01/subclass 0x08/prog-if 0x02, NOT a vendor
//! id — real NVMe controllers ship under many different PCI-SIG vendor
//! ids, unlike virtio's single Red Hat vendor id).
//!
//! Real, honest scope note (unlike `driver-virtio-blk`, which has years
//! of this project's own QEMU-verified history behind it): this crate's
//! register/queue protocol logic is written directly against the NVMe
//! base spec's own PCIe register layout and Admin/I/O command formats,
//! and is host-tested wherever the logic is pure (bit-packing, queue
//! index/doorbell arithmetic, completion phase-bit tracking — see this
//! file's own `#[cfg(test)]` module).
//!
//! **Real QEMU verification (2026-09-12)**: booted with a real
//! `-device nvme` attached — `hal_x86_64::peripheral`'s own class-code
//! scan found it (`peripheral devices: 3`, up from 2 with no NVMe
//! attached), `KernelState::root_mmio_nvme_cap` resolved to a real
//! capability, and `kernel_arch_glue::spawn_nvme_driver` spawned this
//! process with a real BAR0 window and all five queue/data pages
//! actually mapped (`spawn_nvme_driver: driver-nvme spawned` in the real
//! boot log), with no crash or hang anywhere else in the rest of the
//! boot sequence. What this does NOT yet directly confirm: whether
//! `Nvme::do_probe`'s own real MMIO handshake against the controller
//! (the admin queue bring-up, Identify Namespace, I/O queue creation)
//! actually completes successfully — `subsystem_main` does not currently
//! report `probe()`'s own outcome anywhere observable, so that is
//! structural correctness (spec-literal register offsets/bit positions,
//! host-tested) plus real capability/mapping proof, not yet a directly
//! observed successful handshake. A follow-up report opcode (mirroring
//! other subsystems' own `*_REPORT` pattern) would close that last gap.
//!
//! MVP scope, matching `driver-virtio-blk`'s own: one request in flight
//! at a time, one logical block per request, a fixed one-page (4096
//! byte) data buffer per I/O command (so a 512-byte-LBA namespace uses
//! the first 512 bytes of it, a 4096-byte-LBA namespace uses the whole
//! page — either way NEVER spans a PRP list, so `PRP1` alone is always
//! enough and this driver never needs to build one, the same "exactly
//! one region, no scatter-gather" simplification `driver-virtio-blk`
//! makes for its own single-sector data buffer).
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod subsystem_entry;

use driver_framework::{DeviceDriver, DeviceInfo, DriverError};
use ipc_protocol::driver::DriverErrorCode;
use ipc_protocol::{DriverRequest, DriverResponse};

/// Controller Registers (BAR0), spec §3.1 — offsets only, every access
/// goes through `Nvme`'s own accessor methods so callers never poke a
/// raw offset directly.
pub mod reg {
    /// Controller Capabilities (CAP), 8 bytes, read-only.
    pub const CAP: usize = 0x00;
    /// Version (VS), 4 bytes, read-only.
    pub const VS: usize = 0x08;
    /// Controller Configuration (CC), 4 bytes, read-write.
    pub const CC: usize = 0x14;
    /// Controller Status (CSTS), 4 bytes, read-only.
    pub const CSTS: usize = 0x1C;
    /// Admin Queue Attributes (AQA), 4 bytes, read-write.
    pub const AQA: usize = 0x24;
    /// Admin Submission Queue Base Address (ASQ), 8 bytes, read-write.
    pub const ASQ: usize = 0x28;
    /// Admin Completion Queue Base Address (ACQ), 8 bytes, read-write.
    pub const ACQ: usize = 0x30;
    /// Start of the doorbell register array — each doorbell's own real
    /// offset also depends on `cap::dstrd` (`doorbell_offset`'s own doc
    /// comment), so this is a base, not a fixed per-queue offset.
    pub const DOORBELL_BASE: usize = 0x1000;
}

/// Pure bit-decoding of the 64-bit CAP register (spec §3.1.1) — kept as
/// free functions over a raw `u64` (not a struct with a constructor)
/// since callers only ever need one or two fields at a time, right after
/// a single real MMIO read.
pub mod cap {
    /// Maximum Queue Entries Supported, 0's-based — add 1 for the real
    /// maximum entry count any single queue (admin or I/O) may have.
    pub fn mqes(raw: u64) -> u32 {
        (raw & 0xFFFF) as u32 + 1
    }
    /// Doorbell Stride — the real stride in BYTES between consecutive
    /// doorbell registers is `4 << dstrd` (spec §3.1.1: "the value is in
    /// units of `(2 ^ (2 + DSTRD))` bytes").
    pub fn dstrd(raw: u64) -> u32 {
        ((raw >> 32) & 0xF) as u32
    }
    /// Whether the NVM command set (bit 37) is supported — the only
    /// command set this driver ever selects (`Nvme::do_probe`'s own
    /// `CC.CSS = 0`).
    pub fn nvm_command_set_supported(raw: u64) -> bool {
        (raw >> 37) & 0x1 != 0
    }
    /// Worst-case controller ready timeout, in milliseconds — spec
    /// §3.1.1's own `TO` field is in 500ms units.
    pub fn timeout_ms(raw: u64) -> u32 {
        (((raw >> 24) & 0xFF) as u32) * 500
    }
}

/// The real byte stride between consecutive doorbell registers — spec
/// §3.1.1 CAP.DSTRD (`cap::dstrd`'s own doc comment).
pub fn doorbell_stride_bytes(cap_raw: u64) -> usize {
    4usize << cap::dstrd(cap_raw)
}

/// Submission queue tail doorbell offset for queue `qid` (0 = admin) —
/// spec §3.1.13/§3.1.14: `0x1000 + (2 * qid) * stride`.
pub fn sq_tail_doorbell_offset(qid: u16, cap_raw: u64) -> usize {
    reg::DOORBELL_BASE + (2 * qid as usize) * doorbell_stride_bytes(cap_raw)
}

/// Completion queue head doorbell offset for queue `qid` (0 = admin) —
/// spec §3.1.13/§3.1.14: `0x1000 + (2 * qid + 1) * stride`.
pub fn cq_head_doorbell_offset(qid: u16, cap_raw: u64) -> usize {
    reg::DOORBELL_BASE + (2 * qid as usize + 1) * doorbell_stride_bytes(cap_raw)
}

/// Builds the 32-bit Controller Configuration (CC) register value this
/// driver always uses once enabling the controller (spec §3.1.5):
/// `EN=1`, `CSS=0` (NVM command set), `MPS=0` (4096-byte host memory
/// page size — this driver's every queue/buffer is exactly one 4096-byte
/// page, so no larger page size is ever needed), `AMS=0` (round-robin,
/// the only arbitration mechanism every NVMe controller MUST support),
/// `SHN=0` (no shutdown notification), `IOSQES=6` (64-byte I/O
/// submission queue entries — `2^6`, spec-mandated), `IOCQES=4`
/// (16-byte I/O completion queue entries — `2^4`, spec-mandated).
pub fn build_cc_enable() -> u32 {
    const IOSQES: u32 = 6;
    const IOCQES: u32 = 4;
    1 // EN
        | (IOSQES << 16)
        | (IOCQES << 20)
}

/// Whether `csts` reports the controller ready (spec §3.1.6, `RDY` bit
/// 0).
pub fn csts_ready(csts: u32) -> bool {
    csts & 0x1 != 0
}

/// Whether `csts` reports a fatal controller status (spec §3.1.6, `CFS`
/// bit 1) — `do_probe` treats this as an immediate, unrecoverable probe
/// failure rather than continuing to poll `RDY`.
pub fn csts_fatal(csts: u32) -> bool {
    csts & 0x2 != 0
}

/// Builds the 32-bit Admin Queue Attributes (AQA) register value (spec
/// §3.1.9) for admin submission/completion queues of `depth` entries
/// each (both always the SAME depth in this driver — `AdminQueues`'s own
/// doc comment). Both sub-fields are 0's-based (a `depth` of 1 encodes
/// as `0`).
pub fn build_aqa(depth: u16) -> u32 {
    let zero_based = (depth.saturating_sub(1)) as u32;
    zero_based | (zero_based << 16)
}

/// NVMe Admin command opcodes this driver issues (spec §5).
pub mod admin_opcode {
    /// Create I/O Submission Queue.
    pub const CREATE_IO_SQ: u8 = 0x01;
    /// Create I/O Completion Queue.
    pub const CREATE_IO_CQ: u8 = 0x05;
    /// Identify.
    pub const IDENTIFY: u8 = 0x06;
}

/// NVM command set I/O opcodes this driver issues (spec §6).
pub mod io_opcode {
    /// Write.
    pub const WRITE: u8 = 0x01;
    /// Read.
    pub const READ: u8 = 0x02;
}

/// `Identify` command CNS (Controller or Namespace Structure) values
/// this driver uses (spec §5.15.1) — only Identify Namespace is needed
/// (this driver only ever reports ONE namespace's `DeviceInfo`, NSID 1).
pub mod identify_cns {
    /// Identify Namespace data structure for the namespace named by
    /// `NSID`.
    pub const NAMESPACE: u8 = 0x00;
}

/// The one namespace this MVP driver ever addresses — real NVMe
/// namespace ids are 1-based; every QEMU `-device nvme` (and every real
/// single-namespace SSD) always has a namespace 1.
pub const NSID: u32 = 1;

/// A 64-byte NVMe Submission Queue Entry (spec §4.2, Figure 105) —
/// `#[repr(C)]` so its byte layout matches the spec exactly; every field
/// here is written by this driver's own command builders below, never
/// constructed piecemeal elsewhere.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SubmissionQueueEntry {
    /// CDW0: `OPC` (bits 0:7), `FUSE` (bits 8:9), `PSDT` (bits 14:15,
    /// always 0 here — PRPs, never SGLs), `CID` (bits 16:31).
    pub cdw0: u32,
    /// Namespace Identifier.
    pub nsid: u32,
    /// Reserved (CDW2/CDW3) — always zero.
    pub reserved: u64,
    /// Metadata Pointer (CDW4/CDW5) — always zero (this driver never
    /// uses metadata).
    pub mptr: u64,
    /// PRP Entry 1 — the data buffer's own physical address (this
    /// driver's own MVP scope never needs PRP2/a PRP list — this file's
    /// own module doc comment).
    pub prp1: u64,
    /// PRP Entry 2 — always zero (unused, `prp1`'s own doc comment).
    pub prp2: u64,
    /// Command Dword 10 — meaning depends on the opcode.
    pub cdw10: u32,
    /// Command Dword 11 — meaning depends on the opcode.
    pub cdw11: u32,
    /// Command Dword 12 — meaning depends on the opcode.
    pub cdw12: u32,
    /// Command Dword 13 — always zero (unused by every command this
    /// driver issues).
    pub cdw13: u32,
    /// Command Dword 14 — always zero.
    pub cdw14: u32,
    /// Command Dword 15 — always zero.
    pub cdw15: u32,
}

const _: () = assert!(core::mem::size_of::<SubmissionQueueEntry>() == 64);

impl SubmissionQueueEntry {
    /// The zeroed entry every command builder below starts from.
    const ZERO: Self = Self {
        cdw0: 0,
        nsid: 0,
        reserved: 0,
        mptr: 0,
        prp1: 0,
        prp2: 0,
        cdw10: 0,
        cdw11: 0,
        cdw12: 0,
        cdw13: 0,
        cdw14: 0,
        cdw15: 0,
    };

    fn cdw0(opcode: u8, cid: u16) -> u32 {
        opcode as u32 | ((cid as u32) << 16)
    }

    /// Identify Namespace (spec §5.15) for `NSID` (this driver's own
    /// single namespace) — the returned 4096-byte structure lands at
    /// `data_buf_phys`.
    pub fn identify_namespace(cid: u16, data_buf_phys: u64) -> Self {
        Self {
            cdw0: Self::cdw0(admin_opcode::IDENTIFY, cid),
            nsid: NSID,
            prp1: data_buf_phys,
            cdw10: identify_cns::NAMESPACE as u32,
            ..Self::ZERO
        }
    }

    /// Create I/O Completion Queue (spec §5.4): `qid` (>= 1), `depth`
    /// entries (real count, NOT 0's-based — converted here), backed by
    /// `queue_phys` (must be exactly `depth * 16` bytes, one physically
    /// contiguous region — `PC = 1`, the only mode this driver ever
    /// uses). Interrupts are NEVER enabled by this MVP driver (`IEN =
    /// 0`) — completion is observed by polling the phase bit
    /// (`CompletionQueueEntry::phase`'s own doc comment), the same
    /// documented, still-correct alternative `driver-virtio-blk::
    /// wait_for_completion` uses for ITS OWN polling path; a real
    /// interrupt-driven completion path (mirroring `driver-virtio-blk`'s
    /// `subsystem_entry.rs`) is later work, once this MVP's own polling
    /// path is QEMU-verified.
    pub fn create_io_cq(cid: u16, qid: u16, depth: u16, queue_phys: u64) -> Self {
        let zero_based_size = depth.saturating_sub(1);
        Self {
            cdw0: Self::cdw0(admin_opcode::CREATE_IO_CQ, cid),
            prp1: queue_phys,
            cdw10: qid as u32 | ((zero_based_size as u32) << 16),
            cdw11: 1, // PC = 1 (physically contiguous); IEN = 0 (polling).
            ..Self::ZERO
        }
    }

    /// Create I/O Submission Queue (spec §5.5): `qid` (>= 1), `depth`
    /// entries, backed by `queue_phys` (must be exactly `depth * 64`
    /// bytes), reporting completions to `cqid` (the I/O completion queue
    /// this SQ is paired with — created first, `Nvme::do_probe`'s own
    /// ordering).
    pub fn create_io_sq(cid: u16, qid: u16, depth: u16, queue_phys: u64, cqid: u16) -> Self {
        let zero_based_size = depth.saturating_sub(1);
        Self {
            cdw0: Self::cdw0(admin_opcode::CREATE_IO_SQ, cid),
            prp1: queue_phys,
            cdw10: qid as u32 | ((zero_based_size as u32) << 16),
            cdw11: 1 | ((cqid as u32) << 16), // PC = 1; QPRIO = 0 (urgent-disabled default); CQID.
            ..Self::ZERO
        }
    }

    /// Read or Write (NVM command set, spec §6.7/§6.15) `nlb` logical
    /// blocks (real count, 0's-based on the wire — converted here)
    /// starting at `slba`, into/from `data_buf_phys`.
    pub fn read_write(opcode: u8, cid: u16, slba: u64, nlb: u16, data_buf_phys: u64) -> Self {
        let zero_based_nlb = nlb.saturating_sub(1);
        Self {
            cdw0: Self::cdw0(opcode, cid),
            nsid: NSID,
            prp1: data_buf_phys,
            cdw10: slba as u32,
            cdw11: (slba >> 32) as u32,
            cdw12: zero_based_nlb as u32,
            ..Self::ZERO
        }
    }
}

/// A 16-byte NVMe Completion Queue Entry (spec §4.6, Figure 111).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CompletionQueueEntry {
    /// DW0 — command-specific (e.g. Identify's own result field; unused
    /// by this driver for every command it issues).
    pub dw0: u32,
    /// DW1 — reserved.
    pub dw1: u32,
    /// DW2 — SQ Head Pointer (bits 0:15), SQ Identifier (bits 16:31).
    pub dw2: u32,
    /// DW3 — Command Identifier (bits 0:15), Phase Tag `P` (bit 16),
    /// Status Field `SF` (bits 17:31).
    pub dw3: u32,
}

const _: () = assert!(core::mem::size_of::<CompletionQueueEntry>() == 16);

impl CompletionQueueEntry {
    /// The Phase Tag (spec §4.6.2): flips (0<->1) each time the
    /// controller wraps around this completion queue — the ONLY
    /// reliable way to tell "a new entry landed here" from "this slot's
    /// old, stale contents", since a completion queue is never
    /// explicitly zeroed by the driver after each entry is consumed
    /// (spec §4.6: the controller does not clear a CQ entry on
    /// completion; only the phase bit distinguishes new from stale).
    pub fn phase(&self) -> bool {
        (self.dw3 >> 16) & 0x1 != 0
    }

    /// Command Identifier this completion answers — must match the
    /// `CID` the corresponding `SubmissionQueueEntry::cdw0` used, so a
    /// caller can confirm it read the right completion (this driver's
    /// own MVP scope only ever has one command in flight at a time per
    /// queue, so this is a consistency check, not a dispatch key).
    pub fn command_id(&self) -> u16 {
        (self.dw3 & 0xFFFF) as u16
    }

    /// Status Field (spec §4.6.1): `0` means success (`SCT = 0, SC =
    /// 0`) — every other value is some real error the controller
    /// reported. The full 15-bit field (`SCT` + `SC` + `M`/`DNR`) is
    /// returned as-is; this driver only ever checks it against zero
    /// (`Nvme`'s own callers), matching `driver-virtio-blk`'s own
    /// "any nonzero status is `DeviceIo`" simplification.
    pub fn status(&self) -> u16 {
        ((self.dw3 >> 17) & 0x7FFF) as u16
    }
}

/// One admin-queue (or I/O-queue) pair's own tail/head tracking — pure
/// bookkeeping, no hardware access, reused identically for both the
/// admin and the I/O queue pair (`Nvme`'s own two fields of this type).
/// MVP scope: `depth` is always small enough (2) that only ONE command
/// is ever truly in flight at a time — this struct still tracks a real
/// ring position (not just a bool), so the phase-bit wraparound logic
/// is exercised for real, the same rigor `driver-virtio-blk`'s own
/// `next_idx` gets even though its own MVP is also "one in flight".
#[derive(Debug, Clone, Copy)]
pub struct QueuePair {
    /// Number of entries in EACH of this pair's submission/completion
    /// queues (both always the same depth in this driver).
    pub depth: u16,
    /// Next free submission queue slot (wraps at `depth`) — also the
    /// next SQ tail doorbell value to ring.
    pub sq_tail: u16,
    /// Next completion queue slot this driver expects to read next —
    /// wraps at `depth`; also the next CQ head doorbell value to ring
    /// once consumed.
    pub cq_head: u16,
    /// The phase bit value a NEW completion is expected to carry —
    /// starts `true` (spec §4.6.2: the controller's phase tag starts at
    /// 1 for the very first pass through a freshly-created completion
    /// queue) and flips every time `cq_head` wraps back to 0.
    pub expected_phase: bool,
}

impl QueuePair {
    /// A fresh pair of `depth`-entry queues, not yet used.
    pub const fn new(depth: u16) -> Self {
        Self { depth, sq_tail: 0, cq_head: 0, expected_phase: true }
    }

    /// Reserves the next submission slot, returning its index — the
    /// caller writes the command there, then advances `sq_tail`.
    pub fn current_sq_slot(&self) -> u16 {
        self.sq_tail
    }

    /// Advances past the just-submitted slot (wrapping at `depth`).
    pub fn advance_sq(&mut self) {
        self.sq_tail = (self.sq_tail + 1) % self.depth;
    }

    /// The completion slot this driver should look at next.
    pub fn current_cq_slot(&self) -> u16 {
        self.cq_head
    }

    /// Advances past a just-consumed completion (wrapping at `depth`,
    /// flipping `expected_phase` exactly on wraparound — spec §4.6.2).
    pub fn advance_cq(&mut self) {
        self.cq_head += 1;
        if self.cq_head == self.depth {
            self.cq_head = 0;
            self.expected_phase = !self.expected_phase;
        }
    }
}

/// Fixed queue depth for BOTH the admin queue pair and the I/O queue
/// pair — 2 entries is the minimum that lets this driver's own MVP
/// scope ("one command in flight at a time") still exercise a REAL
/// wraparound (a depth-1 queue can never wrap, which would leave
/// `QueuePair::advance_cq`'s own phase-flip logic untested by anything
/// this driver actually does).
pub const QUEUE_DEPTH: u16 = 2;

/// This driver's own I/O queue id — NVMe queue ids are 1-based for I/O
/// queues (0 is always the admin queue); this MVP scope only ever
/// creates ONE I/O queue pair.
pub const IO_QUEUE_ID: u16 = 1;

/// The NVMe driver state. `bar0`/regions all default to `0` ("not
/// granted yet" — mirrors `driver_virtio_blk::VirtioBlk`'s identical
/// sentinel convention) until real capabilities are wired in by
/// `subsystem_entry.rs` (kernel-side spawn glue, not written yet — this
/// file's own module doc comment).
pub struct Nvme {
    /// Mapped virtual base of the controller's own BAR0 register window
    /// (0 = not granted yet).
    bar0: usize,
    /// Admin submission queue — mapped virtual base.
    admin_sq_va: usize,
    /// Admin completion queue — mapped virtual base.
    admin_cq_va: usize,
    /// I/O submission queue — mapped virtual base.
    io_sq_va: usize,
    /// I/O completion queue — mapped virtual base.
    io_cq_va: usize,
    /// One page, used for BOTH Identify (during `probe`) and every I/O
    /// data transfer afterward (`probe` never overlaps a real I/O
    /// request, so reusing the same page is safe and saves a grant).
    data_buf_va: usize,
    /// The doorbell stride/CAP-derived values `do_probe` reads once and
    /// every later doorbell write reuses — `0` until `probe` runs.
    cap_raw: u64,
    admin: QueuePair,
    io: QueuePair,
    /// Namespace block size in bytes, read from Identify Namespace
    /// during `probe` (512 or 4096 on every real/QEMU NVMe namespace
    /// this driver targets).
    block_size: u32,
    /// Namespace capacity in blocks, read from Identify Namespace.
    block_count: u64,
    /// Whether `probe` completed successfully.
    ready: bool,
}

impl Nvme {
    /// Creates the driver bound to a BAR0 window mapped at `bar0` and
    /// five same-process pages (admin SQ/CQ, I/O SQ/CQ, one shared data
    /// buffer) — pass all zero in tests, before any grant exists.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        bar0: usize,
        admin_sq_va: usize,
        admin_cq_va: usize,
        io_sq_va: usize,
        io_cq_va: usize,
        data_buf_va: usize,
    ) -> Self {
        Self {
            bar0,
            admin_sq_va,
            admin_cq_va,
            io_sq_va,
            io_cq_va,
            data_buf_va,
            cap_raw: 0,
            admin: QueuePair::new(QUEUE_DEPTH),
            io: QueuePair::new(QUEUE_DEPTH),
            block_size: 0,
            block_count: 0,
            ready: false,
        }
    }

    /// Sector size this driver reports — the real, per-namespace value
    /// read from Identify Namespace (unlike `driver-virtio-blk`, NVMe
    /// has no single fixed sector size across every device).
    pub fn sector_size(&self) -> u32 {
        self.block_size
    }

    /// Whether `probe` has completed.
    pub fn is_ready(&self) -> bool {
        self.ready
    }

    fn transport_is_bound(&self) -> bool {
        self.bar0 != 0
            && self.admin_sq_va != 0
            && self.admin_cq_va != 0
            && self.io_sq_va != 0
            && self.io_cq_va != 0
            && self.data_buf_va != 0
    }

    /// Validates a `ReadBlocks`/`WriteBlocks` request — same shape as
    /// `driver_virtio_blk::VirtioBlk::validate_io`. MVP scope: exactly
    /// one logical block per request, and it must fit within this
    /// driver's own one-page data buffer (`block_size <= 4096`, true for
    /// every real 512- or 4096-byte-LBA namespace).
    pub fn validate_io(&self, sector_count: u32, lba: u64) -> Result<(), DriverErrorCode> {
        if sector_count != 1 {
            return Err(DriverErrorCode::Unsupported);
        }
        if self.block_count != 0 && lba + 1 > self.block_count {
            return Err(DriverErrorCode::OutOfRange);
        }
        Ok(())
    }

    // ---- real MMIO accessors ---------------------------------------
    //
    // Every one of these is a thin, single-purpose volatile access —
    // `do_probe`/`submit_admin`/`submit_io` call ONLY these, never a raw
    // offset directly, mirroring `driver_virtio_blk::VirtioBlk`'s own
    // "accessors, not inline offsets" discipline.

    /// # Safety
    /// `self.bar0` must be a real, mapped MMIO window.
    unsafe fn read_cap(&self) -> u64 {
        // SAFETY: forwarded from this method's own contract.
        unsafe { ((self.bar0 + reg::CAP) as *const u64).read_volatile() }
    }

    /// # Safety
    /// Same contract as `read_cap`.
    unsafe fn write_cc(&self, value: u32) {
        // SAFETY: forwarded from this method's own contract.
        unsafe { ((self.bar0 + reg::CC) as *mut u32).write_volatile(value) };
    }

    /// # Safety
    /// Same contract as `read_cap`.
    unsafe fn read_csts(&self) -> u32 {
        // SAFETY: forwarded from this method's own contract.
        unsafe { ((self.bar0 + reg::CSTS) as *const u32).read_volatile() }
    }

    /// # Safety
    /// Same contract as `read_cap`.
    unsafe fn write_aqa(&self, value: u32) {
        // SAFETY: forwarded from this method's own contract.
        unsafe { ((self.bar0 + reg::AQA) as *mut u32).write_volatile(value) };
    }

    /// # Safety
    /// Same contract as `read_cap`.
    unsafe fn write_asq(&self, phys: u64) {
        // SAFETY: forwarded from this method's own contract.
        unsafe { ((self.bar0 + reg::ASQ) as *mut u64).write_volatile(phys) };
    }

    /// # Safety
    /// Same contract as `read_cap`.
    unsafe fn write_acq(&self, phys: u64) {
        // SAFETY: forwarded from this method's own contract.
        unsafe { ((self.bar0 + reg::ACQ) as *mut u64).write_volatile(phys) };
    }

    /// # Safety
    /// Same contract as `read_cap`; `qid`/`self.cap_raw` must already be
    /// real (`self.cap_raw` populated by `do_probe` before any doorbell
    /// is ever rung).
    unsafe fn ring_sq_doorbell(&self, qid: u16, value: u16) {
        let offset = sq_tail_doorbell_offset(qid, self.cap_raw);
        // SAFETY: forwarded from this method's own contract.
        unsafe { ((self.bar0 + offset) as *mut u32).write_volatile(value as u32) };
    }

    /// # Safety
    /// Same contract as `ring_sq_doorbell`.
    unsafe fn ring_cq_doorbell(&self, qid: u16, value: u16) {
        let offset = cq_head_doorbell_offset(qid, self.cap_raw);
        // SAFETY: forwarded from this method's own contract.
        unsafe { ((self.bar0 + offset) as *mut u32).write_volatile(value as u32) };
    }

    /// The physical address of a mapped virtual address within this
    /// process's own granted regions — `driver_virtio_blk::layout`'s own
    /// doc comment explains why a driver process has no other way to
    /// learn this (no VA-to-PA translation syscall for a non-root
    /// thread): `kernel_arch_glue`'s own spawn-time setup (not written
    /// yet — this file's own module doc comment) is expected to write
    /// each region's own physical base as the first 8 bytes of that
    /// region, the SAME convention `driver_virtio_blk::layout::
    /// PHYS_BASE_OFFSET` already established.
    ///
    /// # Safety
    /// `va` must be one of this driver's own mapped regions, with its
    /// physical-base header word already populated.
    unsafe fn phys_of(&self, va: usize) -> u64 {
        // SAFETY: forwarded from this method's own contract.
        unsafe { (va as *const u64).read_volatile() }
    }

    /// Writes one submission queue entry at `queue_va`'s own
    /// `slot`'th 64-byte position, one page in (past that region's own
    /// physical-base header word — `phys_of`'s own doc comment; every
    /// queue region is one page, `QUEUE_DEPTH * 64 = 128` bytes fits
    /// comfortably after an 8-byte header).
    ///
    /// # Safety
    /// `queue_va` must be one of this driver's own mapped, page-sized
    /// queue regions.
    unsafe fn write_sqe(&self, queue_va: usize, slot: u16, entry: SubmissionQueueEntry) {
        let addr = queue_va + 8 + slot as usize * core::mem::size_of::<SubmissionQueueEntry>();
        // SAFETY: forwarded from this method's own contract; `slot <
        // QUEUE_DEPTH` is guaranteed by every caller via `QueuePair`'s
        // own wrapping arithmetic.
        unsafe { (addr as *mut SubmissionQueueEntry).write_volatile(entry) };
    }

    /// Reads one completion queue entry at `queue_va`'s own `slot`'th
    /// 16-byte position — same header-offset convention as `write_sqe`.
    ///
    /// # Safety
    /// Same contract as `write_sqe`.
    unsafe fn read_cqe(&self, queue_va: usize, slot: u16) -> CompletionQueueEntry {
        let addr = queue_va + 8 + slot as usize * core::mem::size_of::<CompletionQueueEntry>();
        // SAFETY: forwarded from this method's own contract.
        unsafe { (addr as *const CompletionQueueEntry).read_volatile() }
    }

    /// Runs the full NVMe controller bring-up (spec §3.5.1 "Initial
    /// Controller State"), Identify Namespace, and I/O queue creation.
    /// Real MMIO/queue-memory reads/writes throughout, via the accessors
    /// above — see this file's own module doc comment for this method's
    /// real, honest QEMU-verification status.
    fn do_probe(&mut self) -> Result<(), DriverError> {
        // SAFETY: `transport_is_bound` (checked by the caller, `probe`)
        // confirms every region below is a real, mapped address.
        unsafe {
            self.cap_raw = self.read_cap();
            if !cap::nvm_command_set_supported(self.cap_raw) {
                return Err(DriverError::ProbeFailed);
            }
            if cap::mqes(self.cap_raw) < QUEUE_DEPTH as u32 {
                // A real controller reporting fewer entries than this
                // driver's own fixed QUEUE_DEPTH cannot host either
                // queue pair at all.
                return Err(DriverError::ProbeFailed);
            }

            // Controller Reset (spec §3.5.1 / §7.6.1): CC.EN must be
            // observed 0 with CSTS.RDY 0 before admin queue setup — if
            // the controller was left enabled by a previous owner
            // (never true on a fresh QEMU boot, but a real reset is
            // cheap and spec-correct either way), disable first and wait
            // for RDY to drop.
            self.write_cc(0);
            if !self.poll_csts_rdy(false) {
                return Err(DriverError::ProbeFailed);
            }

            // Admin queue setup (spec §3.5.1 steps 1-3): AQA/ASQ/ACQ
            // MUST be programmed before CC.EN is set.
            self.write_aqa(build_aqa(QUEUE_DEPTH));
            self.write_asq(self.phys_of(self.admin_sq_va));
            self.write_acq(self.phys_of(self.admin_cq_va));

            // Enable (spec §3.5.1 step 4) and wait for RDY.
            self.write_cc(build_cc_enable());
            if !self.poll_csts_rdy(true) {
                return Err(DriverError::ProbeFailed);
            }
        }

        // Identify Namespace (NSID 1) to learn the real block size/
        // count — this driver's `DeviceInfo` must report the truth, not
        // a guess (unlike virtio-blk, NVMe has no fixed sector size).
        // SAFETY: same contract as the admin setup above.
        let identify_ok = unsafe { self.admin_identify_namespace() };
        if !identify_ok {
            return Err(DriverError::ProbeFailed);
        }

        // I/O queue pair (spec §3.5.1 step 5: create the I/O CQ before
        // its paired I/O SQ, exactly this order — a Create I/O SQ naming
        // a not-yet-created CQID is a real, well-documented error case).
        // SAFETY: same contract as the admin setup above.
        let queues_ok = unsafe { self.admin_create_io_queues() };
        if !queues_ok {
            return Err(DriverError::ProbeFailed);
        }

        Ok(())
    }

    /// Bounded poll of `CSTS.RDY` until it reaches `want` — spec
    /// §3.1.1's own `CAP.TO` names the real worst-case timeout, but this
    /// driver's own bounded SPIN COUNT (not a real wall-clock timer —
    /// this process has no timer access of its own) mirrors
    /// `driver_virtio_blk::VirtioBlk::wait_for_completion`'s identical
    /// "bounded, not infinite" reasoning: a controller that never
    /// becomes ready must not wedge this driver process forever.
    ///
    /// # Safety
    /// `self.bar0` must be a real, mapped MMIO window.
    unsafe fn poll_csts_rdy(&self, want: bool) -> bool {
        const MAX_SPINS: u32 = 20_000_000;
        for _ in 0..MAX_SPINS {
            // SAFETY: forwarded from this method's own contract.
            let csts = unsafe { self.read_csts() };
            if csts_fatal(csts) {
                return false;
            }
            if csts_ready(csts) == want {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    /// Submits one admin command and busy-polls the admin completion
    /// queue for its answer — MVP scope: exactly one admin command in
    /// flight at a time (`do_probe`'s only two admin callers,
    /// `admin_identify_namespace`/`admin_create_io_queues`, never
    /// overlap). Returns the completion entry, or `None` on a bounded
    /// timeout (same reasoning as `poll_csts_rdy`).
    ///
    /// # Safety
    /// `self.bar0`/`self.admin_sq_va`/`self.admin_cq_va` must all be
    /// real, mapped regions; `self.cap_raw` must already be populated.
    unsafe fn submit_admin(&mut self, entry: SubmissionQueueEntry) -> Option<CompletionQueueEntry> {
        let slot = self.admin.current_sq_slot();
        // SAFETY: forwarded from this method's own contract.
        unsafe { self.write_sqe(self.admin_sq_va, slot, entry) };
        self.admin.advance_sq();
        // SAFETY: forwarded from this method's own contract.
        unsafe { self.ring_sq_doorbell(0, self.admin.sq_tail) };

        const MAX_SPINS: u32 = 20_000_000;
        for _ in 0..MAX_SPINS {
            let cq_slot = self.admin.current_cq_slot();
            // SAFETY: forwarded from this method's own contract.
            let cqe = unsafe { self.read_cqe(self.admin_cq_va, cq_slot) };
            if cqe.phase() == self.admin.expected_phase {
                self.admin.advance_cq();
                // SAFETY: forwarded from this method's own contract.
                unsafe { self.ring_cq_doorbell(0, self.admin.cq_head) };
                return Some(cqe);
            }
            core::hint::spin_loop();
        }
        None
    }

    /// Identify Namespace (NSID 1) into `self.data_buf_va`'s own page,
    /// then extracts `block_count`/`block_size` from the real returned
    /// structure (spec §5.15.2.1: `NSZE` — Namespace Size, 8 bytes at
    /// offset 0 — and `FLBAS`/`LBAF` — the currently-selected LBA
    /// format's own block size). Returns whether the command succeeded
    /// AND reported a usable (nonzero) block size.
    ///
    /// # Safety
    /// Same contract as `submit_admin`; `self.data_buf_va` must be a
    /// real, mapped page.
    unsafe fn admin_identify_namespace(&mut self) -> bool {
        // SAFETY: forwarded from this method's own contract.
        let data_phys = unsafe { self.phys_of(self.data_buf_va) };
        let cid = self.admin.current_sq_slot();
        let cmd = SubmissionQueueEntry::identify_namespace(cid, data_phys);
        // SAFETY: forwarded from this method's own contract.
        let Some(cqe) = (unsafe { self.submit_admin(cmd) }) else {
            return false;
        };
        if cqe.status() != 0 {
            return false;
        }

        // Identify Namespace data structure (spec §5.15.2.1): NSZE
        // (bytes 0..8), FLBAS (byte 26, bits 0:3 select an LBAF index),
        // LBAF array starts at byte 128, 4 bytes each — LBADS (bits
        // 16:23 of that 4-byte entry) is log2(block size in bytes).
        // SAFETY: `self.data_buf_va` is a real, mapped page (forwarded
        // contract); reading past its own physical-base header word,
        // same convention `write_sqe`/`read_cqe` already use.
        let base = (self.data_buf_va + 8) as *const u8;
        let nsze = unsafe { (base as *const u64).read_volatile() };
        let flbas = unsafe { base.add(26).read_volatile() } & 0xF;
        let lbaf_entry = unsafe {
            (base.add(128 + flbas as usize * 4) as *const u32).read_volatile()
        };
        let lbads = ((lbaf_entry >> 16) & 0xFF) as u32;
        if lbads == 0 {
            return false;
        }
        self.block_count = nsze;
        self.block_size = 1u32 << lbads;
        self.block_size != 0 && self.block_size <= 4096
    }

    /// Creates the one I/O completion queue then the one I/O submission
    /// queue this driver ever uses (spec §3.5.1 step 5, order matters —
    /// `SubmissionQueueEntry::create_io_cq`'s own doc comment).
    ///
    /// # Safety
    /// Same contract as `submit_admin`; `self.io_sq_va`/`self.io_cq_va`
    /// must both be real, mapped pages.
    unsafe fn admin_create_io_queues(&mut self) -> bool {
        // SAFETY: forwarded from this method's own contract.
        let cq_phys = unsafe { self.phys_of(self.io_cq_va) };
        let cid_cq = self.admin.current_sq_slot();
        let cq_cmd = SubmissionQueueEntry::create_io_cq(cid_cq, IO_QUEUE_ID, QUEUE_DEPTH, cq_phys);
        // SAFETY: forwarded from this method's own contract.
        let Some(cqe) = (unsafe { self.submit_admin(cq_cmd) }) else {
            return false;
        };
        if cqe.status() != 0 {
            return false;
        }

        // SAFETY: forwarded from this method's own contract.
        let sq_phys = unsafe { self.phys_of(self.io_sq_va) };
        let cid_sq = self.admin.current_sq_slot();
        let sq_cmd =
            SubmissionQueueEntry::create_io_sq(cid_sq, IO_QUEUE_ID, QUEUE_DEPTH, sq_phys, IO_QUEUE_ID);
        // SAFETY: forwarded from this method's own contract.
        let Some(cqe) = (unsafe { self.submit_admin(sq_cmd) }) else {
            return false;
        };
        cqe.status() == 0
    }

    /// Submits one I/O read/write command and busy-polls the I/O
    /// completion queue — same shape as `submit_admin`, over the I/O
    /// queue pair instead of the admin one.
    ///
    /// # Safety
    /// `self.bar0`/`self.io_sq_va`/`self.io_cq_va` must all be real,
    /// mapped regions; `self.cap_raw` must already be populated
    /// (`self.ready`, checked by every public caller, guarantees this).
    unsafe fn submit_io(&mut self, entry: SubmissionQueueEntry) -> Option<CompletionQueueEntry> {
        let slot = self.io.current_sq_slot();
        // SAFETY: forwarded from this method's own contract.
        unsafe { self.write_sqe(self.io_sq_va, slot, entry) };
        self.io.advance_sq();
        // SAFETY: forwarded from this method's own contract.
        unsafe { self.ring_sq_doorbell(IO_QUEUE_ID, self.io.sq_tail) };

        const MAX_SPINS: u32 = 20_000_000;
        for _ in 0..MAX_SPINS {
            let cq_slot = self.io.current_cq_slot();
            // SAFETY: forwarded from this method's own contract.
            let cqe = unsafe { self.read_cqe(self.io_cq_va, cq_slot) };
            if cqe.phase() == self.io.expected_phase {
                self.io.advance_cq();
                // SAFETY: forwarded from this method's own contract.
                unsafe { self.ring_cq_doorbell(IO_QUEUE_ID, self.io.cq_head) };
                return Some(cqe);
            }
            core::hint::spin_loop();
        }
        None
    }

    /// Issues one real Read or Write against `self.data_buf_va`'s own
    /// page (`validate_io` already confirmed `sector_count == 1` and
    /// in-range) — `pub`: `subsystem_entry.rs` calls this directly for
    /// the real I/O path, the same split `driver_virtio_blk::VirtioBlk::
    /// submit_request`/`ack_completion`'s own doc comment explains
    /// (kept as one combined call here rather than split
    /// submit/ack-separately, since this driver's own MVP has no real
    /// interrupt-driven path yet to need that split for — this file's
    /// own module doc comment).
    ///
    /// # Safety
    /// `self.ready` must be true (`probe` already succeeded).
    pub unsafe fn read_write(&mut self, opcode: u8, lba: u64) -> Result<(), DriverErrorCode> {
        // SAFETY: forwarded from this method's own contract.
        let data_phys = unsafe { self.phys_of(self.data_buf_va) };
        let cid = self.io.current_sq_slot();
        let cmd = SubmissionQueueEntry::read_write(opcode, cid, lba, 1, data_phys);
        // SAFETY: forwarded from this method's own contract.
        let Some(cqe) = (unsafe { self.submit_io(cmd) }) else {
            return Err(DriverErrorCode::DeviceIo);
        };
        if cqe.status() == 0 {
            Ok(())
        } else {
            Err(DriverErrorCode::DeviceIo)
        }
    }
}

impl DeviceDriver for Nvme {
    fn probe(&mut self) -> Result<DeviceInfo, DriverError> {
        if !self.transport_is_bound() {
            return Err(DriverError::ProbeFailed);
        }
        self.do_probe()?;
        self.ready = true;
        Ok(DeviceInfo {
            sector_size: self.block_size,
            sector_count: self.block_count,
        })
    }

    fn handle_irq(&mut self, _line: u32) {
        // Real completion handling happens synchronously inside
        // `submit_admin`/`submit_io`'s own polling loop (this MVP has
        // exactly one thread of control and one in-flight command per
        // queue, mirroring `driver_virtio_blk::VirtioBlk::handle_irq`'s
        // own identical no-op reasoning) — kept as a no-op to satisfy
        // the trait; `DriverRequest::Irq` below still routes through it
        // for interface completeness.
    }

    fn handle_request(&mut self, req: DriverRequest) -> DriverResponse {
        if !self.ready {
            return DriverResponse::Failed { code: DriverErrorCode::ProbeFailed };
        }
        match req {
            DriverRequest::Probe => DriverResponse::Ready {
                sector_size: self.block_size,
                sector_count: self.block_count,
            },
            DriverRequest::ReadBlocks { lba, sector_count, .. } => {
                if let Err(code) = self.validate_io(sector_count, lba) {
                    return DriverResponse::Failed { code };
                }
                // SAFETY: `self.ready` (checked above).
                match unsafe { self.read_write(io_opcode::READ, lba) } {
                    Ok(()) => DriverResponse::Completed { sectors: 1 },
                    Err(code) => DriverResponse::Failed { code },
                }
            }
            DriverRequest::WriteBlocks { lba, sector_count, .. } => {
                if let Err(code) = self.validate_io(sector_count, lba) {
                    return DriverResponse::Failed { code };
                }
                // SAFETY: `self.ready` (checked above).
                match unsafe { self.read_write(io_opcode::WRITE, lba) } {
                    Ok(()) => DriverResponse::Completed { sectors: 1 },
                    Err(code) => DriverResponse::Failed { code },
                }
            }
            DriverRequest::Irq { line } => {
                self.handle_irq(line);
                DriverResponse::Completed { sectors: 0 }
            }
            DriverRequest::Quiesce => DriverResponse::Ready {
                sector_size: self.block_size,
                sector_count: self.block_count,
            },
            DriverRequest::SendFrame { .. } | DriverRequest::PollFrame => DriverResponse::Failed {
                code: DriverErrorCode::Unsupported,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_field_decoding_matches_spec_bit_positions() {
        // MQES = 15 (0's-based) -> 16 real entries; DSTRD = 2; NVM
        // command set bit (37) set; TO = 10 (500ms units -> 5000ms).
        let raw: u64 = 15 | (2u64 << 32) | (1u64 << 37) | (10u64 << 24);
        assert_eq!(cap::mqes(raw), 16);
        assert_eq!(cap::dstrd(raw), 2);
        assert!(cap::nvm_command_set_supported(raw));
        assert_eq!(cap::timeout_ms(raw), 5000);
    }

    #[test]
    fn doorbell_stride_is_four_shifted_by_dstrd() {
        let raw_dstrd0: u64 = 0;
        let raw_dstrd2: u64 = 2u64 << 32;
        assert_eq!(doorbell_stride_bytes(raw_dstrd0), 4);
        assert_eq!(doorbell_stride_bytes(raw_dstrd2), 16);
    }

    #[test]
    fn doorbell_offsets_follow_the_2n_2n_plus_1_pattern() {
        let raw: u64 = 0; // dstrd = 0, stride = 4 bytes.
        assert_eq!(sq_tail_doorbell_offset(0, raw), 0x1000);
        assert_eq!(cq_head_doorbell_offset(0, raw), 0x1000 + 4);
        assert_eq!(sq_tail_doorbell_offset(1, raw), 0x1000 + 8);
        assert_eq!(cq_head_doorbell_offset(1, raw), 0x1000 + 12);
    }

    #[test]
    fn csts_ready_and_fatal_read_the_correct_bits() {
        assert!(!csts_ready(0));
        assert!(csts_ready(0b1));
        assert!(!csts_fatal(0b1));
        assert!(csts_fatal(0b10));
    }

    #[test]
    fn build_aqa_zero_biases_both_fields() {
        // depth 2 -> zero-based 1 in both the low and high half-word.
        assert_eq!(build_aqa(2), 1 | (1 << 16));
        assert_eq!(build_aqa(1), 0);
    }

    #[test]
    fn build_cc_enable_sets_en_and_the_spec_mandated_entry_sizes() {
        let cc = build_cc_enable();
        assert_eq!(cc & 0x1, 1); // EN
        assert_eq!((cc >> 16) & 0xF, 6); // IOSQES = log2(64)
        assert_eq!((cc >> 20) & 0xF, 4); // IOCQES = log2(16)
    }

    #[test]
    fn submission_queue_entry_is_exactly_64_bytes() {
        assert_eq!(core::mem::size_of::<SubmissionQueueEntry>(), 64);
    }

    #[test]
    fn completion_queue_entry_is_exactly_16_bytes() {
        assert_eq!(core::mem::size_of::<CompletionQueueEntry>(), 16);
    }

    #[test]
    fn identify_namespace_command_targets_nsid_1_with_the_right_cns() {
        let cmd = SubmissionQueueEntry::identify_namespace(7, 0x1000);
        assert_eq!(cmd.cdw0 & 0xFF, admin_opcode::IDENTIFY as u32);
        assert_eq!((cmd.cdw0 >> 16) & 0xFFFF, 7);
        assert_eq!(cmd.nsid, NSID);
        assert_eq!(cmd.prp1, 0x1000);
        assert_eq!(cmd.cdw10 & 0xFF, identify_cns::NAMESPACE as u32);
    }

    #[test]
    fn create_io_cq_command_zero_biases_the_queue_size() {
        let cmd = SubmissionQueueEntry::create_io_cq(1, 1, QUEUE_DEPTH, 0x2000);
        assert_eq!(cmd.cdw10 & 0xFFFF, 1); // QID
        assert_eq!((cmd.cdw10 >> 16) & 0xFFFF, (QUEUE_DEPTH - 1) as u32); // QSIZE, 0's based
        assert_eq!(cmd.cdw11 & 0x1, 1); // PC
    }

    #[test]
    fn create_io_sq_command_carries_its_own_cqid() {
        let cmd = SubmissionQueueEntry::create_io_sq(2, IO_QUEUE_ID, QUEUE_DEPTH, 0x3000, IO_QUEUE_ID);
        assert_eq!(cmd.cdw10 & 0xFFFF, IO_QUEUE_ID as u32);
        assert_eq!((cmd.cdw11 >> 16) & 0xFFFF, IO_QUEUE_ID as u32);
    }

    #[test]
    fn read_write_command_splits_a_64_bit_lba_across_two_dwords_and_zero_biases_nlb() {
        let lba: u64 = 0x1_0000_0002;
        let cmd = SubmissionQueueEntry::read_write(io_opcode::READ, 3, lba, 1, 0x4000);
        assert_eq!(cmd.cdw10, lba as u32);
        assert_eq!(cmd.cdw11, (lba >> 32) as u32);
        assert_eq!(cmd.cdw12 & 0xFFFF, 0); // NLB 0's-based: 1 block -> 0.
        assert_eq!(cmd.nsid, NSID);
    }

    #[test]
    fn completion_phase_command_id_and_status_read_the_correct_bits() {
        // Phase set, CID = 0x1234, status = 0x02 (a nonzero, real error).
        let dw3 = 0x1234 | (1 << 16) | (0x02 << 17);
        let cqe = CompletionQueueEntry { dw0: 0, dw1: 0, dw2: 0, dw3 };
        assert!(cqe.phase());
        assert_eq!(cqe.command_id(), 0x1234);
        assert_eq!(cqe.status(), 0x02);
    }

    #[test]
    fn completion_status_zero_means_success() {
        let cqe = CompletionQueueEntry { dw0: 0, dw1: 0, dw2: 0, dw3: 0 };
        assert!(!cqe.phase());
        assert_eq!(cqe.status(), 0);
    }

    #[test]
    fn queue_pair_wraps_sq_tail_and_flips_phase_on_cq_wraparound() {
        let mut q = QueuePair::new(2);
        assert_eq!(q.current_sq_slot(), 0);
        q.advance_sq();
        assert_eq!(q.current_sq_slot(), 1);
        q.advance_sq();
        assert_eq!(q.current_sq_slot(), 0); // wrapped

        assert!(q.expected_phase);
        q.advance_cq();
        assert_eq!(q.current_cq_slot(), 1);
        assert!(q.expected_phase); // no wrap yet
        q.advance_cq();
        assert_eq!(q.current_cq_slot(), 0);
        assert!(!q.expected_phase); // flipped on wraparound
    }

    #[test]
    fn validate_io_checks_sector_count_then_bounds() {
        let mut d = Nvme::new(0x1000_0000, 0, 0, 0, 0, 0);
        d.block_count = 100;
        assert_eq!(d.validate_io(1, 0), Ok(()));
        assert_eq!(d.validate_io(1, 99), Ok(()));
        assert_eq!(d.validate_io(2, 0), Err(DriverErrorCode::Unsupported));
        assert_eq!(d.validate_io(1, 100), Err(DriverErrorCode::OutOfRange));
    }

    #[test]
    fn probe_without_any_granted_region_fails() {
        // Every region absent (0): `probe`'s own early-return check
        // catches this BEFORE `do_probe` ever touches real memory — the
        // only `probe` path a host test can safely exercise, same
        // reasoning `driver_virtio_blk::tests::probe_without_mmio_fails`
        // gives for its own identical case.
        let mut d = Nvme::new(0, 0, 0, 0, 0, 0);
        assert_eq!(d.probe(), Err(DriverError::ProbeFailed));
    }

    #[test]
    fn transport_is_bound_once_every_region_is_real() {
        let d = Nvme::new(0x1000_0000, 0x2000_0000, 0x2000_1000, 0x2000_2000, 0x2000_3000, 0x2000_4000);
        assert!(d.transport_is_bound());
    }

    #[test]
    fn requests_before_ready_are_rejected() {
        let mut d = Nvme::new(0x1000_0000, 0x2000_0000, 0x2000_1000, 0x2000_2000, 0x2000_3000, 0x2000_4000);
        let r = d.handle_request(DriverRequest::ReadBlocks { lba: 0, sector_count: 1, shared_cap: 1 });
        assert!(matches!(r, DriverResponse::Failed { code: DriverErrorCode::ProbeFailed }));
    }

    #[test]
    fn multi_sector_request_is_unsupported_in_this_mvp() {
        let mut d = Nvme::new(0x1000_0000, 0, 0, 0, 0, 0);
        d.ready = true;
        d.block_count = 100;
        let r = d.handle_request(DriverRequest::WriteBlocks { lba: 0, sector_count: 2, shared_cap: 1 });
        assert!(matches!(r, DriverResponse::Failed { code: DriverErrorCode::Unsupported }));
    }

    #[test]
    fn out_of_range_read_is_rejected_without_touching_hardware() {
        let mut d = Nvme::new(0x1000_0000, 0, 0, 0, 0, 0);
        d.ready = true;
        d.block_count = 100;
        let r = d.handle_request(DriverRequest::ReadBlocks { lba: 100, sector_count: 1, shared_cap: 1 });
        assert!(matches!(r, DriverResponse::Failed { code: DriverErrorCode::OutOfRange }));
    }
}
