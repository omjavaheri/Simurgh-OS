//! ============================================================================
//! mm.rs
//!
//! Purpose: the wire-level control protocol for mm-service, the
//! high-level memory POLICY service (03-Kernel-Subsystems-Layer.md
//! §2.5) — distinct from the microkernel's raw `UntypedMemory`
//! mechanism (02 §3). Other services register their own memory
//! accounting with it; it answers OOM victim, swap-victim, and
//! compute-pool queries.
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §2.5 (this
//! service's three responsibilities — OOM, swap, and CXL/unified-memory
//! coordination are all covered as DECISION queries here; the actual
//! I/O each decision leads to — reclaiming a process, moving bytes to a
//! block device, performing a cross-pool copy — belongs to whichever
//! process holds the relevant capability, not mm-service or this
//! protocol).
//!
//! Position in the system: encoded into `kernel_ipc::SmallMessage`.
//! `ReclaimClass`/`ComputeKind` here are this protocol's OWN wire-level
//! copies of `mm_service::ReclaimClass`/`hal_manifest::ComputeKind` —
//! kept separate rather than shared, matching this crate's own
//! established "`ipc-protocol` never depends on a subsystem crate"
//! dependency direction (subsystems depend on `ipc-protocol`, never the
//! reverse); `mm::subsystem_entry` converts between the two.
//!
//! Safety/invariants: plain integer fields; `Copy`.
//! ============================================================================

/// How aggressively a process should be reclaimed from — the wire-level
/// twin of `mm_service::ReclaimClass` (see that type's own doc comment
/// for what each variant means to OOM victim selection).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReclaimClass {
    /// Spare unless nothing else remains.
    Protected = 0,
    /// Ordinary candidate, ranked by footprint.
    Normal = 1,
    /// Preferred victim.
    Sacrificial = 2,
}

/// Which kind of compute unit a memory pool is attached to — the
/// wire-level twin of `hal_manifest::ComputeKind`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeKind {
    /// CPU-attached DRAM.
    Cpu = 0,
    /// GPU-attached memory.
    Gpu = 1,
    /// NPU-attached memory.
    Npu = 2,
    /// TPU-attached memory.
    Tpu = 3,
    /// FPGA-attached memory.
    Fpga = 4,
}

/// A request to mm-service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmRequest {
    /// Registers or updates a process's own memory accounting. Reply:
    /// `Registered`.
    Register {
        /// The process's thread id (its handle for reclaim requests).
        thread: u32,
        /// Resident bytes it is currently charged for.
        resident_bytes: u64,
        /// How reclaimable it is.
        class: ReclaimClass,
    },
    /// Drops a process's own accounting (it exited). Reply:
    /// `Unregistered`.
    Unregister {
        /// The process's thread id.
        thread: u32,
    },
    /// Asks for the current OOM victim under the registered set. Reply:
    /// `Victim`.
    QueryVictim,
    /// Asks for the running total of resident memory across the
    /// registered set. Reply: `TotalResident`.
    QueryTotalResident,
    /// Registers or updates one swappable region's own accounting. Reply:
    /// `SwapRegionRegistered`.
    RegisterSwapRegion {
        /// The owning process's thread id.
        thread: u32,
        /// The owning process's own identifier for this region.
        region_id: u32,
        /// The region's size.
        bytes: u64,
        /// Monotonic timestamp of this region's last access.
        last_touched_ns: u64,
    },
    /// Drops one region's own accounting. Reply:
    /// `SwapRegionUnregistered`.
    UnregisterSwapRegion {
        /// The owning process's thread id.
        thread: u32,
        /// The owning process's own identifier for this region.
        region_id: u32,
    },
    /// Asks for the current swap-out victim under the registered set.
    /// Reply: `SwapVictim`.
    QuerySwapVictim,
    /// Registers or updates one compute pool's own accounting. Reply:
    /// `ComputePoolRegistered`.
    RegisterComputePool {
        /// Stable identifier for this pool.
        pool_id: u32,
        /// Which kind of compute unit this pool is attached to.
        kind: ComputeKind,
        /// The pool's total size.
        capacity_bytes: u64,
        /// Bytes currently allocated from this pool.
        used_bytes: u64,
    },
    /// Asks which registered pool should satisfy an allocation of `bytes`.
    /// Reply: `ComputePoolChosen`.
    QueryComputePool {
        /// The allocation size to satisfy.
        bytes: u64,
        /// A preferred pool kind (locality), if any.
        preferred_kind: Option<ComputeKind>,
    },
}

/// A reply from mm-service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmResponse {
    /// `Register` completed.
    Registered,
    /// `Unregister` completed.
    Unregistered,
    /// `QueryVictim` result. `thread == u32::MAX` means no process is
    /// currently registered (the wire-level "no victim" sentinel — same
    /// convention this crate's own `FsResponse`/`DriverResponse` already
    /// use throughout instead of an `Option`).
    Victim {
        /// The chosen victim's thread id, or `u32::MAX` for none.
        thread: u32,
    },
    /// `QueryTotalResident` result.
    TotalResident {
        /// Total resident bytes across the registered set.
        bytes: u64,
    },
    /// `RegisterSwapRegion` completed.
    SwapRegionRegistered,
    /// `UnregisterSwapRegion` completed.
    SwapRegionUnregistered,
    /// `QuerySwapVictim` result. `thread == u32::MAX` (with `region_id`
    /// meaningless) means no region is currently registered — same
    /// sentinel convention as `Victim` above.
    SwapVictim {
        /// The chosen victim's owning thread id, or `u32::MAX` for none.
        thread: u32,
        /// The chosen victim's own region id.
        region_id: u32,
    },
    /// `RegisterComputePool` completed.
    ComputePoolRegistered,
    /// `QueryComputePool` result. `pool_id == u32::MAX` means no
    /// registered pool had room — same sentinel convention as `Victim`
    /// above.
    ComputePoolChosen {
        /// The chosen pool's id, or `u32::MAX` for none.
        pool_id: u32,
    },
    /// The request could not be decoded/handled (e.g. an unsupported
    /// opcode from a version-skewed peer) — same "an honest error
    /// variant, not a repurposed success shape" convention `FsResponse::
    /// Error`/`DisplayResponse::Error` already establish.
    Error {
        /// Machine-readable error code.
        code: MmErrorCode,
    },
}

/// mm-service error codes.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MmErrorCode {
    /// The request could not be decoded, or named an unsupported
    /// operation.
    Unsupported = 1,
}
