//! ============================================================================
//! root-task
//!
//! Purpose: the first user-space process. It owns the initial capability
//! set the kernel hands it at boot (all of RAM as `UntypedMemory`, plus
//! the Hardware Manifest), and is responsible for *policy*: how to divide
//! memory among services, which services to start, and what capabilities
//! each one gets (03-Kernel-Subsystems-Layer.md §1). The kernel provides
//! only mechanism (`Retype`, `CapGrant`, `Map` — 02 §3/§6).
//!
//! Architecture reference: 03-Kernel-Subsystems-Layer.md §1 (Root Task
//! role), §5.1 (MVP: bring up Device Manager + minimal VFS + one block
//! driver); 02-Microkernel-Layer.md §3 (UntypedMemory), §8.2 (MVP: Root
//! Task spawns a second thread and does synchronous IPC with it).
//!
//! Position in the system: an isolated layer-3 process. It talks to the
//! kernel only through the syscall surface (`kernel_core::SyscallOp` — used
//! here purely as the ABI vocabulary; a thin userspace syscall shim will
//! wrap it later) and to other services through `ipc-protocol` messages.
//!
//! MVP scope: this crate currently provides the two pieces that are pure,
//! testable policy — the memory-split plan and the service spawn plan.
//! Executing the plan (issuing the actual `Retype`/`CapGrant` syscalls and
//! loading service images) is wired once the layer-2 TCB-load path exists.
//!
//! Safety/invariants: planning is allocation-light and total; a plan never
//! over-commits the available untyped memory.
//! ============================================================================

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

/// A service the Root Task starts at boot (03-Kernel-Subsystems-Layer.md §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// Device Manager — spawns and supervises driver processes (§2.1).
    DeviceManager,
    /// VFS Router + the native filesystem service (§2.2).
    VfsService,
    /// A single block driver (virtio-blk on QEMU) for the MVP (§5.1).
    BlockDriver,
    /// The Security Broker's CapGrant/CapRevoke intermediary (Issue #28,
    /// 02-Microkernel-Layer.md §2.1/§6). The ONLY process Root Task
    /// grants authority to issue real `CapGrant`/`CapRevoke` syscalls on
    /// the Security Broker's (layer 4) behalf — the Security Broker
    /// itself never holds a kernel capability directly. Speaks
    /// `ipc_protocol::security::{SecurityRequest, SecurityResponse}`
    /// (`Namespace::Security`) to the Security Broker and issues real
    /// `SyscallOp::CapGrant`/`CapRevoke` to the kernel on its behalf,
    /// resolving each request's `target_service` to a destination
    /// `CapId` via its own internal, boot-time mapping (Issue #30's
    /// decision — see `02-Microkernel-Layer.md` §2.1: this mapping is
    /// deliberately NOT a kernel concept). Requires Root Task to grant it
    /// a destination-TCB `CapId` for every other service it might need to
    /// grant capabilities into — which is why it boots LAST in
    /// `BOOT_ORDER`, after every such destination already exists.
    SecurityBrokerIntermediary,
}

impl Service {
    /// Boot order — Device Manager first (drivers need it), then VFS,
    /// then the block driver (VFS mounts it), then the Security Broker
    /// intermediary last: it needs a destination-TCB `CapId` for every
    /// other service it might later be asked to grant a capability into,
    /// so those services must already exist for Root Task to grant it
    /// those `CapId`s at spawn time.
    pub const BOOT_ORDER: [Service; 4] = [
        Service::DeviceManager,
        Service::VfsService,
        Service::BlockDriver,
        Service::SecurityBrokerIntermediary,
    ];

    /// Rough working-set budget for this service, in bytes — how much
    /// `UntypedMemory` the Root Task earmarks for it before it starts.
    /// Starting figures; tuned once services are real.
    pub const fn memory_budget_bytes(self) -> u64 {
        match self {
            Service::DeviceManager => 4 * 1024 * 1024,
            Service::VfsService => 8 * 1024 * 1024,
            Service::BlockDriver => 2 * 1024 * 1024,
            // Small and fixed: this service holds no bulk data, just a
            // service-id -> CapId lookup table and in-flight request
            // bookkeeping — closer to BlockDriver's footprint than
            // VfsService's.
            Service::SecurityBrokerIntermediary => 2 * 1024 * 1024,
        }
    }
}

/// One entry in the memory-split plan: a service and the untyped-memory
/// slice size reserved for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryGrant {
    /// The service this slice is for.
    pub service: Service,
    /// Bytes reserved (page-rounded).
    pub bytes: u64,
}

/// The Root Task's plan for one boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootPlan {
    /// Per-service memory reservations, in boot order.
    pub grants: Vec<MemoryGrant>,
    /// Bytes kept in reserve for the Root Task itself (its own heap,
    /// capability tables, and headroom for later spawns).
    pub root_reserve_bytes: u64,
    /// Bytes left unallocated (handed out lazily later).
    pub free_bytes: u64,
}

/// Errors from planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanError {
    /// The total usable memory is too small to satisfy the Root Task
    /// reserve plus every service's minimum budget.
    InsufficientMemory,
}

/// Page size the plan rounds reservations to (matches the kernel's).
pub const PAGE_SIZE: u64 = 4096;

/// Builds the boot plan for `total_usable_bytes` of RAM (the sum the Root
/// Task computes from its `UntypedMemory` capabilities / the manifest).
///
/// Policy: reserve `root_reserve` for the Root Task, then give each
/// service in `Service::BOOT_ORDER` its `memory_budget_bytes`, then leave
/// the rest free. Fails if that does not fit.
pub fn plan_boot(total_usable_bytes: u64) -> Result<BootPlan, PlanError> {
    let root_reserve = round_up(total_usable_bytes / 16, PAGE_SIZE).max(4 * 1024 * 1024);

    let mut grants = Vec::new();
    let mut committed = root_reserve;
    for svc in Service::BOOT_ORDER {
        let bytes = round_up(svc.memory_budget_bytes(), PAGE_SIZE);
        committed = committed.saturating_add(bytes);
        grants.push(MemoryGrant { service: svc, bytes });
    }

    if committed > total_usable_bytes {
        return Err(PlanError::InsufficientMemory);
    }

    Ok(BootPlan {
        grants,
        root_reserve_bytes: root_reserve,
        free_bytes: total_usable_bytes - committed,
    })
}

/// Rounds `v` up to a multiple of `align` (a power of two).
pub const fn round_up(v: u64, align: u64) -> u64 {
    (v + align - 1) & !(align - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_fits_in_reasonable_ram() {
        let plan = plan_boot(128 * 1024 * 1024).unwrap();
        assert_eq!(plan.grants.len(), 4);
        let committed: u64 = plan.root_reserve_bytes
            + plan.grants.iter().map(|g| g.bytes).sum::<u64>();
        assert_eq!(committed + plan.free_bytes, 128 * 1024 * 1024);
        assert!(plan.free_bytes > 0);
    }

    #[test]
    fn plan_rejects_tiny_ram() {
        assert_eq!(plan_boot(1 * 1024 * 1024), Err(PlanError::InsufficientMemory));
    }

    #[test]
    fn boot_order_is_device_manager_first() {
        assert_eq!(Service::BOOT_ORDER[0], Service::DeviceManager);
    }

    #[test]
    fn boot_order_ends_with_security_broker_intermediary() {
        // It needs a destination-TCB CapId for every other service it
        // might grant a capability into (Issue #28/#30), so those
        // services must already exist when it starts.
        assert_eq!(
            Service::BOOT_ORDER[Service::BOOT_ORDER.len() - 1],
            Service::SecurityBrokerIntermediary
        );
    }
}
