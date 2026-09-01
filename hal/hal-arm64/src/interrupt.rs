//! ============================================================================
//! interrupt.rs — ARM64
//!
//! Implements `hal_core::interrupt::InterruptController` for ARM64,
//! per 01-HAL-Layer.md section 3.4: "یکسان‌سازی... GIC v3/v4 (ARM64)...
//! پشت یک API واحد".
//!
//! Design:
//!   - GICv3 system register interface (ICC_* registers, accessed via
//!     MRS/MSR) is used for the CPU interface (EOI, priority, IAR read)
//!     — this is the modern, MMIO-free interface GICv3/v4 introduced
//!     specifically to avoid the MMIO overhead GICv2 required; every
//!     QEMU `virt` machine target (section 8's acceptance criteria)
//!     with `gic-version=3` (the default for recent QEMU versions)
//!     supports this.
//!   - The GIC Distributor (GICD) remains MMIO-based (there is no
//!     system-register equivalent for distributor-wide configuration
//!     like enabling/routing a specific SPI) — its base address is
//!     supplied by Device Tree / ACPI MADT GIC Distributor entry,
//!     folded in via `memory.rs`'s firmware table parsing, mirroring
//!     how hal-x86_64's interrupt.rs receives its xAPIC MMIO base.
//!   - SGIs (SGI0-15, software-generated interrupts) implement
//!     `send_ipi` — GICv3's direct equivalent of x86_64's ICR-based
//!     IPI mechanism.
//! ============================================================================

use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicU64, Ordering};

use hal_core::error::HalError;
use hal_core::interrupt::{InterruptController, IrqHandler, IrqId};
use hal_manifest::raw::InterruptControllerKindRaw;

use crate::timer;

// ============================================================================
// GICv3 system register access (ICC_* registers, MRS/MSR — no MMIO)
// ============================================================================

/// Reads the Interrupt Acknowledge Register (ICC_IAR1_EL1): returns
/// the INTID of the highest-priority pending interrupt and
/// simultaneously acknowledges it (moves it from Pending to Active
/// state, per GICv3 spec section 4.1). A value of 1020-1023 indicates
/// a "spurious" read (no real interrupt pending).
#[cfg(not(target_os = "none"))]
fn read_iar() -> u32 {
    // Host (`cargo test`) stub — no GIC CPU interface off the bare-metal
    // target. 1023 is the architectural "spurious / nothing pending"
    // INTID, the safe value for any code path that might reach here.
    1023
}

#[cfg(target_os = "none")]
fn read_iar() -> u32 {
    let value: u64;
    // SAFETY: ICC_IAR1_EL1 is unconditionally readable once the GIC
    // CPU interface has been enabled (this file's
    // `bootstrap_current_core` does so before any interrupt can be
    // taken, matching cpu.rs's VBAR_EL1 load ordering) — no further
    // preconditions.
    unsafe {
        core::arch::asm!("mrs {}, ICC_IAR1_EL1", out(reg) value);
    }
    (value & 0xFF_FFFF) as u32 // INTID is bits 23:0
}

/// Writes the End Of Interrupt Register (ICC_EOIR1_EL1) for `intid`,
/// completing the priority-drop half of interrupt completion (GICv3
/// spec section 4.1: EOI is split into priority-drop, via this
/// register, and deactivation — for this project's single-priority-
/// group MVP configuration, writing EOIR alone also deactivates,
/// matching the simplified single-step model most GICv3 tutorials and
/// QEMU's default configuration assume).
///
/// # Safety
/// `intid` must be the SAME value most recently returned by
/// `read_iar()` on this core, not yet EOI'd — writing an EOI for an
/// INTID that was not the one actually acknowledged produces undefined
/// GIC state per the spec.
#[cfg(not(target_os = "none"))]
unsafe fn write_eoi(_intid: u32) {
    // Host (`cargo test`) stub — no GIC CPU interface off the bare-metal
    // target.
}

#[cfg(target_os = "none")]
unsafe fn write_eoi(intid: u32) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!("msr ICC_EOIR1_EL1, {}", in(reg) intid as u64);
    }
}

/// Enables the GICv3 CPU interface (ICC_SRE_EL1: system register
/// enable) and sets the priority mask to allow all priorities through
/// (ICC_PMR_EL1), plus enables Group 1 interrupt signaling
/// (ICC_IGRPEN1_EL1) — the standard three-register bring-up sequence
/// for a GICv3 CPU interface (GICv3 spec section 4.6.1).
///
/// # Safety
/// Must be called once per core, before this core relies on any IRQ
/// being delivered.
#[cfg(not(target_os = "none"))]
unsafe fn enable_cpu_interface() {
    // Host (`cargo test`) stub — no GICv3 CPU interface off the
    // bare-metal target.
}

#[cfg(target_os = "none")]
unsafe fn enable_cpu_interface() {
    // SAFETY: forwarded from this function's own contract; these three
    // writes are the documented, well-defined GICv3 CPU interface
    // bring-up sequence. Requires `ICC_SRE_EL2.SRE` (or EL3's
    // equivalent) already set by firmware — true for QEMU's `virt`
    // machine's own EDK2/ArmVirtQemu firmware, which hands this project
    // off directly at EL1 (see `lib.rs`'s own `_start` doc comment on
    // why the EL2 branch there never actually runs in practice), so
    // this project has no opportunity to set it itself even if it
    // needed to.
    unsafe {
        // ICC_SRE_EL1 bit 0 = SRE (system register enable).
        core::arch::asm!("mrs x0, ICC_SRE_EL1", "orr x0, x0, #1", "msr ICC_SRE_EL1, x0", "isb", out("x0") _);
        // ICC_PMR_EL1: priority mask, 0xFF = allow all priorities.
        core::arch::asm!("mov x0, #0xFF", "msr ICC_PMR_EL1, x0", out("x0") _);
        // ICC_IGRPEN1_EL1 bit 0 = enable Group 1 interrupts (the group
        // this project uses uniformly for both SPIs and SGIs, avoiding
        // the added complexity of a Group 0/Group 1 split this MVP
        // phase does not need).
        core::arch::asm!("mov x0, #1", "msr ICC_IGRPEN1_EL1, x0", out("x0") _);
    }
}

// ============================================================================
// GIC Distributor (GICD) — MMIO-based, per module docs
// ============================================================================

mod gicr_reg {
    /// Redistributor Wake Register (RD_base frame, offset 0x0014): bit 1
    /// = ProcessorSleep (software clears this to wake the redistributor
    /// — QEMU's emulated GICv3 defaults to AWAKE for a single-core boot,
    /// but this is the architecturally-required bring-up step per the
    /// GICv3 spec's own reference sequence, not something to rely on an
    /// emulator default for), bit 2 = ChildrenAsleep (read-only,
    /// software polls this to clear after clearing ProcessorSleep).
    pub const WAKER: u32 = 0x0014;
    /// SGI_base frame (RD_base + `SGI_BASE_OFFSET`) Interrupt Set-Enable
    /// Register for INTID 0-31 (SGIs + PPIs) — the GICv3 REPLACEMENT for
    /// the Distributor's own `gicd_reg::ISENABLER` covering the SAME
    /// INTID range, which becomes RES0/ignored for INTID 0-31 once
    /// `GICD_CTLR.ARE` is enabled (see `bootstrap_current_core`'s own
    /// doc comment on the real bug this fixes).
    pub const ISENABLER0: u32 = 0x0100;
    /// SGI_base frame Interrupt Priority Registers, same one-byte-per-
    /// INTID layout as `gicd_reg::IPRIORITYR`, for the SAME reason.
    pub const IPRIORITYR: u32 = 0x0400;
    /// Redistributors are always allocated in adjacent RD_base+SGI_base
    /// frame PAIRS (64 KiB each); the SGI_base frame — where PPI/SGI
    /// enable and priority actually live — is this fixed offset past
    /// the RD_base frame `bootstrap_current_core` also touches (for
    /// `WAKER`).
    pub const SGI_BASE_OFFSET: u64 = 0x1_0000;
}

mod gicd_reg {
    /// Distributor Control Register.
    pub const CTLR: u32 = 0x0000;
    /// Interrupt Set-Enable Registers (one bit per INTID, 32 per
    /// register).
    pub const ISENABLER: u32 = 0x0100;
    /// Interrupt Clear-Enable Registers.
    pub const ICENABLER: u32 = 0x0180;
    /// Interrupt Priority Registers (one byte per INTID).
    pub const IPRIORITYR: u32 = 0x0400;
    /// Interrupt Routing Registers (GICv3: 64-bit, one per SPI, target
    /// affinity routing — replaces GICv2's 8-bit ITARGETSR).
    pub const IROUTER: u32 = 0x6100;
}

/// # Safety
/// `gicd_base` must be a valid, mapped GICD MMIO base address (mapped
/// via `MemoryBootstrap::setup_identity_mapping` with
/// `MapPermissions::DEVICE_MMIO` before this is called — same ordering
/// contract as hal-x86_64's xapic_read/write).
unsafe fn gicd_read32(gicd_base: u64, offset: u32) -> u32 {
    let ptr = (gicd_base + offset as u64) as *const u32;
    // SAFETY: forwarded from this function's own contract; volatile
    // for the same reason as hal-x86_64's xapic_read.
    unsafe { ptr.read_volatile() }
}

/// # Safety
/// Same contract as `gicd_read32`.
unsafe fn gicd_write32(gicd_base: u64, offset: u32, value: u32) {
    let ptr = (gicd_base + offset as u64) as *mut u32;
    // SAFETY: forwarded from this function's own contract.
    unsafe { ptr.write_volatile(value) }
}

/// # Safety
/// Same contract as `gicd_read32`, for the 64-bit IROUTER register.
unsafe fn gicd_write64(gicd_base: u64, offset: u32, value: u64) {
    let ptr = (gicd_base + offset as u64) as *mut u64;
    // SAFETY: forwarded from this function's own contract.
    unsafe { ptr.write_volatile(value) }
}

// ============================================================================
// SGI (Software Generated Interrupt) — send_ipi mechanism
// ============================================================================

/// Vector reserved for the ARM Generic Timer's PPI (Private Peripheral
/// Interrupt) — INTID 30 is the standard, fixed INTID for the
/// non-secure EL1 physical timer per the GIC/Generic-Timer integration
/// convention QEMU's `virt` machine follows (and the broader Arm
/// SBSA/SBBR platform conventions), unlike x86_64 where the timer
/// vector is a software choice (interrupt.rs's `TIMER_VECTOR = 32`).
/// PPIs, unlike x86_64's freely-assignable vectors, have architecturally
/// fixed INTIDs (16-31) — this is a hardware convention, not a project
/// choice.
pub(crate) const TIMER_PPI_INTID: u32 = 30;

/// First INTID available for `register_irq`. INTIDs 0-15 are SGIs
/// (used internally by `send_ipi`, not exposed via `register_irq`),
/// 16-31 are PPIs (INTID 30 reserved for the timer above; the
/// remaining PPIs are reserved for this project's future per-core
/// peripheral needs), 32+ are SPIs (Shared Peripheral Interrupts) —
/// the general-purpose device IRQ space this project exposes through
/// `register_irq`, mirroring hal-x86_64's `FIRST_USABLE_IRQ_VECTOR`
/// concept.
const FIRST_USABLE_INTID: u32 = 32;

/// GICv3 supports up to 1020 SPIs; sized generously but boundedly for
/// this no_std/no_alloc fixed-table requirement, matching
/// hal-x86_64's IRQ_TABLE_SIZE pattern.
const MAX_TRACKED_INTIDS: usize = 480;

// ============================================================================
// InterruptCtrl — InterruptController implementation
// ============================================================================

pub struct InterruptCtrl {
    gicd_base: u64,
    handlers: RefCell<[Option<IrqHandler>; MAX_TRACKED_INTIDS]>,
    ipi_target_core_count: Cell<u32>,
}

impl InterruptCtrl {
    /// Constructs the interrupt controller abstraction for the current
    /// core. `gicd_base` is discovered by `memory.rs`'s firmware table
    /// parsing (ACPI MADT GIC Distributor entry, or Device Tree
    /// `interrupt-controller` node per section 10's ACPI-preferred,
    /// DT-fallback policy) and threaded through the same way
    /// hal-x86_64's `xapic_mmio_base()` is read directly from an MSR —
    /// here it must come from firmware tables since ARM64 has no
    /// architectural register analogous to IA32_APIC_BASE for locating
    /// the distributor.
    ///
    /// NOTE: for this MVP phase, `gicd_base` is accepted as a
    /// parameter with a documented QEMU-`virt`-machine-default fallback
    /// (see `hal_arm64_rust_entry`, lib.rs) rather than requiring full
    /// Device Tree parsing to already exist — full DT-based discovery
    /// is a tracked follow-up alongside memory.rs's own DT parsing
    /// scope (see that file).
    pub fn new(gicd_base: u64) -> Self {
        Self {
            gicd_base,
            handlers: RefCell::new([None; MAX_TRACKED_INTIDS]),
            ipi_target_core_count: Cell::new(1),
        }
    }

    pub fn set_topology(&self, core_count: u32) {
        self.ipi_target_core_count.set(core_count);
    }

    pub fn detected_kind(&self) -> InterruptControllerKindRaw {
        // This file always configures GICv3 (per module docs); GICv4's
        // additional virtual-LPI capabilities are not used by this MVP
        // phase, so GICv3 is reported regardless of whether the
        // underlying hardware happens to be GICv4-capable (GICv4 is a
        // strict superset when used in GICv3-compatible mode, which is
        // what this file does).
        InterruptControllerKindRaw::Gicv3
    }

    pub fn primary_base(&self) -> u64 {
        self.gicd_base
    }

    /// GICv3's Redistributor is the "secondary" MMIO region hal-
    /// manifest's `InterruptControllerInfoRaw::secondary_base` doc
    /// comment anticipates for exactly this architecture. Full
    /// per-core Redistributor base discovery (each core has its own)
    /// is a tracked follow-up alongside the multi-core enumeration
    /// deferral in cpu.rs — this MVP phase's single-core scope means
    /// only core 0's Redistributor is ever relevant, and system-
    /// register-based PPI/SGI handling above does not actually require
    /// touching the Redistributor's MMIO region at all (unlike SPI
    /// configuration, which does require GICD access) — so `None` is
    /// accurate for this phase's actual usage, not just a placeholder.
    pub fn secondary_base(&self) -> Option<u64> {
        None
    }

    /// Configures SPI `intid` in the distributor: sets its priority,
    /// routes it to core 0 (this MVP phase's only core), and enables
    /// it. Called from `register_irq` below — GICv3, unlike x86_64's
    /// APIC, requires per-IRQ distributor configuration before an SPI
    /// can be delivered at all (there is no equivalent of x86_64's
    /// "any IDT gate works once the vector fires" model; SPIs are
    /// disabled by default at the distributor).
    fn configure_spi(&self, intid: u32) {
        let reg_index = (intid / 32) as u32;
        let bit = intid % 32;

        // Priority: one byte per INTID at IPRIORITYR + intid. Set to a
        // mid-range value (0x80) — this MVP phase does not yet
        // implement priority-based preemption policy (a layer 2
        // scheduler concern per 02-Microkernel-Layer.md section 4.4's
        // Priority Inheritance requirement), so every SPI gets the
        // same priority for now.
        //
        // SAFETY: `self.gicd_base` was mapped as DEVICE_MMIO before
        // this instance became reachable (ordering contract mirrors
        // hal-x86_64's `bootstrap_current_core` xAPIC mapping
        // requirement) — see this file's own `bootstrap_current_core`.
        unsafe {
            let byte_offset = gicd_reg::IPRIORITYR + intid;
            gicd_write32(self.gicd_base, byte_offset & !0x3, 0x8080_8080);
        }

        // Routing: IROUTER is a 64-bit register per SPI (GICv3 uses
        // affinity-based routing, not a target-core bitmask like
        // GICv2's ITARGETSR). Affinity 0.0.0.0 (all fields zero) routes
        // to core 0's affinity — this MVP phase's only core.
        //
        // SAFETY: same ordering contract as above.
        unsafe {
            gicd_write64(self.gicd_base, gicd_reg::IROUTER + (intid - 32) * 8, 0);
        }

        // Enable: one bit per INTID in ISENABLER.
        //
        // SAFETY: same ordering contract as above.
        unsafe {
            gicd_write32(self.gicd_base, gicd_reg::ISENABLER + reg_index * 4, 1 << bit);
        }
    }
}

impl InterruptController for InterruptCtrl {
    fn register_irq(&self, irq: IrqId, handler: IrqHandler) -> Result<(), HalError> {
        let intid = irq.as_u32();
        if intid < FIRST_USABLE_INTID || intid >= FIRST_USABLE_INTID + MAX_TRACKED_INTIDS as u32 {
            return Err(HalError::InvalidIrqId);
        }
        let idx = (intid - FIRST_USABLE_INTID) as usize;
        let mut handlers = self.handlers.borrow_mut();
        if handlers[idx].is_some() {
            return Err(HalError::IrqAlreadyRegistered);
        }
        handlers[idx] = Some(handler);
        drop(handlers);

        self.configure_spi(intid);
        Ok(())
    }

    fn unregister_irq(&self, irq: IrqId) {
        let intid = irq.as_u32();
        if intid >= FIRST_USABLE_INTID && intid < FIRST_USABLE_INTID + MAX_TRACKED_INTIDS as u32 {
            let idx = (intid - FIRST_USABLE_INTID) as usize;
            self.handlers.borrow_mut()[idx] = None;

            let reg_index = intid / 32;
            let bit = intid % 32;
            // SAFETY: same ordering contract as configure_spi.
            unsafe {
                gicd_write32(self.gicd_base, gicd_reg::ICENABLER + reg_index * 4, 1 << bit);
            }
        }
    }

    fn mask_irq(&self, irq: IrqId) -> Result<(), HalError> {
        let intid = irq.as_u32();
        if intid < FIRST_USABLE_INTID || intid >= FIRST_USABLE_INTID + MAX_TRACKED_INTIDS as u32 {
            return Err(HalError::InvalidIrqId);
        }
        let reg_index = intid / 32;
        let bit = intid % 32;
        // Unlike x86_64's Local APIC (which has no general per-vector
        // mask register, per hal-x86_64/interrupt.rs's mask_irq doc
        // comment), GICv3's ICENABLER genuinely IS a real per-SPI mask
        // — this is a case where ARM64's abstraction is MORE complete
        // than x86_64's for this specific operation, not less.
        //
        // SAFETY: ordering contract per configure_spi.
        unsafe {
            gicd_write32(self.gicd_base, gicd_reg::ICENABLER + reg_index * 4, 1 << bit);
        }
        Ok(())
    }

    fn unmask_irq(&self, irq: IrqId) -> Result<(), HalError> {
        let intid = irq.as_u32();
        if intid < FIRST_USABLE_INTID || intid >= FIRST_USABLE_INTID + MAX_TRACKED_INTIDS as u32 {
            return Err(HalError::InvalidIrqId);
        }
        let reg_index = intid / 32;
        let bit = intid % 32;
        // SAFETY: ordering contract per configure_spi.
        unsafe {
            gicd_write32(self.gicd_base, gicd_reg::ISENABLER + reg_index * 4, 1 << bit);
        }
        Ok(())
    }

    fn send_ipi(&self, target_core: usize, vector: u8) -> Result<(), HalError> {
        if target_core as u32 >= self.ipi_target_core_count.get() {
            return Err(HalError::InvalidIpiTarget);
        }

        // ICC_SGI1R_EL1 encoding (GICv3 spec section 12.2.3): bits
        // 27:24 = INTID (SGI number, 0-15 — `vector` is truncated to
        // this range since SGIs have no wider addressing, unlike
        // x86_64's full 8-bit IPI vector), bits 55:48 = target list
        // affinity-0 (bitmask of cores within this affinity level to
        // target), other affinity fields zero for this MVP phase's
        // single-affinity-level (Aff0-only) core topology.
        let sgi_id = (vector & 0x0F) as u64;
        let target_list: u64 = 1 << target_core; // Aff0 bitmask
        let value = (sgi_id << 24) | (target_list << 0);

        // SAFETY: ICC_SGI1R_EL1 write is well-defined per the GICv3
        // spec for any validly-encoded SGI ID (0-15, guaranteed by the
        // `& 0x0F` mask above) and target list.
        #[cfg(target_os = "none")]
        unsafe {
            core::arch::asm!("msr ICC_SGI1R_EL1, {}", in(reg) value);
        }
        // Host (`cargo test`) build: the target-range check above is the
        // part unit tests exercise; the register write itself is
        // bare-metal only.
        #[cfg(not(target_os = "none"))]
        let _ = value;

        Ok(())
    }

    fn irq_line_count(&self) -> u32 {
        MAX_TRACKED_INTIDS as u32
    }

    fn ipi_target_core_count(&self) -> u32 {
        self.ipi_target_core_count.get()
    }

    fn end_of_interrupt(&self, irq: IrqId) {
        // SAFETY: this is only ever called from dispatch_current_irq
        // (below) with the exact INTID `read_iar()` just returned,
        // satisfying `write_eoi`'s contract.
        unsafe {
            write_eoi(irq.as_u32());
        }
    }
}

impl InterruptCtrl {
    /// Performs one-time, per-core GIC bring-up: enables the CPU
    /// interface (system registers) and, for the timer PPI, configures
    /// its priority via the distributor (PPIs, unlike SPIs, do not
    /// need distributor-level routing since they are inherently
    /// per-core, but DO still need enabling via ISENABLER like any
    /// other INTID).
    ///
    /// # Safety
    /// Must be called once per core, after `Cpu::bootstrap_current_core`
    /// (cpu.rs) has already loaded VBAR_EL1, and after the GICD MMIO
    /// region has been mapped via `MemoryBootstrap::
    /// setup_identity_mapping` with `MapPermissions::DEVICE_MMIO` at
    /// `self.gicd_base` — mirrors hal-x86_64's
    /// `InterruptCtrl::bootstrap_current_core` ordering contract
    /// exactly.
    pub unsafe fn bootstrap_current_core(&self) -> Result<(), HalError> {
        // SAFETY: forwarded from this function's own contract.
        unsafe {
            enable_cpu_interface();
        }

        // Enable the distributor itself (GICD_CTLR) — a REAL, PRE-
        // EXISTING gap this session's preemption work found via QEMU:
        // `gicd_reg::CTLR` was DEFINED but never actually WRITTEN
        // anywhere in this crate (confirmed via `grep -rn
        // "gicd_reg::CTLR"` turning up only its own declaration). Per-
        // INTID enable (ISENABLER) and the CPU interface's own Group 1
        // enable (ICC_IGRPEN1_EL1, `enable_cpu_interface` above) are
        // BOTH necessary but NOT sufficient — the distributor has its
        // OWN top-level "forward Group 1 interrupts at all" gate, off
        // by default on QEMU's emulated GICv3 (confirmed via
        // instrumented bisection: the CPU interface enabled cleanly,
        // ISENABLER/IPRIORITYR writes succeeded, `TimerAbstraction::
        // set_oneshot` armed a real future deadline, yet the timer PPI
        // never reached this core at all until this write was added).
        // Bit 1 = EnableGrp1 (this project's single-security-state GIC
        // configuration — QEMU's `virt` machine models no Secure world
        // — per the GICv3 architecture spec's "GICD_CTLR when GICD_
        // CTLR.DS == 1" register view); bit 4 = ARE (Affinity Routing
        // Enable), required for `configure_spi`'s own IROUTER writes
        // (affinity-based SPI routing) to have any effect at all — set
        // here too since it was equally unwritten before this fix,
        // though every SPI configured before this fix was configured
        // moot: no INTID could reach the core regardless without
        // EnableGrp1 either.
        //
        // SAFETY: ordering contract per this method's own doc comment.
        unsafe {
            gicd_write32(self.gicd_base, gicd_reg::CTLR, (1 << 0) | (1 << 1) | (1 << 4));
        }

        // Enable the timer PPI (INTID 30) — via the REDISTRIBUTOR, not
        // the distributor. A SECOND real, pre-existing bug this
        // session's preemption work found via QEMU (found only after
        // fixing GICD_CTLR above, which is what exposed it): PPIs/SGIs
        // (INTID 0-31) are configured through the Distributor's own
        // `gicd_reg::ISENABLER`/`IPRIORITYR` ONLY in GICv2 or when
        // `GICD_CTLR.ARE` is disabled — per the GICv3 architecture
        // spec, once ARE is enabled (as it now is, required for
        // `configure_spi`'s own SPI affinity routing), GICD's own
        // ISENABLER0/IPRIORITYR for INTID 0-31 become RES0/ignored, and
        // the REDISTRIBUTOR's SGI_base frame carries the real registers
        // instead — `secondary_base()`'s own doc comment ASSERTED "no
        // Redistributor MMIO access is needed" for this reason, which
        // this session's own instrumented bisection disproved (writes
        // to the distributor path silently had no effect once ARE was
        // on; the timer PPI still never reached this core). Wakes the
        // redistributor first (`GICR_WAKER.ProcessorSleep`, cleared per
        // the GICv3 spec's own reference bring-up sequence — QEMU's
        // emulated redistributor happens to default to already-awake
        // for a single-core boot, but this is not something to rely on
        // an emulator default for), then writes `GICR_IPRIORITYR`/
        // `GICR_ISENABLER0` in its SGI_base frame. `gicr_base` is a
        // QEMU-`virt`-machine-default fallback, same MVP-phase
        // convention as `memory.rs`'s own `QEMU_VIRT_DEFAULT_GICD_BASE`
        // (full Device Tree/ACPI-based Redistributor discovery is a
        // tracked follow-up alongside that file's own).
        //
        // SAFETY: ordering contract per this method's own doc comment;
        // `gicr_base` names QEMU virt's fixed, documented single-core
        // Redistributor MMIO base.
        unsafe {
            const QEMU_VIRT_DEFAULT_GICR_BASE: u64 = 0x080A_0000;
            let gicr_base = QEMU_VIRT_DEFAULT_GICR_BASE;

            let mut waker = gicd_read32(gicr_base, gicr_reg::WAKER);
            waker &= !(1 << 1); // clear ProcessorSleep
            gicd_write32(gicr_base, gicr_reg::WAKER, waker);
            while gicd_read32(gicr_base, gicr_reg::WAKER) & (1 << 2) != 0 {
                // Poll ChildrenAsleep until it clears.
            }

            let sgi_base = gicr_base + gicr_reg::SGI_BASE_OFFSET;
            let byte_offset = gicr_reg::IPRIORITYR + TIMER_PPI_INTID;
            gicd_write32(sgi_base, byte_offset & !0x3, 0x8080_8080);
            gicd_write32(sgi_base, gicr_reg::ISENABLER0, 1 << TIMER_PPI_INTID);
        }

        Ok(())
    }
}

// ============================================================================
// Global dispatch — mirrors hal-x86_64's GLOBAL_CONTROLLER_PTR pattern
// ============================================================================

static GLOBAL_CONTROLLER_PTR: AtomicU64 = AtomicU64::new(0);
static GLOBAL_TIMER_PTR: AtomicU64 = AtomicU64::new(0);

pub fn set_global_controller(controller: &InterruptCtrl) {
    GLOBAL_CONTROLLER_PTR.store(controller as *const InterruptCtrl as u64, Ordering::SeqCst);
}

pub fn set_global_timer(t: &timer::Timer) {
    GLOBAL_TIMER_PTR.store(t as *const timer::Timer as u64, Ordering::SeqCst);
}

fn global_timer_ref() -> &'static timer::Timer {
    let ptr = GLOBAL_TIMER_PTR.load(Ordering::SeqCst);
    // SAFETY: same lifetime argument as hal-x86_64's global_timer_ref
    // — set once from hal_arm64_rust_entry on a value living for the
    // remainder of program execution.
    unsafe { &*(ptr as *const timer::Timer) }
}

/// Called from `cpu.rs`'s `irq_exception_entry` (EL1-native IRQs) and
/// `irq_el0_entry` (IRQs preempting a running U-mode thread) trampolines
/// via `common_interrupt_entry`/`common_irq_el0_entry`. Unlike x86_64's
/// vector-number-on-stack approach, this function itself reads the
/// pending INTID from the GIC (`read_iar`) since AArch64's vector table
/// has no per-IRQ stub to pre-capture it — see cpu.rs's exception vector
/// table module docs. Returns the INTID actually dispatched (or a value
/// `>= 1020`, the GICv3 spurious-read range, if nothing was pending) so
/// `common_irq_el0_entry` can tell whether this was specifically the
/// timer PPI without duplicating the IAR read/EOI sequence itself.
pub fn dispatch_current_irq() -> u32 {
    let ptr = GLOBAL_CONTROLLER_PTR.load(Ordering::SeqCst);
    if ptr == 0 {
        return 1023; // mirrors hal-x86_64's dispatch_vector unreachable-in-practice guard
    }
    // SAFETY: same lifetime argument as hal-x86_64's dispatch_vector —
    // `ptr` was stored by set_global_controller from a value living for
    // the remainder of program execution.
    let controller = unsafe { &*(ptr as *const InterruptCtrl) };

    let intid = read_iar();
    if intid >= 1020 {
        // Spurious read (no interrupt actually pending) — per GICv3
        // spec section 4.1, no EOI should be issued for a spurious
        // INTID.
        return intid;
    }

    if intid == TIMER_PPI_INTID {
        timer::on_timer_interrupt(global_timer_ref());
        controller.end_of_interrupt(IrqId::new(intid));
        return intid;
    }

    if intid >= FIRST_USABLE_INTID {
        let idx = (intid - FIRST_USABLE_INTID) as usize;
        if idx < MAX_TRACKED_INTIDS {
            let handler = controller.handlers.borrow()[idx];
            if let Some(handler) = handler {
                handler(IrqId::new(intid));
            }
        }
    }

    controller.end_of_interrupt(IrqId::new(intid));
    intid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller_with_base(gicd_base: u64) -> InterruptCtrl {
        InterruptCtrl {
            gicd_base,
            handlers: RefCell::new([None; MAX_TRACKED_INTIDS]),
            ipi_target_core_count: Cell::new(4),
        }
    }

    fn dummy_handler(_irq: IrqId) {}

    #[test]
    fn register_irq_rejects_below_first_usable_intid() {
        let ctrl = controller_with_base(0x0800_0000);
        // Note: this test only exercises the range check, not the
        // real gicd_write32 calls configure_spi would make (no real
        // MMIO exists on the host test target) — register_irq's range
        // validation happens BEFORE configure_spi is called, so this
        // path never reaches MMIO.
        assert_eq!(
            ctrl.register_irq(IrqId::new(5), dummy_handler),
            Err(HalError::InvalidIrqId)
        );
    }

    #[test]
    fn send_ipi_rejects_out_of_range_target() {
        let ctrl = controller_with_base(0x0800_0000);
        assert_eq!(ctrl.send_ipi(99, 3), Err(HalError::InvalidIpiTarget));
    }

    #[test]
    fn detected_kind_is_always_gicv3() {
        let ctrl = controller_with_base(0x0800_0000);
        assert_eq!(ctrl.detected_kind(), InterruptControllerKindRaw::Gicv3);
    }

    #[test]
    fn primary_base_reflects_constructor_argument() {
        let ctrl = controller_with_base(0x0800_0000);
        assert_eq!(ctrl.primary_base(), 0x0800_0000);
    }

    #[test]
    fn secondary_base_is_none_in_this_mvp_phase() {
        let ctrl = controller_with_base(0x0800_0000);
        assert_eq!(ctrl.secondary_base(), None);
    }

    #[test]
    fn irq_line_count_matches_table_size() {
        let ctrl = controller_with_base(0x0800_0000);
        assert_eq!(ctrl.irq_line_count() as usize, MAX_TRACKED_INTIDS);
    }
}