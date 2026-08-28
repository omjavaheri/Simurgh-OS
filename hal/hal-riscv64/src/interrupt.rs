//! ============================================================================
//! interrupt.rs — RISC-V (RV64GC)
//!
//! Implements `hal_core::interrupt::InterruptController` for RISC-V,
//! per 01-HAL-Layer.md section 3.4: "یکسان‌سازی... PLIC + CLIC
//! (RISC-V)... پشت یک API واحد".
//!
//! Design:
//!   - PLIC (Platform-Level Interrupt Controller) handles external
//!     interrupts (device IRQs — this project's `register_irq` IRQ
//!     space) — an MMIO-based controller, per the RISC-V PLIC spec.
//!     This is the mechanism `register_irq`/`mask_irq`/`unmask_irq`
//!     target.
//!   - CLIC (Core-Local Interrupt Controller) is an OPTIONAL,
//!     newer-generation extension for fast, vectored, per-core
//!     interrupt handling. Per section 3.4's framing ("PLIC + CLIC"),
//!     both are meant to be unified behind one API — in practice, CLIC
//!     hardware is not yet present on this project's QEMU `virt`
//!     machine target (section 8's acceptance criteria), so this file
//!     implements the PLIC path fully and documents CLIC as a
//!     detected-but-currently-unused capability, mirroring how
//!     hal-arm64/interrupt.rs treats GICv4 features as a strict
//!     superset it does not specifically exploit yet.
//!   - Software interrupts (RISC-V's IPI mechanism) are NOT PLIC-based
//!     at all — they use the SBI IPI extension (an `ecall`, mirroring
//!     timer.rs's SBI-mediated deadline setting), since raising an SSI
//!     (Supervisor Software Interrupt) on another hart requires
//!     M-mode mediation the same way setting `mtimecmp` does.
//! ============================================================================

use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicU64, Ordering};

use hal_core::error::HalError;
use hal_core::interrupt::{InterruptController, IrqHandler, IrqId};
use hal_manifest::raw::InterruptControllerKindRaw;

use crate::timer;

// ============================================================================
// PLIC MMIO register layout (per the RISC-V PLIC spec)
// ============================================================================

mod plic_reg {
    /// Priority register for interrupt source `id`: one 32-bit word
    /// per source, at `PRIORITY_BASE + id * 4`.
    pub const PRIORITY_BASE: u32 = 0x0000;
    /// Pending bits: one bit per source, 32 sources per word.
    pub const PENDING_BASE: u32 = 0x1000;
    /// Enable bits for a given "context" (this project only uses
    /// context 1 — hart 0's S-mode context, per QEMU virt's
    /// conventional PLIC context numbering: context 0 is hart 0
    /// M-mode, context 1 is hart 0 S-mode).
    pub const ENABLE_BASE: u32 = 0x2000;
    pub const ENABLE_CONTEXT_STRIDE: u32 = 0x80;
    /// Per-context priority threshold and claim/complete register.
    pub const CONTEXT_BASE: u32 = 0x20_0000;
    pub const CONTEXT_STRIDE: u32 = 0x1000;
    pub const THRESHOLD_OFFSET: u32 = 0x0000;
    pub const CLAIM_COMPLETE_OFFSET: u32 = 0x0004;
}

/// This project's hart 0 S-mode PLIC context index, per QEMU virt's
/// conventional numbering (module docs above) — a real multi-hart
/// system would need this computed per-hart (context = hart_id * 2 + 1
/// for S-mode, following the same convention), a tracked follow-up
/// alongside cpu.rs's single-hart MVP scope.
const PLIC_CONTEXT: u32 = 1;

/// # Safety
/// `plic_base` must be a valid, mapped PLIC MMIO base address (mapped
/// via `MemoryBootstrap::setup_identity_mapping` with
/// `MapPermissions::DEVICE_MMIO` before this is called — same ordering
/// contract as the other two architectures' interrupt controller MMIO
/// access).
unsafe fn plic_read32(plic_base: u64, offset: u32) -> u32 {
    let ptr = (plic_base + offset as u64) as *const u32;
    // SAFETY: forwarded from this function's own contract; volatile
    // for the same reordering-prevention reason as every other MMIO
    // access in this project.
    unsafe { ptr.read_volatile() }
}

/// # Safety
/// Same contract as `plic_read32`.
unsafe fn plic_write32(plic_base: u64, offset: u32, value: u32) {
    let ptr = (plic_base + offset as u64) as *mut u32;
    // SAFETY: forwarded from this function's own contract.
    unsafe { ptr.write_volatile(value) }
}

// ============================================================================
// SBI IPI extension (software interrupts — see module docs)
// ============================================================================

const SBI_EXT_IPI: usize = 0x735049; // "sPI" per the SBI spec's IPI extension ID
const SBI_IPI_SEND_IPI: usize = 0;

/// Issues the SBI IPI extension's "Send IPI" call, requesting M-mode
/// firmware raise a Supervisor Software Interrupt on every hart in
/// `hart_mask` (a bitmask, per the SBI spec — this project's single-
/// hart MVP phase only ever sets bit 0, but the mechanism itself is
/// mask-based for when multi-hart support lands, mirroring cpu.rs's
/// documented multi-hart follow-up).
///
/// # Safety
/// See `timer.rs`'s `sbi_set_timer` doc comment for the general SBI
/// `ecall` contract — the SBI IPI extension is, unlike TIME, part of
/// SBI's mandatory extension set (every SBI implementation compliant
/// with the spec's base requirements must support it), so this call
/// cannot target unimplemented firmware.
#[cfg(not(target_os = "none"))]
unsafe fn sbi_send_ipi(_hart_mask: u64) {
    // Host (`cargo test`) stub — no SBI firmware off the bare-metal
    // target.
}

#[cfg(target_os = "none")]
unsafe fn sbi_send_ipi(hart_mask: u64) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") SBI_EXT_IPI,
            in("a6") SBI_IPI_SEND_IPI,
            in("a0") hart_mask,
            in("a1") 0usize, // hart_mask_base = 0 (mask covers harts 0-63 directly)
            lateout("a0") _,
            lateout("a1") _,
        );
    }
}

/// First PLIC interrupt source ID available for `register_irq`. Source
/// ID 0 is architecturally reserved ("no interrupt") per the PLIC
/// spec, so usable sources start at 1 — mirroring the other two
/// architectures' FIRST_USABLE_* constants, though here the reserved
/// range is much smaller (just ID 0, vs x86_64's 32 exception vectors
/// or ARM64's 32 SGI+PPI range) since PLIC sources are exclusively
/// external device interrupts with no CPU-exception overlap the way
/// x86_64's IDT or ARM64's VBAR_EL1 table has.
const FIRST_USABLE_SOURCE: u32 = 1;

/// PLIC supports up to 1023 sources on most implementations; sized
/// boundedly for this no_std/no_alloc fixed-table requirement,
/// matching the other two architectures' IRQ table sizing pattern.
const MAX_TRACKED_SOURCES: usize = 512;

// ============================================================================
// InterruptCtrl — InterruptController implementation
// ============================================================================

pub struct InterruptCtrl {
    plic_base: u64,
    handlers: RefCell<[Option<IrqHandler>; MAX_TRACKED_SOURCES]>,
    ipi_target_core_count: Cell<u32>,
}

impl InterruptCtrl {
    /// Constructs the interrupt controller abstraction for the current
    /// hart. `plic_base` is discovered by `memory.rs`'s Device Tree
    /// walk (this file's `plic_base()` accessor, mirroring
    /// hal-arm64/memory.rs's `gicd_base()` pattern).
    pub fn new(plic_base: u64) -> Self {
        Self {
            plic_base,
            handlers: RefCell::new([None; MAX_TRACKED_SOURCES]),
            ipi_target_core_count: Cell::new(1),
        }
    }

    pub fn set_topology(&self, core_count: u32) {
        self.ipi_target_core_count.set(core_count);
    }

    pub fn detected_kind(&self) -> InterruptControllerKindRaw {
        // Per module docs: this file implements the PLIC path; CLIC
        // presence detection (via Device Tree, a tracked follow-up
        // alongside memory.rs's minimal-parsing scope) would refine
        // this to InterruptControllerKindRaw::PlicClic once CLIC is
        // actually exercised — reported as PlicClic unconditionally
        // for now since hal-manifest's raw.rs defines exactly one
        // combined variant for RISC-V (no separate "Plic-only" variant
        // exists), matching that type's own modeling of PLIC+CLIC as
        // inherently paired on this architecture.
        InterruptControllerKindRaw::PlicClic
    }

    pub fn primary_base(&self) -> u64 {
        self.plic_base
    }

    /// This project's CLIC support is detection-only (per module
    /// docs) — no separate CLIC MMIO region is mapped or used, so
    /// `None` accurately reflects this phase's actual usage, mirroring
    /// hal-arm64/interrupt.rs's `secondary_base` reasoning for its own
    /// currently-unused Redistributor region.
    pub fn secondary_base(&self) -> Option<u64> {
        None
    }

    fn set_priority(&self, source: u32, priority: u32) {
        // SAFETY: `self.plic_base` was mapped as DEVICE_MMIO before
        // this instance became reachable — same ordering contract as
        // this file's own `bootstrap_current_core`.
        unsafe {
            plic_write32(self.plic_base, plic_reg::PRIORITY_BASE + source * 4, priority);
        }
    }

    fn set_enabled(&self, source: u32, enabled: bool) {
        let word_index = source / 32;
        let bit = source % 32;
        let offset = plic_reg::ENABLE_BASE + PLIC_CONTEXT * plic_reg::ENABLE_CONTEXT_STRIDE + word_index * 4;

        // SAFETY: same ordering contract as set_priority. Read-modify-
        // write is required since ENABLE is a bitmask register shared
        // across all 32 sources in this word — unlike GICv3's
        // ISENABLER/ICENABLER, which have separate SET/CLEAR registers
        // that avoid needing read-modify-write, PLIC's enable register
        // is a plain bitmask requiring explicit RMW to change one bit
        // without disturbing its siblings.
        unsafe {
            let current = plic_read32(self.plic_base, offset);
            let updated = if enabled { current | (1 << bit) } else { current & !(1 << bit) };
            plic_write32(self.plic_base, offset, updated);
        }
    }
}

impl InterruptController for InterruptCtrl {
    fn register_irq(&self, irq: IrqId, handler: IrqHandler) -> Result<(), HalError> {
        let source = irq.as_u32();
        if source < FIRST_USABLE_SOURCE || source as usize >= MAX_TRACKED_SOURCES {
            return Err(HalError::InvalidIrqId);
        }
        let idx = (source - FIRST_USABLE_SOURCE) as usize;
        let mut handlers = self.handlers.borrow_mut();
        if handlers[idx].is_some() {
            return Err(HalError::IrqAlreadyRegistered);
        }
        handlers[idx] = Some(handler);
        drop(handlers);

        // Priority 1 (lowest non-zero — priority 0 means "never
        // interrupt" per the PLIC spec) for every source in this MVP
        // phase, same "no priority policy yet" scope as
        // hal-arm64/interrupt.rs's configure_spi.
        self.set_priority(source, 1);
        self.set_enabled(source, true);

        Ok(())
    }

    fn unregister_irq(&self, irq: IrqId) {
        let source = irq.as_u32();
        if source >= FIRST_USABLE_SOURCE && (source as usize) < MAX_TRACKED_SOURCES {
            let idx = (source - FIRST_USABLE_SOURCE) as usize;
            self.handlers.borrow_mut()[idx] = None;
            self.set_enabled(source, false);
        }
    }

    fn mask_irq(&self, irq: IrqId) -> Result<(), HalError> {
        let source = irq.as_u32();
        if source < FIRST_USABLE_SOURCE || source as usize >= MAX_TRACKED_SOURCES {
            return Err(HalError::InvalidIrqId);
        }
        // Like GICv3 (and unlike x86_64's Local APIC), PLIC genuinely
        // has a per-source enable bit — masking a specific device IRQ
        // without unregistering its handler is a real, direct
        // operation here.
        self.set_enabled(source, false);
        Ok(())
    }

    fn unmask_irq(&self, irq: IrqId) -> Result<(), HalError> {
        let source = irq.as_u32();
        if source < FIRST_USABLE_SOURCE || source as usize >= MAX_TRACKED_SOURCES {
            return Err(HalError::InvalidIrqId);
        }
        self.set_enabled(source, true);
        Ok(())
    }

    fn send_ipi(&self, target_core: usize, vector: u8) -> Result<(), HalError> {
        if target_core as u32 >= self.ipi_target_core_count.get() {
            return Err(HalError::InvalidIpiTarget);
        }

        // Unlike x86_64 (ICR vector field) or ARM64 (SGI ID 0-15),
        // RISC-V's SBI IPI mechanism carries NO vector/payload at all
        // — it can only raise a generic Supervisor Software Interrupt
        // on the target hart(s); disambiguating WHY the IPI was sent
        // is entirely a software convention the microkernel (layer 2)
        // must establish on its own (e.g. a shared-memory mailbox the
        // SSI handler checks), not something this HAL primitive
        // carries. `vector` is therefore accepted for API symmetry
        // with the other two architectures' `send_ipi` but has no
        // effect on this architecture — documented here rather than
        // silently dropped without explanation.
        let _ = vector;

        let hart_mask: u64 = 1 << target_core;
        // SAFETY: well-defined per the SBI spec for any hart_mask
        // covering harts 0-63, per sbi_send_ipi's own doc comment.
        unsafe {
            sbi_send_ipi(hart_mask);
        }

        Ok(())
    }

    fn irq_line_count(&self) -> u32 {
        MAX_TRACKED_SOURCES as u32
    }

    fn ipi_target_core_count(&self) -> u32 {
        self.ipi_target_core_count.get()
    }

    fn end_of_interrupt(&self, irq: IrqId) {
        // PLIC's "complete" operation: writing the claimed source ID
        // back to the claim/complete register (the SAME register used
        // to claim it — this is how PLIC distinguishes "claim" reads
        // from "complete" writes). Must be the exact ID most recently
        // claimed via read_claim (called from dispatch_current_interrupt
        // below), mirroring GICv3's write_eoi contract.
        let offset = plic_reg::CONTEXT_BASE + PLIC_CONTEXT * plic_reg::CONTEXT_STRIDE + plic_reg::CLAIM_COMPLETE_OFFSET;
        // SAFETY: same ordering contract as set_priority/set_enabled;
        // `irq.as_u32()` is trusted to be the exact ID this same
        // dispatch cycle's `read_claim` returned, per
        // `dispatch_current_interrupt`'s own call ordering.
        unsafe {
            plic_write32(self.plic_base, offset, irq.as_u32());
        }
    }
}

impl InterruptCtrl {
    /// Reads the PLIC claim register: returns the highest-priority
    /// pending, enabled source ID for this context, and simultaneously
    /// marks it as claimed (removing it from the pending set) — the
    /// PLIC spec's combined claim mechanism, analogous to GICv3's
    /// `read_iar` (hal-arm64/interrupt.rs). A return value of 0 means
    /// "no interrupt pending" (source ID 0 is reserved, per
    /// FIRST_USABLE_SOURCE's doc comment).
    fn read_claim(&self) -> u32 {
        let offset = plic_reg::CONTEXT_BASE + PLIC_CONTEXT * plic_reg::CONTEXT_STRIDE + plic_reg::CLAIM_COMPLETE_OFFSET;
        // SAFETY: same ordering contract as this struct's other MMIO
        // accessors.
        unsafe { plic_read32(self.plic_base, offset) }
    }

    /// Performs one-time, per-hart PLIC bring-up: sets this hart's
    /// S-mode context priority threshold to 0 (allowing every non-zero-
    /// priority source through, since this MVP phase does not yet
    /// implement a priority policy — same "everything gets priority 1,
    /// threshold 0" scope as `register_irq`'s `set_priority` call),
    /// and enables both the external-interrupt (`SEIE`) and software-
    /// interrupt (`SSIE`) bits in `sie` (the timer's `STIE` bit is
    /// separately enabled by `timer::enable_timer_interrupt`, per that
    /// file's module docs on why timer enable is a distinct single-bit
    /// operation with no PLIC involvement at all).
    ///
    /// # Safety
    /// Must be called once per hart, after `Cpu::bootstrap_current_core`
    /// (cpu.rs) has already loaded `stvec`, and after the PLIC MMIO
    /// region has been mapped via `MemoryBootstrap::
    /// setup_identity_mapping` with `MapPermissions::DEVICE_MMIO` at
    /// `self.plic_base` — mirrors the other two architectures'
    /// `bootstrap_current_core` ordering contract exactly.
    pub unsafe fn bootstrap_current_core(&self) -> Result<(), HalError> {
        let threshold_offset = plic_reg::CONTEXT_BASE + PLIC_CONTEXT * plic_reg::CONTEXT_STRIDE + plic_reg::THRESHOLD_OFFSET;
        // SAFETY: forwarded from this method's own contract.
        unsafe {
            plic_write32(self.plic_base, threshold_offset, 0);
        }

        const SIE_SEIE_BIT: u64 = 1 << 9; // Supervisor External Interrupt Enable
        const SIE_SSIE_BIT: u64 = 1 << 1; // Supervisor Software Interrupt Enable

        // SAFETY: setting well-defined `sie` bits, same justification
        // as timer.rs's enable_timer_interrupt. Bare-metal only; the
        // host (`cargo test`) build has no `sie` CSR and no test drives
        // per-hart bring-up.
        #[cfg(target_os = "none")]
        unsafe {
            core::arch::asm!(
                "csrs sie, {}",
                in(reg) (SIE_SEIE_BIT | SIE_SSIE_BIT),
            );
        }
        #[cfg(not(target_os = "none"))]
        let _ = (SIE_SEIE_BIT, SIE_SSIE_BIT);

        Ok(())
    }
}

// ============================================================================
// Global dispatch — mirrors the other two architectures' pattern
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
    // SAFETY: same lifetime argument as the other two architectures'
    // global_timer_ref — set once from hal_riscv64_rust_entry on a
    // value living for the remainder of program execution.
    unsafe { &*(ptr as *const timer::Timer) }
}

/// RISC-V standard supervisor interrupt cause codes (per the
/// Privileged spec's `scause` interrupt encoding, section 4.1.8) —
/// these are the `cause_code` values `cpu.rs`'s `common_trap_entry`
/// extracts and passes to this function.
const SCAUSE_SUPERVISOR_SOFTWARE_INTERRUPT: u32 = 1;
const SCAUSE_SUPERVISOR_TIMER_INTERRUPT: u32 = 5;
const SCAUSE_SUPERVISOR_EXTERNAL_INTERRUPT: u32 = 9;

/// Called from `cpu.rs`'s `common_trap_entry` when `scause` indicates
/// an interrupt (top bit set). `cause_code` is one of the
/// SCAUSE_SUPERVISOR_* constants above.
pub fn dispatch_current_interrupt(cause_code: u32) {
    match cause_code {
        SCAUSE_SUPERVISOR_TIMER_INTERRUPT => {
            timer::on_timer_interrupt(global_timer_ref());
            // Per timer.rs's module docs: the timer interrupt has no
            // PLIC involvement and no explicit "complete" step the way
            // an external interrupt does — the interrupt condition
            // clears automatically once a new (later) deadline is set
            // via a subsequent `sbi_set_timer` call (timer.rs's
            // set_oneshot/cancel_oneshot), mirroring how a fired
            // IA32_TSC_DEADLINE/CNTP_CVAL_EL0 deadline does not need a
            // separate "EOI" the way a PLIC/GIC source does.
        }

        SCAUSE_SUPERVISOR_SOFTWARE_INTERRUPT => {
            // Per send_ipi's module docs: this project's SSI handling
            // in this MVP phase has no registered IPI payload/callback
            // mechanism yet (the microkernel, layer 2, is what will
            // eventually consume IPIs meaningfully) — clearing the
            // pending SSI is required before returning, or this trap
            // would immediately re-fire.
            //
            // SAFETY: `sip` (Supervisor Interrupt Pending) bit 1
            // (SSIP) is software-clearable per the RISC-V Privileged
            // spec — clearing it here is the documented way to
            // acknowledge a software interrupt. Bare-metal only.
            #[cfg(target_os = "none")]
            unsafe {
                core::arch::asm!("csrci sip, 0x2");
            }
        }

        SCAUSE_SUPERVISOR_EXTERNAL_INTERRUPT => {
            let ptr = GLOBAL_CONTROLLER_PTR.load(Ordering::SeqCst);
            if ptr == 0 {
                return; // mirrors the other two architectures'
                // unreachable-in-practice guard.
            }
            // SAFETY: same lifetime argument as the other two
            // architectures' dispatch functions.
            let controller = unsafe { &*(ptr as *const InterruptCtrl) };

            let source = controller.read_claim();
            if source == 0 {
                return; // spurious claim (no interrupt actually
                // pending) — per the PLIC spec, no complete should be
                // issued for source 0.
            }

            if source >= FIRST_USABLE_SOURCE && (source as usize) < MAX_TRACKED_SOURCES {
                let idx = (source - FIRST_USABLE_SOURCE) as usize;
                let handler = controller.handlers.borrow()[idx];
                if let Some(handler) = handler {
                    handler(IrqId::new(source));
                }
            }

            controller.end_of_interrupt(IrqId::new(source));
        }

        _ => {
            // An interrupt cause this MVP phase does not expect
            // (e.g. a hypervisor-level interrupt cause, not relevant
            // to this project's S-mode-only kernel) — ignored rather
            // than halting, since an unexpected INTERRUPT (as opposed
            // to an unexpected synchronous EXCEPTION, which cpu.rs's
            // common_trap_entry does halt on) is less likely to
            // indicate a fatal inconsistency and more likely to be a
            // spurious/unused cause code this phase simply has nothing
            // to do for.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn controller_with_base(plic_base: u64) -> InterruptCtrl {
        InterruptCtrl {
            plic_base,
            handlers: RefCell::new([None; MAX_TRACKED_SOURCES]),
            ipi_target_core_count: Cell::new(4),
        }
    }

    fn dummy_handler(_irq: IrqId) {}

    #[test]
    fn register_irq_rejects_source_zero() {
        let ctrl = controller_with_base(0x0c00_0000);
        assert_eq!(
            ctrl.register_irq(IrqId::new(0), dummy_handler),
            Err(HalError::InvalidIrqId)
        );
    }

    #[test]
    fn send_ipi_rejects_out_of_range_target() {
        let ctrl = controller_with_base(0x0c00_0000);
        assert_eq!(ctrl.send_ipi(99, 0), Err(HalError::InvalidIpiTarget));
    }

    #[test]
    fn detected_kind_is_always_plic_clic() {
        let ctrl = controller_with_base(0x0c00_0000);
        assert_eq!(ctrl.detected_kind(), InterruptControllerKindRaw::PlicClic);
    }

    #[test]
    fn primary_base_reflects_constructor_argument() {
        let ctrl = controller_with_base(0x0c00_0000);
        assert_eq!(ctrl.primary_base(), 0x0c00_0000);
    }

    #[test]
    fn secondary_base_is_none_in_this_mvp_phase() {
        let ctrl = controller_with_base(0x0c00_0000);
        assert_eq!(ctrl.secondary_base(), None);
    }

    #[test]
    fn scause_cause_codes_match_riscv_spec() {
        assert_eq!(SCAUSE_SUPERVISOR_SOFTWARE_INTERRUPT, 1);
        assert_eq!(SCAUSE_SUPERVISOR_TIMER_INTERRUPT, 5);
        assert_eq!(SCAUSE_SUPERVISOR_EXTERNAL_INTERRUPT, 9);
    }
}