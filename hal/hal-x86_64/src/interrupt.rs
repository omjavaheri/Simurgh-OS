//! ============================================================================
//! interrupt.rs — x86_64
//!
//! Implements `hal_core::interrupt::InterruptController` for x86_64,
//! per 01-HAL-Layer.md section 3.4: "یکسان‌سازی APIC/x2APIC (x86_64)...
//! پشت یک API واحد".
//!
//! Design:
//!   - x2APIC (MSR-based, no MMIO) is used whenever CPUID reports it
//!     present — simpler and faster than xAPIC's MMIO register access,
//!     and required for systems with more than 255 cores (not relevant
//!     to this MVP's QEMU targets, but the correct default regardless).
//!   - xAPIC (MMIO-based, at the physical base reported by
//!     IA32_APIC_BASE MSR) is the fallback for CPUs without x2APIC.
//!   - Vector 32 is reserved for the Local APIC Timer (TSC-deadline
//!     mode, per timer.rs's module docs on APIC/timer sequencing).
//!     Vectors 33-255 are available for `register_irq`.
//!
//! Coordination with cpu.rs: the low-level ISR trampoline
//! (`isr_common_trampoline`, defined via `global_asm!` in cpu.rs) calls
//! `common_interrupt_entry`, which calls `dispatch_vector` (this file)
//! with the fired vector number. `dispatch_vector` looks up this
//! module's registered-handler table and invokes the matching
//! `hal_core::interrupt::IrqHandler`.
//!
//! Coordination with timer.rs: vector 32's dispatch entry calls
//! `timer::on_timer_interrupt` directly (not through the general
//! `register_irq` table), since the timer's callback plumbing
//! (`TimerCallback`, a bare `fn()`) is a different shape from
//! `IrqHandler`'s `fn(IrqId)` — see `dispatch_vector`'s doc comment.
//! ============================================================================

use core::arch::x86_64::__cpuid_count;
use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicU64, Ordering};

use hal_core::error::HalError;
use hal_core::interrupt::{InterruptController, IrqHandler, IrqId};
use hal_manifest::raw::InterruptControllerKindRaw;

use crate::timer;

// ============================================================================
// CPUID-based x2APIC detection (mirrors cpu.rs / timer.rs's
// CpuidSource split for testability, per section 8.4)
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
struct CpuidResult {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

trait CpuidSource {
    fn cpuid(&self, leaf: u32, subleaf: u32) -> CpuidResult;
}

struct RealCpuid;

impl CpuidSource for RealCpuid {
    fn cpuid(&self, leaf: u32, subleaf: u32) -> CpuidResult {
        // SAFETY: CPUID is unconditionally available in x86_64 long
        // mode (same reasoning as cpu.rs's RealCpuid::cpuid).
        let r = unsafe { __cpuid_count(leaf, subleaf) };
        CpuidResult { eax: r.eax, ebx: r.ebx, ecx: r.ecx, edx: r.edx }
    }
}

/// CPUID leaf 1, ECX bit 21: x2APIC present.
fn detect_x2apic(cpuid: &impl CpuidSource) -> bool {
    let leaf1 = cpuid.cpuid(1, 0);
    leaf1.ecx & (1 << 21) != 0
}

/// CPUID leaf 1, EBX bits 31:24: this core's own initial (x)APIC ID —
/// same field `cpu.rs`'s own `read_initial_apic_id` reads for
/// `Cpu::current_core_id`, duplicated here (not made `pub(crate)` and
/// reused) for the same small-self-contained-helper reasoning
/// `hal-arm64::peripheral`'s own module doc comment gives for its BAR0
/// probe: this file already carries its own local `CpuidSource`
/// machinery for `detect_x2apic`, so a second tiny leaf-1 reader costs
/// less than a cross-module visibility change.
fn initial_apic_id(cpuid: &impl CpuidSource) -> u32 {
    let leaf1 = cpuid.cpuid(1, 0);
    leaf1.ebx >> 24
}

// ============================================================================
// MSR access (x2APIC register access, and reading IA32_APIC_BASE to
// locate the xAPIC MMIO window)
// ============================================================================

const IA32_APIC_BASE_MSR: u32 = 0x1B;

/// Base MSR address for x2APIC registers (Intel SDM Vol. 3A, Table
/// 10-6): register `r` (the same offset used for xAPIC MMIO, e.g. 0x30
/// for EOI, 0x300 for ICR-low) is read/written via MSR
/// `X2APIC_MSR_BASE + (r >> 4)`.
const X2APIC_MSR_BASE: u32 = 0x800;

fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: reading an MSR that exists on this CPU (all MSRs
    // referenced in this file are either architectural, per the Intel
    // SDM, or gated behind the x2APIC/APIC feature checks that select
    // which code path executes) has no additional preconditions beyond
    // Ring 0 execution, which this crate always runs at.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
        );
    }
    ((high as u64) << 32) | low as u64
}

/// # Safety
/// See `timer.rs`'s `wrmsr` doc comment for the general contract.
/// Every call site in this file targets either `IA32_APIC_BASE_MSR`
/// (writing back its own previously-read value, only to set the
/// enable bit) or an x2APIC register MSR, both documented safe to
/// write with the values this file constructs, per the Intel SDM's
/// APIC programming chapter (10.12).
unsafe fn wrmsr(msr: u32, value: u64) {
    let low = value as u32;
    let high = (value >> 32) as u32;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") low,
            in("edx") high,
        );
    }
}

// ============================================================================
// xAPIC MMIO register access
// ============================================================================

/// Reads the xAPIC MMIO base physical address from IA32_APIC_BASE
/// (bits 12-35), masking off the low 12 bits' flag fields (BSP flag,
/// x2APIC enable, global enable).
fn xapic_mmio_base() -> u64 {
    rdmsr(IA32_APIC_BASE_MSR) & 0x000F_FFFF_FFFF_F000
}

/// Reads a 32-bit xAPIC register at MMIO offset `offset` from
/// `mmio_base`.
///
/// # Safety
/// `mmio_base` must be a valid, mapped xAPIC MMIO base address (per
/// `hal_core::memory::MemoryBootstrap::setup_identity_mapping` having
/// already mapped it with `MapPermissions::DEVICE_MMIO`, per section
/// 3.2/3.4's coordination — `InterruptCtrl::bootstrap_current_core`
/// below is responsible for ensuring this mapping exists before any
/// xAPIC register access).
unsafe fn xapic_read(mmio_base: u64, offset: u32) -> u32 {
    let ptr = (mmio_base + offset as u64) as *const u32;
    // SAFETY: forwarded from this function's own contract; xAPIC MMIO
    // registers are volatile hardware state and must be accessed with
    // `read_volatile` to prevent the compiler from reordering or
    // eliding what looks like a redundant load.
    unsafe { ptr.read_volatile() }
}

/// # Safety
/// Same contract as `xapic_read`.
unsafe fn xapic_write(mmio_base: u64, offset: u32, value: u32) {
    let ptr = (mmio_base + offset as u64) as *mut u32;
    // SAFETY: forwarded from this function's own contract;
    // `write_volatile` for the same reordering-prevention reason as
    // `xapic_read`.
    unsafe {
        ptr.write_volatile(value);
    }
}

// xAPIC MMIO register offsets relevant to this file (Intel SDM Vol.
// 3A, Table 10-1).
mod xapic_reg {
    pub const ID: u32 = 0x20;
    pub const EOI: u32 = 0xB0;
    pub const SPURIOUS_INTERRUPT_VECTOR: u32 = 0xF0;
    pub const LVT_TIMER: u32 = 0x320;
    pub const ICR_LOW: u32 = 0x300;
    pub const ICR_HIGH: u32 = 0x310;
    /// Timer Initial Count Register — writing this starts the timer
    /// counting down (in whatever mode LVT_TIMER's own bits selected);
    /// also this project's fallback one-shot arming mechanism for CPUs
    /// TCG reports as lacking TSC-deadline mode (see timer.rs's own
    /// module docs on why this fallback exists).
    pub const INITIAL_COUNT: u32 = 0x380;
    /// Timer Current Count Register (read-only) — counts down from
    /// `INITIAL_COUNT` to 0 at the rate `DIVIDE_CONFIGURATION`
    /// selects; used both to calibrate that rate against a known clock
    /// (this project uses the TSC, per timer.rs) and, in principle, to
    /// read remaining time on an armed deadline.
    pub const CURRENT_COUNT: u32 = 0x390;
    /// Divide Configuration Register — selects how much to divide the
    /// bus clock by before it reaches the timer's own counter (Intel
    /// SDM Table 10-10). This project fixes it at divide-by-16 (encoded
    /// value `0b0011`) for the fallback one-shot path — see timer.rs's
    /// own calibration doc comment for why the EXACT bus-clock
    /// frequency this implies is irrelevant (calibration measures the
    /// resulting tick rate directly against the TSC, so the choice only
    /// affects calibration/counter GRANULARITY, not correctness).
    pub const DIVIDE_CONFIGURATION: u32 = 0x3E0;
}

// x2APIC MSR register indices, derived from the same offsets above per
// X2APIC_MSR_BASE's doc comment (`X2APIC_MSR_BASE + (offset >> 4)`).
mod x2apic_reg {
    pub const ID: u32 = super::X2APIC_MSR_BASE + (super::xapic_reg::ID >> 4);
    pub const EOI: u32 = super::X2APIC_MSR_BASE + (super::xapic_reg::EOI >> 4);
    pub const SPURIOUS_INTERRUPT_VECTOR: u32 =
        super::X2APIC_MSR_BASE + (super::xapic_reg::SPURIOUS_INTERRUPT_VECTOR >> 4);
    pub const LVT_TIMER: u32 = super::X2APIC_MSR_BASE + (super::xapic_reg::LVT_TIMER >> 4);
    /// x2APIC merges ICR-low/high into a single 64-bit MSR (unlike
    /// xAPIC's two separate 32-bit MMIO registers) — Intel SDM 10.12.9.
    pub const ICR: u32 = super::X2APIC_MSR_BASE + 0x30;
    pub const INITIAL_COUNT: u32 = super::X2APIC_MSR_BASE + (super::xapic_reg::INITIAL_COUNT >> 4);
    pub const CURRENT_COUNT: u32 = super::X2APIC_MSR_BASE + (super::xapic_reg::CURRENT_COUNT >> 4);
    pub const DIVIDE_CONFIGURATION: u32 =
        super::X2APIC_MSR_BASE + (super::xapic_reg::DIVIDE_CONFIGURATION >> 4);
}

/// Vector reserved for the Local APIC Timer (TSC-deadline mode), per
/// this file's module docs. Chosen as the first usable vector after
/// the 32 CPU-exception vectors (0-31, per cpu.rs's IDT layout).
pub(crate) const TIMER_VECTOR: u8 = 32;

/// First vector available for `register_irq`. Vectors below this are
/// reserved: 0-31 for CPU exceptions (cpu.rs), 32 for the timer (this
/// file).
pub(crate) const FIRST_USABLE_IRQ_VECTOR: u8 = 33;

const IRQ_TABLE_SIZE: usize = 256 - FIRST_USABLE_IRQ_VECTOR as usize;

/// Which underlying register access mode is active. Chosen once at
/// construction (`InterruptCtrl::new`) and never changed afterward —
/// switching between xAPIC and x2APIC mid-boot is not a scenario this
/// project's hardware targets require.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApicMode {
    Xapic { mmio_base: u64 },
    X2apic,
}

// ============================================================================
// InterruptCtrl — InterruptController implementation
// ============================================================================

pub struct InterruptCtrl {
    mode: ApicMode,
    /// Registered handlers, indexed by `vector - FIRST_USABLE_IRQ_VECTOR`.
    /// `RefCell` (not `Cell`) because `IrqHandler` (a `fn` pointer) is
    /// `Copy`, but the table itself needs interior mutability across
    /// `&self` calls exactly like cpu.rs's `IDT` needs `static mut` —
    /// here scoped per-instance instead, since `InterruptCtrl` is a
    /// single per-core value rather than a single global table.
    handlers: RefCell<[Option<IrqHandler>; IRQ_TABLE_SIZE]>,
    ipi_target_core_count: Cell<u32>,
}

impl InterruptCtrl {
    /// Constructs the interrupt controller abstraction for the current
    /// core. Detects x2APIC vs xAPIC via CPUID; for xAPIC, reads the
    /// MMIO base from IA32_APIC_BASE but does NOT yet map it into the
    /// page tables — that mapping is established by
    /// `bootstrap_current_core` below, which has access to the
    /// `Memory` value needed to call
    /// `MemoryBootstrap::setup_identity_mapping` (section 3.2).
    pub fn new() -> Self {
        let cpuid = RealCpuid;
        let mode = if detect_x2apic(&cpuid) {
            ApicMode::X2apic
        } else {
            ApicMode::Xapic { mmio_base: xapic_mmio_base() }
        };

        Self {
            mode,
            handlers: RefCell::new([None; IRQ_TABLE_SIZE]),
            // Populated by `set_topology` once cpu.rs's core-count
            // discovery is available (currently 1 for this MVP's
            // single-core QEMU target, per cpu.rs's
            // `detected_core_count` doc comment on its own MADT
            // follow-up).
            ipi_target_core_count: Cell::new(1),
        }
    }

    /// Updates the IPI target core count once real topology is known
    /// (called from `hal_x86_64_rust_entry`, lib.rs, after `Cpu`'s
    /// core count is available — mirrors `Cpu::mark_iommu_capable`'s
    /// cross-module data flow pattern from cpu.rs).
    pub fn set_topology(&self, core_count: u32) {
        self.ipi_target_core_count.set(core_count);
    }

    fn read_reg(&self, xapic_offset: u32, x2apic_msr: u32) -> u32 {
        match self.mode {
            // SAFETY: `mmio_base` was established at construction from
            // IA32_APIC_BASE and mapped by `bootstrap_current_core`
            // before any register access is expected to occur — the
            // same ordering contract documented on that method.
            ApicMode::Xapic { mmio_base } => unsafe { xapic_read(mmio_base, xapic_offset) },
            ApicMode::X2apic => rdmsr(x2apic_msr) as u32,
        }
    }

    fn write_reg(&self, xapic_offset: u32, x2apic_msr: u32, value: u32) {
        match self.mode {
            // SAFETY: same ordering contract as `read_reg`.
            ApicMode::Xapic { mmio_base } => unsafe { xapic_write(mmio_base, xapic_offset, value) },
            // SAFETY: writing an x2APIC register MSR with a
            // caller-constructed value from this file's own register
            // helpers, per `wrmsr`'s doc comment.
            ApicMode::X2apic => unsafe { wrmsr(x2apic_msr, value as u64) },
        }
    }

    /// Sends the Interrupt Command Register write that actually
    /// triggers an IPI. x2APIC uses one 64-bit MSR write; xAPIC
    /// requires writing ICR-high (destination) BEFORE ICR-low
    /// (command+trigger), per Intel SDM 10.6.1 — writing ICR-low is
    /// what actually dispatches the IPI, so it must be written last.
    fn write_icr(&self, destination_apic_id: u32, low_bits: u32) {
        match self.mode {
            ApicMode::Xapic { mmio_base } => {
                // SAFETY: ordering contract per `read_reg`/`write_reg`;
                // ICR-high must be written before ICR-low per the SDM
                // ordering requirement stated above.
                unsafe {
                    xapic_write(mmio_base, xapic_reg::ICR_HIGH, destination_apic_id << 24);
                    xapic_write(mmio_base, xapic_reg::ICR_LOW, low_bits);
                }
            }
            ApicMode::X2apic => {
                let value = ((destination_apic_id as u64) << 32) | low_bits as u64;
                // SAFETY: x2APIC's merged ICR MSR write per
                // `x2apic_reg::ICR`'s doc comment; well-defined per the
                // SDM for any destination/command encoding this file
                // constructs.
                unsafe {
                    wrmsr(x2apic_reg::ICR, value);
                }
            }
        }
    }

    /// Reports which `InterruptControllerKindRaw` this instance
    /// detected, for `built_hardware_manifest` (memory.rs).
    pub fn detected_kind(&self) -> InterruptControllerKindRaw {
        match self.mode {
            ApicMode::Xapic { .. } => InterruptControllerKindRaw::ApicXapic,
            ApicMode::X2apic => InterruptControllerKindRaw::ApicX2apic,
        }
    }

    /// Primary MMIO/MSR base, for `InterruptControllerInfoRaw::primary_base`
    /// (hal-manifest raw.rs). For x2APIC (MSR-based, no MMIO window),
    /// this is 0 per that field's doc comment allowing "unused for
    /// MSR-based x2APIC".
    pub fn primary_base(&self) -> u64 {
        match self.mode {
            ApicMode::Xapic { mmio_base } => mmio_base,
            ApicMode::X2apic => 0,
        }
    }

    /// x86_64's APIC has no secondary MMIO region analogous to ARM64
    /// GIC's distributor+redistributor split (hal-manifest raw.rs's
    /// `InterruptControllerInfoRaw::secondary_base` doc comment) —
    /// always `None` here.
    pub fn secondary_base(&self) -> Option<u64> {
        None
    }
}

impl Default for InterruptCtrl {
    fn default() -> Self {
        Self::new()
    }
}

impl InterruptController for InterruptCtrl {
    fn register_irq(&self, irq: IrqId, handler: IrqHandler) -> Result<(), HalError> {
        let vector = irq.as_u32();
        if vector < FIRST_USABLE_IRQ_VECTOR as u32 || vector > 255 {
            return Err(HalError::InvalidIrqId);
        }
        let idx = (vector - FIRST_USABLE_IRQ_VECTOR as u32) as usize;
        let mut handlers = self.handlers.borrow_mut();
        if handlers[idx].is_some() {
            return Err(HalError::IrqAlreadyRegistered);
        }
        handlers[idx] = Some(handler);
        Ok(())
    }

    fn unregister_irq(&self, irq: IrqId) {
        let vector = irq.as_u32();
        if vector >= FIRST_USABLE_IRQ_VECTOR as u32 && vector <= 255 {
            let idx = (vector - FIRST_USABLE_IRQ_VECTOR as u32) as usize;
            self.handlers.borrow_mut()[idx] = None;
        }
    }

    fn mask_irq(&self, irq: IrqId) -> Result<(), HalError> {
        // Per-vector masking on APIC is done at the DEVICE side (e.g.
        // an I/O APIC redirection table entry's mask bit, owned by the
        // layer 3 Device Manager per 03-Kernel-Subsystems-Layer.md
        // section 2.1, not by the Local APIC this file abstracts) —
        // the Local APIC itself has no per-arbitrary-vector mask
        // register outside of the LVT entries (Timer, LINT0/1, etc.),
        // which are not general-purpose IRQ lines. This method
        // therefore validates the vector range (consistent with
        // register_irq's validation) but has no hardware action to
        // perform at the Local APIC level for a general device IRQ —
        // full I/O APIC redirection table masking is a tracked
        // follow-up once the layer 3 Device Manager's I/O APIC
        // programming exists.
        let vector = irq.as_u32();
        if vector < FIRST_USABLE_IRQ_VECTOR as u32 || vector > 255 {
            return Err(HalError::InvalidIrqId);
        }
        Ok(())
    }

    fn unmask_irq(&self, irq: IrqId) -> Result<(), HalError> {
        // See `mask_irq`'s doc comment — same scope limitation applies
        // symmetrically.
        let vector = irq.as_u32();
        if vector < FIRST_USABLE_IRQ_VECTOR as u32 || vector > 255 {
            return Err(HalError::InvalidIrqId);
        }
        Ok(())
    }

    fn send_ipi(&self, target_core: usize, vector: u8) -> Result<(), HalError> {
        if target_core as u32 >= self.ipi_target_core_count.get() {
            return Err(HalError::InvalidIpiTarget);
        }

        // ICR-low bit layout (Intel SDM 10.6.1): bits 0-7 = vector,
        // bits 8-10 = delivery mode (000 = Fixed), bit 14 = level
        // (1 = assert), bits 18-19 = destination shorthand
        // (00 = no shorthand, use destination field).
        let icr_low = vector as u32 | (1 << 14);

        // `target_core` here is used directly as the destination APIC
        // ID — this MVP phase assumes a 1:1 core-index-to-APIC-ID
        // mapping (true for QEMU's default core enumeration, per
        // section 8's acceptance criteria). A real MADT-derived
        // core-index-to-APIC-ID table is a tracked follow-up alongside
        // cpu.rs's own `detected_core_count` MADT follow-up.
        self.write_icr(target_core as u32, icr_low);

        Ok(())
    }

    fn irq_line_count(&self) -> u32 {
        IRQ_TABLE_SIZE as u32
    }

    fn ipi_target_core_count(&self) -> u32 {
        self.ipi_target_core_count.get()
    }

    fn end_of_interrupt(&self, _irq: IrqId) {
        self.write_reg(xapic_reg::EOI, x2apic_reg::EOI, 0);
    }

    /// x86_64's own override of `InterruptController::msi_message`'s
    /// default `None` — the only architecture this project targets with
    /// a real message-signaled-interrupt path (Intel SDM Vol. 3A
    /// §10.11). Encodes the STANDARD (non-remappable, non-x2APIC-
    /// extended-destination) MSI/MSI-X address/data format, which every
    /// destination APIC ID this MVP ever targets (0, this single-core
    /// phase's only core — see `send_ipi`'s own "1:1 core-index-to-
    /// APIC-ID" caveat, identical assumption here) fits within: the
    /// address's own 8-bit destination field.
    ///
    /// Message Address (Intel SDM Table 10-1, "Interrupt Address
    /// Redirection Table"): bits 31:20 fixed `0xFEE`, bits 19:12 =
    /// destination APIC ID, bit 3 = Redirection Hint (0 = fixed
    /// destination, not lowest-priority), bit 2 = Destination Mode
    /// (0 = physical).
    ///
    /// Message Data (Intel SDM Table 10-11): bits 7:0 = vector, bits
    /// 10:8 = delivery mode (000 = Fixed), bit 15 = trigger mode
    /// (0 = edge — MSI/MSI-X interrupts are always edge-triggered by
    /// construction, spec-mandated, unlike legacy INTx's level-
    /// triggered line).
    fn msi_message(&self, irq: IrqId) -> Option<(u64, u32)> {
        let vector = irq.as_u32();
        if vector < FIRST_USABLE_IRQ_VECTOR as u32 || vector > 255 {
            return None;
        }
        let dest_apic_id = initial_apic_id(&RealCpuid);
        let address = 0xFEE0_0000u64 | ((dest_apic_id as u64) << 12);
        let data = vector; // delivery mode Fixed (000) and edge trigger are both the all-zero encoding.
        Some((address, data))
    }

    // Note: `bootstrap_current_core` per hal_core::cpu::CpuAbstraction
    // is a DIFFERENT trait (this file implements
    // hal_core::interrupt::InterruptController only) — this struct's
    // own per-core APIC bring-up is exposed as the inherent method
    // below, called explicitly from lib.rs's hal_x86_64_rust_entry
    // alongside cpu.rs's Cpu::bootstrap_current_core, rather than
    // being part of the InterruptController trait surface itself
    // (hal-core's trait, being architecture-independent, does not
    // declare a bootstrap method — only CpuAbstraction does, per
    // section 3.1's framing of "per-core bootstrap" as specifically a
    // CPU Abstraction responsibility).
}

impl InterruptCtrl {
    /// Performs one-time, per-core Local APIC bring-up: enables the
    /// APIC (both the xAPIC/x2APIC enable bit in IA32_APIC_BASE and
    /// the software-enable bit in the Spurious Interrupt Vector
    /// Register), and configures the LVT Timer entry so `timer.rs`'s
    /// `Timer::set_oneshot` calls actually deliver an interrupt — see
    /// timer.rs's `Timer::new` doc comment on this exact ordering
    /// requirement.
    ///
    /// `tsc_deadline_capable` selects WHICH LVT Timer mode: TSC-
    /// deadline (Intel SDM Table 10-6) if the CPU supports it, or
    /// plain one-shot count mode otherwise — a REAL, QEMU-confirmed
    /// gap this session's preemption work found: TCG (this project's
    /// only tested software-emulation accelerator, no KVM/WHPX
    /// available in this environment) does not implement TSC-deadline
    /// mode under ANY CPU model (confirmed via QEMU's own diagnostic:
    /// `"TCG doesn't support requested feature: CPUID[eax=01h].ECX.
    /// tsc-deadline"`), so this fallback is not a hypothetical —
    /// timer.rs's own `Timer::set_oneshot` doc comment has the full
    /// story of the calibrated one-shot mechanism this enables.
    /// `DIVIDE_CONFIGURATION` is set to divide-by-16 unconditionally
    /// (harmless in TSC-deadline mode, where it goes unused) so the
    /// fallback path is ready the instant `set_oneshot` first needs it.
    ///
    /// # Safety
    /// Must be called once per core, after `Cpu::bootstrap_current_core`
    /// (cpu.rs) has already loaded the IDT (so `TIMER_VECTOR`'s gate
    /// is valid before this method could cause it to fire), and — if
    /// operating in xAPIC mode — after the xAPIC MMIO region has been
    /// mapped via `MemoryBootstrap::setup_identity_mapping` with
    /// `MapPermissions::DEVICE_MMIO` at this instance's `primary_base()`.
    pub unsafe fn bootstrap_current_core(&self, tsc_deadline_capable: bool) -> Result<(), HalError> {
        // Ensure the APIC enable bit is set in IA32_APIC_BASE. On
        // every target this project boots on (UEFI-handed-off long
        // mode), the APIC is already globally enabled by firmware —
        // this is a defensive re-assertion, not a cold bring-up from a
        // disabled state.
        let apic_base = rdmsr(IA32_APIC_BASE_MSR);
        const APIC_GLOBAL_ENABLE: u64 = 1 << 11;
        const X2APIC_ENABLE: u64 = 1 << 10;
        let desired = match self.mode {
            ApicMode::Xapic { .. } => apic_base | APIC_GLOBAL_ENABLE,
            ApicMode::X2apic => apic_base | APIC_GLOBAL_ENABLE | X2APIC_ENABLE,
        };
        if desired != apic_base {
            // SAFETY: re-writing IA32_APIC_BASE with only the
            // enable bit(s) changed, base address field untouched —
            // well-defined per Intel SDM 10.12.1.
            unsafe {
                wrmsr(IA32_APIC_BASE_MSR, desired);
            }
        }

        // Software-enable the APIC via the Spurious Interrupt Vector
        // Register: bit 8 = APIC software enable, bits 0-7 = spurious
        // vector (set to 0xFF, the conventional choice avoiding
        // collision with any real exception/IRQ vector).
        const APIC_SOFTWARE_ENABLE: u32 = 1 << 8;
        const SPURIOUS_VECTOR: u32 = 0xFF;
        self.write_reg(
            xapic_reg::SPURIOUS_INTERRUPT_VECTOR,
            x2apic_reg::SPURIOUS_INTERRUPT_VECTOR,
            APIC_SOFTWARE_ENABLE | SPURIOUS_VECTOR,
        );

        // Configure LVT Timer: bits 0-7 = vector, bits 18-17 = timer
        // mode (10 = TSC-deadline, per Intel SDM Table 10-6, encoded as
        // bit 18 set; 00 = one-shot count mode, no bits beyond the
        // vector) — see this method's own doc comment for why the
        // choice is conditional.
        const LVT_TIMER_MODE_TSC_DEADLINE: u32 = 1 << 18;
        let lvt_timer_value = if tsc_deadline_capable {
            LVT_TIMER_MODE_TSC_DEADLINE | TIMER_VECTOR as u32
        } else {
            TIMER_VECTOR as u32
        };
        self.write_reg(xapic_reg::LVT_TIMER, x2apic_reg::LVT_TIMER, lvt_timer_value);

        // Divide-by-16 (encoded value `0b0011`, Intel SDM Table 10-10) —
        // only meaningful for one-shot count mode, but harmless to set
        // unconditionally (unused in TSC-deadline mode).
        const DIVIDE_BY_16: u32 = 0b0011;
        self.write_reg(
            xapic_reg::DIVIDE_CONFIGURATION,
            x2apic_reg::DIVIDE_CONFIGURATION,
            DIVIDE_BY_16,
        );

        Ok(())
    }

    /// Masks or unmasks the LVT Timer entry (bit 16) without touching
    /// its vector/mode bits — used by timer.rs's calibration routine to
    /// keep a stray interrupt from being TAKEN mid-calibration (belt-
    /// and-suspenders: IF is already clear throughout syscall handling,
    /// where calibration first runs, but this does not rely on that).
    pub(crate) fn set_lvt_timer_masked(&self, masked: bool) {
        const LVT_MASKED: u32 = 1 << 16;
        let current = self.read_reg(xapic_reg::LVT_TIMER, x2apic_reg::LVT_TIMER);
        let next = if masked { current | LVT_MASKED } else { current & !LVT_MASKED };
        self.write_reg(xapic_reg::LVT_TIMER, x2apic_reg::LVT_TIMER, next);
    }

    /// Writes the Timer Initial Count Register — in one-shot count
    /// mode (`bootstrap_current_core`'s fallback LVT Timer
    /// configuration), this both ARMS a countdown of `ticks` (at
    /// whatever rate `DIVIDE_CONFIGURATION` selects) and, written as 0,
    /// is this project's cancel mechanism (a 0 initial count stops the
    /// timer without ever reaching 0 "for real" — Intel SDM 10.5.4).
    /// Also used directly by timer.rs's own calibration routine (armed
    /// with `u32::MAX`, measured against the TSC).
    pub(crate) fn write_initial_count(&self, ticks: u32) {
        self.write_reg(xapic_reg::INITIAL_COUNT, x2apic_reg::INITIAL_COUNT, ticks);
    }

    /// Reads the Timer Current Count Register — the countdown's current
    /// value, used by timer.rs's calibration routine to measure how far
    /// `INITIAL_COUNT` counted down over a KNOWN (TSC-measured)
    /// duration.
    pub(crate) fn read_current_count(&self) -> u32 {
        self.read_reg(xapic_reg::CURRENT_COUNT, x2apic_reg::CURRENT_COUNT)
    }
}

// ============================================================================
// Global dispatch table access
//
// `dispatch_vector` is called from cpu.rs's `common_interrupt_entry`
// (the low-level ISR trampoline's Rust-side counterpart). It needs
// access to the SAME `InterruptCtrl` instance `hal_x86_64_rust_entry`
// constructed — stored here as a global, exactly mirroring cpu.rs's
// `static mut IDT` pattern for the same "single per-core instance,
// written once at boot, read during interrupt handling" shape.
// ============================================================================

/// Holds the address of the live `InterruptCtrl` instance, set once by
/// `set_global_controller` (called from `hal_x86_64_rust_entry` right
/// after constructing `X86_64Hal`). `AtomicU64` (not a raw `static mut
/// *mut InterruptCtrl`) so `dispatch_vector` can read it with a defined
/// memory ordering even though, per this MVP's single-core scope, no
/// actual cross-core race is currently possible — this keeps the
/// mechanism correct without changes once multi-core support
/// (cpu.rs's tracked MADT follow-up) lands.
static GLOBAL_CONTROLLER_PTR: AtomicU64 = AtomicU64::new(0);

/// Registers `controller` as the target of `dispatch_vector` calls.
/// Must be called exactly once, from `hal_x86_64_rust_entry`, before
/// interrupts are enabled on this core.
pub fn set_global_controller(controller: &InterruptCtrl) {
    GLOBAL_CONTROLLER_PTR.store(controller as *const InterruptCtrl as u64, Ordering::SeqCst);
}

/// Returns the live `InterruptCtrl` instance `set_global_controller`
/// registered, or `None` if called before that has happened. Shared by
/// `dispatch_vector` below and timer.rs's own fallback one-shot path
/// (`Timer::set_oneshot`'s calibrated-LAPIC-count branch), both of
/// which need to reach the SAME per-core controller instance from
/// outside this module.
pub(crate) fn global_controller() -> Option<&'static InterruptCtrl> {
    let ptr = GLOBAL_CONTROLLER_PTR.load(Ordering::SeqCst);
    if ptr == 0 {
        return None;
    }
    // SAFETY: `ptr` was stored by `set_global_controller` from a valid
    // `&InterruptCtrl` whose referent (`X86_64Hal::interrupt`, living in
    // `hal_x86_64_rust_entry`'s own `.bss` static storage — see that
    // function's own doc comment) lives for the remainder of program
    // execution — no code in this crate ever moves or drops that value
    // out from under this pointer.
    Some(unsafe { &*(ptr as *const InterruptCtrl) })
}

/// Called by `cpu.rs`'s `common_interrupt_entry` with the vector number
/// the CPU's ISR stub captured. Special-cases `TIMER_VECTOR` (routing
/// to `timer::on_timer_interrupt`, since `TimerCallback`'s `fn()` shape
/// differs from `IrqHandler`'s `fn(IrqId)`, per this file's module
/// docs); otherwise looks up and invokes the registered `IrqHandler`
/// for that vector, then always signals end-of-interrupt regardless of
/// whether a handler was found (a spurious/unregistered vector still
/// needs EOI so the APIC does not stall future interrupt delivery).
pub fn dispatch_vector(vector: u8) {
    // No controller registered yet — this can only happen if an
    // interrupt somehow fires before `set_global_controller` ran, which
    // should be unreachable given interrupts remain hardware-masked
    // until after boot sequencing completes (boot.S never issues `sti`,
    // and neither does any code in this crate prior to
    // `hal_x86_64_rust_entry` finishing setup).
    let Some(controller) = global_controller() else {
        return;
    };

    if vector == TIMER_VECTOR {
        timer::on_timer_interrupt(global_timer_ref());
        controller.end_of_interrupt(IrqId::new(vector as u32));
        return;
    }

    if vector >= FIRST_USABLE_IRQ_VECTOR {
        let idx = (vector - FIRST_USABLE_IRQ_VECTOR) as usize;
        let handler = controller.handlers.borrow()[idx];
        if let Some(handler) = handler {
            handler(IrqId::new(vector as u32));
        }
    }

    controller.end_of_interrupt(IrqId::new(vector as u32));
}

/// Mirrors `GLOBAL_CONTROLLER_PTR`'s pattern for the `Timer` instance,
/// so `dispatch_vector` can reach it for the `TIMER_VECTOR` special
/// case above without threading a `&Timer` through `IrqHandler`'s
/// fixed `fn(IrqId)` signature.
static GLOBAL_TIMER_PTR: AtomicU64 = AtomicU64::new(0);

pub fn set_global_timer(t: &timer::Timer) {
    GLOBAL_TIMER_PTR.store(t as *const timer::Timer as u64, Ordering::SeqCst);
}

fn global_timer_ref() -> &'static timer::Timer {
    let ptr = GLOBAL_TIMER_PTR.load(Ordering::SeqCst);
    // SAFETY: same lifetime argument as `dispatch_vector`'s controller
    // dereference above — `set_global_timer` is called once, from
    // `hal_x86_64_rust_entry`, on a value living for the remainder of
    // program execution. A null pointer here would only occur if this
    // function were reachable before `set_global_timer` ran, which —
    // per the same interrupts-stay-masked-until-boot-completes
    // argument as `dispatch_vector` — cannot happen for TIMER_VECTOR
    // specifically, since arming the first TSC-deadline oneshot
    // (timer.rs) never happens before boot sequencing finishes.
    unsafe { &*(ptr as *const timer::Timer) }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockCpuid {
        leaf1_ecx: u32,
    }

    impl CpuidSource for MockCpuid {
        fn cpuid(&self, leaf: u32, _subleaf: u32) -> CpuidResult {
            match leaf {
                1 => CpuidResult { eax: 0, ebx: 0, ecx: self.leaf1_ecx, edx: 0 },
                _ => CpuidResult::default(),
            }
        }
    }

    #[test]
    fn detects_x2apic_from_leaf1_ecx_bit21() {
        let mock = MockCpuid { leaf1_ecx: 1 << 21 };
        assert!(detect_x2apic(&mock));
    }

    #[test]
    fn no_x2apic_when_bit_clear() {
        let mock = MockCpuid { leaf1_ecx: 0 };
        assert!(!detect_x2apic(&mock));
    }

    fn controller_with_mode(mode: ApicMode) -> InterruptCtrl {
        InterruptCtrl {
            mode,
            handlers: RefCell::new([None; IRQ_TABLE_SIZE]),
            ipi_target_core_count: Cell::new(4),
        }
    }

    fn dummy_handler(_irq: IrqId) {}

    #[test]
    fn register_irq_rejects_below_first_usable_vector() {
        let ctrl = controller_with_mode(ApicMode::X2apic);
        assert_eq!(
            ctrl.register_irq(IrqId::new(10), dummy_handler),
            Err(HalError::InvalidIrqId)
        );
    }

    #[test]
    fn register_irq_accepts_valid_vector() {
        let ctrl = controller_with_mode(ApicMode::X2apic);
        assert!(ctrl.register_irq(IrqId::new(FIRST_USABLE_IRQ_VECTOR as u32), dummy_handler).is_ok());
    }

    #[test]
    fn register_irq_rejects_double_registration() {
        let ctrl = controller_with_mode(ApicMode::X2apic);
        let vec = IrqId::new(FIRST_USABLE_IRQ_VECTOR as u32);
        ctrl.register_irq(vec, dummy_handler).unwrap();
        assert_eq!(ctrl.register_irq(vec, dummy_handler), Err(HalError::IrqAlreadyRegistered));
    }

    #[test]
    fn unregister_allows_re_registration() {
        let ctrl = controller_with_mode(ApicMode::X2apic);
        let vec = IrqId::new(FIRST_USABLE_IRQ_VECTOR as u32);
        ctrl.register_irq(vec, dummy_handler).unwrap();
        ctrl.unregister_irq(vec);
        assert!(ctrl.register_irq(vec, dummy_handler).is_ok());
    }

    #[test]
    fn send_ipi_rejects_out_of_range_target() {
        let ctrl = controller_with_mode(ApicMode::X2apic);
        assert_eq!(ctrl.send_ipi(99, 0x30), Err(HalError::InvalidIpiTarget));
    }

    #[test]
    fn irq_line_count_matches_table_size() {
        let ctrl = controller_with_mode(ApicMode::X2apic);
        assert_eq!(ctrl.irq_line_count() as usize, IRQ_TABLE_SIZE);
    }

    #[test]
    fn detected_kind_reflects_mode() {
        let x2 = controller_with_mode(ApicMode::X2apic);
        assert_eq!(x2.detected_kind(), InterruptControllerKindRaw::ApicX2apic);

        let xapic = controller_with_mode(ApicMode::Xapic { mmio_base: 0xFEE0_0000 });
        assert_eq!(xapic.detected_kind(), InterruptControllerKindRaw::ApicXapic);
        assert_eq!(xapic.primary_base(), 0xFEE0_0000);
    }

    #[test]
    fn x2apic_primary_base_is_zero() {
        let ctrl = controller_with_mode(ApicMode::X2apic);
        assert_eq!(ctrl.primary_base(), 0);
    }

    #[test]
    fn secondary_base_always_none_on_x86_64() {
        let ctrl = controller_with_mode(ApicMode::X2apic);
        assert_eq!(ctrl.secondary_base(), None);
    }
}