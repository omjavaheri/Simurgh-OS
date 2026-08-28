//! ============================================================================
//! interrupt.rs
//!
//! Interrupt Controller Abstraction, per 01-HAL-Layer.md section 3.4 and
//! the trait pre-draft in section 4:
//!
//!   pub trait InterruptController {
//!       fn register_irq(&self, irq: IrqId, handler: IrqHandler) -> Result<(), HalError>;
//!       fn mask_irq(&self, irq: IrqId);
//!       fn unmask_irq(&self, irq: IrqId);
//!       fn send_ipi(&self, target_core: usize, vector: u8);
//!   }
//!
//! Responsibilities per section 3.4: unify APIC/x2APIC (x86_64),
//! GICv3/v4 (ARM64), and PLIC + CLIC (RISC-V) behind one API:
//! `register_irq`, `mask_irq`, `unmask_irq`, `send_ipi`.
//!
//! This trait is the foundation the Device Manager (layer 3, section
//! 2.1) builds on: "صدور Capability محدود به هر درایور: فقط IRQ همان
//! دستگاه" — layer 3 grants a driver process a Capability scoped to
//! exactly one `IrqId`, and the microkernel's syscall layer enforces
//! that scope before ever reaching down into this trait.
//! ============================================================================

use crate::error::HalError;

// ============================================================================
// IRQ identifier
// ============================================================================

/// An architecture-independent interrupt line identifier.
///
/// The actual numeric meaning differs per architecture (an APIC vector
/// number on x86_64, a GIC INTID on ARM64, a PLIC/CLIC source number on
/// RISC-V) — callers above hal-core never need to know which, since
/// this trait's implementation (in each `hal-<arch>` crate) is the only
/// code that maps `IrqId` onto the real hardware numbering.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IrqId(pub u32);

impl IrqId {
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

// ============================================================================
// IRQ handler
// ============================================================================

/// Callback signature invoked when a registered IRQ fires.
///
/// Kept as a plain function pointer, not a boxed closure, for the same
/// no_std/no_alloc reason as `TimerCallback` in timer.rs: this crate
/// runs before any heap exists (hal-manifest section 9), and both
/// hal-core and every hal-<arch> crate link into the same pre-heap boot
/// binary (01-HAL-Layer.md, section 0).
///
/// The `IrqId` is passed back into the callback so a single dispatcher
/// function can be registered for multiple lines and branch on which
/// one fired, without needing per-line closures/captured state.
///
/// Per section 2.1 of 03-Kernel-Subsystems-Layer.md, the actual owning
/// driver logic lives in an isolated layer 3 process; what gets
/// registered here at the HAL level is typically a small, fixed
/// microkernel-side trampoline that turns this hardware IRQ into an
/// IPC/Notification delivered to that driver process — this function
/// pointer itself does not (and must not) run arbitrary driver code
/// directly in Privileged mode.
pub type IrqHandler = fn(IrqId);

// ============================================================================
// InterruptController trait (section 4 pre-draft, extended with error
// handling and explicit unregister/current-core awareness, since the
// pre-draft signatures for mask/unmask/send_ipi did not return Result
// at all — an omission that would force a panic-or-ignore choice on
// every hardware-reported failure, which is not acceptable in a
// Privileged-mode crate)
// ============================================================================

/// Per-architecture interrupt controller abstraction. Implemented once
/// per architecture crate (`hal-x86_64::interrupt::InterruptCtrl`,
/// `hal-arm64::interrupt::InterruptCtrl`,
/// `hal-riscv64::interrupt::InterruptCtrl`), each wrapping its own
/// hardware controller (APIC/x2APIC, GICv3/v4, PLIC+CLIC) behind this
/// one API.
pub trait InterruptController {
    /// Registers `handler` to be invoked whenever `irq` fires, and
    /// unmasks the line so it can actually deliver interrupts.
    ///
    /// Returns `Err(HalError::InvalidIrqId)` if `irq` is outside the
    /// range this controller reports via `irq_line_count()` below.
    /// Returns `Err(HalError::IrqAlreadyRegistered)` if a handler is
    /// already registered for this line — per section 3.4, hal-core
    /// enforces exactly one handler per line; sharing/demultiplexing an
    /// IRQ across multiple consumers is a layer 3 (Device Manager)
    /// concern built on top of this primitive, not something HAL itself
    /// does.
    fn register_irq(&self, irq: IrqId, handler: IrqHandler) -> Result<(), HalError>;

    /// Removes a previously registered handler for `irq` and masks the
    /// line. A no-op (not an error) if no handler was registered.
    ///
    /// Not present in the section 4 pre-draft, but required for the
    /// Device Manager's restart policy (03-Kernel-Subsystems-Layer.md,
    /// section 2.1: "کرش یک درایور → Device Manager آن را در یک
    /// پروسه‌ی جدید دوباره بالا می‌آورد") — restarting a driver process
    /// must be able to cleanly release its old IRQ registration before
    /// the new process instance registers again.
    fn unregister_irq(&self, irq: IrqId);

    /// Masks (disables delivery of) `irq` without unregistering its
    /// handler. Returns `Err(HalError::InvalidIrqId)` if `irq` is out
    /// of range.
    fn mask_irq(&self, irq: IrqId) -> Result<(), HalError>;

    /// Unmasks (re-enables delivery of) a previously masked `irq`.
    /// Returns `Err(HalError::InvalidIrqId)` if `irq` is out of range.
    fn unmask_irq(&self, irq: IrqId) -> Result<(), HalError>;

    /// Sends an inter-processor interrupt to `target_core`, carrying
    /// `vector` as an architecture-defined payload (e.g. an APIC vector
    /// number on x86_64, an SGI ID on ARM64 GIC, or a software
    /// interrupt cause encoding on RISC-V).
    ///
    /// Used by the microkernel's scheduler (02-Microkernel-Layer.md,
    /// section 4) to wake or preempt a thread running on a different
    /// core — e.g. for priority inheritance across cores, or to signal
    /// a core to reschedule after a remote `CapRevoke`.
    ///
    /// Returns `Err(HalError::InvalidIpiTarget)` if `target_core` does
    /// not exist, or exceeds this controller's reported
    /// `ipi_target_core_count`.
    fn send_ipi(&self, target_core: usize, vector: u8) -> Result<(), HalError>;

    /// Total number of distinct IRQ lines this controller exposes.
    /// Mirrors `hal_manifest::raw::InterruptControllerInfoRaw::irq_line_count`,
    /// exposed directly so callers can validate an `IrqId` without
    /// separately holding a manifest reference.
    fn irq_line_count(&self) -> u32;

    /// Number of cores this controller can target with `send_ipi`.
    /// Mirrors `InterruptControllerInfoRaw::ipi_target_core_count`.
    fn ipi_target_core_count(&self) -> u32;

    /// Signals end-of-interrupt to the hardware controller for the
    /// currently-being-serviced IRQ on this core (e.g. writing the EOI
    /// register on APIC/GIC, or the architecture-appropriate equivalent
    /// on PLIC).
    ///
    /// Must be called by the architecture's low-level interrupt entry
    /// code AFTER the registered `IrqHandler` returns, and before
    /// returning from the interrupt context — without this, most
    /// hardware controllers will never deliver a further interrupt on
    /// the same (or, on some controllers, any) line. Exposed here
    /// rather than folded automatically into `register_irq`'s handler
    /// dispatch because EOI timing relative to handler execution is
    /// itself architecture-specific (e.g. GIC supports EOI-before- vs
    /// EOI-after-handler modes) and must remain under the architecture
    /// implementation's explicit control.
    fn end_of_interrupt(&self, irq: IrqId);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::{Cell, RefCell};

    // ------------------------------------------------------------------
    // Mock hardware implementation, per section 8.4.
    //
    // Uses a small fixed-size table (not a Vec) to stay representative
    // of how a real no_std/no_alloc architecture implementation would
    // actually track registered handlers.
    // ------------------------------------------------------------------

    const MOCK_IRQ_LINES: usize = 8;
    const MOCK_IPI_CORES: usize = 4;

    struct MockInterruptController {
        handlers: RefCell<[Option<IrqHandler>; MOCK_IRQ_LINES]>,
        masked: RefCell<[bool; MOCK_IRQ_LINES]>,
        last_ipi: Cell<Option<(usize, u8)>>,
    }

    impl MockInterruptController {
        fn new() -> Self {
            Self {
                handlers: RefCell::new([None; MOCK_IRQ_LINES]),
                masked: RefCell::new([true; MOCK_IRQ_LINES]),
                last_ipi: Cell::new(None),
            }
        }
    }

    impl InterruptController for MockInterruptController {
        fn register_irq(&self, irq: IrqId, handler: IrqHandler) -> Result<(), HalError> {
            let idx = irq.as_u32() as usize;
            if idx >= MOCK_IRQ_LINES {
                return Err(HalError::InvalidIrqId);
            }
            let mut handlers = self.handlers.borrow_mut();
            if handlers[idx].is_some() {
                return Err(HalError::IrqAlreadyRegistered);
            }
            handlers[idx] = Some(handler);
            self.masked.borrow_mut()[idx] = false;
            Ok(())
        }

        fn unregister_irq(&self, irq: IrqId) {
            let idx = irq.as_u32() as usize;
            if idx < MOCK_IRQ_LINES {
                self.handlers.borrow_mut()[idx] = None;
                self.masked.borrow_mut()[idx] = true;
            }
        }

        fn mask_irq(&self, irq: IrqId) -> Result<(), HalError> {
            let idx = irq.as_u32() as usize;
            if idx >= MOCK_IRQ_LINES {
                return Err(HalError::InvalidIrqId);
            }
            self.masked.borrow_mut()[idx] = true;
            Ok(())
        }

        fn unmask_irq(&self, irq: IrqId) -> Result<(), HalError> {
            let idx = irq.as_u32() as usize;
            if idx >= MOCK_IRQ_LINES {
                return Err(HalError::InvalidIrqId);
            }
            self.masked.borrow_mut()[idx] = false;
            Ok(())
        }

        fn send_ipi(&self, target_core: usize, vector: u8) -> Result<(), HalError> {
            if target_core >= MOCK_IPI_CORES {
                return Err(HalError::InvalidIpiTarget);
            }
            self.last_ipi.set(Some((target_core, vector)));
            Ok(())
        }

        fn irq_line_count(&self) -> u32 {
            MOCK_IRQ_LINES as u32
        }

        fn ipi_target_core_count(&self) -> u32 {
            MOCK_IPI_CORES as u32
        }

        fn end_of_interrupt(&self, _irq: IrqId) {
            // Mock: nothing to do.
        }
    }

    fn dummy_handler(_irq: IrqId) {}

    #[test]
    fn register_irq_succeeds_within_range() {
        let ctrl = MockInterruptController::new();
        assert!(ctrl.register_irq(IrqId::new(3), dummy_handler).is_ok());
    }

    #[test]
    fn register_irq_rejects_out_of_range() {
        let ctrl = MockInterruptController::new();
        assert_eq!(
            ctrl.register_irq(IrqId::new(999), dummy_handler),
            Err(HalError::InvalidIrqId)
        );
    }

    #[test]
    fn register_irq_rejects_double_registration() {
        let ctrl = MockInterruptController::new();
        ctrl.register_irq(IrqId::new(0), dummy_handler).unwrap();
        assert_eq!(
            ctrl.register_irq(IrqId::new(0), dummy_handler),
            Err(HalError::IrqAlreadyRegistered)
        );
    }

    #[test]
    fn unregister_allows_re_registration() {
        let ctrl = MockInterruptController::new();
        ctrl.register_irq(IrqId::new(0), dummy_handler).unwrap();
        ctrl.unregister_irq(IrqId::new(0));
        assert!(ctrl.register_irq(IrqId::new(0), dummy_handler).is_ok());
    }

    #[test]
    fn mask_and_unmask_within_range() {
        let ctrl = MockInterruptController::new();
        ctrl.register_irq(IrqId::new(1), dummy_handler).unwrap();
        assert!(ctrl.mask_irq(IrqId::new(1)).is_ok());
        assert!(ctrl.masked.borrow()[1]);
        assert!(ctrl.unmask_irq(IrqId::new(1)).is_ok());
        assert!(!ctrl.masked.borrow()[1]);
    }

    #[test]
    fn send_ipi_rejects_invalid_target() {
        let ctrl = MockInterruptController::new();
        assert_eq!(
            ctrl.send_ipi(999, 0x30),
            Err(HalError::InvalidIpiTarget)
        );
    }

    #[test]
    fn send_ipi_records_target_and_vector() {
        let ctrl = MockInterruptController::new();
        assert!(ctrl.send_ipi(2, 0x40).is_ok());
        assert_eq!(ctrl.last_ipi.get(), Some((2, 0x40)));
    }
}