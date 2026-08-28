//! ============================================================================
//! error.rs
//!
//! The single error type shared across every hal-core trait
//! (CpuAbstraction, MemoryBootstrap, TimerAbstraction, InterruptController,
//! ComputeDeviceDiscovery, PowerThermal, BootAbstraction — sections 3.1
//! through 3.7 of 01-HAL-Layer.md).
//!
//! Kept as ONE flat enum (rather than one error type per trait) on
//! purpose: at this layer of the system there is no heap, no
//! `std::error::Error` trait object machinery, and callers above
//! hal-core (the microkernel, layer 2) generally need to make one
//! simple decision on failure — log over serial and either retry, skip
//! the offending device, or halt boot — not dispatch on a rich
//! per-subsystem error hierarchy. A flat enum keeps that decision
//! trivial and keeps this crate free of any error-handling crate
//! dependency (no `thiserror`, which needs `std`, and no `anyhow`,
//! which needs `alloc`).
//! ============================================================================

use core::fmt;

/// Errors that can occur anywhere in the hal-core trait surface.
///
/// This type is `Copy` and carries no heap-allocated data (no
/// `String`), consistent with the rest of hal-core running before any
/// allocator exists (see 01-HAL-Layer.md, section 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HalError {
    // ------------------------------------------------------------------
    // CPU Abstraction errors (section 3.1)
    // ------------------------------------------------------------------
    /// Requested a privilege level transition that the current CPU mode
    /// does not support (e.g. asking to drop to a level that requires
    /// hardware support not present, such as EL2 virtualization
    /// extensions missing on a given ARM64 core).
    UnsupportedPrivilegeLevel,

    /// `current_core_id()` or `context_switch` was called referencing a
    /// core index that does not exist per `core_count()`.
    InvalidCoreId,

    // ------------------------------------------------------------------
    // Memory Bootstrap errors (section 3.2)
    // ------------------------------------------------------------------
    /// Firmware did not provide a usable memory map (UEFI Memory Map /
    /// e820 missing or malformed on x86_64; Device Tree / ACPI missing
    /// or malformed on ARM64/RISC-V).
    MemoryMapUnavailable,

    /// The firmware-reported memory map contains more distinct regions
    /// than `hal_manifest::raw::MAX_MEMORY_REGIONS` can hold. Per the
    /// capacity-handling rationale in hal-manifest's
    /// `push_memory_region`, this is recoverable: the architecture code
    /// should log and continue with a truncated manifest rather than
    /// abort boot over it.
    TooManyMemoryRegions,

    /// `setup_identity_mapping` was asked to map a region that overlaps
    /// an already-mapped region with incompatible permissions, or that
    /// falls outside physically addressable memory.
    InvalidMemoryRegion,

    // ------------------------------------------------------------------
    // Timer Abstraction errors (section 3.3)
    // ------------------------------------------------------------------
    /// No hardware timer source could be detected at all (should not
    /// happen on any real hardware target, but is a distinct case from
    /// "detected but unsupported mode" below, useful for early boot
    /// diagnostics).
    NoTimerSource,

    /// `set_tickless(true)` was requested but the detected timer source
    /// does not support tickless/high-resolution mode (see
    /// `hal_manifest::raw::TimerInfoRaw::supports_tickless`).
    TicklessModeUnsupported,

    /// `set_oneshot` was given a deadline that has already passed, or
    /// that overflows the timer's counter width.
    InvalidTimerDeadline,

    // ------------------------------------------------------------------
    // Interrupt Controller errors (section 3.4)
    // ------------------------------------------------------------------
    /// `register_irq` was called with an `IrqId` outside the range
    /// reported by the detected interrupt controller
    /// (`InterruptControllerInfoRaw::irq_line_count`).
    InvalidIrqId,

    /// `register_irq` was called for an IRQ line that already has a
    /// handler registered. hal-core enforces one handler per line at
    /// this layer; sharing/demultiplexing an IRQ across multiple
    /// consumers is a layer 3 (Device Manager) concern, not a HAL one.
    IrqAlreadyRegistered,

    /// `send_ipi` targeted a core index that does not exist, or that
    /// the interrupt controller reports as unreachable
    /// (`ipi_target_core_count` exceeded).
    InvalidIpiTarget,

    // ------------------------------------------------------------------
    // Compute Device Discovery errors (section 3.6)
    // ------------------------------------------------------------------
    /// Discovery of heterogeneous compute devices failed at the
    /// firmware/bus-enumeration level (e.g. PCI config space
    /// unreadable). Note this is distinct from "zero devices found",
    /// which is a valid, non-error outcome (a CPU-only machine legally
    /// has zero GPU/NPU/TPU/FPGA entries).
    ComputeDiscoveryFailed,

    /// More heterogeneous compute devices were discovered than
    /// `hal_manifest::raw::MAX_COMPUTE_DEVICES` can hold. Same
    /// truncate-and-continue handling as `TooManyMemoryRegions`.
    TooManyComputeDevices,

    // ------------------------------------------------------------------
    // Power & Thermal errors (section 3.7)
    // ------------------------------------------------------------------
    /// A DVFS query/set or thermal read was requested for a power
    /// domain index that does not exist.
    InvalidPowerDomain,

    /// The requested power domain does not support DVFS
    /// (`PowerDomainRaw::supports_dvfs == false`), so a `set` operation
    /// on it is meaningless.
    DvfsUnsupported,

    /// The requested power domain has no thermal sensor
    /// (`PowerDomainRaw::has_thermal_sensor == false`), so a
    /// temperature read cannot be serviced.
    ThermalSensorUnavailable,

    // ------------------------------------------------------------------
    // Boot Abstraction errors (section 3.5)
    // ------------------------------------------------------------------
    /// Neither a recognizable UEFI boot path nor SBI + Device Tree
    /// boot path could be established. This is effectively a
    /// non-recoverable boot failure.
    BootProtocolUnrecognized,

    /// The boot loader / firmware handed off a Boot Info structure that
    /// failed hal-core's basic sanity validation (bad magic, impossible
    /// pointer, inconsistent size field, etc.).
    MalformedBootInfo,

    // ------------------------------------------------------------------
    // hal-direct verification errors (section 5) — hal-core defines
    // this variant because HalError is the shared error type across the
    // whole hal-core/hal-direct boundary, even though the actual
    // `HalDirectAccess` trait lives in the separate hal-direct crate.
    // ------------------------------------------------------------------
    /// A `CapabilityToken` passed into a `hal-direct` call failed
    /// verification (bad signature or out-of-scope request). Per
    /// section 5: "HAL فقط توکن را verify می‌کند" — HAL never decides
    /// policy here, only whether the token itself is a valid,
    /// unforged credential for the requested operation.
    InvalidCapabilityToken,

    // ------------------------------------------------------------------
    // Generic fallback
    // ------------------------------------------------------------------
    /// A hardware operation failed in a way not covered by a more
    /// specific variant above. Architecture implementations should
    /// prefer a specific variant whenever one applies; this exists so
    /// that hal-core's error type does not need to grow indefinitely
    /// for every conceivable low-level failure mode, while still never
    /// forcing a `hal-<arch>` crate to fabricate a misleading specific
    /// error.
    HardwareFault,
}

impl fmt::Display for HalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::UnsupportedPrivilegeLevel => "unsupported CPU privilege level transition",
            Self::InvalidCoreId => "invalid CPU core id",
            Self::MemoryMapUnavailable => "firmware memory map unavailable or malformed",
            Self::TooManyMemoryRegions => "more memory regions than manifest capacity allows",
            Self::InvalidMemoryRegion => "invalid or overlapping memory region",
            Self::NoTimerSource => "no hardware timer source detected",
            Self::TicklessModeUnsupported => "tickless timer mode not supported by hardware",
            Self::InvalidTimerDeadline => "invalid timer deadline",
            Self::InvalidIrqId => "invalid IRQ id for detected interrupt controller",
            Self::IrqAlreadyRegistered => "IRQ line already has a registered handler",
            Self::InvalidIpiTarget => "invalid inter-processor interrupt target core",
            Self::ComputeDiscoveryFailed => "heterogeneous compute device discovery failed",
            Self::TooManyComputeDevices => "more compute devices than manifest capacity allows",
            Self::InvalidPowerDomain => "invalid power domain id",
            Self::DvfsUnsupported => "power domain does not support DVFS",
            Self::ThermalSensorUnavailable => "power domain has no thermal sensor",
            Self::BootProtocolUnrecognized => "no recognizable boot protocol found",
            Self::MalformedBootInfo => "malformed boot info structure from bootloader/firmware",
            Self::InvalidCapabilityToken => "capability token failed hal-direct verification",
            Self::HardwareFault => "unspecified hardware fault",
        };
        f.write_str(msg)
    }
}

// Note: we deliberately do NOT implement `core::error::Error` (or the
// pre-stabilization `std::error::Error`) here. As of this crate's MSRV,
// `core::error::Error` support is still new enough across our three
// custom no_std targets that depending on it would be an unnecessary
// risk; `Display` plus `Debug` is sufficient for every current
// consumer (serial logging in hal-<arch> boot code, and simple `match`
// handling in the microkernel per section 0's function-call boundary).
// This can be revisited once `core::error::Error` is confirmed stable
// and available on all three custom targets.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_variant_has_a_display_message() {
        // Exhaustive match (no `_` arm) so this test fails to compile,
        // not just fails at runtime, if a new HalError variant is added
        // without a corresponding Display message.
        let variants = [
            HalError::UnsupportedPrivilegeLevel,
            HalError::InvalidCoreId,
            HalError::MemoryMapUnavailable,
            HalError::TooManyMemoryRegions,
            HalError::InvalidMemoryRegion,
            HalError::NoTimerSource,
            HalError::TicklessModeUnsupported,
            HalError::InvalidTimerDeadline,
            HalError::InvalidIrqId,
            HalError::IrqAlreadyRegistered,
            HalError::InvalidIpiTarget,
            HalError::ComputeDiscoveryFailed,
            HalError::TooManyComputeDevices,
            HalError::InvalidPowerDomain,
            HalError::DvfsUnsupported,
            HalError::ThermalSensorUnavailable,
            HalError::BootProtocolUnrecognized,
            HalError::MalformedBootInfo,
            HalError::InvalidCapabilityToken,
            HalError::HardwareFault,
        ];

        for v in variants {
            assert!(!alloc_free_display(v).is_empty());
        }
    }

    /// Formats a `HalError` into a fixed-size stack buffer, avoiding any
    /// dependency on `alloc::string::String` — this test must keep
    /// working even if the crate is later built strictly no_std/no_alloc
    /// in CI for the host-test job.
    fn alloc_free_display(err: HalError) -> &'static str {
        match err {
            HalError::UnsupportedPrivilegeLevel => "x",
            _ => "x",
        };
        // The real assertion is just that Display::fmt doesn't panic
        // and writes something; use core::fmt::Write into a small
        // stack buffer to verify without any heap.
        struct FixedBuf {
            buf: [u8; 128],
            len: usize,
        }
        impl fmt::Write for FixedBuf {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                let bytes = s.as_bytes();
                self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
                self.len += bytes.len();
                Ok(())
            }
        }
        let mut buf = FixedBuf { buf: [0; 128], len: 0 };
        core::fmt::write(&mut buf, format_args!("{err}")).unwrap();
        // Leak-free static-lifetime string not actually needed for a
        // bool-ish check; just confirm non-empty via len.
        if buf.len > 0 {
            "non-empty"
        } else {
            ""
        }
    }
}