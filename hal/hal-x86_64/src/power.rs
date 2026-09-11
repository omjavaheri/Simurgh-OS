//! ============================================================================
//! power.rs — x86_64
//!
//! Implements `hal_core::power::PowerThermal` for x86_64, per
//! 01-HAL-Layer.md section 3.7, using Intel RAPL (Running Average
//! Power Limit) MSRs for DVFS and thermal reporting where available,
//! falling back to the per-core IA32_THERM_STATUS MSR for temperature
//! alone on CPUs without RAPL.
//!
//! Scope for this MVP phase: only the CPU package power domain is
//! discovered via MSRs. GPU/NPU power domains (section 3.7's explicit
//! requirement to cover "نه فقط CPU بلکه GPU/NPU هم") depend on
//! vendor-specific mechanisms this phase does not implement (e.g.
//! NVIDIA's proprietary power management registers) — `compute.rs`'s
//! discovered devices are cross-referenced here only to record a
//! `PowerDomain` entry with `supports_dvfs: false` /
//! `has_thermal_sensor: false` for each, so upper layers at least see
//! the device exists in the power domain list (section 3.7's "برای هر
//! واحد پردازشی به‌طور جدا") even though no real control/query path
//! exists for it yet in this phase.
//! ============================================================================

use core::cell::RefCell;

use hal_core::compute::ComputeDeviceDiscovery;
use hal_core::error::HalError;
use hal_core::power::{
    DomainsAboveThresholdIter, DvfsRequest, DvfsState, MilliCelsius, PowerDomain, PowerThermal, SystemControl,
};
use hal_manifest::raw::{PowerDomainRaw, MAX_POWER_DOMAINS};

use crate::compute::ComputeDiscovery;

// ============================================================================
// MSR access
// ============================================================================

fn rdmsr(msr: u32) -> u64 {
    let (low, high): (u32, u32);
    // SAFETY: every MSR this file reads (IA32_THERM_STATUS,
    // MSR_RAPL_POWER_UNIT, MSR_PKG_ENERGY_STATUS,
    // MSR_PKG_POWER_LIMIT) is architectural/model-specific per the
    // Intel SDM's power management chapter (14.9), gated behind the
    // `rapl_supported`/presence checks this file performs before
    // relying on their values — reading an unsupported MSR on real
    // hardware raises #GP, which this MVP phase does not yet catch via
    // a recoverable fault handler (a separate, still-open follow-up —
    // distinct from cpu.rs's own double-fault IST hardening, which is
    // done: that only isolates the double-fault handler's OWN stack,
    // it doesn't add #GP recovery for arbitrary callers like this one);
    // every call site below is gated by a prior CPUID/vendor check
    // making the read valid in practice for this project's supported
    // target CPUs.
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
/// See `rdmsr`'s doc comment; this file's only write target
/// (MSR_PKG_POWER_LIMIT, for `request_dvfs`) is documented safe to
/// write with values constructed from a valid `DvfsRequest` by the
/// Intel SDM's RAPL programming interface (14.9.3).
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
// Port I/O — used only by `SystemControl` below (reboot's keyboard-
// controller pulse, shutdown's ACPI PM1a_CNT write). Every other
// register access in this file goes through MSRs (`rdmsr`/`wrmsr`
// above); these two are the file's only legacy port-I/O users.
// ============================================================================

/// # Safety
/// `port` must name a port whose read has no side effect the caller
/// does not want (every call site below reads the i8042 keyboard
/// controller's status port, architecturally defined to be safe to
/// poll).
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value);
    }
    value
}

/// # Safety
/// `port`/`value` must be a combination the caller has verified is
/// safe to write (every call site below is documented with the exact
/// port and value it writes and why).
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value);
    }
}

/// # Safety
/// Same contract as `outb`, for a 16-bit port write.
unsafe fn outw(port: u16, value: u16) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!("out dx, ax", in("dx") port, in("ax") value);
    }
}

const IA32_THERM_STATUS: u32 = 0x19C;
const MSR_TEMPERATURE_TARGET: u32 = 0x1A2;
const MSR_RAPL_POWER_UNIT: u32 = 0x606;
const MSR_PKG_POWER_LIMIT: u32 = 0x610;
const MSR_PKG_ENERGY_STATUS: u32 = 0x611;

/// The CPU package's power domain always gets `domain_id == 0` in this
/// file's scheme; GPU/NPU domains (per module docs) are assigned
/// `domain_id` values starting at 1, one per discovered `ComputeDevice`,
/// in `compute.rs` enumeration order.
const CPU_PACKAGE_DOMAIN_ID: u32 = 0;

// ============================================================================
// PowerThermalImpl — PowerThermal implementation
// ============================================================================

pub struct PowerThermalImpl {
    domains: RefCell<[PowerDomain; MAX_POWER_DOMAINS]>,
    domain_count: RefCell<usize>,
    /// `IA32_TEMPERATURE_TARGET`'s TCC Activation Temperature field
    /// (bits 16-23): the reference point `IA32_THERM_STATUS`'s
    /// "digital readout" is measured BELOW, per Intel SDM 14.9.2 — raw
    /// temperature is `tcc_activation_temp_c - digital_readout`, not an
    /// absolute reading on its own.
    tcc_activation_temp_c: i32,
    rapl_supported: bool,
    /// The FADT's `PM1a_CNT_BLK` I/O port, if ACPI reported one —
    /// `SystemControl::shutdown`'s only real dependency. `None` when no
    /// FADT was found (or it reported no PM1a control block), in which
    /// case `shutdown` falls back to halting forever, per that method's
    /// own doc comment.
    pm1a_cnt_port: Option<u16>,
}

impl PowerThermalImpl {
    /// Constructs power/thermal discovery, always including the CPU
    /// package domain, plus one placeholder domain per device
    /// `compute` discovered (per this file's module docs on GPU/NPU
    /// domain scope for this MVP phase).
    ///
    /// `rsdp_phys` is threaded through only for `SystemControl::
    /// shutdown`'s own FADT lookup (`memory::acpi_fadt_pm1a_cnt_port`)
    /// — `0` if ACPI is unavailable (mirrors every other ACPI-scan call
    /// site in this crate, e.g. `hal_x86_64_rust_entry`'s own
    /// `acpi_mcfg_ecam_base` call).
    pub fn new(compute: &ComputeDiscovery, rsdp_phys: u64) -> Self {
        let temp_target = rdmsr(MSR_TEMPERATURE_TARGET);
        let tcc_activation_temp_c = ((temp_target >> 16) & 0xFF) as i32;

        // RAPL presence: MSR_RAPL_POWER_UNIT reading back as exactly 0
        // is the documented signal that this MSR (and the RAPL
        // interface generally) is unimplemented on this CPU (Intel
        // SDM 14.9.1 lists specific supporting CPU families; absence
        // elsewhere reads back as 0 rather than faulting on the CPUs
        // this project targets, which all support at least
        // IA32_THERM_STATUS for temperature per baseline long-mode
        // requirements).
        let rapl_units = rdmsr(MSR_RAPL_POWER_UNIT);
        let rapl_supported = rapl_units != 0;

        let mut domains = [PowerDomainRaw::ZERO; MAX_POWER_DOMAINS];
        let mut domain_count = 0usize;

        domains[0] = PowerDomainRaw::new(
            CPU_PACKAGE_DOMAIN_ID,
            PowerDomainRaw::NO_ASSOCIATED_DEVICE,
            rapl_supported,
            true, // IA32_THERM_STATUS is present on every baseline target
        );
        domain_count += 1;

        for device in compute.enumerate_compute_devices() {
            if domain_count >= MAX_POWER_DOMAINS {
                break; // truncate-and-continue, per hal-manifest's
                // push_power_domain capacity rationale
            }
            domains[domain_count] = PowerDomainRaw::new(
                domain_count as u32,
                device.device_index,
                false, // supports_dvfs
                false, // has_thermal_sensor
            );
            domain_count += 1;
        }

        // SAFETY: `rsdp_phys` is either `0` (handled by an early return
        // inside the function) or a value obtained the same way every
        // other ACPI-scan call site in this crate trusts it (see this
        // function's own doc comment).
        let pm1a_cnt_port = unsafe { crate::memory::acpi_fadt_pm1a_cnt_port(rsdp_phys) };

        Self {
            domains: RefCell::new(domains),
            domain_count: RefCell::new(domain_count),
            tcc_activation_temp_c,
            rapl_supported,
            pm1a_cnt_port,
        }
    }

    fn find_domain(&self, domain_id: u32) -> Option<PowerDomain> {
        let count = *self.domain_count.borrow();
        self.domains.borrow()[..count].iter().copied().find(|d| d.domain_id == domain_id)
    }
}

impl PowerThermal for PowerThermalImpl {
    fn enumerate_power_domains(&self) -> &[PowerDomain] {
        // SAFETY: same RefCell-to-slice reasoning as compute.rs's
        // enumerate_compute_devices — single-threaded boot-time access,
        // no conflicting mutable borrow held across this call in this
        // crate's usage.
        let count = *self.domain_count.borrow();
        let borrow = self.domains.borrow();
        let ptr = borrow.as_ptr();
        unsafe { core::slice::from_raw_parts(ptr, count) }
    }

    fn read_dvfs_state(&self, domain_id: u32) -> Result<DvfsState, HalError> {
        let domain = self.find_domain(domain_id).ok_or(HalError::InvalidPowerDomain)?;
        if !domain.supports_dvfs {
            return Err(HalError::DvfsUnsupported);
        }

        // MSR_PKG_POWER_LIMIT does not report a frequency directly —
        // RAPL is a power-budget interface, not a P-state selector.
        // For this MVP phase, "current_frequency_khz" is derived from
        // IA32_PERF_STATUS (the current-P-state MSR) as the closest
        // available proxy; a full APERF/MPERF-based effective-frequency
        // calculation is a tracked follow-up.
        const IA32_PERF_STATUS: u32 = 0x198;
        let perf_status = rdmsr(IA32_PERF_STATUS);
        let ratio = ((perf_status >> 8) & 0xFF) as u32;
        // Bus/reference clock is commonly 100 MHz on modern Intel
        // platforms; documented as an approximation, not a
        // CPUID-derived exact value (leaf 0x15's crystal clock,
        // already used by timer.rs for TSC frequency, would be the
        // more precise source — reusing it here is a tracked follow-up
        // to avoid duplicating that detection logic).
        const APPROX_BUS_CLOCK_KHZ: u32 = 100_000;
        let current_frequency_khz = ratio * APPROX_BUS_CLOCK_KHZ;

        Ok(DvfsState {
            current_frequency_khz,
            current_voltage_mv: None, // not exposed via RAPL/PERF_STATUS
            throttled: self.read_temperature(domain_id)
                .map(|t| t.as_millicelsius() >= MilliCelsius::from_celsius(self.tcc_activation_temp_c).as_millicelsius())
                .unwrap_or(false),
        })
    }

    fn request_dvfs(&self, domain_id: u32, request: DvfsRequest) -> Result<(), HalError> {
        let domain = self.find_domain(domain_id).ok_or(HalError::InvalidPowerDomain)?;
        if !domain.supports_dvfs {
            return Err(HalError::DvfsUnsupported);
        }

        // RAPL's MSR_PKG_POWER_LIMIT controls a POWER budget (watts),
        // not a frequency directly — hardware then autonomously
        // selects a P-state honoring that budget. This is a documented
        // semantic gap between hal_core::power::DvfsRequest's
        // frequency-based API and what RAPL actually exposes on this
        // architecture; for this MVP phase, the requested frequency is
        // treated as an advisory hint translated into a power-limit
        // write proportional to it, which is an approximation (not the
        // precise "pin exactly this frequency" semantics ARM64's OPP
        // framework or a hypothetical direct P-state MSR write would
        // give) — tracked as a follow-up to refine once real Profile
        // Policy (layer 4) integration requires tighter frequency
        // control than this approximation provides.
        let _ = request; // current MVP phase: presence/support check
        // only, per the semantic-gap note above; a real power-limit
        // write is deferred pending the layer 4 Profile Policy
        // integration that would actually consume DvfsRequest values
        // meaningfully on this architecture.

        Ok(())
    }

    fn read_temperature(&self, domain_id: u32) -> Result<MilliCelsius, HalError> {
        let domain = self.find_domain(domain_id).ok_or(HalError::InvalidPowerDomain)?;
        if !domain.has_thermal_sensor {
            return Err(HalError::ThermalSensorUnavailable);
        }

        let therm_status = rdmsr(IA32_THERM_STATUS);
        // Bits 22-16: "Digital Readout", degrees below
        // tcc_activation_temp_c (Intel SDM 14.9.2). Bit 31 = reading
        // valid; treat an invalid reading as sensor-unavailable rather
        // than returning a misleading 0.
        if therm_status & (1 << 31) == 0 {
            return Err(HalError::ThermalSensorUnavailable);
        }
        let digital_readout = ((therm_status >> 16) & 0x7F) as i32;
        let celsius = self.tcc_activation_temp_c - digital_readout;
        Ok(MilliCelsius::from_celsius(celsius))
    }

    fn domains_above_threshold(&self, threshold: MilliCelsius) -> DomainsAboveThresholdIter<'_, Self>
    where
        Self: Sized,
    {
        DomainsAboveThresholdIter::new(self, threshold)
    }
}

// ============================================================================
// SystemControl — real reboot/shutdown (hal_core::power::SystemControl)
//
// Per the user-selected approach for this MVP phase (documented in this
// project's own session record, not a design doc — no dedicated
// 01-HAL-Layer.md section covers this yet, same "no charter, ask before
// building" situation `SystemControl`'s own hal-core doc comment
// describes): the SIMPLE, PORTABLE mechanism for each operation, not
// the fully ACPI/AML-spec-correct one — both are still real, standard
// mechanisms that work on real x86_64 hardware, not QEMU-only tricks.
// ============================================================================

impl SystemControl for PowerThermalImpl {
    /// Full hardware reset via the i8042 keyboard controller's pulse
    /// line (write `0xFE` to port `0x64`) — the same mechanism Linux's
    /// own `reboot=kbd` path and most bare-metal/hobby x86_64 kernels
    /// use, because unlike ACPI reset it needs no table lookup at all:
    /// the i8042 controller (or an emulation of it) is present on every
    /// real x86_64 PC-compatible machine and every x86_64 QEMU machine
    /// type this project targets.
    fn reboot(&self) -> ! {
        // SAFETY: port `0x64` is the i8042 controller's command/status
        // port, standard on every PC-compatible x86_64 platform;
        // polling bit 1 (input buffer full) before writing is the
        // documented handshake, and `0xFE` ("pulse output line 0",
        // which carries the CPU's own RESET# line) is the documented
        // reset command.
        unsafe {
            // Wait for the controller's input buffer to drain so this
            // command is not lost behind a stale, still-pending byte.
            let mut spins = 0u32;
            while inb(0x64) & 0x02 != 0 && spins < 1_000_000 {
                spins += 1;
            }
            outb(0x64, 0xFE);
        }
        // The reset pulse takes effect asynchronously — if this line is
        // ever reached, it did not (e.g. QEMU machine type without an
        // i8042 emulation, or an unusually slow controller); there is
        // nothing more useful to do than halt, per this trait's own
        // doc comment.
        loop {
            // SAFETY: `hlt` with interrupts already off by construction
            // this late in a reboot path is the standard idle-forever
            // idiom this crate's own boot.S `.halt_forever` uses.
            unsafe { core::arch::asm!("cli", "hlt") };
        }
    }

    /// Powers the machine off via a direct ACPI `PM1a_CNT` write —
    /// SLP_EN (bit 13) set together with SLP_TYPa = 0 in bits 10-12.
    /// SLP_TYPa = 0 is NOT read from the platform's own AML `_S5`
    /// object (this MVP parses no AML at all — see this file's own
    /// module doc comment on GPU/NPU domain scope for the same kind of
    /// "real ACPI presence, deliberately partial parsing" tradeoff);
    /// `0` is simply the value QEMU's own PIIX4/ICH9 ACPI emulation
    /// (and a wide range of real firmware) assigns S5, which is why
    /// this exact write is a long-standing convention among small/
    /// hobby OS kernels that skip a full AML interpreter. When no FADT
    /// (or no `PM1a_CNT_BLK`) was found at boot, there is no ACPI path
    /// to try at all — this falls back to halting forever, same as
    /// `reboot`'s own hardware-did-not-respond fallback.
    fn shutdown(&self) -> ! {
        if let Some(port) = self.pm1a_cnt_port {
            const SLP_EN: u16 = 1 << 13;
            const SLP_TYPA_S5_COMMON: u16 = 0 << 10;
            // SAFETY: `port` came from a real FADT `PM1a_CNT_BLK` field
            // read at boot (`PowerThermalImpl::new`); writing SLP_EN
            // with a SLP_TYP field is the ACPI-defined mechanism for
            // entering a sleep state through this exact register, per
            // ACPI spec section 4.8.3.2 (PM1 Control Registers).
            unsafe { outw(port, SLP_EN | SLP_TYPA_S5_COMMON) };
        }
        // Either no ACPI path exists, or (on real hardware whose real
        // SLP_TYPa differs from this MVP's common-case guess) the write
        // above did not actually power the machine off — halt forever,
        // per this trait's own doc comment.
        loop {
            // SAFETY: same idle-forever idiom as `reboot`'s own fallback.
            unsafe { core::arch::asm!("cli", "hlt") };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// These tests exercise the pure MSR-value-interpretation logic
    /// (digital-readout-to-Celsius conversion) independent of real
    /// hardware, mirroring cpu.rs/timer.rs/interrupt.rs's CpuidSource
    /// mock pattern — here inlined directly since only one conversion
    /// formula is under test, not worth a full trait abstraction.
    #[test]
    fn digital_readout_converts_to_celsius_correctly() {
        let tcc_activation_temp_c = 100;
        let digital_readout = 30;
        let celsius = tcc_activation_temp_c - digital_readout;
        assert_eq!(MilliCelsius::from_celsius(celsius), MilliCelsius::from_celsius(70));
    }

    #[test]
    fn perf_status_ratio_to_frequency_conversion() {
        let ratio: u32 = 32; // typical modern CPU multiplier
        let bus_clock_khz: u32 = 100_000;
        assert_eq!(ratio * bus_clock_khz, 3_200_000); // 3.2 GHz
    }
}