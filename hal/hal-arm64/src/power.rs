//! ============================================================================
//! power.rs — ARM64
//!
//! Implements `hal_core::power::PowerThermal` for ARM64, per
//! 01-HAL-Layer.md section 3.7.
//!
//! Design: unlike x86_64, where RAPL (a well-defined, universal MSR
//! interface across virtually every modern Intel/AMD CPU) provides a
//! single standard mechanism, AArch64 has NO architecturally-mandated
//! power/thermal MSR-equivalent interface at all — DVFS and thermal
//! monitoring on real ARM64 hardware are exposed through
//! vendor-specific mechanisms (e.g. a per-SoC PMIC accessed via I2C/
//! SCMI, or vendor-specific system registers), NOT through anything
//! the ARMv8-A base architecture standardizes the way RAPL is at least
//! consistent across x86_64 vendors.
//!
//! The one architecturally-standard piece this file DOES use: SCMI
//! (System Control and Management Interface, an Arm-defined but
//! optional standard for firmware-mediated power/performance/sensor
//! control over a shared-memory + mailbox transport) — when present
//! (advertised via a Device Tree/ACPI PPTT-adjacent mechanism this MVP
//! phase does not yet fully probe for), it would be the correct,
//! portable path. This phase does not implement full SCMI (a
//! non-trivial mailbox protocol), and instead — consistent with this
//! project's "truncate and continue, document the gap" philosophy
//! established in every other hal-<arch> file — reports every power
//! domain (CPU package and each compute device) with
//! `supports_dvfs: false` / `has_thermal_sensor: false`, giving upper
//! layers an accurate (if minimal) picture rather than a fabricated
//! one. Real DVFS/thermal control on ARM64 is a tracked, substantial
//! follow-up (SCMI client implementation) for a later phase.
//! ============================================================================

use core::cell::RefCell;

use hal_core::compute::ComputeDeviceDiscovery;
use hal_core::error::HalError;
use hal_core::power::{
    DomainsAboveThresholdIter, DvfsRequest, DvfsState, MilliCelsius, PowerDomain, PowerThermal, SystemControl,
};
use hal_manifest::raw::{PowerDomainRaw, MAX_POWER_DOMAINS};

use crate::compute::ComputeDiscovery;

const CPU_PACKAGE_DOMAIN_ID: u32 = 0;

// ============================================================================
// PowerThermalImpl — PowerThermal implementation
// ============================================================================

pub struct PowerThermalImpl {
    domains: RefCell<[PowerDomain; MAX_POWER_DOMAINS]>,
    domain_count: RefCell<usize>,
}

impl PowerThermalImpl {
    /// Constructs power/thermal discovery. Per module docs, this MVP
    /// phase has no working DVFS/thermal backend on ARM64 at all — the
    /// CPU package domain and one domain per discovered compute device
    /// are still recorded (satisfying section 3.7's "برای هر واحد
    /// پردازشی به‌طور جدا" requirement at the DATA-MODEL level), each
    /// explicitly marked as unsupported rather than omitted or
    /// fabricated.
    pub fn new(compute: &ComputeDiscovery) -> Self {
        let mut domains = [PowerDomainRaw::ZERO; MAX_POWER_DOMAINS];
        let mut domain_count = 0usize;

        domains[0] = PowerDomainRaw::new(
            CPU_PACKAGE_DOMAIN_ID,
            PowerDomainRaw::NO_ASSOCIATED_DEVICE,
            false,
            false,
        );
        domain_count += 1;

        for device in compute.enumerate_compute_devices() {
            if domain_count >= MAX_POWER_DOMAINS {
                break;
            }
            domains[domain_count] = PowerDomainRaw::new(
                domain_count as u32,
                device.device_index,
                false,
                false,
            );
            domain_count += 1;
        }

        Self {
            domains: RefCell::new(domains),
            domain_count: RefCell::new(domain_count),
        }
    }

    fn find_domain(&self, domain_id: u32) -> Option<PowerDomain> {
        let count = *self.domain_count.borrow();
        self.domains.borrow()[..count].iter().copied().find(|d| d.domain_id == domain_id)
    }
}

impl PowerThermal for PowerThermalImpl {
    fn enumerate_power_domains(&self) -> &[PowerDomain] {
        // SAFETY: same RefCell-to-slice reasoning as every other
        // enumerate_* method in this project's hal-<arch> crates —
        // single-threaded boot-time access, no conflicting mutable
        // borrow held across this call.
        let count = *self.domain_count.borrow();
        let borrow = self.domains.borrow();
        let ptr = borrow.as_ptr();
        unsafe { core::slice::from_raw_parts(ptr, count) }
    }

    fn read_dvfs_state(&self, domain_id: u32) -> Result<DvfsState, HalError> {
        let domain = self.find_domain(domain_id).ok_or(HalError::InvalidPowerDomain)?;
        // Every domain in this MVP phase has supports_dvfs == false
        // (per module docs), so this always returns DvfsUnsupported —
        // matching hal_core::power::PowerThermal's documented contract
        // for that exact condition rather than inventing a fake
        // successful read.
        if !domain.supports_dvfs {
            return Err(HalError::DvfsUnsupported);
        }
        unreachable!("no ARM64 power domain in this MVP phase reports supports_dvfs = true");
    }

    fn request_dvfs(&self, domain_id: u32, _request: DvfsRequest) -> Result<(), HalError> {
        let domain = self.find_domain(domain_id).ok_or(HalError::InvalidPowerDomain)?;
        if !domain.supports_dvfs {
            return Err(HalError::DvfsUnsupported);
        }
        unreachable!("no ARM64 power domain in this MVP phase reports supports_dvfs = true");
    }

    fn read_temperature(&self, domain_id: u32) -> Result<MilliCelsius, HalError> {
        let domain = self.find_domain(domain_id).ok_or(HalError::InvalidPowerDomain)?;
        if !domain.has_thermal_sensor {
            return Err(HalError::ThermalSensorUnavailable);
        }
        unreachable!("no ARM64 power domain in this MVP phase reports has_thermal_sensor = true");
    }

    fn domains_above_threshold(&self, threshold: MilliCelsius) -> DomainsAboveThresholdIter<'_, Self>
    where
        Self: Sized,
    {
        // Per DomainsAboveThresholdIter's own implementation
        // (hal-core/src/power.rs), it skips any domain without
        // has_thermal_sensor before ever calling read_temperature —
        // so this iterator is always empty on this architecture in
        // this MVP phase, correctly and without ever reaching the
        // unreachable!() branches above.
        DomainsAboveThresholdIter::new(self, threshold)
    }
}

// ============================================================================
// SystemControl — real reboot/shutdown, via PSCI (Power State
// Coordination Interface, Arm DEN 0022) — the one ARM64 power
// mechanism that IS architecturally standardized (unlike DVFS/thermal,
// per this file's own module doc comment), and required firmware on
// every real ARMv8-A platform this project targets as well as every
// ARM64 QEMU machine type it tests against.
// ============================================================================

/// PSCI function IDs (32-bit calling convention — DEN 0022 section
/// 5.1): `SYSTEM_OFF`/`SYSTEM_RESET` take no arguments and, per spec,
/// do not return on success.
const PSCI_SYSTEM_OFF: u32 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u32 = 0x8400_0009;

/// Issues a PSCI call via `smc #0` — the conduit this crate's own boot
/// path implies is correct: `boot.S`'s EL2->EL1 drop (this crate's
/// `lib.rs`) means the kernel never retains EL2, so on QEMU's `virt`
/// machine (this project's own ARM64 test target) PSCI is provided by
/// EL3 firmware reached directly via SMC — the "no EL2 present at all"
/// configuration QEMU uses unless `virtualization=on` is explicitly
/// passed (which this project's own QEMU test scripts do not), and the
/// same conduit real firmware overwhelmingly uses when no hypervisor
/// occupies EL2 either. Per the SMC32 calling convention, PSCI results
/// return in `x0`; `SYSTEM_OFF`/`SYSTEM_RESET` are defined not to
/// return at all on success — but this call is NOT marked
/// `options(noreturn)`: a non-compliant or unexpectedly configured
/// firmware returning anyway must fall through to `reboot`/`shutdown`'s
/// own halt-forever fallback below, not hit undefined behavior.
///
/// # Safety
/// `smc` traps to EL3 firmware; this is only sound to call on a
/// platform whose firmware actually implements the standard PSCI
/// function IDs above, per DEN 0022 — true for every real ARMv8-A
/// platform (PSCI is mandatory for any Arm-compliant boot firmware)
/// and QEMU's own `virt` machine.
#[cfg(target_os = "none")]
unsafe fn psci_smc_call(function_id: u32) {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "smc #0",
            inout("x0") function_id => _,
            in("x1") 0u64,
            in("x2") 0u64,
            in("x3") 0u64,
        );
    }
}

/// Host (`cargo test`) stub — `smc` is not a valid instruction for the
/// host target. Unit tests never call `reboot`/`shutdown` (both `-> !`),
/// so this only exists so the crate compiles.
///
/// # Safety
/// None — trivially safe, kept `unsafe` only so both this stub and the
/// real bare-metal version above share one call-site signature.
#[cfg(not(target_os = "none"))]
unsafe fn psci_smc_call(_function_id: u32) {}

/// Halts this core forever — the fallback both `reboot` and `shutdown`
/// use if their own PSCI call did not actually reset/power off the
/// machine (see `SystemControl`'s own doc comment). Gated the same way
/// as `psci_smc_call` for the same host-build reason (`wfe` is not a
/// valid instruction off the bare-metal target).
#[cfg(target_os = "none")]
fn idle_forever() -> ! {
    loop {
        // SAFETY: `wfe` is the standard ARM64 idle-forever idiom.
        unsafe { core::arch::asm!("wfe") };
    }
}

#[cfg(not(target_os = "none"))]
fn idle_forever() -> ! {
    loop {}
}

impl SystemControl for PowerThermalImpl {
    fn reboot(&self) -> ! {
        // SAFETY: see `psci_smc_call`'s own doc comment.
        unsafe { psci_smc_call(PSCI_SYSTEM_RESET) };
        // Reached only if firmware did not honor the call — nothing
        // more useful to do, per `hal_core::power::SystemControl`'s own
        // doc comment.
        idle_forever()
    }

    fn shutdown(&self) -> ! {
        // SAFETY: see `psci_smc_call`'s own doc comment.
        unsafe { psci_smc_call(PSCI_SYSTEM_OFF) };
        idle_forever()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn power_with_domains(domains: [PowerDomainRaw; MAX_POWER_DOMAINS], count: usize) -> PowerThermalImpl {
        PowerThermalImpl {
            domains: RefCell::new(domains),
            domain_count: RefCell::new(count),
        }
    }

    fn zeroed_domains() -> [PowerDomainRaw; MAX_POWER_DOMAINS] {
        [PowerDomainRaw::ZERO; MAX_POWER_DOMAINS]
    }

    #[test]
    fn cpu_package_domain_reports_unsupported_dvfs() {
        let mut domains = zeroed_domains();
        domains[0] = PowerDomainRaw::new(
            CPU_PACKAGE_DOMAIN_ID,
            PowerDomainRaw::NO_ASSOCIATED_DEVICE,
            false,
            false,
        );
        let power = power_with_domains(domains, 1);

        assert_eq!(power.read_dvfs_state(0), Err(HalError::DvfsUnsupported));
        assert_eq!(
            power.request_dvfs(0, DvfsRequest { target_frequency_khz: 1_000_000 }),
            Err(HalError::DvfsUnsupported)
        );
    }

    #[test]
    fn cpu_package_domain_reports_no_thermal_sensor() {
        let mut domains = zeroed_domains();
        domains[0] = PowerDomainRaw::new(
            CPU_PACKAGE_DOMAIN_ID,
            PowerDomainRaw::NO_ASSOCIATED_DEVICE,
            false,
            false,
        );
        let power = power_with_domains(domains, 1);

        assert_eq!(power.read_temperature(0), Err(HalError::ThermalSensorUnavailable));
    }

    #[test]
    fn invalid_domain_id_is_rejected() {
        let power = power_with_domains(zeroed_domains(), 0);
        assert_eq!(power.read_temperature(99), Err(HalError::InvalidPowerDomain));
    }

    #[test]
    fn domains_above_threshold_is_always_empty_in_this_mvp_phase() {
        let mut domains = zeroed_domains();
        domains[0] = PowerDomainRaw::new(
            0,
            PowerDomainRaw::NO_ASSOCIATED_DEVICE,
            false,
            false,
        );
        let power = power_with_domains(domains, 1);

        let hot: alloc::vec::Vec<u32> =
            power.domains_above_threshold(MilliCelsius::from_celsius(0)).collect();
        assert!(hot.is_empty());
    }

    extern crate alloc;
}