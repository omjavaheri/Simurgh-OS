//! ============================================================================
//! power.rs — RISC-V (RV64GC)
//!
//! Implements `hal_core::power::PowerThermal` for RISC-V, per
//! 01-HAL-Layer.md section 3.7.
//!
//! Design: like ARM64 (and unlike x86_64's RAPL), the RISC-V base ISA
//! and privileged spec define NO standard power-management or thermal-
//! sensor register interface at all. The RISC-V equivalent of ARM's
//! SCMI is, in practice, ALSO commonly implemented via SBI itself — a
//! (currently still-evolving, at time of this project's design) SBI
//! "SUSP"/power-management extension family, plus vendor-specific PMU
//! event counters accessible through the SBI PMU extension (which DOES
//! exist and is stable, but covers performance-counter virtualization,
//! not DVFS/thermal control).
//!
//! This MVP phase implements neither the power-management SBI
//! extension family nor any vendor-specific DVFS/thermal path — same
//! documented-gap philosophy as hal-arm64/power.rs: every power domain
//! (CPU package and each discovered compute device) is recorded with
//! `supports_dvfs: false` / `has_thermal_sensor: false`, satisfying
//! section 3.7's per-unit domain-modeling requirement at the data
//! level while being honest that no working control/query path exists
//! yet. Real DVFS/thermal control on RISC-V is a tracked, substantial
//! follow-up (SBI power-management extension client, once that
//! extension family stabilizes further) for a later phase — this
//! project's structure (mirroring hal-x86_64/hal-arm64's identical
//! `PowerThermal` shape) means slotting in a real implementation later
//! requires no interface changes, only filling in this file's bodies.
//! ============================================================================

use core::cell::RefCell;

use hal_core::compute::ComputeDeviceDiscovery;
use hal_core::error::HalError;
use hal_core::power::{DomainsAboveThresholdIter, DvfsRequest, DvfsState, MilliCelsius, PowerDomain, PowerThermal};
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
    /// phase has no working DVFS/thermal backend on RISC-V at all —
    /// the CPU package domain and one domain per discovered compute
    /// device are still recorded, each explicitly marked as
    /// unsupported rather than omitted or fabricated, mirroring
    /// hal-arm64/power.rs's identical approach and rationale.
    pub fn new(compute: &ComputeDiscovery) -> Self {
        let mut domains = [PowerDomainRaw::ZERO; MAX_POWER_DOMAINS];
        let mut domain_count = 0usize;

        // `::new` rather than struct-literal + `..ZERO`: `PowerDomainRaw`'s
        // padding fields are private to hal-manifest (FRU across that
        // boundary is E0451) — matches hal-x86_64/power.rs.
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
        if !domain.supports_dvfs {
            return Err(HalError::DvfsUnsupported);
        }
        unreachable!("no RISC-V power domain in this MVP phase reports supports_dvfs = true");
    }

    fn request_dvfs(&self, domain_id: u32, _request: DvfsRequest) -> Result<(), HalError> {
        let domain = self.find_domain(domain_id).ok_or(HalError::InvalidPowerDomain)?;
        if !domain.supports_dvfs {
            return Err(HalError::DvfsUnsupported);
        }
        unreachable!("no RISC-V power domain in this MVP phase reports supports_dvfs = true");
    }

    fn read_temperature(&self, domain_id: u32) -> Result<MilliCelsius, HalError> {
        let domain = self.find_domain(domain_id).ok_or(HalError::InvalidPowerDomain)?;
        if !domain.has_thermal_sensor {
            return Err(HalError::ThermalSensorUnavailable);
        }
        unreachable!("no RISC-V power domain in this MVP phase reports has_thermal_sensor = true");
    }

    fn domains_above_threshold(&self, threshold: MilliCelsius) -> DomainsAboveThresholdIter<'_, Self>
    where
        Self: Sized,
    {
        // Same reasoning as hal-arm64/power.rs: DomainsAboveThresholdIter
        // (hal-core/src/power.rs) skips any domain without
        // has_thermal_sensor before ever calling read_temperature, so
        // this iterator is always empty on this architecture in this
        // MVP phase, correctly and without ever reaching the
        // unreachable!() branches above.
        DomainsAboveThresholdIter::new(self, threshold)
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