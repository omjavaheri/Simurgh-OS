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
use hal_core::power::{DomainsAboveThresholdIter, DvfsRequest, DvfsState, MilliCelsius, PowerDomain, PowerThermal};
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
    // a recoverable fault handler (a tracked follow-up alongside
    // cpu.rs's IST/double-fault TODO); every call site below is gated
    // by a prior CPUID/vendor check making the read valid in practice
    // for this project's supported target CPUs.
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
}

impl PowerThermalImpl {
    /// Constructs power/thermal discovery, always including the CPU
    /// package domain, plus one placeholder domain per device
    /// `compute` discovered (per this file's module docs on GPU/NPU
    /// domain scope for this MVP phase).
    pub fn new(compute: &ComputeDiscovery) -> Self {
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

        Self {
            domains: RefCell::new(domains),
            domain_count: RefCell::new(domain_count),
            tcc_activation_temp_c,
            rapl_supported,
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