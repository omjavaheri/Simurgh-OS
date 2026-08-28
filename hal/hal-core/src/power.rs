//! ============================================================================
//! power.rs
//!
//! Power & Thermal Query Interface, per 01-HAL-Layer.md section 3.7:
//!
//!   - API to read/set DVFS (Dynamic Voltage Frequency Scaling) for
//!     each processing unit SEPARATELY (not just the CPU, but GPU/NPU
//!     too)
//!   - report temperature for each unit, for upper layers' throttling
//!     decisions
//!
//! No trait pre-draft was given for this section in the source document
//! (section 4's Rust sketch stops at ComputeDeviceDiscovery) — the
//! trait below is written from scratch to match section 3.7's stated
//! responsibilities, and deliberately mirrors the shape of
//! ComputeDeviceDiscovery (compute.rs) since power domains are indexed
//! against compute devices via `PowerDomainRaw::associated_compute_device_index`
//! (hal-manifest raw.rs).
//!
//! Feeds directly into:
//!   - 04-System-Services-Policy-Layer.md section 6: `PowerPolicy`
//!     (Balanced | Performance | Efficiency) per profile — Policy Layer
//!     decides WHAT setting to request; this trait is only the
//!     MECHANISM for reading/applying it.
//!   - 02-Microkernel-Layer.md section 4: the Throughput scheduler's
//!     NUMA/compute-affinity awareness can factor in thermal headroom
//!     reported here when deciding placement.
//! ============================================================================

use crate::error::HalError;

// Re-export the raw power domain type directly from hal-manifest, for
// the same reason as MemoryBootstrap/ComputeDeviceDiscovery: at the
// point this trait's discovery-time data was built, no heap existed
// yet, so the raw `#[repr(C)]` type IS the correct boot-time
// representation — no benefit in defining a second, parallel type here.
pub use hal_manifest::raw::PowerDomainRaw as PowerDomain;

// ============================================================================
// DVFS types
// ============================================================================

/// A concrete performance state request for a power domain, expressed
/// as a target frequency. Kept as a plain frequency value (rather than
/// an opaque "P-state index" like ACPI _PSS tables use) because
/// frequency is the one unit that means the same thing across x86_64
/// (P-states), ARM64 (OPP — Operating Performance Points), and RISC-V
/// (vendor-specific DVFS registers) — an index-based P-state table
/// would leak architecture-specific numbering into upper layers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DvfsRequest {
    /// Target frequency in kHz. The architecture implementation snaps
    /// this to the nearest hardware-supported operating point; it does
    /// not need to be an exact match.
    pub target_frequency_khz: u32,
}

/// Current DVFS state as read back from hardware, distinct from
/// `DvfsRequest` because the actual applied frequency and voltage may
/// not exactly match what was last requested (thermal throttling,
/// hardware-autonomous P-state selection on some x86_64 CPUs, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DvfsState {
    pub current_frequency_khz: u32,
    /// Current voltage in millivolts, if the hardware exposes it
    /// (`None` on platforms where only frequency is queryable/settable,
    /// which is common — voltage is often managed autonomously by
    /// firmware/PMIC even when frequency is software-controlled).
    pub current_voltage_mv: Option<u32>,
    /// True if the hardware is currently throttling this domain below
    /// the last requested frequency for thermal or power-budget
    /// reasons — upper layers (Profile Policy, layer 4) use this to
    /// distinguish "we asked for less" from "hardware is limiting us".
    pub throttled: bool,
}

// ============================================================================
// Thermal types
// ============================================================================

/// A temperature reading, in millidegrees Celsius (matching the
/// convention used by Linux's hwmon/thermal subsystem, chosen for
/// familiarity to anyone porting sensor drivers via the layer 5 Linux
/// Compat Runtime, and because integer millidegrees avoids floating
/// point in this no_std/no_alloc crate entirely).
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MilliCelsius(pub i32);

impl MilliCelsius {
    pub const fn from_celsius(c: i32) -> Self {
        Self(c * 1000)
    }

    pub const fn as_millicelsius(self) -> i32 {
        self.0
    }
}

// ============================================================================
// PowerThermal trait
// ============================================================================

/// Per-architecture power and thermal query/control abstraction.
/// Implemented once per architecture crate
/// (`hal-x86_64::power::PowerThermal`, `hal-arm64::power::PowerThermal`,
/// `hal-riscv64::power::PowerThermal`).
///
/// Every method is scoped to a `PowerDomain` (identified by
/// `domain_id`, per `hal_manifest::raw::PowerDomainRaw`) rather than
/// implicitly assuming "the CPU" — per section 3.7's explicit
/// requirement that this cover every processing unit separately (CPU,
/// GPU, NPU, ...), not just the CPU package.
pub trait PowerThermal {
    /// Returns every power domain discovered on this machine. Like
    /// `ComputeDeviceDiscovery::enumerate_compute_devices`, this
    /// borrows directly from the architecture implementation's own
    /// fixed-capacity storage — no heap involved.
    fn enumerate_power_domains(&self) -> &[PowerDomain];

    /// Reads the current DVFS state for `domain_id`.
    ///
    /// Returns `Err(HalError::InvalidPowerDomain)` if no domain with
    /// this id exists. Returns `Err(HalError::DvfsUnsupported)` if the
    /// domain exists but does not support DVFS at all (see
    /// `PowerDomain::supports_dvfs`).
    fn read_dvfs_state(&self, domain_id: u32) -> Result<DvfsState, HalError>;

    /// Requests a new DVFS operating point for `domain_id`.
    ///
    /// This is a MECHANISM call only — the POLICY decision of which
    /// frequency to request for which profile (Balanced / Performance /
    /// Efficiency) is made entirely in
    /// 04-System-Services-Policy-Layer.md's Profile Policy Layer
    /// (section 6), which calls this through the Security Broker after
    /// validating the caller holds the appropriate `hal-direct`-style
    /// authorization (per 01-HAL-Layer.md section 5's Capability-gating
    /// principle, applied here to power control just as it is to raw
    /// MMIO/performance-counter access).
    ///
    /// Returns `Err(HalError::InvalidPowerDomain)` /
    /// `Err(HalError::DvfsUnsupported)` under the same conditions as
    /// `read_dvfs_state`.
    fn request_dvfs(&self, domain_id: u32, request: DvfsRequest) -> Result<(), HalError>;

    /// Reads the current temperature for `domain_id`.
    ///
    /// Returns `Err(HalError::InvalidPowerDomain)` if no domain with
    /// this id exists. Returns
    /// `Err(HalError::ThermalSensorUnavailable)` if the domain exists
    /// but has no thermal sensor (see `PowerDomain::has_thermal_sensor`).
    fn read_temperature(&self, domain_id: u32) -> Result<MilliCelsius, HalError>;

    /// Returns the domain_id of every power domain currently reporting
    /// a temperature at or above `threshold`. A convenience aggregate
    /// query (rather than requiring callers to loop
    /// `enumerate_power_domains` + `read_temperature` themselves) since
    /// this exact query is the one the layer 2 scheduler and layer 4
    /// Profile Policy both need for throttling decisions (section 3.7:
    /// "برای استفاده‌ی لایه‌ی بالاتر در تصمیم throttling") — implemented
    /// here once so every architecture crate does the underlying sensor
    /// sweep in whatever way is cheapest on its own hardware (e.g. a
    /// single batched register read on some platforms), rather than
    /// forcing a fixed per-domain call pattern on upper layers.
    fn domains_above_threshold(&self, threshold: MilliCelsius) -> DomainsAboveThresholdIter<'_, Self>
    where
        Self: Sized;
}

/// Iterator returned by `PowerThermal::domains_above_threshold`.
///
/// A hand-written iterator (rather than returning a boxed
/// `dyn Iterator`, which would require `alloc`) so this trait stays
/// usable in this crate's no_std/no_alloc configuration.
pub struct DomainsAboveThresholdIter<'a, T: PowerThermal + ?Sized> {
    controller: &'a T,
    domains: core::slice::Iter<'a, PowerDomain>,
    threshold: MilliCelsius,
}

impl<'a, T: PowerThermal + ?Sized> DomainsAboveThresholdIter<'a, T> {
    pub fn new(controller: &'a T, threshold: MilliCelsius) -> Self {
        Self {
            controller,
            domains: controller.enumerate_power_domains().iter(),
            threshold,
        }
    }
}

impl<'a, T: PowerThermal + ?Sized> Iterator for DomainsAboveThresholdIter<'a, T> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        for domain in self.domains.by_ref() {
            if !domain.has_thermal_sensor {
                continue;
            }
            if let Ok(temp) = self.controller.read_temperature(domain.domain_id) {
                if temp >= self.threshold {
                    return Some(domain.domain_id);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    // ------------------------------------------------------------------
    // Mock hardware implementation, per section 8.4.
    // ------------------------------------------------------------------

    struct MockPowerThermal {
        domains: [PowerDomain; 2],
        cpu_temp: Cell<MilliCelsius>,
        gpu_temp: Cell<MilliCelsius>,
        cpu_freq_khz: Cell<u32>,
    }

    impl MockPowerThermal {
        fn new() -> Self {
            let mut cpu_domain = PowerDomain::ZERO;
            cpu_domain.domain_id = 0;
            cpu_domain.associated_compute_device_index = PowerDomain::NO_ASSOCIATED_DEVICE;
            cpu_domain.supports_dvfs = true;
            cpu_domain.has_thermal_sensor = true;

            let mut gpu_domain = PowerDomain::ZERO;
            gpu_domain.domain_id = 1;
            gpu_domain.associated_compute_device_index = 0; // ties to compute_devices[0]
            gpu_domain.supports_dvfs = true;
            gpu_domain.has_thermal_sensor = true;

            Self {
                domains: [cpu_domain, gpu_domain],
                cpu_temp: Cell::new(MilliCelsius::from_celsius(45)),
                gpu_temp: Cell::new(MilliCelsius::from_celsius(70)),
                cpu_freq_khz: Cell::new(3_200_000),
            }
        }
    }

    impl PowerThermal for MockPowerThermal {
        fn enumerate_power_domains(&self) -> &[PowerDomain] {
            &self.domains
        }

        fn read_dvfs_state(&self, domain_id: u32) -> Result<DvfsState, HalError> {
            let domain = self
                .domains
                .iter()
                .find(|d| d.domain_id == domain_id)
                .ok_or(HalError::InvalidPowerDomain)?;
            if !domain.supports_dvfs {
                return Err(HalError::DvfsUnsupported);
            }
            Ok(DvfsState {
                current_frequency_khz: self.cpu_freq_khz.get(),
                current_voltage_mv: None,
                throttled: false,
            })
        }

        fn request_dvfs(&self, domain_id: u32, request: DvfsRequest) -> Result<(), HalError> {
            let domain = self
                .domains
                .iter()
                .find(|d| d.domain_id == domain_id)
                .ok_or(HalError::InvalidPowerDomain)?;
            if !domain.supports_dvfs {
                return Err(HalError::DvfsUnsupported);
            }
            self.cpu_freq_khz.set(request.target_frequency_khz);
            Ok(())
        }

        fn read_temperature(&self, domain_id: u32) -> Result<MilliCelsius, HalError> {
            let domain = self
                .domains
                .iter()
                .find(|d| d.domain_id == domain_id)
                .ok_or(HalError::InvalidPowerDomain)?;
            if !domain.has_thermal_sensor {
                return Err(HalError::ThermalSensorUnavailable);
            }
            Ok(if domain_id == 0 {
                self.cpu_temp.get()
            } else {
                self.gpu_temp.get()
            })
        }

        fn domains_above_threshold(&self, threshold: MilliCelsius) -> DomainsAboveThresholdIter<'_, Self> {
            DomainsAboveThresholdIter::new(self, threshold)
        }
    }

    #[test]
    fn read_temperature_returns_correct_value_per_domain() {
        let power = MockPowerThermal::new();
        assert_eq!(power.read_temperature(0).unwrap(), MilliCelsius::from_celsius(45));
        assert_eq!(power.read_temperature(1).unwrap(), MilliCelsius::from_celsius(70));
    }

    #[test]
    fn read_temperature_rejects_invalid_domain() {
        let power = MockPowerThermal::new();
        assert_eq!(power.read_temperature(99), Err(HalError::InvalidPowerDomain));
    }

    #[test]
    fn dvfs_request_updates_state() {
        let power = MockPowerThermal::new();
        power
            .request_dvfs(0, DvfsRequest { target_frequency_khz: 1_600_000 })
            .unwrap();
        let state = power.read_dvfs_state(0).unwrap();
        assert_eq!(state.current_frequency_khz, 1_600_000);
    }

    #[test]
    fn domains_above_threshold_finds_only_hot_domain() {
        let power = MockPowerThermal::new();
        let hot: alloc::vec::Vec<u32> =
            power.domains_above_threshold(MilliCelsius::from_celsius(60)).collect();
        assert_eq!(hot, alloc::vec![1]); // only the GPU (70C) is above 60C
    }

    #[test]
    fn no_domains_above_very_high_threshold() {
        let power = MockPowerThermal::new();
        let hot: alloc::vec::Vec<u32> =
            power.domains_above_threshold(MilliCelsius::from_celsius(100)).collect();
        assert!(hot.is_empty());
    }

    // Tests use `alloc::vec::Vec` purely as a *test convenience* to
    // collect iterator output for assertions — the crate under test
    // (hal-core) itself never uses alloc; this is safe because dev-
    // dependencies/test code compiles for the host target, which has
    // std/alloc freely available regardless of hal-core's own no_std
    // configuration.
    extern crate alloc;
}