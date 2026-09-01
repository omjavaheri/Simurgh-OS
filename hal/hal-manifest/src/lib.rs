//! ============================================================================
//! hal-manifest
//!
//! Shared Hardware Manifest data structures, per 01-HAL-Layer.md, section 9.
//!
//! This crate is `#![no_std]` unconditionally (it must be usable from the
//! boot path in hal-core / hal-x86_64 / hal-arm64 / hal-riscv64, where no
//! heap allocator exists yet). It exposes two layers:
//!
//!   - `raw` module (always available): the `#[repr(C)]`, fixed-size,
//!     no-heap `HardwareManifestRaw` used for the boot-time HAL -> Root
//!     Task handoff.
//!
//!   - top-level `HardwareManifest` (only with `feature = "alloc"`): the
//!     `Vec`-based dynamic representation used from layer 3 onward, once
//!     the Root Task has a real heap. Built by converting from
//!     `HardwareManifestRaw` via `HardwareManifest::from_raw`.
//!
//! Per section 9's closing paragraph: "یعنی محدودیت اندازه‌ی ثابت فقط در
//! پایین‌ترین نقطه‌ی سیستم اعمال می‌شود، نه در کل معماری" — the fixed-size
//! constraint only applies at the lowest point of the system, not to the
//! architecture as a whole. This crate is the exact boundary where that
//! transition happens.
//! ============================================================================

#![no_std]
// `alloc` is an external crate declaration, needed only when the "alloc"
// feature is enabled. Gating the `extern crate alloc` declaration itself
// (rather than just gating individual items) keeps the crate from
// pulling in the alloc dependency at all in the boot-path configuration.
#![cfg_attr(feature = "alloc", allow(clippy::module_name_repetitions))]

pub mod raw;

#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
mod dynamic {
    //! Dynamic, heap-backed representation of the Hardware Manifest.
    //! Only compiled with `feature = "alloc"` — see module-level docs.

    use crate::raw::{
        ComputeDeviceRaw, ComputeKindRaw, HardwareManifestRaw, InterruptControllerInfoRaw,
        InterruptControllerKindRaw, MemoryRegionKindRaw, MemoryRegionRaw, PeripheralDeviceRaw,
        PeripheralKindRaw, PowerDomainRaw, TimerInfoRaw, TimerKindRaw, VendorIdRaw,
    };
    use alloc::string::String;
    use alloc::vec::Vec;

    // ------------------------------------------------------------------
    // CPU info (dynamic side has no fixed-size constraint, but CPU info
    // itself has no variable-length data, so this mirrors the raw shape
    // closely — kept as its own type per the trait pre-draft in
    // 01-HAL-Layer.md section 4: `pub cpu: CpuInfo` inside
    // `HardwareManifest`).
    // ------------------------------------------------------------------
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct CpuFeatureFlags(pub u64);

    #[derive(Debug, Clone, Copy)]
    pub struct CpuInfo {
        pub core_count: usize,
        pub feature_flags: CpuFeatureFlags,
    }

    // ------------------------------------------------------------------
    // Memory region (dynamic)
    // ------------------------------------------------------------------
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MemoryRegionKind {
        Usable,
        Reserved,
        AcpiReclaimable,
        AcpiNvs,
        Mmio,
        KernelImage,
        BootReserved,
    }

    impl From<MemoryRegionKindRaw> for MemoryRegionKind {
        fn from(raw: MemoryRegionKindRaw) -> Self {
            match raw {
                MemoryRegionKindRaw::Usable => Self::Usable,
                MemoryRegionKindRaw::Reserved => Self::Reserved,
                MemoryRegionKindRaw::AcpiReclaimable => Self::AcpiReclaimable,
                MemoryRegionKindRaw::AcpiNvs => Self::AcpiNvs,
                MemoryRegionKindRaw::Mmio => Self::Mmio,
                MemoryRegionKindRaw::KernelImage => Self::KernelImage,
                MemoryRegionKindRaw::BootReserved => Self::BootReserved,
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct MemoryRegion {
        pub base_addr: u64,
        pub length_bytes: u64,
        pub kind: MemoryRegionKind,
        pub behind_iommu: bool,
    }

    impl From<MemoryRegionRaw> for MemoryRegion {
        fn from(raw: MemoryRegionRaw) -> Self {
            Self {
                base_addr: raw.base_addr,
                length_bytes: raw.length_bytes,
                kind: raw.kind.into(),
                behind_iommu: raw.behind_iommu,
            }
        }
    }

    // ------------------------------------------------------------------
    // Compute device (dynamic) — matches the pre-draft trait API in
    // 01-HAL-Layer.md section 4 almost verbatim (`ComputeDevice` struct
    // with `kind`, `vendor`, `dedicated_memory_bytes: Option<u64>`,
    // `unified_memory_capable`, `capability_token`).
    // ------------------------------------------------------------------
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ComputeKind {
        Cpu,
        Gpu,
        Npu,
        Tpu,
        Fpga,
    }

    impl From<ComputeKindRaw> for ComputeKind {
        fn from(raw: ComputeKindRaw) -> Self {
            match raw {
                ComputeKindRaw::Cpu => Self::Cpu,
                ComputeKindRaw::Gpu => Self::Gpu,
                ComputeKindRaw::Npu => Self::Npu,
                ComputeKindRaw::Tpu => Self::Tpu,
                ComputeKindRaw::Fpga => Self::Fpga,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VendorId(pub u32);

    impl From<VendorIdRaw> for VendorId {
        fn from(raw: VendorIdRaw) -> Self {
            Self(raw.0)
        }
    }

    /// NOTE on `capability_token`: per 01-HAL-Layer.md section 5, HAL
    /// itself never mints Capability tokens — that is the microkernel's
    /// (layer 2) / Security Broker's (layer 4) job. At the point this
    /// dynamic manifest is built (Root Task startup, layer 3), a real
    /// Capability may or may not have been minted yet for a given
    /// device. We therefore keep `capability_token` as `Option` here
    /// rather than requiring one eagerly — the Root Task fills it in
    /// once it actually requests/receives the Capability for a device,
    /// via `set_capability_token` below. This crate does not define
    /// `CapabilityToken` itself (that type belongs to the microkernel's
    /// Capability model, layer 2) — it is generic over it.
    #[derive(Debug, Clone)]
    pub struct ComputeDevice<Cap> {
        pub kind: ComputeKind,
        pub vendor: VendorId,
        pub dedicated_memory_bytes: Option<u64>,
        pub unified_memory_capable: bool,
        pub bandwidth_to_cpu_mbps: u64,
        pub name: String,
        /// Index into the original raw manifest's compute_devices array;
        /// stable identity used when later requesting/attaching a real
        /// Capability for this exact device (see raw.rs,
        /// `ComputeDeviceRaw::device_index` doc comment).
        pub device_index: u32,
        pub capability_token: Option<Cap>,
    }

    impl<Cap> ComputeDevice<Cap> {
        fn from_raw(raw: &ComputeDeviceRaw) -> Self {
            let name_bytes = &raw.short_name[..raw.short_name_len as usize];
            // Raw short names are boot-time-local bytes, not guaranteed
            // valid UTF-8 by construction (though architecture code
            // should only ever write ASCII/UTF-8 into them). Lossy
            // conversion avoids a panic path here — this is
            // diagnostic/display data, not something correctness
            // depends on.
            let name = String::from_utf8_lossy(name_bytes).into_owned();

            Self {
                kind: raw.kind.into(),
                vendor: raw.vendor.into(),
                dedicated_memory_bytes: raw.has_dedicated_memory.then_some(raw.dedicated_memory_bytes),
                unified_memory_capable: raw.unified_memory_capable,
                bandwidth_to_cpu_mbps: raw.bandwidth_to_cpu_mbps,
                name,
                device_index: raw.device_index,
                capability_token: None,
            }
        }

        /// Attaches a real Capability token once the Root Task /
        /// Security Broker has minted one for this device. Per section
        /// 5: HAL only ever verifies tokens, never issues them — this
        /// setter exists purely for upper layers to populate the field
        /// after the fact.
        pub fn set_capability_token(&mut self, token: Cap) {
            self.capability_token = Some(token);
        }
    }

    // ------------------------------------------------------------------
    // Generic MMIO peripheral (dynamic) — see raw.rs's own module
    // comment on why this is separate from ComputeDevice.
    // ------------------------------------------------------------------
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PeripheralKind {
        Unknown,
        Block,
        Network,
        Gpu,
        Console,
    }

    impl From<PeripheralKindRaw> for PeripheralKind {
        fn from(raw: PeripheralKindRaw) -> Self {
            match raw {
                PeripheralKindRaw::Unknown => Self::Unknown,
                PeripheralKindRaw::Block => Self::Block,
                PeripheralKindRaw::Network => Self::Network,
                PeripheralKindRaw::Gpu => Self::Gpu,
                PeripheralKindRaw::Console => Self::Console,
            }
        }
    }

    /// Same `capability_token`/`device_index` contract as `ComputeDevice`
    /// — see that type's own doc comment.
    #[derive(Debug, Clone)]
    pub struct PeripheralDevice<Cap> {
        pub kind: PeripheralKind,
        pub mmio_base: u64,
        pub mmio_size: u64,
        pub irq: u32,
        pub device_index: u32,
        /// See `PeripheralDeviceRaw::config_space_base`'s own doc
        /// comment — `0` for a device with no PCI config space.
        pub config_space_base: u64,
        pub capability_token: Option<Cap>,
    }

    impl<Cap> PeripheralDevice<Cap> {
        fn from_raw(raw: &PeripheralDeviceRaw) -> Self {
            Self {
                kind: raw.kind.into(),
                mmio_base: raw.mmio_base,
                mmio_size: raw.mmio_size,
                irq: raw.irq,
                device_index: raw.device_index,
                config_space_base: raw.config_space_base,
                capability_token: None,
            }
        }

        /// Attaches a real Capability token — see `ComputeDevice::
        /// set_capability_token`'s own doc comment.
        pub fn set_capability_token(&mut self, token: Cap) {
            self.capability_token = Some(token);
        }
    }

    // ------------------------------------------------------------------
    // Interrupt controller / Timer info (dynamic) — no variable-length
    // data, kept as direct mirrors of the raw types for a stable public
    // API surface independent of the raw wire format.
    // ------------------------------------------------------------------
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum InterruptControllerKind {
        ApicXapic,
        ApicX2apic,
        Gicv3,
        Gicv4,
        PlicClic,
    }

    impl From<InterruptControllerKindRaw> for InterruptControllerKind {
        fn from(raw: InterruptControllerKindRaw) -> Self {
            match raw {
                InterruptControllerKindRaw::ApicXapic => Self::ApicXapic,
                InterruptControllerKindRaw::ApicX2apic => Self::ApicX2apic,
                InterruptControllerKindRaw::Gicv3 => Self::Gicv3,
                InterruptControllerKindRaw::Gicv4 => Self::Gicv4,
                InterruptControllerKindRaw::PlicClic => Self::PlicClic,
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct InterruptControllerInfo {
        pub kind: InterruptControllerKind,
        pub primary_base: u64,
        pub secondary_base: Option<u64>,
        pub irq_line_count: u32,
        pub ipi_target_core_count: u32,
    }

    impl From<InterruptControllerInfoRaw> for InterruptControllerInfo {
        fn from(raw: InterruptControllerInfoRaw) -> Self {
            Self {
                kind: raw.kind.into(),
                primary_base: raw.primary_base,
                secondary_base: raw.has_secondary.then_some(raw.secondary_base),
                irq_line_count: raw.irq_line_count,
                ipi_target_core_count: raw.ipi_target_core_count,
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TimerKind {
        Tsc,
        Hpet,
        ArmGenericTimer,
        RiscvSbiTimer,
    }

    impl From<TimerKindRaw> for TimerKind {
        fn from(raw: TimerKindRaw) -> Self {
            match raw {
                TimerKindRaw::Tsc => Self::Tsc,
                TimerKindRaw::Hpet => Self::Hpet,
                TimerKindRaw::ArmGenericTimer => Self::ArmGenericTimer,
                TimerKindRaw::RiscvSbiTimer => Self::RiscvSbiTimer,
            }
        }
    }

    #[derive(Debug, Clone, Copy)]
    pub struct TimerInfo {
        pub kind: TimerKind,
        pub frequency_hz: u64,
        pub supports_tickless: bool,
    }

    impl From<TimerInfoRaw> for TimerInfo {
        fn from(raw: TimerInfoRaw) -> Self {
            Self {
                kind: raw.kind.into(),
                frequency_hz: raw.frequency_hz,
                supports_tickless: raw.supports_tickless,
            }
        }
    }

    // ------------------------------------------------------------------
    // Power domain (dynamic)
    // ------------------------------------------------------------------
    #[derive(Debug, Clone, Copy)]
    pub struct PowerDomain {
        pub domain_id: u32,
        /// `None` if this domain is not tied to one specific compute
        /// device (whole-package/platform-level domain). See
        /// `PowerDomainRaw::NO_ASSOCIATED_DEVICE`.
        pub associated_compute_device_index: Option<u32>,
        pub supports_dvfs: bool,
        pub has_thermal_sensor: bool,
    }

    impl From<PowerDomainRaw> for PowerDomain {
        fn from(raw: PowerDomainRaw) -> Self {
            let associated = if raw.associated_compute_device_index
                == PowerDomainRaw::NO_ASSOCIATED_DEVICE
            {
                None
            } else {
                Some(raw.associated_compute_device_index)
            };
            Self {
                domain_id: raw.domain_id,
                associated_compute_device_index: associated,
                supports_dvfs: raw.supports_dvfs,
                has_thermal_sensor: raw.has_thermal_sensor,
            }
        }
    }

    // ------------------------------------------------------------------
    // Top-level dynamic manifest — matches 01-HAL-Layer.md section 4's
    // `HardwareManifest` struct shape (cpu, memory_regions,
    // compute_devices, interrupt_controller, timer, power_domains).
    //
    // Generic over `Cap` (the Capability token type) rather than
    // depending on the microkernel's Capability model directly: layer 1
    // must not depend on layer 2's crates (see 01-HAL-Layer.md section
    // 0 — the dependency direction is HAL -> linked directly into the
    // kernel binary, not the other way around). Layer 3 code, which
    // does depend on the microkernel's `kernel-cap` crate, instantiates
    // this as `HardwareManifest<kernel_cap::Capability>` (or similar)
    // once it has that type available.
    // ------------------------------------------------------------------
    #[derive(Debug, Clone)]
    pub struct HardwareManifest<Cap> {
        pub cpu: CpuInfo,
        pub memory_regions: Vec<MemoryRegion>,
        pub compute_devices: Vec<ComputeDevice<Cap>>,
        pub peripheral_devices: Vec<PeripheralDevice<Cap>>,
        pub interrupt_controller: InterruptControllerInfo,
        pub timer: TimerInfo,
        pub power_domains: Vec<PowerDomain>,
    }

    impl<Cap> HardwareManifest<Cap> {
        /// Converts the boot-time, fixed-size `HardwareManifestRaw`
        /// into this dynamic, heap-backed representation.
        ///
        /// Per section 9: this conversion happens exactly once, right
        /// after the Root Task comes up and a heap allocator is
        /// available — from that point on, upper layers work
        /// exclusively with this type and never touch
        /// `HardwareManifestRaw` again.
        pub fn from_raw(raw: &HardwareManifestRaw) -> Self {
            let memory_regions = raw
                .memory_regions()
                .iter()
                .copied()
                .map(MemoryRegion::from)
                .collect();

            let compute_devices = raw
                .compute_devices()
                .iter()
                .map(ComputeDevice::from_raw)
                .collect();

            let peripheral_devices = raw
                .peripheral_devices()
                .iter()
                .map(PeripheralDevice::from_raw)
                .collect();

            let power_domains = raw
                .power_domains()
                .iter()
                .copied()
                .map(PowerDomain::from)
                .collect();

            Self {
                cpu: CpuInfo {
                    core_count: raw.cpu_core_count as usize,
                    feature_flags: CpuFeatureFlags(raw.cpu_feature_flags),
                },
                memory_regions,
                compute_devices,
                peripheral_devices,
                interrupt_controller: raw.interrupt_controller.into(),
                timer: raw.timer.into(),
                power_domains,
            }
        }

        /// Total usable physical memory, in bytes, across all regions
        /// marked `MemoryRegionKind::Usable`. Convenience accessor for
        /// upper layers (e.g. Root Task deciding how to carve up
        /// `UntypedMemory` per 02-Microkernel-Layer.md, section 3).
        pub fn total_usable_memory_bytes(&self) -> u64 {
            self.memory_regions
                .iter()
                .filter(|r| r.kind == MemoryRegionKind::Usable)
                .map(|r| r.length_bytes)
                .sum()
        }

        /// Returns all compute devices of a given kind. Convenience
        /// accessor for Profile Policy (layer 4) deciding, e.g., whether
        /// an NPU is present before enabling the AI profile's default
        /// services (04-System-Services-Policy-Layer.md, section 6).
        pub fn compute_devices_of_kind(&self, kind: ComputeKind) -> impl Iterator<Item = &ComputeDevice<Cap>> {
            self.compute_devices.iter().filter(move |d| d.kind == kind)
        }
    }
}

#[cfg(feature = "alloc")]
pub use dynamic::*;

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::raw::*;
    use super::*;

    fn sample_raw() -> HardwareManifestRaw {
        let mut m = HardwareManifestRaw::zeroed();
        m.cpu_core_count = 8;
        m.cpu_feature_flags = 0b1011;

        // `::new` rather than struct-literal + `..ZERO`: `MemoryRegionRaw`'s
        // `_reserved` padding field is private to the `raw` module, so
        // functional record update from here is E0451 — same reason the
        // arch crates construct these via `::new`.
        m.push_memory_region(MemoryRegionRaw::new(
            0,
            0x1000_0000,
            MemoryRegionKindRaw::Usable,
            false,
        ))
        .unwrap();

        let mut gpu = ComputeDeviceRaw::ZERO;
        gpu.kind = ComputeKindRaw::Gpu;
        gpu.vendor = VendorIdRaw(0x10DE);
        gpu.has_dedicated_memory = true;
        gpu.dedicated_memory_bytes = 8 * 1024 * 1024 * 1024;
        gpu.unified_memory_capable = true;
        let name = b"TestGPU";
        gpu.short_name[..name.len()].copy_from_slice(name);
        gpu.short_name_len = name.len() as u8;
        m.push_compute_device(gpu).unwrap();

        m.push_peripheral_device(PeripheralDeviceRaw::new(
            PeripheralKindRaw::Block,
            0x1000_1000,
            0x1000,
            1,
        ))
        .unwrap();

        m
    }

    #[test]
    fn converts_raw_to_dynamic_correctly() {
        let raw = sample_raw();
        let dyn_manifest: HardwareManifest<()> = HardwareManifest::from_raw(&raw);

        assert_eq!(dyn_manifest.cpu.core_count, 8);
        assert_eq!(dyn_manifest.memory_regions.len(), 1);
        assert_eq!(dyn_manifest.total_usable_memory_bytes(), 0x1000_0000);

        assert_eq!(dyn_manifest.compute_devices.len(), 1);
        let gpu = &dyn_manifest.compute_devices[0];
        assert_eq!(gpu.kind, ComputeKind::Gpu);
        assert_eq!(gpu.vendor, VendorId(0x10DE));
        assert_eq!(gpu.dedicated_memory_bytes, Some(8 * 1024 * 1024 * 1024));
        assert!(gpu.unified_memory_capable);
        assert_eq!(gpu.name, "TestGPU");
        assert!(gpu.capability_token.is_none());

        assert_eq!(dyn_manifest.peripheral_devices.len(), 1);
        let blk = &dyn_manifest.peripheral_devices[0];
        assert_eq!(blk.kind, PeripheralKind::Block);
        assert_eq!(blk.mmio_base, 0x1000_1000);
        assert_eq!(blk.mmio_size, 0x1000);
        assert_eq!(blk.irq, 1);
        assert!(blk.capability_token.is_none());
    }

    #[test]
    fn set_capability_token_populates_field() {
        let raw = sample_raw();
        let mut dyn_manifest: HardwareManifest<u64> = HardwareManifest::from_raw(&raw);
        dyn_manifest.compute_devices[0].set_capability_token(42);
        assert_eq!(dyn_manifest.compute_devices[0].capability_token, Some(42));
    }

    #[test]
    fn compute_devices_of_kind_filters_correctly() {
        let raw = sample_raw();
        let dyn_manifest: HardwareManifest<()> = HardwareManifest::from_raw(&raw);
        assert_eq!(dyn_manifest.compute_devices_of_kind(ComputeKind::Gpu).count(), 1);
        assert_eq!(dyn_manifest.compute_devices_of_kind(ComputeKind::Npu).count(), 0);
    }
}