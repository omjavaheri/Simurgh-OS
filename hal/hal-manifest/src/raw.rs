//! ============================================================================
//! raw.rs
//!
//! The `#[repr(C)]`, no-heap representation of the Hardware Manifest.
//!
//! Per 01-HAL-Layer.md, section 9 ("Final decision: Hardware Manifest
//! format"): this structure is used ONLY for the boot-time handoff from
//! HAL (layer 1) to the Root Task (layer 2/3), because at that point in
//! time NO real heap allocator exists yet. Every field is therefore:
//!   - fixed-size (no `Vec`, no `String`, no `Box`)
//!   - `Copy` (so it can be memcpy'd across the HAL -> kernel boundary
//!     without invoking any allocator or drop glue)
//!   - deterministic in size at compile time
//!
//! Once the Root Task is up and a heap is available (layer 3 onward),
//! this raw struct is converted into the dynamic, `Vec`-based
//! `HardwareManifest` defined in `lib.rs` (feature = "alloc"). The
//! fixed-size limits below (MAX_MEMORY_REGIONS, etc.) apply ONLY at this
//! lowest boot-time point of the system, not to the architecture as a
//! whole (see 01-HAL-Layer.md, section 9, closing paragraph).
//! ============================================================================

#![allow(clippy::upper_case_acronyms)]

// ----------------------------------------------------------------------------
// Fixed capacity limits for the boot-time transfer format.
//
// These numbers are deliberately generous for real-world hardware (a
// server-class NUMA machine rarely exceeds a few dozen memory regions
// reported by UEFI/e820, and 32 heterogeneous compute devices already
// covers multi-GPU + multi-NPU setups) while keeping the struct small
// enough to live comfortably on the boot stack before any heap exists.
// ----------------------------------------------------------------------------
pub const MAX_MEMORY_REGIONS: usize = 64;
pub const MAX_COMPUTE_DEVICES: usize = 32;
pub const MAX_POWER_DOMAINS: usize = 16;
/// Matches QEMU's aarch64 `virt` machine's own virtio-mmio slot count (32
/// — confirmed via a device-tree dump of this project's own pinned QEMU
/// version), the largest of the platforms this discovers today; riscv64
/// `virt` exposes only 8.
pub const MAX_PERIPHERAL_DEVICES: usize = 32;

/// Max length for short fixed-width identifier strings embedded in the raw
/// manifest (e.g. a compute device's human-readable model name fragment).
/// Kept short and UTF-8-agnostic (raw bytes) since this crate cannot use
/// `alloc::String` in its no_std/no_alloc configuration.
pub const SHORT_NAME_MAX_LEN: usize = 32;

// ============================================================================
// CPU-related raw types
// ============================================================================

/// Which privilege level abstraction applies. Mirrors the three privilege
/// models described in 01-HAL-Layer.md section 3.1 (Ring 0/3 for x86_64,
/// EL0-EL3 for ARM64, M/S/U-mode for RISC-V) behind one architecture-
/// independent enum, so nothing above layer 1 needs `#[cfg(target_arch)]`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeLevelRaw {
    /// Highest privilege (Ring 0 / EL1 / M-mode boot context before drop
    /// to a lower level, or EL2/S-mode where applicable).
    Kernel = 0,
    /// Unprivileged (Ring 3 / EL0 / U-mode) — user-space, layers 3-5.
    User = 1,
    /// Hypervisor/monitor level, only meaningful on ARM64 (EL2) and
    /// RISC-V (M-mode as a distinct boot stage). Unused on x86_64.
    Monitor = 2,
}

// ============================================================================
// Memory region raw type (section 3.2 — Memory Bootstrap)
// ============================================================================

/// Classification of a physical memory region as reported by firmware
/// (UEFI Memory Map / e820 on x86_64, Device Tree or ACPI on ARM64,
/// Device Tree on RISC-V per section 3.2).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryRegionKindRaw {
    /// Normal RAM, free for general allocation once the Root Task's
    /// allocator is initialized.
    Usable = 0,
    /// Reserved by firmware; must never be allocated from.
    Reserved = 1,
    /// ACPI tables that can be reclaimed after the OS has parsed them.
    AcpiReclaimable = 2,
    /// ACPI NVS (Non-Volatile Storage); must be preserved across sleep
    /// states, never allocated from.
    AcpiNvs = 3,
    /// Memory-mapped I/O region (device registers), not general RAM.
    Mmio = 4,
    /// Region occupied by the HAL/kernel image itself at boot time.
    KernelImage = 5,
    /// Region occupied by the boot-time structures (page tables, boot
    /// info, this very manifest) that the Root Task must not overwrite
    /// until it has copied/consumed them.
    BootReserved = 6,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegionRaw {
    pub base_addr: u64,
    pub length_bytes: u64,
    pub kind: MemoryRegionKindRaw,
    /// True if this region sits behind an IOMMU/SMMU/IOPMP translation
    /// (see section 3.2, "Abstraction یکسان برای MMU/IOMMU"). Upper
    /// layers use this to decide whether DMA from a device targeting
    /// this region needs an IOMMU mapping first.
    pub behind_iommu: bool,
    /// Padding kept explicit (rather than relying on compiler-inserted
    /// padding) so the raw struct's layout is documented and stable
    /// across compiler versions, per the "deterministic size" goal of
    /// section 9.
    _reserved: [u8; 6],
}

impl MemoryRegionRaw {
    pub const ZERO: Self = Self {
        base_addr: 0,
        length_bytes: 0,
        kind: MemoryRegionKindRaw::Reserved,
        behind_iommu: false,
        _reserved: [0; 6],
    };
    pub fn new(
        base_addr: u64,
        length_bytes: u64,
        kind: MemoryRegionKindRaw,
        behind_iommu: bool,
    ) -> Self {
        Self {
            base_addr,
            length_bytes,
            kind,
            behind_iommu,
            _reserved: [0; 6],
        }
    }
}

// ============================================================================
// Heterogeneous compute device raw type (section 3.6)
// ============================================================================

/// First-class compute unit kind. Per section 3.6, GPU/NPU/TPU/FPGA are
/// treated as first-class entity types, not generic PCI devices.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputeKindRaw {
    Cpu = 0,
    Gpu = 1,
    Npu = 2,
    Tpu = 3,
    Fpga = 4,
}

/// PCI-SIG-style vendor identifier (or a project-defined synthetic ID for
/// non-PCI devices such as an SoC-integrated NPU discovered via Device
/// Tree). Kept as a plain newtype so raw.rs has no dependency on any PCI
/// crate.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorIdRaw(pub u32);

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ComputeDeviceRaw {
    pub kind: ComputeKindRaw,
    _pad0: [u8; 3],
    pub vendor: VendorIdRaw,

    /// Whether `dedicated_memory_bytes` below is meaningful. Rust's
    /// `Option<u64>` is not used here because this struct must stay
    /// `#[repr(C)]` with a fully deterministic, FFI-stable layout — an
    /// explicit presence flag is clearer and more portable than relying
    /// on niche-filling optimizations.
    pub has_dedicated_memory: bool,
    _pad1: [u8; 7],
    pub dedicated_memory_bytes: u64,

    /// CXL / vendor-specific unified memory support (section 3.6).
    pub unified_memory_capable: bool,
    _pad2: [u8; 7],

    /// Approximate link bandwidth to the CPU, in megabytes/second, as
    /// reported by firmware/topology data. Zero means "unknown".
    pub bandwidth_to_cpu_mbps: u64,

    /// A short, boot-time-only identifying string (e.g. a truncated
    /// model name), stored as raw bytes since `alloc::String` is not
    /// available in this no-heap struct. Not guaranteed NUL-terminated;
    /// consumers must use `name_len` to know the valid prefix.
    pub short_name: [u8; SHORT_NAME_MAX_LEN],
    pub short_name_len: u8,
    _pad3: [u8; 7],

    /// Opaque device index (NOT a real Capability). Capability tokens
    /// for compute devices are minted later by the microkernel (layer 2)
    /// once its Capability model is initialized — HAL discovery happens
    /// before that subsystem exists (see 01-HAL-Layer.md, section 5:
    /// "HAL فقط توکن را verify می‌کند... صدور این token مسئولیت
    /// Security/Permission Broker در لایه ۴ است"). This index is what
    /// the Root Task uses to look up the device again when it later
    /// requests a real Capability for it.
    pub device_index: u32,
    _pad4: [u8; 4],
}

impl ComputeDeviceRaw {
    pub const ZERO: Self = Self {
        kind: ComputeKindRaw::Cpu,
        _pad0: [0; 3],
        vendor: VendorIdRaw(0),
        has_dedicated_memory: false,
        _pad1: [0; 7],
        dedicated_memory_bytes: 0,
        unified_memory_capable: false,
        _pad2: [0; 7],
        bandwidth_to_cpu_mbps: 0,
        short_name: [0; SHORT_NAME_MAX_LEN],
        short_name_len: 0,
        _pad3: [0; 7],
        device_index: 0,
        _pad4: [0; 4],
    };
}

// ============================================================================
// Generic MMIO peripheral raw type
//
// Deliberately NOT part of `ComputeDeviceRaw`/`ComputeKindRaw` above:
// section 3.6 explicitly frames those as GPU/NPU/TPU/FPGA "first-class
// compute entities... distinct from ordinary peripherals" — a block-
// storage or network transport is exactly that "ordinary peripheral"
// case, so it gets its own discovery surface rather than stretching
// "compute" to cover it. Not named in any HAL-Layer.md section (§11's
// own "nothing open in this layer... record new decisions as they
// arise" note applies here): virtio-mmio device discovery for the
// project's own MVP acceptance driver (03-Kernel-Subsystems-Layer.md
// §5.1's virtio-blk), the first consumer of this new surface.
// ============================================================================

/// What kind of peripheral this MMIO transport carries, per the virtio
/// spec's own `device_id` register (virtio 1.x §2.1) — kept as this
/// project's own small, extensible enum (not the raw virtio device_id
/// integer) so upper layers never need to know virtio's own numbering.
/// Only the MVP acceptance kind (`Block`) is actually driven by a real
/// driver today (`subsystems/drivers/driver-virtio-blk`); the rest are
/// discovered (so the manifest is complete regardless of what layer 3
/// currently uses, matching section 2's Discovery+Policy split) but
/// have no driver yet.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeripheralKindRaw {
    /// virtio device_id not recognised, or a non-virtio peripheral a
    /// future discovery mechanism (e.g. x86_64 PCI enumeration) reports.
    Unknown = 0,
    /// virtio-blk (`device_id` = 2) — 03-Kernel-Subsystems-Layer.md
    /// §5.1's MVP acceptance driver.
    Block = 1,
    /// virtio-net (`device_id` = 1) — `03 §2.3`'s netstack bypass path.
    Network = 2,
    /// virtio-gpu (`device_id` = 16) — `03 §2.4`'s compositor, future.
    Gpu = 3,
    /// virtio-console (`device_id` = 3).
    Console = 4,
}

/// One discovered MMIO-transport peripheral (virtio-mmio on QEMU's
/// `virt` machines today — see `PeripheralKindRaw`'s own doc comment).
/// Pure description data, same "boot-time-only, no Capability minted
/// here" contract `ComputeDeviceRaw` documents: `device_index` is what
/// the Root Task uses to request a real Capability for this exact
/// device later (01-HAL-Layer.md section 5).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PeripheralDeviceRaw {
    pub kind: PeripheralKindRaw,
    _pad0: [u8; 7],

    /// MMIO register window base (physical address).
    pub mmio_base: u64,
    /// MMIO register window size, in bytes.
    pub mmio_size: u64,
    /// Interrupt line this device signals completion on — an
    /// architecture-erased, platform-numbered IRQ id (PLIC interrupt
    /// source number on riscv64, GIC INTID on aarch64 — NOT a raw SPI
    /// number; see each `hal-<arch>`'s own discovery code for the
    /// conversion), consumed the same way `InterruptControllerInfoRaw`'s
    /// own `irq_line_count` numbering already is.
    pub irq: u32,

    /// Opaque device index — same contract as `ComputeDeviceRaw::
    /// device_index`.
    pub device_index: u32,

    /// PCI Configuration Space physical address (ECAM: `ecam_base +
    /// ecam_offset(bus, device, function)` — see `hal_arm64::compute::
    /// ecam_offset`'s own doc comment for the formula), `0` for devices
    /// with no PCI config space at all (e.g. riscv64's virtio-mmio
    /// transport, discovered via Device Tree, not PCI). A modern
    /// virtio-pci device's driver walks this device's OWN capability
    /// list starting here (spec §4.1.4) to locate its COMMON_CFG/
    /// NOTIFY_CFG/ISR_CFG/DEVICE_CFG sub-regions — `mmio_base`/
    /// `mmio_size` above name the BAR those sub-regions live within
    /// (QEMU's own `virtio-pci-modern` convention: BAR4, all four
    /// regions in one window), not the config space itself.
    pub config_space_base: u64,
}

impl PeripheralDeviceRaw {
    pub const ZERO: Self = Self {
        kind: PeripheralKindRaw::Unknown,
        _pad0: [0; 7],
        mmio_base: 0,
        mmio_size: 0,
        irq: 0,
        device_index: 0,
        config_space_base: 0,
    };
    pub fn new(kind: PeripheralKindRaw, mmio_base: u64, mmio_size: u64, irq: u32) -> Self {
        Self {
            kind,
            _pad0: [0; 7],
            mmio_base,
            mmio_size,
            irq,
            device_index: 0,
            config_space_base: 0,
        }
    }

    /// Like `new`, but also names the PCI Configuration Space physical
    /// address — for a virtio-pci device, where `mmio_base` alone
    /// (a BAR) is not enough for the driver to even START capability-
    /// list negotiation (see `config_space_base`'s own doc comment).
    pub fn new_pci(
        kind: PeripheralKindRaw,
        mmio_base: u64,
        mmio_size: u64,
        irq: u32,
        config_space_base: u64,
    ) -> Self {
        Self {
            config_space_base,
            ..Self::new(kind, mmio_base, mmio_size, irq)
        }
    }
}

// ============================================================================
// Interrupt controller raw type (section 3.4)
// ============================================================================

/// Which hardware interrupt controller family was detected, unified
/// behind one API per section 3.4 (APIC/x2APIC, GICv3/v4, PLIC+CLIC).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterruptControllerKindRaw {
    ApicXapic = 0,
    ApicX2apic = 1,
    Gicv3 = 2,
    Gicv4 = 3,
    /// RISC-V pairs a PLIC (external interrupts) with a CLIC (fast
    /// local/vectored interrupts); both are reported together since
    /// section 3.4 treats them as one unified abstraction on RISC-V.
    PlicClic = 4,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InterruptControllerInfoRaw {
    pub kind: InterruptControllerKindRaw,
    _pad0: [u8; 7],

    /// Primary MMIO/register base address (GIC distributor base, PLIC
    /// base, etc.). Zero / unused for MSR-based x2APIC.
    pub primary_base: u64,

    /// Secondary MMIO base, used when the controller needs a second
    /// region (e.g. GIC redistributor base, separate from the
    /// distributor). `has_secondary` indicates whether this is valid.
    pub has_secondary: bool,
    _pad1: [u8; 7],
    pub secondary_base: u64,

    /// Total number of distinct IRQ lines this controller exposes,
    /// used by upper layers to size their IRQ routing tables.
    pub irq_line_count: u32,

    /// Number of physical CPU cores this controller can target with an
    /// inter-processor interrupt (`send_ipi`, section 3.4).
    pub ipi_target_core_count: u32,
}

impl InterruptControllerInfoRaw {
    pub const ZERO: Self = Self {
        kind: InterruptControllerKindRaw::ApicXapic,
        _pad0: [0; 7],
        primary_base: 0,
        has_secondary: false,
        _pad1: [0; 7],
        secondary_base: 0,
        irq_line_count: 0,
        ipi_target_core_count: 0,
    };
    pub fn new(
        kind: InterruptControllerKindRaw,
        primary_base: u64,
        has_secondary: bool,
        secondary_base: u64,
        irq_line_count: u32,
        ipi_target_core_count: u32,
    ) -> Self {
        Self {
            kind,
            _pad0: [0; 7],
            primary_base,
            has_secondary,
            _pad1: [0; 7],
            secondary_base,
            irq_line_count,
            ipi_target_core_count,
        }
    }
}

// ============================================================================
// Timer raw type (section 3.3)
// ============================================================================

/// Which hardware timer source was detected, per section 3.3:
/// TSC/HPET (x86_64), Generic Timer (ARM64), mtime/mtimecmp via SBI
/// (RISC-V).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerKindRaw {
    Tsc = 0,
    Hpet = 1,
    ArmGenericTimer = 2,
    RiscvSbiTimer = 3,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct TimerInfoRaw {
    pub kind: TimerKindRaw,
    _pad0: [u8; 7],

    /// Timer tick frequency in Hz, used to convert raw ticks to
    /// nanoseconds (`TimerAbstraction::now_ns`, section 4).
    pub frequency_hz: u64,

    /// Whether this timer source supports true tickless/high-resolution
    /// mode (section 3.3: "High-resolution / tickless برای AI batch
    /// workload"). If false, only the interactive-tick mode is
    /// available and the Throughput scheduler mode (layer 2, section
    /// 4.1) must fall back to periodic ticks.
    pub supports_tickless: bool,
    _pad1: [u8; 7],
}

impl TimerInfoRaw {
    pub const ZERO: Self = Self {
        kind: TimerKindRaw::Tsc,
        _pad0: [0; 7],
        frequency_hz: 0,
        supports_tickless: false,
        _pad1: [0; 7],
    };
    pub fn new(kind: TimerKindRaw, frequency_hz: u64, supports_tickless: bool) -> Self {
        Self {
            kind,
            _pad0: [0; 7],
            frequency_hz,
            supports_tickless,
            _pad1: [0; 7],
        }
    }
}

// ============================================================================
// Power domain raw type (section 3.7)
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PowerDomainRaw {
    /// Opaque, boot-time-local identifier for this power domain
    /// (e.g. "CPU package 0", "GPU 0", "SoC thermal zone 2").
    pub domain_id: u32,

    /// Index into `compute_devices` this domain is associated with, or
    /// `u32::MAX` if this domain is not tied to a single compute device
    /// (e.g. a whole-package or platform-level domain). Per section
    /// 3.7: "برای هر واحد پردازشی به‌طور جدا (نه فقط CPU بلکه GPU/NPU
    /// هم)".
    pub associated_compute_device_index: u32,

    /// Whether DVFS (Dynamic Voltage Frequency Scaling) can be queried
    /// and set for this domain.
    pub supports_dvfs: bool,
    _pad0: [u8; 3],

    /// Whether a temperature sensor is available for this domain
    /// (section 3.7: "گزارش دمای هر واحد").
    pub has_thermal_sensor: bool,
    _pad1: [u8; 3],
}

impl PowerDomainRaw {
    /// Sentinel meaning "not associated with any specific compute
    /// device" for `associated_compute_device_index`.
    pub const NO_ASSOCIATED_DEVICE: u32 = u32::MAX;

    pub const ZERO: Self = Self {
        domain_id: 0,
        associated_compute_device_index: Self::NO_ASSOCIATED_DEVICE,
        supports_dvfs: false,
        _pad0: [0; 3],
        has_thermal_sensor: false,
        _pad1: [0; 3],
    };
    pub fn new(
        domain_id: u32,
        associated_compute_device_index: u32,
        supports_dvfs: bool,
        has_thermal_sensor: bool,
    ) -> Self {
        Self {
            domain_id,
            associated_compute_device_index,
            supports_dvfs,
            _pad0: [0; 3],
            has_thermal_sensor,
            _pad1: [0; 3],
        }
    }
}

// ============================================================================
// Top-level raw manifest (section 9 — exact structure from the spec)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy)]
pub struct HardwareManifestRaw {
    pub cpu_core_count: u32,
    pub cpu_feature_flags: u64,

    pub memory_region_count: u32,
    pub memory_regions: [MemoryRegionRaw; MAX_MEMORY_REGIONS],

    pub compute_device_count: u32,
    pub compute_devices: [ComputeDeviceRaw; MAX_COMPUTE_DEVICES],

    pub peripheral_device_count: u32,
    pub peripheral_devices: [PeripheralDeviceRaw; MAX_PERIPHERAL_DEVICES],

    pub interrupt_controller: InterruptControllerInfoRaw,
    pub timer: TimerInfoRaw,

    pub power_domain_count: u32,
    pub power_domains: [PowerDomainRaw; MAX_POWER_DOMAINS],
}

impl HardwareManifestRaw {
    /// A fully zeroed manifest. Used as the starting point during boot:
    /// each `hal-<arch>` implementation fills in fields as it discovers
    /// hardware, then hands the completed struct to the Root Task.
    ///
    /// Deliberately NOT derived via `#[derive(Default)]`: `Default` is
    /// only implemented by core for fixed-size arrays up to length 32,
    /// and `MAX_MEMORY_REGIONS` (64) exceeds that. Building the zeroed
    /// value from each field's own `ZERO` const keeps this both
    /// portable and free of any `unsafe` zeroing.
    pub const fn zeroed() -> Self {
        Self {
            cpu_core_count: 0,
            cpu_feature_flags: 0,
            memory_region_count: 0,
            memory_regions: [MemoryRegionRaw::ZERO; MAX_MEMORY_REGIONS],
            compute_device_count: 0,
            compute_devices: [ComputeDeviceRaw::ZERO; MAX_COMPUTE_DEVICES],
            peripheral_device_count: 0,
            peripheral_devices: [PeripheralDeviceRaw::ZERO; MAX_PERIPHERAL_DEVICES],
            interrupt_controller: InterruptControllerInfoRaw::ZERO,
            timer: TimerInfoRaw::ZERO,
            power_domain_count: 0,
            power_domains: [PowerDomainRaw::ZERO; MAX_POWER_DOMAINS],
        }
    }

    /// Returns the populated slice of memory regions, ignoring unused
    /// trailing capacity. Callers above layer 1 should always go
    /// through this rather than indexing `memory_regions` directly,
    /// since the count is authoritative and the array itself may
    /// contain stale/zeroed entries past `memory_region_count`.
    pub fn memory_regions(&self) -> &[MemoryRegionRaw] {
        &self.memory_regions[..self.memory_region_count as usize]
    }

    /// Returns the populated slice of compute devices. See
    /// `memory_regions()` for why this accessor exists instead of
    /// exposing the raw fixed array directly.
    pub fn compute_devices(&self) -> &[ComputeDeviceRaw] {
        &self.compute_devices[..self.compute_device_count as usize]
    }

    /// Returns the populated slice of peripheral devices. See
    /// `memory_regions()` for why this accessor exists instead of
    /// exposing the raw fixed array directly.
    pub fn peripheral_devices(&self) -> &[PeripheralDeviceRaw] {
        &self.peripheral_devices[..self.peripheral_device_count as usize]
    }

    /// Returns the populated slice of power domains.
    pub fn power_domains(&self) -> &[PowerDomainRaw] {
        &self.power_domains[..self.power_domain_count as usize]
    }

    /// Appends a memory region, per architecture discovery code
    /// (`hal-x86_64::memory`, `hal-arm64::memory`, `hal-riscv64::memory`).
    /// Returns `Err(())` if `MAX_MEMORY_REGIONS` capacity is exceeded —
    /// callers at this boot-time stage have no allocator to fall back
    /// to, so this is a hard capacity error the architecture code must
    /// handle (typically by logging over serial and continuing with a
    /// truncated but still-usable manifest, since a boot-time panic
    /// over a rare extra firmware-reported region is worse than
    /// dropping the least-important entries).
    pub fn push_memory_region(&mut self, region: MemoryRegionRaw) -> Result<(), ()> {
        let idx = self.memory_region_count as usize;
        if idx >= MAX_MEMORY_REGIONS {
            return Err(());
        }
        self.memory_regions[idx] = region;
        self.memory_region_count += 1;
        Ok(())
    }

    /// Appends a compute device. See `push_memory_region` for the
    /// capacity-error handling rationale.
    pub fn push_compute_device(&mut self, mut device: ComputeDeviceRaw) -> Result<(), ()> {
        let idx = self.compute_device_count as usize;
        if idx >= MAX_COMPUTE_DEVICES {
            return Err(());
        }
        // The device's own index must match its final slot so that
        // later Capability-minting (layer 2/4) can address it
        // unambiguously by index (see ComputeDeviceRaw::device_index
        // doc comment above).
        device.device_index = idx as u32;
        self.compute_devices[idx] = device;
        self.compute_device_count += 1;
        Ok(())
    }

    /// Appends a peripheral device. Same capacity-error handling and
    /// device_index-assignment rationale as `push_compute_device`.
    pub fn push_peripheral_device(&mut self, mut device: PeripheralDeviceRaw) -> Result<(), ()> {
        let idx = self.peripheral_device_count as usize;
        if idx >= MAX_PERIPHERAL_DEVICES {
            return Err(());
        }
        device.device_index = idx as u32;
        self.peripheral_devices[idx] = device;
        self.peripheral_device_count += 1;
        Ok(())
    }

    /// Appends a power domain. See `push_memory_region` for the
    /// capacity-error handling rationale.
    pub fn push_power_domain(&mut self, domain: PowerDomainRaw) -> Result<(), ()> {
        let idx = self.power_domain_count as usize;
        if idx >= MAX_POWER_DOMAINS {
            return Err(());
        }
        self.power_domains[idx] = domain;
        self.power_domain_count += 1;
        Ok(())
    }
}

// ============================================================================
// Compile-time sanity checks
//
// These `const` assertions catch, at compile time, any accidental
// change to a Raw type's field layout that would silently break the
// HAL -> Root Task boot-time handoff (which relies on both sides
// agreeing on the exact byte layout of this struct — see section 9).
// ============================================================================
const _: () = {
    // The struct must be `Copy` and contain no padding-sensitive
    // surprises; asserting a concrete size here means any future field
    // addition/removal is a deliberate, visible change to this
    // constant rather than a silent ABI shift.
    // MemoryRegionRaw: base_addr(8) + length_bytes(8) + kind(1) + behind_iommu(1) + _reserved(6) = 24
    assert!(core::mem::size_of::<MemoryRegionRaw>() == 24);
    // ComputeDeviceRaw: 
    // kind(1) + _pad0(3) + vendor(4) + has_dedicated_memory(1) + _pad1(7) + 
    // dedicated_memory_bytes(8) + unified_memory_capable(1) + _pad2(7) + 
    // bandwidth_to_cpu_mbps(8) + short_name(32) + short_name_len(1) + _pad3(7) + 
    // device_index(4) + _pad4(4) = 88
    assert!(core::mem::size_of::<ComputeDeviceRaw>() == 88);
    // InterruptControllerInfoRaw: 
    // kind(1) + _pad0(7) + primary_base(8) + has_secondary(1) + _pad1(7) + 
    // secondary_base(8) + irq_line_count(4) + ipi_target_core_count(4) = 40
    assert!(core::mem::size_of::<InterruptControllerInfoRaw>() == 40);
    // TimerInfoRaw: 
    // kind(1) + _pad0(7) + frequency_hz(8) + supports_tickless(1) + _pad1(7) = 24
    assert!(core::mem::size_of::<TimerInfoRaw>() == 24);
    // PowerDomainRaw: 
    // domain_id(4) + associated_compute_device_index(4) + supports_dvfs(1) + 
    // _pad0(3) + has_thermal_sensor(1) + _pad1(3) = 16
    // The struct should remain 16 bytes: two u32s (8) + two bools (2) + two 3-byte pads (6) = 16
    assert!(core::mem::size_of::<PowerDomainRaw>() == 16);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// This test runs on the host target (see workspace
    /// default-members), not on any no_std architecture target — it
    /// exercises the pure data-layout logic that is architecture-
    /// independent.
    #[test]
    fn zeroed_manifest_has_no_entries() {
        let m = HardwareManifestRaw::zeroed();
        assert_eq!(m.memory_region_count, 0);
        assert_eq!(m.compute_device_count, 0);
        assert_eq!(m.peripheral_device_count, 0);
        assert_eq!(m.power_domain_count, 0);
        assert!(m.memory_regions().is_empty());
        assert!(m.compute_devices().is_empty());
        assert!(m.peripheral_devices().is_empty());
        assert!(m.power_domains().is_empty());
    }

    #[test]
    fn push_memory_region_respects_capacity() {
        let mut m = HardwareManifestRaw::zeroed();
        for _ in 0..MAX_MEMORY_REGIONS {
            assert!(m.push_memory_region(MemoryRegionRaw::ZERO).is_ok());
        }
        assert!(m.push_memory_region(MemoryRegionRaw::ZERO).is_err());
        assert_eq!(m.memory_region_count as usize, MAX_MEMORY_REGIONS);
    }

    #[test]
    fn push_compute_device_assigns_sequential_index() {
        let mut m = HardwareManifestRaw::zeroed();
        m.push_compute_device(ComputeDeviceRaw::ZERO).unwrap();
        m.push_compute_device(ComputeDeviceRaw::ZERO).unwrap();
        assert_eq!(m.compute_devices()[0].device_index, 0);
        assert_eq!(m.compute_devices()[1].device_index, 1);
    }

    #[test]
    fn push_peripheral_device_assigns_sequential_index_and_respects_capacity() {
        let mut m = HardwareManifestRaw::zeroed();
        let blk = PeripheralDeviceRaw::new(PeripheralKindRaw::Block, 0x1000_1000, 0x1000, 1);
        m.push_peripheral_device(blk).unwrap();
        m.push_peripheral_device(blk).unwrap();
        assert_eq!(m.peripheral_devices()[0].device_index, 0);
        assert_eq!(m.peripheral_devices()[1].device_index, 1);
        assert_eq!(m.peripheral_devices()[0].kind, PeripheralKindRaw::Block);
        assert_eq!(m.peripheral_devices()[0].mmio_base, 0x1000_1000);

        let mut full = HardwareManifestRaw::zeroed();
        for _ in 0..MAX_PERIPHERAL_DEVICES {
            assert!(full.push_peripheral_device(PeripheralDeviceRaw::ZERO).is_ok());
        }
        assert!(full.push_peripheral_device(PeripheralDeviceRaw::ZERO).is_err());
    }
}
