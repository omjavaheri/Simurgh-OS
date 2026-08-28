//! ============================================================================
//! compute.rs — RISC-V (RV64GC)
//!
//! Implements `hal_core::compute::ComputeDeviceDiscovery` for RISC-V,
//! per 01-HAL-Layer.md section 3.6.
//!
//! Design: like ARM64 (and unlike x86_64), RISC-V has no architectural
//! I/O port space at all — PCIe configuration space access is
//! EXCLUSIVELY via ECAM, identical in mechanism to
//! hal-arm64/src/compute.rs (same 4KB-per-function windowing, same
//! PCI spec class-code/BAR-sizing logic, since none of that is
//! access-method- or architecture-specific). The only real difference
//! from hal-arm64's version is WHERE `ecam_base` comes from: this
//! project's Device Tree walker (`memory.rs`) would need to locate a
//! `pci-host-ecam-generic`-compatible node's `reg` property — a
//! parsing target this MVP phase's minimal FDT walker does not yet
//! cover (per memory.rs's documented `memory`/`plic`/`iommu`-only
//! scope), so `ecam_base` here uses a documented QEMU `virt` machine
//! default, exactly mirroring how `interrupt.rs`'s `plic_base` and
//! `memory.rs`'s `QEMU_VIRT_DEFAULT_MEMORY_BASE` already handle the
//! same kind of not-yet-parsed Device Tree property.
//! ============================================================================

use core::cell::RefCell;

use hal_core::compute::{ComputeDevice, ComputeDeviceDiscovery, ComputeKind};
use hal_core::error::HalError;
use hal_manifest::raw::{ComputeDeviceRaw, ComputeKindRaw, VendorIdRaw, MAX_COMPUTE_DEVICES};

// ============================================================================
// ECAM-based PCI configuration space access — identical mechanism to
// hal-arm64/src/compute.rs (see that file's module docs for why ECAM
// is the only option on architectures without I/O port space).
// Reproduced here rather than shared, per this project's established
// convention (each hal-<arch> crate owns its own copy of low-level
// primitives even when byte-identical — see hal-riscv64/timer.rs's
// module docs on the same convention applied to its SBI call helper).
// ============================================================================

fn ecam_offset(bus: u8, device: u8, function: u8) -> u64 {
    ((bus as u64) << 20) | ((device as u64) << 15) | ((function as u64) << 12)
}

/// # Safety
/// `ecam_base` must be a valid, mapped ECAM MMIO base address (mapped
/// via `MemoryBootstrap::setup_identity_mapping` with
/// `MapPermissions::DEVICE_MMIO` before this is called).
unsafe fn ecam_read_u32(ecam_base: u64, bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let addr = ecam_base + ecam_offset(bus, device, function) + offset as u64;
    let ptr = addr as *const u32;
    // SAFETY: forwarded from this function's own contract; volatile
    // for the same reordering-prevention reason as every other MMIO
    // access in this project.
    unsafe { ptr.read_volatile() }
}

/// # Safety
/// Same contract as `ecam_read_u32`.
unsafe fn ecam_write_u32(ecam_base: u64, bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let addr = ecam_base + ecam_offset(bus, device, function) + offset as u64;
    let ptr = addr as *mut u32;
    // SAFETY: forwarded from this function's own contract.
    unsafe { ptr.write_volatile(value) }
}

#[derive(Debug, Clone, Copy)]
struct PciDeviceHeader {
    vendor_id: u16,
    device_id: u16,
    class_code: u8,
    subclass: u8,
    header_type: u8,
}

/// # Safety
/// Same contract as `ecam_read_u32`.
unsafe fn read_pci_header(ecam_base: u64, bus: u8, device: u8, function: u8) -> Option<PciDeviceHeader> {
    // SAFETY: forwarded from this function's own contract.
    let dword0 = unsafe { ecam_read_u32(ecam_base, bus, device, function, 0x00) };
    let vendor_id = (dword0 & 0xFFFF) as u16;
    if vendor_id == 0xFFFF {
        return None;
    }
    let device_id = (dword0 >> 16) as u16;

    // SAFETY: forwarded from this function's own contract.
    let dword2 = unsafe { ecam_read_u32(ecam_base, bus, device, function, 0x08) };
    let subclass = ((dword2 >> 16) & 0xFF) as u8;
    let class_code = ((dword2 >> 24) & 0xFF) as u8;

    // SAFETY: forwarded from this function's own contract.
    let dword3 = unsafe { ecam_read_u32(ecam_base, bus, device, function, 0x0C) };
    let header_type = ((dword3 >> 16) & 0xFF) as u8;

    Some(PciDeviceHeader { vendor_id, device_id, class_code, subclass, header_type })
}

/// # Safety
/// Same contract as `ecam_read_u32`/`ecam_write_u32`. Same standard
/// PCI BAR-sizing procedure as hal-x86_64/hal-arm64's `probe_bar_size`
/// — access-method-independent, per the PCI spec (section 6.2.5.1).
unsafe fn probe_bar_size(ecam_base: u64, bus: u8, device: u8, function: u8, bar_index: u8) -> Option<u64> {
    let offset = 0x10 + bar_index * 4;
    // SAFETY: forwarded from this function's own contract.
    let original = unsafe { ecam_read_u32(ecam_base, bus, device, function, offset) };

    if original & 0x1 != 0 {
        return None; // I/O-space BAR — same documented limitation as
        // hal-arm64/compute.rs: RISC-V, like ARM64, has no
        // architectural I/O space to route such a BAR to.
    }

    // SAFETY: forwarded from this function's own contract; original
    // value always restored below.
    unsafe {
        ecam_write_u32(ecam_base, bus, device, function, offset, 0xFFFF_FFFF);
    }
    // SAFETY: forwarded from this function's own contract.
    let size_mask = unsafe { ecam_read_u32(ecam_base, bus, device, function, offset) };
    // SAFETY: forwarded from this function's own contract; restoring
    // the original value.
    unsafe {
        ecam_write_u32(ecam_base, bus, device, function, offset, original);
    }

    if size_mask == 0 {
        return None;
    }

    let size_bits = size_mask & 0xFFFF_FFF0;
    Some((!size_bits as u64) + 1)
}

// ============================================================================
// Classification — identical logic to the other two architectures'
// compute.rs, since PCI class codes and vendor IDs are access-method-
// and architecture-independent.
// ============================================================================

const PCI_CLASS_DISPLAY_CONTROLLER: u8 = 0x03;
const PCI_CLASS_PROCESSING_ACCELERATOR: u8 = 0x12;

const KNOWN_NPU_TPU_VENDOR_IDS: &[(u16, ComputeKindRaw)] = &[
    (0x1AE0, ComputeKindRaw::Tpu), // Google (Cloud TPU PCIe accelerators)
];

fn classify_pci_device(header: &PciDeviceHeader) -> Option<ComputeKindRaw> {
    if header.class_code == PCI_CLASS_DISPLAY_CONTROLLER {
        return Some(ComputeKindRaw::Gpu);
    }
    if header.class_code == PCI_CLASS_PROCESSING_ACCELERATOR {
        return Some(ComputeKindRaw::Npu);
    }
    for &(vendor, kind) in KNOWN_NPU_TPU_VENDOR_IDS {
        if header.vendor_id == vendor {
            return Some(kind);
        }
    }
    None
}

/// Documented fallback ECAM base for QEMU's `virt` machine (RISC-V
/// variant), used only until this project's Device Tree walker
/// (memory.rs) is extended to parse the `pci-host-ecam-generic` node —
/// see module docs. This is QEMU's well-known, stable default RISC-V
/// `virt` machine PCIe ECAM window base, not an arbitrary guess.
const QEMU_VIRT_DEFAULT_ECAM_BASE: u64 = 0x3000_0000;

// ============================================================================
// ComputeDiscovery — ComputeDeviceDiscovery implementation
// ============================================================================

pub struct ComputeDiscovery {
    devices: RefCell<[ComputeDevice; MAX_COMPUTE_DEVICES]>,
    device_count: RefCell<usize>,
    ecam_base: u64,
}

impl ComputeDiscovery {
    /// Performs a full PCI bus scan over ECAM. Same addressable space
    /// (buses 0-255, devices 0-31, functions 0-7) as the other two
    /// architectures — defined by the PCI spec itself.
    ///
    /// Per module docs, `ecam_base` currently uses
    /// `QEMU_VIRT_DEFAULT_ECAM_BASE` rather than a Device-Tree-derived
    /// value, since `memory.rs`'s minimal FDT walker does not yet
    /// parse the PCIe host bridge node — this constructor therefore
    /// takes NO parameter (unlike hal-arm64's `ComputeDiscovery::new`,
    /// which already threads through an ACPI-derived `ecam_base`),
    /// simply using the constant directly. This asymmetry with
    /// hal-arm64 is intentional and documented rather than papered
    /// over with a fake parameter that always receives the same
    /// hardcoded value from its only caller.
    ///
    /// Per section 2's Discovery + Policy model, this always runs in
    /// full at construction — never trimmed based on install profile.
    pub fn new() -> Self {
        let ecam_base = QEMU_VIRT_DEFAULT_ECAM_BASE;
        let mut devices = [ComputeDeviceRaw::ZERO; MAX_COMPUTE_DEVICES];
        let mut device_count = 0usize;

        'bus_scan: for bus in 0..=255u8 {
            for device in 0..32u8 {
                // SAFETY: `ecam_base` points at QEMU virt's documented
                // default ECAM window, which this project's QEMU-
                // targeted MVP phase (section 8's acceptance criteria)
                // relies on being mapped by `hal_riscv64_rust_entry`
                // before this scan runs, mirroring hal-arm64's
                // equivalent ordering contract.
                let header0 = unsafe { read_pci_header(ecam_base, bus, device, 0) };
                let Some(header0) = header0 else {
                    continue;
                };

                let function_count = if header0.header_type & 0x80 != 0 { 8 } else { 1 };

                for function in 0..function_count {
                    // SAFETY: same ordering contract as above.
                    let header = unsafe { read_pci_header(ecam_base, bus, device, function) };
                    let Some(header) = header else {
                        continue;
                    };

                    let Some(kind) = classify_pci_device(&header) else {
                        continue;
                    };

                    if device_count >= MAX_COMPUTE_DEVICES {
                        break 'bus_scan;
                    }

                    // SAFETY: same ordering contract as above.
                    let dedicated_memory_bytes =
                        unsafe { probe_bar_size(ecam_base, bus, device, function, 0) };

                    let mut entry = ComputeDeviceRaw::ZERO;
                    entry.kind = kind;
                    entry.vendor = VendorIdRaw(header.vendor_id as u32);
                    entry.has_dedicated_memory = dedicated_memory_bytes.is_some();
                    entry.dedicated_memory_bytes = dedicated_memory_bytes.unwrap_or(0);
                    // Same documented scope limitation as the other
                    // two architectures: unified memory (CXL)
                    // capability requires parsing PCIe extended
                    // capability structures, not yet implemented.
                    entry.unified_memory_capable = false;

                    devices[device_count] = entry;
                    device_count += 1;
                }
            }
        }

        Self {
            devices: RefCell::new(devices),
            device_count: RefCell::new(device_count),
            ecam_base,
        }
    }
}

impl Default for ComputeDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

impl ComputeDeviceDiscovery for ComputeDiscovery {
    fn enumerate_compute_devices(&self) -> &[ComputeDevice] {
        // SAFETY: same RefCell-to-slice reasoning as the other two
        // architectures' identical method.
        let count = *self.device_count.borrow();
        let borrow = self.devices.borrow();
        let ptr = borrow.as_ptr();
        unsafe { core::slice::from_raw_parts(ptr, count) }
    }

    fn rescan(&self, kind_filter: Option<ComputeKind>) -> Result<(), HalError> {
        let fresh = Self::new();
        let fresh_count = *fresh.device_count.borrow();
        if fresh_count > MAX_COMPUTE_DEVICES {
            return Err(HalError::TooManyComputeDevices);
        }

        let _ = kind_filter; // same full-rescan MVP scope as the other
        // two architectures' rescan.

        *self.devices.borrow_mut() = *fresh.devices.borrow();
        *self.device_count.borrow_mut() = fresh_count;
        Ok(())
    }

    fn device_by_index(&self, device_index: u32) -> Option<&ComputeDevice> {
        self.enumerate_compute_devices()
            .iter()
            .find(|d| d.device_index == device_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_controller_classified_as_gpu() {
        let header = PciDeviceHeader {
            vendor_id: 0x10DE,
            device_id: 0x1234,
            class_code: PCI_CLASS_DISPLAY_CONTROLLER,
            subclass: 0x00,
            header_type: 0,
        };
        assert_eq!(classify_pci_device(&header), Some(ComputeKindRaw::Gpu));
    }

    #[test]
    fn processing_accelerator_classified_as_npu() {
        let header = PciDeviceHeader {
            vendor_id: 0x1234,
            device_id: 0x5678,
            class_code: PCI_CLASS_PROCESSING_ACCELERATOR,
            subclass: 0x00,
            header_type: 0,
        };
        assert_eq!(classify_pci_device(&header), Some(ComputeKindRaw::Npu));
    }

    #[test]
    fn known_vendor_allowlist_overrides_generic_class() {
        let header = PciDeviceHeader {
            vendor_id: 0x1AE0,
            device_id: 0x0001,
            class_code: 0x00,
            subclass: 0x00,
            header_type: 0,
        };
        assert_eq!(classify_pci_device(&header), Some(ComputeKindRaw::Tpu));
    }

    #[test]
    fn ecam_offset_computes_correct_layout() {
        let offset = ecam_offset(1, 2, 3);
        assert_eq!(offset, 0x100000 | 0x10000 | 0x3000);
    }

    #[test]
    fn qemu_virt_default_ecam_base_is_documented_value() {
        assert_eq!(QEMU_VIRT_DEFAULT_ECAM_BASE, 0x3000_0000);
    }
}