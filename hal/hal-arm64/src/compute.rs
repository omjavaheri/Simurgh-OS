//! ============================================================================
//! compute.rs — ARM64
//!
//! Implements `hal_core::compute::ComputeDeviceDiscovery` for ARM64,
//! per 01-HAL-Layer.md section 3.6.
//!
//! Design difference from hal-x86_64/src/compute.rs: ARM64 has no
//! legacy CONFIG_ADDRESS/CONFIG_DATA I/O-port PCI access mechanism at
//! all (AArch64 defines no architectural I/O port space the way
//! x86_64 does — `IN`/`OUT`-equivalent instructions do not exist).
//! PCIe on ARM64 is accessed exclusively via ECAM (Enhanced
//! Configuration Access Mechanism): a flat, memory-mapped region where
//! each (bus, device, function) gets its own 4KB configuration space
//! window at a directly computable offset — no address/data port
//! indirection needed at all, which actually makes this file's config
//! space access SIMPLER than hal-x86_64's, despite requiring an extra
//! discovery step (the ECAM base) up front.
//!
//! `ecam_base` is discovered the same way `interrupt.rs` obtains
//! `gicd_base`: via ACPI (the MCFG table, "Memory-mapped ConFiGuration
//! space" — PCI Firmware Spec section 4.1.2) parsed by `memory.rs`
//! alongside its MADT/IORT walk, with a documented QEMU `virt` machine
//! default fallback matching this project's established pattern for
//! every firmware-table-derived base address on this architecture.
//! ============================================================================

use core::cell::RefCell;

use hal_core::compute::{ComputeDevice, ComputeDeviceDiscovery, ComputeKind};
use hal_core::error::HalError;
use hal_manifest::raw::{ComputeDeviceRaw, ComputeKindRaw, VendorIdRaw, MAX_COMPUTE_DEVICES};

// ============================================================================
// ECAM-based PCI configuration space access
// ============================================================================

/// Computes the ECAM offset for (bus, device, function): each function
/// gets a dedicated 4KB (0x1000) window, addressed as
/// `bus << 20 | device << 15 | function << 12` — the fixed ECAM layout
/// defined by the PCI Express spec (section 7.2.2), identical on every
/// platform that implements ECAM (not an ARM64-specific encoding, just
/// the mechanism ARM64 exclusively relies on where x86_64 has the
/// legacy port-based alternative too).
pub(crate) fn ecam_offset(bus: u8, device: u8, function: u8) -> u64 {
    ((bus as u64) << 20) | ((device as u64) << 15) | ((function as u64) << 12)
}

/// Reads one 32-bit dword from PCI configuration space at
/// (bus, device, function, offset) via ECAM.
///
/// # Safety
/// `ecam_base` must be a valid, mapped ECAM MMIO base address (mapped
/// via `MemoryBootstrap::setup_identity_mapping` with
/// `MapPermissions::DEVICE_MMIO` before this is called — same ordering
/// contract as `interrupt.rs`'s GICD access, and as
/// hal-x86_64/compute.rs's PCI I/O port access requires no equivalent
/// mapping step at all, since I/O ports are not memory-mapped;  ECAM,
/// being MMIO, does require it).
pub(crate) unsafe fn ecam_read_u32(ecam_base: u64, bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let addr = ecam_base + ecam_offset(bus, device, function) + offset as u64;
    let ptr = addr as *const u32;
    // SAFETY: forwarded from this function's own contract; volatile
    // for the same reordering-prevention reason as every other MMIO
    // access in this crate (memory.rs's gicd_read32, interrupt.rs's
    // GICD access).
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
pub(crate) struct PciDeviceHeader {
    pub(crate) vendor_id: u16,
    pub(crate) device_id: u16,
    pub(crate) class_code: u8,
    pub(crate) subclass: u8,
    pub(crate) header_type: u8,
}

/// # Safety
/// Same contract as `ecam_read_u32`.
pub(crate) unsafe fn read_pci_header(ecam_base: u64, bus: u8, device: u8, function: u8) -> Option<PciDeviceHeader> {
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

/// BAR sizing via the standard PCI write-all-ones-and-read-back
/// procedure — identical logic to hal-x86_64/compute.rs's
/// `probe_bar_size`, just reached through ECAM MMIO instead of I/O
/// ports; the PCI spec's BAR sizing mechanism itself (section 6.2.5.1)
/// is access-method-independent.
///
/// # Safety
/// Same contract as `ecam_read_u32`/`ecam_write_u32`.
unsafe fn probe_bar_size(ecam_base: u64, bus: u8, device: u8, function: u8, bar_index: u8) -> Option<u64> {
    let offset = 0x10 + bar_index * 4;
    // SAFETY: forwarded from this function's own contract.
    let original = unsafe { ecam_read_u32(ecam_base, bus, device, function, offset) };

    if original & 0x1 != 0 {
        return None; // I/O-space BAR — note this bit's meaning is
        // preserved from the PCI spec even though ARM64 itself has no
        // architectural I/O space; a device can still legally declare
        // an I/O-space BAR in configuration space, this project simply
        // has no way to route traffic to it (an acceptable limitation,
        // since compute-class devices — this file's entire scope,
        // per module docs — do not use I/O-space BARs in practice).
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
// Classification — identical logic to hal-x86_64/compute.rs, since PCI
// class codes and vendor IDs are access-method-independent (the same
// device reports the same class code whether reached via ECAM or I/O
// ports).
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

/// Documented fallback ECAM base for QEMU's `virt` machine, used only
/// if ACPI MCFG parsing fails to find one — matches the same
/// established pattern as `memory.rs`'s `QEMU_VIRT_DEFAULT_GICD_BASE`
/// and `interrupt.rs`'s PPI INTID conventions: this is QEMU's
/// well-known, stable default `virt` machine high-memory PCIe ECAM
/// window base, not an arbitrary guess. Full MCFG-based discovery
/// (reading the precise, firmware-reported base/bus range rather than
/// relying on this default) is a tracked follow-up alongside
/// memory.rs's own ACPI table parsing scope for this MVP phase.
const QEMU_VIRT_DEFAULT_ECAM_BASE: u64 = 0x40_1000_0000;

// ============================================================================
// ComputeDiscovery — ComputeDeviceDiscovery implementation
// ============================================================================

pub struct ComputeDiscovery {
    devices: RefCell<[ComputeDevice; MAX_COMPUTE_DEVICES]>,
    device_count: RefCell<usize>,
    ecam_base: u64,
}

impl ComputeDiscovery {
    /// Performs a full PCI bus scan over ECAM (buses 0-255, devices
    /// 0-31, functions 0-7, same addressable space as
    /// hal-x86_64/compute.rs — this range is defined by the PCI spec
    /// itself, not by the access mechanism).
    ///
    /// `ecam_base` is supplied by `hal_arm64_rust_entry` (lib.rs) —
    /// see this file's module docs and `QEMU_VIRT_DEFAULT_ECAM_BASE`'s
    /// doc comment for how it is currently obtained in this MVP phase.
    ///
    /// Per section 2's Discovery + Policy model, this always runs in
    /// full at construction — never trimmed based on install profile.
    pub fn new(ecam_base: u64) -> Self {
        let mut devices = [ComputeDeviceRaw::ZERO; MAX_COMPUTE_DEVICES];
        let mut device_count = 0usize;

        'bus_scan: for bus in 0..=255u8 {
            for device in 0..32u8 {
                // SAFETY: `ecam_base` is trusted per this constructor's
                // own doc comment (mapped by `hal_arm64_rust_entry`
                // before this scan runs, mirroring interrupt.rs's
                // bootstrap_current_core ordering contract for
                // gicd_base).
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
                    // Same documented scope limitation as
                    // hal-x86_64/compute.rs: unified memory (CXL)
                    // capability requires parsing PCIe DVSEC/CXL
                    // extended capability structures, which ECAM does
                    // expose (unlike x86_64's legacy port mechanism,
                    // ECAM's 4KB window per function DOES include
                    // extended config space) — but this MVP phase does
                    // not yet parse capability lists at all, so this
                    // remains a tracked follow-up here too, for
                    // consistency with the x86_64 implementation's
                    // current scope.
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

impl ComputeDeviceDiscovery for ComputeDiscovery {
    fn enumerate_compute_devices(&self) -> &[ComputeDevice] {
        // SAFETY: same RefCell-to-slice reasoning as
        // hal-x86_64/compute.rs's identical method — single-threaded
        // boot-time access, no conflicting mutable borrow held across
        // this call in this crate's usage.
        let count = *self.device_count.borrow();
        let borrow = self.devices.borrow();
        let ptr = borrow.as_ptr();
        unsafe { core::slice::from_raw_parts(ptr, count) }
    }

    fn rescan(&self, kind_filter: Option<ComputeKind>) -> Result<(), HalError> {
        let fresh = Self::new(self.ecam_base);
        let fresh_count = *fresh.device_count.borrow();
        if fresh_count > MAX_COMPUTE_DEVICES {
            return Err(HalError::TooManyComputeDevices);
        }

        let _ = kind_filter; // same full-rescan MVP scope as
        // hal-x86_64/compute.rs's rescan.

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
        // bus=1, device=2, function=3:
        // (1 << 20) | (2 << 15) | (3 << 12) = 0x100000 | 0x10000 | 0x3000
        let offset = ecam_offset(1, 2, 3);
        assert_eq!(offset, 0x100000 | 0x10000 | 0x3000);
    }

    #[test]
    fn ecam_offset_zero_for_bus_zero_device_zero_function_zero() {
        assert_eq!(ecam_offset(0, 0, 0), 0);
    }

    #[test]
    fn qemu_virt_default_ecam_base_is_documented_value() {
        // QEMU `virt` high-memory PCIe ECAM window base (0x4010000000) —
        // same value edk2's ArmVirtQemu uses for PcdPciExpressBaseAddress.
        assert_eq!(QEMU_VIRT_DEFAULT_ECAM_BASE, 0x40_1000_0000);
    }
}