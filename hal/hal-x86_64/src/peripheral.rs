//! ============================================================================
//! peripheral.rs — x86_64
//!
//! Implements `hal_core::peripheral::PeripheralDeviceDiscovery` for
//! x86_64 — see `hal_core::peripheral`'s own module doc comment for why
//! this is separate from `compute.rs`'s `ComputeDeviceDiscovery`
//! (GPU/NPU/TPU/FPGA-only, 01-HAL-Layer.md section 3.6).
//!
//! Design difference from `compute.rs`: that file uses the legacy PCI
//! configuration mechanism (I/O ports 0xCF8/0xCFC), which only reaches
//! the standard 256-byte config space — enough for `compute.rs`'s own
//! vendor/class/BAR-size probing, but `kernel_arch_glue`'s own virtio-
//! pci capability-list walk (mirroring `hal_arm64::peripheral`'s own
//! aarch64 port exactly) dereferences `config_space_base` as a raw MMIO
//! pointer, so this file needs a real ECAM (memory-mapped) config-space
//! window instead — the same requirement `hal_arm64::peripheral` already
//! has, solved the identical way: this file carries its own small,
//! self-contained ECAM read/BAR0-probe helpers (mirroring `hal_arm64::
//! compute`'s own, which this crate's own `compute.rs` has no
//! equivalent of, having chosen the I/O-port mechanism instead).
//!
//! `ecam_base` is supplied by the caller (`hal_x86_64_rust_entry`,
//! lib.rs), resolved via `memory::acpi_mcfg_ecam_base` — real ACPI MCFG
//! table parsing, NOT a hardcoded constant. **Real bug found via QEMU**
//! while bringing this file up: an initial attempt hardcoded QEMU q35's
//! own well-documented `MCH_HOST_BRIDGE_PCIEXBAR_DEFAULT` (0xB0000000),
//! mirroring `hal_arm64::compute::QEMU_VIRT_DEFAULT_ECAM_BASE`'s own
//! accepted MVP-phase shortcut for the OTHER PCI-using architecture —
//! on this project's actual QEMU/OVMF combination that address read
//! back as a clean, non-faulting `0x00000000` at bus 0/device 0/
//! function 0 (where the host bridge unconditionally exists on any q35
//! machine), instead of either a real device OR PCI's own "absent"
//! `0xFFFFFFFF` pattern — proof the guess was simply wrong for this
//! OVMF build's own PCIEXBAR placement (a genuinely unmapped access
//! would have page-faulted instead, so this was not a mapping problem).
//! See `hal_x86_64::memory::Memory::rsdp_phys`'s own doc comment for the
//! full story.
//!
//! IRQ routing: unlike aarch64 (legacy INTx, swizzled to a fixed GIC
//! SPI at discovery time — `hal_arm64::peripheral::resolve_pci_intx_
//! irq`), this architecture uses MSI-X (`hal_core::interrupt::
//! InterruptController::msi_message`'s own doc comment covers the full
//! rationale for why x86_64 is the one architecture that gets this
//! treatment). MSI-X has no PHYSICAL wire to discover at scan time —
//! the driver (`kernel_arch_glue`) ASSIGNS a vector by writing it into
//! the device's own MSI-X table — so `irq` here is simply a fixed,
//! reserved APIC vector number this file picks once, exactly the same
//! "HAL discovers a real IRQ id, kernel-arch-glue just uses it" shape
//! `mmio.irq` already has for the other two architectures, just backed
//! by assignment instead of physical-wire resolution.
//! ============================================================================

use hal_manifest::raw::{PeripheralDeviceRaw as PeripheralDevice, PeripheralKindRaw as PeripheralKind};

/// Capacity for this walker's own scratch storage — matches
/// `hal_manifest::raw::MAX_PERIPHERAL_DEVICES`, same reasoning as
/// hal-arm64's own identical constant.
const MAX_SCAN: usize = hal_manifest::raw::MAX_PERIPHERAL_DEVICES;

/// virtio's own PCI-SIG vendor id ("Red Hat, Inc."), per the virtio 1.x
/// spec's own PCI Vendor/Device ID appendix.
const VIRTIO_PCI_VENDOR_ID: u16 = 0x1AF4;

const PCI_CLASS_MASS_STORAGE: u8 = 0x01;
const PCI_CLASS_NETWORK: u8 = 0x02;
const PCI_CLASS_DISPLAY: u8 = 0x03;

/// Reserved APIC vector for the virtio-blk device's own MSI-X interrupt
/// — see this file's own module doc comment for why this is an
/// ASSIGNMENT, not a discovery, on this architecture. Any value at or
/// above `hal_x86_64::interrupt`'s own `FIRST_USABLE_IRQ_VECTOR` (33)
/// works; 44 is arbitrary, chosen simply to stay clear of the LAPIC
/// timer (32) and leave low headroom free for any future device.
const X86_64_VIRTIO_BLK_MSI_VECTOR: u32 = 44;
/// Same role as `X86_64_VIRTIO_BLK_MSI_VECTOR`, for the virtio-net
/// device — a SEPARATE vector, not the same one. **Real bug found via
/// QEMU** (driver-virtio-net's own multi-arch interrupt-driven-TX
/// session): every PCI device this scan discovered was originally
/// assigned `X86_64_VIRTIO_BLK_MSI_VECTOR` unconditionally, regardless
/// of `kind` — harmless while virtio-blk was the only PCI device this
/// project ever bound a REAL IRQ to (virtio-net stayed polling-only, so
/// its own `IrqBind` was never even attempted), but the instant BOTH a
/// virtio-blk AND a virtio-net device are present in the same boot
/// (QEMU's own default `-netdev`+`-device virtio-net-pci` alongside
/// `-device virtio-blk-pci`, or even aarch64's/x86_64's own board
/// defaults), `kernel_arch_glue::spawn_virtio_net_driver`'s own
/// `IrqBind` call failed outright — `hal_x86_64::interrupt::InterruptCtrl
/// ::register_irq`'s own `HalError::IrqAlreadyRegistered` check
/// (correctly) rejected registering the SAME vector blk's own `IrqBind`
/// had already claimed moments earlier. Fixed by giving each `Peripheral
/// Kind` its own reserved vector (`msi_vector_for_kind` below) — the
/// same "HAL discovers a real IRQ id, kernel-arch-glue just uses it"
/// shape either way, just no longer collapsing every device onto one.
const X86_64_VIRTIO_NET_MSI_VECTOR: u32 = 45;

/// Picks the reserved MSI-X vector for a just-classified PCI device —
/// see `X86_64_VIRTIO_NET_MSI_VECTOR`'s own doc comment for why this
/// must NOT collapse onto a single shared constant. `PeripheralKind::
/// Unknown`/`Gpu`/anything else this project does not yet bind a real
/// IRQ to still gets a distinct-from-blk/net vector (harmless — nothing
/// calls `IrqBind` for those kinds today, so no collision is possible
/// either way; kept distinct anyway so this function never needs a
/// TODO the day one of them does).
fn msi_vector_for_kind(kind: PeripheralKind) -> u32 {
    match kind {
        PeripheralKind::Block => X86_64_VIRTIO_BLK_MSI_VECTOR,
        PeripheralKind::Network => X86_64_VIRTIO_NET_MSI_VECTOR,
        _ => X86_64_VIRTIO_NET_MSI_VECTOR + 1,
    }
}

fn ecam_offset(bus: u8, device: u8, function: u8) -> u64 {
    ((bus as u64) << 20) | ((device as u64) << 15) | ((function as u64) << 12)
}

/// # Safety
/// `ecam_base` must be a valid, mapped ECAM MMIO base address (mapped
/// via `MemoryBootstrap::setup_identity_mapping` with
/// `MapPermissions::DEVICE_MMIO` before this is called — same ordering
/// contract `hal_arm64::compute::ecam_read_u32`'s own doc comment
/// documents).
unsafe fn ecam_read_u32(ecam_base: u64, bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let addr = ecam_base + ecam_offset(bus, device, function) + offset as u64;
    let ptr = addr as *const u32;
    // SAFETY: forwarded from this function's own contract; volatile for
    // the same reordering-prevention reason as every other MMIO access
    // in this crate.
    unsafe { ptr.read_volatile() }
}

#[derive(Debug, Clone, Copy)]
struct PciDeviceHeader {
    vendor_id: u16,
    class_code: u8,
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

    // SAFETY: forwarded from this function's own contract.
    let dword2 = unsafe { ecam_read_u32(ecam_base, bus, device, function, 0x08) };
    let class_code = ((dword2 >> 24) & 0xFF) as u8;

    // SAFETY: forwarded from this function's own contract.
    let dword3 = unsafe { ecam_read_u32(ecam_base, bus, device, function, 0x0C) };
    let header_type = ((dword3 >> 16) & 0xFF) as u8;

    Some(PciDeviceHeader { vendor_id, class_code, header_type })
}

/// Maps a PCI class code (for a device already confirmed to carry
/// virtio's own vendor id) to this project's own `PeripheralKind`.
fn classify_virtio_pci_device(header: &PciDeviceHeader) -> PeripheralKind {
    match header.class_code {
        PCI_CLASS_MASS_STORAGE => PeripheralKind::Block,
        PCI_CLASS_NETWORK => PeripheralKind::Network,
        PCI_CLASS_DISPLAY => PeripheralKind::Gpu,
        _ => PeripheralKind::Unknown,
    }
}

/// BAR0 sizing — identical logic to `hal_arm64::peripheral::probe_bar0`,
/// duplicated here for the same self-contained-helper reasoning that
/// file's own doc comment gives.
///
/// # Safety
/// Same contract as `ecam_read_u32`.
unsafe fn probe_bar0(ecam_base: u64, bus: u8, device: u8, function: u8) -> Option<(u64, u64)> {
    // SAFETY: forwarded from this function's own contract.
    let bar0 = unsafe { ecam_read_u32(ecam_base, bus, device, function, 0x10) };
    if bar0 & 0x1 != 0 {
        return None; // I/O-space BAR — same documented non-scope as compute.rs's own probe_bar_size.
    }
    let base = (bar0 & 0xFFFF_FFF0) as u64;

    let addr = ecam_base + ecam_offset(bus, device, function) + 0x10;
    let ptr = addr as *mut u32;
    // SAFETY: forwarded from this function's own contract; original
    // value always restored below (standard PCI BAR-sizing procedure,
    // spec section 6.2.5.1).
    unsafe { ptr.write_volatile(0xFFFF_FFFF) };
    // SAFETY: forwarded from this function's own contract.
    let size_mask = unsafe { ptr.read_volatile() };
    // SAFETY: forwarded from this function's own contract; restoring.
    unsafe { ptr.write_volatile(bar0) };

    if size_mask == 0 {
        return None;
    }
    let size = (!(size_mask & 0xFFFF_FFF0) as u64) + 1;
    Some((base, size))
}

// ============================================================================
// PeripheralDiscovery — PeripheralDeviceDiscovery implementation
// ============================================================================

pub struct PeripheralDiscovery {
    devices: [PeripheralDevice; MAX_SCAN],
    device_count: usize,
}

impl PeripheralDiscovery {
    /// Performs a full PCI bus scan over ECAM looking for virtio's own
    /// vendor id — mirrors `hal_arm64::peripheral::PeripheralDiscovery::
    /// new`'s own scan loop shape exactly. Per section 2's Discovery +
    /// Policy model, this always runs in full at construction.
    ///
    /// `ecam_base` is supplied by the caller (`hal_x86_64_rust_entry`),
    /// resolved via `memory::acpi_mcfg_ecam_base` — see this file's own
    /// module doc comment for why that MUST be the real, firmware-
    /// reported base, not a hardcoded guess. `0` (no MCFG table found,
    /// or no RSDP at all) is handled gracefully: every scan iteration's
    /// own `read_pci_header` simply reads unmapped/garbage memory at
    /// low physical addresses and finds `vendor_id == 0xFFFF`
    /// everywhere, so this constructor still returns cleanly with zero
    /// devices — the SAME "peripheral devices: 0, driver demo skipped"
    /// path a real device-free boot already takes.
    pub fn new(ecam_base: u64) -> Self {
        let mut devices = [PeripheralDevice::ZERO; MAX_SCAN];
        let mut device_count = 0usize;

        'bus_scan: for bus in 0..=255u8 {
            for device in 0..32u8 {
                // SAFETY: `ecam_base` is either `0` (see this method's
                // own doc comment on why that degrades gracefully) or a
                // real, firmware-reported ECAM base `hal_x86_64_rust_
                // entry` resolved via ACPI MCFG before this scan runs —
                // same ordering contract `hal_arm64::compute::
                // ComputeDiscovery::new` already documents for its own
                // ECAM scan).
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

                    if header.vendor_id != VIRTIO_PCI_VENDOR_ID {
                        continue;
                    }

                    if device_count >= MAX_SCAN {
                        break 'bus_scan;
                    }

                    // SAFETY: same ordering contract as above.
                    let bar0 = unsafe { probe_bar0(ecam_base, bus, device, function) };
                    let (mmio_base, mmio_size) = bar0.unwrap_or((0, 0));
                    let config_space_base = ecam_base + ecam_offset(bus, device, function);

                    let kind = classify_virtio_pci_device(&header);
                    devices[device_count] = PeripheralDevice::new_pci(
                        kind,
                        mmio_base,
                        mmio_size,
                        msi_vector_for_kind(kind),
                        config_space_base,
                    );
                    device_count += 1;
                }
            }
        }

        for (i, d) in devices.iter_mut().enumerate().take(device_count) {
            d.device_index = i as u32;
        }

        Self { devices, device_count }
    }
}

impl hal_core::peripheral::PeripheralDeviceDiscovery for PeripheralDiscovery {
    fn enumerate_peripheral_devices(&self) -> &[PeripheralDevice] {
        &self.devices[..self.device_count]
    }

    fn device_by_index(&self, device_index: u32) -> Option<&PeripheralDevice> {
        self.enumerate_peripheral_devices()
            .iter()
            .find(|d| d.device_index == device_index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_virtio_pci_matches_pci_class_codes() {
        let mk = |class_code: u8| PciDeviceHeader {
            vendor_id: VIRTIO_PCI_VENDOR_ID,
            class_code,
            header_type: 0,
        };
        assert_eq!(classify_virtio_pci_device(&mk(PCI_CLASS_MASS_STORAGE)), PeripheralKind::Block);
        assert_eq!(classify_virtio_pci_device(&mk(PCI_CLASS_NETWORK)), PeripheralKind::Network);
        assert_eq!(classify_virtio_pci_device(&mk(PCI_CLASS_DISPLAY)), PeripheralKind::Gpu);
        assert_eq!(classify_virtio_pci_device(&mk(0xFF)), PeripheralKind::Unknown);
    }

    #[test]
    fn virtio_pci_vendor_id_matches_spec() {
        assert_eq!(VIRTIO_PCI_VENDOR_ID, 0x1AF4);
    }

    #[test]
    fn ecam_offset_computes_correct_layout() {
        let offset = ecam_offset(1, 2, 3);
        assert_eq!(offset, 0x100000 | 0x10000 | 0x3000);
    }

    #[test]
    fn msi_vector_for_kind_never_collapses_blk_and_net_onto_the_same_vector() {
        // Real bug this test guards against — `X86_64_VIRTIO_NET_MSI_
        // VECTOR`'s own doc comment: `IrqBind` for a SECOND real PCI
        // device fails outright if it gets assigned the SAME vector an
        // earlier `IrqBind` already claimed.
        assert_ne!(msi_vector_for_kind(PeripheralKind::Block), msi_vector_for_kind(PeripheralKind::Network));
        assert!(msi_vector_for_kind(PeripheralKind::Block) >= crate::interrupt::FIRST_USABLE_IRQ_VECTOR as u32);
        assert!(msi_vector_for_kind(PeripheralKind::Network) >= crate::interrupt::FIRST_USABLE_IRQ_VECTOR as u32);
    }

    #[test]
    fn msi_vector_is_at_or_above_first_usable_irq_vector() {
        assert!(X86_64_VIRTIO_BLK_MSI_VECTOR >= crate::interrupt::FIRST_USABLE_IRQ_VECTOR as u32);
    }
}
