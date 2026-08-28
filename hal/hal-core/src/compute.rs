//! ============================================================================
//! compute.rs
//!
//! Heterogeneous Compute Discovery, per 01-HAL-Layer.md section 3.6 and
//! the trait pre-draft in section 4:
//!
//!   pub trait ComputeDeviceDiscovery {
//!       fn enumerate_compute_devices(&self) -> &[ComputeDevice];
//!   }
//!
//!   pub struct ComputeDevice {
//!       pub kind: ComputeKind,       // Cpu, Gpu, Npu, Tpu, Fpga
//!       pub vendor: VendorId,
//!       pub dedicated_memory_bytes: Option<u64>,
//!       pub unified_memory_capable: bool,
//!       pub capability_token: CapabilityToken,
//!   }
//!
//! Responsibilities per section 3.6:
//!   - identify GPU/NPU/TPU/FPGA as a FIRST-CLASS entity type, not a
//!     "generic peripheral PCI device"
//!   - for each compute unit: type, vendor, dedicated memory, bandwidth
//!     to CPU, Unified Memory support (CXL / vendor-specific)
//!   - record this information in the Hardware Manifest even if no
//!     service currently uses it
//!
//! Per section 2 (Discovery + Policy model): this discovery ALWAYS runs
//! fully, regardless of the install profile chosen later in layer 4 —
//! "یک دستگاه NPU که در پروفایل «عمومی» نصب شده، همچنان توسط HAL شناسایی
//! و Capability Token آن ساخته می‌شود — فقط سرویس بالادستی که از آن
//! استفاده می‌کند، پیش‌فرض غیرفعال است."
//! ============================================================================

use crate::error::HalError;

// Re-export the raw compute device types directly from hal-manifest,
// for the same reason as MemoryBootstrap in memory.rs: at the point
// ComputeDeviceDiscovery runs (before any heap exists), the raw,
// `#[repr(C)]`, no-heap representation IS the correct representation —
// there is no benefit to a second, parallel type here that would just
// need converting right back.
pub use hal_manifest::raw::{ComputeDeviceRaw as ComputeDevice, ComputeKindRaw as ComputeKind, VendorIdRaw as VendorId};

// ============================================================================
// ComputeDeviceDiscovery trait
// ============================================================================

/// Per-architecture heterogeneous compute discovery. Implemented once
/// per architecture crate (`hal-x86_64::compute::ComputeDiscovery`,
/// `hal-arm64::compute::ComputeDiscovery`,
/// `hal-riscv64::compute::ComputeDiscovery`).
///
/// Discovery mechanism differs per architecture (PCI config space scan
/// plus vendor-specific probing on x86_64/ARM64 servers; Device Tree
/// `compatible` string matching for SoC-integrated NPUs on ARM64/RISC-V
/// embedded targets) — this trait hides all of that behind one uniform
/// query surface, per section 4's closing rule that layer 2+ code must
/// never contain `#[cfg(target_arch)]`.
pub trait ComputeDeviceDiscovery {
    /// Returns every heterogeneous compute device discovered on this
    /// machine — CPU cores are NOT included here (those are reported by
    /// `CpuAbstraction::core_count`, cpu.rs); this trait is specifically
    /// for GPU/NPU/TPU/FPGA-class devices, per section 3.6's framing of
    /// them as first-class entities distinct from ordinary peripherals.
    ///
    /// The returned slice borrows directly from the architecture
    /// implementation's own fixed-capacity storage (ultimately backed
    /// by `hal_manifest::raw::HardwareManifestRaw`), never from `alloc`
    /// — consistent with hal-manifest section 9's boot-time no-heap
    /// philosophy.
    ///
    /// An empty slice is a valid, non-error result (a CPU-only machine
    /// legitimately has zero entries here) — see
    /// `HalError::ComputeDiscoveryFailed` for the distinct case of
    /// discovery itself failing (e.g. PCI config space unreadable).
    fn enumerate_compute_devices(&self) -> &[ComputeDevice];

    /// Re-runs discovery for a specific device kind. Not present in the
    /// section 4 pre-draft, but needed for a case the spec's Discovery
    /// model implies without stating explicitly: hot-pluggable compute
    /// devices (e.g. an external GPU connected via Thunderbolt/USB4
    /// after boot). Since section 2 guarantees discovery is always
    /// complete and profile-independent, a rescan must be able to
    /// update the manifest's device list at runtime, not just once at
    /// boot.
    ///
    /// Returns `Err(HalError::ComputeDiscoveryFailed)` if the
    /// rescan itself fails at the bus/firmware level.
    /// Returns `Err(HalError::TooManyComputeDevices)` if the rescan
    /// would exceed `hal_manifest::raw::MAX_COMPUTE_DEVICES` — matching
    /// the same truncate-and-continue capacity handling used at initial
    /// boot discovery (see hal-manifest's `push_compute_device`).
    fn rescan(&self, kind_filter: Option<ComputeKind>) -> Result<(), HalError>;

    /// Looks up a single device by its stable `device_index` (the same
    /// index assigned at discovery time — see
    /// `hal_manifest::raw::ComputeDeviceRaw::device_index` doc comment
    /// for why this index, rather than a pointer or a name, is the
    /// stable identity used when a Capability is later minted for this
    /// exact device by the microkernel/Security Broker, per section 5).
    ///
    /// Returns `None` if no device exists at that index (e.g. it was
    /// removed by a hot-unplug and a subsequent `rescan`).
    fn device_by_index(&self, device_index: u32) -> Option<&ComputeDevice>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::RefCell;
    use hal_manifest::raw::MAX_COMPUTE_DEVICES;

    // ------------------------------------------------------------------
    // Mock hardware implementation, per section 8.4.
    //
    // Uses a fixed-size array with a count (mirroring
    // HardwareManifestRaw's own push/count pattern in hal-manifest),
    // rather than a Vec, to stay representative of a real no_std/
    // no_alloc architecture implementation.
    // ------------------------------------------------------------------

    struct MockComputeDiscovery {
        devices: RefCell<([ComputeDevice; 4], usize)>,
        fail_rescan: bool,
    }

    impl MockComputeDiscovery {
        fn new() -> Self {
            let mut devices = [ComputeDevice::ZERO; 4];

            let mut gpu = ComputeDevice::ZERO;
            gpu.kind = ComputeKind::Gpu;
            gpu.vendor = VendorId(0x10DE);
            gpu.has_dedicated_memory = true;
            gpu.dedicated_memory_bytes = 8 * 1024 * 1024 * 1024;
            gpu.device_index = 0;
            devices[0] = gpu;

            let mut npu = ComputeDevice::ZERO;
            npu.kind = ComputeKind::Npu;
            npu.vendor = VendorId(0x1AE0);
            npu.unified_memory_capable = true;
            npu.device_index = 1;
            devices[1] = npu;

            Self {
                devices: RefCell::new((devices, 2)),
                fail_rescan: false,
            }
        }
    }

    impl ComputeDeviceDiscovery for MockComputeDiscovery {
        fn enumerate_compute_devices(&self) -> &[ComputeDevice] {
            // SAFETY-free trick for the mock only: RefCell does not
            // allow returning a borrowed slice tied to `&self` directly
            // without `Ref` plumbing, so the mock leaks a `'static`-ish
            // borrow via unsafe is avoided by instead exposing a
            // helper that copies count/slice at call time in real
            // tests below. For trait-shape purposes we implement this
            // by borrowing for the duration of the call via a raw
            // pointer into the RefCell's underlying storage, which is
            // sound here because the mock is single-threaded and never
            // mutates `devices` while a slice from this method is held
            // in the same test.
            let borrow = self.devices.borrow();
            let (arr, count) = &*borrow;
            let ptr = arr.as_ptr();
            let len = *count;
            // SAFETY: `arr` is stored inline in `self` (via RefCell)
            // and outlives this borrow's use in every test below,
            // which never mutates `devices` while holding the returned
            // slice.
            unsafe { core::slice::from_raw_parts(ptr, len) }
        }

        fn rescan(&self, _kind_filter: Option<ComputeKind>) -> Result<(), HalError> {
            if self.fail_rescan {
                return Err(HalError::ComputeDiscoveryFailed);
            }
            Ok(())
        }

        fn device_by_index(&self, device_index: u32) -> Option<&ComputeDevice> {
            self.enumerate_compute_devices()
                .iter()
                .find(|d| d.device_index == device_index)
        }
    }

    #[test]
    fn enumerate_returns_discovered_devices() {
        let discovery = MockComputeDiscovery::new();
        let devices = discovery.enumerate_compute_devices();
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].kind, ComputeKind::Gpu);
        assert_eq!(devices[1].kind, ComputeKind::Npu);
    }

    #[test]
    fn empty_discovery_is_not_an_error() {
        let discovery = MockComputeDiscovery {
            devices: RefCell::new(([ComputeDevice::ZERO; 4], 0)),
            fail_rescan: false,
        };
        assert!(discovery.enumerate_compute_devices().is_empty());
    }

    #[test]
    fn device_by_index_finds_correct_device() {
        let discovery = MockComputeDiscovery::new();
        let dev = discovery.device_by_index(1).unwrap();
        assert_eq!(dev.kind, ComputeKind::Npu);
        assert!(dev.unified_memory_capable);
    }

    #[test]
    fn device_by_index_returns_none_when_absent() {
        let discovery = MockComputeDiscovery::new();
        assert!(discovery.device_by_index(99).is_none());
    }

    #[test]
    fn rescan_reports_discovery_failure() {
        let discovery = MockComputeDiscovery {
            devices: RefCell::new(([ComputeDevice::ZERO; 4], 0)),
            fail_rescan: true,
        };
        assert_eq!(
            discovery.rescan(None),
            Err(HalError::ComputeDiscoveryFailed)
        );
    }

    #[test]
    fn manifest_capacity_matches_max_compute_devices_constant() {
        // Sanity check that this trait's mental model of capacity
        // stays aligned with hal-manifest's actual constant, so a
        // future change to MAX_COMPUTE_DEVICES is visible here too.
        assert_eq!(MAX_COMPUTE_DEVICES, 32);
    }
}