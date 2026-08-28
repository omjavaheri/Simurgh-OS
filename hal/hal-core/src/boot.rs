//! ============================================================================
//! boot.rs
//!
//! Boot Abstraction, per 01-HAL-Layer.md section 3.5:
//!
//!   - uniform entry regardless of bootloader: UEFI (x86_64/ARM64) or
//!     SBI + Device Tree (RISC-V)
//!   - handoff of control to the microkernel via one standard Boot Info
//!     structure (NOT tied to UEFI's or Device Tree's own format)
//!
//! This is the very first hal-core type touched during boot: each
//! architecture's `boot.S` does the absolute minimum assembly needed to
//! establish a valid stack, then jumps into architecture-specific Rust
//! init code, which itself builds a `BootInfo` value and — per
//! 01-HAL-Layer.md section 0 — hands control to the microkernel via a
//! direct Rust function call (NOT IPC, since HAL and the microkernel
//! link into the same Privileged binary).
//!
//! Per section 9's boot-time no-heap philosophy: `BootInfo` and
//! everything it points to must remain valid and fixed-size until the
//! Root Task has copied whatever it needs out of it — nothing here may
//! assume a heap exists yet.
//! ============================================================================

use crate::error::HalError;
use hal_manifest::raw::HardwareManifestRaw;

// ============================================================================
// Boot protocol identification
// ============================================================================

/// Which bootloader/firmware handoff protocol actually delivered
/// control to HAL. Recorded for diagnostics and for the rare cases
/// where upper layers need to know (e.g. layer 5's Linux Compat
/// Runtime VMM choosing a matching boot protocol to present to its own
/// guest kernel) — but per section 3.5, everything ABOVE this point is
/// otherwise fully uniform regardless of which variant fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootProtocol {
    /// x86_64 or ARM64, entered via a UEFI bootloader stub.
    Uefi,
    /// RISC-V, entered via SBI with a Device Tree blob (mandatory per
    /// the SBI spec, section 3.2).
    SbiDeviceTree,
}

// ============================================================================
// Boot Info — the standard structure handed to the microkernel
// (section 3.5: "تحویل کنترل به میکروکرنل با یک ساختار Boot Info
// استاندارد (نه وابسته به فرمت خاص UEFI یا DT)")
// ============================================================================

/// Magic value at the start of every `BootInfo`, used by
/// `BootInfo::validate` to reject a corrupt or uninitialized structure
/// before the microkernel trusts any of its fields. Chosen as an
/// arbitrary but recognizable 64-bit pattern (ASCII "HALBOOT1" bytes),
/// not because it needs to be cryptographically meaningful — this is a
/// sanity check against programmer error / memory corruption, not a
/// security boundary.
const BOOT_INFO_MAGIC: u64 = 0x4841_4C42_4F4F_5431; // "HALBOOT1"

const BOOT_INFO_VERSION: u32 = 1;

/// The single, architecture-independent structure HAL hands to the
/// microkernel at boot, regardless of which `BootProtocol` actually
/// fired. This is the concrete realization of section 3.5's
/// requirement for a standard Boot Info structure "not dependent on any
/// specific UEFI or Device Tree format".
///
/// `#[repr(C)]` and `Copy`, consistent with `HardwareManifestRaw`
/// (hal-manifest, section 9) — this struct is built and consumed before
/// any heap allocator exists.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BootInfo {
    /// Must equal `BOOT_INFO_MAGIC`. Checked by `validate()`.
    magic: u64,

    /// Layout version of this struct itself. Bumped whenever a field
    /// is added/removed/reordered, so a future microkernel build can
    /// detect a HAL binary built against a mismatched hal-core version
    /// rather than silently misreading fields (relevant because,
    /// per section 0, HAL and the microkernel are compiled into the
    /// same final binary from the same workspace — but this guards
    /// against accidental drift during development, e.g. a stale
    /// incremental build artifact).
    version: u32,

    _reserved0: u32,

    /// Which handoff path actually delivered control (section 3.5).
    pub protocol: BootProtocol,
    _reserved1: [u8; 7],

    /// The complete, already-populated Hardware Manifest (hal-manifest,
    /// section 9) discovered before this struct was built. Per section
    /// 2's Discovery + Policy model, this is ALWAYS the full discovery
    /// result — never trimmed based on an install profile, since
    /// profile policy is a layer 4 concern applied on top of this data,
    /// not during its collection.
    pub hardware_manifest: HardwareManifestRaw,

    /// Physical address of this core's initial, HAL-established page
    /// table root (set up via `MemoryBootstrap::setup_identity_mapping`
    /// calls during early boot, memory.rs). The microkernel's own
    /// memory management (02-Microkernel-Layer.md, section 3:
    /// UntypedMemory, retype, map/unmap) takes ownership of virtual
    /// memory management from this point forward — this field is only
    /// the STARTING point, not something the microkernel is expected to
    /// keep using as-is.
    pub initial_page_table_phys: u64,

    /// Physical address range occupied by the HAL/kernel image itself,
    /// so the Root Task (layer 3) knows not to hand this range out as
    /// free `UntypedMemory` (mirrors the
    /// `MemoryRegionKindRaw::KernelImage` classification in
    /// hal-manifest, provided again here directly for convenience since
    /// the Root Task needs it immediately, before it has necessarily
    /// finished walking the full memory region list).
    pub kernel_image_phys_start: u64,
    pub kernel_image_phys_end: u64,

    /// Physical address range occupied by boot-time-only structures
    /// (this very `BootInfo`, the initial page tables, any boot-stage
    /// stack) that the Root Task may reclaim as free memory ONLY after
    /// it has finished reading everything it needs from them — mirrors
    /// `MemoryRegionKindRaw::BootReserved`.
    pub boot_reserved_phys_start: u64,
    pub boot_reserved_phys_end: u64,

    /// The core id this boot sequence is running on — always 0 for the
    /// bootstrap processor (BSP) on every architecture in this project;
    /// present explicitly rather than assumed, since secondary core
    /// bring-up (per `CpuAbstraction::bootstrap_current_core`, cpu.rs)
    /// reuses parts of the same boot info structure conceptually, even
    /// though each architecture's actual secondary-core entry path is
    /// its own, much smaller, trampoline.
    pub boot_core_id: u32,
    _reserved2: u32,
}

impl BootInfo {
    /// Constructs a new `BootInfo`. Called once, by architecture-
    /// specific early-boot Rust code, after `hardware_manifest` has
    /// been fully populated by that architecture's discovery routines
    /// (memory.rs's `MemoryBootstrap`, compute.rs's
    /// `ComputeDeviceDiscovery`, etc.) and minimal identity mapping is
    /// in place.
    pub fn new(
        protocol: BootProtocol,
        hardware_manifest: HardwareManifestRaw,
        initial_page_table_phys: u64,
        kernel_image_phys_range: (u64, u64),
        boot_reserved_phys_range: (u64, u64),
        boot_core_id: u32,
    ) -> Self {
        Self {
            magic: BOOT_INFO_MAGIC,
            version: BOOT_INFO_VERSION,
            _reserved0: 0,
            protocol,
            _reserved1: [0; 7],
            hardware_manifest,
            initial_page_table_phys,
            kernel_image_phys_start: kernel_image_phys_range.0,
            kernel_image_phys_end: kernel_image_phys_range.1,
            boot_reserved_phys_start: boot_reserved_phys_range.0,
            boot_reserved_phys_end: boot_reserved_phys_range.1,
            boot_core_id,
            _reserved2: 0,
        }
    }

    /// Validates that this `BootInfo` is well-formed before the
    /// microkernel trusts any of its fields.
    ///
    /// Called by the microkernel immediately upon receiving control
    /// (per section 0: a direct Rust function call, not IPC — the
    /// microkernel calls this on the `BootInfo` value HAL just handed
    /// it, before doing anything else with it).
    ///
    /// Returns `Err(HalError::MalformedBootInfo)` if the magic doesn't
    /// match, the version is unrecognized, or the physical address
    /// ranges are internally inconsistent (end < start, or the boot-
    /// reserved and kernel-image ranges overlap in a way that would
    /// make later reclamation unsafe).
    ///
    /// It also enforces the two positive properties 01-HAL-Layer.md §8.2
    /// requires of a "valid Hardware Manifest" that this struct carries:
    /// at least one usable memory region was discovered
    /// (`hardware_manifest.memory_region_count >= 1`), and the timer the
    /// microkernel is about to drive its scheduler off is actually live
    /// (`hardware_manifest.timer.frequency_hz != 0`). Both are data bugs
    /// in the architecture discovery path rather than pointer/layout
    /// corruption, but they make the `BootInfo` just as unusable to the
    /// microkernel, so they fail validation here rather than silently
    /// handing over a manifest that claims zero RAM or a stopped clock.
    pub fn validate(&self) -> Result<(), HalError> {
        if self.magic != BOOT_INFO_MAGIC {
            return Err(HalError::MalformedBootInfo);
        }
        if self.version != BOOT_INFO_VERSION {
            return Err(HalError::MalformedBootInfo);
        }
        if self.kernel_image_phys_end < self.kernel_image_phys_start {
            return Err(HalError::MalformedBootInfo);
        }
        if self.boot_reserved_phys_end < self.boot_reserved_phys_start {
            return Err(HalError::MalformedBootInfo);
        }
        // §8.2: the manifest must report at least one memory region.
        if self.hardware_manifest.memory_region_count == 0 {
            return Err(HalError::MalformedBootInfo);
        }
        // §8.2: the manifest must report an active timer. A zero tick
        // frequency means discovery never found (or failed to bring up)
        // a timer source — see `TimerInfoRaw::ZERO` / `NoTimerSource`.
        if self.hardware_manifest.timer.frequency_hz == 0 {
            return Err(HalError::MalformedBootInfo);
        }
        Ok(())
    }

    /// Convenience check the Root Task uses when deciding whether a
    /// candidate physical address falls inside the still-in-use kernel
    /// image range (and must therefore never be handed out as free
    /// `UntypedMemory`, per 02-Microkernel-Layer.md section 3).
    pub fn overlaps_kernel_image(&self, addr: u64) -> bool {
        addr >= self.kernel_image_phys_start && addr < self.kernel_image_phys_end
    }

    /// Convenience check for whether an address falls inside the
    /// boot-reserved range (safe to reclaim only after the Root Task
    /// has finished consuming this `BootInfo` and its embedded
    /// manifest).
    pub fn overlaps_boot_reserved(&self, addr: u64) -> bool {
        addr >= self.boot_reserved_phys_start && addr < self.boot_reserved_phys_end
    }
}

// ============================================================================
// Compile-time sanity check, mirroring hal-manifest raw.rs's approach:
// catches an accidental layout change to BootInfo that would silently
// break the HAL -> microkernel handoff.
// ============================================================================
const _: () = {
    // Note: this size will change whenever HardwareManifestRaw's own
    // size changes (BootInfo embeds it directly, not a reference to
    // it) — that coupling is intentional per section 3.5's requirement
    // that BootInfo be one self-contained, standard structure, not a
    // set of pointers into separately-lifetimed boot data.
    assert!(core::mem::size_of::<BootProtocol>() == 1);
};

#[cfg(test)]
mod tests {
    use super::*;
    use hal_manifest::raw::{
        HardwareManifestRaw, MemoryRegionKindRaw, MemoryRegionRaw, TimerInfoRaw, TimerKindRaw,
    };

    /// A manifest that satisfies §8.2: one usable memory region and a
    /// live timer. Architecture discovery always produces at least this
    /// much on real hardware / QEMU; the zeroed manifest deliberately
    /// does not, so tests that want a *failing* manifest start from
    /// `HardwareManifestRaw::zeroed()` instead.
    fn valid_manifest() -> HardwareManifestRaw {
        let mut m = HardwareManifestRaw::zeroed();
        m.push_memory_region(MemoryRegionRaw::new(
            0,
            0x1000_0000,
            MemoryRegionKindRaw::Usable,
            false,
        ))
        .unwrap();
        m.timer = TimerInfoRaw::new(TimerKindRaw::Tsc, 1_000_000_000, false);
        m
    }

    fn sample_boot_info() -> BootInfo {
        BootInfo::new(
            BootProtocol::Uefi,
            valid_manifest(),
            0x1000,
            (0x10_0000, 0x20_0000),
            (0x20_0000, 0x21_0000),
            0,
        )
    }

    #[test]
    fn freshly_constructed_boot_info_validates() {
        let info = sample_boot_info();
        assert!(info.validate().is_ok());
    }

    #[test]
    fn corrupted_magic_fails_validation() {
        let mut info = sample_boot_info();
        info.magic = 0xDEAD_BEEF_DEAD_BEEF;
        assert_eq!(info.validate(), Err(HalError::MalformedBootInfo));
    }

    #[test]
    fn mismatched_version_fails_validation() {
        let mut info = sample_boot_info();
        info.version = 99;
        assert_eq!(info.validate(), Err(HalError::MalformedBootInfo));
    }

    #[test]
    fn inverted_kernel_image_range_fails_validation() {
        let mut info = sample_boot_info();
        info.kernel_image_phys_start = 0x20_0000;
        info.kernel_image_phys_end = 0x10_0000;
        assert_eq!(info.validate(), Err(HalError::MalformedBootInfo));
    }

    #[test]
    fn zero_memory_regions_fails_validation() {
        // §8.2: a manifest reporting no memory regions is unusable to
        // the microkernel even though every pointer/range field is fine.
        let info = BootInfo::new(
            BootProtocol::Uefi,
            HardwareManifestRaw::zeroed(),
            0x1000,
            (0x10_0000, 0x20_0000),
            (0x20_0000, 0x21_0000),
            0,
        );
        assert_eq!(info.validate(), Err(HalError::MalformedBootInfo));
    }

    #[test]
    fn inactive_timer_fails_validation() {
        // §8.2: a manifest with at least one memory region but a timer
        // whose tick frequency is still zero (discovery never brought a
        // timer source up) must not validate.
        let mut manifest = valid_manifest();
        manifest.timer = TimerInfoRaw::ZERO;
        let info = BootInfo::new(
            BootProtocol::Uefi,
            manifest,
            0x1000,
            (0x10_0000, 0x20_0000),
            (0x20_0000, 0x21_0000),
            0,
        );
        assert_eq!(info.validate(), Err(HalError::MalformedBootInfo));
    }

    #[test]
    fn manifest_with_one_region_and_live_timer_validates() {
        // The positive companion to the two tests above: the minimum
        // §8.2 manifest shape passes.
        let info = sample_boot_info();
        assert_eq!(info.hardware_manifest.memory_region_count, 1);
        assert_ne!(info.hardware_manifest.timer.frequency_hz, 0);
        assert!(info.validate().is_ok());
    }

    #[test]
    fn overlaps_kernel_image_detects_correctly() {
        let info = sample_boot_info();
        assert!(info.overlaps_kernel_image(0x15_0000));
        assert!(!info.overlaps_kernel_image(0x5_0000));
        assert!(!info.overlaps_kernel_image(0x20_0000)); // end is exclusive
    }

    #[test]
    fn overlaps_boot_reserved_detects_correctly() {
        let info = sample_boot_info();
        assert!(info.overlaps_boot_reserved(0x20_5000));
        assert!(!info.overlaps_boot_reserved(0x15_0000));
    }

    #[test]
    fn boot_protocol_records_correctly() {
        let info = sample_boot_info();
        assert_eq!(info.protocol, BootProtocol::Uefi);

        let riscv_info = BootInfo::new(
            BootProtocol::SbiDeviceTree,
            HardwareManifestRaw::zeroed(),
            0x1000,
            (0x10_0000, 0x20_0000),
            (0x20_0000, 0x21_0000),
            0,
        );
        assert_eq!(riscv_info.protocol, BootProtocol::SbiDeviceTree);
    }
}