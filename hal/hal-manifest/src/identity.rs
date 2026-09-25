//! ============================================================================
//! identity.rs
//!
//! Purpose: the raw, UNCANONICALISED board-level machine identifiers the
//! firmware exposes (SMBIOS Type 1 / 2 / 3 today; Device Tree root
//! properties later), in a fixed-size, no-heap, byte-exact form.
//!
//! Architecture reference: docs/machine-id.md sections 3 and 11
//! (01-HAL-Layer.md: discovery is always complete, never profile-limited).
//!
//! Position in the system: produced by the bootloader (SMBIOS parse) and
//! decoded by each `hal-<arch>` crate into `HardwareManifestRaw::
//! machine_identity`; consumed by the kernel, which feeds it to the
//! `machine-id-core` crate. The HAL only carries bytes; canonicalisation,
//! placeholder rejection and hashing live in `machine-id-core`.
//!
//! Safety/invariants: every field is a plain byte or byte array (no u16+,
//! no padding), so the layout is identical on every architecture and can
//! be copied verbatim through the bootloader handoff block
//! (`to_bytes` / `from_bytes`) with no endianness or alignment concerns.
//! Reachable via `hal_manifest::raw::*` (re-exported from raw.rs).
//! ============================================================================

/// Capacity of one text field's byte array (the length lives in `len`).
pub const IDENTITY_TEXT_MAX: usize = 63;

/// One raw text identifier: `len` valid bytes in `bytes`. `len == 0`
/// means "absent". Bytes are exactly as firmware reported them (after the
/// bootloader truncated them to `IDENTITY_TEXT_MAX`); no trimming here.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct IdentityTextRaw {
    pub len: u8,
    pub bytes: [u8; IDENTITY_TEXT_MAX],
}

impl IdentityTextRaw {
    pub const ZERO: Self = Self { len: 0, bytes: [0; IDENTITY_TEXT_MAX] };

    /// Builds a field from raw bytes, truncating to `IDENTITY_TEXT_MAX`.
    pub fn from_slice(src: &[u8]) -> Self {
        let n = src.len().min(IDENTITY_TEXT_MAX);
        let mut bytes = [0u8; IDENTITY_TEXT_MAX];
        bytes[..n].copy_from_slice(&src[..n]);
        Self { len: n as u8, bytes }
    }

    /// The valid bytes. A corrupt `len` above capacity is clamped, never
    /// trusted (the record crosses a firmware/bootloader trust boundary).
    pub fn as_slice(&self) -> &[u8] {
        let n = (self.len as usize).min(IDENTITY_TEXT_MAX);
        &self.bytes[..n]
    }
}

/// Where the identity fields came from. Values are part of the handoff
/// byte contract (`MachineIdentityRaw::source`).
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IdentitySourceRaw {
    /// No identity data at all (riscv64 today; UEFI without SMBIOS).
    None = 0,
    /// SMBIOS 2.x / 3.x structure table located via the UEFI configuration table.
    Smbios = 1,
    // TODO(spec): 2 = Device Tree root `serial-number` (riscv64 / DT-booted
    // arm64), docs/machine-id.md section 3 item 2. Not implemented.
}

/// Bit set in `MachineIdentityRaw::present` when `uuid` holds the SMBIOS
/// Type 1 UUID bytes exactly as stored in the table.
pub const IDENTITY_PRESENT_UUID: u8 = 1 << 0;

/// Byte size of `MachineIdentityRaw` on the handoff wire.
pub const MACHINE_IDENTITY_RAW_SIZE: usize = 344;

/// Raw board-level identity record. Size 344 bytes, alignment 1.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MachineIdentityRaw {
    /// `IDENTITY_PRESENT_*` bits. Absence of everything is `0`.
    pub present: u8,
    /// `IdentitySourceRaw` as a byte (a byte, not the enum, so a corrupt
    /// handoff cannot materialise an invalid enum value).
    pub source: u8,
    /// SMBIOS spec version the table declares (entry point major.minor).
    /// Decides the UUID byte-order rule: >= 2.6 stores the first three
    /// UUID fields little-endian (docs/machine-id.md 5.1, TODO-13).
    pub smbios_major: u8,
    pub smbios_minor: u8,
    pub _reserved: [u8; 4],
    /// SMBIOS Type 1 UUID, the 16 bytes exactly as stored in the table.
    pub uuid: [u8; 16],
    /// Type 1 manufacturer (weak id W2 + virtual-machine detection).
    pub manufacturer: IdentityTextRaw,
    /// Type 1 product name (weak id W2 + virtual-machine detection).
    pub product: IdentityTextRaw,
    /// Type 1 serial number (S3).
    pub system_serial: IdentityTextRaw,
    /// Type 2 baseboard serial number (S2).
    pub board_serial: IdentityTextRaw,
    /// Type 3 chassis serial number (S3 fallback).
    pub chassis_serial: IdentityTextRaw,
}

impl MachineIdentityRaw {
    pub const ZERO: Self = Self {
        present: 0,
        source: IdentitySourceRaw::None as u8,
        smbios_major: 0,
        smbios_minor: 0,
        _reserved: [0; 4],
        uuid: [0; 16],
        manufacturer: IdentityTextRaw::ZERO,
        product: IdentityTextRaw::ZERO,
        system_serial: IdentityTextRaw::ZERO,
        board_serial: IdentityTextRaw::ZERO,
        chassis_serial: IdentityTextRaw::ZERO,
    };

    /// Serialises to the handoff byte layout (field order, no padding).
    pub fn to_bytes(&self) -> [u8; MACHINE_IDENTITY_RAW_SIZE] {
        let mut out = [0u8; MACHINE_IDENTITY_RAW_SIZE];
        out[0] = self.present;
        out[1] = self.source;
        out[2] = self.smbios_major;
        out[3] = self.smbios_minor;
        out[4..8].copy_from_slice(&self._reserved);
        out[8..24].copy_from_slice(&self.uuid);
        let mut off = 24;
        for t in [&self.manufacturer, &self.product, &self.system_serial, &self.board_serial, &self.chassis_serial] {
            out[off] = t.len;
            out[off + 1..off + 64].copy_from_slice(&t.bytes);
            off += 64;
        }
        out
    }

    /// Parses the handoff byte layout. Never fails: a `len` byte above
    /// capacity is clamped; an unknown `source` is kept as a byte and
    /// treated as "no identity" by consumers.
    pub fn from_bytes(b: &[u8; MACHINE_IDENTITY_RAW_SIZE]) -> Self {
        let mut s = Self::ZERO;
        s.present = b[0];
        s.source = b[1];
        s.smbios_major = b[2];
        s.smbios_minor = b[3];
        s._reserved.copy_from_slice(&b[4..8]);
        s.uuid.copy_from_slice(&b[8..24]);
        let mut off = 24;
        for t in [
            &mut s.manufacturer,
            &mut s.product,
            &mut s.system_serial,
            &mut s.board_serial,
            &mut s.chassis_serial,
        ] {
            t.len = b[off].min(IDENTITY_TEXT_MAX as u8);
            t.bytes.copy_from_slice(&b[off + 1..off + 64]);
            off += 64;
        }
        s
    }

    /// Whether the SMBIOS UUID field is meaningful.
    pub fn has_uuid(&self) -> bool {
        self.present & IDENTITY_PRESENT_UUID != 0
    }
}

/// Magic word introducing the identity trailer in the bootloader handoff
/// block (ASCII `"SIMSMB"` + 16-bit layout version). Additive like the
/// framebuffer's magic: absent/zeroed/newer -> "no identity". Must stay
/// numerically equal to `uefi-bootloader`'s `SMBIOS_HANDOFF_MAGIC`.
pub const IDENTITY_HANDOFF_MAGIC: u64 = 0x5349_4D53_4D42_0001;

/// Byte size of the identity trailer: magic (8) + the 344-byte record.
pub const IDENTITY_HANDOFF_SIZE: usize = 8 + MACHINE_IDENTITY_RAW_SIZE;

/// Decodes the identity trailer. Wrong magic -> `MachineIdentityRaw::ZERO`.
/// Shared by every UEFI-booted `hal-<arch>` crate (pure, host-testable).
pub fn decode_identity_trailer(bytes: &[u8; IDENTITY_HANDOFF_SIZE]) -> MachineIdentityRaw {
    let mut magic = [0u8; 8];
    magic.copy_from_slice(&bytes[..8]);
    if u64::from_le_bytes(magic) != IDENTITY_HANDOFF_MAGIC {
        return MachineIdentityRaw::ZERO;
    }
    let mut rec = [0u8; MACHINE_IDENTITY_RAW_SIZE];
    rec.copy_from_slice(&bytes[8..]);
    MachineIdentityRaw::from_bytes(&rec)
}

// Compile-time layout guard: header(8) + uuid(16) + 5 * text(64) = 344.
const _: () = {
    assert!(core::mem::size_of::<IdentityTextRaw>() == 64);
    assert!(core::mem::size_of::<MachineIdentityRaw>() == MACHINE_IDENTITY_RAW_SIZE);
    assert!(core::mem::align_of::<MachineIdentityRaw>() == 1);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_the_handoff_bytes() {
        let mut id = MachineIdentityRaw::ZERO;
        id.present = IDENTITY_PRESENT_UUID;
        id.source = IdentitySourceRaw::Smbios as u8;
        id.smbios_major = 3;
        id.smbios_minor = 4;
        id.uuid = [7; 16];
        id.system_serial = IdentityTextRaw::from_slice(b"SN-123");
        id.board_serial = IdentityTextRaw::from_slice(&[b'x'; 200]);
        let back = MachineIdentityRaw::from_bytes(&id.to_bytes());
        assert_eq!(back, id);
        assert_eq!(back.board_serial.as_slice().len(), IDENTITY_TEXT_MAX);
        assert!(back.has_uuid());
    }

    #[test]
    fn trailer_needs_the_magic() {
        let mut id = MachineIdentityRaw::ZERO;
        id.source = IdentitySourceRaw::Smbios as u8;
        let mut t = [0u8; IDENTITY_HANDOFF_SIZE];
        t[..8].copy_from_slice(&IDENTITY_HANDOFF_MAGIC.to_le_bytes());
        t[8..].copy_from_slice(&id.to_bytes());
        assert_eq!(decode_identity_trailer(&t), id);
        t[0] ^= 1;
        assert_eq!(decode_identity_trailer(&t), MachineIdentityRaw::ZERO);
        assert_eq!(decode_identity_trailer(&[0u8; IDENTITY_HANDOFF_SIZE]), MachineIdentityRaw::ZERO);
    }

    #[test]
    fn corrupt_length_is_clamped() {
        let mut b = [0u8; MACHINE_IDENTITY_RAW_SIZE];
        b[24] = 250;
        let id = MachineIdentityRaw::from_bytes(&b);
        assert_eq!(id.manufacturer.len as usize, IDENTITY_TEXT_MAX);
        assert_eq!(id.manufacturer.as_slice().len(), IDENTITY_TEXT_MAX);
        assert!(!MachineIdentityRaw::ZERO.has_uuid());
    }
}
