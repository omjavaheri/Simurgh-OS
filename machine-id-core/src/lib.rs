//! Purpose: derive the machine id from raw board-level identifiers, purely
//! and deterministically (docs/machine-id.md sections 5, 6, 8, 9).
//!
//! What is implemented (v1, owner decisions 2026-09-25):
//!   - the id is built from BOARD-LEVEL identifiers only: S1 SMBIOS system
//!     UUID, S2 baseboard serial, S3 system serial (chassis serial as its
//!     fallback). NIC MAC, disk and TPM are deliberately left out (no
//!     central source for them exists yet, see the doc's section 2).
//!   - recompute-only stability: same hardware -> same id after reinstall.
//!     The persisted identifier record and K-of-N matching (sections 7.2,
//!     10) are NOT implemented: `TODO(spec)` TODO-1 / TODO-10 in the doc.
//!   - the id is GUID-shaped (RFC 4122 version/variant bits, section 6).
//!
//! Position: `#![no_std]`, no heap, no arch code. `uefi-bootloader` uses the
//! `smbios` module; `kernel-core` calls [`compute`] once at boot.
//!
//! Safety/invariants: no `unsafe`; `compute` is a pure function of its
//! input, so two boots on unchanged hardware give the same id.

#![no_std]

#[cfg(test)]
extern crate std;

pub mod sha256;
pub mod smbios;

use hal_manifest::raw::MachineIdentityRaw;
use sha256::Sha256;

/// Hash domain label; bumping it changes every id (doc section 6, TODO-9).
pub const LABEL: &[u8] = b"simurgh-machine-id-v1";

/// Algorithm version reported next to the id (matches the label's `v1`).
pub const ALGORITHM_VERSION: u32 = 1;

/// Tags of the hashed fields (doc section 4 / 6). Emitted in ascending order.
pub const TAG_SYSTEM_UUID: u8 = 0x01; // S1
pub const TAG_BOARD_SERIAL: u8 = 0x02; // S2
pub const TAG_SYSTEM_SERIAL: u8 = 0x03; // S3 (chassis serial as fallback)
/// Weak salt tags (0x80+). Used ONLY when no strong id is accepted, so a
/// weak id at least differs between machine models; never mixed into a
/// strong id (doc section 7.3 recommendation, TODO-3).
pub const TAG_WEAK_MANUFACTURER: u8 = 0x81;
pub const TAG_WEAK_PRODUCT: u8 = 0x82;

/// `MachineId::strong_mask` bits: which strong identifiers were accepted.
pub const STRONG_UUID: u8 = 1 << 0;
pub const STRONG_BOARD_SERIAL: u8 = 1 << 1;
pub const STRONG_SYSTEM_SERIAL: u8 = 1 << 2;

/// The result of one derivation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MachineId {
    /// GUID-shaped 128-bit id (RFC 4122 version 5 / variant 10 bits set).
    pub id: [u8; 16],
    /// No strong identifier was accepted: NOT guaranteed unique
    /// (doc section 8). Consumers must treat it as advisory only.
    pub weak: bool,
    /// Firmware strings identify a hypervisor (doc section 9).
    pub virtual_machine: bool,
    /// `STRONG_*` bits of the strong identifiers that went into the hash.
    pub strong_mask: u8,
}

// ---------------------------------------------------------------------------
// Canonicalisation (doc section 5.1)
// ---------------------------------------------------------------------------

/// Placeholder strings OEMs leave in SMBIOS (doc 5.1, list version v1).
/// Compared after cleaning, so entries are lowercase without whitespace,
/// hyphens, colons or braces. Growing this list changes existing ids, so
/// it may only grow together with a new `LABEL` (TODO-9).
const PLACEHOLDERS: &[&[u8]] = &[
    b"tobefilledbyoem",
    b"tobefilledbyo.e.m.",
    b"tobefilledbyo.e.m",
    b"defaultstring",
    b"default",
    b"notspecified",
    b"notapplicable",
    b"notavailable",
    b"n/a",
    b"na",
    b"none",
    b"null",
    b"unknown",
    b"systemserialnumber",
    b"systemproductname",
    b"systemmanufacturer",
    b"baseboardserialnumber",
    b"chassisserialnumber",
    b"oem",
    b"ok",
    b"123456789",
    b"0123456789",
    b"serialnumber",
    b"invalid",
    b"empty",
    b"filledbyoem",
];

/// Maximum length of a cleaned text identifier.
pub const CLEAN_MAX: usize = 64;

/// Cleans one raw text identifier (doc 5.1): trims whitespace/NULs,
/// lowercases ASCII, drops internal whitespace, hyphens, colons and braces,
/// then rejects placeholders. Returns the cleaned length in `out`, or
/// `None` if the identifier is rejected (treated as absent).
pub fn clean_text(raw: &[u8], out: &mut [u8; CLEAN_MAX]) -> Option<usize> {
    let mut n = 0usize;
    for &c in raw {
        match c {
            0 | b' ' | b'\t' | b'\r' | b'\n' | 0x0B | 0x0C | b'-' | b':' | b'{' | b'}' => {}
            _ => {
                if n == CLEAN_MAX {
                    // Longer than any real serial; keep the prefix (stable).
                    break;
                }
                out[n] = c.to_ascii_lowercase();
                n += 1;
            }
        }
    }
    let s = &out[..n];
    if n < 4 || s.iter().all(|&c| c == s[0]) {
        return None;
    }
    if PLACEHOLDERS.iter().any(|p| *p == s) {
        return None;
    }
    Some(n)
}

/// Vendor UUIDs known to be duplicated across boards, in canonical
/// (RFC 4122 text) byte order. Same versioning rule as `PLACEHOLDERS`.
const DUPLICATED_UUIDS: &[[u8; 16]] = &[
    // 03000200-0400-0500-0006-000700080009 (AMI reference default)
    [0x03, 0x00, 0x02, 0x00, 0x04, 0x00, 0x05, 0x00, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09],
    // 00020003-0004-0005-0006-000700080009
    [0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09],
    // 12345678-1234-5678-90ab-cddeefaabbcc
    [0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xDE, 0xEF, 0xAA, 0xBB, 0xCC],
];

/// SMBIOS 2.6+ stores the first three UUID fields little-endian; convert
/// to the RFC 4122 text/byte order. Older tables are used as reported
/// (TODO-13: exact treatment for < 2.6 firmware is still an open question).
pub fn canonical_uuid(raw: &[u8; 16], major: u8, minor: u8) -> [u8; 16] {
    let mut u = *raw;
    if major > 2 || (major == 2 && minor >= 6) {
        u[0..4].reverse();
        u[4..6].reverse();
        u[6..8].reverse();
    }
    u
}

/// Accepts a canonical UUID or rejects it (all-same byte covers all-zero and
/// all-0xFF; plus the duplicated-vendor list, checked in both byte orders).
fn uuid_acceptable(canonical: &[u8; 16], raw: &[u8; 16]) -> bool {
    if canonical.iter().all(|&b| b == canonical[0]) {
        return false;
    }
    !DUPLICATED_UUIDS.iter().any(|d| d == canonical || d == raw)
}

// ---------------------------------------------------------------------------
// Virtual machine detection (doc section 9, firmware-string half)
// ---------------------------------------------------------------------------

const VM_MARKERS: &[&[u8]] = &[
    b"qemu",
    b"kvm",
    b"vmware",
    b"virtualbox",
    b"innotek",
    b"xen",
    b"bochs",
    b"parallels",
    b"bhyve",
    b"openstack",
    b"google compute",
    b"amazon ec2",
    b"virtual machine",
    b"hyper-v",
];

fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w.iter().zip(needle).all(|(a, b)| a.to_ascii_lowercase() == *b))
}

fn looks_virtual(raw: &MachineIdentityRaw) -> bool {
    // TODO(spec): also fold in the CPUID hypervisor bit and virtual-OUI
    // MACs (doc section 9) once those inputs reach this crate.
    VM_MARKERS
        .iter()
        .any(|m| contains_ci(raw.manufacturer.as_slice(), m) || contains_ci(raw.product.as_slice(), m))
}

// ---------------------------------------------------------------------------
// Hash construction (doc section 6)
// ---------------------------------------------------------------------------

fn put_field(h: &mut Sha256, tag: u8, value: &[u8]) {
    h.update(&[tag]);
    h.update(&(value.len() as u16).to_be_bytes());
    h.update(value);
}

/// Derives the machine id from the raw identity record.
pub fn compute(raw: &MachineIdentityRaw) -> MachineId {
    let mut h = Sha256::new();
    h.update(&(LABEL.len() as u16).to_be_bytes());
    h.update(LABEL);

    let mut strong_mask = 0u8;
    let mut buf = [0u8; CLEAN_MAX];

    // Only SMBIOS-sourced records are interpreted; anything else is "no id".
    let smbios = raw.source == hal_manifest::raw::IdentitySourceRaw::Smbios as u8;

    if smbios && raw.has_uuid() {
        let canon = canonical_uuid(&raw.uuid, raw.smbios_major, raw.smbios_minor);
        if uuid_acceptable(&canon, &raw.uuid) {
            put_field(&mut h, TAG_SYSTEM_UUID, &canon);
            strong_mask |= STRONG_UUID;
        }
    }
    if smbios {
        if let Some(n) = clean_text(raw.board_serial.as_slice(), &mut buf) {
            put_field(&mut h, TAG_BOARD_SERIAL, &buf[..n]);
            strong_mask |= STRONG_BOARD_SERIAL;
        }
        let sys = clean_text(raw.system_serial.as_slice(), &mut buf);
        let sys = match sys {
            Some(n) => Some(n),
            None => clean_text(raw.chassis_serial.as_slice(), &mut buf),
        };
        if let Some(n) = sys {
            put_field(&mut h, TAG_SYSTEM_SERIAL, &buf[..n]);
            strong_mask |= STRONG_SYSTEM_SERIAL;
        }
    }

    let weak = strong_mask == 0;
    if weak && smbios {
        // Weak salt: model identity only, so weak ids differ between models.
        let mut b1 = [0u8; CLEAN_MAX];
        if let Some(n) = clean_text(raw.manufacturer.as_slice(), &mut b1) {
            put_field(&mut h, TAG_WEAK_MANUFACTURER, &b1[..n]);
        }
        let mut b2 = [0u8; CLEAN_MAX];
        if let Some(n) = clean_text(raw.product.as_slice(), &mut b2) {
            put_field(&mut h, TAG_WEAK_PRODUCT, &b2[..n]);
        }
    }

    let digest = h.finalize();
    let mut id = [0u8; 16];
    id.copy_from_slice(&digest[..16]);
    id[6] = (id[6] & 0x0F) | 0x50; // version 5 style (TODO-7: custom marker?)
    id[8] = (id[8] & 0x3F) | 0x80; // RFC 4122 variant 10xx

    MachineId { id, weak, virtual_machine: smbios && looks_virtual(raw), strong_mask }
}

/// Canonical lowercase `8-4-4-4-12` text form (36 ASCII bytes).
pub fn format_guid(id: &[u8; 16]) -> [u8; 36] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = [b'-'; 36];
    let mut o = 0;
    for (i, b) in id.iter().enumerate() {
        if i == 4 || i == 6 || i == 8 || i == 10 {
            o += 1;
        }
        out[o] = HEX[(b >> 4) as usize];
        out[o + 1] = HEX[(b & 15) as usize];
        o += 2;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hal_manifest::raw::{IdentitySourceRaw, IdentityTextRaw, IDENTITY_PRESENT_UUID};

    fn raw(uuid: Option<[u8; 16]>, board: &str, sys: &str, chassis: &str) -> MachineIdentityRaw {
        let mut r = MachineIdentityRaw::ZERO;
        r.source = IdentitySourceRaw::Smbios as u8;
        r.smbios_major = 3;
        r.smbios_minor = 4;
        if let Some(u) = uuid {
            r.uuid = u;
            r.present |= IDENTITY_PRESENT_UUID;
        }
        r.board_serial = IdentityTextRaw::from_slice(board.as_bytes());
        r.system_serial = IdentityTextRaw::from_slice(sys.as_bytes());
        r.chassis_serial = IdentityTextRaw::from_slice(chassis.as_bytes());
        r.manufacturer = IdentityTextRaw::from_slice(b"Acme Corp");
        r.product = IdentityTextRaw::from_slice(b"Model X");
        r
    }

    fn text(id: &[u8; 16]) -> std::string::String {
        std::string::String::from_utf8(format_guid(id).to_vec()).unwrap()
    }

    const UUID: [u8; 16] = [0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];

    /// The SMBIOS-spec style example: LE fields swapped for 2.6+.
    #[test]
    fn uuid_mixed_endian_fix() {
        let c = canonical_uuid(&UUID, 3, 0);
        assert_eq!(c, [0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_eq!(canonical_uuid(&UUID, 2, 6), c);
        assert_eq!(canonical_uuid(&UUID, 2, 5), UUID);
    }

    /// Fixed test vector: preimage (built independently with printf and
    /// hashed with sha256sum) is
    /// u16be(21) "simurgh-machine-id-v1"
    /// 01 0010 <canonical uuid 33221100-5544-7766-8899-aabbccddeeff>
    /// 02 0006 "bsn777" (hyphen dropped)
    /// 03 0006 "sn0042".
    #[test]
    fn fixed_vector_strong_id() {
        let r = compute(&raw(Some(UUID), "BSN-777", "SN-0042", "CH-9"));
        assert!(!r.weak);
        assert_eq!(r.strong_mask, 0b111);
        assert!(!r.virtual_machine);
        assert_eq!(text(&r.id), EXPECTED_STRONG);
    }

    #[test]
    fn deterministic_and_field_sensitive() {
        let a = compute(&raw(Some(UUID), "BSN-777", "SN-0042", ""));
        let b = compute(&raw(Some(UUID), "BSN-777", "SN-0042", ""));
        assert_eq!(a, b);
        let c = compute(&raw(Some(UUID), "BSN-778", "SN-0042", ""));
        assert_ne!(a.id, c.id);
        // Version and variant bits.
        assert_eq!(a.id[6] >> 4, 5);
        assert_eq!(a.id[8] >> 6, 0b10);
        // Whitespace/case/hyphen differences do not change the id.
        let d = compute(&raw(Some(UUID), " bsn 777 ", "sn:0042", ""));
        assert_eq!(a.id, d.id);
    }

    #[test]
    fn chassis_serial_is_the_system_serial_fallback() {
        let a = compute(&raw(None, "", "To be filled by O.E.M.", "CH-1234"));
        assert_eq!(a.strong_mask, STRONG_SYSTEM_SERIAL);
        assert!(!a.weak);
        let b = compute(&raw(None, "", "CH-1234", ""));
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn placeholders_and_junk_are_rejected() {
        let mut buf = [0u8; CLEAN_MAX];
        for bad in [
            "", "   ", "abc", "0000000", "FFFFFFFF", "xxxx", "To Be Filled By O.E.M.", "Default string",
            "System Serial Number", "Not Specified", "None", "N/A", "123456789", "  Unknown\0\0", "{1111}",
        ] {
            assert!(clean_text(bad.as_bytes(), &mut buf).is_none(), "{bad:?} should be rejected");
        }
        assert_eq!(clean_text(b" Ab-Cd:12 ", &mut buf), Some(6));
        assert_eq!(&buf[..6], b"abcd12");
    }

    #[test]
    fn junk_uuids_are_rejected_and_fall_back_to_weak() {
        for u in [[0u8; 16], [0xFF; 16], [0x11; 16], DUPLICATED_UUIDS[0], DUPLICATED_UUIDS[1], DUPLICATED_UUIDS[2]] {
            let r = compute(&raw(Some(u), "", "", ""));
            assert!(r.weak, "{u:?}");
            assert_eq!(r.strong_mask, 0);
        }
    }

    #[test]
    fn weak_id_differs_by_model_and_no_smbios_is_weak() {
        let mut a = raw(None, "", "", "");
        let mut b = a;
        b.product = IdentityTextRaw::from_slice(b"Model Z");
        let (ra, rb) = (compute(&a), compute(&b));
        assert!(ra.weak && rb.weak);
        assert_ne!(ra.id, rb.id);
        a.source = IdentitySourceRaw::None as u8;
        let none = compute(&a);
        assert!(none.weak);
        assert_eq!(compute(&MachineIdentityRaw::ZERO).id, none.id);
    }

    #[test]
    fn virtual_flag() {
        let mut r = raw(Some(UUID), "", "", "");
        r.manufacturer = IdentityTextRaw::from_slice(b"QEMU");
        r.product = IdentityTextRaw::from_slice(b"Standard PC (Q35 + ICH9, 2009)");
        assert!(compute(&r).virtual_machine);
        r.manufacturer = IdentityTextRaw::from_slice(b"Microsoft Corporation");
        r.product = IdentityTextRaw::from_slice(b"Virtual Machine");
        assert!(compute(&r).virtual_machine);
        r.manufacturer = IdentityTextRaw::from_slice(b"LENOVO");
        r.product = IdentityTextRaw::from_slice(b"ThinkPad");
        assert!(!compute(&r).virtual_machine);
    }

    #[test]
    fn guid_text_format() {
        let id: [u8; 16] = core::array::from_fn(|i| (i as u8) * 0x11);
        assert_eq!(text(&id), "00112233-4455-6677-8899-aabbccddeeff");
    }

    /// Filled in from the independently computed reference (see the test above).
    const EXPECTED_STRONG: &str = "a971f05a-b3ac-500e-bf43-63757335ce57";
}
