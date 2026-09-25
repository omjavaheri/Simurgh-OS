//! Purpose: pure SMBIOS parsing for the machine id (docs/machine-id.md
//! sections 3 item 1 and 11): decode the 2.x / 3.x entry point to learn
//! where the structure table lives, then walk the table and extract the
//! Type 1 (system), Type 2 (baseboard) and Type 3 (chassis) fields into a
//! `MachineIdentityRaw`. No canonicalisation here (that is `crate::canon`).
//!
//! Position: called by `uefi-bootloader` (which owns the unsafe physical
//! memory reads and hands this module plain byte slices) and by host tests.
//! Safety/invariants: `no unsafe`; every offset is bounds-checked because
//! the table is firmware-controlled input; a truncated or malformed table
//! yields whatever was parsed before the damage, never a panic.

use hal_manifest::raw::{
    IdentitySourceRaw, IdentityTextRaw, MachineIdentityRaw, IDENTITY_PRESENT_UUID,
};

/// Where the structure table is, as declared by an SMBIOS entry point.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TableLocation {
    /// Physical address of the first structure.
    pub address: u64,
    /// Length of the structure table in bytes (SMBIOS3: the *maximum* size).
    pub length: u32,
    pub major: u8,
    pub minor: u8,
}

/// Upper bound on the table bytes the bootloader will read, so a corrupt
/// length can never make it walk arbitrary memory.
pub const MAX_TABLE_BYTES: u32 = 256 * 1024;

fn checksum_ok(b: &[u8]) -> bool {
    b.iter().fold(0u8, |a, x| a.wrapping_add(*x)) == 0
}

/// Decodes a 64-bit SMBIOS 3.x entry point (`_SM3_`, at least 24 bytes).
pub fn parse_entry_point_3(ep: &[u8]) -> Option<TableLocation> {
    if ep.len() < 24 || &ep[0..5] != b"_SM3_" {
        return None;
    }
    let len = ep[6] as usize;
    if len < 24 || len > ep.len() || !checksum_ok(&ep[..len]) {
        return None;
    }
    let length = u32::from_le_bytes([ep[12], ep[13], ep[14], ep[15]]);
    let address = u64::from_le_bytes([ep[16], ep[17], ep[18], ep[19], ep[20], ep[21], ep[22], ep[23]]);
    Some(TableLocation { address, length, major: ep[7], minor: ep[8] })
}

/// Decodes a 32-bit SMBIOS 2.x entry point (`_SM_`, at least 31 bytes).
pub fn parse_entry_point_2(ep: &[u8]) -> Option<TableLocation> {
    if ep.len() < 31 || &ep[0..4] != b"_SM_" {
        return None;
    }
    let len = ep[5] as usize;
    if len < 31 || len > ep.len() || !checksum_ok(&ep[..len]) {
        return None;
    }
    let length = u16::from_le_bytes([ep[0x16], ep[0x17]]) as u32;
    let address = u32::from_le_bytes([ep[0x18], ep[0x19], ep[0x1A], ep[0x1B]]) as u64;
    Some(TableLocation { address, length, major: ep[6], minor: ep[7] })
}

/// The `idx`-th (1-based) string of a structure's string-set, or empty.
fn string_at(strings: &[u8], idx: u8) -> &[u8] {
    if idx == 0 {
        return &[];
    }
    let mut n = 1u8;
    let mut start = 0usize;
    while start < strings.len() {
        let end = strings[start..].iter().position(|&c| c == 0).map(|p| start + p).unwrap_or(strings.len());
        if n == idx {
            return &strings[start..end];
        }
        n = n.wrapping_add(1);
        start = end + 1;
    }
    &[]
}

/// Walks the structure table and fills a `MachineIdentityRaw`.
///
/// `table` is exactly the structure-table bytes (already clamped to
/// `MAX_TABLE_BYTES` by the caller); `major`/`minor` come from the entry
/// point. Type 1/2/3 are used at most once each (first wins).
pub fn parse_structure_table(table: &[u8], major: u8, minor: u8) -> MachineIdentityRaw {
    let mut id = MachineIdentityRaw::ZERO;
    id.source = IdentitySourceRaw::Smbios as u8;
    id.smbios_major = major;
    id.smbios_minor = minor;
    let (mut got1, mut got2, mut got3) = (false, false, false);

    let mut pos = 0usize;
    while pos + 4 <= table.len() {
        let typ = table[pos];
        let flen = table[pos + 1] as usize;
        if flen < 4 || pos + flen > table.len() {
            break;
        }
        let formatted = &table[pos..pos + flen];
        // String-set: after the formatted area, terminated by a double NUL.
        let sstart = pos + flen;
        let mut send = sstart;
        while send + 1 < table.len() && !(table[send] == 0 && table[send + 1] == 0) {
            send += 1;
        }
        let strings = &table[sstart..send.min(table.len())];
        let next = send + 2;

        let s = |off: usize| -> IdentityTextRaw {
            match formatted.get(off) {
                Some(&i) => IdentityTextRaw::from_slice(string_at(strings, i)),
                None => IdentityTextRaw::ZERO,
            }
        };
        match typ {
            1 if !got1 => {
                got1 = true;
                id.manufacturer = s(4);
                id.product = s(5);
                id.system_serial = s(7);
                if flen >= 0x18 {
                    id.uuid.copy_from_slice(&formatted[8..24]);
                    id.present |= IDENTITY_PRESENT_UUID;
                }
            }
            2 if !got2 => {
                got2 = true;
                id.board_serial = s(7);
            }
            3 if !got3 => {
                got3 = true;
                id.chassis_serial = s(7);
            }
            127 => break,
            _ => {}
        }
        if got1 && got2 && got3 {
            break;
        }
        pos = next;
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    /// Builds one structure: formatted area of `flen` bytes with `fill`
    /// applied, followed by the string-set.
    pub(crate) fn structure(typ: u8, flen: usize, fill: &dyn Fn(&mut [u8]), strings: &[&str]) -> Vec<u8> {
        let mut f = std::vec![0u8; flen];
        f[0] = typ;
        f[1] = flen as u8;
        fill(&mut f);
        let mut v = f;
        if strings.is_empty() {
            v.extend_from_slice(&[0, 0]);
        } else {
            for s in strings {
                v.extend_from_slice(s.as_bytes());
                v.push(0);
            }
            v.push(0);
        }
        v
    }

    pub(crate) fn sample_table(uuid: [u8; 16]) -> Vec<u8> {
        let mut t = Vec::new();
        // Type 0 (BIOS) first, to prove unrelated structures are skipped.
        t.extend(structure(0, 0x18, &|_| {}, &["Vendor", "1.0"]));
        t.extend(structure(
            1,
            0x1B,
            &|f| {
                f[4] = 1; // manufacturer
                f[5] = 2; // product
                f[7] = 3; // serial
                f[8..24].copy_from_slice(&uuid);
            },
            &["Acme Corp", "Model X", "SN-0042"],
        ));
        t.extend(structure(2, 0x0F, &|f| {
            f[4] = 1;
            f[5] = 2;
            f[7] = 3;
        }, &["Acme Corp", "Board Y", "BSN-777"]));
        t.extend(structure(3, 0x16, &|f| {
            f[4] = 1;
            f[7] = 2;
        }, &["Acme Corp", "CH-9"]));
        t.extend(structure(127, 4, &|_| {}, &[]));
        t
    }

    #[test]
    fn parses_type_1_2_3() {
        let uuid: [u8; 16] = core::array::from_fn(|i| i as u8 + 1);
        let id = parse_structure_table(&sample_table(uuid), 3, 4);
        assert!(id.has_uuid());
        assert_eq!(id.uuid, uuid);
        assert_eq!(id.manufacturer.as_slice(), b"Acme Corp");
        assert_eq!(id.product.as_slice(), b"Model X");
        assert_eq!(id.system_serial.as_slice(), b"SN-0042");
        assert_eq!(id.board_serial.as_slice(), b"BSN-777");
        assert_eq!(id.chassis_serial.as_slice(), b"CH-9");
        assert_eq!((id.smbios_major, id.smbios_minor), (3, 4));
    }

    #[test]
    fn truncated_table_never_panics() {
        let full = sample_table([9; 16]);
        for n in 0..full.len() {
            let _ = parse_structure_table(&full[..n], 2, 8);
        }
        assert!(!parse_structure_table(&[], 2, 8).has_uuid());
    }

    #[test]
    fn old_type1_without_uuid_field_has_no_uuid() {
        let mut t = Vec::new();
        t.extend(structure(1, 0x08, &|f| f[7] = 1, &["ONLYSERIAL"]));
        t.extend(structure(127, 4, &|_| {}, &[]));
        let id = parse_structure_table(&t, 2, 3);
        assert!(!id.has_uuid());
        assert_eq!(id.system_serial.as_slice(), b"ONLYSERIAL");
    }

    fn with_checksum(mut b: Vec<u8>, cs_at: usize) -> Vec<u8> {
        b[cs_at] = 0;
        let sum = b.iter().fold(0u8, |a, x| a.wrapping_add(*x));
        b[cs_at] = 0u8.wrapping_sub(sum);
        b
    }

    #[test]
    fn entry_point_3_decodes_and_checks_checksum() {
        let mut ep = std::vec![0u8; 24];
        ep[0..5].copy_from_slice(b"_SM3_");
        ep[6] = 24;
        ep[7] = 3;
        ep[8] = 5;
        ep[12..16].copy_from_slice(&0x1234u32.to_le_bytes());
        ep[16..24].copy_from_slice(&0x7FAB_C000u64.to_le_bytes());
        let ep = with_checksum(ep, 5);
        let loc = parse_entry_point_3(&ep).unwrap();
        assert_eq!(loc, TableLocation { address: 0x7FAB_C000, length: 0x1234, major: 3, minor: 5 });
        let mut bad = ep.clone();
        bad[9] ^= 1;
        assert!(parse_entry_point_3(&bad).is_none());
        assert!(parse_entry_point_3(&ep[..10]).is_none());
    }

    #[test]
    fn entry_point_2_decodes() {
        let mut ep = std::vec![0u8; 31];
        ep[0..4].copy_from_slice(b"_SM_");
        ep[5] = 31;
        ep[6] = 2;
        ep[7] = 8;
        ep[0x16..0x18].copy_from_slice(&0x0400u16.to_le_bytes());
        ep[0x18..0x1C].copy_from_slice(&0x000F_0000u32.to_le_bytes());
        let ep = with_checksum(ep, 4);
        let loc = parse_entry_point_2(&ep).unwrap();
        assert_eq!(loc, TableLocation { address: 0xF_0000, length: 0x400, major: 2, minor: 8 });
        assert!(parse_entry_point_3(&ep).is_none());
    }
}
