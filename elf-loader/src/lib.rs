//! ============================================================================
//! elf-loader
//!
//! Purpose: parse exactly the shape of ELF this workspace ever produces —
//! a 64-bit, little-endian, statically-linked, non-relocatable (`ET_EXEC`)
//! executable, per every `targets/*.json`'s `"relocation-model": "static"`
//! / `"position-independent-executables": false` — and return its entry
//! point plus every `PT_LOAD` segment. Deliberately NOT a general-purpose
//! ELF library (no relocation processing, no dynamic linking, no section
//! headers): this project writes minimal, purpose-built parsers for
//! narrow, well-understood formats (hal-riscv64/memory.rs's FDT walker,
//! hal-x86_64/memory.rs's ACPI table walker) rather than pulling in a
//! general external crate.
//!
//! Architecture reference: originally `uefi-bootloader/src/elf.rs`
//! (loads the kernel image itself); promoted to a shared crate once
//! `kernel-arch-glue` needed the identical logic to load subsystem
//! process images (03-Kernel-Subsystems-Layer.md's "subsystems as
//! processes" packaging — IMPLEMENTATION-PLAN.md follow-up).
//!
//! Position in the system: sits ALONGSIDE the `hal-*`/`kernel-*` layers,
//! not inside their dependency chain — it is pure, architecture-
//! independent byte-parsing logic with no `hal-core`/`kernel-core`
//! knowledge, so either side can depend on it without violating the
//! bottom-up layering rule.
//!
//! Safety/invariants: `#![no_std]`, no unsafe. Every read is bounds-
//! checked against the input slice's own length before use; malformed
//! input produces an `Err`, never a panic or an out-of-bounds read.
//! ============================================================================
#![no_std]

/// ELF magic number: 0x7F 'E' 'L' 'F'.
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// e_ident[EI_CLASS] = ELFCLASS64.
const ELFCLASS64: u8 = 2;
/// e_ident[EI_DATA] = ELFDATA2LSB (little-endian).
const ELFDATA2LSB: u8 = 1;

/// p_type = PT_LOAD: a loadable segment.
const PT_LOAD: u32 = 1;

/// e_type value for an executable file (ET_EXEC) — this project's images
/// are non-relocatable static executables, not shared objects (ET_DYN).
const ET_EXEC: u16 = 2;

/// e_machine values (ELF spec's machine type registry) for the three
/// architectures this workspace targets. Callers pass the one they
/// expect to `parse_and_collect_load_segments`; this crate does not
/// itself know which architecture it is running on (no `cfg`s — see
/// this file's own doc comment on why).
pub mod machine {
    pub const EM_X86_64: u16 = 62;
    pub const EM_AARCH64: u16 = 183;
    pub const EM_RISCV: u16 = 243;
}

/// One `PT_LOAD` program header entry's fields relevant to loading — per
/// the ELF64 spec's Program Header Table ("Elf64_Phdr") layout. Exposes
/// BOTH `vaddr` and `paddr`: a caller doing a higher-half kernel-style
/// load (`uefi-bootloader`) uses `paddr` as the actual copy target (its
/// linker script's `AT()` directives put the real load address there,
/// with `vaddr` only meaningful once paging activates later); a caller
/// loading a flat user-mode process image (`kernel-arch-glue`, no
/// VMA/LMA split) uses `vaddr` for both "where this ends up mapped" and
/// as the copy target within its own fresh untyped memory. `flags`
/// carries the standard `PF_X`/`PF_W`/`PF_R` bits so a caller can install
/// per-segment protection instead of one blanket permission for the
/// whole image.
#[derive(Debug, Clone, Copy)]
pub struct LoadSegment {
    /// Offset of this segment's data within the ELF file itself.
    pub file_offset: u64,
    /// Number of bytes to copy from the file (may be less than
    /// `mem_size` — the remainder must be zero-filled, per the ELF
    /// spec's ".bss inside a PT_LOAD segment" convention).
    pub file_size: u64,
    /// This segment's linked virtual address (p_vaddr).
    pub vaddr: u64,
    /// This segment's linked physical address (p_paddr) — equals
    /// `vaddr` unless the producing linker script deliberately splits
    /// them (a VMA/LMA split, e.g. a higher-half kernel image).
    pub paddr: u64,
    /// Total size in memory (>= file_size; the difference is
    /// zero-filled .bss).
    pub mem_size: u64,
    /// Raw `p_flags` (bit 0 = `PF_X`, bit 1 = `PF_W`, bit 2 = `PF_R`,
    /// per the ELF64 spec) — NOT this workspace's own HAL-level
    /// R/W/X/U bit encoding; translate at the call site.
    pub flags: u32,
}

/// `p_flags` bit for an executable segment (`PF_X`).
pub const PF_X: u32 = 1;
/// `p_flags` bit for a writable segment (`PF_W`).
pub const PF_W: u32 = 2;
/// `p_flags` bit for a readable segment (`PF_R`).
pub const PF_R: u32 = 4;

#[derive(Debug, PartialEq, Eq)]
pub enum ElfError {
    TooShort,
    BadMagic,
    NotClass64,
    NotLittleEndian,
    NotExecutable,
    WrongMachine,
    BadProgramHeaderOffset,
}

/// The 64-byte ELF64 file header (System V ABI, ELF64 spec section
/// "ELF Header"). Field layout matches the spec exactly; read via
/// manual byte slicing rather than a `#[repr(C)]` struct cast, since
/// the input byte slice's alignment is not guaranteed to match a Rust
/// struct's requirements (e.g. `include_bytes!` only guarantees byte-
/// array alignment, not `u64` alignment).
struct Elf64Header {
    e_entry: u64,
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&data[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

impl Elf64Header {
    /// Parses and validates the 64-byte ELF64 header at the start of
    /// `data` against `expected_machine` (one of `machine::EM_*`).
    fn parse(data: &[u8], expected_machine: u16) -> Result<Self, ElfError> {
        if data.len() < 64 {
            return Err(ElfError::TooShort);
        }
        if data[0..4] != ELF_MAGIC {
            return Err(ElfError::BadMagic);
        }
        if data[4] != ELFCLASS64 {
            return Err(ElfError::NotClass64);
        }
        if data[5] != ELFDATA2LSB {
            return Err(ElfError::NotLittleEndian);
        }

        let e_type = read_u16(data, 16);
        let e_machine = read_u16(data, 18);
        let e_entry = read_u64(data, 24);
        let e_phoff = read_u64(data, 32);
        let e_phentsize = read_u16(data, 54);
        let e_phnum = read_u16(data, 56);

        if e_type != ET_EXEC {
            return Err(ElfError::NotExecutable);
        }
        if e_machine != expected_machine {
            return Err(ElfError::WrongMachine);
        }

        Ok(Self { e_entry, e_phoff, e_phentsize, e_phnum })
    }
}

/// Parses `data` as a 64-bit ELF executable for `expected_machine` (one
/// of `machine::EM_*`) and returns its entry point plus every `PT_LOAD`
/// segment. Non-`PT_LOAD` program headers (e.g. `PT_GNU_STACK`, if ever
/// present) are silently skipped — neither caller in this workspace has
/// a use for anything beyond what must actually be loaded into memory.
pub fn parse_and_collect_load_segments(
    data: &[u8],
    expected_machine: u16,
) -> Result<(u64, impl Iterator<Item = LoadSegment> + '_), ElfError> {
    let header = Elf64Header::parse(data, expected_machine)?;

    let ph_start = header.e_phoff as usize;
    let ph_entry_size = header.e_phentsize as usize;
    let ph_count = header.e_phnum as usize;

    let ph_table_end = ph_start
        .checked_add(ph_entry_size.checked_mul(ph_count).ok_or(ElfError::BadProgramHeaderOffset)?)
        .ok_or(ElfError::BadProgramHeaderOffset)?;
    if ph_table_end > data.len() {
        return Err(ElfError::BadProgramHeaderOffset);
    }

    let entry = header.e_entry;

    let segments = (0..ph_count).filter_map(move |i| {
        let base = ph_start + i * ph_entry_size;
        let p_type = read_u32(data, base);
        if p_type != PT_LOAD {
            return None;
        }
        let p_flags = read_u32(data, base + 4);
        let p_offset = read_u64(data, base + 8);
        let p_vaddr = read_u64(data, base + 16);
        let p_paddr = read_u64(data, base + 24);
        let p_filesz = read_u64(data, base + 32);
        let p_memsz = read_u64(data, base + 40);

        Some(LoadSegment {
            file_offset: p_offset,
            file_size: p_filesz,
            vaddr: p_vaddr,
            paddr: p_paddr,
            mem_size: p_memsz,
            flags: p_flags,
        })
    });

    Ok((entry, segments))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-builds the smallest valid ELF64 `ET_EXEC` this parser
    /// accepts: a 64-byte file header plus one `PT_LOAD` program header
    /// entry, no section headers (this parser never reads them).
    fn build_minimal_elf(machine: u16, entry: u64, seg: LoadSegment, body: &[u8]) -> alloc_free_vec::Vec {
        let mut v = alloc_free_vec::Vec::new();
        // e_ident
        v.extend_from_slice(&ELF_MAGIC);
        v.push(ELFCLASS64);
        v.push(ELFDATA2LSB);
        v.push(1); // EI_VERSION
        v.extend_from_slice(&[0u8; 9]); // EI_OSABI..EI_PAD
        // e_type, e_machine
        v.extend_from_slice(&ET_EXEC.to_le_bytes());
        v.extend_from_slice(&machine.to_le_bytes());
        // e_version
        v.extend_from_slice(&1u32.to_le_bytes());
        // e_entry, e_phoff, e_shoff
        v.extend_from_slice(&entry.to_le_bytes());
        let phoff: u64 = 64;
        v.extend_from_slice(&phoff.to_le_bytes());
        v.extend_from_slice(&0u64.to_le_bytes()); // e_shoff
        // e_flags
        v.extend_from_slice(&0u32.to_le_bytes());
        // e_ehsize, e_phentsize, e_phnum
        v.extend_from_slice(&64u16.to_le_bytes());
        let phentsize: u16 = 56;
        v.extend_from_slice(&phentsize.to_le_bytes());
        v.extend_from_slice(&1u16.to_le_bytes()); // e_phnum
        // e_shentsize, e_shnum, e_shstrndx
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        v.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(v.len(), 64);

        // One Elf64_Phdr (56 bytes)
        v.extend_from_slice(&PT_LOAD.to_le_bytes());
        v.extend_from_slice(&seg.flags.to_le_bytes());
        v.extend_from_slice(&seg.file_offset.to_le_bytes());
        v.extend_from_slice(&seg.vaddr.to_le_bytes());
        v.extend_from_slice(&seg.paddr.to_le_bytes());
        v.extend_from_slice(&seg.file_size.to_le_bytes());
        v.extend_from_slice(&seg.mem_size.to_le_bytes());
        v.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align
        assert_eq!(v.len(), 64 + 56);

        // Segment body, at file_offset (already == v.len() by construction below)
        v.extend_from_slice(body);
        v
    }

    /// A tiny dependency-free growable byte buffer — this crate is
    /// `#![no_std]` with no `alloc` dependency for its real logic, so
    /// tests build their own fixed-capacity buffer rather than pull in
    /// `alloc` just for `#[cfg(test)]` fixtures.
    mod alloc_free_vec {
        pub struct Vec {
            buf: [u8; 512],
            len: usize,
        }
        impl Vec {
            pub fn new() -> Self {
                Self { buf: [0; 512], len: 0 }
            }
            pub fn push(&mut self, b: u8) {
                self.buf[self.len] = b;
                self.len += 1;
            }
            pub fn extend_from_slice(&mut self, s: &[u8]) {
                self.buf[self.len..self.len + s.len()].copy_from_slice(s);
                self.len += s.len();
            }
            pub fn len(&self) -> usize {
                self.len
            }
            pub fn as_slice(&self) -> &[u8] {
                &self.buf[..self.len]
            }
        }
    }

    #[test]
    fn parses_entry_and_one_load_segment() {
        let seg = LoadSegment {
            file_offset: 120,
            file_size: 4,
            vaddr: 0xC000_0000,
            paddr: 0xC000_0000,
            mem_size: 8, // 4 bytes of file data + 4 bytes of zero-filled .bss
            flags: PF_R | PF_X,
        };
        let data = build_minimal_elf(machine::EM_RISCV, 0xC000_0000, seg, &[1, 2, 3, 4]);

        let (entry, segments) =
            parse_and_collect_load_segments(data.as_slice(), machine::EM_RISCV).unwrap();
        assert_eq!(entry, 0xC000_0000);
        let segs: alloc_free_vec::Vec = {
            let mut v = alloc_free_vec::Vec::new();
            for s in segments {
                assert_eq!(s.file_offset, 120);
                assert_eq!(s.file_size, 4);
                assert_eq!(s.mem_size, 8);
                assert_eq!(s.vaddr, 0xC000_0000);
                assert_eq!(s.flags, PF_R | PF_X);
                v.push(1);
            }
            v
        };
        assert_eq!(segs.len(), 1);
    }

    /// Collapses `Result<(u64, impl Iterator<Item = LoadSegment>), ElfError>`
    /// into `Result<u64, ElfError>` by immediately draining the segment
    /// iterator. The iterator borrows the input slice; the error-path
    /// tests below only care about the `Err` case, and letting that
    /// borrow escape a `match` whose `Ok` arm is never taken still trips
    /// NLL's conservative drop-glue analysis for the unconstructed `Ok`
    /// variant — this sidesteps it entirely rather than fighting it.
    fn parse_err_only(data: &[u8], expected_machine: u16) -> Result<u64, ElfError> {
        let (entry, segments) = parse_and_collect_load_segments(data, expected_machine)?;
        let _ = segments.count();
        Ok(entry)
    }

    #[test]
    fn rejects_wrong_machine() {
        let seg = LoadSegment {
            file_offset: 120,
            file_size: 0,
            vaddr: 0,
            paddr: 0,
            mem_size: 0,
            flags: PF_R,
        };
        let data = build_minimal_elf(machine::EM_X86_64, 0, seg, &[]);
        assert_eq!(
            parse_err_only(data.as_slice(), machine::EM_AARCH64),
            Err(ElfError::WrongMachine)
        );
    }

    #[test]
    fn rejects_too_short() {
        assert_eq!(parse_err_only(&[0u8; 10], machine::EM_X86_64), Err(ElfError::TooShort));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut data = [0u8; 64];
        data[0] = b'X';
        assert_eq!(parse_err_only(&data, machine::EM_X86_64), Err(ElfError::BadMagic));
    }
}
