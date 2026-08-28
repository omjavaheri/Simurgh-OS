//! ============================================================================
//! elf.rs
//!
//! A minimal, hand-written 64-bit ELF parser — reads exactly what this
//! bootloader needs (entry point + loadable PT_LOAD segments) from the
//! kernel-stub image embedded via `include_bytes!` in main.rs.
//!
//! Deliberately NOT a general-purpose ELF library: this project's
//! kernels are always statically linked, non-relocatable (per
//! linker.ld's `"relocation-model": "static"`), little-endian,
//! 64-bit ELF executables — so this parser only needs to understand
//! that one shape, mirroring the project's established pattern of
//! writing minimal, purpose-built parsers (e.g. hal-riscv64/memory.rs's
//! FDT walker, hal-x86_64/memory.rs's ACPI table walker) rather than
//! pulling in a general external crate for a narrow, well-understood
//! format.
//! ============================================================================

/// ELF magic number: 0x7F 'E' 'L' 'F'.
const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];

/// e_ident[EI_CLASS] = ELFCLASS64.
const ELFCLASS64: u8 = 2;
/// e_ident[EI_DATA] = ELFDATA2LSB (little-endian).
const ELFDATA2LSB: u8 = 1;

/// p_type = PT_LOAD: a loadable segment.
const PT_LOAD: u32 = 1;

#[derive(Debug)]
pub enum ElfError {
    TooShort,
    BadMagic,
    NotClass64,
    NotLittleEndian,
    NotExecutable,
    NotX86_64,
    NotAArch64,
    NotRiscv,
    BadProgramHeaderOffset,
}

/// The 64-byte ELF64 file header (System V ABI, ELF64 spec section
/// "ELF Header"). Field layout matches the spec exactly; read via
/// manual byte slicing below rather than a `#[repr(C)]` struct cast,
/// since the embedded byte slice's alignment is not guaranteed to
/// match a Rust struct's requirements (include_bytes! only guarantees
/// byte-array alignment, not u64 alignment).
struct Elf64Header {
    e_type: u16,
    e_machine: u16,
    e_entry: u64,
    e_phoff: u64,
    e_phentsize: u16,
    e_phnum: u16,
}

/// e_machine value for x86_64 (EM_X86_64), per the ELF spec's machine
/// type registry.
/// e_machine value for x86_64 (EM_X86_64)
const EM_X86_64: u16 = 62;
/// e_machine value for AArch64 (EM_AARCH64)
const EM_AARCH64: u16 = 183;
/// e_machine value for RISC-V (EM_RISCV)
const EM_RISCV: u16 = 243;
/// e_type value for an executable file (ET_EXEC) — this project's
/// kernels are non-relocatable static executables, not shared objects
/// (ET_DYN), per linker.ld's "relocation-model": "static".
const ET_EXEC: u16 = 2;

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
    /// `data`.
    fn parse(data: &[u8]) -> Result<Self, ElfError> {
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
        #[cfg(target_arch = "x86_64")]
        if e_machine != EM_X86_64 {
            return Err(ElfError::NotX86_64);
        }
        #[cfg(target_arch = "aarch64")]
        if e_machine != EM_AARCH64 {
            return Err(ElfError::NotAArch64);
        }
        #[cfg(target_arch = "riscv64")]
        if e_machine != EM_RISCV {
            return Err(ElfError::NotRiscv);
        }

        Ok(Self { e_type, e_machine, e_entry, e_phoff, e_phentsize, e_phnum })
    }
}

/// One PT_LOAD program header entry's fields relevant to loading —
/// per ELF64 spec's Program Header Table, "Elf64_Phdr" layout.
#[derive(Debug, Clone, Copy)]
pub struct LoadSegment {
    /// Offset of this segment's data within the ELF file itself.
    pub file_offset: u64,
    /// Number of bytes to copy from the file (may be less than
    /// `mem_size` — the remainder must be zero-filled, per ELF spec's
    /// ".bss inside a PT_LOAD segment" convention).
    pub file_size: u64,
    /// Physical address this segment must be placed at in memory —
    /// this project's kernels use p_paddr (not p_vaddr) as the actual
    /// load target, matching linker.ld's LMA/VMA split (hal-x86_64/
    /// linker.ld's AT() directives place physical load addresses in
    /// p_paddr; the CPU only sees p_vaddr's higher-half addresses
    /// once paging is active, which is not yet the case at this
    /// bootloader stage).
    pub phys_addr: u64,
    /// Total size in memory (>= file_size; the difference is
    /// zero-filled .bss).
    pub mem_size: u64,
}

/// Parses `data` as a 64-bit ELF executable and returns its entry
/// point plus every PT_LOAD segment. Non-PT_LOAD program headers
/// (e.g. PT_GNU_STACK, if ever present) are silently skipped — this
/// bootloader has no use for anything beyond what must be loaded into
/// memory before jumping to `entry`.
pub fn parse_and_collect_load_segments(data: &[u8]) -> Result<(u64, impl Iterator<Item = LoadSegment> + '_), ElfError> {
    let header = Elf64Header::parse(data)?;

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
        let p_offset = read_u64(data, base + 8);
        let p_paddr = read_u64(data, base + 24);
        let p_filesz = read_u64(data, base + 32);
        let p_memsz = read_u64(data, base + 40);

        Some(LoadSegment {
            file_offset: p_offset,
            file_size: p_filesz,
            phys_addr: p_paddr,
            mem_size: p_memsz,
        })
    });

    Ok((entry, segments))
}