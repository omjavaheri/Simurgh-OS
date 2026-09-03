//! ============================================================================
//! cpu.rs — x86_64
//!
//! Implements `hal_core::cpu::CpuAbstraction<X86_64_CONTEXT_BYTES>` for
//! x86_64, per 01-HAL-Layer.md section 3.1:
//!   - per-core bootstrap (GDT + IDT, uniform Interrupt/Exception
//!     Vector Table setup)
//!   - privilege level management (Ring 0 / Ring 3)
//!   - hardware context switch (register save/restore)
//!   - CPUID-based feature flag detection, mapped onto hal-core's
//!     architecture-independent `CpuFeatureFlags` bitfield
//!
//! Per targets/x86_64-hal.json's "+soft-float" setting, none of this
//! file's code (or any Rust code in this crate) uses SSE/AVX registers
//! — the GDT/IDT/context-switch machinery below deals exclusively with
//! general-purpose and control registers.
//! ============================================================================

use core::arch::x86_64::__cpuid_count;
use core::cell::Cell;
use core::mem::size_of;

use hal_core::cpu::{CpuAbstraction, CpuContext, CpuFeatureFlags, PrivilegeLevel};
use hal_core::error::HalError;

use crate::X86_64_CONTEXT_BYTES;

// ============================================================================
// CPUID access, made testable via a trait (mirrors hal-direct's
// TokenVerifier pattern: real hardware access behind a trait, so pure
// bit-parsing logic can be unit tested on the host without executing
// a real CPUID instruction against a specific machine's feature set).
// ============================================================================

#[derive(Debug, Clone, Copy, Default)]
pub struct CpuidResult {
    pub eax: u32,
    pub ebx: u32,
    pub ecx: u32,
    pub edx: u32,
}

pub trait CpuidSource {
    fn cpuid(&self, leaf: u32, subleaf: u32) -> CpuidResult;
}

/// Real CPUID access via `core::arch::x86_64::__cpuid_count`, which is
/// available in `core` (not `std`) and therefore usable in this
/// `no_std` crate without any extra dependency.
pub struct RealCpuid;

impl CpuidSource for RealCpuid {
    fn cpuid(&self, leaf: u32, subleaf: u32) -> CpuidResult {
        // SAFETY: CPUID is unconditionally available on every x86_64
        // CPU (it is part of the baseline long-mode architecture this
        // target requires) — no CPUID-support probing is needed the
        // way it would be on 32-bit x86.
        let result = unsafe { __cpuid_count(leaf, subleaf) };
        CpuidResult {
            eax: result.eax,
            ebx: result.ebx,
            ecx: result.ecx,
            edx: result.edx,
        }
    }
}

/// Detects CPU features via CPUID and maps them onto hal-core's
/// architecture-independent `CpuFeatureFlags` (hal-core/src/cpu.rs).
///
/// Pure function of a `CpuidSource` — this is what unit tests below
/// exercise with a mock implementation, independent of what the actual
/// build/test host CPU supports.
///
/// NOTE on `IOMMU_CAPABLE`: x86_64 IOMMU (VT-d) presence is NOT
/// reported via CPUID at all — it is discovered from the ACPI DMAR
/// table, which is `memory.rs`'s responsibility (section 3.2). This
/// function therefore never sets that bit; `Cpu::mark_iommu_capable`
/// below lets `memory.rs` fold that discovery into the same
/// `CpuFeatureFlags` value after the fact, once ACPI parsing has run.
pub fn detect_feature_flags(cpuid: &impl CpuidSource) -> CpuFeatureFlags {
    let mut flags = CpuFeatureFlags::empty();

    let leaf1 = cpuid.cpuid(1, 0);
    if leaf1.edx & (1 << 26) != 0 {
        flags |= CpuFeatureFlags::SIMD_128; // SSE2, baseline for long mode anyway
    }
    if leaf1.ecx & (1 << 28) != 0 {
        flags |= CpuFeatureFlags::SIMD_256; // AVX
    }
    if leaf1.ecx & (1 << 25) != 0 {
        flags |= CpuFeatureFlags::CRYPTO_AES;
    }
    if leaf1.ecx & (1 << 13) != 0 {
        flags |= CpuFeatureFlags::WIDE_ATOMICS; // CMPXCHG16B
    }
    if leaf1.ecx & (1 << 5) != 0 {
        flags |= CpuFeatureFlags::VIRTUALIZATION; // VMX
    }

    // Leaf 7, subleaf 0: extended feature flags.
    let leaf7 = cpuid.cpuid(7, 0);
    if leaf7.ebx & (1 << 5) != 0 {
        flags |= CpuFeatureFlags::SIMD_256; // AVX2 (idempotent if AVX already set it)
    }
    if leaf7.ebx & (1 << 16) != 0 {
        flags |= CpuFeatureFlags::SIMD_512; // AVX512F
    }
    if leaf7.ebx & (1 << 29) != 0 {
        flags |= CpuFeatureFlags::CRYPTO_SHA;
    }

    // Leaf 0xA: architectural performance monitoring. EAX bits 0-7 are
    // the reported version id; 0 means "not supported".
    let leaf_a = cpuid.cpuid(0x0A, 0);
    if (leaf_a.eax & 0xFF) > 0 {
        flags |= CpuFeatureFlags::PERF_COUNTERS;
    }

    flags
}

/// Reads this core's APIC id from CPUID leaf 1, EBX bits 24-31 (the
/// "initial APIC ID" field). Used as this core's `current_core_id()`.
///
/// NOTE: the classic xAPIC ID field is only 8 bits wide (max 255
/// cores). Systems with more cores rely on x2APIC (CPUID leaf 0x0B),
/// which `interrupt.rs`'s x2APIC detection already needs to handle
/// separately for `send_ipi`; extending core-id lookup to the x2APIC
/// path is deferred here as a follow-up once `interrupt.rs`'s x2APIC
/// support lands, since core-count-beyond-255 is not relevant to the
/// QEMU-based MVP boot targets in section 8.
fn read_initial_apic_id(cpuid: &impl CpuidSource) -> u8 {
    let leaf1 = cpuid.cpuid(1, 0);
    ((leaf1.ebx >> 24) & 0xFF) as u8
}

// ============================================================================
// GDT — flat long-mode segment layout
// ============================================================================

/// Segment selector values, matching the GDT entry order below. Used
/// both by `load_gdt` (to reload CS via a far return) and by
/// `set_privilege_level`/`context_switch` when constructing a target
/// context's initial CS/SS values for a new thread.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentSelector {
    Null = 0x00,
    KernelCode = 0x08,
    KernelData = 0x10,
    /// Ring 3 selectors carry a DPL of 3 encoded in the low 2 bits (the
    /// RPL field) — 0x18 | 3 and 0x20 | 3.
    UserCode = 0x1B,
    UserData = 0x23,
    /// The TSS descriptor (slots 5-6 below — a 64-bit TSS descriptor is
    /// 16 bytes, spanning two `u64` GDT slots, unlike every other entry
    /// here). Loaded via `ltr`, never used as a segment register value.
    Tss = 0x28,
}

/// One flat-model, long-mode GDT entry. Values below encode: present,
/// long-mode code (L bit) for code segments, DPL 0 for kernel entries
/// and DPL 3 for user entries, and full-limit flat descriptors (base=0,
/// limit=0xFFFFF with G bit set) — the standard layout every x86_64
/// long-mode OS uses, since segmentation itself is not used for memory
/// protection in long mode (paging does that); these entries exist
/// purely to satisfy the CPU's mode-switching requirements.
///
/// Slots 5-6 (the TSS descriptor) cannot be a compile-time constant —
/// its `base` field is `&TSS`'s runtime address — so unlike the other
/// five entries they are written by `bootstrap_current_core` (via
/// `encode_tss_descriptor`) before `load_gdt` runs. `static mut` for the
/// same single-core, write-once-before-any-concurrent-access reason as
/// `IDT` below.
static mut GDT: [u64; 7] = [
    0x0000_0000_0000_0000, // 0x00: null descriptor (required by the architecture)
    0x00AF_9A00_0000_FFFF, // 0x08: kernel code, DPL0, long mode
    0x00AF_9200_0000_FFFF, // 0x10: kernel data, DPL0
    0x00AF_FA00_0000_FFFF, // 0x18: user code, DPL3 (selector 0x1B with RPL=3)
    0x00AF_F200_0000_FFFF, // 0x20: user data, DPL3 (selector 0x23 with RPL=3)
    0,                     // 0x28: TSS descriptor, low 8 bytes — filled at boot
    0,                     // 0x30 (not a real selector): TSS descriptor, high 8 bytes (base[63:32])
];

// ============================================================================
// TSS — Task State Segment (needed the moment ANY Ring 3 -> Ring 0
// transition can happen, e.g. a U-mode `int 0x80` syscall below): on
// x86_64 a privilege-raising interrupt/exception ALWAYS switches to the
// stack in `TSS.rsp0` before pushing anything — unlike RISC-V, where
// `sp` is never hardware-switched on a trap. Without a loaded TSS with a
// valid `rsp0`, the CPU faults trying to find one (a double/triple
// fault) the instant U-mode code takes ANY trap. This project uses none
// of the TSS's other historical x86 features (hardware task-switching,
// IST stacks, an I/O permission bitmap) — `rsp0` is the only field that
// matters here.
// ============================================================================

/// 64 KiB — this is the stack the CPU switches to for the duration of
/// servicing a U-mode trap. The trampolines themselves (syscall/fault)
/// only ever push a small, fixed number of registers, but the SYSCALL
/// HANDLERS they call into can recurse arbitrarily deep in an
/// unoptimized (`dev`-profile) build: **bug found via QEMU** — the P2/
/// device-manager demo's `P2_REPORT_A` handler calls
/// `spawn_device_manager_x86`/`spawn_faulty_driver_x86`
/// (`root_task::plan_boot` + `kernel_arch_glue::spawn_process`, several
/// unoptimized stack frames deep each) directly from THIS stack — with
/// the original 16 KiB, this overflowed below `TSS_RSP0_STACK`,
/// corrupting whatever sat below it and producing an unrecoverable
/// `#GP`/`#DF` storm (QEMU `-d int`: ~4500 `v=0d` at the SAME `RIP`,
/// `RSP` stuck near the bottom of the 16 KiB region, escalating to one
/// `v=08` double fault) with zero further serial output — silent from
/// the boot log's perspective, diagnosed only via `-d int` tracing.
/// 64 KiB (matching hal-riscv64's own identical fix for an analogous
/// deep-recursion-into-`spawn_process` stack-overflow bug) resolved it.
const TSS_RSP0_STACK_SIZE: usize = 64 * 1024;
/// `.bss`, zeroed by the loader — never read before `bootstrap_current_core`
/// points `TSS.rsp0` at its top.
static mut TSS_RSP0_STACK: [u8; TSS_RSP0_STACK_SIZE] = [0; TSS_RSP0_STACK_SIZE];

/// x86_64 TSS layout (Intel SDM Vol. 3A, section 8.7). `#[repr(C, packed)]`
/// to match the hardware-defined byte offsets exactly — this struct is
/// never accessed through a Rust reference in a way that would trip
/// packed-field alignment lints (every field is read/written by value).
#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    /// Stack pointer loaded into RSP on a transition to Ring 0. The only
    /// field this project's TSS actually uses.
    rsp0: u64,
    rsp1: u64,
    rsp2: u64,
    reserved1: u64,
    /// Interrupt Stack Table — 7 optional dedicated stacks a specific
    /// IDT gate can request instead of `rsp0` (e.g. for a double-fault
    /// handler that must not trust the current stack). Unused (all
    /// zero) — no IDT gate here sets an IST index.
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    /// I/O permission bitmap base, as an offset from the TSS's own
    /// start. Set past `size_of::<Tss>()` (no bitmap follows), which
    /// the architecture defines as "no I/O bitmap present" — every
    /// I/O port access from Ring 3 traps, which is fine: this project
    /// has no port-I/O-capable U-mode code.
    iomap_base: u16,
}

impl Tss {
    const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp0: 0,
            rsp1: 0,
            rsp2: 0,
            reserved1: 0,
            ist: [0; 7],
            reserved2: 0,
            reserved3: 0,
            iomap_base: size_of::<Tss>() as u16,
        }
    }
}

/// The system-wide TSS. `static mut` for the same reason as `IDT`/`GDT`:
/// written once, on the bootstrap core, before any trap can be taken.
static mut TSS: Tss = Tss::new();

/// Encodes a 64-bit TSS descriptor (Intel SDM Vol. 3A, section 7.2.3)
/// pointing at `tss_addr`, split into the GDT's two-slot representation
/// (low 8 bytes, high 8 bytes = `base[63:32]`).
///
/// Access byte `0x89`: present, DPL 0, type `0b1001` (64-bit TSS,
/// available — not busy). Limit is `size_of::<Tss>() - 1` (103), well
/// under the 20-bit limit field's range, so the G (granularity) bit
/// stays clear (byte-granular limit).
fn encode_tss_descriptor(tss_addr: u64) -> (u64, u64) {
    let limit = (size_of::<Tss>() - 1) as u64;
    let base_low24 = tss_addr & 0xFF_FFFF;
    let base_mid8 = (tss_addr >> 24) & 0xFF;
    let base_high32 = (tss_addr >> 32) & 0xFFFF_FFFF;
    let access: u64 = 0x89;
    let low = limit
        | (base_low24 << 16)
        | (access << 40)
        | (((limit >> 16) & 0xF) << 48)
        | (base_mid8 << 56);
    (low, base_high32)
}

/// Loads the TSS selector via `ltr`.
///
/// # Safety
/// The GDT's TSS descriptor (slots 5-6) must already describe a valid,
/// `'static` `Tss` — i.e. this must run after `encode_tss_descriptor`'s
/// result has been written into `GDT` and after `load_gdt()`.
unsafe fn load_tss() {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        core::arch::asm!(
            "ltr {sel:x}",
            sel = in(reg) SegmentSelector::Tss as u16,
            options(nostack, preserves_flags),
        );
    }
}

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

/// Loads the GDT and reloads every segment register to point at the
/// new table, including a far-return-based reload of CS (the only
/// reliable way to change CS on x86_64 without a full privilege-level
/// transition).
///
/// # Safety
/// Must only be called once per core, during that core's
/// `bootstrap_current_core`, before any code depends on segment
/// registers already pointing at a different (e.g. UEFI-provided) GDT.
unsafe fn load_gdt() {
    let pointer = DescriptorTablePointer {
        limit: (size_of::<[u64; 7]>() - 1) as u16,
        // SAFETY: reading the address of `GDT` (not its contents) is
        // sound regardless of `static mut` aliasing rules, since we
        // only ever take `.as_ptr()` here — same reasoning as `IDT`'s
        // own `load_idt` below.
        base: unsafe { GDT.as_ptr() as u64 },
    };

    // SAFETY: `pointer` describes a `'static` table (GDT above) that
    // outlives the entire program; `lgdt` itself only loads the GDTR
    // and has no further preconditions beyond the pointer being valid,
    // which it is by construction here.
    unsafe {
        core::arch::asm!(
            "lgdt [{ptr}]",
            // Reload data segment registers directly (no far jump
            // needed for these).
            "mov ax, {kdata:x}",
            "mov ds, ax",
            "mov es, ax",
            "mov fs, ax",
            "mov gs, ax",
            "mov ss, ax",
            // Reloading CS requires a far return: push the new CS
            // selector and a return address, then `retfq` pops both
            // and jumps, which is the standard idiom for reloading CS
            // in 64-bit mode without triggering a full ring transition.
            "lea rax, [rip + 2f]",
            "push {kcode}",
            "push rax",
            "retfq",
            "2:",
            ptr = in(reg) &pointer,
            kdata = in(reg) SegmentSelector::KernelData as u16,
            kcode = in(reg) SegmentSelector::KernelCode as u64,
            out("rax") _,
        );
    }
}

// ============================================================================
// IDT — Interrupt/Exception Vector Table (section 3.1: "تنظیم
// Interrupt/Exception Vector Table به شکل یکسان برای هر سه معماری")
// ============================================================================

const IDT_ENTRY_COUNT: usize = 256;

#[repr(C)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0, // present bit clear = not a valid gate
            offset_mid: 0,
            offset_high: 0,
            reserved: 0,
        }
    }

    /// Builds a present, DPL0, 64-bit interrupt-gate entry pointing at
    /// `handler`. Interrupt gates (as opposed to trap gates) clear IF
    /// automatically on entry, which is the correct default for every
    /// vector here — this project's IRQ handlers
    /// (`hal_core::interrupt::IrqHandler`) run with interrupts disabled
    /// unless they explicitly re-enable them, consistent with
    /// `InterruptController::end_of_interrupt` (hal-core/src/
    /// interrupt.rs) being the caller-controlled point where the
    /// hardware is told the IRQ is fully serviced.
    fn gate(handler: u64) -> Self {
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector: SegmentSelector::KernelCode as u16,
            ist: 0, // TODO(layer 1 follow-up): use IST slot 1 for double-fault
            // (vector 8) — a TSS exists now (see this file's TSS
            // module docs), but wiring double-fault's own dedicated
            // stack through it is still a tracked follow-up, not done
            // speculatively here.
            type_attr: 0b1000_1110, // present, DPL0, 64-bit interrupt gate
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: ((handler >> 32) & 0xFFFF_FFFF) as u32,
            reserved: 0,
        }
    }

    /// Like `gate`, but DPL 3 — reachable via a software interrupt
    /// (`int`) executed from Ring 3 without a #GP. Every OTHER vector
    /// stays DPL 0 (`gate` above): a CPU exception or hardware IRQ is
    /// never something U-mode code should be able to trigger directly
    /// through the IDT's own privilege check, only through the actual
    /// mechanism that raises it. Used for exactly one vector — the
    /// syscall gate `bootstrap_current_core` installs after the generic
    /// population loop.
    fn gate_dpl3(handler: u64) -> Self {
        Self {
            offset_low: (handler & 0xFFFF) as u16,
            selector: SegmentSelector::KernelCode as u16,
            ist: 0,
            type_attr: 0b1110_1110, // present, DPL3, 64-bit interrupt gate
            offset_mid: ((handler >> 16) & 0xFFFF) as u16,
            offset_high: ((handler >> 32) & 0xFFFF_FFFF) as u32,
            reserved: 0,
        }
    }
}

/// The system-wide IDT. `static mut` (not `Cell`/atomic) because it is
/// written exactly once, by `Cpu::bootstrap_current_core` on the
/// bootstrap processor, before any other core exists or any interrupt
/// can fire — see that method's safety discussion.
static mut IDT: [IdtEntry; IDT_ENTRY_COUNT] = [IdtEntry::missing(); IDT_ENTRY_COUNT];

/// Loads the IDT via `lidt`.
///
/// # Safety
/// `IDT` must already be fully populated (every vector either a valid
/// gate or an intentional `missing()` placeholder) before this is
/// called — an unpopulated gate firing produces a general protection
/// fault rather than the intended handler, which is acceptable ONLY
/// for genuinely unused vectors.
unsafe fn load_idt() {
    let pointer = DescriptorTablePointer {
        limit: (size_of::<[IdtEntry; IDT_ENTRY_COUNT]>() - 1) as u16,
        // SAFETY: reading the address of `IDT` (not its contents) is
        // sound regardless of `static mut` aliasing rules, since we
        // only ever take `.as_ptr()` here, never a `&mut` alias
        // concurrent with another reference.
        base: unsafe { IDT.as_ptr() as u64 },
    };
    // SAFETY: `pointer` references the `'static` IDT table; `lidt`
    // only loads the IDTR register.
    unsafe {
        core::arch::asm!("lidt [{ptr}]", ptr = in(reg) &pointer);
    }
}

// ----------------------------------------------------------------------------
// Common exception/IRQ entry trampoline
//
// Per hal_core::interrupt::IrqHandler's doc comment: the function
// registered via `InterruptController::register_irq` is a small,
// fixed dispatcher — the actual low-level ISR stub that the CPU jumps
// to on interrupt is generated here in assembly (one per vector, via
// `global_asm!`'s repeat directive), pushes the vector number, and
// calls into `common_interrupt_entry` below, which looks up and
// invokes the registered handler from `interrupt.rs`'s dispatch table.
// ----------------------------------------------------------------------------

core::arch::global_asm!(
    r#"
    .altmacro
    // Intel SDM Vol. 3A Table 6-1: vectors 8 (#DF), 10 (#TS), 11 (#NP),
    // 12 (#SS), 13 (#GP), 14 (#PF), 17 (#AC) push a 64-bit error code
    // BEFORE the CPU's own RIP/CS/RFLAGS/RSP/SS frame; every other
    // vector pushes none. `common_interrupt_entry` needs a stack layout
    // that is uniform across all 256 stubs (a fixed offset for "the
    // vector number", "the error code"), so vectors WITHOUT a hardware
    // error code push a dummy 0 here — matches the standard technique
    // (e.g. the OSDev wiki's own IDT stub generator). **Real bug found
    // via QEMU** (this session's x86_64 preemption work): before this
    // fix every stub pushed only \vector, so for any error-code vector
    // that actually fired, `isr_common_trampoline`'s `add rsp, 8` popped
    // ONE slot too few, misaligning `iretq`'s own frame — the CPU would
    // load the error code as RIP and fault again immediately, with the
    // generic path's silent EOI-and-resume (see `dispatch_vector`)
    // turning that into an infinite, silent re-fault loop: no serial
    // output, no crash, just a permanently stuck core. Never triggered
    // by this project's own #UD/timer/syscall traps (all three have
    // DEDICATED gates bypassing this generic path entirely) until a
    // paging edge case in the P2/device-manager demo's 5th driver
    // respawn took a real #GP/#PF here for the first time.
    .macro isr_stub vector
    .global isr_stub_\vector
    isr_stub_\vector:
    .set has_err, 0
    .if \vector == 8
    .set has_err, 1
    .endif
    .if \vector == 10
    .set has_err, 1
    .endif
    .if \vector == 11
    .set has_err, 1
    .endif
    .if \vector == 12
    .set has_err, 1
    .endif
    .if \vector == 13
    .set has_err, 1
    .endif
    .if \vector == 14
    .set has_err, 1
    .endif
    .if \vector == 17
    .set has_err, 1
    .endif
    .if has_err == 0
        push 0
    .endif
        push \vector
        jmp isr_common_trampoline
    .endm

    .set i, 0
    .rept 256
        isr_stub %i
        .set i, i+1
    .endr

    isr_common_trampoline:
        # Save general-purpose registers per the SysV-adjacent layout
        # common_interrupt_entry expects (see the `extern "C"` fn
        # below): a pointer to this saved-register block is passed in
        # RDI.
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8
        push rbp
        push rdi
        push rsi
        push rdx
        push rcx
        push rbx
        push rax

        mov rdi, rsp
        call common_interrupt_entry

        pop rax
        pop rbx
        pop rcx
        pop rdx
        pop rsi
        pop rdi
        pop rbp
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15

        add rsp, 16  # discard the pushed vector number + error code (see isr_stub's doc comment)
        iretq
    "#
);

/// Called from the assembly trampoline above with a pointer to the
/// saved register block. Reads the vector number that
/// `isr_stub_<N>` pushed (at a fixed, known stack offset relative to
/// `saved_regs`) and dispatches to `interrupt.rs`'s registered
/// handler table.
///
/// Kept deliberately thin per hal_core::interrupt's IrqHandler doc
/// comment: "این function pointer خودش نباید کد اختیاری درایور را
/// مستقیم در Privileged mode اجرا کند" — this trampoline only reads
/// the vector and calls into `interrupt::dispatch_vector`, which is
/// where the actual registered `IrqHandler` (a plain `fn(IrqId)`, per
/// hal-core) is invoked.
#[no_mangle]
extern "C" fn common_interrupt_entry(saved_regs: *const u64) {
    // SAFETY: `saved_regs` points at the 15-register block the
    // trampoline above just pushed, immediately followed on the stack
    // by [vector][error_code][RIP][CS] — `isr_stub`'s uniform layout
    // (see its own doc comment) — both facts hold by construction of
    // the assembly above, which this function's only caller.
    let vector = unsafe { *saved_regs.add(15) } as u8;

    // Vectors 0-31 are CPU exceptions (Intel SDM Vol. 3A Table 6-1).
    // `#UD` (6) and the LAPIC timer (32, not in this range at all) have
    // DEDICATED gates that bypass this generic path entirely (see
    // `hal_x86_64_rust_entry`'s IDT setup), so any exception reaching
    // HERE is one this project has no handler for — e.g. a `#GP`/`#PF`
    // from an unexpected paging/permission edge case. `dispatch_vector`
    // would otherwise just EOI and fall through to `iretq`, silently
    // RESUMING at the same faulting instruction — for a genuine CPU
    // exception (not a spurious IRQ) that just re-faults forever with
    // no diagnostic output at all (the exact silent-hang symptom this
    // comment's fix addresses — see `isr_stub`'s doc comment for the
    // stack-imbalance bug found alongside it). Print what we can via
    // raw port I/O (no dependency on any higher-layer logger — this is
    // `hal-x86_64`, below `kernel-arch-glue`'s `klog!`) and halt: there
    // is no recovery path for an exception nothing registered for.
    if vector < 32 {
        // SAFETY: `error_code`/`rip` sit at the fixed offsets `isr_stub`'s
        // uniform per-vector layout guarantees.
        let error_code = unsafe { *saved_regs.add(16) };
        let rip = unsafe { *saved_regs.add(17) };
        let cr3: u64;
        let cr2: u64;
        // SAFETY: reading cr2/cr3 has no preconditions in a trap handler.
        unsafe {
            core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
            core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
        }
        diag_print("\r\nUNHANDLED CPU EXCEPTION vector=");
        diag_print_hex(vector as u64);
        diag_print(" error_code=");
        diag_print_hex(error_code);
        diag_print(" rip=");
        diag_print_hex(rip);
        diag_print(" cr3=");
        diag_print_hex(cr3);
        diag_print(" cr2(fault_va)=");
        diag_print_hex(cr2);
        diag_print("\r\n");
        loop {
            // SAFETY: `cli`/`hlt` are the standard side-effect-free halt
            // sequence — same terminal-state choice as
            // `halt_on_unexpected_fault` below.
            unsafe {
                core::arch::asm!("cli");
                core::arch::asm!("hlt");
            }
        }
    }

    crate::interrupt::dispatch_vector(vector);
}

/// Raw COM1 (`0x3F8`) byte write — port I/O, so it needs no page-table
/// mapping regardless of which `cr3` is currently loaded. Used only by
/// `common_interrupt_entry`'s unhandled-exception diagnostic above,
/// which by definition cannot assume `kernel-arch-glue`'s `klog!` (or
/// any other higher-layer logger) is safe to call from this context.
/// Not `#[cfg(target_os = "none")]`-gated: `common_interrupt_entry`
/// itself isn't (its `global_asm!` caller is never cfg-gated — see that
/// function's own doc comment), so this must compile on host too, even
/// though it is never actually invoked there.
fn diag_putc(c: u8) {
    // SAFETY: `out dx, al` to the fixed, standard COM1 I/O port has no
    // preconditions beyond the port existing (true under QEMU/real
    // hardware alike; a missing UART just drops the byte).
    unsafe {
        core::arch::asm!(
            "out dx, al",
            in("dx") 0x3F8u16,
            in("al") c,
            options(nomem, nostack, preserves_flags),
        );
    }
}

fn diag_print(s: &str) {
    for b in s.bytes() {
        diag_putc(b);
    }
}

fn diag_print_hex(v: u64) {
    diag_putc(b'0');
    diag_putc(b'x');
    for i in (0..16).rev() {
        let nibble = ((v >> (i * 4)) & 0xF) as u8;
        diag_putc(if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 });
    }
}

// ============================================================================
// Saved hardware context layout (matches X86_64_CONTEXT_BYTES = 160,
// per crate root lib.rs's doc comment on that constant)
// ============================================================================

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct X86_64Context {
    // Callee-saved general-purpose registers (SysV x86_64 ABI):
    rbx: u64,
    rbp: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    // Stack pointer of the suspended context.
    rsp: u64,
    // Instruction pointer to resume at.
    rip: u64,
    // Flags register.
    rflags: u64,
    // Address space root (per-thread page table base, per
    // 02-Microkernel-Layer.md section 3's UntypedMemory/PageTable
    // model — the microkernel writes this field when creating a new
    // thread's address space; hal-core's context_switch only needs to
    // reload it faithfully).
    cr3: u64,
    // Segment selectors active for this context, needed because
    // context_switch may cross a privilege-level boundary (kernel <->
    // user thread).
    cs: u64,
    ss: u64,
    // FS base, used for thread-local storage per the SysV ABI (read/
    // written via the FSBASE/GSBASE MSRs on this baseline; the FSGSBASE
    // instruction extension is not assumed present).
    fs_base: u64,
    // Padding to reach exactly 160 bytes (13 fields × 8 bytes = 104;
    // 7 more u64 slots reserved for future fields — e.g. GS base,
    // debug registers — without changing X86_64_CONTEXT_BYTES again).
    _reserved: [u64; 7],
}

const _: () = {
    assert!(size_of::<X86_64Context>() == X86_64_CONTEXT_BYTES);
};

// ============================================================================
// Cpu — CpuAbstraction<X86_64_CONTEXT_BYTES> implementation
// ============================================================================

pub struct Cpu {
    cpuid: RealCpuid,
    /// Feature flags detected purely from CPUID at construction time.
    /// `IOMMU_CAPABLE` (which CPUID cannot report — see
    /// `detect_feature_flags`'s doc comment) is folded in later by
    /// `mark_iommu_capable`, hence `Cell` rather than a plain field.
    feature_flags: Cell<CpuFeatureFlags>,
    /// Cached at construction from CPUID leaf 1's initial APIC ID
    /// (`read_initial_apic_id`). Immutable after construction: a given
    /// running core's APIC id does not change during its lifetime.
    core_id: u8,
}

impl Cpu {
    /// Constructs the CPU abstraction for the CURRENT core. Must be
    /// called once per core (the bootstrap processor calls this from
    /// `hal_x86_64_rust_entry`; secondary cores — not yet implemented
    /// in this MVP phase, per 01-HAL-Layer.md section 8's acceptance
    /// criteria which only requires single-core QEMU boot — will call
    /// it from their own trampoline entry point in a later phase).
    pub fn new() -> Self {
        let cpuid = RealCpuid;
        let feature_flags = Cell::new(detect_feature_flags(&cpuid));
        let core_id = read_initial_apic_id(&cpuid);
        Self { cpuid, feature_flags, core_id }
    }

    /// Called by `memory.rs` once ACPI DMAR table parsing has
    /// determined whether VT-d (IOMMU) is present — see
    /// `detect_feature_flags`'s doc comment on why this cannot be
    /// folded into CPUID-only detection.
    pub fn mark_iommu_capable(&self, present: bool) {
        let mut flags = self.feature_flags.get();
        flags.set(CpuFeatureFlags::IOMMU_CAPABLE, present);
        self.feature_flags.set(flags);
    }

    /// `core_count()`'s real implementation requires walking the ACPI
    /// MADT table to enumerate every listed Local APIC entry — that
    /// table is parsed by `memory.rs` alongside the rest of ACPI
    /// (section 3.2), not by this module. For the current MVP phase
    /// (single-core QEMU boot per section 8's acceptance criteria),
    /// this returns 1; multi-core enumeration is a tracked follow-up
    /// once `memory.rs`'s ACPI/MADT parsing exists and can be threaded
    /// through here (mirroring how `mark_iommu_capable` above already
    /// establishes the pattern for memory.rs -> cpu.rs data flow).
    fn detected_core_count(&self) -> usize {
        1
    }
}

impl Default for Cpu {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuAbstraction<{ crate::X86_64_CONTEXT_BYTES }> for Cpu {
    fn core_count(&self) -> usize {
        self.detected_core_count()
    }

    fn current_core_id(&self) -> usize {
        self.core_id as usize
    }

    fn feature_flags(&self) -> CpuFeatureFlags {
        self.feature_flags.get()
    }

    unsafe fn context_switch(
        &self,
        from: &mut CpuContext<{ crate::X86_64_CONTEXT_BYTES }>,
        to: &CpuContext<{ crate::X86_64_CONTEXT_BYTES }>,
    ) {
        // SAFETY: `CpuContext<160>`'s byte buffer has the exact same
        // size and required alignment as `X86_64Context` (enforced by
        // the `const _` size assertion above); reinterpreting the
        // buffer through this typed view is sound as long as the
        // buffer was either zero-initialized (valid for all-zero
        // X86_64Context) or previously written by this exact function,
        // both of which are guaranteed by this trait method's own
        // safety contract (hal-core/src/cpu.rs::CpuAbstraction::
        // context_switch).
        let from_ctx = unsafe { &mut *(from.as_bytes_mut().as_mut_ptr() as *mut X86_64Context) };
        let to_ctx = unsafe { &*(to.as_bytes().as_ptr() as *const X86_64Context) };

        // SAFETY: this is the hardware register save/restore this
        // trait method exists to perform. Preconditions (interrupts
        // disabled, non-aliasing contexts, valid `to_ctx`) are the
        // caller's responsibility per the trait's own safety
        // documentation; this implementation trusts them exactly as
        // that contract specifies.
        unsafe {
            core::arch::asm!(
                // Save the CURRENTLY running context's callee-saved
                // registers and control state into `from_ctx`.
                "mov [{from_ptr} + 0x00], rbx",
                "mov [{from_ptr} + 0x08], rbp",
                "mov [{from_ptr} + 0x10], r12",
                "mov [{from_ptr} + 0x18], r13",
                "mov [{from_ptr} + 0x20], r14",
                "mov [{from_ptr} + 0x28], r15",
                "mov [{from_ptr} + 0x30], rsp",
                // Capture a return address as this context's resume
                // point: label `2:` below, reached again the NEXT time
                // some future context_switch call restores `from_ctx`.
                //
                // NOTE: uses a named local label (`2:`) via the `.L`-
                // style numeric-label syntax combined with an explicit
                // `options(...)`-free plain asm! block. Earlier this
                // used `1f`/`1:`, which triggered an "Undefined
                // temporary symbol .Ltmp1" error from LLVM's
                // integrated assembler when the same numeric label
                // appeared inside a `lea ... [rip + 1f]` reference
                // combined with a later unconditional `jmp` out of the
                // block — switching to `2:` (a different, unused
                // numeric label in this function) avoids whatever
                // internal temporary-symbol collision LLVM's asm
                // parser was hitting on `1`.
                "lea rax, [rip + 2f]",
                "mov [{from_ptr} + 0x38], rax",
                "pushfq",
                "pop rax",
                "mov [{from_ptr} + 0x40], rax",
                "mov rax, cr3",
                "mov [{from_ptr} + 0x48], rax",

                // Restore `to_ctx`'s state and jump to its saved RIP.
                "mov rax, [{to_ptr} + 0x48]",
                "mov cr3, rax",
                "mov rax, [{to_ptr} + 0x40]",
                "push rax",
                "popfq",
                "mov rsp, [{to_ptr} + 0x30]",
                "mov rbx, [{to_ptr} + 0x00]",
                "mov rbp, [{to_ptr} + 0x08]",
                "mov r12, [{to_ptr} + 0x10]",
                "mov r13, [{to_ptr} + 0x18]",
                "mov r14, [{to_ptr} + 0x20]",
                "mov r15, [{to_ptr} + 0x28]",
                "mov rax, [{to_ptr} + 0x38]",
                "jmp rax",

                "2:",
                from_ptr = in(reg) from_ctx as *mut X86_64Context,
                to_ptr = in(reg) to_ctx as *const X86_64Context,
                out("rax") _,
            );
        }
    }

    fn init_context(
        &self,
        context: &mut CpuContext<{ crate::X86_64_CONTEXT_BYTES }>,
        entry: usize,
        stack_top: usize,
    ) {
        // SAFETY: a `[u8; X86_64_CONTEXT_BYTES]` buffer is layout-
        // compatible with `X86_64Context` (`#[repr(C)]`, size asserted
        // by the `const _` above). Zeroing then setting the fields the
        // `context_switch` restore path consumes for a fresh thread:
        // `rip` (`jmp`ed to), `rsp`, `rflags`, `cr3`. `cs`/`ss` are not
        // reloaded by the restore path (same privilege), so 0 is fine.
        let ctx = unsafe {
            &mut *(context.as_bytes_mut().as_mut_ptr() as *mut X86_64Context)
        };
        *ctx = X86_64Context::default();
        ctx.rsp = stack_top as u64;
        ctx.rip = entry as u64;
        // Bit 1 is the reserved-always-1 flag; IF (bit 9) left clear so
        // the freshly started thread does not take interrupts until it
        // (or the kernel) explicitly enables them.
        ctx.rflags = 0x2;

        #[cfg(target_os = "none")]
        {
            // SAFETY: reading CR3 is a privileged but side-effect-free
            // MOV; the new thread runs in this same address space.
            let cr3: u64;
            unsafe { core::arch::asm!("mov {0}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags)) };
            ctx.cr3 = cr3;
        }
        #[cfg(not(target_os = "none"))]
        {
            ctx.cr3 = 0;
        }
    }

    #[cfg(target_os = "none")]
    fn map_ram_identity(&self, root_frame: usize, bytes_gib: usize, user_accessible: bool) {
        x86_64_paging::map_ram_identity(root_frame, bytes_gib, user_accessible)
    }

    #[cfg(target_os = "none")]
    fn activate_address_space(&self, root_frame: usize) {
        if root_frame == 0 {
            // Unlike riscv64's Bare-mode sentinel, x86_64 cannot run
            // without paging active at all (long mode REQUIRES
            // `CR0.PG = 1`) — there is no "disable" state to return to.
            // `0` is simply a no-op here.
            return;
        }
        // SAFETY: the caller guarantees `root_frame` is a valid, fully
        // built PML4 (via `map_ram_identity` / `map_range`) that maps at
        // least all memory this core is currently executing from and
        // about to touch.
        unsafe {
            core::arch::asm!(
                "mov cr3, {root}",
                root = in(reg) root_frame as u64,
                options(nostack, preserves_flags),
            );
        }
    }

    #[cfg(target_os = "none")]
    fn flush_tlb(&self) {
        // SAFETY: reloading CR3 with its own current value is
        // architecturally guaranteed to flush every non-global TLB
        // entry — the simplest whole-TLB shootdown, matching
        // hal-riscv64's `sfence.vma` (no rs1/rs2) in scope; a single-
        // address `invlpg` is a later optimisation, mirroring that same
        // tracked follow-up there.
        unsafe {
            core::arch::asm!(
                "mov {tmp}, cr3",
                "mov cr3, {tmp}",
                tmp = out(reg) _,
                options(nostack, preserves_flags),
            );
        }
    }

    #[cfg(target_os = "none")]
    fn map_range(
        &self,
        root_frame: usize,
        vaddr: usize,
        paddr: usize,
        len: usize,
        perm_bits: usize,
        pool_base: usize,
        pool_len: usize,
    ) -> u32 {
        x86_64_paging::map_range(root_frame, vaddr, paddr, len, perm_bits, pool_base, pool_len)
    }

    #[cfg(target_os = "none")]
    fn enter_user(&self, entry: usize, stack_top: usize) -> ! {
        // SAFETY: a one-way Ring 0 -> Ring 3 drop via a fabricated
        // IRETQ frame: push SS (user data | RPL 3), RSP (`stack_top`),
        // RFLAGS (IF=1, so the dropped thread can eventually take
        // interrupts once one is routed to it — harmless today, nothing
        // is), CS (user code | RPL 3), RIP (`entry`), then `iretq`
        // pops all five and drops privilege. Never returns.
        unsafe {
            core::arch::asm!(
                "push {ss}",
                "push {sp}",
                "push {flags}",
                "push {cs}",
                "push {entry}",
                "iretq",
                ss = in(reg) SegmentSelector::UserData as u64,
                sp = in(reg) stack_top as u64,
                flags = in(reg) 0x202u64,
                cs = in(reg) SegmentSelector::UserCode as u64,
                entry = in(reg) entry as u64,
                options(noreturn),
            );
        }
    }

    fn init_user_context(
        &self,
        context: &mut hal_core::UserContext,
        entry: usize,
        stack_top: usize,
        root_frame: usize,
    ) {
        // SAFETY: `hal_core::UserContext` is `#[repr(C, align(8))]` over
        // exactly `[u8; HAL_USER_CONTEXT_BYTES]`, and `X8664UserContext`
        // is `#[repr(C)]` of a size asserted `<=` that (the `const _`
        // beside its definition) — so the buffer's leading bytes ARE a
        // valid `X8664UserContext`.
        let ctx = unsafe { &mut *(context.as_bytes_mut().as_mut_ptr() as *mut X8664UserContext) };
        *ctx = X8664UserContext::default();
        ctx.rip = entry as u64;
        ctx.rsp = stack_top as u64;
        ctx.cs = SegmentSelector::UserCode as u64;
        ctx.ss = SegmentSelector::UserData as u64;
        ctx.rflags = 0x202; // IF=1, reserved bit 1 = 1

        // `root_frame == 0` means "keep whatever is active" — read CR3
        // back so the first `resume_user` does not clobber the live
        // translation (mirrors hal-riscv64's `satp` handling here
        // exactly).
        #[cfg(target_os = "none")]
        {
            let cr3: u64;
            // SAFETY: reading CR3 has no preconditions in S-mode... err,
            // Ring 0.
            unsafe {
                core::arch::asm!("mov {0}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
            }
            ctx.cr3 = if root_frame != 0 { root_frame as u64 } else { cr3 };
        }
        #[cfg(not(target_os = "none"))]
        {
            ctx.cr3 = root_frame as u64;
        }
    }

    #[cfg(target_os = "none")]
    unsafe fn resume_user(&self, context: &hal_core::UserContext) -> ! {
        // SAFETY: the buffer is a valid `X8664UserContext` (see
        // `init_user_context`); the resumable-context + interrupts-
        // masked obligations are this method's documented caller
        // contract.
        let blob = context.as_bytes().as_ptr() as *const X8664UserContext;
        unsafe { restore_user_and_iretq(blob) }
    }

    #[cfg(not(target_os = "none"))]
    unsafe fn resume_user(&self, context: &hal_core::UserContext) -> ! {
        let _ = context;
        unreachable!("resume_user is bare-metal only (host test build)");
    }

    fn set_privilege_level(&self, level: PrivilegeLevel) -> Result<(), HalError> {
        match level {
            // x86_64 has no direct equivalent of ARM64 EL2 / RISC-V
            // M-mode as a general "monitor" level reachable from
            // ordinary kernel code — VMX root/non-root operation is a
            // fundamentally different mechanism (VMLAUNCH/VMRESUME,
            // not a CPL change) that belongs to the layer 5 Linux
            // Compat Runtime's VMM (05-Legacy-Compat-Applications-
            // Layer.md section 3.1), not to this general-purpose
            // privilege-level primitive.
            PrivilegeLevel::Monitor => Err(HalError::UnsupportedPrivilegeLevel),
            // Kernel/User here describe which SEGMENT SELECTORS
            // (SegmentSelector::Kernel* vs User*) a NEWLY CREATED
            // thread's context should be initialized with — actually
            // dropping the CURRENTLY executing core's CPL happens only
            // as a side effect of `context_switch`'s IRETQ-equivalent
            // restore path (jmp to `to_ctx`'s rip with `to_ctx`'s
            // cs/ss already reflecting the target level), never as a
            // standalone operation on x86_64 (there is no instruction
            // to lower CPL without also changing RIP/RSP/SS). This
            // method therefore exists as a validation/no-op point for
            // architecture-independent callers (hal-core's trait
            // contract) rather than performing an immediate transition
            // itself.
            PrivilegeLevel::Kernel | PrivilegeLevel::User => Ok(()),
        }
    }

    fn bootstrap_current_core(&self) -> Result<(), HalError> {
        // `IA32_EFER.NXE` (bit 11, MSR 0xC0000080): UEFI hands off with
        // long mode already active (`LME`/`LMA` set) but has no reason to
        // set `NXE` on this kernel's behalf — it is a pure OS policy
        // choice. Without it, bit 63 of every paging-structure entry is
        // ARCHITECTURALLY RESERVED (Intel SDM: "If IA32_EFER.NXE = 0, the
        // XD bit is reserved in all paging-structure entries"), yet
        // `x86_64_paging::map_range`'s own `NO_EXECUTE` constant (`1 <<
        // 63`) is unconditionally OR'd into every non-executable leaf's
        // flags — every `map_range` call requesting `perm_bits` without
        // `EXECUTE` (the common case: almost all data mappings) has been
        // setting a reserved bit since this mechanism was first built.
        // **Real, QEMU-confirmed bug** (found via WHPX hardware-
        // accelerated boot testing, not TCG): TCG's software CPU model
        // silently tolerates the reserved bit and just treats it as NX
        // regardless of `EFER.NXE` — a non-architectural leniency that
        // masked this for every prior TCG-only boot this project has
        // ever run — but WHPX (backed by real Intel VT-x, which enforces
        // this reservation during CR3-load / paging-structure validation)
        // rejected it outright: `activate_address_space`'s `mov cr3`
        // caused an immediate `WHvRunVpExitReasonInvalidVpRegisterValue`
        // the instant a table built by `map_range` with any non-
        // executable leaf became CR3's target. Fixed at the true root:
        // enable `NXE` here, once, before ANY page table this crate
        // builds can ever be activated — not by removing the `NO_EXECUTE`
        // bit from `map_range` (which would make every "non-executable"
        // mapping this kernel creates silently executable instead, a
        // real W^X regression, not merely a cosmetic one).
        //
        // SAFETY: `RDMSR`/`WRMSR` on `IA32_EFER` have no preconditions
        // beyond Ring 0 execution (always true in this crate) and
        // require no prior paging/GDT/IDT state — safe to do first, here,
        // before anything else in this function.
        unsafe {
            let low: u32;
            let high: u32;
            core::arch::asm!("rdmsr", in("ecx") 0xC000_0080u32, out("eax") low, out("edx") high);
            let efer = ((high as u64) << 32) | low as u64;
            let efer = efer | (1 << 11); // NXE
            core::arch::asm!(
                "wrmsr",
                in("ecx") 0xC000_0080u32,
                in("eax") efer as u32,
                in("edx") (efer >> 32) as u32,
            );
        }

        // SAFETY: single-core boot, before any trap can fire. `TSS.rsp0`
        // must be valid before ANY Ring 3 -> Ring 0 transition can
        // happen (see the TSS's own module doc comment) — set up before
        // `load_gdt`/`load_tss` below reference it, and before any
        // interrupt (which `bootstrap_current_core`'s own contract
        // already guarantees, per the comment on `load_gdt` just below).
        unsafe {
            let rsp0 = core::ptr::addr_of_mut!(TSS_RSP0_STACK)
                .cast::<u8>()
                .add(TSS_RSP0_STACK_SIZE) as u64;
            TSS.rsp0 = rsp0;
            let (low, high) = encode_tss_descriptor(core::ptr::addr_of!(TSS) as u64);
            GDT[5] = low;
            GDT[6] = high;
        }

        // SAFETY: called exactly once per core, before any interrupt
        // can fire on this core (interrupts remain hardware-masked
        // from UEFI handoff through this point — boot.S never issued
        // `sti`), and before any other code depends on segment
        // registers pointing at a specific GDT — see `load_gdt`'s own
        // safety contract, satisfied here by this being the first call
        // to it for this core.
        unsafe {
            load_gdt();
        }

        // Populate the IDT: vectors 0-31 are CPU exceptions, 32-255
        // are available for IRQ use by `interrupt.rs`'s
        // InterruptController implementation. Every vector gets a gate
        // pointing at its `isr_stub_<N>` (generated by the
        // `global_asm!` block above) — unused IRQ vectors simply route
        // to `common_interrupt_entry`, which finds no registered
        // handler in `interrupt.rs`'s dispatch table and returns
        // immediately (a spurious-interrupt-safe default).
        //
        // SAFETY: `IDT` is written here, on the bootstrap core, before
        // `load_idt()` is called and before interrupts are enabled —
        // no concurrent access is possible at this point in boot.
        unsafe {
            for vector in 0..IDT_ENTRY_COUNT {
                // Each `isr_stub_<N>` symbol's address is resolved at
                // link time; we cannot index them as a Rust array
                // (they are individually named assembly labels), so we
                // compute the address via the vector's known
                // 8-byte-stub-in-a-flat-table layout is NOT used here
                // — instead each stub is reached through a generated
                // lookup table emitted by the same global_asm! block
                // for exactly this purpose.
                let handler_addr = isr_stub_address(vector as u8);
                IDT[vector] = IdtEntry::gate(handler_addr);
            }
        }

        // The syscall gate: DPL 3 so U-mode's `int 0x80` doesn't take a
        // #GP, pointing at the DEDICATED `isr_syscall_trampoline` (NOT
        // the generic `isr_stub_<N>` the loop above just installed for
        // this same vector) — the generic ISR path has no TrapOutcome-
        // style switch semantics a syscall handler needs. Installed
        // AFTER the loop specifically so it overrides that vector's
        // generic gate; `load_idt`/`load_tss` run once, after both.
        //
        // SAFETY: `IDT`/`TSS`/`GDT` are written here, on the bootstrap
        // core, before `load_idt`/`load_tss` are called and before
        // interrupts are enabled — no concurrent access is possible.
        unsafe {
            unsafe extern "C" {
                static isr_syscall_trampoline: u8;
            }
            let addr = &isr_syscall_trampoline as *const u8 as u64;
            IDT[SYSCALL_VECTOR as usize] = IdtEntry::gate_dpl3(addr);
        }

        // The fault gate: `#UD` (vector 6), same override pattern as the
        // syscall gate just above — points at the DEDICATED
        // `isr_fault_trampoline` instead of the generic `isr_stub_6` the
        // loop installed, since only the dedicated one has TrapOutcome-
        // style switch semantics. Stays DPL 0 (the default `gate()`
        // already installed): `#UD` is CPU-generated, not raised via a
        // software `int`, so the IDT's own DPL check (which only applies
        // to `int nn`) never blocks it regardless.
        //
        // SAFETY: `IDT` is written here, on the bootstrap core, before
        // `load_idt` is called and before interrupts are enabled — no
        // concurrent access is possible.
        unsafe {
            unsafe extern "C" {
                static isr_fault_trampoline: u8;
            }
            let addr = &isr_fault_trampoline as *const u8 as u64;
            IDT[FAULT_VECTOR_UD as usize] = IdtEntry::gate(addr);
        }

        // The timer gate: `interrupt::TIMER_VECTOR` (32), same override
        // pattern as the syscall/fault gates above — points at the
        // DEDICATED `isr_timer_trampoline` instead of the generic
        // `isr_stub_32` the loop installed, since only the dedicated one
        // has TrapOutcome-style switch semantics (02-Microkernel-
        // Layer.md §4's preemptive scheduler). Stays DPL 0 (the default
        // `gate()` already installed): the LAPIC timer is hardware-
        // generated, never raised via a software `int`, so the IDT's DPL
        // check (which only applies to `int nn`) never blocks it either
        // way — same reasoning as the fault gate just above.
        //
        // SAFETY: `IDT` is written here, on the bootstrap core, before
        // `load_idt` is called and before interrupts are enabled — no
        // concurrent access is possible.
        unsafe {
            unsafe extern "C" {
                static isr_timer_trampoline: u8;
            }
            let addr = &isr_timer_trampoline as *const u8 as u64;
            IDT[crate::interrupt::TIMER_VECTOR as usize] = IdtEntry::gate(addr);
        }

        // SAFETY: `IDT`/`TSS`/`GDT` are fully populated at this point
        // (generic loop + both dedicated overrides above); this is the
        // bootstrap core, before interrupts are enabled — no concurrent
        // access is possible.
        unsafe {
            load_idt();
            load_tss();
        }

        Ok(())
    }
}

// A flat table of `isr_stub_<N>` addresses, generated alongside the
// stubs themselves so Rust code can look one up by vector number
// without 256 hand-written `extern "C"` declarations.
//
// NOTE: `.quad isr_stub_%i` cannot be written directly inside a
// `.rept` loop — under `.altmacro`, `%expr`-to-decimal substitution
// only happens for arguments passed INTO a macro invocation, not for
// text appearing directly in a directive. `isr_addr` below exists
// solely so `%i` is substituted correctly via that macro-call path,
// exactly like `isr_stub %i` already does for the stubs themselves.
core::arch::global_asm!(
    r#"
    .altmacro
    .macro isr_addr vector
        .quad isr_stub_\vector
    .endm

    .section .rodata
    .global isr_stub_table
    isr_stub_table:
    .set i, 0
    .rept 256
        isr_addr %i
        .set i, i+1
    .endr
    "#
);

unsafe extern "C" {
    static isr_stub_table: [u64; IDT_ENTRY_COUNT];
}

fn isr_stub_address(vector: u8) -> u64 {
    // SAFETY: `isr_stub_table` is a `'static`, fully-initialized
    // (link-time-constant) array emitted by the `global_asm!` block
    // above — indexing it with any `u8` value is in-bounds by
    // construction (256 entries for all 256 possible vector values).
    unsafe { isr_stub_table[vector as usize] }
}

// ============================================================================
// U-mode syscall boundary (`int 0x80`, DPL 3) — analogous to
// hal-riscv64's `ecall`/`SyscallHandler`/`TrapOutcome`/`common_trap_entry`,
// but on a DEDICATED trampoline rather than reusing the generic 256-
// vector ISR path above: that path has no TrapOutcome-style switch
// semantics (it always resumes exactly where an interrupt landed,
// correct for a hardware IRQ but not for a syscall that may need to
// switch which thread is running), and only saves 15 GPRs in a layout
// that doesn't cover a full resumable U-mode context.
// ============================================================================

/// This project's own raw software-interrupt convention for a syscall
/// (there is no ISA-defined one on x86_64 the way `ecall` is on
/// RISC-V) — deliberately the same vector Linux's classic 32-bit ABI
/// used, for a convention any x86 developer recognizes.
const SYSCALL_VECTOR: u8 = 0x80;

/// The on-stack layout `isr_syscall_trampoline` pushes: 15 GPRs (every
/// one except `rsp`, which is part of the hardware-pushed IRETQ frame
/// below and never needs an explicit save/restore of its own), then
/// whatever the CPU auto-pushed crossing from Ring 3 to Ring 0 on this
/// `int 0x80` (`RIP`, `CS`, `RFLAGS`, `RSP`, `SS`, in that order —
/// present because DPL 3 gates always carry a privilege change here).
/// Field ORDER matches the trampoline's own push sequence exactly (`rax`
/// pushed LAST = lowest address = offset 0).
#[repr(C)]
struct SyscallFrame {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

/// A suspended U-mode thread's full context — `SyscallFrame`'s exact
/// same leading 160 bytes (so a save is one `copy_nonoverlapping`, not a
/// field-by-field copy) plus `cr3` (the IRETQ frame carries no notion of
/// address space — CR3 must be read/written separately, exactly like
/// riscv64's `RiscvUserContext` carries `satp` alongside its own trap-
/// frame-shaped prefix).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct X8664UserContext {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
    cr3: u64,
}

const _: () = {
    assert!(size_of::<X8664UserContext>() <= hal_core::HAL_USER_CONTEXT_BYTES);
};

/// What the syscall handler decided should happen next — identical
/// shape to hal-riscv64's own `TrapOutcome` (see that type's own doc
/// comment for the rationale behind each variant); duplicated here
/// rather than shared because every other piece of the trap-handling
/// surface (the frame layout, the restore mechanism) is architecture-
/// local too, and hal_core defines no such type.
pub enum TrapOutcome {
    /// Return to the trapping thread with `.0` in `rax`, `rip` advanced
    /// past the 2-byte `int 0x80`. The ordinary syscall return.
    Resume(usize),
    /// Same as `Resume`, but also places `.1` in `rsi` — for a syscall
    /// whose result genuinely does not fit in one register (e.g. `Recv`
    /// returning both the sender's `ThreadId` and the message label —
    /// see `kernel/src/main.rs`'s `IPC_RECV` demo opcode, and hal-
    /// riscv64's own identical `Resume2`). `rsi` (this project's own
    /// `a1` register — see `SyscallHandler`'s doc comment) is reused
    /// for the second value, same "same register both directions"
    /// convention riscv64's own `a1`/`x11` uses. A separate variant
    /// rather than widening `Resume` itself: every OTHER existing
    /// caller only ever has one value to return, and this keeps them
    /// untouched.
    Resume2(usize, usize),
    /// Serialise the trapping thread's full context into the
    /// `HAL_USER_CONTEXT_BYTES` blob at `save`, then restore `into` and
    /// `iretq` into it. Both pointers are kernel-owned, 8-byte-aligned
    /// `hal_core::UserContext` storage.
    SwitchTo {
        /// Where to write the outgoing thread's snapshot.
        save: *mut u8,
        /// The incoming thread's context to resume.
        into: *const u8,
    },
    /// Like `SwitchTo`, but only the L4-style IPC fast path's minimal
    /// register set is saved/restored (SysV's own callee-saved set —
    /// `rbx`/`rbp`/`r12`-`r15` — plus this project's own message
    /// registers `rdi`/`rsi`, plus the always-mandatory `rip`/`cs`/
    /// `rflags`/`rsp`/`ss`/`cr3` — see `save_ipc_fast_context`'s own
    /// doc comment for exactly which and why), not every GPR. Used
    /// ONLY by `kernel/src/main.rs`'s real `IPC_CALL`/`IPC_RECV`/
    /// `IPC_REPLY` opcodes — every OTHER switch in this codebase keeps
    /// using plain `SwitchTo`'s full, unconditional guarantee. Mirrors
    /// hal-riscv64's own identical `SwitchToFast`.
    SwitchToFast {
        /// Where to write the outgoing thread's fast-path snapshot.
        save: *mut u8,
        /// The incoming thread's fast-path context to resume.
        into: *const u8,
    },
    /// The trapping thread has been TERMINATED — no save (a terminated
    /// thread never resumes); just restores `into` and `iretq`s into it.
    Terminate {
        /// The next thread's context to resume.
        into: *const u8,
    },
}

/// Signature of the handler the microkernel registers for an
/// `int 0x80` from U-mode: raw `(rax, rdi, rsi)` — this project's own
/// convention (`rax` = opcode, mirroring the real Linux `syscall`/`int
/// 0x80` ABIs where `rax`/`eax` is always the syscall number) — returning
/// a `TrapOutcome` telling the trampoline how to resume.
pub type SyscallHandler = fn(usize, usize, usize) -> TrapOutcome;

#[cfg(target_os = "none")]
static mut SYSCALL_HANDLER: Option<SyscallHandler> = None;

/// Registers the handler `common_syscall_entry` calls for an
/// `int 0x80` from U-mode. The microkernel calls this once during boot,
/// before it drops any process to user mode — same "no handler, no
/// behavior change" contract as hal-riscv64's `set_syscall_handler`, so
/// a binary that links `hal-x86_64` but never runs user code (e.g.
/// `kernel-stub`) simply never registers one.
#[cfg(target_os = "none")]
pub fn set_syscall_handler(handler: SyscallHandler) {
    // SAFETY: single-core boot; set exactly once before any U-mode
    // `int 0x80` can be taken.
    unsafe {
        core::ptr::addr_of_mut!(SYSCALL_HANDLER).write(Some(handler));
    }
}

core::arch::global_asm!(
    r#"
    .section .text
    .global isr_syscall_trampoline
    isr_syscall_trampoline:
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8
        push rbp
        push rdi
        push rsi
        push rdx
        push rcx
        push rbx
        push rax

        mov rdi, rsp
        call common_syscall_entry

        mov rbx, [rsp + 8]
        mov rcx, [rsp + 16]
        mov rdx, [rsp + 24]
        mov rsi, [rsp + 32]
        mov rdi, [rsp + 40]
        mov rbp, [rsp + 48]
        mov r8,  [rsp + 56]
        mov r9,  [rsp + 64]
        mov r10, [rsp + 72]
        mov r11, [rsp + 80]
        mov r12, [rsp + 88]
        mov r13, [rsp + 96]
        mov r14, [rsp + 104]
        mov r15, [rsp + 112]
        mov rax, [rsp + 0]
        add rsp, 120
        iretq
    "#
);

/// Host (`cargo test`) stub — reached only from the bare-metal
/// `isr_syscall_trampoline`'s `call common_syscall_entry` above, which
/// (being a `global_asm!` block) is not itself `#[cfg(target_os =
/// "none")]`-gated and so is present in every build; without this stub
/// the host build fails to LINK (an unresolved `common_syscall_entry`
/// symbol) rather than merely never executing this dead trampoline —
/// same fix hal-riscv64's own `common_trap_entry` host stub applies for
/// the identical reason.
#[cfg(not(target_os = "none"))]
#[no_mangle]
extern "C" fn common_syscall_entry(_frame: *mut SyscallFrame) {}

/// Called from `isr_syscall_trampoline` with a pointer to the pushed
/// `SyscallFrame`. Reads `rax`/`rdi`/`rsi` as `(opcode, a0, a1)`,
/// dispatches to the registered `SyscallHandler`, and either returns
/// normally (the `Resume` case — the trampoline above pops the
/// (in-place modified) saved registers and `iretq`s back to the SAME
/// trapping thread) or diverges into `restore_user_and_iretq` (the
/// `SwitchTo`/`Terminate` cases — a DIFFERENT thread's context, never
/// returning to this trampoline invocation at all).
#[cfg(target_os = "none")]
#[no_mangle]
extern "C" fn common_syscall_entry(frame: *mut SyscallFrame) {
    // SAFETY: `frame` points at the 160-byte block `isr_syscall_trampoline`
    // just pushed (GPRs) followed by the CPU's own auto-pushed IRETQ
    // frame — both valid for the lifetime of this call, this function's
    // only caller.
    let f = unsafe { &mut *frame };
    // SAFETY: single-core; `SYSCALL_HANDLER` is only written by
    // `set_syscall_handler` during boot, before any U-mode `int 0x80`.
    let handler = unsafe { core::ptr::addr_of!(SYSCALL_HANDLER).read() };
    let Some(h) = handler else {
        // No handler registered (e.g. `kernel-stub`, which never enters
        // U-mode): nothing meaningful to do with an unexpected syscall
        // trap — halt rather than silently `iretq` back into whatever
        // caused it.
        loop {
            core::hint::spin_loop();
        }
    };
    match h(f.rax as usize, f.rdi as usize, f.rsi as usize) {
        TrapOutcome::Resume(ret) => {
            f.rax = ret as u64;
            // `rip` needs NO adjustment here: unlike a hardware exception
            // (which points AT the faulting instruction, "int $0x80"'s
            // COMPLETE, HARDWARE-SAVED return address already points at
            // the instruction FOLLOWING the 2-byte `int 0x80` — Intel SDM
            // Vol. 3 §6.3.1, "software interrupt": the saved CS:RIP is the
            // address of the instruction after INT n, exactly like a CALL
            // instruction's own return address. **Real bug found via
            // QEMU** (this session's P2/device-manager demo, not the
            // original U-mode+syscall milestone that introduced this
            // line): an earlier draft of this function added a manual
            // `f.rip += 2` here on top of that already-correct hardware
            // value, DOUBLE-advancing past the next instruction's own
            // first 2 bytes. This went unnoticed in the original
            // milestone's narrow ALIVE/REPORT/spin-forever test (and
            // even survived this session's OWN two-process cooperative
            // round-trip) purely by luck — the skipped 2 bytes happened
            // to still decode into something harmless for BOTH of those
            // specific code layouts — but device-manager's
            // `subsystem_main` hit a genuinely bad byte boundary: landing
            // 2 bytes into a 6-byte `movl $1, %r8d`, decoding garbage for
            // its remaining bytes, which then read from a bogus address
            // and took a Ring-3 `#PF` (confirmed via a temporary raw-
            // serial dump of `rip` on entry, which was ALREADY correct
            // pre-adjustment: `0x4000017e`, matching the disassembled
            // next instruction exactly — proving the hardware advance
            // alone is correct and any further `+=` is the bug).
        }
        TrapOutcome::Resume2(a0, a1) => {
            f.rax = a0 as u64;
            f.rsi = a1 as u64;
        }
        TrapOutcome::SwitchTo { save, into } => {
            // SAFETY: `save`/`into` are kernel-owned, 8-byte-aligned
            // `HAL_USER_CONTEXT_BYTES` blobs (the trampoline/
            // `hal_core::UserContext` contract). Snapshot the outgoing
            // thread — resuming AFTER its `int 0x80` — then never
            // return: `restore_user_and_iretq` abandons this trap
            // frame's stack and `iretq`s into the incoming thread.
            //
            // `f.rip` (NOT `f.rip + 2`): same bug/fix as the `Resume`
            // arm just above — the hardware-saved return address ALREADY
            // points past the 2-byte `int 0x80`.
            unsafe {
                save_syscall_frame_as_user_context(
                    f,
                    f.rip,
                    save as *mut X8664UserContext,
                );
                restore_user_and_iretq(into as *const X8664UserContext);
            }
        }
        TrapOutcome::SwitchToFast { save, into } => {
            // SAFETY: `save`/`into` are kernel-owned, 8-byte-aligned
            // `HAL_USER_CONTEXT_BYTES` blobs, same contract as `SwitchTo`.
            // `f.rip` unchanged — same reasoning as `SwitchTo` above.
            unsafe {
                save_ipc_fast_context(f, f.rip, save as *mut X8664UserContext);
                restore_ipc_fast_context(into as *const X8664UserContext);
            }
        }
        TrapOutcome::Terminate { into } => {
            // No save: this trap frame is simply abandoned, same as any
            // other terminated thread.
            // SAFETY: `into` is a kernel-owned, 8-byte-aligned
            // `HAL_USER_CONTEXT_BYTES` blob.
            unsafe { restore_user_and_iretq(into as *const X8664UserContext) };
        }
    }
}

/// Serialises an interrupted U-mode `SyscallFrame` into an
/// `X8664UserContext` so it can be `restore_user_and_iretq`'d later.
/// `resume_rip` is where the thread should continue — for a suspended
/// `int 0x80`, the caller passes `f.rip` UNCHANGED: the hardware-saved
/// return address for a software interrupt already points past the
/// 2-byte `int 0x80` (see `common_syscall_entry`'s `Resume` arm doc
/// comment for the bug this fixes). Captures the *live* CR3, which for
/// a trap taken from U-mode already describes the thread's own address
/// space.
///
/// # Safety
/// `dst` must point at valid, writable `HAL_USER_CONTEXT_BYTES`-sized,
/// 8-byte-aligned storage.
#[cfg(target_os = "none")]
unsafe fn save_syscall_frame_as_user_context(
    frame: &SyscallFrame,
    resume_rip: u64,
    dst: *mut X8664UserContext,
) {
    let cr3: u64;
    // SAFETY: reading CR3 has no preconditions in a trap handler.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    // SAFETY: `dst` is valid writable storage of the matching size /
    // alignment per this function's contract; `SyscallFrame` and
    // `X8664UserContext` share their leading 160 bytes field-for-field
    // (see `X8664UserContext`'s own doc comment).
    unsafe {
        core::ptr::copy_nonoverlapping(
            frame as *const SyscallFrame as *const u8,
            dst as *mut u8,
            size_of::<SyscallFrame>(),
        );
        (*dst).rip = resume_rip;
        (*dst).cr3 = cr3;
    }
}

/// Restores a full `X8664UserContext` and `iretq`s into U-mode. Never
/// returns. Shared by `resume_user` (first entry, from an
/// `init_user_context` blob) and the syscall trampoline's process
/// hand-off path (from a blob it just serialised out of a trap frame).
///
/// # Safety
/// `blob` must point at a valid, resumable `X8664UserContext` whose
/// `cr3` names an address space that maps this core's IDT/GDT/TSS
/// targets and the identity-mapped low RAM `blob` itself lives in.
/// Interrupts must be masked (true throughout — DPL 3 interrupt gates
/// already clear IF on entry, same as every other vector here).
#[cfg(target_os = "none")]
unsafe fn restore_user_and_iretq(blob: *const X8664UserContext) -> ! {
    // SAFETY: contract above. `r15` carries the blob base for the whole
    // sequence (every other GPR this restores, `rax` last): x86_64 has
    // no spare GPR beyond the 15 a full context restores, so — exactly
    // like hal-riscv64's `restore_user_and_sret` uses `t6` — ONE of the
    // restored registers must double as the pointer, loaded from its
    // OWN saved slot dead last, once nothing after it needs `blob`
    // anymore.
    unsafe {
        core::arch::asm!(
            "mov rax, [r15 + 160]", // cr3
            "mov cr3, rax",
            "mov rax, [r15 + 152]", // ss
            "push rax",
            "mov rax, [r15 + 144]", // rsp
            "push rax",
            "mov rax, [r15 + 136]", // rflags
            "push rax",
            "mov rax, [r15 + 128]", // cs
            "push rax",
            "mov rax, [r15 + 120]", // rip
            "push rax",
            "mov rbx, [r15 + 8]",
            "mov rcx, [r15 + 16]",
            "mov rdx, [r15 + 24]",
            "mov rsi, [r15 + 32]",
            "mov rdi, [r15 + 40]",
            "mov rbp, [r15 + 48]",
            "mov r8,  [r15 + 56]",
            "mov r9,  [r15 + 64]",
            "mov r10, [r15 + 72]",
            "mov r11, [r15 + 80]",
            "mov r12, [r15 + 88]",
            "mov r13, [r15 + 96]",
            "mov r14, [r15 + 104]",
            "mov rax, [r15 + 0]",
            "mov r15, [r15 + 112]",
            "iretq",
            in("r15") blob,
            options(noreturn),
        );
    }
}

/// Serialises only the L4-style IPC fast path's minimal register set —
/// SysV's own callee-saved GPRs (`rbx`/`rbp`/`r12`-`r15`) plus this
/// project's own message/return registers (`rdi`=a0 input, `rsi`=a1
/// input-and-Resume2-output, `rax`=Resume/Resume2's own return-value
/// register — see `SyscallHandler`'s and `poke_saved_a0_a1`'s own doc
/// comments for why `rax` is here despite being SysV CALLER-saved: this
/// project's convention puts the syscall's RETURN value in `rax`
/// specifically so it must survive an IPC fast-path switch the same way
/// riscv64's `a0` does, even though on x86_64 `rax` and the message
/// INPUT registers are physically different from each other), plus the
/// always-mandatory resume state (`rip`/`cs`/`rflags`/`rsp`/`ss`/`cr3`).
/// Deliberately narrower than `save_syscall_frame_as_user_context`: the
/// REMAINING SysV caller-saved registers (`rcx`/`rdx`/`r8`-`r11`) are
/// scratch across a call boundary by the ABI's own contract, and an IPC
/// `int 0x80` is treated as exactly that boundary — same reasoning as
/// hal-riscv64's identical `save_ipc_fast_context`, just with x86_64's
/// own SysV register split (widened by one register, `rax`, for the
/// reason above) instead of RISC-V's calling convention. Every field NOT
/// written here is left at whatever `dst` already held — callers must
/// pass a blob this function fully owns (never a stale general-purpose
/// snapshot), exactly as `restore_ipc_fast_context` only ever reads the
/// fields this function writes.
///
/// # Safety
/// `dst` must point at valid, writable `HAL_USER_CONTEXT_BYTES`-sized,
/// 8-byte-aligned storage.
#[cfg(target_os = "none")]
unsafe fn save_ipc_fast_context(frame: &SyscallFrame, resume_rip: u64, dst: *mut X8664UserContext) {
    let cr3: u64;
    // SAFETY: reading CR3 has no preconditions in a trap handler.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    // SAFETY: `dst` is valid writable storage per this function's
    // contract; each field write is in-bounds of `X8664UserContext`.
    unsafe {
        (*dst).rax = frame.rax;
        (*dst).rbx = frame.rbx;
        (*dst).rbp = frame.rbp;
        (*dst).r12 = frame.r12;
        (*dst).r13 = frame.r13;
        (*dst).r14 = frame.r14;
        (*dst).r15 = frame.r15;
        (*dst).rdi = frame.rdi;
        (*dst).rsi = frame.rsi;
        (*dst).rip = resume_rip;
        (*dst).cs = frame.cs;
        (*dst).rflags = frame.rflags;
        (*dst).rsp = frame.rsp;
        (*dst).ss = frame.ss;
        (*dst).cr3 = cr3;
    }
}

/// Restores the fast-path register set `save_ipc_fast_context` wrote and
/// `iretq`s into U-mode. The remaining SysV CALLER-saved GPRs
/// (`rcx`/`rdx`/`r8`-`r11` — NOT `rax`, which `save_ipc_fast_context`'s
/// own doc comment explains is deliberately preserved rather than
/// treated as scratch) are explicitly ZEROED rather than left with
/// whatever the previous occupant of this CPU's registers held — the
/// same deliberate cross-thread information-disclosure fix
/// hal-riscv64's `restore_ipc_fast_context` documents for its own
/// caller-saved set (`t0`-`t6`,`a2`-`a7`): "don't touch" would leak the
/// PREVIOUS thread's register contents into the incoming one.
///
/// # Safety
/// Same contract as `restore_user_and_iretq`: `blob` must point at a
/// valid, resumable fast-path `X8664UserContext` (as produced by
/// `save_ipc_fast_context`) whose `cr3` names an address space that maps
/// this core's IDT/GDT/TSS targets and the identity-mapped low RAM
/// `blob` itself lives in.
#[cfg(target_os = "none")]
unsafe fn restore_ipc_fast_context(blob: *const X8664UserContext) -> ! {
    // SAFETY: contract above. `r15` carries the blob base throughout,
    // loaded from its OWN saved slot dead last — same "one restored
    // register doubles as the pointer" trick `restore_user_and_iretq`
    // uses, for the same reason (x86_64 has no spare GPR). `rax` is used
    // as scratch while shuttling the IRETQ frame onto the stack; its
    // scratch value there is irrelevant — it gets OVERWRITTEN below,
    // before `iretq`, with its real preserved value loaded from the
    // blob (see `save_ipc_fast_context`'s doc comment on why `rax` is
    // preserved here rather than zeroed like the rest of SysV's
    // caller-saved set), so nothing of that scratch use survives into
    // the resumed thread.
    unsafe {
        core::arch::asm!(
            "mov rax, [r15 + 160]", // cr3
            "mov cr3, rax",
            "mov rax, [r15 + 152]", // ss
            "push rax",
            "mov rax, [r15 + 144]", // rsp
            "push rax",
            "mov rax, [r15 + 136]", // rflags
            "push rax",
            "mov rax, [r15 + 128]", // cs
            "push rax",
            "mov rax, [r15 + 120]", // rip
            "push rax",
            "mov rbx, [r15 + 8]",   // preserved (SysV callee-saved)
            "xor rcx, rcx",         // zeroed (SysV caller-saved)
            "xor rdx, rdx",         // zeroed (SysV caller-saved)
            "mov rsi, [r15 + 32]",  // preserved (message register a1)
            "mov rdi, [r15 + 40]",  // preserved (message register a0)
            "mov rbp, [r15 + 48]",  // preserved (SysV callee-saved)
            "xor r8,  r8",          // zeroed (SysV caller-saved)
            "xor r9,  r9",          // zeroed (SysV caller-saved)
            "xor r10, r10",         // zeroed (SysV caller-saved)
            "xor r11, r11",         // zeroed (SysV caller-saved)
            "mov r12, [r15 + 88]",  // preserved (SysV callee-saved)
            "mov r13, [r15 + 96]",  // preserved (SysV callee-saved)
            "mov r14, [r15 + 104]", // preserved (SysV callee-saved)
            "mov rax, [r15 + 0]",   // preserved (return-value register —
                                     // see save_ipc_fast_context's doc
                                     // comment) — after rax's scratch
                                     // use above is done
            "mov r15, [r15 + 112]", // preserved — MUST be last: every
                                     // prior line still dereferences r15
            "iretq",
            in("r15") blob,
            options(noreturn),
        );
    }
}

/// Writes `a0`/`a1` directly into a saved `X8664UserContext`'s
/// **return-value** registers — used by `kernel/src/main.rs`'s IPC
/// syscall handlers to deliver a message INTO a thread that is being
/// woken via a direct hand-off (a `SwitchToFast`/`SwitchTo` target that
/// never itself re-enters `common_syscall_entry` to pick up a `Resume`/
/// `Resume2` return value the normal way — see `kernel_arch_glue`'s
/// `IpcSwitch::poke` field doc comment).
///
/// Deliberately `rax`/`rsi`, NOT `rdi`/`rsi`: unlike hal-riscv64 (whose
/// `ecall` convention reuses the SAME register, `a0`/x10, for both the
/// syscall's input argument and its return value, so poking `a0`/`a1`
/// there is automatically also "poking the return value"), this
/// project's own x86_64 convention deliberately keeps the two separate
/// — `rdi`/`rsi` are the INPUT message registers (`SyscallHandler`'s
/// own doc comment), but `rax`/`rsi` are what `Resume`/`Resume2` write
/// a result into (mirroring the real Linux `int 0x80` ABI, where `rax`
/// is always the return register). Since this function's whole point is
/// delivering a value the resuming thread reads as its syscall's
/// RETURN, it must target the SAME registers `Resume2` does, not the
/// input ones — **real bug found via QEMU** (this session's x86_64 IPC
/// fast-path fan-out): an earlier draft wrote `rdi`/`rsi` here (copying
/// hal-riscv64's field names literally rather than its actual "return
/// register" semantics), which compiled and ran but silently delivered
/// `Reply`'s value into the WRONG registers — the resuming `IPC_CALL`
/// caller read its reply back from `rax` (per `raw_syscall_x86`'s own
/// `inlateout("rax")` convention) and always saw `0`, confirmed via a
/// QEMU serial capture showing `root task (U-mode, x86_64): syscall
/// result = 0x0` where `0xc0ffef` (`0xC0FFEE + 1`, `umode_ipc_server_
/// x86`'s reply) was expected.
///
/// # Safety
/// `ctx` must point at a valid, exclusively-owned `X8664UserContext`
/// (the same blob a `SwitchTo`/`SwitchToFast` `save`/`into` pointer
/// names) — not currently being read or written by anything else.
#[cfg(target_os = "none")]
pub unsafe fn poke_saved_a0_a1(ctx: *mut u8, a0: usize, a1: usize) {
    // SAFETY: contract above; `X8664UserContext` is `#[repr(C)]` and
    // `ctx` is required to point at one.
    unsafe {
        let c = &mut *(ctx as *mut X8664UserContext);
        c.rax = a0 as u64;
        c.rsi = a1 as u64;
    }
}

// ============================================================================
// Per-process fault isolation (`#UD`, Ring 3 -> Ring 0) — analogous to
// hal-riscv64's `FaultHandler`/`common_trap_entry`'s exception branch
// (03-Kernel-Subsystems-Layer.md §2.1/§5.2: a driver crash must kill only
// that ONE process). Routed through a SECOND dedicated trampoline
// (`isr_fault_trampoline`), separate from both the generic 256-vector ISR
// path (no TrapOutcome semantics) and the syscall boundary above (a
// different vector, a different calling convention) — reusing
// `SyscallFrame`'s exact layout, since `#UD` (unlike e.g. `#PF`/`#GP`)
// pushes NO error code, so the hardware-pushed IRETQ frame sits at the
// same offset the syscall trampoline already expects.
// ============================================================================

/// `#UD` (Invalid Opcode) — this project's fault-injection demo choice on
/// x86_64, analogous to hal-riscv64's `.word 0`: `ud2` is the ISA-
/// guaranteed-invalid encoding, so a deliberately crashing process can
/// trigger it with a single, unambiguous instruction. The ONLY vector
/// this mechanism currently handles — a real kernel would extend this to
/// every exception vector that can legitimately occur from Ring 3 (e.g.
/// `#PF`/`#GP`), a tracked follow-up once a concrete need arises.
const FAULT_VECTOR_UD: u8 = 6;

/// Signature of the handler `common_fault_entry` calls for a Ring-3
/// `#UD`: `(vector, rip, _reserved)` — mirrors hal-riscv64's
/// `FaultHandler`'s `(cause_code, sepc, stval)` shape; `_reserved` stays
/// 0 today (there is no AArch64/RISC-V-style single fault-info register
/// value for `#UD` the way `stval`/`FAR_EL1` carry one for a memory
/// fault) but keeps the signature stable if a future vector needs it.
pub type FaultHandler = fn(usize, usize, usize) -> TrapOutcome;

#[cfg(target_os = "none")]
static mut FAULT_HANDLER: Option<FaultHandler> = None;

/// Registers the handler `common_fault_entry` calls for a Ring-3 `#UD`.
/// Same "no handler, no behavior change" contract as `set_syscall_handler`
/// — a binary that never registers one (e.g. `kernel-stub`) is unaffected;
/// an unhandled `#UD` (no registered handler, or one taken from Ring 0)
/// halts, same as any other unexpected fault.
#[cfg(target_os = "none")]
pub fn set_fault_handler(handler: FaultHandler) {
    // SAFETY: single-core boot; set exactly once before any drop to
    // Ring 3.
    unsafe {
        core::ptr::addr_of_mut!(FAULT_HANDLER).write(Some(handler));
    }
}

core::arch::global_asm!(
    r#"
    .section .text
    .global isr_fault_trampoline
    isr_fault_trampoline:
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8
        push rbp
        push rdi
        push rsi
        push rdx
        push rcx
        push rbx
        push rax

        mov rdi, rsp
        call common_fault_entry

        mov rbx, [rsp + 8]
        mov rcx, [rsp + 16]
        mov rdx, [rsp + 24]
        mov rsi, [rsp + 32]
        mov rdi, [rsp + 40]
        mov rbp, [rsp + 48]
        mov r8,  [rsp + 56]
        mov r9,  [rsp + 64]
        mov r10, [rsp + 72]
        mov r11, [rsp + 80]
        mov r12, [rsp + 88]
        mov r13, [rsp + 96]
        mov r14, [rsp + 104]
        mov r15, [rsp + 112]
        mov rax, [rsp + 0]
        add rsp, 120
        iretq
    "#
);

/// Host (`cargo test`) stub — same reason `common_syscall_entry` needs
/// one (the `global_asm!` trampoline's `call` is never cfg-gated).
#[cfg(not(target_os = "none"))]
#[no_mangle]
extern "C" fn common_fault_entry(_frame: *mut SyscallFrame) {}

/// Called from `isr_fault_trampoline` with a pointer to the pushed
/// `SyscallFrame`. A CPU exception (unlike a syscall) can be taken from
/// EITHER privilege level, so this checks `frame.cs & 3` first: a Ring-0
/// `#UD` is the kernel's own bug and stays genuinely fatal (falls
/// through to `halt_on_unexpected_fault`, mirroring hal-riscv64's own
/// "S-mode fault stays unconditionally fatal" choice), never reaching
/// the registered handler at all.
#[cfg(target_os = "none")]
#[no_mangle]
extern "C" fn common_fault_entry(frame: *mut SyscallFrame) {
    // SAFETY: `frame` points at the 160-byte block `isr_fault_trampoline`
    // just pushed, this function's only caller.
    let f = unsafe { &mut *frame };
    let from_ring3 = (f.cs & 3) == 3;
    if from_ring3 {
        // SAFETY: single-core; `FAULT_HANDLER` is only written by
        // `set_fault_handler` during boot, before any drop to Ring 3.
        let handler = unsafe { core::ptr::addr_of!(FAULT_HANDLER).read() };
        if let Some(h) = handler {
            match h(FAULT_VECTOR_UD as usize, f.rip as usize, 0) {
                TrapOutcome::Resume(ret) => {
                    // Not the expected outcome for a fatal exception (the
                    // faulting instruction is still `ud2`, so resuming
                    // at the SAME `rip` would just re-fault forever),
                    // but the type is shared with the syscall path, so
                    // this arm must exist — same as hal-riscv64's own
                    // fault-handler `Resume` arm.
                    f.rax = ret as u64;
                    return;
                }
                TrapOutcome::Resume2(a0, a1) => {
                    // Not a real handler outcome for a fatal exception —
                    // no `FaultHandler` implementation returns this
                    // today — but `TrapOutcome` is shared with the IPC
                    // syscall path, so this arm must exist for
                    // exhaustiveness. Deliver both values the same way
                    // `Resume` does and return.
                    f.rax = a0 as u64;
                    f.rsi = a1 as u64;
                    return;
                }
                TrapOutcome::SwitchTo { save, into } => {
                    // SAFETY: `save`/`into` are kernel-owned, 8-byte-
                    // aligned `HAL_USER_CONTEXT_BYTES` blobs. Resume
                    // point is `f.rip` unchanged (the faulting
                    // instruction never legitimately completes).
                    unsafe {
                        save_syscall_frame_as_user_context(
                            f,
                            f.rip,
                            save as *mut X8664UserContext,
                        );
                        restore_user_and_iretq(into as *const X8664UserContext);
                    }
                }
                TrapOutcome::SwitchToFast { save, into } => {
                    // Unreachable in practice — no `FaultHandler`
                    // implementation returns this — but falls back to a
                    // FULL save/restore rather than the narrower fast-
                    // path one: a fault handler has no basis for
                    // assuming the L4 IPC fast path's register-set
                    // narrowing is safe here, so this deliberately does
                    // NOT call `save_ipc_fast_context`/
                    // `restore_ipc_fast_context`. Same choice hal-
                    // riscv64's own fault handler makes for its
                    // `SwitchToFast` arm.
                    // SAFETY: `save`/`into` are kernel-owned, 8-byte-
                    // aligned `HAL_USER_CONTEXT_BYTES` blobs.
                    unsafe {
                        save_syscall_frame_as_user_context(
                            f,
                            f.rip,
                            save as *mut X8664UserContext,
                        );
                        restore_user_and_iretq(into as *const X8664UserContext);
                    }
                }
                TrapOutcome::Terminate { into } => {
                    // The expected outcome: the faulting thread is dead,
                    // its trap frame abandoned, no save.
                    // SAFETY: `into` is a kernel-owned, 8-byte-aligned
                    // `HAL_USER_CONTEXT_BYTES` blob.
                    unsafe { restore_user_and_iretq(into as *const X8664UserContext) };
                }
            }
            return;
        }
    }
    halt_on_unexpected_fault();
}

/// Halts the core in Ring 0 until any interrupt is serviced — the
/// x86_64 counterpart to `hal_arm64::cpu::wfi`/`hal_riscv64::cpu::wfi`
/// (see either's own doc comment for the full cross-architecture
/// rationale: ordinary kernel code stays interrupt-masked except at
/// this one deliberate wait point). `sti` unmasks interrupts; the CPU-
/// guaranteed "STI shadow" (Intel SDM Vol. 2A, `STI`) means an
/// interrupt that becomes pending between `sti` and `hlt` is never
/// lost — it is still held off until `hlt` actually executes. `hlt`
/// (SDM Vol. 2A, `HLT`: "If an enabled interrupt... is received... the
/// processor resumes execution at the instruction following the HLT
/// instruction") then halts until that interrupt (or any later one)
/// fires; its registered handler runs to completion (via the ordinary
/// `common_interrupt_entry` -> `dispatch_vector` path) and `iretq`s
/// back to the SAME context, resuming right here — no context switch
/// happens, unlike a scheduler-driven wake. `cli` immediately restores
/// the masked-by-default invariant. Unlike ARM64's `wfi`/RISC-V's own
/// `wfi`, x86_64's HLT-resume address is unconditionally architecture-
/// guaranteed (not an implementation-defined QEMU/TCG quirk needing a
/// `global_asm!` retry-label workaround), so no equivalent to
/// `hal_arm64_wfi`'s own labelled-trampoline fixup is needed here.
#[cfg(target_os = "none")]
pub fn hlt_wait_for_irq() {
    // SAFETY: valid to execute at CPL 0 (true for every caller of this
    // function — kernel/Ring-0 code only) with no other preconditions;
    // always eventually returns (immediately if an interrupt is already
    // pending, per `HLT`'s own architectural guarantee, or after a
    // genuine hardware wait) rather than ever deadlocking. Not
    // `options(preserves_flags)`: `sti`/`cli` deliberately DO modify
    // `RFLAGS.IF`, which is the entire point of this sequence.
    unsafe {
        core::arch::asm!("sti", "hlt", "cli", options(nostack));
    }
}

/// Host test build: no real Ring-0/IF state exists — a no-op, same
/// stance `hal_arm64::cpu::wfi`'s own host fallback takes (see its doc
/// comment) so this function remains callable, unconditionally, by
/// architecture-erased callers built for the host test target.
#[cfg(not(target_os = "none"))]
pub fn hlt_wait_for_irq() {}

#[cfg(target_os = "none")]
fn halt_on_unexpected_fault() -> ! {
    loop {
        // SAFETY: `hlt` is the standard, side-effect-free halt — same
        // terminal-state justification as every other architecture's
        // unhandled-fault path.
        unsafe {
            core::arch::asm!("cli");
            core::arch::asm!("hlt");
        }
    }
}

// ============================================================================
// Preemptive scheduling (LAPIC timer, `interrupt::TIMER_VECTOR`, Ring 3
// -> Ring 0) — 02-Microkernel-Layer.md §4, analogous to hal-riscv64's
// supervisor-timer-interrupt handling in `common_trap_entry` and hal-
// arm64's `irq_el0_entry`/`TickHandler`. Routed through a THIRD dedicated
// trampoline (`isr_timer_trampoline`), for the same reason the syscall
// and fault boundaries each needed their own: the generic 256-vector ISR
// path (`isr_common_trampoline`) has no TrapOutcome-style switch
// semantics — it always resumes exactly where an interrupt landed,
// correct for an ordinary IRQ handler but not for a tick that may need
// to switch which thread is running. Reuses `SyscallFrame`'s exact
// layout: a hardware interrupt (unlike `#GP`/`#PF`) pushes no error
// code, so the auto-pushed IRETQ frame sits at the same offset the
// syscall/fault trampolines already expect.
// ============================================================================

/// Signature of the handler the microkernel registers for the LAPIC
/// timer interrupt (`interrupt::TIMER_VECTOR`) taken **while a Ring-3
/// thread was running** — the preemptive scheduler's entry point.
/// Takes no arguments (`isr_timer_trampoline` owns the interrupted
/// frame) and returns a `TrapOutcome`: `Resume` to let the current
/// thread keep its quantum, or `SwitchTo` to preempt it. The handler is
/// responsible for re-arming (or cancelling) the timer via
/// `HalInterface`. Mirrors hal-riscv64's `TickHandler` / hal-arm64's
/// `TickHandler` exactly.
pub type TickHandler = fn() -> TrapOutcome;

#[cfg(target_os = "none")]
static mut TICK_HANDLER: Option<TickHandler> = None;

/// Registers the preemptive-scheduler tick handler `common_timer_entry`
/// calls when the LAPIC timer interrupt lands on a running Ring-3
/// thread. Set once during boot. Until it is set (and the kernel arms a
/// deadline via `HalInterface::arm_timer`), the timer interrupt still
/// fires and gets acknowledged/EOI'd by `interrupt::dispatch_vector`
/// (matching `on_timer_interrupt`'s existing callback mechanism) but
/// triggers no thread switch — so `kernel-stub`, which registers no
/// handler and never enters Ring 3, is unaffected.
#[cfg(target_os = "none")]
pub fn set_tick_handler(handler: TickHandler) {
    // SAFETY: single-core boot; set exactly once before the timer is
    // armed and before any drop to Ring 3.
    unsafe {
        core::ptr::addr_of_mut!(TICK_HANDLER).write(Some(handler));
    }
}

core::arch::global_asm!(
    r#"
    .section .text
    .global isr_timer_trampoline
    isr_timer_trampoline:
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8
        push rbp
        push rdi
        push rsi
        push rdx
        push rcx
        push rbx
        push rax

        mov rdi, rsp
        call common_timer_entry

        mov rbx, [rsp + 8]
        mov rcx, [rsp + 16]
        mov rdx, [rsp + 24]
        mov rsi, [rsp + 32]
        mov rdi, [rsp + 40]
        mov rbp, [rsp + 48]
        mov r8,  [rsp + 56]
        mov r9,  [rsp + 64]
        mov r10, [rsp + 72]
        mov r11, [rsp + 80]
        mov r12, [rsp + 88]
        mov r13, [rsp + 96]
        mov r14, [rsp + 104]
        mov r15, [rsp + 112]
        mov rax, [rsp + 0]
        add rsp, 120
        iretq
    "#
);

/// Host (`cargo test`) stub — same reason `common_syscall_entry`/
/// `common_fault_entry` each need one (the `global_asm!` trampoline's
/// `call` is never cfg-gated).
#[cfg(not(target_os = "none"))]
#[no_mangle]
extern "C" fn common_timer_entry(_frame: *mut SyscallFrame) {}

/// Called from `isr_timer_trampoline` with a pointer to the pushed
/// `SyscallFrame`. Always dispatches through `interrupt::dispatch_
/// vector` first (GIC-equivalent EOI + the existing `TimerCallback`
/// mechanism — matches the generic ISR path's own handling of this
/// vector) — ONLY if the interrupt landed on Ring 3 AND a `TickHandler`
/// is registered does it also ask the preemptive scheduler what to do
/// next; a timer tick taken from Ring 0 (kernel-mode work, or before
/// any thread has dropped to Ring 3 yet) just gets acknowledged and
/// resumes normally, mirroring `common_fault_entry`'s own Ring 0 vs.
/// Ring 3 split. Resume point is `f.rip` UNCHANGED either way: unlike
/// `int 0x80` (a software interrupt whose hardware-saved return address
/// already points past it), an ordinary hardware interrupt's saved
/// `rip` points AT the instruction that was about to execute — exactly
/// where execution should continue.
#[cfg(target_os = "none")]
#[no_mangle]
extern "C" fn common_timer_entry(frame: *mut SyscallFrame) {
    // SAFETY: `frame` points at the 160-byte block `isr_timer_trampoline`
    // just pushed, this function's only caller.
    let f = unsafe { &mut *frame };

    crate::interrupt::dispatch_vector(crate::interrupt::TIMER_VECTOR);

    let from_ring3 = (f.cs & 3) == 3;
    if !from_ring3 {
        return;
    }
    // SAFETY: single-core; `TICK_HANDLER` is only written by
    // `set_tick_handler` during boot, before the timer is armed.
    let handler = unsafe { core::ptr::addr_of!(TICK_HANDLER).read() };
    let Some(h) = handler else {
        return;
    };
    match h() {
        TrapOutcome::Resume(_) => {}
        TrapOutcome::Resume2(..) => {
            // Not a real `TickHandler` outcome (no implementation
            // returns this) — exists only for `TrapOutcome`
            // exhaustiveness, same as hal-riscv64's own tick-handler
            // `Resume2` arm. Both values would be meaningless here (a
            // preemption tick returns no message registers), so this is
            // treated identically to `Resume`.
        }
        TrapOutcome::SwitchTo { save, into } => {
            // SAFETY: `save`/`into` are kernel-owned, 8-byte-aligned
            // `HAL_USER_CONTEXT_BYTES` blobs. Never returns:
            // `restore_user_and_iretq` abandons this trap frame's stack
            // and `iretq`s into the incoming thread.
            unsafe {
                save_syscall_frame_as_user_context(f, f.rip, save as *mut X8664UserContext);
                restore_user_and_iretq(into as *const X8664UserContext);
            }
        }
        TrapOutcome::SwitchToFast { save, into } => {
            // Unreachable in practice (no `TickHandler` implementation
            // returns this), but falls back to a FULL save/restore for
            // the same reason `common_fault_entry`'s own `SwitchToFast`
            // arm does — a preemption tick has no basis for assuming
            // the fast path's narrower register set is safe.
            // SAFETY: `save`/`into` are kernel-owned, 8-byte-aligned
            // `HAL_USER_CONTEXT_BYTES` blobs.
            unsafe {
                save_syscall_frame_as_user_context(f, f.rip, save as *mut X8664UserContext);
                restore_user_and_iretq(into as *const X8664UserContext);
            }
        }
        TrapOutcome::Terminate { into } => {
            // Not the expected outcome for a plain preemption tick (the
            // preempted thread is still perfectly resumable), but the
            // type is shared with the syscall/fault paths, so this arm
            // must exist — same as hal-riscv64's/hal-arm64's own tick-
            // handler `Terminate` arms.
            // SAFETY: `into` is a kernel-owned, 8-byte-aligned
            // `HAL_USER_CONTEXT_BYTES` blob.
            unsafe { restore_user_and_iretq(into as *const X8664UserContext) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock CPUID source for testing `detect_feature_flags` without
    /// depending on the actual test-runner host CPU's feature set —
    /// per section 8.4's "mock hardware" testing philosophy, applied
    /// here at the architecture-crate level.
    struct MockCpuid {
        leaf1: CpuidResult,
        leaf7: CpuidResult,
        leaf_a: CpuidResult,
    }

    impl CpuidSource for MockCpuid {
        fn cpuid(&self, leaf: u32, _subleaf: u32) -> CpuidResult {
            match leaf {
                1 => self.leaf1,
                7 => self.leaf7,
                0x0A => self.leaf_a,
                _ => CpuidResult::default(),
            }
        }
    }

    #[test]
    fn detects_sse2_and_avx_from_leaf1() {
        let mock = MockCpuid {
            leaf1: CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 1 << 28, // AVX
                edx: 1 << 26, // SSE2
            },
            leaf7: CpuidResult::default(),
            leaf_a: CpuidResult::default(),
        };
        let flags = detect_feature_flags(&mock);
        assert!(flags.contains(CpuFeatureFlags::SIMD_128));
        assert!(flags.contains(CpuFeatureFlags::SIMD_256));
        assert!(!flags.contains(CpuFeatureFlags::SIMD_512));
    }

    #[test]
    fn detects_avx512_from_leaf7() {
        let mock = MockCpuid {
            leaf1: CpuidResult::default(),
            leaf7: CpuidResult {
                eax: 0,
                ebx: 1 << 16, // AVX512F
                ecx: 0,
                edx: 0,
            },
            leaf_a: CpuidResult::default(),
        };
        let flags = detect_feature_flags(&mock);
        assert!(flags.contains(CpuFeatureFlags::SIMD_512));
    }

    #[test]
    fn detects_perf_counters_from_leaf_a() {
        let mock = MockCpuid {
            leaf1: CpuidResult::default(),
            leaf7: CpuidResult::default(),
            leaf_a: CpuidResult { eax: 2, ebx: 0, ecx: 0, edx: 0 }, // version 2
        };
        let flags = detect_feature_flags(&mock);
        assert!(flags.contains(CpuFeatureFlags::PERF_COUNTERS));
    }

    #[test]
    fn no_perf_counters_when_leaf_a_version_zero() {
        let mock = MockCpuid {
            leaf1: CpuidResult::default(),
            leaf7: CpuidResult::default(),
            leaf_a: CpuidResult::default(), // eax = 0 => unsupported
        };
        let flags = detect_feature_flags(&mock);
        assert!(!flags.contains(CpuFeatureFlags::PERF_COUNTERS));
    }

    #[test]
    fn iommu_capable_is_never_set_by_cpuid_alone() {
        let mock = MockCpuid {
            leaf1: CpuidResult { eax: 0, ebx: 0, ecx: 0xFFFF_FFFF, edx: 0xFFFF_FFFF },
            leaf7: CpuidResult { eax: 0, ebx: 0xFFFF_FFFF, ecx: 0, edx: 0 },
            leaf_a: CpuidResult::default(),
        };
        let flags = detect_feature_flags(&mock);
        assert!(!flags.contains(CpuFeatureFlags::IOMMU_CAPABLE));
    }

    #[test]
    fn x86_64_context_matches_declared_size() {
        assert_eq!(size_of::<X86_64Context>(), X86_64_CONTEXT_BYTES);
    }

    #[test]
    fn initial_apic_id_reads_correct_ebx_bits() {
        let mock = MockCpuid {
            leaf1: CpuidResult { eax: 0, ebx: 7 << 24, ecx: 0, edx: 0 },
            leaf7: CpuidResult::default(),
            leaf_a: CpuidResult::default(),
        };
        assert_eq!(read_initial_apic_id(&mock), 7);
    }
}

// ============================================================================
// x86_64 4-level page-table helpers (PML4 -> PDPT -> PD -> PT)
//
// Bare-metal only. `map_ram_identity` / `activate_address_space` (above)
// plus `map_range` here are the whole page-table surface the microkernel
// drives through `hal_core::HalInterface` — mirrors hal-riscv64's own
// `riscv_sv39` module (that crate's cpu.rs) almost exactly: below the top
// level, both architectures use 9-bit-per-level, 4 KiB-page, 3-level
// tables at the SAME virtual-address bit positions (bits 38:30 / 29:21 /
// 20:12) — Sv39 was designed to structurally resemble this.
//
// The one real difference `map_ram_identity`/`map_range` must account
// for: x86_64's CR3 ALWAYS points at a PML4 (mapping the full 256 TiB
// address space via 512 entries of 512 GiB each) — there is no ISA-level
// way to make CR3 point directly at a "1 GiB-per-entry" table the way
// Sv39's root does. So `root_frame` here names TWO CONTIGUOUS PAGES: the
// PML4 itself, and (at `root_frame + 4096`) a companion PDPT that
// `map_ram_identity` links as PML4[0]. `kernel-arch-glue::enter` carves 2
// pages for every architecture's `root_pt` uniformly (harmless waste of
// one page on Sv39/AArch64, which only ever use the first) precisely so
// this crate can rely on that second page always being there.
// ============================================================================
#[cfg(target_os = "none")]
pub(crate) mod x86_64_paging {
    /// PTE present bit.
    pub const PRESENT: u64 = 1 << 0;
    /// PTE writable bit.
    pub const WRITABLE: u64 = 1 << 1;
    /// PTE user-accessible bit. Unlike Sv39 (where only the LEAF's `U`
    /// bit matters), x86_64 ANDs the U/S bit across EVERY level of the
    /// walk — an intermediate entry with this bit clear blocks Ring 3
    /// access to everything beneath it, regardless of the leaf's own
    /// bit. `map_ram_identity` therefore always sets this on the PML4
    /// entry (shared infrastructure for both kernel- and user-mapped
    /// regions under it) and only gates it, per the caller's
    /// `user_accessible` argument, on the PDPT identity leaves
    /// themselves; `map_range` mirrors that same always-set-on-
    /// intermediates rule for the PD/PT levels it builds.
    pub const USER: u64 = 1 << 2;
    /// PDPT/PD leaf (huge-page) bit — "PS" in the Intel SDM's
    /// terminology.
    pub const HUGE_PAGE: u64 = 1 << 7;
    /// PTE no-execute bit. x86_64's execute permission is INVERTED
    /// relative to hal_core's portable `perm_bits` (RISC-V/ARM64 set a
    /// bit to ALLOW execute; x86_64 sets a bit to FORBID it) — the one
    /// flag here with the opposite sense of its `perm_bits` source bit.
    pub const NO_EXECUTE: u64 = 1 << 63;
    /// Physical-address mask within a present, non-huge PTE (bits
    /// 51:12; bits 62:52 are available/ignored, bit 63 is `NO_EXECUTE`
    /// above).
    const PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    /// Reads `IA32_APIC_BASE` (Intel SDM 10.12.1) directly — a small,
    /// deliberate duplication of `interrupt.rs`'s own identically-named
    /// concept (`xapic_mmio_base()`): `map_ram_identity` (below) has no
    /// access to the live `InterruptCtrl` instance at all — `HalInterface`
    /// never threads it through (`build_interface(&hal.cpu, &hal.timer)`
    /// only ever exposes CPU/timer state to `kernel_arch_glue`) — so it
    /// re-derives the SAME physical base independently rather than
    /// assuming the architectural reset default, correctly handling the
    /// (rare, not exercised by this project's own QEMU targets, but
    /// architecturally legal) case of firmware relocating it.
    fn xapic_mmio_base_masked() -> u64 {
        let low: u32;
        let high: u32;
        // SAFETY: RDMSR on IA32_APIC_BASE (an always-present
        // architectural MSR) has no preconditions beyond Ring 0
        // execution, which this crate always runs at.
        unsafe {
            core::arch::asm!("rdmsr", in("ecx") 0x1Bu32, out("eax") low, out("edx") high);
        }
        (((high as u64) << 32) | low as u64) & 0x000F_FFFF_FFFF_F000
    }

    /// Zeroes `root_frame` (the PML4), `root_frame + 4096` (its
    /// companion PDPT — see this module's doc comment), and installs
    /// `bytes_gib` 1 GiB identity leaves (VA == PA) into the PDPT, with
    /// PML4[0] pointing at that PDPT. R+W+X (x86_64 has no separate
    /// "readable" bit — `PRESENT` alone means readable) and, if
    /// `user_accessible`, the PDPT leaves are `USER` too (PML4[0] itself
    /// is ALWAYS `USER` — see the `USER` constant's doc comment for why
    /// narrowing it here would also block any later user-accessible
    /// mapping under this same PML4 entry, e.g. `.user_text` mapped
    /// afterward via `map_range`).
    ///
    /// ALSO always installs a kernel-only 2 MiB identity leaf covering
    /// the Local APIC's MMIO region, using `root_frame + 8192` as a
    /// THIRD scratch page (a dedicated PD table for JUST that leaf) —
    /// a REAL, QEMU-confirmed gap this session's preemption work found:
    /// every process's own page table only ever identity-mapped
    /// `bytes_gib` (1 for x86_64's own small, low-loaded kernel image),
    /// leaving the xAPIC unreachable the instant paging activated with
    /// a Ring-3 thread's own CR3 live — invisible until this session's
    /// own timer ISR became the FIRST code to touch xAPIC MMIO from
    /// OUTSIDE the original boot-time identity map (confirmed via
    /// instrumented bisection: the read silently hung with no
    /// diagnostic — this crate's own generic-ISR path has no `#PF`/
    /// `#GP` dump the way hal-arm64's `trap_diag` does).
    ///
    /// Deliberately a 2 MiB PD-level leaf, NOT a coarser 1 GiB PDPT-
    /// level one (which a FIRST attempt at this fix used, and which
    /// genuinely regressed the existing "two isolated Sv39 spaces"/
    /// two-process demo's own `map_range` calls — QEMU-confirmed via
    /// `map_range error`): the xAPIC's default base (0xFEE0_0000) falls
    /// in the SAME 1 GiB PDPT slot (index 3, VA 0xC000_0000..
    /// 0xFFFF_FFFF) this project's OWN demo machinery already uses
    /// fine-grained `map_range` calls for (`P2_VA_A_CONST`=0xC0040000,
    /// the "two Sv39 spaces" proof's 0xE0000000/0xF0000000, process C's
    /// 0xC0300000, etc.) — a whole-GiB BLOCK there collides with (and
    /// wins over, per `map_range`'s own "block already covers this"
    /// rejection) all of them. A 2 MiB leaf at ONLY the xAPIC's own
    /// sub-range leaves every other address in that GiB's PD table free
    /// for `map_range` to populate normally afterward — `map_range`'s
    /// own descent (see its doc comment) finds PDPT[3] is already a
    /// TABLE pointer (not a block) here and simply continues into it.
    ///
    /// # Preconditions
    /// `root_frame`, `root_frame + 4096`, and `root_frame + 8192` are
    /// page-aligned, writable physical frames; single core; called
    /// before `activate_address_space` switches CR3 to this table (all
    /// three frames must stay directly addressable via the CURRENTLY
    /// active mapping while this runs).
    pub fn map_ram_identity(root_frame: usize, bytes_gib: usize, user_accessible: bool) {
        let pml4 = root_frame as *mut u64;
        let pdpt = (root_frame + 4096) as *mut u64;
        let xapic_pd = (root_frame + 8192) as *mut u64;
        // SAFETY: precondition above — `pml4`/`pdpt`/`xapic_pd` are
        // three distinct, writable, page-aligned frames.
        unsafe {
            for i in 0..512 {
                pml4.add(i).write_volatile(0);
                pdpt.add(i).write_volatile(0);
                xapic_pd.add(i).write_volatile(0);
            }
            let pml4_flags = PRESENT | WRITABLE | USER;
            let mut leaf_flags = PRESENT | WRITABLE | HUGE_PAGE;
            if user_accessible {
                leaf_flags |= USER;
            }
            pml4.write_volatile((root_frame as u64 + 4096) | pml4_flags);
            for gib in 0..bytes_gib.min(512) {
                pdpt.add(gib).write_volatile(((gib as u64) << 30) | leaf_flags);
            }

            let xapic_base = xapic_mmio_base_masked();
            let xapic_gib = (xapic_base >> 30) as usize;
            if bytes_gib <= xapic_gib && xapic_gib < 512 {
                let xapic_pd_index = ((xapic_base >> 21) & 0x1FF) as usize;
                let xapic_leaf_pa = xapic_base & !0x1F_FFFF; // 2 MiB-align
                xapic_pd
                    .add(xapic_pd_index)
                    .write_volatile(xapic_leaf_pa | PRESENT | WRITABLE | HUGE_PAGE);
                // PDPT[xapic_gib] points at this PD as a TABLE (bit 7
                // clear — no HUGE_PAGE here, unlike the `bytes_gib`
                // block loop above): `map_range`'s own descent (see its
                // doc comment) relies on distinguishing "block" from
                // "table" at exactly this bit.
                pdpt.add(xapic_gib)
                    .write_volatile((root_frame as u64 + 8192) | PRESENT | WRITABLE | USER);
            }
        }
    }

    /// Maps `[vaddr, vaddr + len)` -> `[paddr, ...)` at 4 KiB granularity,
    /// descending from `root_frame`'s companion PDPT (NOT PML4 itself —
    /// `map_ram_identity` already linked PML4[0] to it, and every VA
    /// this microkernel ever maps lives below 512 GiB, so `map_range`
    /// never needs to touch PML4 again), allocating any missing PD/PT
    /// levels from the pre-zeroed pool at
    /// `[pool_base, pool_base + pool_len * 4096)`. `perm_bits` is
    /// `READ=1, WRITE=2, EXECUTE=4, USER=8` (`READ` is a no-op on
    /// x86_64 — there is no way to make a `PRESENT` page unreadable).
    ///
    /// Returns the number of pool frames consumed, or `u32::MAX` on
    /// error (misaligned args, a huge-page leaf already covering the
    /// range, or the pool running out).
    ///
    /// # Preconditions
    /// `map_ram_identity` has already run on this `root_frame`; the pool
    /// frames are zeroed; single core; every physical address here
    /// (root, pool, leaves) is directly addressable via the CURRENTLY
    /// active mapping.
    pub fn map_range(
        root_frame: usize,
        vaddr: usize,
        paddr: usize,
        len: usize,
        perm_bits: usize,
        pool_base: usize,
        pool_len: usize,
    ) -> u32 {
        if root_frame == 0 || len == 0 || ((vaddr | paddr | len) & 0xFFF) != 0 {
            return u32::MAX;
        }
        let mut leaf = PRESENT;
        if perm_bits & 2 != 0 {
            leaf |= WRITABLE;
        }
        if perm_bits & 8 != 0 {
            leaf |= USER;
        }
        if perm_bits & 4 == 0 {
            leaf |= NO_EXECUTE;
        }

        let pdpt = root_frame + 4096;
        let mut used = 0usize;
        let pages = len / 4096;
        for p in 0..pages {
            let va = vaddr + p * 4096;
            let pa = paddr + p * 4096;
            let (pdpt_i, pd_i, pt_i) = ((va >> 30) & 0x1FF, (va >> 21) & 0x1FF, (va >> 12) & 0x1FF);

            // Descend / build PD.
            // SAFETY: `pdpt` is `root_frame`'s companion PDPT, already
            // built by `map_ram_identity`; paging still addresses it
            // directly per this function's precondition.
            let pd = unsafe {
                let slot = (pdpt as *mut u64).add(pdpt_i);
                let e = slot.read_volatile();
                if e & PRESENT == 0 {
                    if used >= pool_len {
                        return u32::MAX;
                    }
                    let t = pool_base + used * 4096;
                    used += 1;
                    slot.write_volatile((t as u64) | PRESENT | WRITABLE | USER);
                    t
                } else if e & HUGE_PAGE != 0 {
                    return u32::MAX; // a 1 GiB leaf already covers this VA
                } else {
                    (e & PHYS_MASK) as usize
                }
            };

            // Descend / build PT.
            // SAFETY: `pd` is a valid page-table frame just resolved above.
            let pt = unsafe {
                let slot = (pd as *mut u64).add(pd_i);
                let e = slot.read_volatile();
                if e & PRESENT == 0 {
                    if used >= pool_len {
                        return u32::MAX;
                    }
                    let t = pool_base + used * 4096;
                    used += 1;
                    slot.write_volatile((t as u64) | PRESENT | WRITABLE | USER);
                    t
                } else if e & HUGE_PAGE != 0 {
                    return u32::MAX; // a 2 MiB leaf already covers this VA
                } else {
                    (e & PHYS_MASK) as usize
                }
            };

            // Install the 4 KiB leaf.
            // SAFETY: `pt` is a valid page-table frame just resolved above.
            unsafe {
                (pt as *mut u64)
                    .add(pt_i)
                    .write_volatile((pa as u64 & PHYS_MASK) | leaf);
            }
        }
        used as u32
    }
}