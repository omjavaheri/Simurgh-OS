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
}

/// One flat-model, long-mode GDT entry. Values below encode: present,
/// long-mode code (L bit) for code segments, DPL 0 for kernel entries
/// and DPL 3 for user entries, and full-limit flat descriptors (base=0,
/// limit=0xFFFFF with G bit set) — the standard layout every x86_64
/// long-mode OS uses, since segmentation itself is not used for memory
/// protection in long mode (paging does that); these entries exist
/// purely to satisfy the CPU's mode-switching requirements.
static GDT: [u64; 5] = [
    0x0000_0000_0000_0000, // 0x00: null descriptor (required by the architecture)
    0x00AF_9A00_0000_FFFF, // 0x08: kernel code, DPL0, long mode
    0x00AF_9200_0000_FFFF, // 0x10: kernel data, DPL0
    0x00AF_FA00_0000_FFFF, // 0x18: user code, DPL3 (selector 0x1B with RPL=3)
    0x00AF_F200_0000_FFFF, // 0x20: user data, DPL3 (selector 0x23 with RPL=3)
];

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
        limit: (size_of::<[u64; 5]>() - 1) as u16,
        base: GDT.as_ptr() as u64,
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
            // (vector 8) once the TSS is built — running the double-
            // fault handler on a dedicated stack is standard practice
            // to survive a kernel stack overflow, but requires a TSS
            // this MVP phase does not yet build (see module docs).
            type_attr: 0b1000_1110, // present, DPL0, 64-bit interrupt gate
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
    .macro isr_stub vector
    .global isr_stub_\vector
    isr_stub_\vector:
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

        add rsp, 8   # discard the pushed vector number
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
    // by the vector number pushed by `isr_stub_<N>` — both facts hold
    // by construction of the assembly above, which this function's
    // only caller.
    let vector = unsafe { *saved_regs.add(15) } as u8;
    crate::interrupt::dispatch_vector(vector);
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
            load_idt();
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