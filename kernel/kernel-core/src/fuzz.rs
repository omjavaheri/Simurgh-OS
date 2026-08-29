//! ============================================================================
//! fuzz.rs
//!
//! Purpose: 02-Microkernel-Layer.md §8.6 MVP acceptance criterion — "Fuzz
//! testing سطح syscall (چون این لایه attack surface اصلی سیستم است)": a
//! layer-3 process can put ANY bit pattern into a `SyscallOp`'s
//! `CapId` / `ThreadId` / count / rights / permission arguments, so
//! `dispatch` must never panic or corrupt kernel state no matter how
//! malformed the input is — every failure mode has to come back as a
//! typed `SyscallError`. This module drives `dispatch` with a large
//! volume of pseudo-random `SyscallOp` values (out-of-range ids, wrong
//! object kinds, absurd counts, arbitrary rights bitmasks, arbitrary
//! addresses) and asserts the Root Task's own bookkeeping survives every
//! single call, across several fixed seeds.
//!
//! Architecture reference: 02-Microkernel-Layer.md §8.6, §1.1 ("dispatch
//! never allocates, never spins" — a panic is the one failure mode this
//! module exists to rule out).
//!
//! Position in the system: host-only (`#[cfg(test)]`), run by
//! `cargo test -p kernel-core`. This is a deterministic, dependency-free
//! property harness, not a continuous/coverage-guided fuzzing campaign
//! (`cargo-fuzz` + libFuzzer needs a nightly + clang toolchain this
//! project's Windows-hosted workflow does not carry) — same
//! harness-now/tuning-later posture as the §8.3 IPC benchmark
//! (IMPLEMENTATION-PLAN.md Phase D6: "numbers/tooling are phase-2, the
//! harness is MVP").
//!
//! Safety/invariants: no `unsafe` in this file. `Rng` is seeded per run
//! from a fixed list, so a failure reproduces deterministically from the
//! seed + iteration index printed in the assertion message.
//! ============================================================================

#![cfg(test)]

use crate::state::KernelState;
use crate::syscall::SyscallOp;
use hal_core::cpu::{CpuAbstraction, CpuContext, CpuFeatureFlags, PrivilegeLevel};
use hal_core::timer::{TimerAbstraction, TimerCallback, TimerMode};
use hal_core::{
    BootInfo, BootProtocol, HalError, MapPermissions, VirtAddr, HAL_CONTEXT_BYTES,
};
use hal_manifest::raw::{
    HardwareManifestRaw, MemoryRegionKindRaw, MemoryRegionRaw, TimerInfoRaw, TimerKindRaw,
};
use kernel_cap::{CapId, CapabilityRights, ThreadId};
use kernel_ipc::SmallMessage;
use kernel_mm::KernelObjectType;

/// Minimal mock `HalInterface` for `dispatch`'s `hal` parameter. Its
/// default (no-op / `u32::MAX`-returning) `map_range` means every `Map`
/// this fuzzer generates that reaches `do_map`'s hardware branch (once
/// `install_map_pool` below makes `map_pool_base() != 0`) takes the
/// ROLLBACK path — exercising that under thousands of adversarial inputs
/// is as much the point of this harness as the rest of the surface.
struct MockCpu;
impl CpuAbstraction<HAL_CONTEXT_BYTES> for MockCpu {
    fn core_count(&self) -> usize {
        1
    }
    fn current_core_id(&self) -> usize {
        0
    }
    fn feature_flags(&self) -> CpuFeatureFlags {
        CpuFeatureFlags::empty()
    }
    unsafe fn context_switch(
        &self,
        _from: &mut CpuContext<HAL_CONTEXT_BYTES>,
        _to: &CpuContext<HAL_CONTEXT_BYTES>,
    ) {
    }
    fn set_privilege_level(&self, _level: PrivilegeLevel) -> Result<(), HalError> {
        Ok(())
    }
    fn bootstrap_current_core(&self) -> Result<(), HalError> {
        Ok(())
    }
}

struct MockTimer;
impl TimerAbstraction for MockTimer {
    fn now_ns(&self) -> u64 {
        0
    }
    fn set_oneshot(&self, _deadline_ns: u64, _mode: TimerMode) -> Result<(), HalError> {
        Ok(())
    }
    fn cancel_oneshot(&self) {}
    fn set_tickless(&self, _enabled: bool) -> Result<(), HalError> {
        Ok(())
    }
    fn set_timer_callback(&self, _callback: TimerCallback) {}
    fn supports_tickless(&self) -> bool {
        false
    }
    fn frequency_hz(&self) -> u64 {
        1_000_000_000
    }
}

/// splitmix64 — a small, dependency-free, non-cryptographic PRNG. Fast
/// and spreads bits well enough over many iterations to hit boundary
/// values (0, near `u32::MAX`) as well as the interior of each range.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }
    /// Uniform-enough value in `0..bound` (0 if `bound == 0`).
    fn next_range(&mut self, bound: u32) -> u32 {
        if bound == 0 {
            0
        } else {
            self.next_u32() % bound
        }
    }
    fn next_bool(&mut self) -> bool {
        self.next_u64() & 1 == 1
    }
}

fn boot_with_ram(mb: u64) -> BootInfo {
    let mut m = HardwareManifestRaw::zeroed();
    m.cpu_core_count = 1;
    m.push_memory_region(MemoryRegionRaw::new(
        0x100_0000,
        mb * 1024 * 1024,
        MemoryRegionKindRaw::Usable,
        false,
    ))
    .unwrap();
    m.timer = TimerInfoRaw::new(TimerKindRaw::Tsc, 1_000_000_000, false);
    BootInfo::new(
        BootProtocol::Uefi,
        m,
        0x1000,
        (0x10_0000, 0x20_0000),
        (0x20_0000, 0x21_0000),
        0,
    )
}

/// A `CapId` skewed toward the interesting cases: the boot-seeded
/// untyped capability (slot 0), a plausible small slot, a value just
/// under `u32::MAX`, and a fully arbitrary one — so the run spends time
/// both near real table boundaries and far past them.
fn random_cap_id(rng: &mut Rng) -> CapId {
    match rng.next_range(4) {
        0 => CapId::new(0),
        1 => CapId::new(rng.next_range(32)),
        2 => CapId::new(u32::MAX - rng.next_range(4)),
        _ => CapId::new(rng.next_u32()),
    }
}

/// A `ThreadId` skewed the same way, plus `root` itself so some fraction
/// of calls come from a genuinely live caller.
fn random_thread_id(rng: &mut Rng, root: ThreadId) -> ThreadId {
    match rng.next_range(3) {
        0 => root,
        1 => ThreadId::new(rng.next_range(200)),
        _ => ThreadId::new(rng.next_u32()),
    }
}

fn random_object_type(rng: &mut Rng) -> KernelObjectType {
    match rng.next_range(6) {
        0 => KernelObjectType::Untyped,
        1 => KernelObjectType::PageTable,
        2 => KernelObjectType::ThreadControlBlock,
        3 => KernelObjectType::Endpoint,
        4 => KernelObjectType::Notification,
        _ => KernelObjectType::CapabilitySpace,
    }
}

fn random_message(rng: &mut Rng) -> SmallMessage {
    let label = rng.next_u64();
    let n = rng.next_range(7) as usize; // 0..=6 == SmallMessage::MSG_MAX_WORDS
    let mut words = [0u64; 6];
    for w in words.iter_mut().take(n) {
        *w = rng.next_u64();
    }
    SmallMessage::from_words(label, &words[..n]).unwrap_or_else(|_| SmallMessage::new(label))
}

/// One pseudo-random `SyscallOp`, uniformly over all eight variants, with
/// every field independently adversarial (see the field-level helpers
/// above) — exactly the shape an untrusted layer-3 process controls.
fn random_op(rng: &mut Rng) -> SyscallOp {
    match rng.next_range(8) {
        0 => SyscallOp::Send {
            endpoint: random_cap_id(rng),
            msg: random_message(rng),
        },
        1 => SyscallOp::Recv {
            endpoint: random_cap_id(rng),
        },
        2 => SyscallOp::Call {
            endpoint: random_cap_id(rng),
            msg: random_message(rng),
        },
        3 => SyscallOp::Yield,
        4 => SyscallOp::CapGrant {
            target_thread: random_cap_id(rng),
            cap: random_cap_id(rng),
            rights: CapabilityRights::from_bits_truncate(rng.next_u32()),
        },
        5 => SyscallOp::CapRevoke {
            cap: random_cap_id(rng),
        },
        6 => SyscallOp::Retype {
            untyped: random_cap_id(rng),
            target_type: random_object_type(rng),
            // Zero, one, a plausible handful, and near-`u32::MAX` — the
            // last two are what `UntypedMemory::retype`'s `checked_mul`
            // overflow guard and the region-size `OutOfMemory` check
            // exist for.
            count: match rng.next_range(4) {
                0 => 0,
                1 => 1,
                2 => rng.next_range(64),
                _ => u32::MAX - rng.next_range(4),
            },
        },
        _ => SyscallOp::Map {
            page_table: random_cap_id(rng),
            frame: random_cap_id(rng),
            vaddr: VirtAddr::new(rng.next_u64() as usize),
            perms: MapPermissions {
                readable: rng.next_bool(),
                writable: rng.next_bool(),
                executable: rng.next_bool(),
                device_uncached: rng.next_bool(),
            },
        },
    }
}

#[test]
fn syscall_dispatch_survives_random_malformed_input() {
    const ITERATIONS: u32 = 200_000;
    // Fixed seeds so a failure reproduces exactly from the printed
    // "seed {:#x} iter {}" in the assertion message — no seed logging
    // infrastructure needed.
    const SEEDS: [u64; 4] = [0x1234_5678_9abc_def0, 0xdead_beef_cafe_babe, 1, 0];

    for &seed in &SEEDS {
        let boot = boot_with_ram(64);
        let mut state = KernelState::from_boot_info(&boot).expect("boot succeeds");
        let root = state.root_thread;
        let root_cs = state.root_cap_space;
        let mut rng = Rng(seed);
        let (cpu, timer) = (MockCpu, MockTimer);
        let hal = hal_core::build_interface(&cpu, &timer);
        // A fake pool (never dereferenced — `MockCpu`'s default
        // `map_range` ignores its args and always reports failure) so
        // `do_map`'s hardware-walk-then-rollback path actually runs
        // under fuzzing, not just the "no pool installed" skip.
        state.install_map_pool(0x1000, 4);

        for i in 0..ITERATIONS {
            // Mostly the real Root Task (so legitimate-looking sequences
            // like Retype-then-use-the-new-cap get exercised too), some
            // fraction from a bogus/absent caller thread id.
            let caller = if rng.next_range(5) == 0 {
                random_thread_id(&mut rng, root)
            } else {
                root
            };
            let op = random_op(&mut rng);
            let now_ns = i as u64 * 1_000;

            // The property under test: dispatch always RETURNS — Ok or a
            // typed Err — no matter how malformed `caller`/`op` are. If
            // this ever panics, the test process aborts and reports
            // which seed/iteration/op triggered it.
            let _ = state.dispatch(caller, now_ns, op, &hal);

            // An adversarial syscall aimed at some other (possibly
            // nonexistent) object must never corrupt the Root Task's OWN
            // bookkeeping — every object-table slot `Retype` can touch is
            // allocated via `alloc_*` (which only ever claims a free
            // slot), so these should be structurally impossible to lose,
            // but that is exactly the kind of invariant a regression here
            // would be catching.
            assert!(
                state.tcb(root).is_some(),
                "seed {:#x} iter {}: Root Task TCB vanished",
                seed,
                i
            );
            assert!(
                state.cap_space(root_cs).is_some(),
                "seed {:#x} iter {}: Root Task capability space vanished",
                seed,
                i
            );
        }
    }
}
