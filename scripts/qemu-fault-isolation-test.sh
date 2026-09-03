#!/usr/bin/env bash
# ============================================================================
# scripts/qemu-fault-isolation-test.sh <x86_64|aarch64|riscv64>
#
# Boots the REAL `kernel` binary (not `kernel-stub`) for one architecture
# under QEMU and asserts the serial log reaches device-manager's own
# terminal fault-isolation verdict from 03-Kernel-Subsystems-Layer.md §5.2:
#
#     "کرش عمدی یک درایور (panic تزریق‌شده در تست) -> Device Manager آن را
#     restart می‌کند بدون این‌که بقیه‌ی سیستم متاثر شود (این باید یک تست
#     خودکار در CI باشد، نه فقط ادعا)"
#
# `umode_root`'s own boot sequence spawns a deliberately-faulting driver
# (`.word 0` / `ud2` / an illegal instruction, depending on architecture),
# lets device-manager supervise+restart it MAX_RESTARTS_IN_WINDOW+1 (6)
# times, and settles on a terminal "Failed" state - the SAME real,
# QEMU-verified cycle this project's own IMPLEMENTATION-PLAN.md sessions
# have exercised manually many times over. This script is that manual
# verification, automated, so it runs on every push instead of only when
# someone happens to boot a debug build by hand.
#
# This test needs no virtio device at all - device-manager's own fault-
# isolation demo is unconditional, reached regardless of whether a block/
# network peripheral was discovered at boot - so the QEMU invocations here
# are deliberately minimal (no -netdev/-device beyond the platform's own
# defaults).
#
# riscv64 is a KNOWN, already-documented, currently-open exception: the
# real kernel hits a still-unresolved Compositor spawn fault (`.claude/
# IMPLEMENTATION-PLAN.md` Sessions 25/27) several steps BEFORE `umode_
# root`'s own sequence ever reaches device-manager's spawn, so this test
# cannot pass there yet. `--allow-fail` (or the `ALLOW_FAIL=1` env var)
# makes that architecture's own failure non-fatal to the caller instead of
# silently skipping it - the CI workflow uses this so riscv64 stays
# VISIBLE (its own job still runs and its own log is still captured) but
# does not block the pipeline on a bug that already has its own tracked,
# open investigation.
#
# x86_64 and aarch64 boot through the UEFI path, reusing `uefi-bootloader`
# with `SIMURGH_UEFI_KERNEL_BIN=kernel` (its own env var, added specifically
# for this kind of manual/CI verification of the REAL kernel binary rather
# than `kernel-stub`) - same OVMF/AAVMF firmware convention `scripts/qemu-
# smoke.sh` already establishes; see that script's own comments for the
# Windows/native_path translation rationale, which applies identically
# here. riscv64 boots straight off SBI + the QEMU-supplied device tree.
# ============================================================================
set -euo pipefail

ARCH="${1:?usage: qemu-fault-isolation-test.sh <x86_64|aarch64|riscv64> [--allow-fail]}"
ALLOW_FAIL=0
if [[ "${2:-}" == "--allow-fail" || "${ALLOW_FAIL:-0}" == "1" ]]; then
	ALLOW_FAIL=1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TIMEOUT_SECS="${QEMU_FAULT_TEST_TIMEOUT:-90}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
LOG="$WORK/serial.log"

# See `scripts/qemu-smoke.sh`'s own identical helper for why this
# translation is needed on Windows/Git-Bash.
native_path() {
	if command -v cygpath >/dev/null 2>&1; then
		cygpath -w "$1"
	else
		printf '%s\n' "$1"
	fi
}

PASS_MARKER="state=Failed restarts_in_window=6"

run_qemu() {
	echo "+ (timeout ${TIMEOUT_SECS}s) $*" >&2
	set +e
	timeout --foreground "${TIMEOUT_SECS}" "$@" </dev/null >"$LOG" 2>&1
	local rc=$?
	set -e
	if [[ $rc -ne 0 && $rc -ne 124 && $rc -ne 143 ]]; then
		echo "WARNING: QEMU exited with unexpected status $rc" >&2
	fi
}

case "$ARCH" in
riscv64)
	cargo xbuild-microkernel-riscv64
	KERNEL="target/riscv64gc-hal/debug/kernel"
	run_qemu qemu-system-riscv64 -M virt -smp 1 -m 256M \
		-nographic -no-reboot -kernel "$KERNEL"
	;;

x86_64 | aarch64)
	# See `scripts/qemu-smoke.sh`'s own identical comment: the Debian/
	# Ubuntu `ovmf` package's firmware file names have changed across
	# releases (Ubuntu 24.04 ships `OVMF_CODE_4M.fd`/`OVMF_VARS_4M.fd`,
	# not the older plain names) - try every known name in order.
	first_existing() {
		for f in "$@"; do
			[[ -f "$f" ]] && printf '%s\n' "$f" && return 0
		done
		return 1
	}
	OVMF_CODE_CANDIDATES_x86_64=(/usr/share/OVMF/OVMF_CODE.fd /usr/share/OVMF/OVMF_CODE_4M.fd)
	OVMF_VARS_CANDIDATES_x86_64=(/usr/share/OVMF/OVMF_VARS.fd /usr/share/OVMF/OVMF_VARS_4M.fd)
	OVMF_CODE_CANDIDATES_aarch64=(/usr/share/AAVMF/AAVMF_CODE.fd /usr/share/AAVMF/AAVMF_CODE_4M.fd)
	OVMF_VARS_CANDIDATES_aarch64=(/usr/share/AAVMF/AAVMF_VARS.fd /usr/share/AAVMF/AAVMF_VARS_4M.fd)

	if [[ "$ARCH" == "x86_64" ]]; then
		UEFI_TARGET="x86_64-unknown-uefi"
		BOOT_NAME="BOOTX64.EFI"
		CODE="${OVMF_CODE:-$(first_existing "${OVMF_CODE_CANDIDATES_x86_64[@]}" || printf '%s' "${OVMF_CODE_CANDIDATES_x86_64[0]}")}"
		VARS="${OVMF_VARS:-$(first_existing "${OVMF_VARS_CANDIDATES_x86_64[@]}" || printf '%s' "${OVMF_VARS_CANDIDATES_x86_64[0]}")}"
		QEMU=(qemu-system-x86_64 -machine q35 -m 256M)
	else
		UEFI_TARGET="aarch64-unknown-uefi"
		BOOT_NAME="BOOTAA64.EFI"
		CODE="${OVMF_CODE:-$(first_existing "${OVMF_CODE_CANDIDATES_aarch64[@]}" || printf '%s' "${OVMF_CODE_CANDIDATES_aarch64[0]}")}"
		VARS="${OVMF_VARS:-$(first_existing "${OVMF_VARS_CANDIDATES_aarch64[@]}" || printf '%s' "${OVMF_VARS_CANDIDATES_aarch64[0]}")}"
		# gic-version=3 explicit - see `.cargo/config.toml`'s own runner
		# comment for why QEMU's own default isn't reliable across versions.
		QEMU=(qemu-system-aarch64 -machine virt,gic-version=3 -cpu cortex-a72 -m 256M)
	fi

	if [[ ! -f "$CODE" ]]; then
		echo "ERROR: OVMF code firmware not found at '$CODE' (set OVMF_CODE=)" >&2
		exit 2
	fi

	rustup target add "$UEFI_TARGET" >/dev/null 2>&1 || true
	SIMURGH_UEFI_KERNEL_BIN=kernel cargo build -p uefi-bootloader --target "$UEFI_TARGET"

	ESP="$WORK/esp"
	mkdir -p "$ESP/EFI/BOOT"
	cp "target/$UEFI_TARGET/debug/uefi-bootloader.efi" "$ESP/EFI/BOOT/$BOOT_NAME"

	VARS_RW="$WORK/OVMF_VARS.fd"
	if [[ -f "$VARS" ]]; then
		cp "$VARS" "$VARS_RW"
	else
		# aarch64 AAVMF vars are 64 MiB of zeros when absent - same
		# convention `scripts/qemu-smoke.sh` already establishes.
		head -c 67108864 /dev/zero >"$VARS_RW"
	fi

	run_qemu "${QEMU[@]}" \
		-drive "if=pflash,format=raw,readonly=on,file=$(native_path "$CODE")" \
		-drive "if=pflash,format=raw,file=$(native_path "$VARS_RW")" \
		-drive "format=raw,file=fat:rw:$(native_path "$ESP")" \
		-nographic -no-reboot -net none
	;;

*)
	echo "ERROR: unknown arch '$ARCH' (expected x86_64, aarch64, or riscv64)" >&2
	exit 2
	;;
esac

echo "---------------- captured serial output ----------------"
cat "$LOG"
echo "-------------------------------------------------------"

if grep -qF "$PASS_MARKER" "$LOG"; then
	echo "PASS ($ARCH): device-manager reached '$PASS_MARKER' - real fault injection, real restart cycle, real terminal verdict"
	exit 0
fi

echo "FAIL ($ARCH): serial log never reached '$PASS_MARKER'" >&2
if [[ "$ALLOW_FAIL" == "1" ]]; then
	echo "NOTE ($ARCH): --allow-fail set - treating as a known, tracked issue rather than a pipeline failure (see .claude/IMPLEMENTATION-PLAN.md, riscv64 Compositor spawn fault, Sessions 25/27)" >&2
	exit 0
fi
exit 1
