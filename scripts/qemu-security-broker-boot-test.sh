#!/usr/bin/env bash
# ============================================================================
# scripts/qemu-security-broker-boot-test.sh <x86_64|aarch64|riscv64>
#
# Boots the REAL `kernel` binary (not `kernel-stub`) for one architecture
# under QEMU and asserts the serial log reaches the terminal verdict of the
# security-broker-intermediary demo (Issue #28): `simurgh-security-broker`
# (a separately-built ELF from the `simurgh-security-broker` repo, no
# longer just a `std` library exercised only by that repo's own test
# suite) is spawned as a real process, asks the real, separately-spawned
# `security-broker-intermediary` subsystem for a REAL `CapGrant` against a
# SECOND real target (mm-service), and that capability is REVOKED across
# both capability spaces — the same "real capability minting through a
# spawned intermediary" story `MD/00-Overview.md`'s "capabilities replace
# permissions everywhere" principle commits to, now automated instead of
# only verified by hand.
#
# Mirrors `scripts/qemu-fault-isolation-test.sh`'s own structure exactly
# (same QEMU-invocation-per-arch shape, same `--allow-fail` convention) —
# see that script's own comments for the OVMF/AAVMF firmware-name and
# Windows/native_path rationale, which apply identically here.
#
# riscv64 is a KNOWN, already-documented, currently-open exception (same
# one `qemu-fault-isolation-test.sh` already tracks): the real kernel hits
# a still-unresolved Compositor spawn fault several steps BEFORE `umode_
# root`'s own sequence ever reaches the security-broker-intermediary demo,
# so this test cannot pass there yet. `--allow-fail` makes that
# architecture's own failure non-fatal.
# ============================================================================
set -euo pipefail

ARCH="${1:?usage: qemu-security-broker-boot-test.sh <x86_64|aarch64|riscv64> [--allow-fail]}"
ALLOW_FAIL=0
if [[ "${2:-}" == "--allow-fail" || "${ALLOW_FAIL:-0}" == "1" ]]; then
	ALLOW_FAIL=1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TIMEOUT_SECS="${QEMU_SECURITY_BROKER_TEST_TIMEOUT:-90}"
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

# The intermediary demo's own LAST line (the 2nd-target revoke, the
# furthest point the demo reaches) — see `kernel/kernel/src/main.rs`'s own
# `"... revoked the 2nd demo capability — {freed} slot(s) freed (Issue
# #28, multi-target proof)"` call sites (one per architecture). Matched
# without the arch-specific `(x86_64)`/`(aarch64)` prefix (riscv64/the
# generic path have neither) and without the `{freed}` count, since that
# count is real allocator-dependent output, not a fixed string.
PASS_MARKER="security-broker-intermediary revoked the 2nd demo capability"

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

# `-m 512M`, not the original `256M`: see `scripts/qemu-fault-isolation-
# test.sh`'s own identical comment for the full rationale — the same
# embedded-kernel-image capacity ceiling applies to every QEMU boot of
# this kernel, not just the fault-isolation test.
case "$ARCH" in
riscv64)
	cargo xbuild-microkernel-riscv64
	KERNEL="target/riscv64gc-hal/debug/kernel"
	run_qemu qemu-system-riscv64 -M virt -smp 1 -m 512M \
		-nographic -no-reboot -kernel "$KERNEL"
	;;

x86_64 | aarch64)
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
		QEMU=(qemu-system-x86_64 -machine q35 -m 512M)
	else
		UEFI_TARGET="aarch64-unknown-uefi"
		BOOT_NAME="BOOTAA64.EFI"
		CODE="${OVMF_CODE:-$(first_existing "${OVMF_CODE_CANDIDATES_aarch64[@]}" || printf '%s' "${OVMF_CODE_CANDIDATES_aarch64[0]}")}"
		VARS="${OVMF_VARS:-$(first_existing "${OVMF_VARS_CANDIDATES_aarch64[@]}" || printf '%s' "${OVMF_VARS_CANDIDATES_aarch64[0]}")}"
		QEMU=(qemu-system-aarch64 -machine virt,gic-version=3 -cpu cortex-a72 -m 512M)
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
	echo "PASS ($ARCH): security-broker-intermediary reached '$PASS_MARKER' - real spawned security-broker process, real IPC CapGrant/CapRevoke round trip via the intermediary, real 2nd-target proof"
	exit 0
fi

echo "FAIL ($ARCH): serial log never reached '$PASS_MARKER'" >&2
if [[ "$ALLOW_FAIL" == "1" ]]; then
	echo "NOTE ($ARCH): --allow-fail set - treating as a known, tracked issue rather than a pipeline failure" >&2
	exit 0
fi
exit 1
