#!/usr/bin/env bash
# ============================================================================
# scripts/qemu-smoke.sh <x86_64|aarch64|riscv64>
#
# Boots the kernel-stub image for one architecture under QEMU and asserts
# the serial log reaches the "handoff complete" markers from
# 01-HAL-Layer.md §8.1/§8.3:
#
#     BootInfo validation: OK
#     kernel-stub halting (Phase 1 complete)
#
# kernel-stub deliberately parks in a halt loop rather than powering the
# machine off, so QEMU never exits on its own — this script runs it under
# `timeout` and inspects the captured serial output afterwards.
#
# riscv64 boots straight off SBI + the QEMU-supplied device tree
# (`-kernel`), so it needs nothing beyond `qemu-system-riscv64`.
#
# x86_64 and aarch64 boot through the UEFI path: this script builds
# `uefi-bootloader` (which `include_bytes!`s the freshly built
# kernel-stub ELF), drops it into a throwaway ESP tree, and points QEMU
# at OVMF firmware. Set the firmware locations via:
#
#     OVMF_CODE=/path/to/CODE.fd   OVMF_VARS=/path/to/VARS.fd   (optional)
#
# Defaults match the Debian/Ubuntu `ovmf` + `qemu-efi-aarch64` packages.
# ============================================================================
set -euo pipefail

ARCH="${1:?usage: qemu-smoke.sh <x86_64|aarch64|riscv64>}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TIMEOUT_SECS="${QEMU_SMOKE_TIMEOUT:-90}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
LOG="$WORK/serial.log"

PASS_MARKER_1="BootInfo validation: OK"
PASS_MARKER_2="Phase 1 complete"

run_qemu() {
	# Run QEMU detached from a TTY, capture serial to $LOG, and don't let
	# a hung boot wedge CI. `timeout` returning 124 (killed) is expected
	# and fine — the log content is the real pass/fail signal.
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
	cargo xbuild-kernel-riscv64
	KERNEL="target/riscv64gc-hal/debug/kernel-stub"
	# `-nographic` already routes the first serial port to stdio.
	run_qemu qemu-system-riscv64 -M virt -smp 1 -m 256M \
		-nographic -no-reboot -kernel "$KERNEL"
	;;

x86_64 | aarch64)
	OVMF_CODE_DEFAULT_x86_64="/usr/share/OVMF/OVMF_CODE.fd"
	OVMF_VARS_DEFAULT_x86_64="/usr/share/OVMF/OVMF_VARS.fd"
	OVMF_CODE_DEFAULT_aarch64="/usr/share/AAVMF/AAVMF_CODE.fd"
	OVMF_VARS_DEFAULT_aarch64="/usr/share/AAVMF/AAVMF_VARS.fd"

	if [[ "$ARCH" == "x86_64" ]]; then
		cargo xbuild-kernel-x86_64
		UEFI_TARGET="x86_64-unknown-uefi"
		BOOT_NAME="BOOTX64.EFI"
		CODE="${OVMF_CODE:-$OVMF_CODE_DEFAULT_x86_64}"
		VARS="${OVMF_VARS:-$OVMF_VARS_DEFAULT_x86_64}"
		QEMU=(qemu-system-x86_64 -machine q35 -m 256M)
	else
		cargo xbuild-kernel-aarch64
		UEFI_TARGET="aarch64-unknown-uefi"
		BOOT_NAME="BOOTAA64.EFI"
		CODE="${OVMF_CODE:-$OVMF_CODE_DEFAULT_aarch64}"
		VARS="${OVMF_VARS:-$OVMF_VARS_DEFAULT_aarch64}"
		QEMU=(qemu-system-aarch64 -machine virt -cpu cortex-a72 -m 256M)
	fi

	if [[ ! -f "$CODE" ]]; then
		echo "ERROR: OVMF code firmware not found at '$CODE' (set OVMF_CODE=)" >&2
		exit 2
	fi

	rustup target add "$UEFI_TARGET" >/dev/null 2>&1 || true
	cargo build -p uefi-bootloader --target "$UEFI_TARGET"

	ESP="$WORK/esp"
	mkdir -p "$ESP/EFI/BOOT"
	cp "target/$UEFI_TARGET/debug/uefi-bootloader.efi" "$ESP/EFI/BOOT/$BOOT_NAME"

	# Writable per-run copy of the OVMF vars store.
	VARS_RW="$WORK/OVMF_VARS.fd"
	if [[ -f "$VARS" ]]; then
		cp "$VARS" "$VARS_RW"
	else
		# aarch64 AAVMF vars are 64 MiB of zeros when absent.
		head -c 67108864 /dev/zero >"$VARS_RW"
	fi

	run_qemu "${QEMU[@]}" \
		-drive "if=pflash,format=raw,readonly=on,file=$CODE" \
		-drive "if=pflash,format=raw,file=$VARS_RW" \
		-drive "format=raw,file=fat:rw:$ESP" \
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

if grep -qF "$PASS_MARKER_1" "$LOG" && grep -qF "$PASS_MARKER_2" "$LOG"; then
	echo "PASS ($ARCH): reached '$PASS_MARKER_1' and '$PASS_MARKER_2'"
	exit 0
fi

echo "FAIL ($ARCH): serial log did not contain both success markers" >&2
exit 1
