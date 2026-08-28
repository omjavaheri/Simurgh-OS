// ============================================================================
// build.rs — uefi-bootloader
//
// Locates the kernel-stub ELF binary (built separately, for the
// targets/x86_64-hal.json target, per the workspace's cargo
// xbuild-kernel-x86_64 alias) and exposes its path to main.rs via the
// KERNEL_STUB_PATH environment variable, consumed there through
// `include_bytes!(env!("KERNEL_STUB_PATH"))`.
//
// This crate does NOT build kernel-stub itself (that would require
// invoking a second, differently-configured Cargo build from within a
// build script — fragile and slow). Instead, the developer must build
// kernel-stub FIRST (via `cargo xbuild-kernel-x86_64`), then build
// uefi-bootloader. If the expected file is missing, this build script
// fails with a clear message rather than producing a bootloader that
// embeds stale or absent kernel bytes.
// ============================================================================

use std::path::PathBuf;

fn main() {
    // گرفتن نسخه rustc
    let rustc_version = std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    
    println!("cargo:rustc-env=RUSTC_VERSION={}", rustc_version);
    
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo");

    // The TARGET architecture this bootloader itself is being compiled
    // for (e.g. "x86_64" when built with --target x86_64-unknown-uefi,
    // "aarch64" when built with --target aarch64-unknown-uefi) — NOT
    // the host running `cargo build`. Cargo sets this automatically
    // for every build script invocation, per the CARGO_CFG_* family of
    // environment variables documented in the Cargo reference.
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set by cargo");

    // Each hal-<arch> crate's own build output directory is named
    // after ITS custom target file's stem, per Cargo's convention for
    // custom JSON targets (not a built-in triple name) — these three
    // names must stay in sync with targets/x86_64-hal.json,
    // targets/aarch64-hal.json, and targets/riscv64gc-hal.json's own
    // file names respectively.
    let kernel_target_dir_name = match target_arch.as_str() {
        "x86_64" => "x86_64-hal",
        "aarch64" => "aarch64-hal",
        "riscv64" => "riscv64gc-hal",
        other => panic!(
            "uefi-bootloader build.rs: no kernel-stub target directory mapping for target_arch `{other}`"
        ),
    };

    let build_alias = match target_arch.as_str() {
        "x86_64" => "cargo xbuild-kernel-x86_64",
        "aarch64" => "cargo xbuild-kernel-aarch64",
        "riscv64" => "cargo xbuild-kernel-riscv64",
        _ => unreachable!("already matched above"),
    };

    let kernel_path = PathBuf::from(&manifest_dir)
        .join("..")
        .join("target")
        .join(kernel_target_dir_name)
        .join("debug")
        .join("kernel-stub");

    if !kernel_path.exists() {
        panic!(
            "uefi-bootloader build.rs: kernel-stub binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {build_alias}",
            kernel_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", kernel_path.display());
    println!(
        "cargo:rustc-env=KERNEL_STUB_PATH={}",
        kernel_path.canonicalize().unwrap().display()
    );
}