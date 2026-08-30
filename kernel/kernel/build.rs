// ============================================================================
// build.rs — kernel
//
// Emits the linker-script argument for the FINAL binary link step, exactly
// like `kernel-stub/build.rs`. This MUST live in the crate that actually
// produces the `[[bin]]` (Cargo only honors `cargo:rustc-link-arg*` from
// the final-binary crate's build script, not a dependency's).
//
// The architecture-specific linker script itself physically lives in each
// `hal-<arch>` crate's own `src/` directory; this script only selects
// which one to pass, keyed on the target architecture being built.
//
// ALSO locates `device-manager-bin`'s separately-built ELF, for all
// three architectures, and exposes its path via `DEVICE_MANAGER_ELF_PATH`,
// consumed in `main.rs` through
// `include_bytes!(env!("DEVICE_MANAGER_ELF_PATH"))` — same pattern as
// `uefi-bootloader/build.rs`'s `KERNEL_STUB_PATH`. The developer must
// build it FIRST (`cargo xbuild-subsystem-device-manager-<arch>`); if
// the expected file is missing, this build script fails with a clear
// message rather than embedding stale or absent bytes.
// ============================================================================

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo");
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set by cargo");

    // `kernel/kernel/` is two directories below the workspace root, so the
    // hal crates are at `../../hal/...` from here.
    let linker_script = match target_arch.as_str() {
        "x86_64" => format!("{manifest_dir}/../../hal/hal-x86_64/src/linker.ld"),
        "aarch64" => format!("{manifest_dir}/../../hal/hal-arm64/src/linker.ld"),
        "riscv64" => format!("{manifest_dir}/../../hal/hal-riscv64/src/linker.ld"),
        other => panic!("kernel build.rs: unsupported target_arch `{other}`"),
    };

    println!("cargo:rerun-if-changed={linker_script}");
    println!("cargo:rustc-link-arg-bins=-T{linker_script}");

    // Each `hal-<arch>` crate's own build output directory is named after
    // ITS custom target file's stem (same mapping `uefi-bootloader/
    // build.rs` uses) — must stay in sync with `targets/*.json`'s file
    // names.
    let dm_target_dir_name = match target_arch.as_str() {
        "x86_64" => "x86_64-hal",
        "aarch64" => "aarch64-hal",
        "riscv64" => "riscv64gc-hal",
        other => panic!("kernel build.rs: unreachable target_arch `{other}`"),
    };
    let build_alias = format!("cargo xbuild-subsystem-device-manager-{target_arch}");

    let dm_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("device-manager-bin");

    if !dm_path.exists() {
        panic!(
            "kernel build.rs: device-manager-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {build_alias}",
            dm_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", dm_path.display());
    println!(
        "cargo:rustc-env=DEVICE_MANAGER_ELF_PATH={}",
        dm_path.canonicalize().unwrap().display()
    );
}
