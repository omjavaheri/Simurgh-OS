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
// ALSO locates `device-manager-bin`'s AND `fs-native-bin`'s separately-
// built ELFs, for all three architectures, and exposes their paths via
// `DEVICE_MANAGER_ELF_PATH`/`FS_NATIVE_ELF_PATH`, consumed in `main.rs`
// through `include_bytes!(env!(...))` — same pattern as `uefi-
// bootloader/build.rs`'s `KERNEL_STUB_PATH`. The developer must build
// each FIRST (`cargo xbuild-subsystem-<name>-<arch>`); if an expected
// file is missing, this build script fails with a clear message rather
// than embedding stale or absent bytes.
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

    // Same as above, for `fs-native-bin` (03-Kernel-Subsystems-Layer.md
    // §2.2/§5.3) — the second real subsystem process.
    let fs_build_alias = format!("cargo xbuild-subsystem-fs-native-{target_arch}");
    let fs_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("fs-native-bin");

    if !fs_path.exists() {
        panic!(
            "kernel build.rs: fs-native-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {fs_build_alias}",
            fs_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", fs_path.display());
    println!(
        "cargo:rustc-env=FS_NATIVE_ELF_PATH={}",
        fs_path.canonicalize().unwrap().display()
    );

    // Same as above, for `driver-virtio-blk-bin` (03-Kernel-Subsystems-
    // Layer.md §5.1) — the third real subsystem process.
    let drv_build_alias = format!("cargo xbuild-subsystem-driver-virtio-blk-{target_arch}");
    let drv_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("driver-virtio-blk-bin");

    if !drv_path.exists() {
        panic!(
            "kernel build.rs: driver-virtio-blk-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {drv_build_alias}",
            drv_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", drv_path.display());
    println!(
        "cargo:rustc-env=DRIVER_VIRTIO_BLK_ELF_PATH={}",
        drv_path.canonicalize().unwrap().display()
    );

    // Same as above, for `driver-virtio-net-bin` (03-Kernel-Subsystems-
    // Layer.md §2.3/§5.4) — the fourth real subsystem process, now fanned
    // out to all three architectures (virtio-pci "modern" on aarch64/
    // x86_64, virtio-mmio on riscv64 — `driver_virtio_net::Transport`'s
    // own doc comment), same unconditional shape as `driver-virtio-blk`
    // above.
    let net_build_alias = format!("cargo xbuild-subsystem-driver-virtio-net-{target_arch}");
    let net_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("driver-virtio-net-bin");

    if !net_path.exists() {
        panic!(
            "kernel build.rs: driver-virtio-net-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {net_build_alias}",
            net_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", net_path.display());
    println!(
        "cargo:rustc-env=DRIVER_VIRTIO_NET_ELF_PATH={}",
        net_path.canonicalize().unwrap().display()
    );

    // Same as above, for `netstack-bin` (03-Kernel-Subsystems-Layer.md
    // §2.3/§5.4) — the fifth real subsystem process, and the first that
    // is an IPC CLIENT of another subsystem process (driver-virtio-net)
    // rather than a server.
    let netstack_build_alias = format!("cargo xbuild-subsystem-netstack-{target_arch}");
    let netstack_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("netstack-bin");

    if !netstack_path.exists() {
        panic!(
            "kernel build.rs: netstack-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {netstack_build_alias}",
            netstack_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", netstack_path.display());
    println!(
        "cargo:rustc-env=NETSTACK_ELF_PATH={}",
        netstack_path.canonicalize().unwrap().display()
    );
}
