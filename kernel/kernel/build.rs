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

    // Same as above, for `compositor-bin` (03-Kernel-Subsystems-Layer.md
    // §2.4/§5.4.2) — the sixth real subsystem process, and a real IPC
    // SERVER (like fs-native), not a client (unlike netstack-bin).
    let compositor_build_alias = format!("cargo xbuild-subsystem-compositor-{target_arch}");
    let compositor_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("compositor-bin");

    if !compositor_path.exists() {
        panic!(
            "kernel build.rs: compositor-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {compositor_build_alias}",
            compositor_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", compositor_path.display());
    println!(
        "cargo:rustc-env=COMPOSITOR_ELF_PATH={}",
        compositor_path.canonicalize().unwrap().display()
    );

    // Same as above, for `mm-service-bin` (03-Kernel-Subsystems-Layer.md
    // §2.5) — the seventh real subsystem process, and a real IPC SERVER
    // (like fs-native/compositor-bin), not a client (unlike netstack-bin).
    let mm_service_build_alias = format!("cargo xbuild-subsystem-mm-service-{target_arch}");
    let mm_service_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("mm-service-bin");

    if !mm_service_path.exists() {
        panic!(
            "kernel build.rs: mm-service-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {mm_service_build_alias}",
            mm_service_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", mm_service_path.display());
    println!(
        "cargo:rustc-env=MM_SERVICE_ELF_PATH={}",
        mm_service_path.canonicalize().unwrap().display()
    );

    // Same as above, for `security-broker-bin` — the first LAYER-4 process
    // this project spawns as a real Simurgh-OS subsystem (REPO-simurgh-
    // security-broker.md §1), not a layer-3 one. Unlike every ELF above,
    // its source lives in the SEPARATE `simurgh-security-broker` git repo
    // (per this project's own architecture: layer 4 is out-of-tree,
    // CLAUDE.md's "Layers 4-5 ... live in separate repositories"), so its
    // build output lands in THAT repo's own `target/` directory, not this
    // workspace's — the path below crosses out of `Simurgh-OS` entirely
    // into its sibling directory. This is a LOCAL-DEV-ONLY assumption
    // (both repos are siblings under the same parent folder on this
    // machine, per that repo's own build alias below) that will need to
    // become a real tagged-artifact fetch once `ipc-protocol` is a
    // published dependency `simurgh-security-broker` consumes instead of
    // this ad-hoc path stitch — flagged for Omid, not hidden.
    let sb_build_alias =
        format!("(in simurgh-security-broker) cargo +nightly-2025-01-15 build --bin security-broker-bin --features subsystem-bin --target ../Simurgh-OS/targets/{dm_target_dir_name}.json -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem");
    let sb_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("simurgh-security-broker")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("security-broker-bin");

    if !sb_path.exists() {
        panic!(
            "kernel build.rs: security-broker-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {sb_build_alias}",
            sb_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", sb_path.display());
    println!(
        "cargo:rustc-env=SECURITY_BROKER_ELF_PATH={}",
        sb_path.canonicalize().unwrap().display()
    );

    // Same as above, for `security-broker-intermediary-bin` (Issue #28) —
    // the CapGrant/CapRevoke intermediary. Unlike `security-broker-bin`
    // above, this IS an in-tree subsystem (same `target/<arch>/debug/`
    // directory as every other one in this block), since it is
    // kernel-privilege-adjacent trusted glue this project owns directly,
    // not a separate layer-4 repo.
    let sbi_build_alias = format!("cargo xbuild-subsystem-security-broker-intermediary-{target_arch}");
    let sbi_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("security-broker-intermediary-bin");

    if !sbi_path.exists() {
        panic!(
            "kernel build.rs: security-broker-intermediary-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {sbi_build_alias}",
            sbi_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", sbi_path.display());
    println!(
        "cargo:rustc-env=SECURITY_BROKER_INTERMEDIARY_ELF_PATH={}",
        sbi_path.canonicalize().unwrap().display()
    );
}
