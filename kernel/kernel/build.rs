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


/// Copies an embedded subsystem ELF into `OUT_DIR` with its debug info
/// stripped, and returns the copy's path (what `include_bytes!` embeds).
///
/// Why: the debug-profile subsystem ELFs carry tens of MiB of DWARF that
/// nothing at runtime reads (the ELF loader walks program headers only),
/// yet it lands inside the kernel image. On aarch64 that pushes the image
/// across PA 0x4400_0000, where the Windows QEMU edk2 build fails with
/// "ConvertPages ... kernel image corrupted" (WSL's AAVMF tolerates it).
/// `--strip-debug` keeps symbols and every PT_LOAD segment byte-identical,
/// so behaviour is unchanged. If no objcopy is found the ELF is copied
/// unstripped, which is still correct, just bigger.
fn staged_elf(src: &std::path::Path) -> std::path::PathBuf {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR not set"));
    let dst = out_dir.join(src.file_name().expect("ELF path has a file name"));
    let src = src.canonicalize().unwrap();
    let _ = std::fs::remove_file(&dst);
    let stripped = objcopy_path()
        .map(|tool| {
            std::process::Command::new(tool)
                .arg("--strip-debug")
                .arg(&src)
                .arg(&dst)
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        })
        .unwrap_or(false);
    if !stripped {
        println!("cargo:warning=objcopy unavailable; embedding {} unstripped", src.display());
        std::fs::copy(&src, &dst).expect("copy ELF into OUT_DIR");
    }
    dst.canonicalize().unwrap()
}

/// Finds `llvm-objcopy` from the pinned toolchain's `llvm-tools-preview`.
fn objcopy_path() -> Option<std::path::PathBuf> {
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    let out = std::process::Command::new(rustc).args(["--print", "sysroot"]).output().ok()?;
    let sysroot = std::path::PathBuf::from(String::from_utf8(out.stdout).ok()?.trim());
    for entry in std::fs::read_dir(sysroot.join("lib").join("rustlib")).ok()?.flatten() {
        for name in ["llvm-objcopy.exe", "llvm-objcopy"] {
            let cand = entry.path().join("bin").join(name);
            if cand.exists() {
                return Some(cand);
            }
        }
    }
    None
}

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
        staged_elf(&dm_path).display()
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
        staged_elf(&fs_path).display()
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
        staged_elf(&drv_path).display()
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
        staged_elf(&net_path).display()
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
        staged_elf(&netstack_path).display()
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
        staged_elf(&compositor_path).display()
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
        staged_elf(&mm_service_path).display()
    );

    // Same as above, for `log-collector-native-bin` (04-System-Services-
    // Policy-Layer-v2.md §2.2) — the real Log Collector service, another
    // real IPC SERVER (like fs-native/compositor/mm-service), and the
    // real peer `simurgh-diagnostics`'s own long-existing client
    // transport (`RealLogCollector`, a separate, out-of-tree repo) talks
    // to.
    let log_collector_build_alias = format!("cargo xbuild-subsystem-log-collector-native-{target_arch}");
    let log_collector_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("log-collector-native-bin");

    if !log_collector_path.exists() {
        panic!(
            "kernel build.rs: log-collector-native-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {log_collector_build_alias}",
            log_collector_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", log_collector_path.display());
    println!(
        "cargo:rustc-env=LOG_COLLECTOR_ELF_PATH={}",
        staged_elf(&log_collector_path).display()
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
        staged_elf(&sb_path).display()
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
        staged_elf(&sbi_path).display()
    );

    // Same as `security-broker-bin` above, for `init-bin` — the SECOND
    // layer-4 process this project spawns as a real Simurgh-OS subsystem
    // (REPO-simurgh-init.md §1: "the very first one the kernel's Root Task
    // would start"). Its source lives in the SEPARATE `simurgh-init` git
    // repo, same local-dev-only sibling-directory path stitch as
    // `security-broker-bin` — flagged for Omid there, applies identically
    // here.
    let init_build_alias =
        format!("(in simurgh-init) cargo +nightly-2025-01-15 build -p init-core --bin init-bin --features subsystem-bin --target ../Simurgh-OS/targets/{dm_target_dir_name}.json -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem");
    let init_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("simurgh-init")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("init-bin");

    if !init_path.exists() {
        panic!(
            "kernel build.rs: init-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {init_build_alias}",
            init_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", init_path.display());
    println!(
        "cargo:rustc-env=INIT_ELF_PATH={}",
        staged_elf(&init_path).display()
    );

    // Same as `init-bin` above, for `account-manager-bin` — the THIRD
    // layer-4 process this project spawns as a real Simurgh-OS subsystem
    // (`simurgh-account-manager`, a separate git repo). Same local-dev-
    // only sibling-directory path stitch.
    let am_build_alias =
        format!("(in simurgh-account-manager) cargo +nightly-2025-01-15 build -p session-manager --bin account-manager-bin --features subsystem-bin --target ../Simurgh-OS/targets/{dm_target_dir_name}.json -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem");
    let am_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("simurgh-account-manager")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("account-manager-bin");

    if !am_path.exists() {
        panic!(
            "kernel build.rs: account-manager-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {am_build_alias}",
            am_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", am_path.display());
    println!(
        "cargo:rustc-env=ACCOUNT_MANAGER_ELF_PATH={}",
        staged_elf(&am_path).display()
    );

    // Same as `account-manager-bin` above, for `backup-manager-bin` — the
    // FOURTH layer-4 process this project spawns as a real Simurgh-OS
    // subsystem (`simurgh-backup-manager`, a separate git repo). Same
    // local-dev-only sibling-directory path stitch.
    let bm_build_alias =
        format!("(in simurgh-backup-manager) cargo +nightly-2025-01-15 build -p backup-core --bin backup-manager-bin --features subsystem-bin --target ../Simurgh-OS/targets/{dm_target_dir_name}.json -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem");
    let bm_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("simurgh-backup-manager")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("backup-manager-bin");

    if !bm_path.exists() {
        panic!(
            "kernel build.rs: backup-manager-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {bm_build_alias}",
            bm_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", bm_path.display());
    println!(
        "cargo:rustc-env=BACKUP_MANAGER_ELF_PATH={}",
        staged_elf(&bm_path).display()
    );

    // Same as `backup-manager-bin` above, for `diagnostics-manager-bin` —
    // the FIFTH layer-4 process this project spawns as a real Simurgh-OS
    // subsystem (`simurgh-diagnostics`, a separate git repo). Same
    // local-dev-only sibling-directory path stitch.
    let dg_build_alias =
        format!("(in simurgh-diagnostics) cargo +nightly-2025-01-15 build -p diagnostics-manager --bin diagnostics-manager-bin --features subsystem-bin --target ../Simurgh-OS/targets/{dm_target_dir_name}.json -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem");
    let dg_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("simurgh-diagnostics")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("diagnostics-manager-bin");

    if !dg_path.exists() {
        panic!(
            "kernel build.rs: diagnostics-manager-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {dg_build_alias}",
            dg_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", dg_path.display());
    println!(
        "cargo:rustc-env=DIAGNOSTICS_MANAGER_ELF_PATH={}",
        staged_elf(&dg_path).display()
    );

    // Same as `diagnostics-manager-bin` above, for `store-bin` — the
    // SIXTH layer-4 process this project spawns as a real Simurgh-OS
    // subsystem (`simurgh-store`, a separate git repo). Same
    // local-dev-only sibling-directory path stitch.
    let st_build_alias =
        format!("(in simurgh-store) cargo +nightly-2025-01-15 build -p manifest-installer --bin store-bin --features subsystem-bin --target ../Simurgh-OS/targets/{dm_target_dir_name}.json -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem");
    let st_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("simurgh-store")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("store-bin");

    if !st_path.exists() {
        panic!(
            "kernel build.rs: store-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {st_build_alias}",
            st_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", st_path.display());
    println!(
        "cargo:rustc-env=STORE_ELF_PATH={}",
        staged_elf(&st_path).display()
    );

    // Same as `store-bin` above, for `native-loader-bin` — the SEVENTH
    // layer-4 process this project spawns as a real Simurgh-OS subsystem
    // (`simurgh-native-sdk`, a separate git repo). Same local-dev-only
    // sibling-directory path stitch.
    let nl_build_alias =
        format!("(in simurgh-native-sdk) cargo +nightly-2025-01-15 build -p native-loader --bin native-loader-bin --features subsystem-bin --target ../Simurgh-OS/targets/{dm_target_dir_name}.json -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem");
    let nl_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("simurgh-native-sdk")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("native-loader-bin");

    if !nl_path.exists() {
        panic!(
            "kernel build.rs: native-loader-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {nl_build_alias}",
            nl_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", nl_path.display());
    println!(
        "cargo:rustc-env=NATIVE_LOADER_ELF_PATH={}",
        staged_elf(&nl_path).display()
    );

    // Same as `native-loader-bin` above, for `policy-engine-bin` — the
    // EIGHTH layer-4 process this project spawns as a real Simurgh-OS
    // subsystem (`simurgh-profile-policy`, a separate git repo). Same
    // local-dev-only sibling-directory path stitch.
    //
    // **Real, flagged exception — `release`, not `debug`, unlike every
    // other subsystem-bin here**: `policy-engine-bin` links `rhai`, a
    // real scripting-language engine, not a plain-struct service — its
    // `dev`-profile (debug, unoptimized) build is ~34 MiB, and this
    // whole ELF gets embedded WHOLE into the kernel's own image via
    // `include_bytes!` (`main.rs`'s `POLICY_ENGINE_ELF`). Confirmed via
    // a real QEMU boot: with the `debug` build embedded, the resulting
    // ~92 MiB kernel image made OVMF's own boot loader fail with
    // "BdsDxe: ... Out of Resources" before this project's own code ever
    // ran — a firmware-level failure, not a `Simurgh-OS` kernel bug. The
    // `release` build is ~2.9 MiB (roughly 12x smaller — optimization +
    // stripped debug info), which resolved it. Every other subsystem-bin
    // stays on `debug` deliberately (matches the whole project's dev-
    // profile convention and keeps panics/asserts informative); this is
    // the one crate large enough that the tradeoff flips.
    let pp_build_alias =
        format!("(in simurgh-profile-policy) cargo +nightly-2025-01-15 build --release -p simurgh-profile-policy --bin policy-engine-bin --features subsystem-bin --target ../Simurgh-OS/targets/{dm_target_dir_name}.json -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem");
    let pp_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("simurgh-profile-policy")
        .join("target")
        .join(dm_target_dir_name)
        .join("release")
        .join("policy-engine-bin");

    if !pp_path.exists() {
        panic!(
            "kernel build.rs: policy-engine-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {pp_build_alias}",
            pp_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", pp_path.display());
    println!(
        "cargo:rustc-env=POLICY_ENGINE_ELF_PATH={}",
        staged_elf(&pp_path).display()
    );

    // Same as `policy-engine-bin` above, for `shell-bin` — the NINTH
    // layer-4 process this project spawns as a real Simurgh-OS subsystem
    // (`simurgh-shell`, a separate git repo, no `MD/REPO-Simurgh-OS/`
    // charter — Omid's own 2026-09-10 direction). Same local-dev-only
    // sibling-directory path stitch, and the ordinary `debug` profile
    // (not `release`): unlike `policy-engine-bin`, this crate has no
    // large third-party dependency like `rhai` pushing its debug build
    // past OVMF's own size ceiling.
    let shell_build_alias =
        format!("(in simurgh-shell) cargo +nightly-2025-01-15 build -p shell-core --bin shell-bin --features subsystem-bin --target ../Simurgh-OS/targets/{dm_target_dir_name}.json -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem");
    let shell_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("simurgh-shell")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("shell-bin");

    if !shell_path.exists() {
        panic!(
            "kernel build.rs: shell-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {shell_build_alias}",
            shell_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", shell_path.display());
    println!(
        "cargo:rustc-env=SHELL_ELF_PATH={}",
        staged_elf(&shell_path).display()
    );

    // Same as `shell-bin` above, for `fm-core-bin` — the TENTH layer-4
    // process this project spawns as a real Simurgh-OS subsystem
    // (`simurgh-file-manager`, a separate git repo). Same local-dev-only
    // sibling-directory path stitch, ordinary `debug` profile (no large
    // third-party dependency like `policy-engine-bin`'s `rhai`).
    let fm_build_alias =
        format!("(in simurgh-file-manager) cargo +nightly-2025-01-15 build -p fm-core --bin fm-core-bin --features subsystem-bin --target ../Simurgh-OS/targets/{dm_target_dir_name}.json -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem");
    let fm_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("simurgh-file-manager")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("fm-core-bin");

    if !fm_path.exists() {
        panic!(
            "kernel build.rs: fm-core-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {fm_build_alias}",
            fm_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", fm_path.display());
    println!(
        "cargo:rustc-env=FILE_MANAGER_ELF_PATH={}",
        staged_elf(&fm_path).display()
    );

    // Same as `fm-core-bin` above, for `ui-core-bin` — the ELEVENTH
    // layer-4/5/6 process this project spawns as a real Simurgh-OS
    // subsystem (`Simurgh-UI-Template01`, a separate git repo — the base
    // graphical desktop environment). Same local-dev-only sibling-
    // directory path stitch, ordinary `debug` profile.
    let ui_build_alias =
        format!("(in Simurgh-UI-Template01) cargo +nightly-2025-01-15 build -p ui-core --bin ui-core-bin --features subsystem-bin --target ../Simurgh-OS/targets/{dm_target_dir_name}.json -Z build-std=core,alloc -Z build-std-features=compiler-builtins-mem");
    let ui_path = std::path::PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("Simurgh-UI-Template01")
        .join("target")
        .join(dm_target_dir_name)
        .join("debug")
        .join("ui-core-bin");

    if !ui_path.exists() {
        panic!(
            "kernel build.rs: ui-core-bin binary not found at {} (target_arch = {target_arch}).\n\
             Build it first with: {ui_build_alias}",
            ui_path.display()
        );
    }

    println!("cargo:rerun-if-changed={}", ui_path.display());
    println!(
        "cargo:rustc-env=UI_CORE_ELF_PATH={}",
        staged_elf(&ui_path).display()
    );

    // `driver-i8042-bin` (real-input-handling plan, Stage B) — x86_64
    // ONLY, unlike every ELF above: no i8042 device exists on aarch64/
    // riscv64 (`hal_manifest::raw::PeripheralKindRaw::Input`'s own doc
    // comment), so `driver-i8042` has no linker script and cannot even
    // be built for those targets. `main.rs`'s own consumption of
    // `DRIVER_I8042_ELF_PATH` is `#[cfg(target_arch = "x86_64")]`-gated
    // to match — this is the first ELF embed in this build script that
    // is genuinely architecture-conditional, not just architecture-
    // parameterized.
    if target_arch == "x86_64" {
        let i8042_build_alias = "cargo xbuild-subsystem-driver-i8042-x86_64".to_string();
        let i8042_path = std::path::PathBuf::from(&manifest_dir)
            .join("..")
            .join("..")
            .join("target")
            .join(dm_target_dir_name)
            .join("debug")
            .join("driver-i8042-bin");

        if !i8042_path.exists() {
            panic!(
                "kernel build.rs: driver-i8042-bin binary not found at {} (target_arch = {target_arch}).\n\
                 Build it first with: {i8042_build_alias}",
                i8042_path.display()
            );
        }

        println!("cargo:rerun-if-changed={}", i8042_path.display());
        println!(
            "cargo:rustc-env=DRIVER_I8042_ELF_PATH={}",
            staged_elf(&i8042_path).display()
        );

        // `driver-mouse-bin` (mouse-input plan, Stage 1b) — x86_64-only,
        // same reason as `driver-i8042-bin` just above.
        let mouse_build_alias = "cargo xbuild-subsystem-driver-mouse-x86_64".to_string();
        let mouse_path = std::path::PathBuf::from(&manifest_dir)
            .join("..")
            .join("..")
            .join("target")
            .join(dm_target_dir_name)
            .join("debug")
            .join("driver-mouse-bin");

        if !mouse_path.exists() {
            panic!(
                "kernel build.rs: driver-mouse-bin binary not found at {} (target_arch = {target_arch}).\n\
                 Build it first with: {mouse_build_alias}",
                mouse_path.display()
            );
        }

        println!("cargo:rerun-if-changed={}", mouse_path.display());
        println!(
            "cargo:rustc-env=DRIVER_MOUSE_ELF_PATH={}",
            staged_elf(&mouse_path).display()
        );

        // `driver-nvme-bin` — x86_64-only, same reason as `driver-i8042-
        // bin`/`driver-mouse-bin` just above (NVMe discovery only exists
        // in `hal_x86_64::peripheral` today).
        let nvme_build_alias = "cargo xbuild-subsystem-driver-nvme-x86_64".to_string();
        let nvme_path = std::path::PathBuf::from(&manifest_dir)
            .join("..")
            .join("..")
            .join("target")
            .join(dm_target_dir_name)
            .join("debug")
            .join("driver-nvme-bin");

        if !nvme_path.exists() {
            panic!(
                "kernel build.rs: driver-nvme-bin binary not found at {} (target_arch = {target_arch}).\n\
                 Build it first with: {nvme_build_alias}",
                nvme_path.display()
            );
        }

        println!("cargo:rerun-if-changed={}", nvme_path.display());
        println!(
            "cargo:rustc-env=DRIVER_NVME_ELF_PATH={}",
            staged_elf(&nvme_path).display()
        );

        // `driver-hda-bin` (Intel HD Audio, docs/audio-plan.md) — x86_64-only,
        // same reason as the NVMe driver just above.
        let hda_build_alias = "cargo xbuild-subsystem-driver-hda-x86_64".to_string();
        let hda_path = std::path::PathBuf::from(&manifest_dir)
            .join("..")
            .join("..")
            .join("target")
            .join(dm_target_dir_name)
            .join("debug")
            .join("driver-hda-bin");

        if !hda_path.exists() {
            panic!(
                "kernel build.rs: driver-hda-bin binary not found at {} (target_arch = {target_arch}).\n\
                 Build it first with: {hda_build_alias}",
                hda_path.display()
            );
        }

        println!("cargo:rerun-if-changed={}", hda_path.display());
        println!(
            "cargo:rustc-env=DRIVER_HDA_ELF_PATH={}",
            staged_elf(&hda_path).display()
        );
    }
}
