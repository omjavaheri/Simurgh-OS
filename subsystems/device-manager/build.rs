// ============================================================================
// build.rs — device-manager
//
// Emits the linker-script argument for `device-manager-bin`'s own
// `[[bin]]` link step, mirroring `kernel/kernel/build.rs` exactly
// (Cargo only honors `cargo:rustc-link-arg*` from the crate that
// actually produces the `[[bin]]`, not a dependency's).
//
// For any `target_arch` outside the three below (including a plain
// host build of this crate's library — `device-manager` is also a
// normal `rlib` dependency of `kernel`, and has its own host-testable
// unit tests), this build script does nothing: there is no
// `device-manager-bin` `[[bin]]` being produced for those targets to
// need a linker script.
// ============================================================================

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo");
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    let linker_script_name = match target_arch.as_str() {
        "riscv64" => "subsystem-bin-riscv64.ld",
        "x86_64" => "subsystem-bin-x86_64.ld",
        "aarch64" => "subsystem-bin-aarch64.ld",
        _ => return,
    };

    let linker_script = format!("{manifest_dir}/src/{linker_script_name}");
    println!("cargo:rerun-if-changed={linker_script}");
    println!("cargo:rustc-link-arg-bins=-T{linker_script}");
}
