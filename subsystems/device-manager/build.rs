// ============================================================================
// build.rs — device-manager
//
// Emits the linker-script argument for `device-manager-bin`'s own
// `[[bin]]` link step, mirroring `kernel/kernel/build.rs` exactly
// (Cargo only honors `cargo:rustc-link-arg*` from the crate that
// actually produces the `[[bin]]`, not a dependency's).
//
// riscv64-only for now (this session's "subsystems as processes"
// packaging scope — see subsystem-bin-riscv64.ld's own doc comment on
// why x86_64/aarch64 need their own base-address variant first). For
// any other `target_arch` (including a plain host build of this
// crate's library — `device-manager` is also a normal `rlib`
// dependency of `kernel`, and has its own host-testable unit tests),
// this build script does nothing: there is no `device-manager-bin`
// `[[bin]]` being produced for those targets to need a linker script.
// ============================================================================

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo");
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target_arch != "riscv64" {
        return;
    }

    let linker_script = format!("{manifest_dir}/src/subsystem-bin-riscv64.ld");
    println!("cargo:rerun-if-changed={linker_script}");
    println!("cargo:rustc-link-arg-bins=-T{linker_script}");
}
