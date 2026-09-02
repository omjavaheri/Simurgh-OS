// ============================================================================
// build.rs — mm-service
//
// Emits the linker-script argument for `mm-service-bin`'s own `[[bin]]`
// link step. Mirrors `subsystems/compositor/build.rs` exactly (see that
// file's own doc comment for the full rationale — Cargo only honors
// `cargo:rustc-link-arg*` from the crate that actually produces the
// `[[bin]]`).
//
// For any `target_arch` outside the three below (including a plain host
// build of this crate's library — `mm-service` is also a normal `rlib`
// with its own host-testable unit tests), this build script does
// nothing.
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
