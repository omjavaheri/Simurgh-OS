// ============================================================================
// build.rs — driver-mouse
//
// Mirrors `driver-i8042/build.rs` exactly — see that file's own doc
// comment. x86_64-only: no linker script exists for any other target.
// ============================================================================

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo");
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();

    if target_arch != "x86_64" {
        return;
    }

    let linker_script = format!("{manifest_dir}/src/subsystem-bin-x86_64.ld");
    println!("cargo:rerun-if-changed={linker_script}");
    println!("cargo:rustc-link-arg-bins=-T{linker_script}");
}
