// ============================================================================
// build.rs — driver-i8042
//
// Emits the linker-script argument for `driver-i8042-bin`'s own `[[bin]]`
// link step. Mirrors `driver-virtio-blk/build.rs` exactly — see that
// file's own doc comment for the full rationale.
//
// x86_64-only: no i8042 device exists on aarch64/riscv64, so only one
// linker script exists (unlike driver-virtio-blk/net's three) — for any
// other `target_arch` (including a plain host build of this crate's
// library), this build script does nothing.
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
