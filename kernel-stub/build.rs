// ============================================================================
// build.rs — kernel-stub
//
// Emits the linker script argument for the FINAL binary link step.
// This MUST live here (not in hal-x86_64/hal-arm64/hal-riscv64's own
// build.rs) because Cargo only honors `cargo:rustc-link-arg=...` from
// the build script of the crate that actually produces the final
// binary — a library crate's build script emitting this flag has no
// effect on a downstream binary crate that depends on it. Since
// kernel-stub is the actual `[[bin]]` target, its build.rs is the
// correct (and only working) place for this.
//
// The linker script itself still PHYSICALLY lives inside each
// hal-<arch> crate's own directory (hal/hal-<arch>/linker.ld), since
// its content is architecture-specific — this build.rs only selects
// which one to pass to the linker, based on the target architecture
// this build is being compiled for.
// ============================================================================

fn main() {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set by cargo");
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").expect("CARGO_CFG_TARGET_ARCH not set by cargo");

    let linker_script = match target_arch.as_str() {
        "x86_64" => format!("{manifest_dir}/../hal/hal-x86_64/src/linker.ld"),
        "aarch64" => format!("{manifest_dir}/../hal/hal-arm64/src/linker.ld"),
        "riscv64" => format!("{manifest_dir}/../hal/hal-riscv64/src/linker.ld"),
        other => panic!("kernel-stub build.rs: unsupported target_arch `{other}`"),
    };

    println!("cargo:rerun-if-changed={linker_script}");
    println!("cargo:rustc-link-arg-bins=-T{linker_script}");
}