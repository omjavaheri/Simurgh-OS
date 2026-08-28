// This crate is a library (rlib), not a final binary target — the
// linker script it owns (linker.ld, next to this file) is applied by
// the DOWNSTREAM binary crate's own build.rs (see kernel-stub/build.rs),
// since Cargo only honors `cargo:rustc-link-arg*` from the build
// script of the crate actually producing the final binary. This
// build.rs is intentionally now a no-op, kept only so `build = "build.rs"`
// in Cargo.toml does not need to be removed if this crate needs a real
// build step again in the future.
fn main() {}