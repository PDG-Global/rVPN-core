// Build script for rvpn-mobile
// Path 1: Minimal FFI for rvpn-client lifecycle management

fn main() {
    // Tell cargo to re-run this script if the API files change
    println!("cargo:rerun-if-changed=src/api.rs");
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/ffi.rs");
}
