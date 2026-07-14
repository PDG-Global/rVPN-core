// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HarmonyOS NEXT NAPI FFI surface.
//!
//! Every function here is exported via `extern "C"` for the NAPI C++ shim
//! in `rvpn-harmonyos/entry/src/main/cpp/napi_module.cc`. Payloads that
//! carry any structure are serialised as JSON strings — this keeps the
//! C boundary trivial and the ArkTS side gets a `JSON.parse`-able string.

use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::OnceLock;

/// Returns a null-terminated static string containing the version of the
/// `rvpn-mobile` crate at build time. Ownership stays with Rust — the
/// caller must not free the returned pointer.
#[no_mangle]
pub extern "C" fn rvpn_version() -> *const c_char {
    static VERSION: OnceLock<CString> = OnceLock::new();
    VERSION
        .get_or_init(|| {
            CString::new(env!("CARGO_PKG_VERSION"))
                .expect("CARGO_PKG_VERSION never contains an interior NUL")
        })
        .as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn rvpn_version_returns_cargo_pkg_version() {
        let ptr = rvpn_version();
        assert!(!ptr.is_null());
        let s = unsafe { CStr::from_ptr(ptr) }.to_str().unwrap();
        assert_eq!(s, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn rvpn_version_pointer_is_stable_across_calls() {
        // The OnceLock guarantees the CString is allocated exactly once,
        // so the returned pointer must be identical on repeated calls.
        // NAPI shim can rely on that when caching converted strings.
        let a = rvpn_version();
        let b = rvpn_version();
        assert_eq!(a, b);
    }
}
