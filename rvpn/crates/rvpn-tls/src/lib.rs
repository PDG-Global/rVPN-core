// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// R-VPN TLS facade. Three interchangeable backends selected by cargo features:
//
// * `boring` (default) — BoringSSL with Chrome ClientHello mimicry.
//   Used by desktop (`rvpn-client`) and macOS.
// * `rustls`           — plain rustls, all allocations via mimalloc.
//   Used by Android (inline in rvpn-mobile) and optionally iOS.
// * `native-tls`       — platform-native TLS (Security.framework on iOS/macOS).
//   Proof-of-concept for iOS: eliminates BoringSSL entirely.
//
// `TlsFingerprint` / `fingerprint_from_str` are backend-independent and always
// available.

pub mod tls_fingerprint;

#[cfg(any(
    feature = "rustls",
    all(feature = "boring", not(target_os = "android"))
))]
pub mod resumption;

#[cfg(feature = "boring")]
pub mod tls_boring;

#[cfg(feature = "rustls")]
pub mod tls_rustls;

#[cfg(feature = "native-tls")]
pub mod tls_native;

pub use tls_fingerprint::{fingerprint_from_str, TlsFingerprint};

#[cfg(any(
    feature = "rustls",
    all(feature = "boring", not(target_os = "android"))
))]
pub use resumption::ResumptionStore;

#[cfg(feature = "boring")]
pub use tls_boring::{connect_chrome_like, ChromeTlsStream};

#[cfg(all(feature = "boring", not(target_os = "android")))]
pub use tls_boring::connect_chrome_like_with_resumption;

#[cfg(feature = "rustls")]
pub use tls_rustls::{
    build_client_config_with_store, connect_rustls, connect_rustls_with_store, RustlsTlsStream,
};

#[cfg(feature = "native-tls")]
pub use tls_native::{connect_native, NativeTlsStream};
