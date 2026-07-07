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

#[cfg(feature = "boring")]
pub mod tls_boring;

#[cfg(feature = "rustls")]
pub mod tls_rustls;

#[cfg(feature = "native-tls")]
pub mod tls_native;

pub use tls_fingerprint::{TlsFingerprint, fingerprint_from_str};

#[cfg(feature = "boring")]
pub use tls_boring::{ChromeTlsStream, connect_chrome_like};

#[cfg(feature = "rustls")]
pub use tls_rustls::{RustlsTlsStream, connect_rustls};

#[cfg(feature = "native-tls")]
pub use tls_native::{NativeTlsStream, connect_native};
