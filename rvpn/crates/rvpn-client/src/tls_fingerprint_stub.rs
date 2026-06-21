// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Minimal TlsFingerprint stub for Android.
// Android uses rustls (not BoringSSL) so only the enum is needed for
// config compatibility. The full tls_boring module is not compiled.

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsFingerprint {
    #[default]
    Chrome,
    Firefox,
    Safari,
    None,
}

pub fn fingerprint_from_str(s: &str) -> Option<TlsFingerprint> {
    match s.to_lowercase().as_str() {
        "chrome" => Some(TlsFingerprint::Chrome),
        "firefox" => Some(TlsFingerprint::Firefox),
        "safari" => Some(TlsFingerprint::Safari),
        "none" => Some(TlsFingerprint::None),
        _ => None,
    }
}
