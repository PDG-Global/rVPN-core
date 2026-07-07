// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Backend-independent TLS fingerprint enum.
//
// `TlsFingerprint` and `fingerprint_from_str` have no TLS-backend dependencies,
// so they live in this always-compiled module. This lets crates that only need
// the enum (e.g. rvpn-mobile on Android, config parsing on iOS with the rustls
// backend) consume it without forcing a particular backend.

/// TLS fingerprint types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum TlsFingerprint {
    /// Chrome 120+ fingerprint (most common)
    #[default]
    Chrome,
    /// Firefox fingerprint
    Firefox,
    /// Safari fingerprint
    Safari,
    /// No fingerprinting
    None,
}

/// Parse fingerprint from string
pub fn fingerprint_from_str(s: &str) -> Option<TlsFingerprint> {
    match s.to_lowercase().as_str() {
        "chrome" | "chrome120" => Some(TlsFingerprint::Chrome),
        "firefox" | "firefox120" => Some(TlsFingerprint::Firefox),
        "safari" | "safari17" => Some(TlsFingerprint::Safari),
        "none" | "standard" => Some(TlsFingerprint::None),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_parsing() {
        assert_eq!(fingerprint_from_str("chrome"), Some(TlsFingerprint::Chrome));
        assert_eq!(fingerprint_from_str("Chrome"), Some(TlsFingerprint::Chrome));
        assert_eq!(fingerprint_from_str("none"), Some(TlsFingerprint::None));
        assert_eq!(fingerprint_from_str("invalid"), None);
    }
}
