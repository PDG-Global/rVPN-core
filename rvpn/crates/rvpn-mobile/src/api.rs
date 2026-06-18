//! R-VPN Mobile API - Path 1 Architecture
//!
//! This module provides the high-level API for mobile platforms.
//! Architecture: Swift owns SOCKS5, Rust manages rvpn-client lifecycle only.

use serde::{Deserialize, Serialize};

/// Configuration for R-VPN connection (matches JSON from Swift)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileConfig {
    /// Server WebSocket URL (e.g., "wss://001.sg.97688.io:443/api/v1/ws")
    pub server_address: String,
    /// Path to identity key file
    pub identity_key_path: String,
    /// Path to server prekey bundle JSON file
    pub prekey_bundle_path: String,
    /// DNS servers to use
    #[serde(default)]
    pub dns_servers: Vec<String>,
    /// TLS fingerprint (chrome, firefox, safari, ios, android, edge, none)
    #[serde(default)]
    pub tls_fingerprint: Option<String>,
}

impl Default for MobileConfig {
    fn default() -> Self {
        Self {
            server_address: "wss://localhost:443/api/v1/ws".to_string(),
            identity_key_path: "identity.key".to_string(),
            prekey_bundle_path: "prekey_bundle.json".to_string(),
            dns_servers: Vec::new(),
            tls_fingerprint: None,
        }
    }
}

/// Convert MobileConfig to JSON string for FFI
impl MobileConfig {
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
}

// Note: The legacy FFI functions (rvpn_start, rvpn_stop, etc.) have been removed.
// iOS uses ios-direct-tun mode with ios_tun_ffi.rs functions (rvpn_tun_*).
// If other platforms need legacy FFI, they should implement it separately.
