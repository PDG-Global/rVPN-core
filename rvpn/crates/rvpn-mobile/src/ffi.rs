//! R-VPN Mobile FFI - Minimal TunConfig for iOS Direct TUN
//!
//! This file contains only TunConfig which is needed by ios_tun and ios_tun_ffi.
//! All legacy FFI code has been removed as iOS uses ios-direct-tun exclusively.

use serde::{Deserialize, Serialize};

/// Configuration for TUN mode
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TunConfig {
    /// Server WebSocket address
    pub server_address: String,
    /// Path to identity key file
    pub identity_key_path: String,
    /// Path to server prekey bundle JSON file
    pub prekey_bundle_path: String,
    /// DNS servers (optional)
    #[serde(default)]
    pub dns_servers: Vec<String>,
    /// Networks to bypass VPN (CIDR notation, optional)
    #[serde(default)]
    pub bypass_networks: Vec<String>,
    /// MTU setting (default: 1420)
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Split tunnel enabled (optional)
    #[serde(default)]
    pub split_tunnel_enabled: bool,
    /// Built-in bypass countries (optional)
    #[serde(default)]
    pub builtin_bypass_countries: Vec<String>,
    /// Bypass domains (optional)
    #[serde(default)]
    pub bypass_domains: Vec<String>,
    /// Tunnel domains (optional)
    #[serde(default)]
    pub tunnel_domains: Vec<String>,
    /// Block ads (optional)
    #[serde(default)]
    pub block_ads: bool,
    /// Local DNS server bind address (default: 127.0.0.1:53)
    #[serde(default = "default_dns_bind_addr")]
    pub dns_bind_addr: String,
    /// Enable local DNS proxy (default: false)
    #[serde(default)]
    pub enable_dns_proxy: bool,
    /// TLS fingerprint (chrome, firefox, safari, none)
    #[serde(default)]
    pub tls_fingerprint: Option<String>,
}

fn default_dns_bind_addr() -> String {
    "127.0.0.1:5353".to_string()
}

fn default_mtu() -> u16 {
    1420
}
