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
    /// Stealth ClientHello mimicry: "chrome", "firefox", "safari", "none".
    /// This selects which browser's TLS handshake shape we imitate to blend
    /// in with normal HTTPS traffic and evade DPI classifiers.
    ///
    /// Renamed from `tls_fingerprint` to make room for `server_identity_pin`
    /// (below) — the old name was misleading because "fingerprint" already
    /// means "server identity hash" in TOFU-land. The `alias` keeps old
    /// on-disk configs deserialising.
    #[serde(default, alias = "tlsFingerprint")]
    pub stealth_fingerprint: Option<String>,
    /// TOFU pin of the server's X3DH Ed25519 identity key, canonical
    /// `ik:1:<base32>` (see `rvpn_core::identity_pin`).
    ///
    /// - `Some(_)` — enforce on handshake. Any mismatch returns
    ///   `Error::ServerIdentityMismatch { expected, actual }`.
    /// - `None`   — TOFU capture path. The app calls
    ///   `rvpn_tun_get_server_identity()` after `Connected` and writes the
    ///   returned pin into the profile.
    ///
    /// `serverFingerprint` alias covers the legacy Swift/Kotlin field name
    /// that older builds still use for the same slot.
    #[serde(default, alias = "serverFingerprint")]
    pub server_identity_pin: Option<String>,
    /// Path to JSON file mapping country codes to CIDR arrays.
    /// Format: {"CN": ["1.0.1.0/24", ...]}
    /// Used instead of compiled-in builtin IPs.
    #[serde(default)]
    pub country_ips_file: Option<String>,
    /// Additional named exit servers for multi-server routing (optional).
    ///
    /// The top-level `server_address` + `prekey_bundle_path` form the
    /// implicit `"default"` exit; entries here add more, keyed by `name`.
    /// The client identity key is shared across all servers (SSH-model —
    /// one client key, many hosts). Traffic is steered by `routing` below:
    /// domain rules are learned via DNS interception, IP/CIDR rules match
    /// packet destinations directly. Routed exits never silently fall back
    /// to the default server.
    #[serde(default)]
    pub extra_servers: Vec<MobileServerEntry>,
    /// Per-exit routing rules, keyed by server `name` from `extra_servers`.
    /// Same semantics as the CLI's `[routing.<name>]` sections. Rules for
    /// `"default"` are rejected (unmatched traffic already goes there).
    #[serde(default)]
    pub routing: std::collections::HashMap<String, rvpn_split_tunnel::RoutingRule>,
}

/// An additional named exit server for multi-server Direct TUN routing.
///
/// Mirrors the CLI's `[[server]]` block (`ServerEntry` in rvpn-client) but
/// with mobile's camelCase JSON and file-path bundle reference.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MobileServerEntry {
    /// Symbolic name used as the key in `routing`. Must be unique and
    /// cannot be `"default"`.
    pub name: String,
    /// WebSocket address (e.g. `wss://sg.example.com:443/api/v1/ws`).
    pub address: String,
    /// Path to this server's X3DH prekey bundle JSON (app-group container).
    pub prekey_bundle_path: String,
    /// Optional pinned identity fingerprint (`ik:1:<base32>`). If unset,
    /// this exit uses TOFU like the default server.
    #[serde(default, alias = "serverFingerprint")]
    pub server_identity_pin: Option<String>,
    /// TLS SNI hostname (optional; defaults to the URL host).
    #[serde(default)]
    pub sni_hostname: Option<String>,
}

fn default_dns_bind_addr() -> String {
    "127.0.0.1:5353".to_string()
}

fn default_mtu() -> u16 {
    1420
}
