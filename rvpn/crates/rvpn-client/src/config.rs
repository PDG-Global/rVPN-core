//! Client configuration

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[cfg(not(target_os = "android"))]
use crate::tls_boring::TlsFingerprint;
#[cfg(target_os = "android")]
use crate::tls_fingerprint_stub::TlsFingerprint;

/// Main client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    /// Server WebSocket address
    #[serde(default = "default_server_address")]
    pub server_address: String,

    /// TLS SNI hostname
    #[serde(default)]
    pub sni_hostname: Option<String>,

    /// Path to identity key file
    #[serde(default = "default_identity_key_file")]
    pub identity_key_file: PathBuf,

    /// Server public key for authentication
    #[serde(default)]
    pub server_public_key: Option<String>,

    /// Path to server prekey bundle JSON file
    #[serde(default)]
    pub prekey_bundle: Option<PathBuf>,

    /// SOCKS5 proxy configuration
    #[serde(default)]
    pub socks5: Socks5Config,

    /// TUN device configuration
    #[serde(default)]
    pub tun: TunConfig,

    /// Performance settings
    #[serde(default)]
    pub performance: PerformanceConfig,

    /// Split tunnel configuration
    #[serde(default)]
    pub split_tunnel: SplitTunnelConfig,

    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,

    /// Server identity verification configuration
    #[serde(default)]
    pub server_identity: ServerIdentityConfig,

    /// HTTP/HTTPS proxy configuration
    #[serde(default)]
    pub http_proxy: HttpProxyConfig,

    /// DNS proxy configuration (for SOCKS5 mode — routes DNS through the tunnel)
    #[serde(default)]
    pub dns_proxy: DnsProxyConfig,

    /// TLS fingerprint configuration for DPI resistance
    /// Set to "chrome", "firefox", "safari", "ios", "android", "edge", or "none"
    #[serde(default = "default_tls_fingerprint")]
    pub tls_fingerprint: TlsFingerprint,

    /// Data directory for writable files (stats, known_hosts, etc.)
    /// Defaults to platform-specific data directory:
    /// - Linux: ~/.local/share/rvpn/
    /// - macOS: ~/Library/Application Support/rvpn/
    /// - Windows: %APPDATA%/rvpn/
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            server_address: "wss://localhost:443/api/v1/ws".to_string(),
            sni_hostname: None,
            identity_key_file: PathBuf::from("identity.key"),
            server_public_key: None,
            prekey_bundle: None,
            socks5: Socks5Config::default(),
            tun: TunConfig::default(),
            performance: PerformanceConfig::default(),
            split_tunnel: SplitTunnelConfig::default(),
            network: NetworkConfig::default(),
            server_identity: ServerIdentityConfig::default(),
            http_proxy: HttpProxyConfig::default(),
            dns_proxy: DnsProxyConfig::default(),
            tls_fingerprint: TlsFingerprint::default(),
            data_dir: default_data_dir(),
        }
    }
}

impl ClientConfig {
    /// Load configuration from file
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        match ext {
            "toml" => Ok(toml::from_str(&content)?),
            "json" => Ok(serde_json::from_str(&content)?),
            _ => anyhow::bail!("Unsupported config format: {}", ext),
        }
    }
}

fn default_server_address() -> String {
    "wss://localhost:443/api/v1/ws".to_string()
}

fn default_identity_key_file() -> PathBuf {
    PathBuf::from("identity.key")
}

/// SOCKS5 proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Socks5Config {
    /// Listen address for SOCKS5 server
    #[serde(default = "default_socks5_listen")]
    pub listen_address: String,

    /// Enable UDP associate
    #[serde(default = "default_true")]
    pub udp_associate: bool,

    /// Authentication required
    #[serde(default)]
    pub auth_enabled: bool,

    /// Username for authentication
    #[serde(default)]
    pub auth_username: Option<String>,

    /// Password for authentication
    #[serde(default)]
    pub auth_password: Option<String>,

    /// Use multiplexed single-WebSocket connection.
    /// When true, all SOCKS5 flows share one WebSocket with one DoubleRatchet.
    /// When false, each SOCKS5 flow opens a separate WebSocket (default, recommended).
    ///
    /// Non-multiplexed mode (false) is recommended because multiplexed binary traffic
    /// over a single long-lived connection is a distinctive pattern that traffic
    /// classifiers can detect. Non-multiplexed mode mirrors the traffic pattern of
    /// standard tools like Brook — many short-lived WebSocket connections, each carrying
    /// a single request — which blends in with normal HTTPS browsing.
    #[serde(default)]
    pub multiplex: bool,

    /// WebSocket path for multiplexed connections.
    /// When empty (default), derived from server URL as `{server_path}/mux`.
    #[serde(default)]
    pub mux_path: String,
}

impl Default for Socks5Config {
    fn default() -> Self {
        Self {
            listen_address: "127.0.0.1:1080".to_string(),
            udp_associate: true,
            auth_enabled: false,
            auth_username: None,
            auth_password: None,
            multiplex: false,
            mux_path: String::new(),
        }
    }
}

fn default_socks5_listen() -> String {
    "127.0.0.1:1080".to_string()
}

fn default_true() -> bool {
    true
}

/// HTTP/HTTPS proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProxyConfig {
    /// Enable HTTP proxy
    #[serde(default)]
    pub enabled: bool,

    /// Listen address for HTTP proxy server
    #[serde(default = "default_http_proxy_listen")]
    pub listen_address: String,

    /// Basic auth required
    #[serde(default)]
    pub auth_enabled: bool,

    /// Username for Basic auth
    #[serde(default)]
    pub auth_username: Option<String>,

    /// Password for Basic auth
    #[serde(default)]
    pub auth_password: Option<String>,

    /// Use multiplexed single-WebSocket connection.
    /// Default is false — see Socks5Config::multiplex for rationale.
    #[serde(default)]
    pub multiplex: bool,

    /// WebSocket path for multiplexed connections.
    /// When empty (default), derived from server URL as `{server_path}/mux`.
    #[serde(default)]
    pub mux_path: String,
}

impl Default for HttpProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: "127.0.0.1:8118".to_string(),
            auth_enabled: false,
            auth_username: None,
            auth_password: None,
            multiplex: false,
            mux_path: String::new(),
        }
    }
}

fn default_http_proxy_listen() -> String {
    "127.0.0.1:8118".to_string()
}

/// TUN device configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    /// Enable TUN mode (full VPN)
    #[serde(default)]
    pub enabled: bool,

    /// Interface name (None = auto-assigned by OS)
    #[serde(default)]
    pub interface_name: Option<String>,

    /// IP address (CIDR notation) - DEPRECATED: Server now assigns IP dynamically
    /// This field is kept for backward compatibility but ignored in TUN mode
    #[serde(default)]
    pub ip_address: Option<String>,

    /// DNS servers
    #[serde(default = "default_dns_servers")]
    pub dns_servers: Vec<String>,

    /// Routes (CIDR notation)
    #[serde(default)]
    pub routes: Vec<String>,

    /// MTU
    #[serde(default = "default_mtu")]
    pub mtu: u16,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface_name: None, // Auto-assigned by OS
            ip_address: None,     // Server assigns IP dynamically
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            routes: vec!["0.0.0.0/0".to_string()],
            mtu: 1420,
        }
    }
}

fn default_dns_servers() -> Vec<String> {
    vec!["1.1.1.1".to_string()]
}

fn default_mtu() -> u16 {
    1420
}

/// Performance tuning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Number of worker threads
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,

    /// Receive buffer size
    #[serde(default = "default_recv_buffer_size")]
    pub recv_buffer_size: usize,

    /// Send buffer size
    #[serde(default = "default_send_buffer_size")]
    pub send_buffer_size: usize,

    /// Number of crypto worker threads (for parallel encryption/decryption)
    /// Higher values improve throughput under high concurrent load
    /// Each connection is assigned to a specific worker to maintain ordering
    #[serde(default = "default_crypto_worker_count")]
    pub crypto_worker_count: usize,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            worker_threads: 4,
            recv_buffer_size: 262144,
            send_buffer_size: 262144,
            crypto_worker_count: default_crypto_worker_count(),
        }
    }
}

fn default_worker_threads() -> usize {
    4
}

fn default_crypto_worker_count() -> usize {
    4
}

fn default_recv_buffer_size() -> usize {
    262144
}

fn default_send_buffer_size() -> usize {
    262144
}

/// Split tunnel configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SplitTunnelConfig {
    /// Enable split tunneling
    #[serde(default)]
    pub enabled: bool,

    /// Networks that should bypass VPN (CIDR format, one per line)
    #[serde(default, alias = "bypass_networks_file")]
    pub bypass_networks_file: Option<PathBuf>,

    /// Domains that should bypass VPN (one per line)
    #[serde(default, alias = "bypass_domains_file")]
    pub bypass_domains_file: Option<PathBuf>,

    /// Networks that must go through VPN (CIDR format, one per line)
    #[serde(default, alias = "tunnel_networks_file")]
    pub tunnel_networks_file: Option<PathBuf>,

    /// Domains that must go through VPN (one per line)
    #[serde(default, alias = "tunnel_domains_file")]
    pub tunnel_domains_file: Option<PathBuf>,

    /// Auto-reload interval in seconds (0 to disable)
    #[serde(default = "default_reload_interval", alias = "auto_reload_interval")]
    pub auto_reload_interval: u64,

    /// Use built-in IP ranges for bypass (country codes, e.g., ["CN", "HK"])
    /// Empty list means don't use any built-in ranges
    #[serde(
        default = "default_builtin_countries",
        alias = "builtin_bypass_countries"
    )]
    pub builtin_bypass_countries: Vec<String>,

    /// Enable built-in ad blocking
    #[serde(default, alias = "block_ads")]
    pub block_ads: bool,

    /// Custom ad block list file (one domain per line)
    #[serde(default, alias = "ad_block_file")]
    pub ad_block_file: Option<PathBuf>,

    /// Inline bypass networks (CIDR format)
    /// These are loaded in addition to bypass_networks_file
    /// Useful for mobile config where file paths aren't available
    #[serde(default, alias = "bypass_networks")]
    pub bypass_networks: Vec<String>,
}

impl Default for SplitTunnelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bypass_networks_file: None,
            bypass_domains_file: None,
            tunnel_networks_file: None,
            tunnel_domains_file: None,
            auto_reload_interval: 86400,                      // 24 hours
            builtin_bypass_countries: vec!["CN".to_string()], // Default to China
            block_ads: false,
            ad_block_file: None,
            bypass_networks: Vec::new(),
        }
    }
}

fn default_reload_interval() -> u64 {
    86400
}

fn default_builtin_countries() -> Vec<String> {
    vec!["CN".to_string()]
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Enable IPv6 support
    #[serde(default = "default_true")]
    pub ipv6_enabled: bool,

    /// Prefer IPv4 over IPv6 (when both available)
    #[serde(default = "default_true")]
    pub prefer_ipv4: bool,

    /// Enable DNS caching
    #[serde(default = "default_true")]
    pub dns_cache_enabled: bool,

    /// DNS cache TTL in seconds
    #[serde(default = "default_dns_cache_ttl")]
    pub dns_cache_ttl: u64,

    /// Maximum DNS cache entries
    #[serde(default = "default_dns_cache_size")]
    pub dns_cache_size: usize,

    /// Custom DNS servers (overrides system default)
    #[serde(default)]
    pub dns_servers: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            ipv6_enabled: true,
            prefer_ipv4: true,
            dns_cache_enabled: true,
            dns_cache_ttl: 14400, // 4 hours — client-side cache can be aggressive since A-records rarely change
            dns_cache_size: 1000,
            dns_servers: vec![],
        }
    }
}

fn default_dns_cache_ttl() -> u64 {
    14400 // 4 hours
}

fn default_dns_cache_size() -> usize {
    1000
}

/// Server identity verification configuration
///
/// This provides protection against compromised servers by verifying
/// the server's X3DH identity key fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerIdentityConfig {
    /// Server's Ed25519 identity key fingerprint (hex encoded)
    /// If set, the client will verify the server's prekey bundle matches this fingerprint
    #[serde(default)]
    pub fingerprint: Option<String>,

    /// Trust on first use mode
    /// If true, the client will accept any server identity on first connection
    /// and store it for future verification
    #[serde(default = "default_true")]
    pub trust_on_first_use: bool,

    /// Path to store known server identities
    #[serde(default = "default_known_hosts_path")]
    pub known_hosts_file: PathBuf,

    /// Strict mode - if true, connection fails on fingerprint mismatch
    /// If false, only a warning is logged
    #[serde(default = "default_true")]
    pub strict: bool,

    /// Strict TOFU mode - if true, reject unknown server identities on first use
    /// If false (default), accept unknown servers on first connection (standard TOFU)
    #[serde(default)]
    pub strict_mode: bool,
}

impl Default for ServerIdentityConfig {
    fn default() -> Self {
        Self {
            fingerprint: None,
            trust_on_first_use: true,
            known_hosts_file: default_known_hosts_path(),
            strict: true,
            strict_mode: false,
        }
    }
}

fn default_known_hosts_path() -> PathBuf {
    PathBuf::from("known_hosts.json")
}

/// DNS proxy configuration
///
/// When enabled, the client listens for UDP DNS queries on `listen_address` and
/// resolves them through the VPN server's encrypted `/dns` WebSocket endpoint.
/// Point your system DNS (or per-app resolver) at this address so DNS queries
/// travel through the tunnel instead of leaking to the local network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProxyConfig {
    /// Enable the local DNS proxy
    #[serde(default)]
    pub enabled: bool,

    /// UDP listen address (e.g. "127.0.0.1:5353")
    #[serde(default = "default_dns_proxy_listen")]
    pub listen_address: String,

    /// Public nameservers for bypass domain resolution (direct UDP).
    /// Defaults to AliDNS, CloudFlare, Google for global reliability.
    /// CN users may want to put local ISP DNS first for better latency.
    #[serde(default = "default_dns_proxy_nameservers")]
    pub nameservers: Vec<String>,
}

impl Default for DnsProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: default_dns_proxy_listen(),
            nameservers: default_dns_proxy_nameservers(),
        }
    }
}

fn default_dns_proxy_listen() -> String {
    "127.0.0.1:5353".to_string()
}

fn default_dns_proxy_nameservers() -> Vec<String> {
    vec![
        "223.5.5.5:53".to_string(),   // AliDNS (China — fastest for CN users)
        "1.1.1.1:53".to_string(),     // CloudFlare
        "8.8.8.8:53".to_string(),     // Google
    ]
}

fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .map(|d| d.join("rvpn"))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn default_tls_fingerprint() -> TlsFingerprint {
    TlsFingerprint::default()
}

/// Get the configured number of crypto workers
/// Falls back to default if no config is loaded
#[allow(dead_code)]
pub fn get_crypto_worker_count() -> usize {
    // Try to read from environment variable first (for testing)
    if let Ok(val) = std::env::var("RVPN_CRYPTO_WORKERS") {
        if let Ok(count) = val.parse::<usize>() {
            return count.max(1);
        }
    }

    // Return default
    default_crypto_worker_count()
}
