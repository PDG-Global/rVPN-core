//! Client configuration

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[cfg(not(target_os = "android"))]
use rvpn_tls::TlsFingerprint;
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

    /// Stats dashboard configuration (localhost HTTP listener)
    #[serde(default)]
    pub dashboard: DashboardConfig,

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

    /// Additional named servers for multi-server routing (SOCKS5 mode only).
    /// The top-level `server_address` + `prekey_bundle` form the implicit
    /// `"default"` server; entries here add more. Each `[[server]]` block
    /// becomes a routing target keyed by `name`.
    #[serde(default, rename = "server")]
    pub extra_servers: Vec<ServerEntry>,

    /// Per-server routing rules. Keyed by server `name`. Domains match the
    /// SOCKS5 request hostname (exact host, `*.parent`, or bare parent).
    /// IPs match either a literal IPv4/IPv6 target or a CIDR.
    /// If no rule matches, traffic goes to the default server.
    #[serde(default)]
    pub routing: HashMap<String, RoutingRule>,
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
            dashboard: DashboardConfig::default(),
            tls_fingerprint: TlsFingerprint::default(),
            data_dir: default_data_dir(),
            extra_servers: Vec::new(),
            routing: HashMap::new(),
        }
    }
}

/// Additional server for multi-server routing.
///
/// The top-level `server_address` + `prekey_bundle` fields form the implicit
/// `"default"` server; every `[[server]]` block adds another routing target.
/// The client's `identity_key_file` is shared across all servers (SSH-model
/// — one client key, many hosts).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEntry {
    /// Symbolic name used in `[routing.<name>]` sections.
    /// Must be unique and cannot be `"default"`.
    pub name: String,

    /// WebSocket address (e.g. `wss://sg.example.com`).
    pub address: String,

    /// TLS SNI hostname (optional; defaults to the URL host).
    #[serde(default)]
    pub sni_hostname: Option<String>,

    /// Path to this server's X3DH prekey bundle JSON.
    pub prekey_bundle: PathBuf,

    /// Optional pinned identity fingerprint (`ik:1:...`).
    /// If unset, this server uses the top-level `[server_identity]` settings
    /// (TOFU by default).
    #[serde(default)]
    pub fingerprint: Option<String>,
}

/// Routing rules that steer specific hostnames or IPs to a named server.
/// The type lives in `rvpn-split-tunnel` so the mobile crate shares it;
/// re-exported here to keep the CLI config API unchanged.
pub use rvpn_split_tunnel::RoutingRule;

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

/// SOCKS5 tunnel mode.
///
/// - `Legacy`: each SOCKS5 flow opens its own WebSocket + X3DH handshake
///   (`stream_relay.rs`). Many short-lived connections, mirrors Brook.
/// - `Multiplex`: all flows share a single WebSocket (`socks5_tunnel.rs`).
/// - `Pooled`: a per-exit pool of multiplexed WebSocket tunnels
///   (`tunnel_pool.rs`); flows are striped least-loaded across the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Socks5Mode {
    /// Per-flow WebSocket connections (default).
    Legacy,
    /// Single shared multiplexed WebSocket.
    Multiplex,
    /// Per-exit pool of multiplexed WebSockets with least-loaded striping.
    Pooled,
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
    ///
    /// Deprecated compat alias for `mode`: `multiplex = true` maps to
    /// `mode = "multiplex"` unless `mode` is explicitly set (mode wins).
    #[serde(default)]
    pub multiplex: bool,

    /// Tunnel mode: "legacy" | "multiplex" | "pooled".
    /// When unset, derived from the `multiplex` compat flag (default "legacy").
    #[serde(default)]
    pub mode: Option<Socks5Mode>,

    /// WebSocket path for multiplexed connections.
    /// When empty (default), derived from server URL as `{server_path}/mux`.
    #[serde(default)]
    pub mux_path: String,

    /// Target number of live multiplexed tunnels per exit server (pooled mode).
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,

    /// Hard ceiling on live tunnels per exit under load (pooled mode).
    #[serde(default = "default_pool_max")]
    pub pool_max: usize,

    /// Soft cap on active flows per pooled tunnel. When all tunnels are at
    /// cap the pool grows toward `pool_max`; flows may briefly exceed the cap.
    #[serde(default = "default_max_flows_per_conn")]
    pub max_flows_per_conn: usize,

    /// Rotate (drain + replace) a pooled tunnel after this many seconds.
    /// Jittered ±`rotation_jitter` per tunnel at creation.
    #[serde(default = "default_rotate_after_secs")]
    pub rotate_after_secs: u64,

    /// Rotate a pooled tunnel after this many megabytes relayed (both
    /// directions). Jittered ±`rotation_jitter` per tunnel at creation.
    #[serde(default = "default_rotate_after_mb")]
    pub rotate_after_mb: u64,

    /// Rotation jitter fraction (0.0–0.5). A metronome rotation schedule is
    /// itself a traffic pattern, so thresholds are randomized per tunnel.
    #[serde(default = "default_rotation_jitter")]
    pub rotation_jitter: f64,
}

impl Socks5Config {
    /// Effective tunnel mode: explicit `mode` wins; otherwise the legacy
    /// `multiplex` bool maps to Multiplex/Legacy.
    pub fn effective_mode(&self) -> Socks5Mode {
        match (self.mode, self.multiplex) {
            (Some(m), _) => m,
            (None, true) => Socks5Mode::Multiplex,
            (None, false) => Socks5Mode::Legacy,
        }
    }

    /// Validate pooled-mode knobs. Returns a config error on inconsistent
    /// values rather than silently clamping.
    pub fn validate_pool(&self) -> anyhow::Result<()> {
        if self.pool_size == 0 {
            anyhow::bail!("socks5.pool_size must be at least 1");
        }
        if self.pool_max < self.pool_size {
            anyhow::bail!(
                "socks5.pool_max ({}) must be >= socks5.pool_size ({})",
                self.pool_max,
                self.pool_size
            );
        }
        if self.max_flows_per_conn == 0 {
            anyhow::bail!("socks5.max_flows_per_conn must be at least 1");
        }
        if self.rotate_after_secs < 60 {
            anyhow::bail!(
                "socks5.rotate_after_secs ({}) must be at least 60",
                self.rotate_after_secs
            );
        }
        if self.rotate_after_mb < 16 {
            anyhow::bail!(
                "socks5.rotate_after_mb ({}) must be at least 16",
                self.rotate_after_mb
            );
        }
        if !(0.0..=0.5).contains(&self.rotation_jitter) {
            anyhow::bail!(
                "socks5.rotation_jitter ({}) must be between 0.0 and 0.5",
                self.rotation_jitter
            );
        }
        Ok(())
    }
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
            mode: None,
            mux_path: String::new(),
            pool_size: default_pool_size(),
            pool_max: default_pool_max(),
            max_flows_per_conn: default_max_flows_per_conn(),
            rotate_after_secs: default_rotate_after_secs(),
            rotate_after_mb: default_rotate_after_mb(),
            rotation_jitter: default_rotation_jitter(),
        }
    }
}

fn default_pool_size() -> usize {
    4
}

fn default_pool_max() -> usize {
    8
}

fn default_max_flows_per_conn() -> usize {
    64
}

fn default_rotate_after_secs() -> u64 {
    600
}

fn default_rotate_after_mb() -> u64 {
    256
}

fn default_rotation_jitter() -> f64 {
    0.2
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

/// Stats dashboard configuration
///
/// When enabled, the client serves a self-contained MRTG/RRD-style HTML+SVG
/// stats page (and a JSON API at `/api/stats.json`) from a small embedded
/// HTTP listener. There is no authentication; access is restricted by client
/// IP against `allow_cidrs` (localhost only by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// Enable the stats dashboard HTTP listener
    #[serde(default)]
    pub enabled: bool,

    /// Listen address for the dashboard (e.g. "127.0.0.1:9800")
    #[serde(default = "default_dashboard_listen")]
    pub listen_address: String,

    /// CIDRs allowed to view the dashboard; others get 403. Defaults to
    /// localhost only. To share on a LAN, bind `listen_address` to the LAN
    /// interface (or 0.0.0.0) and add e.g. "192.168.0.0/16" here.
    #[serde(default = "default_dashboard_allow_cidrs")]
    pub allow_cidrs: Vec<String>,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: default_dashboard_listen(),
            allow_cidrs: default_dashboard_allow_cidrs(),
        }
    }
}

fn default_dashboard_listen() -> String {
    "127.0.0.1:9800".to_string()
}

fn default_dashboard_allow_cidrs() -> Vec<String> {
    vec!["127.0.0.0/8".to_string(), "::1/128".to_string()]
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
pub use rvpn_split_tunnel::SplitTunnelConfig;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_server_toml_round_trips() {
        let raw = r#"
server_address    = "wss://hk.example.com"
identity_key_file = "identity.key"
prekey_bundle     = "hk.bundle.json"

[[server]]
name          = "sg"
address       = "wss://sg.example.com"
prekey_bundle = "sg.bundle.json"

[routing.sg]
domains = ["google.com", "*.google.com"]
ips     = ["8.8.8.8/32", "1.1.1.1"]
"#;

        let cfg: ClientConfig = toml::from_str(raw).expect("parse multi-server config");
        assert_eq!(cfg.server_address, "wss://hk.example.com");
        assert_eq!(cfg.extra_servers.len(), 1);
        assert_eq!(cfg.extra_servers[0].name, "sg");
        assert_eq!(
            cfg.extra_servers[0].address,
            "wss://sg.example.com"
        );

        let sg = cfg.routing.get("sg").expect("routing.sg block present");
        assert_eq!(sg.domains, vec!["google.com".to_string(), "*.google.com".to_string()]);
        assert_eq!(sg.ips, vec!["8.8.8.8/32".to_string(), "1.1.1.1".to_string()]);
    }

    #[test]
    fn single_server_toml_still_parses_without_new_sections() {
        let raw = r#"
server_address    = "wss://hk.example.com"
identity_key_file = "identity.key"
prekey_bundle     = "hk.bundle.json"
"#;
        let cfg: ClientConfig = toml::from_str(raw).expect("parse legacy config");
        assert!(cfg.extra_servers.is_empty());
        assert!(cfg.routing.is_empty());
    }

    #[test]
    fn dashboard_config_toml_round_trips() {
        // Explicit section
        let raw = r#"
server_address = "wss://hk.example.com"

[dashboard]
enabled = true
listen_address = "127.0.0.1:9801"
"#;
        let cfg: ClientConfig = toml::from_str(raw).expect("parse dashboard config");
        assert!(cfg.dashboard.enabled);
        assert_eq!(cfg.dashboard.listen_address, "127.0.0.1:9801");

        // Serialize back out and re-parse
        let serialized = toml::to_string(&cfg).expect("serialize");
        let cfg2: ClientConfig = toml::from_str(&serialized).expect("re-parse");
        assert!(cfg2.dashboard.enabled);
        assert_eq!(cfg2.dashboard.listen_address, "127.0.0.1:9801");

        // Absent section: defaults to disabled on 127.0.0.1:9800
        let cfg3: ClientConfig = toml::from_str("server_address = \"wss://hk.example.com\"")
            .expect("parse without dashboard section");
        assert!(!cfg3.dashboard.enabled);
        assert_eq!(cfg3.dashboard.listen_address, "127.0.0.1:9800");
        assert_eq!(
            cfg3.dashboard.listen_address,
            DashboardConfig::default().listen_address
        );
    }

    #[test]
    fn socks5_mode_defaults_to_legacy() {
        let cfg = Socks5Config::default();
        assert_eq!(cfg.effective_mode(), Socks5Mode::Legacy);
        assert_eq!(cfg.pool_size, 4);
        assert_eq!(cfg.pool_max, 8);
        assert_eq!(cfg.max_flows_per_conn, 64);
        assert_eq!(cfg.rotate_after_secs, 600);
        assert_eq!(cfg.rotate_after_mb, 256);
        assert!((cfg.rotation_jitter - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn socks5_multiplex_bool_is_compat_alias() {
        let cfg: Socks5Config = toml::from_str("multiplex = true").expect("parse");
        assert_eq!(cfg.effective_mode(), Socks5Mode::Multiplex);
    }

    #[test]
    fn socks5_explicit_mode_wins_over_multiplex_bool() {
        let cfg: Socks5Config =
            toml::from_str("multiplex = true\nmode = \"pooled\"").expect("parse");
        assert_eq!(cfg.effective_mode(), Socks5Mode::Pooled);

        let cfg: Socks5Config =
            toml::from_str("multiplex = true\nmode = \"legacy\"").expect("parse");
        assert_eq!(cfg.effective_mode(), Socks5Mode::Legacy);
    }

    #[test]
    fn socks5_mode_parses_all_variants() {
        for (raw, expected) in [
            ("legacy", Socks5Mode::Legacy),
            ("multiplex", Socks5Mode::Multiplex),
            ("pooled", Socks5Mode::Pooled),
        ] {
            let cfg: Socks5Config =
                toml::from_str(&format!("mode = \"{}\"", raw)).expect("parse mode");
            assert_eq!(cfg.effective_mode(), expected);
        }
    }

    #[test]
    fn socks5_mode_rejects_unknown_value() {
        let result = toml::from_str::<Socks5Config>("mode = \"banana\"");
        let err = result.expect_err("unknown mode must be rejected");
        assert!(
            err.to_string().contains("unknown variant"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn socks5_pool_validation() {
        let mut cfg = Socks5Config::default();
        assert!(cfg.validate_pool().is_ok());

        cfg.pool_size = 0;
        assert!(cfg.validate_pool().is_err());
        cfg.pool_size = 4;

        cfg.pool_max = 2;
        assert!(cfg.validate_pool().is_err());
        cfg.pool_max = 8;

        cfg.max_flows_per_conn = 0;
        assert!(cfg.validate_pool().is_err());
        cfg.max_flows_per_conn = 64;
    }

    #[test]
    fn socks5_rotation_validation() {
        let mut cfg = Socks5Config::default();
        assert!(cfg.validate_pool().is_ok());

        cfg.rotate_after_secs = 59;
        assert!(cfg.validate_pool().is_err());
        cfg.rotate_after_secs = 60;
        assert!(cfg.validate_pool().is_ok());

        cfg.rotate_after_mb = 15;
        assert!(cfg.validate_pool().is_err());
        cfg.rotate_after_mb = 16;
        assert!(cfg.validate_pool().is_ok());

        cfg.rotation_jitter = 0.51;
        assert!(cfg.validate_pool().is_err());
        cfg.rotation_jitter = -0.1;
        assert!(cfg.validate_pool().is_err());
        cfg.rotation_jitter = 0.0;
        assert!(cfg.validate_pool().is_ok());
        cfg.rotation_jitter = 0.5;
        assert!(cfg.validate_pool().is_ok());
    }
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
