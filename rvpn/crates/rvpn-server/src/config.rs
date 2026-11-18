//! Server configuration

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Config wrapper for [server] section format
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConfigWrapper {
    #[serde(default)]
    server: ServerConfig,
}

/// Main server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Bind address
    #[serde(default = "default_bind_address")]
    pub bind_address: String,

    /// TLS certificate file
    #[serde(default = "default_tls_cert")]
    pub tls_cert_file: PathBuf,

    /// TLS private key file
    #[serde(default = "default_tls_key")]
    pub tls_key_file: PathBuf,

    /// Allow plaintext WebSocket only behind a trusted TLS-terminating proxy.
    #[serde(default)]
    pub allow_plaintext: bool,

    /// Identity key file
    #[serde(default = "default_identity_key")]
    pub identity_key_file: PathBuf,

    /// X3DH prekey rotation hours
    #[serde(default = "default_prekey_rotation")]
    pub prekey_rotation_hours: u32,

    /// Number of one-time prekeys
    #[serde(default = "default_otpk_count")]
    pub one_time_prekey_count: u32,

    /// Decoy website root
    #[serde(default)]
    pub decoy_root: Option<PathBuf>,

    /// WebSocket path
    #[serde(default = "default_ws_path")]
    pub websocket_path: String,

    /// HTTP port for ACME challenges and redirect (disabled by default)
    #[serde(default)]
    pub http_port: Option<u16>,

    /// Redirect HTTP to HTTPS
    #[serde(default = "default_redirect_http")]
    pub redirect_http_to_https: bool,

    /// Rate limiting
    #[serde(default)]
    pub rate_limit: RateLimitConfig,

    /// Network settings
    #[serde(default)]
    pub network: NetworkConfig,

    /// TUN interface settings
    #[serde(default)]
    pub tun: TunNetworkConfig,

    /// Prekey bundle file (if specified, server will use keys from bundle instead of generating new ones)
    #[serde(default)]
    pub prekey_bundle_file: Option<PathBuf>,

    /// Automatic TLS certificates via Let's Encrypt (ACME TLS-ALPN-01).
    /// When enabled, the server obtains and renews certs itself — no proxy needed.
    #[serde(default)]
    pub acme: AcmeConfig,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:443".to_string(),
            tls_cert_file: PathBuf::from("certs/cert.pem"),
            tls_key_file: PathBuf::from("certs/key.pem"),
            allow_plaintext: false,
            identity_key_file: PathBuf::from("server_identity.key"),
            prekey_rotation_hours: 168,
            one_time_prekey_count: 100,
            decoy_root: None,
            websocket_path: "/api/v1/ws".to_string(),
            http_port: None,
            redirect_http_to_https: true,
            rate_limit: RateLimitConfig::default(),
            network: NetworkConfig::default(),
            tun: TunNetworkConfig::default(),
            prekey_bundle_file: None,
            acme: AcmeConfig::default(),
        }
    }
}

/// Automatic TLS via Let's Encrypt.
///
/// When enabled, `rustls-acme` obtains certificates using the TLS-ALPN-01
/// challenge on the same `:443` listener the server already uses. No
/// separate `:80` port is needed and renewal runs in the background.
///
/// Prerequisites:
/// - Each domain in `domains` must resolve (A/AAAA) to this server.
/// - Inbound `:443` must be reachable from Let's Encrypt's validators.
/// - `cache_dir` must be writable — the ACME account key and issued certs
///   are persisted there so restarts don't hit rate limits.
///
/// Cannot be combined with a static `tls_cert_file` — startup refuses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeConfig {
    /// Enable automatic ACME certificate issuance.
    #[serde(default)]
    pub enabled: bool,

    /// Fully-qualified hostnames to obtain certificates for. Must be non-empty
    /// when `enabled = true`. First entry is the primary CN; the rest ride
    /// along as SANs.
    #[serde(default)]
    pub domains: Vec<String>,

    /// Contact URIs for the ACME account (typically `mailto:ops@example.com`).
    /// Let's Encrypt uses this for expiry warnings if a renewal ever stalls.
    #[serde(default)]
    pub contacts: Vec<String>,

    /// Directory to persist the ACME account key and issued certificates.
    /// Defaults to `"acme-cache"` next to the server binary.
    #[serde(default = "default_acme_cache_dir")]
    pub cache_dir: PathBuf,

    /// Use the Let's Encrypt staging directory instead of production.
    /// Safe for testing — issues untrusted certs but doesn't count against
    /// production rate limits.
    #[serde(default)]
    pub staging: bool,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            domains: Vec::new(),
            contacts: Vec::new(),
            cache_dir: default_acme_cache_dir(),
            staging: false,
        }
    }
}

fn default_acme_cache_dir() -> PathBuf {
    PathBuf::from("acme-cache")
}

impl ServerConfig {
    /// Load configuration from file
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        match ext {
            "toml" => {
                // Try parsing with [server] section first (documented format)
                // If that fails, try root level (direct format)
                if let Ok(wrapper) = toml::from_str::<ConfigWrapper>(&content) {
                    Ok(wrapper.server)
                } else {
                    // Fall back to direct parsing for root-level format
                    Ok(toml::from_str(&content)?)
                }
            }
            "json" => Ok(serde_json::from_str(&content)?),
            _ => anyhow::bail!("Unsupported config format: {}", ext),
        }
    }
}

fn default_bind_address() -> String {
    "0.0.0.0:443".to_string()
}

fn default_tls_cert() -> PathBuf {
    PathBuf::from("certs/cert.pem")
}

fn default_tls_key() -> PathBuf {
    PathBuf::from("certs/key.pem")
}

fn default_identity_key() -> PathBuf {
    PathBuf::from("server_identity.key")
}

fn default_prekey_rotation() -> u32 {
    168
}

fn default_otpk_count() -> u32 {
    100
}

fn default_ws_path() -> String {
    "/api/v1/ws".to_string()
}

fn default_redirect_http() -> bool {
    true
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Max concurrent connections per IP
    #[serde(default = "default_max_connections")]
    pub max_connections_per_ip: u32,

    /// Max handshake attempts per IP per minute
    #[serde(default = "default_max_handshakes")]
    pub max_handshakes_per_minute: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: 500,
            max_handshakes_per_minute: 2000,
        }
    }
}

fn default_max_connections() -> u32 {
    500
}

fn default_max_handshakes() -> u32 {
    2000
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Enable server-managed NAT; containment remains enabled when this is false.
    #[serde(default = "default_true")]
    pub nat_enabled: bool,

    /// Legacy compatibility field; allocation/filtering/NAT use tun.tun_ip instead.
    #[serde(default = "default_dhcp_range")]
    pub dhcp_range: String,

    /// DNS servers
    #[serde(default)]
    pub dns_servers: Vec<String>,

    /// Public addresses of this server that are not assigned to any local
    /// interface — typical for cloud VMs behind 1:1 NAT, where the interface
    /// carries only a private address. Client egress (raw TUN, TCP, UDP and
    /// DNS relays) to these addresses is denied so VPN clients cannot loop
    /// back into the server's own services through the external IP.
    #[serde(default)]
    pub public_addresses: Vec<std::net::IpAddr>,

    /// Permit client-to-client traffic within this server's own TUN pool
    /// (register C24). Default false: the strict containment introduced in
    /// v1.3.7 is preserved. When true, clients on the same server can reach
    /// each other's pool addresses — LAN games, file sharing, local services.
    /// The exemption is pool-specific; it never re-opens 10.0.0.0/8, and the
    /// server's own addresses stay denied. Applies to the raw TUN path
    /// (userspace filter, iptables FORWARD chain, pf anchor).
    #[serde(default)]
    pub allow_client_to_client: bool,

    /// Internal CIDRs TUN clients may reach in addition to public internet
    /// (e.g. ["192.168.1.0/24"] for a home LAN behind another router).
    /// Default empty. Entries are validated at startup and the server
    /// refuses to start on: a default route (0.0.0.0/0 or ::/0), loopback,
    /// link-local/metadata (169.254.0.0/16, fe80::/10), IPv6 ULA (fc00::/7,
    /// covering fd00::/8 and cloud metadata at fd00:ec2::254), or any range
    /// containing one of the server's own addresses. Host-address denial
    /// always wins over these exemptions, including addresses that appear
    /// after startup (refreshed every 60s).
    #[serde(default)]
    pub allowed_internal_ranges: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            nat_enabled: true,
            dhcp_range: "10.200.0.0/24".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
            public_addresses: Vec::new(),
            allow_client_to_client: false,
            allowed_internal_ranges: Vec::new(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_dhcp_range() -> String {
    "10.200.0.0/24".to_string()
}

/// TUN interface configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunNetworkConfig {
    /// Enable TUN interface (default: false for backward compatibility)
    #[serde(default)]
    pub enabled: bool,

    /// TUN interface IP address (CIDR notation)
    #[serde(default = "default_tun_ip")]
    pub tun_ip: String,

    /// TUN interface MTU
    #[serde(default = "default_tun_mtu")]
    pub mtu: u16,

    /// TUN interface name
    #[serde(default = "default_tun_name")]
    pub interface_name: String,

    /// DNS servers to advertise to clients via VirtualIp
    #[serde(default)]
    pub dns_servers: Vec<std::net::IpAddr>,

    /// Optional CAKE shaper bandwidth in kbit/s applied to the TUN interface
    /// (Linux only). Set this just below a known downstream bottleneck (e.g.
    /// a rate-limited transit link) so the queue forms in *our* fq/cake
    /// qdisc — with per-flow fairness — instead of in the bottleneck's own
    /// policer buffer. Absent = no shaper (kernel default qdisc).
    #[serde(default)]
    pub shaper_bandwidth_kbit: Option<u32>,
}

impl Default for TunNetworkConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default to preserve existing behavior
            tun_ip: "10.200.0.1/24".to_string(),
            mtu: 1420,
            interface_name: "tun0".to_string(),
            dns_servers: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))],
            shaper_bandwidth_kbit: None,
        }
    }
}

fn default_tun_ip() -> String {
    "10.200.0.1/24".to_string()
}

fn default_tun_mtu() -> u16 {
    1420
}

fn default_tun_name() -> String {
    "tun0".to_string()
}
