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
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0:443".to_string(),
            tls_cert_file: PathBuf::from("certs/cert.pem"),
            tls_key_file: PathBuf::from("certs/key.pem"),
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
        }
    }
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
    /// Enable NAT
    #[serde(default = "default_true")]
    pub nat_enabled: bool,

    /// DHCP range
    #[serde(default = "default_dhcp_range")]
    pub dhcp_range: String,

    /// DNS servers
    #[serde(default)]
    pub dns_servers: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            nat_enabled: true,
            dhcp_range: "10.200.0.0/24".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
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
}

impl Default for TunNetworkConfig {
    fn default() -> Self {
        Self {
            enabled: false, // Disabled by default to preserve existing behavior
            tun_ip: "10.200.0.1/24".to_string(),
            mtu: 1420,
            interface_name: "tun0".to_string(),
            dns_servers: vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))],
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
