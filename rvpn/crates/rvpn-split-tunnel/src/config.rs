//! Split tunnel configuration

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

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

    /// Path to a JSON file mapping country codes to CIDR arrays.
    /// Format: {"CN": ["1.0.1.0/24", ...], "HK": [...]}
    /// Used instead of compiled-in builtin_ips when the builtin-ips feature is disabled.
    #[serde(default, alias = "country_ips_file")]
    pub country_ips_file: Option<PathBuf>,
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
            country_ips_file: None,
        }
    }
}

fn default_reload_interval() -> u64 {
    86400
}

fn default_builtin_countries() -> Vec<String> {
    vec!["CN".to_string()]
}
