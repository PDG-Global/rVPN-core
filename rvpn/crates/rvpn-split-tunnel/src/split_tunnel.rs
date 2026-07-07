//! Split tunneling for VPN traffic routing (Client-side)
//!
//! This module provides client-side functionality to route traffic either through 
//! the VPN tunnel or directly (bypass), based on IP ranges and domain lists.
//!
//! Priority order (highest to lowest):
//! 1. tunnel_domains - Force through VPN
//! 2. bypass_domains - Route directly
//! 3. tunnel_networks - Force through VPN
//! 4. bypass_networks - Route directly
//!
//! If no match is found, traffic goes through the VPN tunnel by default.
//!
//! ## Data Sources
//!
//! Built-in IP ranges are sourced from APNIC (Asia Pacific Network Information Centre)
//! delegations data: https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest
//!
//! Supported countries: CN, HK, SG, JP, KR, TW (and more via configuration)

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::config::SplitTunnelConfig;
use crate::dns_cache::DnsResolver;

// Built-in IP ranges (feature-gated, ~484KB binary size)
#[cfg(feature = "builtin-ips")]
use crate::builtin_ips::get_country_ips;
#[cfg(feature = "builtin-ips")]
#[allow(unused_imports)]
use crate::builtin_ips::supported_countries;

// Built-in domain lists (feature-gated)
#[cfg(feature = "builtin-domains")]
use crate::builtin_domains::matches_china_domain;
#[cfg(feature = "builtin-domains")]
#[allow(unused_imports)]
use crate::builtin_domains::{matches_ad_domain, is_china_domain, is_ad_domain, matches_force_tunnel_domain};
#[cfg(feature = "builtin-domains")]
#[allow(unused_imports)]
use crate::builtin_domains::get_country_domains;

// Stub implementations when features are disabled
#[cfg(not(feature = "builtin-ips"))]
fn get_country_ips(_country_code: &str) -> Option<&'static [&'static str]> {
    None
}

#[cfg(not(feature = "builtin-domains"))]
#[allow(dead_code)]
fn matches_china_domain(_domain: &str) -> bool { false }
#[cfg(not(feature = "builtin-domains"))]
#[allow(dead_code)]
fn matches_ad_domain(_domain: &str) -> bool { false }
#[cfg(not(feature = "builtin-domains"))]
#[allow(dead_code)]
fn matches_force_tunnel_domain(_domain: &str) -> bool { false }
#[cfg(not(feature = "builtin-domains"))]
#[allow(dead_code)]
fn get_country_domains(_country_code: &str) -> Option<&'static [&'static str]> { None }

/// Routing decision for a connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoutingDecision {
    /// Route through VPN tunnel
    Tunnel,
    /// Bypass VPN, route directly
    Bypass,
    /// Block the connection (for ad blocking)
    Block,
}

/// Internal data structure for split tunnel rules
struct SplitTunnelData {
    /// Networks that should bypass VPN
    bypass_networks: IpNetworkTable<bool>,
    /// Domains that should bypass VPN
    bypass_domains: HashSet<String>,
    /// Networks that must go through VPN
    tunnel_networks: IpNetworkTable<bool>,
    /// Domains that must go through VPN
    tunnel_domains: HashSet<String>,
    /// Domains to block (ads, tracking, malware)
    block_domains: HashSet<String>,
    /// Last reload time
    last_reload: Instant,
}

impl std::fmt::Debug for SplitTunnelData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SplitTunnelData")
            .field("bypass_networks_count", &self.bypass_networks.iter().count())
            .field("bypass_domains_count", &self.bypass_domains.len())
            .field("tunnel_networks_count", &self.tunnel_networks.iter().count())
            .field("tunnel_domains_count", &self.tunnel_domains.len())
            .field("block_domains_count", &self.block_domains.len())
            .field("last_reload", &self.last_reload)
            .finish()
    }
}

impl Clone for SplitTunnelData {
    fn clone(&self) -> Self {
        // Create new empty tables and re-insert all networks
        let mut bypass_networks = IpNetworkTable::new();
        for (network, _) in self.bypass_networks.iter() {
            bypass_networks.insert(network, true);
        }
        
        let mut tunnel_networks = IpNetworkTable::new();
        for (network, _) in self.tunnel_networks.iter() {
            tunnel_networks.insert(network, true);
        }
        
        Self {
            bypass_networks,
            bypass_domains: self.bypass_domains.clone(),
            tunnel_networks,
            tunnel_domains: self.tunnel_domains.clone(),
            block_domains: self.block_domains.clone(),
            last_reload: self.last_reload,
        }
    }
}

impl Default for SplitTunnelData {
    fn default() -> Self {
        Self {
            bypass_networks: IpNetworkTable::new(),
            bypass_domains: HashSet::new(),
            tunnel_networks: IpNetworkTable::new(),
            tunnel_domains: HashSet::new(),
            block_domains: HashSet::new(),
            last_reload: Instant::now(),
        }
    }
}

/// Split tunnel manager with hot-reload support
#[derive(Debug)]
pub struct SplitTunnel {
    /// Configuration
    config: SplitTunnelConfig,
    /// Internal data (protected by RwLock for thread-safe hot-reload)
    data: Arc<RwLock<SplitTunnelData>>,
    /// DNS resolver with caching
    dns_resolver: Arc<DnsResolver>,
}

impl SplitTunnel {
    /// Create a new split tunnel manager from configuration
    pub async fn new(config: SplitTunnelConfig, dns_resolver: Arc<DnsResolver>) -> Result<Self> {
        let data = if config.enabled {
            Self::load_data(&config).await?
        } else {
            SplitTunnelData::default()
        };

        let split_tunnel = Self {
            config,
            data: Arc::new(RwLock::new(data)),
            dns_resolver,
        };

        // Start auto-reload task if enabled
        if split_tunnel.config.enabled && split_tunnel.config.auto_reload_interval > 0 {
            let data_clone = Arc::clone(&split_tunnel.data);
            let config_clone = split_tunnel.config.clone();
            let interval = Duration::from_secs(split_tunnel.config.auto_reload_interval);

            tokio::spawn(async move {
                auto_reload_task(data_clone, config_clone, interval).await;
            });
        }

        Ok(split_tunnel)
    }

    /// Create a disabled split tunnel manager (no routing rules)
    #[allow(dead_code)]
    pub fn disabled() -> Self {
        Self {
            config: SplitTunnelConfig::default(),
            data: Arc::new(RwLock::new(SplitTunnelData::default())),
            dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
        }
    }

    /// Check if split tunneling is enabled
    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Access the shared DNS resolver (for caching)
    #[allow(dead_code)]
    pub fn dns_resolver(&self) -> Arc<DnsResolver> {
        Arc::clone(&self.dns_resolver)
    }

    /// Make a routing decision for a host and its resolved IPs
    ///
    /// Priority order:
    /// 1. tunnel_domains - Force through VPN
    /// 2. bypass_domains - Route directly
    /// 3. force_tunnel_domains (built-in) - Always VPN (overrides IP bypass)
    /// 4. tunnel_networks - Force through VPN
    /// 5. bypass_networks - Route directly
    ///
    /// If no match, defaults to Tunnel
    #[allow(dead_code)]
    pub async fn decide(&self, host: &str, ips: &[IpAddr]) -> RoutingDecision {
        if !self.config.enabled {
            return RoutingDecision::Tunnel;
        }

        let data = self.data.read().await;

        // Check tunnel domains first (highest priority)
        if Self::matches_domain(host, &data.tunnel_domains) {
            debug!("Host {} matches tunnel domain list", host);
            return RoutingDecision::Tunnel;
        }

        // Check bypass domains
        if Self::matches_domain(host, &data.bypass_domains) {
            debug!("Host {} matches bypass domain list", host);
            return RoutingDecision::Bypass;
        }

        // Check built-in force tunnel domains (Google, Facebook, etc.)
        // These override IP-based bypass decisions
        if matches_force_tunnel_domain(host) {
            debug!("Host {} matches force tunnel domain list", host);
            return RoutingDecision::Tunnel;
        }

        // Check tunnel networks
        for ip in ips {
            if data.tunnel_networks.longest_match(*ip).is_some() {
                debug!("IP {} matches tunnel network list", ip);
                return RoutingDecision::Tunnel;
            }
        }

        // Check bypass networks
        for ip in ips {
            if data.bypass_networks.longest_match(*ip).is_some() {
                debug!("IP {} matches bypass network list", ip);
                return RoutingDecision::Bypass;
            }
        }

        // Default to tunnel if no match
        RoutingDecision::Tunnel
    }

    /// Make a routing decision for a host without resolved IPs
    /// This is useful when only the hostname is known
    pub async fn decide_by_host(&self, host: &str) -> RoutingDecision {
        if !self.config.enabled {
            return RoutingDecision::Tunnel;
        }

        let data = self.data.read().await;

        // Check ad/tracker domains first (highest priority)
        if self.config.block_ads
            && (Self::matches_domain(host, &data.block_domains) || matches_ad_domain(host))
        {
            debug!("Host {} matches ad/tracker domain list - blocking", host);
            return RoutingDecision::Block;
        }

        // Check tunnel domains first (highest priority)
        if Self::matches_domain(host, &data.tunnel_domains) {
            debug!("Host {} matches tunnel domain list", host);
            return RoutingDecision::Tunnel;
        }

        // Check bypass domains from file
        if Self::matches_domain(host, &data.bypass_domains) {
            debug!("Host {} matches bypass domain list", host);
            return RoutingDecision::Bypass;
        }

        // Check built-in force tunnel domains (Google, Facebook, etc.)
        // These override China domain bypass
        if matches_force_tunnel_domain(host) {
            debug!("Host {} matches force tunnel domain list", host);
            return RoutingDecision::Tunnel;
        }

        // Check built-in China domains if CN is in bypass countries
        // SECURITY: Validate resolved IPs are in China before bypassing to prevent DNS rebinding
        if self.config.builtin_bypass_countries.contains(&"CN".to_string())
            && matches_china_domain(host)
        {
            debug!("Host {} matches built-in China domain list, validating IPs", host);
            if let Some(ip_addrs) = self.resolve_host_to_ips(host).await {
                if self.ips_match_country(&ip_addrs, "CN") {
                    debug!("Host {} resolved IPs are in China, bypassing", host);
                    return RoutingDecision::Bypass;
                }
                debug!("Host {} resolved IPs not in China, routing through tunnel", host);
                return RoutingDecision::Tunnel;
            }
            // DNS resolution failed, don't bypass - route through tunnel instead
            debug!("Host {} DNS resolution failed, routing through tunnel", host);
            return RoutingDecision::Tunnel;
        }

        // Default to tunnel if no match
        RoutingDecision::Tunnel
    }

    /// Check if a domain matches any pattern in the set
    /// Supports parent domain matching (e.g., "google.com" matches "www.google.com")
    fn matches_domain(host: &str, domains: &HashSet<String>) -> bool {
        // Normalize host to lowercase for case-insensitive matching
        let host = host.to_lowercase();
        if domains.contains(&host) {
            return true;
        }

        // Check parent domains
        let parts: Vec<&str> = host.split('.').collect();
        for i in 1..parts.len() {
            let parent = parts[i..].join(".");
            if domains.contains(&parent) {
                return true;
            }
        }

        false
    }

    /// Resolve a hostname to IP addresses (uses cached DNS resolver)
    pub async fn resolve_host_to_ips(&self, host: &str) -> Option<Vec<IpAddr>> {
        let addrs: Vec<std::net::SocketAddr> = match self.dns_resolver.resolve(host, 0).await {
            Ok(addrs) => addrs,
            Err(e) => {
                debug!("Failed to resolve {}: {}", host, e);
                return None;
            }
        };
        Some(addrs.into_iter().map(|a| a.ip()).collect())
    }

    /// Check if any IP in the list belongs to the specified country CIDR ranges
    fn ips_match_country(&self, ips: &[IpAddr], country: &str) -> bool {
        if let Some(country_cidrs) = get_country_ips(country) {
            for ip in ips {
                for cidr in country_cidrs {
                    // Parse CIDR string like "1.0.1.0/24"
                    if let Ok(network) = cidr.parse::<IpNetwork>() {
                        if network.contains(*ip) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Make a routing decision for a single IP address
    /// This is used by the SOCKS5 server when the target is already an IP address
    /// 
    /// Priority:
    /// 1. tunnel_networks - Force through VPN
    /// 2. bypass_networks - Route directly
    /// 
    /// If no match, defaults to Tunnel
    #[allow(dead_code)]
    pub async fn decide_by_ip(&self, ip: IpAddr) -> RoutingDecision {
        if !self.config.enabled {
            return RoutingDecision::Tunnel;
        }

        let data = self.data.read().await;

        // Check tunnel networks first (higher priority)
        if data.tunnel_networks.longest_match(ip).is_some() {
            debug!("IP {} matches tunnel network list", ip);
            return RoutingDecision::Tunnel;
        }

        // Check bypass networks
        if data.bypass_networks.longest_match(ip).is_some() {
            debug!("IP {} matches bypass network list", ip);
            return RoutingDecision::Bypass;
        }

        // Default to tunnel if no match
        RoutingDecision::Tunnel
    }

    /// Manually trigger a reload of the configuration files
    #[allow(dead_code)]
    pub async fn reload(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        info!("Reloading split tunnel configuration...");
        let new_data = Self::load_data(&self.config).await?;

        let mut data = self.data.write().await;
        *data = new_data;
        drop(data);

        info!("Split tunnel configuration reloaded successfully");
        Ok(())
    }

    /// Get statistics about the loaded rules
    #[allow(dead_code)]
    pub async fn get_stats(&self) -> SplitTunnelStats {
        let data = self.data.read().await;
        SplitTunnelStats {
            bypass_networks_count: data.bypass_networks.iter().count(),
            bypass_domains_count: data.bypass_domains.len(),
            tunnel_networks_count: data.tunnel_networks.iter().count(),
            tunnel_domains_count: data.tunnel_domains.len(),
            last_reload: data.last_reload,
        }
    }

    /// Load data from configuration files and built-in sources
    async fn load_data(config: &SplitTunnelConfig) -> Result<SplitTunnelData> {
        let mut data = SplitTunnelData {
            last_reload: Instant::now(),
            ..Default::default()
        };

        // Load built-in private networks (RFC 1918) as default bypass networks
        // These are always loaded for security and to enable local network access
        let default_bypass_networks = [
            // IPv4 private networks
            "192.168.0.0/16",    // Private network (home routers)
            "10.0.0.0/8",        // Private network (large networks)
            "172.16.0.0/12",     // Private network (medium networks)
            "127.0.0.0/8",       // Loopback
            "169.254.0.0/16",    // Link-local (APIPA)
            "224.0.0.0/4",       // Multicast
            "240.0.0.0/4",       // Reserved for future use
            "100.64.0.0/10",     // Carrier-grade NAT (Shared address space)
            "192.0.0.0/24",      // IETF Protocol Assignments
            "192.0.2.0/24",      // TEST-NET-1 (documentation)
            "198.51.100.0/24",   // TEST-NET-2 (documentation)
            "203.0.113.0/24",    // TEST-NET-3 (documentation)
            // IPv6 private networks
            "::1/128",           // IPv6 loopback
            "fc00::/7",          // IPv6 unique local addresses (ULA)
            "fe80::/10",         // IPv6 link-local
            "ff00::/8",          // IPv6 multicast
        ];

        let mut loaded = 0;
        let mut failed = 0;
        for cidr in default_bypass_networks {
            match cidr.parse::<IpNetwork>() {
                Ok(network) => {
                    data.bypass_networks.insert(network, true);
                    loaded += 1;
                }
                Err(e) => {
                    debug!("Failed to parse default bypass network {}: {}", cidr, e);
                    failed += 1;
                }
            }
        }
        info!("Loaded {} default bypass networks ({} failed)", loaded, failed);

        // Load inline bypass networks from config (overrides defaults)
        for cidr in &config.bypass_networks {
            match cidr.parse::<IpNetwork>() {
                Ok(network) => {
                    data.bypass_networks.insert(network, true);
                    debug!("Loaded inline bypass network: {}", cidr);
                }
                Err(e) => {
                    warn!("Failed to parse inline bypass network {}: {}", cidr, e);
                }
            }
        }

        // Load IP ranges for configured countries.
        // Priority: country_ips_file (dynamic) > builtin_ips (compiled-in)
        if let Some(ref path) = config.country_ips_file {
            match Self::load_country_ips_file(path, &config.builtin_bypass_countries).await {
                Ok(cidrs) => {
                    let count = cidrs.len();
                    for cidr in cidrs {
                        data.bypass_networks.insert(cidr, true);
                    }
                    info!("Loaded {} bypass IPs from country_ips_file {:?}", count, path);
                }
                Err(e) => {
                    warn!("Failed to load country IPs from {:?}: {}", path, e);
                }
            }
        } else {
            // Fall back to compiled-in builtin IPs
            for country_code in &config.builtin_bypass_countries {
                if let Some(ip_ranges) = get_country_ips(country_code) {
                    let mut loaded = 0;
                    let mut failed = 0;
                    for cidr in ip_ranges {
                        match cidr.parse::<IpNetwork>() {
                            Ok(network) => {
                                data.bypass_networks.insert(network, true);
                                loaded += 1;
                            }
                            Err(e) => {
                                debug!("Failed to parse built-in IP {} for {}: {}", cidr, country_code, e);
                                failed += 1;
                            }
                        }
                    }
                    info!("Loaded {} built-in {} IP ranges ({} failed)", loaded, country_code, failed);
                } else {
                    warn!("Unknown country code for built-in IPs: {}", country_code);
                }
            }
        }

        // Load bypass networks from file
        if let Some(ref path) = config.bypass_networks_file {
            match Self::load_networks(path).await {
                Ok(networks) => {
                    let count = networks.len();
                    for network in networks {
                        data.bypass_networks.insert(network, true);
                    }
                    info!("Loaded {} bypass networks from {:?}", count, path);
                }
                Err(e) => {
                    warn!("Failed to load bypass networks from {:?}: {}", path, e);
                }
            }
        }

        // Load bypass domains
        if let Some(ref path) = config.bypass_domains_file {
            match Self::load_domains(path).await {
                Ok(domains) => {
                    let count = domains.len();
                    data.bypass_domains.extend(domains);
                    info!("Loaded {} bypass domains from {:?}", count, path);
                }
                Err(e) => {
                    warn!("Failed to load bypass domains from {:?}: {}", path, e);
                }
            }
        }

        // Load tunnel networks
        if let Some(ref path) = config.tunnel_networks_file {
            match Self::load_networks(path).await {
                Ok(networks) => {
                    let count = networks.len();
                    for network in networks {
                        data.tunnel_networks.insert(network, true);
                    }
                    info!("Loaded {} tunnel networks from {:?}", count, path);
                }
                Err(e) => {
                    warn!("Failed to load tunnel networks from {:?}: {}", path, e);
                }
            }
        }

        // Load tunnel domains
        if let Some(ref path) = config.tunnel_domains_file {
            match Self::load_domains(path).await {
                Ok(domains) => {
                    let count = domains.len();
                    data.tunnel_domains.extend(domains);
                    info!("Loaded {} tunnel domains from {:?}", count, path);
                }
                Err(e) => {
                    warn!("Failed to load tunnel domains from {:?}: {}", path, e);
                }
            }
        }

        // Load ad-block domains
        if let Some(ref path) = config.ad_block_file {
            match Self::load_domains(path).await {
                Ok(domains) => {
                    let count = domains.len();
                    data.block_domains.extend(domains);
                    info!("Loaded {} ad-block domains from {:?}", count, path);
                }
                Err(e) => {
                    warn!("Failed to load ad-block domains from {:?}: {}", path, e);
                }
            }
        }

        // Log summary
        let bypass_nets: usize = data.bypass_networks.iter().count();
        let tunnel_nets: usize = data.tunnel_networks.iter().count();
        #[cfg(feature = "builtin-domains")]
        let builtin_domain_count = if config.builtin_bypass_countries.contains(&"CN".to_string()) {
            crate::builtin_domains::CHINA_DOMAINS.len()
        } else {
            0
        };
        #[cfg(not(feature = "builtin-domains"))]
        let builtin_domain_count = 0;
        info!(
            "Split tunnel rules loaded: {} bypass networks, {} bypass domains ({} built-in CN), {} tunnel networks, {} tunnel domains, {} block domains",
            bypass_nets,
            data.bypass_domains.len(),
            builtin_domain_count,
            tunnel_nets,
            data.tunnel_domains.len(),
            data.block_domains.len()
        );

        Ok(data)
    }

    /// Load country IPs from a JSON file.
    /// Format: {"CN": ["1.0.1.0/24", ...], "HK": [...]}
    /// Only loads CIDRs for the specified country codes.
    async fn load_country_ips_file(path: &Path, countries: &[String]) -> Result<Vec<IpNetwork>> {
        let content = tokio::fs::read_to_string(path).await?;
        let map: std::collections::HashMap<String, Vec<String>> = serde_json::from_str(&content)
            .unwrap_or_else(|_| std::collections::HashMap::new());

        let mut networks = Vec::new();
        for country_code in countries {
            if let Some(cidrs) = map.get(country_code) {
                for cidr in cidrs {
                    match cidr.parse::<IpNetwork>() {
                        Ok(n) => networks.push(n),
                        Err(e) => debug!("Invalid CIDR {} in {}: {}", cidr, country_code, e),
                    }
                }
            }
        }
        Ok(networks)
    }

    /// Load networks from a file (one CIDR per line)
    async fn load_networks(path: &Path) -> Result<Vec<IpNetwork>> {
        let content = tokio::fs::read_to_string(path).await?;
        let mut networks = Vec::new();

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Parse CIDR
            match line.parse::<IpNetwork>() {
                Ok(network) => networks.push(network),
                Err(e) => {
                    warn!("Invalid CIDR '{}': {}", line, e);
                }
            }
        }

        Ok(networks)
    }

    /// Load domains from a file (one domain per line)
    async fn load_domains(path: &Path) -> Result<HashSet<String>> {
        let content = tokio::fs::read_to_string(path).await?;
        let mut domains = HashSet::new();

        for line in content.lines() {
            let line = line.trim().to_lowercase();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            // Remove any trailing dots (FQDN format)
            let domain = line.trim_end_matches('.').to_string();

            if !domain.is_empty() {
                domains.insert(domain);
            }
        }

        Ok(domains)
    }

    /// Load from files directly (for initial loading without async runtime)
    #[allow(dead_code)]
    pub fn load_from_files_sync(config: &SplitTunnelConfig) -> Result<Self> {
        let rt = tokio::runtime::Handle::try_current();
        
        let data = match rt {
            Ok(handle) => {
                // We're in an async context, use block_in_place
                tokio::task::block_in_place(|| {
                    handle.block_on(async { Self::load_data(config).await })
                })?
            }
            Err(_) => {
                // No runtime, create a temporary one
                let rt = tokio::runtime::Runtime::new()?;
                rt.block_on(async { Self::load_data(config).await })?
            }
        };

        Ok(Self {
            config: config.clone(),
            data: Arc::new(RwLock::new(data)),
            dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
        })
    }
}

/// Statistics about split tunnel configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct SplitTunnelStats {
    pub bypass_networks_count: usize,
    pub bypass_domains_count: usize,
    #[allow(dead_code)]
    pub tunnel_networks_count: usize,
    #[allow(dead_code)]
    pub tunnel_domains_count: usize,
    #[allow(dead_code)]
    pub last_reload: Instant,
}

/// Background task for auto-reloading configuration
async fn auto_reload_task(
    data: Arc<RwLock<SplitTunnelData>>,
    config: SplitTunnelConfig,
    interval: Duration,
) {
    let mut ticker = tokio::time::interval(interval);

    loop {
        ticker.tick().await;

        debug!("Auto-reloading split tunnel configuration...");
        
        match SplitTunnel::load_data(&config).await {
            Ok(new_data) => {
                let mut data_guard = data.write().await;
                *data_guard = new_data;
                drop(data_guard);
                debug!("Split tunnel configuration auto-reloaded successfully");
            }
            Err(e) => {
                warn!("Failed to auto-reload split tunnel configuration: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_domain_matching() {
        let mut domains = HashSet::new();
        domains.insert("google.com".to_string());
        domains.insert("baidu.com".to_string());

        assert!(SplitTunnel::matches_domain("google.com", &domains));
        assert!(SplitTunnel::matches_domain("www.google.com", &domains));
        assert!(SplitTunnel::matches_domain("mail.google.com", &domains));
        assert!(SplitTunnel::matches_domain("sub.mail.google.com", &domains));
        assert!(SplitTunnel::matches_domain("baidu.com", &domains));
        assert!(!SplitTunnel::matches_domain("example.com", &domains));
        assert!(!SplitTunnel::matches_domain("oogle.com", &domains));
    }

    #[test]
    fn test_routing_decision_by_host() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        rt.block_on(async {
            let mut data = SplitTunnelData::default();
            data.tunnel_domains.insert("google.com".to_string());
            data.bypass_domains.insert("baidu.com".to_string());

            let split_tunnel = SplitTunnel {
                config: SplitTunnelConfig {
                    enabled: true,
                    ..Default::default()
                },
                data: Arc::new(RwLock::new(data)),
                dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
            };

            // Tunnel domains should return Tunnel
            assert_eq!(
                split_tunnel.decide_by_host("google.com").await,
                RoutingDecision::Tunnel
            );
            assert_eq!(
                split_tunnel.decide_by_host("www.google.com").await,
                RoutingDecision::Tunnel
            );

            // Bypass domains should return Bypass
            assert_eq!(
                split_tunnel.decide_by_host("baidu.com").await,
                RoutingDecision::Bypass
            );
            assert_eq!(
                split_tunnel.decide_by_host("api.baidu.com").await,
                RoutingDecision::Bypass
            );

            // Unknown domains should default to Tunnel
            assert_eq!(
                split_tunnel.decide_by_host("example.com").await,
                RoutingDecision::Tunnel
            );
        });
    }

    #[test]
    fn test_routing_decision_with_ips() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        rt.block_on(async {
            let mut data = SplitTunnelData::default();
            
            // Add bypass network: 1.0.1.0/24
            let bypass_net: IpNetwork = "1.0.1.0/24".parse().unwrap();
            data.bypass_networks.insert(bypass_net, true);
            
            // Add tunnel network: 8.8.8.0/24
            let tunnel_net: IpNetwork = "8.8.8.0/24".parse().unwrap();
            data.tunnel_networks.insert(tunnel_net, true);

            let split_tunnel = SplitTunnel {
                config: SplitTunnelConfig {
                    enabled: true,
                    ..Default::default()
                },
                data: Arc::new(RwLock::new(data)),
                dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
            };

            // Test bypass network
            let bypass_ip = IpAddr::V4(Ipv4Addr::new(1, 0, 1, 100));
            assert_eq!(
                split_tunnel.decide("example.com", &[bypass_ip]).await,
                RoutingDecision::Bypass,
                "IP {} should match bypass network 1.0.1.0/24", bypass_ip
            );

            // Test tunnel network
            let tunnel_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
            assert_eq!(
                split_tunnel.decide("example.com", &[tunnel_ip]).await,
                RoutingDecision::Tunnel
            );

            // Test unknown IP (should default to Tunnel)
            let unknown_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(
                split_tunnel.decide("example.com", &[unknown_ip]).await,
                RoutingDecision::Tunnel
            );
        });
    }

    #[test]
    fn test_domain_priority_over_network() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        rt.block_on(async {
            let mut data = SplitTunnelData::default();
            
            // Add a domain to tunnel list
            data.tunnel_domains.insert("google.com".to_string());
            
            // Add the same IP to bypass list
            let bypass_net: IpNetwork = "8.8.8.0/24".parse().unwrap();
            data.bypass_networks.insert(bypass_net, true);

            let split_tunnel = SplitTunnel {
                config: SplitTunnelConfig {
                    enabled: true,
                    ..Default::default()
                },
                data: Arc::new(RwLock::new(data)),
                dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
            };

            // Domain match should take priority over network
            let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
            assert_eq!(
                split_tunnel.decide("google.com", &[ip]).await,
                RoutingDecision::Tunnel
            );
        });
    }

    #[test]
    fn test_decide_by_ip() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        rt.block_on(async {
            let mut data = SplitTunnelData::default();
            
            // Add bypass network: 192.168.0.0/16 (RFC 1918)
            let bypass_net: IpNetwork = "192.168.0.0/16".parse().unwrap();
            data.bypass_networks.insert(bypass_net, true);
            
            // Add IPv6 loopback
            let bypass_net_v6: IpNetwork = "::1/128".parse().unwrap();
            data.bypass_networks.insert(bypass_net_v6, true);
            
            // Add tunnel network: 8.8.8.0/24
            let tunnel_net: IpNetwork = "8.8.8.0/24".parse().unwrap();
            data.tunnel_networks.insert(tunnel_net, true);

            let split_tunnel = SplitTunnel {
                config: SplitTunnelConfig {
                    enabled: true,
                    ..Default::default()
                },
                data: Arc::new(RwLock::new(data)),
                dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
            };

            // Test bypass network (192.168.x.x)
            let bypass_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(
                split_tunnel.decide_by_ip(bypass_ip).await,
                RoutingDecision::Bypass,
                "IP {} should match bypass network 192.168.0.0/16", bypass_ip
            );

            // Test tunnel network (8.8.8.x)
            let tunnel_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
            assert_eq!(
                split_tunnel.decide_by_ip(tunnel_ip).await,
                RoutingDecision::Tunnel,
                "IP {} should match tunnel network 8.8.8.0/24", tunnel_ip
            );

            // Test unknown IP (should default to Tunnel)
            let unknown_ip = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
            assert_eq!(
                split_tunnel.decide_by_ip(unknown_ip).await,
                RoutingDecision::Tunnel,
                "Unknown IP {} should default to Tunnel", unknown_ip
            );

            // Test IPv6 localhost
            let localhost_v6 = IpAddr::V6(std::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
            assert_eq!(
                split_tunnel.decide_by_ip(localhost_v6).await,
                RoutingDecision::Bypass,
                "IPv6 localhost should match bypass network ::1/128"
            );
        });
    }

    #[test]
    fn test_decide_by_ip_disabled() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        
        rt.block_on(async {
            let data = SplitTunnelData::default();

            let split_tunnel = SplitTunnel {
                config: SplitTunnelConfig {
                    enabled: false,
                    ..Default::default()
                },
                data: Arc::new(RwLock::new(data)),
                dns_resolver: Arc::new(DnsResolver::new(true, 300, 1000, false, true, vec![])),
            };

            // When disabled, all traffic should tunnel
            let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
            assert_eq!(
                split_tunnel.decide_by_ip(ip).await,
                RoutingDecision::Tunnel,
                "When disabled, IP should default to Tunnel"
            );
        });
    }
}
