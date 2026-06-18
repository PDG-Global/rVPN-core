//! Routing engine for smart traffic routing

use std::collections::HashSet;
use std::net::IpAddr;

/// Route action
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouteAction {
    /// Direct connection (bypass VPN)
    Direct,
    /// Through VPN proxy
    #[default]
    Proxy,
    /// Block connection
    Block,
}

/// Routing engine
pub struct RoutingEngine {
    /// China IP ranges (CIDR notation)
    china_ips: Vec<ip_network::IpNetwork>,
    /// China domains (suffix)
    china_domains: Vec<String>,
    /// Blocked domains
    blocked_domains: HashSet<String>,
    /// Default action
    default_action: RouteAction,
}

impl RoutingEngine {
    /// Create a new routing engine
    pub fn new() -> Self {
        Self {
            china_ips: Vec::new(),
            china_domains: Vec::new(),
            blocked_domains: HashSet::new(),
            default_action: RouteAction::Proxy,
        }
    }

    /// Add a China IP range
    pub fn add_china_ip(&mut self, cidr: &str) -> anyhow::Result<()> {
        let network: ip_network::IpNetwork = cidr.parse()?;
        self.china_ips.push(network);
        Ok(())
    }

    /// Add a China domain
    pub fn add_china_domain(&mut self, domain: &str) {
        self.china_domains.push(domain.to_string());
    }

    /// Add a blocked domain
    pub fn add_blocked_domain(&mut self, domain: &str) {
        self.blocked_domains.insert(domain.to_string());
    }

    /// Set default action
    pub fn set_default_action(&mut self, action: RouteAction) {
        self.default_action = action;
    }

    /// Get route decision for IP
    pub fn route_ip(&self, ip: IpAddr) -> RouteAction {
        // Check China IP list
        for network in &self.china_ips {
            if network.contains(ip) {
                return RouteAction::Direct;
            }
        }

        self.default_action
    }

    /// Get route decision for domain
    pub fn route_domain(&self, domain: &str) -> RouteAction {
        // Check blocked domains
        if self.blocked_domains.contains(domain) {
            return RouteAction::Block;
        }

        // Check China domains
        for china_domain in &self.china_domains {
            if domain.ends_with(china_domain) || domain == china_domain {
                return RouteAction::Direct;
            }
        }

        self.default_action
    }

    /// Get route decision (combined)
    pub fn route(&self, ip: Option<IpAddr>, domain: Option<&str>) -> RouteAction {
        // Domain takes precedence if available
        if let Some(d) = domain {
            let result = self.route_domain(d);
            if result != self.default_action {
                return result;
            }
        }

        // Then check IP
        if let Some(i) = ip {
            return self.route_ip(i);
        }

        self.default_action
    }
}

impl Default for RoutingEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Load China IP list (simplified)
pub fn default_china_ips() -> Vec<&'static str> {
    // Simplified list - real implementation would load from file
    vec![
        "220.0.0.0/8",
        "221.0.0.0/8",
        "222.0.0.0/8",
        "60.0.0.0/8",
        "58.0.0.0/8",
    ]
}

/// Load China domain list (simplified)
pub fn default_china_domains() -> Vec<&'static str> {
    vec![
        ".cn",
        ".baidu.com",
        ".taobao.com",
        ".jd.com",
        ".qq.com",
        ".alipay.com",
        ".aliyun.com",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_china_ip_routing() {
        let mut engine = RoutingEngine::new();
        engine.add_china_ip("220.0.0.0/8").unwrap();

        // Test China IP
        let china_ip: IpAddr = "220.181.38.148".parse().unwrap();
        assert_eq!(engine.route_ip(china_ip), RouteAction::Direct);

        // Test US IP
        let us_ip: IpAddr = "142.250.185.78".parse().unwrap();
        assert_eq!(engine.route_ip(us_ip), RouteAction::Proxy);
    }

    #[test]
    fn test_china_domain_routing() {
        let mut engine = RoutingEngine::new();
        engine.add_china_domain(".cn");

        // Test China domain
        assert_eq!(engine.route_domain("baidu.com.cn"), RouteAction::Direct);

        // Test US domain
        assert_eq!(engine.route_domain("google.com"), RouteAction::Proxy);
    }

    #[test]
    fn test_blocked_domain() {
        let mut engine = RoutingEngine::new();
        engine.add_blocked_domain("malware.com");

        assert_eq!(engine.route_domain("malware.com"), RouteAction::Block);
    }
}
