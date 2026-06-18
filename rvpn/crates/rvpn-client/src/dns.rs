//! FakeIP DNS resolver

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

/// FakeIP pool for deferred DNS resolution
pub struct FakeIpPool {
    /// Next available IP in the pool
    next_ip: u32,
    /// Domain to IP mapping
    domain_to_ip: HashMap<String, Ipv4Addr>,
    /// IP to domain mapping (reverse lookup)
    ip_to_domain: HashMap<Ipv4Addr, String>,
}

impl FakeIpPool {
    /// Create a new FakeIP pool with the default range 198.18.0.0/15
    pub fn new() -> Self {
        Self {
            next_ip: 0xC6120000, // 198.18.0.0
            domain_to_ip: HashMap::new(),
            ip_to_domain: HashMap::new(),
        }
    }

    /// Query a domain and get a FakeIP
    pub fn query(&mut self, domain: &str) -> Ipv4Addr {
        if let Some(&ip) = self.domain_to_ip.get(domain) {
            return ip;
        }

        // Allocate new virtual IP
        let ip = Ipv4Addr::from(self.next_ip);
        self.next_ip += 1;

        // Wrap around if we exceed 198.19.255.255
        if self.next_ip > 0xC613FFFF {
            self.next_ip = 0xC6120000;
        }

        self.domain_to_ip.insert(domain.to_string(), ip);
        self.ip_to_domain.insert(ip, domain.to_string());

        ip
    }

    /// Resolve a FakeIP back to the original domain
    pub fn resolve(&self, ip: Ipv4Addr) -> Option<&str> {
        self.ip_to_domain.get(&ip).map(|s| s.as_str())
    }

    /// Check if an IP is in the FakeIP range
    pub fn is_fake_ip(ip: Ipv4Addr) -> bool {
        let octets = ip.octets();
        // 198.18.0.0/15
        octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
    }
}

impl Default for FakeIpPool {
    fn default() -> Self {
        Self::new()
    }
}

/// DNS resolver that supports FakeIP mode
pub struct SmartDnsResolver {
    /// FakeIP pool (if enabled)
    fakeip_pool: Option<Mutex<FakeIpPool>>,
    /// Whether to use FakeIP mode
    use_fakeip: bool,
}

impl SmartDnsResolver {
    pub fn new(use_fakeip: bool) -> Self {
        Self {
            fakeip_pool: if use_fakeip { Some(Mutex::new(FakeIpPool::new())) } else { None },
            use_fakeip,
        }
    }

    /// Resolve a domain name
    pub async fn resolve(&self, domain: &str) -> Result<Vec<Ipv4Addr>, DnsError> {
        if self.use_fakeip {
            if let Some(pool) = &self.fakeip_pool {
                let mut pool = pool.lock().unwrap();
                let ip = pool.query(domain);
                return Ok(vec![ip]);
            }
        }

        // TODO: Real DNS resolution through VPN tunnel
        todo!("Real DNS resolution not yet implemented")
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("DNS resolution failed: {0}")]
    ResolutionFailed(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fake_ip_pool_new() {
        let pool = FakeIpPool::new();
        assert!(pool.domain_to_ip.is_empty());
        assert!(pool.ip_to_domain.is_empty());
    }

    #[test]
    fn test_fake_ip_pool_query_allocates_ip() {
        let mut pool = FakeIpPool::new();
        
        let ip = pool.query("example.com");
        
        // Should be in the 198.18.0.0/15 range
        assert!(FakeIpPool::is_fake_ip(ip));
        assert_eq!(ip.octets()[0], 198);
        assert!(ip.octets()[1] == 18 || ip.octets()[1] == 19);
    }

    #[test]
    fn test_fake_ip_pool_query_caches_same_domain() {
        let mut pool = FakeIpPool::new();
        
        let ip1 = pool.query("example.com");
        let ip2 = pool.query("example.com");
        
        // Same domain should return the same IP
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_fake_ip_pool_query_different_domains() {
        let mut pool = FakeIpPool::new();
        
        let ip1 = pool.query("example.com");
        let ip2 = pool.query("google.com");
        
        // Different domains should get different IPs
        assert_ne!(ip1, ip2);
    }

    #[test]
    fn test_fake_ip_pool_resolve() {
        let mut pool = FakeIpPool::new();
        
        let ip = pool.query("example.com");
        let resolved = pool.resolve(ip);
        
        assert_eq!(resolved, Some("example.com"));
    }

    #[test]
    fn test_fake_ip_pool_resolve_unknown() {
        let pool = FakeIpPool::new();
        
        // Try to resolve an IP that was never allocated
        let unknown_ip = Ipv4Addr::new(198, 18, 0, 100);
        let resolved = pool.resolve(unknown_ip);
        
        assert_eq!(resolved, None);
    }

    #[test]
    fn test_fake_ip_pool_is_fake_ip() {
        // IPs in the 198.18.0.0/15 range
        assert!(FakeIpPool::is_fake_ip(Ipv4Addr::new(198, 18, 0, 0)));
        assert!(FakeIpPool::is_fake_ip(Ipv4Addr::new(198, 18, 255, 255)));
        assert!(FakeIpPool::is_fake_ip(Ipv4Addr::new(198, 19, 0, 0)));
        assert!(FakeIpPool::is_fake_ip(Ipv4Addr::new(198, 19, 255, 255)));
        
        // IPs outside the range
        assert!(!FakeIpPool::is_fake_ip(Ipv4Addr::new(198, 17, 255, 255)));
        assert!(!FakeIpPool::is_fake_ip(Ipv4Addr::new(198, 20, 0, 0)));
        assert!(!FakeIpPool::is_fake_ip(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!FakeIpPool::is_fake_ip(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!FakeIpPool::is_fake_ip(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_fake_ip_pool_wraparound() {
        let mut pool = FakeIpPool::new();
        
        // Set next_ip to just before the end of the range
        pool.next_ip = 0xC613FFFF; // 198.19.255.255
        
        // Query should allocate 198.19.255.255
        let ip1 = pool.query("first.com");
        assert_eq!(ip1, Ipv4Addr::new(198, 19, 255, 255));
        
        // Next query should wrap around to 198.18.0.0
        let ip2 = pool.query("second.com");
        assert_eq!(ip2, Ipv4Addr::new(198, 18, 0, 0));
    }

    #[test]
    fn test_fake_ip_pool_sequential_allocation() {
        let mut pool = FakeIpPool::new();
        
        let ip1 = pool.query("a.com");
        let ip2 = pool.query("b.com");
        let ip3 = pool.query("c.com");
        
        // IPs should be sequential
        let ip1_u32: u32 = ip1.into();
        let ip2_u32: u32 = ip2.into();
        let ip3_u32: u32 = ip3.into();
        
        assert_eq!(ip2_u32, ip1_u32 + 1);
        assert_eq!(ip3_u32, ip2_u32 + 1);
    }

    #[test]
    fn test_smart_dns_resolver_new_with_fakeip() {
        let resolver = SmartDnsResolver::new(true);
        assert!(resolver.use_fakeip);
        assert!(resolver.fakeip_pool.is_some());
    }

    #[test]
    fn test_smart_dns_resolver_new_without_fakeip() {
        let resolver = SmartDnsResolver::new(false);
        assert!(!resolver.use_fakeip);
        assert!(resolver.fakeip_pool.is_none());
    }

    #[tokio::test]
    async fn test_smart_dns_resolver_resolve_fakeip() {
        let resolver = SmartDnsResolver::new(true);
        
        let result = resolver.resolve("example.com").await;
        
        assert!(result.is_ok());
        let ips = result.unwrap();
        assert_eq!(ips.len(), 1);
        assert!(FakeIpPool::is_fake_ip(ips[0]));
    }
}
