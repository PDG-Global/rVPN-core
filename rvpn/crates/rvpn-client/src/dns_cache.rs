//! DNS resolver with caching for R-VPN client
//!
//! This module provides DNS resolution with:
//! - Caching with TTL
//! - IPv6 filtering (when disabled)
//! - IPv4 preference ordering
//! - Optional custom nameservers (direct UDP, bypassing system resolver)

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// DNS cache entry
#[derive(Debug)]
struct DnsEntry {
    ips: Vec<IpAddr>,
    cached_at: Instant,
    ttl: Duration,
    /// If true, this is a negative cache entry (lookup failed).
    /// Kept for a short TTL to prevent retry storms during outages.
    failed: bool,
}

/// DNS resolver with caching
#[derive(Debug)]
pub struct DnsResolver {
    cache: Arc<RwLock<HashMap<String, DnsEntry>>>,
    cache_enabled: bool,
    cache_ttl: Duration,
    cache_size: usize,
    ipv6_enabled: bool,
    prefer_ipv4: bool,
    /// Custom nameservers for direct UDP queries (bypasses system resolver)
    nameservers: Vec<SocketAddr>,
    /// Ensures only one cleanup task is spawned even if start_cleanup_task is called multiple times
    cleanup_started: AtomicBool,
}

/// Global atomic counter for DNS query transaction IDs
static DNS_TXID: AtomicU16 = AtomicU16::new(1);

impl DnsResolver {
    /// Create a new DNS resolver
    pub fn new(
        cache_enabled: bool,
        cache_ttl_secs: u64,
        cache_size: usize,
        ipv6_enabled: bool,
        prefer_ipv4: bool,
        nameservers: Vec<SocketAddr>,
    ) -> Self {
        if !nameservers.is_empty() {
            info!(
                "DnsResolver using custom nameservers: {:?}",
                nameservers
            );
        }
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            cache_enabled,
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            cache_size,
            ipv6_enabled,
            prefer_ipv4,
            nameservers,
            cleanup_started: AtomicBool::new(false),
        }
    }

    /// Resolve a hostname to IP addresses.
    ///
    /// The internal cache is keyed by hostname only (port is not part of the key),
    /// so resolving the same host on different ports shares the same cached IPs.
    pub async fn resolve(&self, host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
        // Check cache first (including negative entries)
        if self.cache_enabled {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(host) {
                if entry.cached_at.elapsed() < entry.ttl {
                    if entry.failed {
                        debug!("DNS negative cache hit for {} (recently failed)", host);
                        return Err(anyhow::anyhow!(
                            "DNS lookup failed for {}: cached failure (TTL {}s remaining)",
                            host,
                            entry.ttl.as_secs() - entry.cached_at.elapsed().as_secs()
                        ));
                    }
                    let addrs: Vec<SocketAddr> = entry
                        .ips
                        .iter()
                        .map(|ip| SocketAddr::new(*ip, port))
                        .collect();
                    if !addrs.is_empty() {
                        debug!(
                            "DNS cache hit for {} ({} addresses)",
                            host,
                            addrs.len()
                        );
                        return Ok(self.order_addresses(addrs));
                    }
                }
            }
        }

        // Try custom nameservers first (direct UDP, bypasses system resolver)
        if !self.nameservers.is_empty() {
            for ns in &self.nameservers {
                match query_nameserver_udp(*ns, host).await {
                    Ok((mut ips, ttl_secs)) => {
                        if !self.ipv6_enabled {
                            let before = ips.len();
                            ips.retain(|ip| matches!(ip, IpAddr::V4(_)));
                            if before != ips.len() {
                                debug!(
                                    "Filtered {} IPv6 addresses for {}",
                                    before - ips.len(),
                                    host
                                );
                            }
                        }
                        if !ips.is_empty() {
                            debug!(
                                "DNS resolved {} via {} ({} addresses, TTL {}s)",
                                host,
                                ns,
                                ips.len(),
                                ttl_secs
                            );
                            let ttl = Duration::from_secs(ttl_secs as u64);
                            let addrs: Vec<SocketAddr> =
                                ips.iter().map(|ip| SocketAddr::new(*ip, port)).collect();
                            self.store_ips(host, ips, Some(ttl)).await;
                            return Ok(self.order_addresses(addrs));
                        }
                    }
                    Err(e) => {
                        debug!("Nameserver {} failed for {}: {}", ns, host, e);
                    }
                }
            }
            debug!(
                "All custom nameservers failed for {}, falling back to system resolver",
                host
            );
        }

        // Fallback to system resolver
        debug!("DNS cache miss for {}, performing lookup", host);
        let lookup_result = tokio::net::lookup_host(format!("{}:{}", host, port)).await;

        match lookup_result {
            Ok(addrs) => {
                let addrs: Vec<SocketAddr> = addrs.collect();

                if addrs.is_empty() {
                    self.store_failure(host).await;
                    return Err(anyhow::anyhow!("No addresses found for {}", host));
                }

                let ips: Vec<IpAddr> = addrs.iter().map(|a| a.ip()).collect();
                self.store_ips(host, ips, None).await;
                Ok(self.order_addresses(addrs))
            }
            Err(e) => {
                warn!("DNS lookup failed for {}: {}", host, e);
                self.store_failure(host).await;
                Err(anyhow::anyhow!("DNS lookup failed for {}: {}", host, e))
            }
        }
    }

    /// Store IPs in cache keyed by hostname.
    /// `ttl` overrides the default cache TTL when provided (e.g. actual TTL from a DNS response).
    async fn store_ips(&self, host: &str, ips: Vec<IpAddr>, ttl: Option<Duration>) {
        if !self.cache_enabled {
            return;
        }
        let entry = DnsEntry {
            ips,
            cached_at: Instant::now(),
            ttl: ttl.unwrap_or(self.cache_ttl),
            failed: false,
        };

        let mut cache = self.cache.write().await;
        self.evict_if_needed(&mut cache).await;
        cache.insert(host.to_string(), entry);
    }

    /// Store a negative cache entry (failed lookup) with short TTL to suppress retry storms.
    async fn store_failure(&self, host: &str) {
        if !self.cache_enabled {
            return;
        }
        const FAILURE_TTL_SECS: u64 = 30;
        let entry = DnsEntry {
            ips: vec![],
            cached_at: Instant::now(),
            ttl: Duration::from_secs(FAILURE_TTL_SECS),
            failed: true,
        };

        let mut cache = self.cache.write().await;
        self.evict_if_needed(&mut cache).await;
        cache.insert(host.to_string(), entry);
    }

    /// Remove expired entries, and if still over limit, evict oldest by `cached_at`.
    async fn evict_if_needed(&self, cache: &mut HashMap<String, DnsEntry>) {
        if cache.len() < self.cache_size {
            return;
        }

        // Remove expired entries first
        let now = Instant::now();
        cache.retain(|_, e| now.duration_since(e.cached_at) < e.ttl);

        // If still too large, evict oldest entries
        if cache.len() >= self.cache_size {
            let mut entries: Vec<(String, Instant)> = cache
                .iter()
                .map(|(k, e)| (k.clone(), e.cached_at))
                .collect();
            entries.sort_by(|a, b| a.1.cmp(&b.1));
            let to_remove = cache.len().saturating_sub(self.cache_size - 1);
            for (key, _) in entries.into_iter().take(to_remove) {
                cache.remove(&key);
            }
        }
    }

    /// Look up cached IPs without performing a network query.
    /// Returns None if not in cache, expired, or entry is a negative cache (failed lookup).
    pub async fn lookup_cached(&self, host: &str) -> Option<Vec<IpAddr>> {
        if !self.cache_enabled {
            return None;
        }
        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(host) {
            if entry.cached_at.elapsed() < entry.ttl {
                if entry.failed {
                    return None;
                }
                if !entry.ips.is_empty() {
                    debug!(
                        "DNS cache hit for {} ({} addresses)",
                        host,
                        entry.ips.len()
                    );
                    return Some(entry.ips.clone());
                }
            }
        }
        None
    }

    /// Get the remaining TTL (in seconds) for a cached entry.
    /// Returns None if not cached, expired, or negative entry.
    pub async fn get_remaining_ttl(&self, host: &str) -> Option<u32> {
        if !self.cache_enabled {
            return None;
        }
        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(host) {
            if entry.failed {
                return None;
            }
            let remaining = entry.ttl.saturating_sub(entry.cached_at.elapsed());
            let secs = remaining.as_secs() as u32;
            if secs > 0 {
                return Some(secs);
            }
        }
        None
    }

    /// Store IPs in cache directly (used when DNS response arrives from server).
    /// Used by rvpn-mobile — kept as public API despite not being called within this crate.
    #[allow(dead_code)]
    pub async fn store(&self, host: &str, ips: Vec<IpAddr>) {
        self.store_with_ttl(host, ips, self.cache_ttl).await;
    }

    /// Store IPs with a specific TTL.
    pub async fn store_with_ttl(&self, host: &str, ips: Vec<IpAddr>, ttl: Duration) {
        if !self.cache_enabled {
            return;
        }
        let entry = DnsEntry {
            ips,
            cached_at: Instant::now(),
            ttl,
            failed: false,
        };

        let mut cache = self.cache.write().await;
        self.evict_if_needed(&mut cache).await;
        cache.insert(host.to_string(), entry);
    }

    /// Start a background task that periodically cleans expired cache entries.
    /// Idempotent — calling multiple times only spawns one task.
    #[allow(dead_code)]
    pub fn start_cleanup_task(self: &Arc<Self>) {
        if self.cleanup_started.swap(true, Ordering::SeqCst) {
            return; // Already started
        }
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                this.cleanup_cache().await;
            }
        });
    }

    /// Order addresses based on preferences (IPv4 first if preferred)
    fn order_addresses(&self, mut addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        if self.prefer_ipv4 {
            // Sort: IPv4 first, then IPv6
            addrs.sort_by(|a, b| match (a.ip(), b.ip()) {
                (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
                (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
                _ => std::cmp::Ordering::Equal,
            });
        }
        addrs
    }

    /// Clear expired cache entries
    #[allow(dead_code)]
    pub async fn cleanup_cache(&self) {
        if !self.cache_enabled {
            return;
        }

        let mut cache = self.cache.write().await;
        let before = cache.len();
        let now = Instant::now();
        cache.retain(|_, entry| now.duration_since(entry.cached_at) < entry.ttl);
        let after = cache.len();

        if before != after {
            debug!("DNS cache cleanup: removed {} expired entries", before - after);
        }
    }

    /// Get cache statistics
    #[allow(dead_code)]
    pub async fn cache_stats(&self) -> (usize, usize) {
        let cache = self.cache.read().await;
        let total = cache.len();
        let expired = cache
            .values()
            .filter(|e| Instant::now().duration_since(e.cached_at) >= e.ttl)
            .count();
        (total, expired)
    }

    /// Clear the entire cache
    #[allow(dead_code)]
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
        debug!("DNS cache cleared");
    }
}

// ---------------------------------------------------------------------------
// Lightweight UDP DNS client (A-record only)
// ---------------------------------------------------------------------------

/// Send a DNS A query via UDP to a specific nameserver and parse the response.
/// Returns the resolved IPv4 addresses and the minimum TTL from the A records.
/// Retries up to 2 times on timeout to handle brief packet loss on congested networks.
async fn query_nameserver_udp(
    nameserver: SocketAddr,
    domain: &str,
) -> anyhow::Result<(Vec<IpAddr>, u32)> {
    const MAX_RETRIES: usize = 2;
    const TIMEOUT_SECS: u64 = 3;

    let mut last_error = None;

    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            // Brief backoff before retry: 200ms, then 500ms
            tokio::time::sleep(Duration::from_millis(200 * attempt as u64)).await;
        }

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let txid = DNS_TXID.fetch_add(1, Ordering::Relaxed);
        let query = build_dns_query_packet(domain, txid);

        if let Err(e) = socket.send_to(&query, nameserver).await {
            last_error = Some(format!("send failed: {}", e));
            continue;
        }

        let mut buf = [0u8; 512];
        match tokio::time::timeout(
            Duration::from_secs(TIMEOUT_SECS),
            socket.recv_from(&mut buf),
        )
        .await
        {
            Ok(Ok((len, _))) => {
                let response = &buf[..len];
                return parse_dns_a_response(response, txid);
            }
            Ok(Err(e)) => last_error = Some(format!("recv error: {}", e)),
            Err(_) => last_error = Some(format!("timeout ({}s)", TIMEOUT_SECS)),
        }
    }

    Err(anyhow::anyhow!(
        "Nameserver {} failed after {} attempts — last: {}",
        nameserver,
        MAX_RETRIES + 1,
        last_error.unwrap_or_else(|| "unknown".to_string())
    ))
}

/// Build a minimal DNS A query packet in wire format.
fn build_dns_query_packet(domain: &str, txid: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(512);
    // Header
    packet.extend_from_slice(&txid.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00]); // Flags: standard query, recursion desired
    packet.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    packet.extend_from_slice(&[0x00, 0x00]); // ANCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00]); // NSCOUNT = 0
    packet.extend_from_slice(&[0x00, 0x00]); // ARCOUNT = 0

    // QNAME
    for label in domain.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0x00); // Null terminator

    // QTYPE = A (1)
    packet.extend_from_slice(&[0x00, 0x01]);
    // QCLASS = IN (1)
    packet.extend_from_slice(&[0x00, 0x01]);

    packet
}

/// Parse a DNS response and extract IPv4 addresses and the minimum TTL from A records.
pub(crate) fn parse_dns_a_response(data: &[u8], expected_txid: u16) -> anyhow::Result<(Vec<IpAddr>, u32)> {
    if data.len() < 12 {
        anyhow::bail!("DNS response too short ({} bytes)", data.len());
    }

    let txid = u16::from_be_bytes([data[0], data[1]]);
    if txid != expected_txid {
        anyhow::bail!("DNS TXID mismatch: expected {}, got {}", expected_txid, txid);
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qr = (flags >> 15) & 1;
    if qr != 1 {
        anyhow::bail!("DNS response QR bit not set");
    }
    let rcode = flags & 0x0F;
    if rcode != 0 {
        anyhow::bail!("DNS response error: RCODE={}", rcode);
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    let mut pos = 12usize;

    // Skip question section
    for _ in 0..qdcount {
        pos = skip_dns_name(data, pos)?;
        pos += 4; // QTYPE + QCLASS
    }

    // Parse answer records
    let mut ips = Vec::new();
    let mut min_ttl = u32::MAX;
    for _ in 0..ancount {
        pos = skip_dns_name(data, pos)?;
        if pos + 10 > data.len() {
            break;
        }
        let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2; // QTYPE
        pos += 2; // QCLASS
        let ttl = u32::from_be_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
        pos += 4; // TTL
        let rdlength = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        if qtype == 1 && rdlength == 4 {
            // A record
            if pos + 4 <= data.len() {
                let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                    data[pos], data[pos + 1], data[pos + 2], data[pos + 3],
                ));
                ips.push(ip);
                if ttl < min_ttl {
                    min_ttl = ttl;
                }
            }
        }
        pos += rdlength;
    }

    if ips.is_empty() {
        anyhow::bail!("No A records in DNS response");
    }

    // Cap TTL to a reasonable maximum (4 hours) to avoid stale data from misconfigured servers
    let ttl = min_ttl.min(14400);
    Ok((ips, ttl))
}

/// Skip a DNS name (labels or pointer compression) and return the position after it.
fn skip_dns_name(data: &[u8], mut pos: usize) -> anyhow::Result<usize> {
    loop {
        if pos >= data.len() {
            anyhow::bail!("Truncated DNS name");
        }
        let len = data[pos] as usize;
        if len == 0 {
            return Ok(pos + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Pointer compression: 2-byte pointer
            return Ok(pos + 2);
        }
        pos += 1 + len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dns_resolution() {
        let resolver = DnsResolver::new(true, 300, 1000, true, true, vec![]);
        let addrs = resolver.resolve("cloudflare.com", 443).await;
        assert!(addrs.is_ok());
        assert!(!addrs.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_ipv4_preference() {
        let resolver = DnsResolver::new(true, 300, 1000, true, true, vec![]);
        let addrs = resolver.resolve("cloudflare.com", 443).await.unwrap();

        // Check that IPv4 addresses come before IPv6
        let mut saw_ipv6 = false;
        for addr in &addrs {
            match addr.ip() {
                IpAddr::V4(_) => {
                    if saw_ipv6 {
                        panic!("IPv4 address found after IPv6 address");
                    }
                }
                IpAddr::V6(_) => {
                    saw_ipv6 = true;
                }
            }
        }
    }
}
