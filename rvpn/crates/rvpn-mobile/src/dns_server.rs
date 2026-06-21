//! Local DNS Server for Android VPN
//!
//! This module implements a local DNS server that:
//! 1. Binds to 127.0.0.1:53 (or configured port)
//! 2. Receives DNS queries from the system
//! 3. Routes queries based on split tunnel rules:
//!    - Local/bypass domains → System resolver
//!    - Remote domains → DoH through WebSocket tunnel
//!
//! Uses hickory-proto for DNS protocol handling.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::doh_client::DohClient;
use rvpn_client::split_tunnel::{SplitTunnel, RoutingDecision as SplitTunnelRoutingDecision};
use rvpn_client::dns_cache::DnsResolver;

/// DNS query routing decision (matches rvpn-client RoutingDecision)
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RoutingDecision {
    /// Use local system resolver (bypass tunnel)
    Bypass,
    /// Use remote DoH through tunnel
    Tunnel,
    /// Block the connection
    Block,
}

impl From<SplitTunnelRoutingDecision> for RoutingDecision {
    fn from(decision: SplitTunnelRoutingDecision) -> Self {
        match decision {
            SplitTunnelRoutingDecision::Bypass => RoutingDecision::Bypass,
            SplitTunnelRoutingDecision::Tunnel => RoutingDecision::Tunnel,
            SplitTunnelRoutingDecision::Block => RoutingDecision::Block,
        }
    }
}

/// Local DNS Server
pub struct DnsServer {
    /// Split tunnel for routing decisions
    split_tunnel: Arc<RwLock<SplitTunnel>>,
    /// DoH client for tunneled queries (optional — if None, uses system DNS for all)
    doh_client: Option<Arc<DohClient>>,
    /// Bind address for the DNS server
    bind_addr: String,
    /// DNS resolver with caching
    dns_resolver: Arc<DnsResolver>,
    /// Public nameservers for bypass domain resolution (direct UDP, avoids loopback)
    nameservers: Vec<SocketAddr>,
    /// Whether to filter AAAA queries. Defaults to true because the upstream
    /// VPN servers are currently IPv4-only; returning empty AAAA responses
    /// prevents dual-stack apps from waiting on IPv6 timeouts.
    filter_aaaa: bool,
}

impl DnsServer {
    /// Default public nameservers for bypass domain resolution.
    /// Using multiple providers for redundancy.
    const DEFAULT_NAMESERVERS: &[&str] = &["8.8.8.8:53", "1.1.1.1:53", "223.5.5.5:53"];

    /// Create a new DNS server with SplitTunnel for routing decisions
    pub fn new(split_tunnel: SplitTunnel) -> Self {
        let dns_resolver = split_tunnel.dns_resolver();
        let nameservers = Self::parse_nameservers(Self::DEFAULT_NAMESERVERS);
        Self {
            split_tunnel: Arc::new(RwLock::new(split_tunnel)),
            doh_client: None,
            bind_addr: "127.0.0.1:53".to_string(),
            dns_resolver,
            nameservers,
            filter_aaaa: true,
        }
    }

    /// Create a new DNS server with custom bind address
    pub fn with_bind_addr(split_tunnel: SplitTunnel, bind_addr: String) -> Self {
        let dns_resolver = split_tunnel.dns_resolver();
        let nameservers = Self::parse_nameservers(Self::DEFAULT_NAMESERVERS);
        Self {
            split_tunnel: Arc::new(RwLock::new(split_tunnel)),
            doh_client: None,
            bind_addr,
            dns_resolver,
            nameservers,
            filter_aaaa: true,
        }
    }

    /// Create a new DNS server with a DoH client for tunnel routing
    pub fn with_doh(split_tunnel: SplitTunnel, doh_client: Arc<DohClient>, bind_addr: String) -> Self {
        let dns_resolver = split_tunnel.dns_resolver();
        let nameservers = Self::parse_nameservers(Self::DEFAULT_NAMESERVERS);
        Self {
            split_tunnel: Arc::new(RwLock::new(split_tunnel)),
            doh_client: Some(doh_client),
            bind_addr,
            dns_resolver,
            nameservers,
            filter_aaaa: true,
        }
    }

    /// Enable or disable AAAA query filtering.
    pub fn set_filter_aaaa(&mut self, enabled: bool) {
        self.filter_aaaa = enabled;
    }

    fn parse_nameservers(addrs: &[&str]) -> Vec<SocketAddr> {
        addrs.iter()
            .filter_map(|s| s.parse().ok())
            .collect()
    }

    /// Get the actual bound address (for port fallback)
    pub fn bind_addr(&self) -> &str {
        &self.bind_addr
    }

    /// Try to bind with fallback ports (5453, 5353, 1053, etc.)
    async fn try_bind_with_fallback(primary: SocketAddr) -> Result<UdpSocket> {
        let ports = [primary.port(), 5353, 1053, 15353, 1153];
        let ip = primary.ip();

        for port in ports {
            let addr = SocketAddr::new(ip, port);
            match UdpSocket::bind(addr).await {
                Ok(socket) => {
                    info!("DNS server bound to {}", addr);
                    return Ok(socket);
                }
                Err(e) => {
                    warn!("Failed to bind DNS to {}: {}", addr, e);
                }
            }
        }

        Err(anyhow::anyhow!("All fallback ports failed"))
    }

    /// Start the DNS server (runs indefinitely)
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let bind_addr: SocketAddr = self.bind_addr.parse()
            .context("Invalid bind address")?;

        // Try to bind to the address - if primary port fails, try fallback ports
        let socket = Arc::new(
            Self::try_bind_with_fallback(bind_addr).await
                .context("Failed to bind DNS UDP socket on any port")?
        );

        // Use a larger buffer to handle EDNS/larger responses
        let mut buf = [0u8; 4096];

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, client_addr)) => {
                    let data = buf[..len].to_vec();
                    let server = self.clone();
                    let sock = socket.clone();

                    tokio::spawn(async move {
                        match Message::from_vec(&data) {
                            Ok(request) => {
                                match server.handle_query(request, client_addr, &sock).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        warn!("Failed to handle DNS query: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to parse DNS message: {}", e);
                            }
                        }
                    });
                }
                Err(e) => {
                    error!("UDP receive error: {}", e);
                }
            }
        }
    }

    /// Handle a single DNS query
    async fn handle_query(
        &self,
        request: Message,
        client_addr: SocketAddr,
        socket: &Arc<UdpSocket>,
    ) -> Result<()> {
        // Validate request
        if request.message_type() != MessageType::Query {
            debug!("Ignoring non-query message");
            return Ok(());
        }

        if request.op_code() != OpCode::Query {
            debug!("Ignoring query with non-standard opcode");
            return Ok(());
        }

        let queries: Vec<&Query> = request.queries().iter().collect();
        if queries.is_empty() {
            debug!("Ignoring query with no questions");
            return Ok(());
        }

        // Handle only the first query
        let query = &queries[0];
        let name = query.name().clone();
        let query_type = query.query_type();

        // Filter AAAA queries when the upstream VPN is IPv4-only. Returning an
        // empty NoError response lets apps fall back to IPv4 immediately instead
        // of waiting for IPv6 timeouts.
        if self.filter_aaaa && query_type == RecordType::AAAA {
            debug!("Filtering AAAA query for {} (IPv4-only upstream)", name);
            let response = self.make_base_response(&request);
            let response_bytes = response.to_vec()
                .context("Failed to serialize AAAA filter response")?;
            socket.send_to(&response_bytes, client_addr).await
                .context("Failed to send AAAA filter response")?;
            return Ok(());
        }

        // Block DNS-over-HTTPS provider lookups to force apps to use system DNS.
        // When Chrome tries to establish DoH, it first resolves dns.google —
        // returning NXDOMAIN forces it to fall back to the system DNS resolver.
        let domain_lower = name.to_ascii().trim_end_matches('.').to_lowercase();
        const DOH_PROVIDERS: &[&str] = &[
            "dns.google", "dns.google.com",
            "cloudflare-dns.com", "one.one.one.one", "1.1.1.1",
            "dns.quad9.net", "doh.opendns.com",
            "mozilla.cloudflare-dns.com",
        ];
        if DOH_PROVIDERS.iter().any(|d| domain_lower == *d || domain_lower.ends_with(&format!(".{}", d))) {
            info!("Blocking DoH provider lookup for {} (forcing system DNS)", name);
            let response = self.make_error_response(&request, ResponseCode::NXDomain);
            let response_bytes = response.to_vec()
                .context("Failed to serialize DNS response")?;
            socket.send_to(&response_bytes, client_addr).await
                .context("Failed to send DNS response")?;
            return Ok(());
        }

        // Make routing decision using SplitTunnel
        let decision = self.route_query(&name).await;

        info!("DNS query: {} {:?} from {} → {:?}", name, query_type, client_addr, decision);

        let response = match decision {
            RoutingDecision::Bypass => {
                info!("Routing {} to local resolver (bypass)", name);
                self.resolve_local(&request, &name, query_type).await
            }
            RoutingDecision::Tunnel => {
                info!("Routing {} to remote DoH (tunnel)", name);
                self.resolve_remote(&request, &name, query_type).await
            }
            RoutingDecision::Block => {
                info!("Blocking {} (ad/tracker)", name);
                self.make_error_response(&request, ResponseCode::NXDomain)
            }
        };

        // Send response back to client
        let response_bytes = response.to_vec()
            .context("Failed to serialize DNS response")?;

        let answer_count = response.answers().len();
        let rcode = response.response_code();
        if answer_count == 0 && decision == RoutingDecision::Tunnel {
            warn!("DNS tunnel query for {} returned 0 answers (rcode={:?}), possible DoH issue", name, rcode);
        }
        info!("DNS response: {} bytes, {} answers, rcode={:?} for {}",
              response_bytes.len(), answer_count, rcode, name);

        match socket.send_to(&response_bytes, client_addr).await {
            Ok(_) => {}
            Err(e) => {
                error!("Failed to send DNS response: {}", e);
            }
        }

        Ok(())
    }

    /// Resolve a domain via the DoH client (tunnel), with caching
    async fn resolve_remote(
        &self,
        request: &Message,
        name: &Name,
        query_type: RecordType,
    ) -> Message {
        let domain = name.to_ascii();
        // Strip trailing dot
        let domain = domain.trim_end_matches('.');

        let qtype_num = match query_type {
            RecordType::A => 1u16,
            RecordType::AAAA => 28u16,
            _ => {
                // For unsupported query types (HTTPS/SVCB, etc.), return an empty
                // NoError response instead of NOTIMPL. Chrome on Android sends
                // HTTPS (type 65) queries and treats NOTIMPL as a fatal error,
                // resulting in DNS_PROBE_FINISHED_BAD_CONFIG.
                debug!("Unsupported DNS query type {:?} for {} — returning empty NoError", query_type, domain);
                return self.make_base_response(request);
            }
        };

        // Check DoH client cache first (this is the authoritative cache for
        // tunnel-domain DNS results). The DnsResolver cache uses a different
        // key format and would always miss, so we skip it.
        if let Some(client) = &self.doh_client {
            if let Some(cached) = client.lookup_cached(domain, qtype_num).await {
                debug!("DoH cache hit for tunnel domain {}", domain);
                let mut response = self.make_base_response(request);
                response.set_response_code(ResponseCode::NoError);
                // Use DoH client's TTL (capped to reasonable max)
                let ttl = client.get_cached_ttl(domain, qtype_num).await.unwrap_or(14400);

                for addr in &cached {
                    match addr {
                        IpAddr::V4(v4) if query_type == RecordType::A => {
                            let rdata = RData::A(rdata::A(*v4));
                            let record = Record::from_rdata(name.clone(), ttl, rdata);
                            let _ = response.add_answer(record);
                        }
                        IpAddr::V6(v6) if query_type == RecordType::AAAA => {
                            let rdata = RData::AAAA(rdata::AAAA(*v6));
                            let record = Record::from_rdata(name.clone(), ttl, rdata);
                            let _ = response.add_answer(record);
                        }
                        _ => {}
                    }
                }

                if response.answers().is_empty() {
                    debug!("No records of requested type for {}", domain);
                    response.set_response_code(ResponseCode::NoError);
                }
                return response;
            }
        }

        match &self.doh_client {
            Some(client) => {
                match client.resolve(domain, qtype_num).await {
                    Ok(addrs) => {
                        let mut response = self.make_base_response(request);
                        response.set_response_code(ResponseCode::NoError);
                        // Use the actual TTL from the DoH response (cached by the client)
                        let ttl = client.get_cached_ttl(domain, qtype_num).await.unwrap_or(14400);

                        for addr in &addrs {
                            match addr {
                                IpAddr::V4(v4) if query_type == RecordType::A => {
                                    let rdata = RData::A(rdata::A(*v4));
                                    let record = Record::from_rdata(name.clone(), ttl, rdata);
                                    let _ = response.add_answer(record);
                                }
                                IpAddr::V6(v6) if query_type == RecordType::AAAA => {
                                    let rdata = RData::AAAA(rdata::AAAA(*v6));
                                    let record = Record::from_rdata(name.clone(), ttl, rdata);
                                    let _ = response.add_answer(record);
                                }
                                _ => {}
                            }
                        }

                        if response.answers().is_empty() {
                            debug!("No records of requested type for {}", domain);
                            response.set_response_code(ResponseCode::NoError);
                        }

                        response
                    }
                    Err(e) => {
                        warn!("Remote DNS resolution failed for {}: {}", domain, e);
                        // Return ServFail instead of falling back to system DNS.
                        // Tunnel domains MUST be resolved through the tunnel.
                        // Falling back to system DNS would leak DNS queries outside the VPN.
                        self.make_error_response(request, ResponseCode::ServFail)
                    }
                }
            }
            None => {
                // No DoH client — this is a configuration error, not a fallback.
                // Tunnel domains require the DoH client to work.
                warn!("No DoH client configured for tunnel domain {}", domain);
                self.make_error_response(request, ResponseCode::ServFail)
            }
        }
    }

    /// Resolve a domain via direct UDP to public nameservers (bypass)
    ///
    /// On iOS, when the VPN is active, system DNS is redirected to our proxy (127.0.0.1:53).
    /// Using tokio::net::lookup_host() would loop back to ourselves. Instead, we send the
    /// raw DNS query directly to public nameservers via UDP.
    async fn resolve_local(
        &self,
        request: &Message,
        name: &Name,
        query_type: RecordType,
    ) -> Message {
        // Check the shared DNS resolver cache first. Bypass domains are resolved
        // via direct UDP, but if we already have a fresh answer we can skip the
        // network round-trip entirely.
        let domain = name.to_ascii();
        let domain = domain.trim_end_matches('.');
        if let Some(cached) = self.dns_resolver.lookup_cached(domain).await {
            if let Some(remaining_ttl) = self.dns_resolver.get_remaining_ttl(domain).await {
                let mut response = self.make_base_response(request);
                response.set_response_code(ResponseCode::NoError);
                for addr in cached {
                    match (addr, query_type) {
                        (IpAddr::V4(v4), RecordType::A) => {
                            let rdata = RData::A(rdata::A(v4));
                            let _ = response.add_answer(Record::from_rdata(name.clone(), remaining_ttl, rdata));
                        }
                        (IpAddr::V6(v6), RecordType::AAAA) => {
                            let rdata = RData::AAAA(rdata::AAAA(v6));
                            let _ = response.add_answer(Record::from_rdata(name.clone(), remaining_ttl, rdata));
                        }
                        _ => {}
                    }
                }
                if !response.answers().is_empty() {
                    debug!("DNS cache hit for bypass domain {} ({} answers)", domain, response.answers().len());
                    return response;
                }
            }
        }

        match self.resolve_via_udp_forward(request).await {
            Ok(response) => {
                // Cache successful bypass UDP responses
                let domain = name.to_ascii();
                let domain = domain.trim_end_matches('.');
                let mut ips = Vec::new();
                let mut min_ttl = u32::MAX;
                for record in response.answers() {
                    if let Some(rdata) = record.data() {
                        match rdata {
                            RData::A(a) => {
                                ips.push(IpAddr::V4(a.0));
                                min_ttl = min_ttl.min(record.ttl());
                            }
                            RData::AAAA(aaaa) => {
                                ips.push(IpAddr::V6(aaaa.0));
                                min_ttl = min_ttl.min(record.ttl());
                            }
                            _ => {}
                        }
                    }
                }
                if !ips.is_empty() && min_ttl != u32::MAX {
                    let ttl = std::time::Duration::from_secs(min_ttl.min(14400) as u64);
                    self.dns_resolver.store_with_ttl(domain, ips, ttl).await;
                }
                response
            }
            Err(e) => {
                warn!("UDP forward failed for bypass domain {}: {}, falling back to system resolver", name, e);
                self.resolve_via_system(request, name, query_type).await
            }
        }
    }

    /// Forward a raw DNS query to public nameservers via UDP.
    /// Returns the raw DNS response message.
    async fn resolve_via_udp_forward(
        &self,
        request: &Message,
    ) -> Result<Message> {
        let query_bytes = request.to_vec()
            .context("Failed to serialize DNS query for UDP forward")?;

        // Try each nameserver in order
        for ns in &self.nameservers {
            match Self::query_nameserver_udp_raw(*ns, &query_bytes).await {
                Ok(response_bytes) => {
                    match Message::from_vec(&response_bytes) {
                        Ok(response) => {
                            debug!("UDP forward received {} answers from {} for {}",
                                   response.answer_count(), ns, response.queries().first().map(|q| q.name().to_ascii()).unwrap_or_default());
                            return Ok(response);
                        }
                        Err(e) => {
                            warn!("Failed to parse UDP DNS response from {}: {}", ns, e);
                        }
                    }
                }
                Err(e) => {
                    debug!("Nameserver {} query failed: {}", ns, e);
                }
            }
        }

        Err(anyhow::anyhow!("All public nameservers failed for UDP forward"))
    }

    /// Send a raw DNS query to a nameserver and return the raw response.
    /// Retries up to 2 times on timeout to handle brief packet loss on congested networks.
    async fn query_nameserver_udp_raw(
        nameserver: SocketAddr,
        query: &[u8],
    ) -> Result<Vec<u8>> {
        const MAX_RETRIES: usize = 2;
        const TIMEOUT_SECS: u64 = 3;

        let mut last_error = None;

        for attempt in 0..=MAX_RETRIES {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(200 * attempt as u64)).await;
            }

            let socket = UdpSocket::bind("0.0.0.0:0").await
                .context("Failed to bind UDP socket for DNS forward")?;

            if let Err(e) = socket.send_to(query, nameserver).await {
                last_error = Some(format!("send failed: {}", e));
                continue;
            }

            let mut buf = [0u8; 4096];
            match tokio::time::timeout(
                std::time::Duration::from_secs(TIMEOUT_SECS),
                socket.recv_from(&mut buf)
            ).await {
                Ok(Ok((len, _))) => return Ok(buf[..len].to_vec()),
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

    /// Resolve via cached DNS resolver (falls back to system DNS on cache miss)
    async fn resolve_via_system(
        &self,
        request: &Message,
        name: &Name,
        query_type: RecordType,
    ) -> Message {
        let domain = name.to_ascii();
        let domain = domain.trim_end_matches('.');

        match self.dns_resolver.resolve(domain, 0).await {
            Ok(addrs) => {
                let mut response = self.make_base_response(request);
                response.set_response_code(ResponseCode::NoError);
                let ttl = self.dns_resolver.get_remaining_ttl(domain).await.unwrap_or(14400);

                for addr in &addrs {
                    match addr.ip() {
                        IpAddr::V4(v4) if query_type == RecordType::A => {
                            let rdata = RData::A(rdata::A(v4));
                            let record = Record::from_rdata(name.clone(), ttl, rdata);
                            let _ = response.add_answer(record);
                        }
                        IpAddr::V6(v6) if query_type == RecordType::AAAA => {
                            let rdata = RData::AAAA(rdata::AAAA(v6));
                            let record = Record::from_rdata(name.clone(), ttl, rdata);
                            let _ = response.add_answer(record);
                        }
                        _ => {}
                    }
                }

                response
            }
            Err(e) => {
                warn!("System DNS resolution failed for bypass domain {}: {}", domain, e);
                self.make_error_response(request, ResponseCode::ServFail)
            }
        }
    }

    /// Determine routing decision for a domain using SplitTunnel
    pub async fn route_query(&self, name: &Name) -> RoutingDecision {
        let domain = name.to_ascii().trim_end_matches('.').to_lowercase();

        // Use SplitTunnel's decide_by_host for routing decision
        let split_tunnel = self.split_tunnel.read().await;
        let decision = split_tunnel.decide_by_host(&domain).await;

        debug!("Domain {} -> {:?} (via SplitTunnel)", domain, decision);
        decision.into()
    }

    fn make_base_response(&self, request: &Message) -> Message {
        let mut response = Message::new();
        response.set_id(request.id());
        response.set_message_type(MessageType::Response);
        response.set_op_code(OpCode::Query);
        response.set_authoritative(false);
        response.set_recursion_desired(request.recursion_desired());
        response.set_recursion_available(true);

        // Copy questions
        for q in request.queries() {
            response.add_query(q.clone());
        }

        response
    }

    fn make_error_response(&self, request: &Message, code: ResponseCode) -> Message {
        let mut response = self.make_base_response(request);
        response.set_response_code(code);
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_routing_decision_with_split_tunnel() {
        use rvpn_client::split_tunnel::SplitTunnelConfig;

        // Create a SplitTunnel config with built-in China domains enabled
        let config = SplitTunnelConfig {
            enabled: true,
            builtin_bypass_countries: vec!["CN".to_string()],
            block_ads: false,
            ..Default::default()
        };

        let split_tunnel = SplitTunnel::new(config, std::sync::Arc::new(rvpn_client::dns_cache::DnsResolver::new(true, 14400, 1000, false, true, vec![]))).await.unwrap();
        let server = DnsServer::new(split_tunnel);

        // Test China domain (should be bypass)
        let name = Name::from_ascii("www.baidu.com").unwrap();
        let decision = server.route_query(&name).await;
        assert_eq!(decision, RoutingDecision::Bypass);

        // Test non-China domain (should be tunnel)
        let name = Name::from_ascii("www.google.com").unwrap();
        let decision = server.route_query(&name).await;
        assert_eq!(decision, RoutingDecision::Tunnel);
    }

    #[tokio::test]
    async fn test_aaaa_filtering() {
        use std::time::Duration;
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use rvpn_client::split_tunnel::SplitTunnelConfig;

        let config = SplitTunnelConfig {
            enabled: true,
            builtin_bypass_countries: vec![],
            block_ads: false,
            ..Default::default()
        };

        let split_tunnel = SplitTunnel::new(
            config,
            std::sync::Arc::new(rvpn_client::dns_cache::DnsResolver::new(true, 14400, 1000, false, true, vec![])),
        ).await.unwrap();
        let server = Arc::new(DnsServer::new(split_tunnel));

        // Bind a server-side socket and a client socket so handle_query can reply.
        let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();

        let mut request = Message::new();
        request.set_id(0xabcd);
        request.set_message_type(MessageType::Query);
        request.set_op_code(OpCode::Query);
        let name = Name::from_ascii("www.google.com").unwrap();
        request.add_query(Query::query(name, RecordType::AAAA));

        server.handle_query(request, client_addr, &server_socket).await.unwrap();

        let mut buf = [0u8; 4096];
        let (len, _) = tokio::time::timeout(
            Duration::from_secs(1),
            client_socket.recv_from(&mut buf),
        ).await.unwrap().unwrap();
        let response = Message::from_vec(&buf[..len]).unwrap();

        assert_eq!(response.response_code(), ResponseCode::NoError);
        assert!(response.answers().is_empty());
    }
}
