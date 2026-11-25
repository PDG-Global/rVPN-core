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

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::doh_client::DohClient;
use crate::route_map::RouteMap;
use rvpn_split_tunnel::{Router, SplitTunnel, RoutingDecision as SplitTunnelRoutingDecision};
use rvpn_split_tunnel::DnsResolver;

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
    /// Multi-server routing table. When set, `Tunnel` decisions are refined
    /// per domain: `router.choose(domain)` may name a secondary exit, whose
    /// DoH client (from `extra_doh_clients`) resolves the query instead of
    /// the default exit's. `None` = single-server, identical to before.
    router: Option<Arc<Router>>,
    /// Per-secondary-exit DoH clients, keyed by exit name. Each keeps its
    /// own persistent `/dns` WebSocket and its own cache.
    extra_doh_clients: HashMap<String, Arc<DohClient>>,
    /// Shared with the uplink demux: every A address in a secondary-exit
    /// answer is recorded here so packets to it take the same exit.
    route_map: Option<Arc<std::sync::Mutex<RouteMap>>>,
    /// Pre-warm hook: called with the exit name when a routed domain is
    /// resolved, so the exit's TUN session starts before its first packet
    /// arrives. Holds a `Weak<IosTunClient>` internally to avoid a
    /// client ↔ DNS server reference cycle.
    prewarm: Option<Arc<dyn Fn(&str) + Send + Sync>>,
    /// Hostnames of the VPN exit servers themselves (default + secondary
    /// exits). These must NEVER resolve through the tunnel: the tunnel's
    /// own reconnect path depends on resolving them, so routing them via
    /// the DoH client is a circular dependency that deadlocks reconnection
    /// whenever the session is down (DoH fails → ServFail → connect fails →
    /// DoH still fails…). They always take the direct-UDP bypass path.
    server_hostnames: Vec<String>,
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
            router: None,
            extra_doh_clients: HashMap::new(),
            route_map: None,
            prewarm: None,
            server_hostnames: Vec::new(),
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
            router: None,
            extra_doh_clients: HashMap::new(),
            route_map: None,
            prewarm: None,
            server_hostnames: Vec::new(),
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
            router: None,
            extra_doh_clients: HashMap::new(),
            route_map: None,
            prewarm: None,
            server_hostnames: Vec::new(),
        }
    }

    /// Enable multi-server exit routing. After this, `Tunnel` decisions are
    /// refined through `router`: domains matching a secondary exit's rules
    /// resolve via that exit's DoH client, their A answers are recorded in
    /// `route_map`, and `prewarm` starts the exit's TUN session.
    pub fn set_multi_exit(
        &mut self,
        router: Arc<Router>,
        extra_doh_clients: HashMap<String, Arc<DohClient>>,
        route_map: Arc<std::sync::Mutex<RouteMap>>,
        prewarm: Arc<dyn Fn(&str) + Send + Sync>,
    ) {
        self.router = Some(router);
        self.extra_doh_clients = extra_doh_clients;
        self.route_map = Some(route_map);
        self.prewarm = Some(prewarm);
    }

    /// Declare the VPN exit servers' own hostnames. Queries for these are
    /// always answered via the direct-UDP bypass path, never the tunnel —
    /// the tunnel's reconnect logic depends on resolving them, so letting
    /// them go through DoH is a circular dependency (dead session → DoH
    /// ServFail → reconnect can't resolve the server → still dead).
    pub fn set_server_hostnames(&mut self, hostnames: Vec<String>) {
        self.server_hostnames = hostnames
            .into_iter()
            .map(|h| h.trim_end_matches('.').to_lowercase())
            .collect();
    }

    /// Pick the exit for a tunneled domain: the router's choice, or `None`
    /// for the default exit / when no router is configured.
    fn choose_exit(&self, domain: &str) -> Option<String> {
        let router = self.router.as_ref()?;
        let chosen = router.choose(domain);
        if chosen == rvpn_split_tunnel::DEFAULT_SERVER_NAME {
            None
        } else {
            Some(chosen.to_string())
        }
    }

    /// Select the DoH client for an exit: `None`/default exit → the primary
    /// client; a named exit → its dedicated client (`None` if somehow
    /// missing — the caller answers ServFail rather than silently falling
    /// back to another exit).
    fn doh_client_for(&self, exit: Option<&str>) -> Option<&Arc<DohClient>> {
        match exit {
            Some(name) => self.extra_doh_clients.get(name),
            None => self.doh_client.as_ref(),
        }
    }

    /// Record a secondary-exit answer: every A address goes into the shared
    /// route map (so the uplink demux sends those flows via this exit), and
    /// the pre-warm hook starts the exit's session. Never called for the
    /// default exit — absence from the route map already means "default".
    fn note_routed_answer(&self, exit: &str, addrs: &[IpAddr], ttl_secs: u32) {
        if let Some(route_map) = &self.route_map {
            let ttl = Duration::from_secs(ttl_secs.max(30) as u64);
            let mut map = route_map.lock().unwrap();
            for addr in addrs {
                if let IpAddr::V4(v4) = addr {
                    map.insert(IpAddr::V4(*v4), exit, ttl);
                }
            }
        }
        if let Some(prewarm) = &self.prewarm {
            prewarm(exit);
        }
    }

    /// Enable or disable AAAA query filtering.
    pub fn set_filter_aaaa(&mut self, enabled: bool) {
        self.filter_aaaa = enabled;
    }

    /// Set custom upstream nameservers for bypass domain resolution.
    /// Accepts strings like "8.8.8.8:53" or "1.1.1.1:53".
    pub fn set_nameservers(&mut self, addrs: &[String]) {
        let parsed: Vec<SocketAddr> = addrs.iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        if !parsed.is_empty() {
            self.nameservers = parsed;
        }
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

    /// Resolve a raw DNS query packet and return the raw DNS response packet.
    ///
    /// This is the synchronous FFI entry point — the NEDNSProxyProvider extension
    /// calls this directly instead of going through a local UDP server.
    pub async fn resolve_raw(&self, query_bytes: &[u8]) -> Result<Vec<u8>> {
        let request = Message::from_vec(query_bytes)
            .context("Failed to parse DNS query")?;

        // Check routing decision
        let queries: Vec<&Query> = request.queries.iter().collect();
        if queries.is_empty() {
            return Err(anyhow::anyhow!("No questions in query"));
        }

        let name = queries[0].name();
        let query_type = queries[0].query_type();
        let domain = name.to_ascii();
        let domain = domain.trim_end_matches('.');

        // Filter AAAA
        if self.filter_aaaa && query_type == RecordType::AAAA {
            let response = self.make_base_response(&request);
            return response.to_vec().context("Failed to serialize AAAA filter response");
        }

        // Route decision
        let decision = {
            let split_tunnel = self.split_tunnel.read().await;
            split_tunnel.decide_by_host(domain).await
        };

        match decision {
            SplitTunnelRoutingDecision::Block => {
                let mut response = self.make_base_response(&request);
                response.metadata.response_code = ResponseCode::NXDomain;
                response.to_vec().context("Failed to serialize block response")
            }
            SplitTunnelRoutingDecision::Bypass => {
                // Forward raw query bytes to upstream DNS and return raw response
                self.forward_raw_dns(query_bytes, request.metadata.id, queries.first().copied())
                    .await
            }
            SplitTunnelRoutingDecision::Tunnel => {
                // Multi-server: a router may steer this domain to a
                // secondary exit; resolve via that exit's DoH client.
                let exit = self.choose_exit(domain);
                // Resolve via DoH and build minimal response
                self.resolve_tunnel_minimal(&request, name, query_type, domain, exit.as_deref()).await
            }
        }
    }

    /// Forward raw DNS query to upstream nameservers and return raw response.
    async fn forward_raw_dns(
        &self,
        query_bytes: &[u8],
        expected_id: u16,
        expected_query: Option<&Query>,
    ) -> Result<Vec<u8>> {
        for ns in &self.nameservers {
            match Self::query_nameserver_udp_raw(*ns, query_bytes, expected_id, expected_query)
                .await
            {
                Ok(response_bytes) => return Ok(response_bytes),
                Err(_) => continue,
            }
        }
        Err(anyhow::anyhow!("All upstream DNS servers failed"))
    }

    /// Resolve a tunnel domain via DoH, returning a minimal response.
    /// `exit` is the chosen secondary exit name (`None` = default exit).
    async fn resolve_tunnel_minimal(&self, request: &Message, name: &Name, query_type: RecordType, domain: &str, exit: Option<&str>) -> Result<Vec<u8>> {
        let qtype_num: u16 = match query_type {
            RecordType::A => 1,
            RecordType::AAAA => 28,
            _ => {
                let response = self.make_base_response(request);
                return response.to_vec().context("Failed to serialize response");
            }
        };

        let client = match self.doh_client_for(exit) {
            Some(c) => c,
            None => {
                if let Some(exit) = exit {
                    warn!("No DoH client for exit '{}' (domain {})", exit, domain);
                }
                let mut response = self.make_base_response(request);
                response.metadata.response_code = ResponseCode::ServFail;
                return response.to_vec().context("Failed to serialize ServFail");
            }
        };

        // Try cache first
        if let Some(cached) = client.lookup_cached(domain, qtype_num).await {
            let ttl = client.get_cached_ttl(domain, qtype_num).await.unwrap_or(14400);
            if let Some(exit) = exit {
                self.note_routed_answer(exit, &cached, ttl);
            }
            let mut response = self.make_base_response(request);
            response.metadata.response_code = ResponseCode::NoError;
            // First matching record only
            for addr in &cached {
                match addr {
                    IpAddr::V4(v4) if query_type == RecordType::A => {
                        response.add_answer(Record::from_rdata(name.clone(), ttl, RData::A(rdata::A(*v4))));
                        break;
                    }
                    IpAddr::V6(v6) if query_type == RecordType::AAAA => {
                        response.add_answer(Record::from_rdata(name.clone(), ttl, RData::AAAA(rdata::AAAA(*v6))));
                        break;
                    }
                    _ => {}
                }
            }
            return response.to_vec().context("Failed to serialize cached response");
        }

        // Cache miss — resolve via DoH
        match client.resolve(domain, qtype_num).await {
            Ok(addrs) => {
                let ttl = client.get_cached_ttl(domain, qtype_num).await.unwrap_or(14400);
                if let Some(exit) = exit {
                    self.note_routed_answer(exit, &addrs, ttl);
                }
                let mut response = self.make_base_response(request);
                response.metadata.response_code = ResponseCode::NoError;
                for addr in &addrs {
                    match addr {
                        IpAddr::V4(v4) if query_type == RecordType::A => {
                            response.add_answer(Record::from_rdata(name.clone(), ttl, RData::A(rdata::A(*v4))));
                            break;
                        }
                        IpAddr::V6(v6) if query_type == RecordType::AAAA => {
                            response.add_answer(Record::from_rdata(name.clone(), ttl, RData::AAAA(rdata::AAAA(*v6))));
                            break;
                        }
                        _ => {}
                    }
                }
                response.to_vec().context("Failed to serialize DoH response")
            }
            Err(e) => {
                warn!("DoH resolution failed for {}: {}", domain, e);
                let mut response = self.make_base_response(request);
                response.metadata.response_code = ResponseCode::ServFail;
                response.to_vec().context("Failed to serialize ServFail")
            }
        }
    }


    /// Try to bind with fallback ports (5453, 5353, 1053, etc.). Port zero
    /// requests one OS-assigned port and never falls back to a fixed port.
    async fn try_bind_with_fallback(primary: SocketAddr) -> Result<UdpSocket> {
        if primary.port() == 0 {
            let socket = UdpSocket::bind(primary)
                .await
                .with_context(|| format!("Failed to bind DNS to {}", primary))?;
            info!("DNS server bound to {}", socket.local_addr()?);
            return Ok(socket);
        }

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
        self.run_with_ready(|_| {}).await
    }

    /// Start the DNS server and report its actual bound address before serving.
    pub async fn run_with_ready<F>(self: Arc<Self>, ready: F) -> Result<()>
    where
        F: FnOnce(SocketAddr) + Send,
    {
        let bind_addr: SocketAddr = self.bind_addr.parse()
            .context("Invalid bind address")?;

        // Try to bind to the address - if primary port fails, try fallback ports
        let socket = Arc::new(
            Self::try_bind_with_fallback(bind_addr).await
                .context("Failed to bind DNS UDP socket on any port")?
        );
        ready(socket.local_addr().context("Failed to read DNS bound address")?);

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
        if request.metadata.message_type != MessageType::Query {
            debug!("Ignoring non-query message");
            return Ok(());
        }

        if request.metadata.op_code != OpCode::Query {
            debug!("Ignoring query with non-standard opcode");
            return Ok(());
        }

        let queries: Vec<&Query> = request.queries.iter().collect();
        if queries.is_empty() {
            debug!("Ignoring query with no questions");
            return Ok(());
        }

        // Handle only the first query
        let query = &queries[0];
        let name = query.name().clone();
        let query_type = query.query_type();

        // Answer root-domain queries locally. The Android service discovers the
        // DNS proxy by probing with a root query and a short timeout — routing
        // it upstream would make discovery depend on DoH health.
        if name.is_root() {
            let response = self.make_base_response(&request);
            let response_bytes = response.to_vec()
                .context("Failed to serialize root probe response")?;
            socket.send_to(&response_bytes, client_addr).await
                .context("Failed to send root probe response")?;
            return Ok(());
        }

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

        // VPN exit server hostnames always resolve via the direct-UDP bypass
        // path — never through the tunnel. The reconnect logic resolves the
        // server hostname while the tunnel is down (and this proxy is the
        // system resolver); sending that query through DoH deadlocks
        // reconnection.
        if self.server_hostnames.iter().any(|h| *h == domain_lower) {
            info!("Routing {} to local resolver (VPN server hostname, never tunneled)", name);
            let response = self.resolve_local(&request, &name, query_type).await;
            let response_bytes = response.to_vec()
                .context("Failed to serialize DNS response")?;
            socket.send_to(&response_bytes, client_addr).await
                .context("Failed to send DNS response")?;
            return Ok(());
        }

        // Make routing decision using SplitTunnel
        let decision = self.route_query(&name).await;
        // Multi-server: refine Tunnel decisions through the exit router.
        let exit = if decision == RoutingDecision::Tunnel {
            self.choose_exit(&domain_lower)
        } else {
            None
        };

        info!("DNS query: {} {:?} from {} → {:?} (exit={:?})", name, query_type, client_addr, decision, exit);

        let response = match decision {
            RoutingDecision::Bypass => {
                info!("Routing {} to local resolver (bypass)", name);
                self.resolve_local(&request, &name, query_type).await
            }
            RoutingDecision::Tunnel => {
                info!("Routing {} to remote DoH (tunnel, exit={:?})", name, exit);
                self.resolve_remote(&request, &name, query_type, exit.as_deref()).await
            }
            RoutingDecision::Block => {
                info!("Blocking {} (ad/tracker)", name);
                self.make_error_response(&request, ResponseCode::NXDomain)
            }
        };

        // Send response back to client
        let response_bytes = response.to_vec()
            .context("Failed to serialize DNS response")?;

        let answer_count = response.answers.len();
        let rcode = response.metadata.response_code;
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

    /// Resolve a domain via the DoH client (tunnel), with caching.
    /// `exit` names the secondary exit to resolve through (`None` = default).
    async fn resolve_remote(
        &self,
        request: &Message,
        name: &Name,
        query_type: RecordType,
        exit: Option<&str>,
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

        let doh_client = match self.doh_client_for(exit) {
            Some(c) => Some(c),
            None => {
                if let Some(exit) = exit {
                    // No DoH client for the named exit — configuration error,
                    // not a fallback. Never silently resolve a routed domain
                    // through the default exit.
                    warn!("No DoH client for exit '{}' (domain {})", exit, domain);
                    return self.make_error_response(request, ResponseCode::ServFail);
                }
                None
            }
        };

        // Check DoH client cache first (this is the authoritative cache for
        // tunnel-domain DNS results). The DnsResolver cache uses a different
        // key format and would always miss, so we skip it.
        if let Some(client) = doh_client {
            if let Some(cached) = client.lookup_cached(domain, qtype_num).await {
                debug!("DoH cache hit for tunnel domain {}", domain);
                let mut response = self.make_base_response(request);
                response.metadata.response_code = ResponseCode::NoError;
                // Use DoH client's TTL (capped to reasonable max)
                let ttl = client.get_cached_ttl(domain, qtype_num).await.unwrap_or(14400);

                if let Some(exit) = exit {
                    // Refresh the route map from the cached answer — the map's
                    // entries may expire while the DoH cache entry lives on.
                    self.note_routed_answer(exit, &cached, ttl);
                }

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

                if response.answers.is_empty() {
                    debug!("No records of requested type for {}", domain);
                    response.metadata.response_code = ResponseCode::NoError;
                }
                return response;
            }
        }

        match doh_client {
            Some(client) => {
                match client.resolve(domain, qtype_num).await {
                    Ok(addrs) => {
                        let mut response = self.make_base_response(request);
                        response.metadata.response_code = ResponseCode::NoError;
                        // Use the actual TTL from the DoH response (cached by the client)
                        let ttl = client.get_cached_ttl(domain, qtype_num).await.unwrap_or(14400);

                        if let Some(exit) = exit {
                            self.note_routed_answer(exit, &addrs, ttl);
                        }

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

                        if response.answers.is_empty() {
                            debug!("No records of requested type for {}", domain);
                            response.metadata.response_code = ResponseCode::NoError;
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
                response.metadata.response_code = ResponseCode::NoError;
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
                if !response.answers.is_empty() {
                    debug!("DNS cache hit for bypass domain {} ({} answers)", domain, response.answers.len());
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
                for record in &response.answers {
                    match &record.data {
                        RData::A(a) => {
                            ips.push(IpAddr::V4(a.0));
                            min_ttl = min_ttl.min(record.ttl);
                        }
                        RData::AAAA(aaaa) => {
                            ips.push(IpAddr::V6(aaaa.0));
                            min_ttl = min_ttl.min(record.ttl);
                        }
                        _ => {}
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
        let expected_id = request.metadata.id;
        let expected_query = request.queries.first();

        // Try each nameserver in order
        for ns in &self.nameservers {
            match Self::query_nameserver_udp_raw(*ns, &query_bytes, expected_id, expected_query)
                .await
            {
                Ok(response_bytes) => {
                    match Message::from_vec(&response_bytes) {
                        Ok(response) => {
                            debug!("UDP forward received {} answers from {} for {}",
                                   response.answers.len(), ns, response.queries.first().map(|q| q.name().to_ascii()).unwrap_or_default());
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
    ///
    /// The socket is connected() to the nameserver, so the kernel only delivers
    /// datagrams from that address, and a reply is accepted only if it parses as
    /// a DNS message whose transaction ID equals `expected_id` and whose first
    /// question matches `expected_query` (name — case-insensitive, per hickory's
    /// `Name` equality — and query type). Datagrams that fail these checks, e.g.
    /// a racing off-path spoof, are dropped and the wait continues within the
    /// same per-attempt timeout.
    async fn query_nameserver_udp_raw(
        nameserver: SocketAddr,
        query: &[u8],
        expected_id: u16,
        expected_query: Option<&Query>,
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

            if let Err(e) = socket.connect(nameserver).await {
                last_error = Some(format!("connect failed: {}", e));
                continue;
            }

            if let Err(e) = socket.send(query).await {
                last_error = Some(format!("send failed: {}", e));
                continue;
            }

            let mut buf = [0u8; 4096];
            let recv = tokio::time::timeout(
                std::time::Duration::from_secs(TIMEOUT_SECS),
                async {
                    loop {
                        let len = socket.recv(&mut buf).await?;
                        let datagram = &buf[..len];
                        match Message::from_vec(datagram) {
                            Ok(response) => {
                                if response.metadata.id != expected_id {
                                    debug!(
                                        "Dropping DNS reply from {} with mismatched TXID {:#06x} (expected {:#06x})",
                                        nameserver, response.metadata.id, expected_id
                                    );
                                    continue;
                                }
                                if let Some(expected) = expected_query {
                                    let question_matches = response.queries.first()
                                        .map(|q| q.name() == expected.name() && q.query_type() == expected.query_type())
                                        .unwrap_or(false);
                                    if !question_matches {
                                        debug!(
                                            "Dropping DNS reply from {} with mismatched question",
                                            nameserver
                                        );
                                        continue;
                                    }
                                }
                                return Ok::<Vec<u8>, std::io::Error>(datagram.to_vec());
                            }
                            Err(e) => {
                                debug!("Dropping unparseable DNS datagram from {}: {}", nameserver, e);
                                continue;
                            }
                        }
                    }
                }
            ).await;
            match recv {
                Ok(Ok(bytes)) => return Ok(bytes),
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
                response.metadata.response_code = ResponseCode::NoError;
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
        let mut response = Message::new(request.metadata.id, MessageType::Response, OpCode::Query);
        response.metadata.authoritative = false;
        response.metadata.recursion_desired = request.metadata.recursion_desired;
        response.metadata.recursion_available = true;

        // Copy questions
        for q in &request.queries {
            response.add_query(q.clone());
        }

        response
    }

    fn make_error_response(&self, request: &Message, code: ResponseCode) -> Message {
        let mut response = self.make_base_response(request);
        response.metadata.response_code = code;
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal UDP nameserver for tests: answers A queries from a fixed map so
    /// the routing tests don't depend on live DNS. GeoDNS would otherwise make
    /// the builtin-bypass decision depend on where the test runs — a resolver
    /// outside China gets non-CN IPs back for CN domains, and the rebinding
    /// guard then (correctly) routes them through the tunnel.
    async fn spawn_fake_nameserver(
        answers: std::collections::HashMap<String, std::net::Ipv4Addr>,
    ) -> std::net::SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let q = &buf[..n];
                if n < 12 {
                    continue;
                }
                // Extract the QNAME from the query.
                let mut pos = 12;
                let mut name = String::new();
                while pos < n && q[pos] != 0 {
                    let len = q[pos] as usize;
                    pos += 1;
                    if pos + len > n {
                        break;
                    }
                    if !name.is_empty() {
                        name.push('.');
                    }
                    name.push_str(&String::from_utf8_lossy(&q[pos..pos + len]));
                    pos += len;
                }
                let mut resp = Vec::with_capacity(64);
                resp.extend_from_slice(&[q[0], q[1]]); // echo TXID
                resp.extend_from_slice(&[0x81, 0x80]); // QR|RD|RA, RCODE=0
                resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT
                let ip = answers.get(&name);
                resp.extend_from_slice(&(ip.is_some() as u16).to_be_bytes()); // ANCOUNT
                resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT/ARCOUNT
                resp.extend_from_slice(&q[12..]); // echo question
                if let Some(ip) = ip {
                    resp.extend_from_slice(&[0xC0, 0x0C]); // name -> question
                    resp.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
                    resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
                    resp.extend_from_slice(&[0x00, 0x04]); // RDLENGTH
                    resp.extend_from_slice(&ip.octets());
                }
                let _ = sock.send_to(&resp, peer).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_routing_decision_with_split_tunnel() {
        use rvpn_split_tunnel::SplitTunnelConfig;
        use std::collections::HashMap;

        // Create a SplitTunnel config with built-in China domains enabled
        let config = SplitTunnelConfig {
            enabled: true,
            builtin_bypass_countries: vec!["CN".to_string()],
            block_ads: false,
            ..Default::default()
        };

        // 223.5.5.5 (AliDNS) is inside the builtin CN CIDR set, 8.8.8.8 is
        // not. The bypass arm exercises the same CIDR lookup the bypass path
        // uses, so a list update that drops these fixtures fails loudly here
        // instead of silently changing what the test means.
        let cn_ip: std::net::Ipv4Addr = "223.5.5.5".parse().unwrap();
        let edge_ip: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();

        // Builtin China domain whose resolved IPs are in China: bypass.
        let ns = spawn_fake_nameserver(HashMap::from([("www.baidu.com".to_string(), cn_ip)])).await;
        let split_tunnel = SplitTunnel::new(config.clone(), std::sync::Arc::new(rvpn_split_tunnel::DnsResolver::new(true, 14400, 1000, false, true, vec![ns]))).await.unwrap();
        let server = DnsServer::new(split_tunnel);
        let name = Name::from_ascii("www.baidu.com").unwrap();
        assert_eq!(server.route_query(&name).await, RoutingDecision::Bypass);

        // DNS-rebinding guard: the same domain, but the resolved IPs are
        // outside China — it must go through the tunnel, not bypass.
        let ns = spawn_fake_nameserver(HashMap::from([("www.baidu.com".to_string(), edge_ip)])).await;
        let split_tunnel = SplitTunnel::new(config.clone(), std::sync::Arc::new(rvpn_split_tunnel::DnsResolver::new(true, 14400, 1000, false, true, vec![ns]))).await.unwrap();
        let server = DnsServer::new(split_tunnel);
        assert_eq!(server.route_query(&name).await, RoutingDecision::Tunnel);

        // Non-China domain stays in the tunnel.
        let ns = spawn_fake_nameserver(HashMap::new()).await;
        let split_tunnel = SplitTunnel::new(config, std::sync::Arc::new(rvpn_split_tunnel::DnsResolver::new(true, 14400, 1000, false, true, vec![ns]))).await.unwrap();
        let server = DnsServer::new(split_tunnel);
        let name = Name::from_ascii("www.google.com").unwrap();
        assert_eq!(server.route_query(&name).await, RoutingDecision::Tunnel);
    }

    #[tokio::test]
    async fn test_full_tunnel_never_uses_split_dns_bypass() {
        let config = rvpn_split_tunnel::SplitTunnelConfig {
            enabled: false,
            builtin_bypass_countries: vec!["CN".to_string()],
            block_ads: false,
            ..Default::default()
        };
        let split_tunnel = SplitTunnel::new(
            config,
            Arc::new(rvpn_split_tunnel::DnsResolver::new(true, 14400, 1000, false, true, vec![])),
        ).await.unwrap();
        let server = DnsServer::new(split_tunnel);

        let name = Name::from_ascii("www.baidu.com").unwrap();
        assert_eq!(server.route_query(&name).await, RoutingDecision::Tunnel);
    }

    #[tokio::test]
    async fn test_zero_port_reports_os_assigned_ready_address() {
        let server = Arc::new(DnsServer::with_bind_addr(
            test_split_tunnel().await,
            "127.0.0.1:0".to_string(),
        ));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            server.run_with_ready(move |addr| {
                let _ = ready_tx.send(addr);
            }).await
        });

        let addr = tokio::time::timeout(Duration::from_secs(1), ready_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(addr.ip(), IpAddr::from([127, 0, 0, 1]));
        assert_ne!(addr.port(), 0);
        assert!(![5353, 1053, 15353, 1153].contains(&addr.port()));

        task.abort();
        let _ = task.await;
    }

    #[tokio::test]
    async fn test_root_query_answered_locally() {
        use std::time::Duration;
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use rvpn_split_tunnel::SplitTunnelConfig;

        let config = SplitTunnelConfig {
            enabled: true,
            builtin_bypass_countries: vec![],
            block_ads: false,
            ..Default::default()
        };

        let split_tunnel = SplitTunnel::new(
            config,
            std::sync::Arc::new(rvpn_split_tunnel::DnsResolver::new(true, 14400, 1000, false, true, vec![])),
        ).await.unwrap();
        let server = Arc::new(DnsServer::new(split_tunnel));

        let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();

        // Root queries are answered locally, never routed upstream.
        let mut request = Message::new(0x1234, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(Name::root(), RecordType::A));

        server.handle_query(request, client_addr, &server_socket).await.unwrap();

        let mut buf = [0u8; 4096];
        let (len, _) = tokio::time::timeout(
            Duration::from_millis(500),
            client_socket.recv_from(&mut buf),
        ).await.unwrap().unwrap();
        let response = Message::from_vec(&buf[..len]).unwrap();

        assert_eq!(response.metadata.id, 0x1234);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    }

    #[tokio::test]
    async fn test_aaaa_filtering() {
        use std::time::Duration;
        use hickory_proto::op::{Message, MessageType, OpCode, Query};
        use rvpn_split_tunnel::SplitTunnelConfig;

        let config = SplitTunnelConfig {
            enabled: true,
            builtin_bypass_countries: vec![],
            block_ads: false,
            ..Default::default()
        };

        let split_tunnel = SplitTunnel::new(
            config,
            std::sync::Arc::new(rvpn_split_tunnel::DnsResolver::new(true, 14400, 1000, false, true, vec![])),
        ).await.unwrap();
        let server = Arc::new(DnsServer::new(split_tunnel));

        // Bind a server-side socket and a client socket so handle_query can reply.
        let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();

        let mut request = Message::new(0xabcd, MessageType::Query, OpCode::Query);
        let name = Name::from_ascii("www.google.com").unwrap();
        request.add_query(Query::query(name, RecordType::AAAA));

        server.handle_query(request, client_addr, &server_socket).await.unwrap();

        let mut buf = [0u8; 4096];
        let (len, _) = tokio::time::timeout(
            Duration::from_secs(1),
            client_socket.recv_from(&mut buf),
        ).await.unwrap().unwrap();
        let response = Message::from_vec(&buf[..len]).unwrap();

        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
    }

    async fn test_split_tunnel() -> SplitTunnel {
        use rvpn_split_tunnel::SplitTunnelConfig;
        let config = SplitTunnelConfig {
            enabled: true,
            builtin_bypass_countries: vec![],
            block_ads: false,
            ..Default::default()
        };
        SplitTunnel::new(
            config,
            std::sync::Arc::new(rvpn_split_tunnel::DnsResolver::new(true, 14400, 1000, false, true, vec![])),
        ).await.unwrap()
    }

    #[tokio::test]
    async fn test_choose_exit_without_router_is_default() {
        let server = DnsServer::new(test_split_tunnel().await);
        assert_eq!(server.choose_exit("anything.example.com"), None);
    }

    #[tokio::test]
    async fn test_choose_exit_with_router() {
        use rvpn_split_tunnel::{Router, RoutingRule, DEFAULT_SERVER_NAME};

        let mut routing: std::collections::HashMap<String, RoutingRule> = std::collections::HashMap::new();
        routing.insert("sg".to_string(), RoutingRule {
            domains: vec!["routed.example.com".to_string()],
            ips: vec![],
        });
        let router = Arc::new(Router::build(&[DEFAULT_SERVER_NAME, "sg"], &routing).unwrap());
        let route_map = Arc::new(std::sync::Mutex::new(crate::route_map::RouteMap::new()));
        let prewarm: Arc<dyn Fn(&str) + Send + Sync> = Arc::new(|_| {});

        let mut server = DnsServer::new(test_split_tunnel().await);
        server.set_multi_exit(router, HashMap::new(), route_map, prewarm);

        assert_eq!(
            server.choose_exit("www.routed.example.com").as_deref(),
            Some("sg")
        );
        // Apex matches too (Suffix rule).
        assert_eq!(
            server.choose_exit("routed.example.com").as_deref(),
            Some("sg")
        );
        // Unmatched domains stay on the default exit.
        assert_eq!(server.choose_exit("other.example.org"), None);
    }

    #[tokio::test]
    async fn test_note_routed_answer_records_a_only_and_prewarms() {
        use rvpn_split_tunnel::{Router, RoutingRule, DEFAULT_SERVER_NAME};

        let mut routing: std::collections::HashMap<String, RoutingRule> = std::collections::HashMap::new();
        routing.insert("sg".to_string(), RoutingRule::default());
        let router = Arc::new(Router::build(&[DEFAULT_SERVER_NAME, "sg"], &routing).unwrap());
        let route_map = Arc::new(std::sync::Mutex::new(crate::route_map::RouteMap::new()));
        let prewarm_calls = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let calls = Arc::clone(&prewarm_calls);
        let prewarm: Arc<dyn Fn(&str) + Send + Sync> =
            Arc::new(move |exit: &str| calls.lock().unwrap().push(exit.to_string()));

        let mut server = DnsServer::new(test_split_tunnel().await);
        server.set_multi_exit(router, HashMap::new(), Arc::clone(&route_map), prewarm);

        let v4: IpAddr = "203.0.113.7".parse().unwrap();
        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        server.note_routed_answer("sg", &[v4, v6], 300);

        // A address recorded with the exit; AAAA is not (the uplink demux is
        // IPv4-only). Absence = default, so default answers are never here.
        assert_eq!(
            route_map.lock().unwrap().lookup(&v4).as_deref(),
            Some("sg")
        );
        assert_eq!(route_map.lock().unwrap().lookup(&v6), None);
        assert_eq!(prewarm_calls.lock().unwrap().as_slice(), &["sg".to_string()]);
    }

    /// Fake nameserver for the spoof test: on each query it sends, in order,
    /// (1) a poisoned reply from a DIFFERENT socket (different source port —
    /// with a connected socket the kernel never delivers it), (2) a reply with
    /// the wrong TXID from the nameserver address, (3) a reply with the wrong
    /// question from the nameserver address, and finally (4) the genuine
    /// reply. Sends are spaced so the datagrams arrive in order.
    async fn spawn_spoofing_nameserver(
        genuine_ip: std::net::Ipv4Addr,
        poison_ip: std::net::Ipv4Addr,
        wrong_question: Name,
    ) -> std::net::SocketAddr {
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            while let Ok((n, peer)) = sock.recv_from(&mut buf).await {
                let Ok(request) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let id = request.metadata.id;
                let Some(query) = request.queries.first().cloned() else {
                    continue;
                };

                let make_reply = |txid: u16, q: &Query, ip: std::net::Ipv4Addr| {
                    let mut reply = Message::new(txid, MessageType::Response, OpCode::Query);
                    reply.metadata.recursion_available = true;
                    reply.add_query(q.clone());
                    reply.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::A(rdata::A(ip)),
                    ));
                    reply.to_vec().unwrap()
                };

                // (1) Poisoned reply from a different source port.
                let spoofer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let _ = spoofer
                    .send_to(&make_reply(id, &query, poison_ip), peer)
                    .await;
                tokio::time::sleep(Duration::from_millis(50)).await;

                // (2) Wrong TXID from the real nameserver address.
                let _ = sock
                    .send_to(&make_reply(id.wrapping_add(1), &query, poison_ip), peer)
                    .await;
                tokio::time::sleep(Duration::from_millis(20)).await;

                // (3) Wrong question from the real nameserver address.
                let wrong_query = Query::query(wrong_question.clone(), RecordType::A);
                let _ = sock
                    .send_to(&make_reply(id, &wrong_query, poison_ip), peer)
                    .await;
                tokio::time::sleep(Duration::from_millis(20)).await;

                // (4) Genuine reply.
                let _ = sock
                    .send_to(&make_reply(id, &query, genuine_ip), peer)
                    .await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn test_udp_forward_rejects_spoofed_replies() {
        let genuine_ip: std::net::Ipv4Addr = "203.0.113.10".parse().unwrap();
        let poison_ip: std::net::Ipv4Addr = "203.0.113.99".parse().unwrap();
        let wrong_question = Name::from_ascii("other.example.com.").unwrap();
        let ns = spawn_spoofing_nameserver(genuine_ip, poison_ip, wrong_question).await;

        // Build the query, then re-parse the serialized bytes so the expected
        // question has the wire (FQDN) form — exactly as in production, where
        // the request is parsed from received bytes.
        let name = Name::from_ascii("www.example.com.").unwrap();
        let mut request = Message::new(0x4242, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(name, RecordType::A));
        let query_bytes = request.to_vec().unwrap();
        let parsed = Message::from_vec(&query_bytes).unwrap();
        let expected_query = parsed.queries[0].clone();

        let response_bytes =
            DnsServer::query_nameserver_udp_raw(ns, &query_bytes, 0x4242, Some(&expected_query))
                .await
                .unwrap();
        let response = Message::from_vec(&response_bytes).unwrap();

        // The wrong-source-port, wrong-TXID, and wrong-question replies must
        // all be rejected; only the genuine answer is accepted.
        assert_eq!(response.metadata.id, 0x4242);
        assert_eq!(response.answers.len(), 1);
        match &response.answers[0].data {
            RData::A(a) => assert_eq!(a.0, genuine_ip, "accepted a spoofed reply"),
            other => panic!("expected A record, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_blocked_domain_returns_nxdomain() {
        use rvpn_split_tunnel::SplitTunnelConfig;

        // Custom ad-block list with one domain, so decide_by_host returns
        // Block for it (block_ads must be on for the list to apply).
        let block_file =
            std::env::temp_dir().join(format!("rvpn-dns-test-block-{}.txt", std::process::id()));
        std::fs::write(&block_file, "ads.example.com\n").unwrap();

        let config = SplitTunnelConfig {
            enabled: true,
            block_ads: true,
            ad_block_file: Some(block_file.clone()),
            ..Default::default()
        };
        let split_tunnel = SplitTunnel::new(
            config,
            Arc::new(rvpn_split_tunnel::DnsResolver::new(
                true,
                14400,
                1000,
                false,
                true,
                vec![],
            )),
        )
        .await
        .unwrap();
        let server = DnsServer::new(split_tunnel);

        let mut request = Message::new(0x7777, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(
            Name::from_ascii("ads.example.com").unwrap(),
            RecordType::A,
        ));
        let response_bytes = server
            .resolve_raw(&request.to_vec().unwrap())
            .await
            .unwrap();
        let response = Message::from_vec(&response_bytes).unwrap();

        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(response.metadata.id, 0x7777);

        let _ = std::fs::remove_file(&block_file);
    }

    #[tokio::test]
    async fn test_doh_failure_returns_servfail() {
        use rvpn_core::crypto::{IdentityKey, X3DHResponder};

        // A DoH client whose connection task was never started: resolve()
        // fails immediately ("DNS client not started"), exercising the
        // DoH-failure → ServFail arm of the tunnel path.
        let server_bundle = X3DHResponder::new().get_public_bundle();
        let security =
            crate::server_hello::ServerSecurity::new(None, false, &server_bundle).unwrap();
        let flow_config = crate::flow_connector::FlowConnectorConfig {
            server_host: "127.0.0.1".to_string(),
            server_port: 1,
            server_path: "/dns".to_string(),
            tls_fingerprint: rvpn_tls::TlsFingerprint::Chrome,
            identity_key: Arc::new(IdentityKey::generate()),
            server_bundle,
            security,
            #[cfg(any(feature = "ios-direct-tun", feature = "macos-direct-tun"))]
            resumption: None,
        };
        let doh_client = Arc::new(DohClient::new(flow_config, "/dns".to_string()));

        let server = DnsServer::with_doh(
            test_split_tunnel().await,
            doh_client,
            "127.0.0.1:0".to_string(),
        );

        let name = Name::from_ascii("www.google.com").unwrap();
        let mut request = Message::new(0x4321, MessageType::Query, OpCode::Query);
        request.add_query(Query::query(name.clone(), RecordType::A));

        let response = server
            .resolve_remote(&request, &name, RecordType::A, None)
            .await;
        assert_eq!(response.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(response.metadata.id, 0x4321);
    }
}
