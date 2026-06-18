// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DNS-over-WebSocket proxy for desktop SOCKS5 mode
//
// Listens on UDP, forwards DNS queries through the server's encrypted /dns
// WebSocket endpoint. Maintains a persistent connection with auto-reconnect
// and supports concurrent queries via an internal query_id map.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

use rvpn_core::crypto::{DoubleRatchet, IdentityKey, X3DHPublicBundle};
use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::crypto::ratchet::RatchetMessage;
use rvpn_core::protocol::HandshakeMessage;
use rvpn_core::protocol::message::{DnsQuery, DnsResponse};

use crate::dns_cache::DnsResolver;
use crate::split_tunnel::{RoutingDecision, SplitTunnel};
use crate::tls_boring::TlsFingerprint;
use crate::websocket::{connect_websocket, split_websocket, Message, WebSocketReader, WebSocketWriter};

/// Payload type bytes for DNS messages — must match server's DnsHandler
const PAYLOAD_DNS_QUERY: u8 = 0x08;
const PAYLOAD_DNS_RESPONSE: u8 = 0x09;

/// Internal message type: (query, dns_txid_for_reply, client_addr, reply_channel)
type QueryMsg = (DnsQuery, u16, SocketAddr, oneshot::Sender<Option<DnsResponse>>);

/// DNS-over-WebSocket proxy
///
/// Listens for UDP DNS queries on a local port and resolves them through
/// the VPN server's encrypted WebSocket `/dns` endpoint.
///
/// When split tunnel is enabled, bypass/block domains are handled locally
/// without touching the tunnel.
pub struct DnsProxy {
    listen_addr: SocketAddr,
    server_host: String,
    server_port: u16,
    /// Full path to the DNS endpoint, e.g. "/api/v1/ws/dns"
    server_dns_path: String,
    tls_fingerprint: TlsFingerprint,
    identity_key: Arc<IdentityKey>,
    server_bundle: Arc<X3DHPublicBundle>,
    split_tunnel: Arc<SplitTunnel>,
    next_id: AtomicU64,
    /// DNS resolver with caching for both local and tunnel responses
    dns_resolver: Arc<DnsResolver>,
    /// Public nameservers for bypass domain resolution (direct UDP, avoids loopback)
    nameservers: Vec<SocketAddr>,
}

impl DnsProxy {
    pub fn new(
        listen_addr: SocketAddr,
        server_host: String,
        server_port: u16,
        server_path: &str,
        tls_fingerprint: TlsFingerprint,
        identity_key: Arc<IdentityKey>,
        server_bundle: Arc<X3DHPublicBundle>,
        split_tunnel: Arc<SplitTunnel>,
        dns_resolver: Arc<DnsResolver>,
        nameservers: Vec<SocketAddr>,
    ) -> Self {
        // Derive DNS path from base WebSocket path, stripping any mux/tun suffix
        let base_path = server_path.trim_end_matches('/');
        let base_path = base_path
            .strip_suffix("/mux")
            .or_else(|| base_path.strip_suffix("/tun"))
            .unwrap_or(base_path);
        let server_dns_path = format!("{}/dns", base_path);
        Self {
            listen_addr,
            server_host,
            server_port,
            server_dns_path,
            tls_fingerprint,
            identity_key,
            server_bundle,
            split_tunnel,
            next_id: AtomicU64::new(1),
            dns_resolver,
            nameservers,
        }
    }

    /// Start the DNS proxy (runs indefinitely, returns only on fatal error)
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let socket = Arc::new(
            UdpSocket::bind(self.listen_addr)
                .await
                .with_context(|| format!("Failed to bind DNS proxy to {}", self.listen_addr))?,
        );

        info!("DNS proxy listening on {}", self.listen_addr);

        // Channel: UDP tasks → WebSocket connection manager
        let (query_tx, query_rx) = mpsc::unbounded_channel::<QueryMsg>();

        // WebSocket connection manager (runs in background, reconnects on failure)
        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            self_clone.run_ws_manager(query_rx).await;
        });

        // UDP receive loop
        let mut buf = [0u8; 512];
        loop {
            let (n, src) = socket.recv_from(&mut buf).await?;
            let data = buf[..n].to_vec();
            let socket_clone = Arc::clone(&socket);
            let query_tx_clone = query_tx.clone();
            let qid = self.next_id.fetch_add(1, Ordering::Relaxed);

            let split_tunnel_clone = Arc::clone(&self.split_tunnel);
            let dns_resolver_clone = Arc::clone(&self.dns_resolver);
            let nameservers_clone = self.nameservers.clone();
            tokio::spawn(async move {
                match parse_dns_query(&data) {
                    Ok((dns_txid, domain, qtype)) => {
                        debug!("DNS query from {}: {} (type={})", src, domain, qtype);

                        let wire = match split_tunnel_clone.decide_by_host(&domain).await {
                            RoutingDecision::Bypass => {
                                // Resolve locally — bypass domain should not go through tunnel
                                debug!("DNS proxy: resolving {} locally (bypass)", domain);
                                let wire = match resolve_locally(
                                    &data, dns_txid, &domain, qtype, &nameservers_clone
                                ).await {
                                    Ok(wire) => {
                                        // Parse and cache successful bypass responses
                                        if let Ok((ips, ttl_secs)) = crate::dns_cache::parse_dns_a_response(&wire, dns_txid) {
                                            let ttl = std::time::Duration::from_secs(ttl_secs as u64);
                                            dns_resolver_clone.store_with_ttl(&domain, ips, ttl).await;
                                        }
                                        wire
                                    }
                                    Err(e) => {
                                        warn!("DNS proxy: local resolution failed for {}: {}", domain, e);
                                        build_dns_servfail(&data, dns_txid)
                                    }
                                };
                                wire
                            }
                            RoutingDecision::Block => {
                                // Return NXDOMAIN — treat blocked ad/tracker as non-existent
                                debug!("DNS proxy: blocking {} (ad/tracker)", domain);
                                build_dns_nxdomain(&data, dns_txid)
                            }
                            RoutingDecision::Tunnel => {
                                // Check local cache before forwarding through tunnel
                                if let Some(ips) = dns_resolver_clone.lookup_cached(&domain).await {
                                    debug!("DNS proxy: cache hit for {}, skipping tunnel", domain);
                                    let ipv4_addrs: Vec<std::net::Ipv4Addr> = ips
                                        .iter()
                                        .filter_map(|ip| match ip {
                                            IpAddr::V4(v4) => Some(*v4),
                                            _ => None,
                                        })
                                        .collect();
                                    // Use the actual remaining TTL from the cache entry
                                    let ttl = dns_resolver_clone.get_remaining_ttl(&domain).await.unwrap_or(14400);
                                    let response = DnsResponse {
                                        query_id: 0,
                                        success: true,
                                        ipv4_addrs,
                                        ipv6_addrs: vec![],
                                        ttl,
                                        error: None,
                                    };
                                    let wire = build_dns_response(&data, dns_txid, &response);
                                    if let Err(e) = socket_clone.send_to(&wire, src).await {
                                        debug!("DNS proxy: failed to send cached response to {}: {}", src, e);
                                    }
                                    return;
                                }

                                // Forward through encrypted WebSocket tunnel
                                let query = DnsQuery {
                                    query_id: qid,
                                    domain: domain.clone(),
                                    query_type: qtype,
                                };
                                let (reply_tx, reply_rx) = oneshot::channel();
                                if query_tx_clone.send((query, dns_txid, src, reply_tx)).is_err() {
                                    return; // proxy shutting down
                                }
                                // 5s timeout — if the WebSocket is zombie (protocol alive but
                                // server not responding), don't hang the DNS client forever.
                                match tokio::time::timeout(tokio::time::Duration::from_secs(5), reply_rx).await {
                                    Ok(Ok(Some(r))) => build_dns_response(&data, dns_txid, &r),
                                    _ => build_dns_servfail(&data, dns_txid),
                                }
                            }
                        };

                        if let Err(e) = socket_clone.send_to(&wire, src).await {
                            debug!("DNS proxy: failed to send response to {}: {}", src, e);
                        }
                    }
                    Err(e) => {
                        warn!("DNS proxy: failed to parse query from {}: {}", src, e);
                    }
                }
            });
        }
    }

    /// Connection manager loop — reconnects on failure with exponential backoff
    async fn run_ws_manager(self: Arc<Self>, mut query_rx: mpsc::UnboundedReceiver<QueryMsg>) {
        let mut backoff_secs: u64 = 2;

        loop {
            match self.run_ws_session(&mut query_rx).await {
                Ok(_) => {
                    info!(
                        "DNS proxy: WebSocket closed, reconnecting in {}s...",
                        backoff_secs
                    );
                    backoff_secs = 2; // reset on clean close
                }
                Err(e) => {
                    warn!(
                        "DNS proxy: WebSocket error: {}, reconnecting in {}s...",
                        e, backoff_secs
                    );
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_secs(backoff_secs)).await;
            backoff_secs = (backoff_secs * 2).min(30);
        }
    }

    /// Single WebSocket session: connect, handshake, process queries until closed
    async fn run_ws_session(
        &self,
        query_rx: &mut mpsc::UnboundedReceiver<QueryMsg>,
    ) -> Result<()> {
        let ws = connect_websocket(
            &self.server_host,
            self.server_port,
            &self.server_dns_path,
            self.tls_fingerprint,
            None, // SNI hostname not needed for DNS proxy (connects to same server)
        )
        .await
        .context("DNS proxy: WebSocket connect failed")?;

        let (mut reader, writer) = split_websocket(ws);

        let mut ratchet = dns_handshake(&mut reader, &writer, &self.identity_key, &self.server_bundle)
            .await
            .context("DNS proxy: X3DH handshake failed")?;

        info!(
            "DNS proxy: connected to {}{}",
            self.server_host, self.server_dns_path
        );

        // Drain any stale queries that were buffered while disconnected.
        // Their UDP handlers have already timed out (5s), so responses
        // would be ignored anyway. Prevents stale burst on fresh connection.
        let mut drained = 0;
        while let Ok((_, _, _, reply_tx)) = query_rx.try_recv() {
            let _ = reply_tx.send(None);
            drained += 1;
        }
        if drained > 0 {
            warn!("DNS proxy: drained {} stale queries from disconnect buffer", drained);
        }

        /// Pending query with metadata needed for caching and timeout detection
        struct PendingQuery {
            tx: oneshot::Sender<Option<DnsResponse>>,
            domain: String,
            sent_at: Instant,
        }

        // Pending queries: query_id → pending query
        let mut pending: HashMap<u64, PendingQuery> = HashMap::new();

        // Persistent interval for checking pending query age. Using a persistent
        // interval (not tokio::time::sleep inside select!) ensures the check fires
        // regularly even when other branches (reader.recv, query_rx) fire frequently.
        let mut check_interval = tokio::time::interval(Duration::from_secs(10));
        check_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                // Outgoing: new DNS query from UDP handler
                msg = query_rx.recv() => {
                    match msg {
                        Some((query, _dns_txid, _src, reply_tx)) => {
                            let query_id = query.query_id;

                            let query_bytes = serde_json::to_vec(&query)
                                .context("DNS proxy: failed to serialize DnsQuery")?;

                            let encrypted = ratchet
                                .encrypt(&query_bytes, &[PAYLOAD_DNS_QUERY])
                                .map_err(|e| anyhow::anyhow!("DNS proxy: encrypt failed: {:?}", e))?;

                            let serialized = encrypted
                                .to_bytes()
                                .context("DNS proxy: failed to serialize RatchetMessage")?;

                            writer
                                .send(Message::Binary(serialized))
                                .context("DNS proxy: failed to send query")?;

                            pending.insert(query_id, PendingQuery {
                                tx: reply_tx,
                                domain: query.domain,
                                sent_at: Instant::now(),
                            });
                        }
                        None => break, // channel closed (proxy shutting down)
                    }
                }

                // Incoming: response from server (with 120s read timeout as backstop)
                response = tokio::time::timeout(Duration::from_secs(120), reader.recv()) => {
                    match response {
                        Ok(Some(Message::Binary(data))) => {
                            let ratchet_msg = match RatchetMessage::from_bytes(&data) {
                                Ok(m) => m,
                                Err(e) => {
                                    warn!("DNS proxy: failed to parse RatchetMessage: {}", e);
                                    continue;
                                }
                            };

                            let plaintext = match ratchet.decrypt(&ratchet_msg, &[PAYLOAD_DNS_RESPONSE]) {
                                Ok(p) => p,
                                Err(e) => {
                                    warn!("DNS proxy: decryption failed: {:?}", e);
                                    continue;
                                }
                            };

                            let dns_response: DnsResponse = match serde_json::from_slice(&plaintext) {
                                Ok(r) => r,
                                Err(e) => {
                                    warn!("DNS proxy: failed to parse DnsResponse: {}", e);
                                    continue;
                                }
                            };

                            let qid = dns_response.query_id;
                            if let Some(pq) = pending.remove(&qid) {
                                // Cache successful responses to avoid redundant tunnel round-trips
                                if dns_response.success {
                                    let ips: Vec<IpAddr> = dns_response
                                        .ipv4_addrs
                                        .iter()
                                        .map(|ip| IpAddr::V4(*ip))
                                        .collect();
                                    let ttl = Duration::from_secs(dns_response.ttl as u64);
                                    self.dns_resolver.store_with_ttl(&pq.domain, ips, ttl).await;
                                }
                                let _ = pq.tx.send(Some(dns_response));
                            }
                        }
                        Ok(Some(Message::Close(_))) | Ok(None) => {
                            // Fail all pending queries so their UDP handlers can send SERVFAIL
                            for (_, pq) in pending.drain() {
                                let _ = pq.tx.send(None);
                            }
                            break;
                        }
                        Ok(Some(_)) => {
                            // Ping/Pong or other control frames — keepalive received,
                            // but not a DNS response. Continue waiting.
                        }
                        Err(_) => {
                            // No WebSocket activity for 120s. This catches connections
                            // that are completely silent (no pings, no responses).
                            warn!("DNS proxy: no WebSocket activity for 120s, forcing reconnect ({} pending queries)", pending.len());
                            for (_, pq) in pending.drain() {
                                let _ = pq.tx.send(None);
                            }
                            anyhow::bail!("DNS proxy: WebSocket read timeout (120s)");
                        }
                    }
                }

                // Application-level timeout: check if any pending query has been
                // waiting for a response for more than 60s. Using a persistent
                // interval guarantees this check runs regularly regardless of
                // WebSocket control-frame traffic that would reset a naive sleep.
                _ = check_interval.tick(), if !pending.is_empty() => {
                    let now = Instant::now();
                    let oldest = pending.values().map(|pq| pq.sent_at).min();
                    if let Some(oldest) = oldest {
                        if now.duration_since(oldest) >= Duration::from_secs(60) {
                            warn!("DNS proxy: {} pending queries with no response for 60s, forcing reconnect", pending.len());
                            for (_, pq) in pending.drain() {
                                let _ = pq.tx.send(None);
                            }
                            anyhow::bail!("DNS proxy: pending query timeout (60s)");
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

/// Perform X3DH handshake for the DNS WebSocket connection
///
/// Mirrors StreamRelay::perform_handshake but for the DNS endpoint.
async fn dns_handshake(
    reader: &mut WebSocketReader,
    writer: &WebSocketWriter,
    identity_key: &Arc<IdentityKey>,
    server_bundle: &X3DHPublicBundle,
) -> Result<DoubleRatchet> {
    let initiator = X3DHInitiator::from_identity_key(Arc::clone(identity_key));

    let identity_public = initiator.identity_key.x25519_public_key();
    let ephemeral_public = initiator.ephemeral_key.public_key.to_bytes();

    let hello = HandshakeMessage::Hello {
        version: rvpn_core::protocol::ProtocolVersion::CURRENT,
        auth_method: rvpn_core::protocol::AuthMethod::X3DH,
        ephemeral_key: Some(ephemeral_public.to_vec()),
        identity_key: Some(identity_public.to_vec()),
        session_token: None,
        connection_nonce: None,
    };

    let hello_bytes = serde_json::to_vec(&hello).context("Failed to serialize Hello")?;
    writer
        .send(Message::Binary(hello_bytes))
        .context("Failed to send Hello")?;

    let response = reader
        .recv()
        .await
        .ok_or_else(|| anyhow::anyhow!("DNS WebSocket closed during handshake"))?;

    match response {
        Message::Binary(data) => {
            let server_hello: HandshakeMessage =
                serde_json::from_slice(&data).context("Failed to parse ServerHello")?;

            match server_hello {
                HandshakeMessage::ServerHello {
                    ephemeral_key: _server_ephemeral,
                    ..
                } => {
                    let (shared_secret, _) = initiator
                        .agree(server_bundle)
                        .context("X3DH key agreement failed")?;

                    // In X3DH, the server (Bob) doesn't generate an ephemeral key.
                    // The _server_ephemeral field in ServerHello is empty.
                    // We pass zeros since init_alice doesn't use this parameter.
                    Ok(DoubleRatchet::init_alice(shared_secret, [0u8; 32]))
                }
                _ => Err(anyhow::anyhow!("Unexpected handshake message from server")),
            }
        }
        _ => Err(anyhow::anyhow!("Expected binary message during handshake")),
    }
}

/// Parse a DNS wire-format query packet.
///
/// Returns `(transaction_id, domain, qtype)`.
fn parse_dns_query(data: &[u8]) -> Result<(u16, String, u16)> {
    if data.len() < 17 {
        return Err(anyhow::anyhow!("DNS query too short ({} bytes)", data.len()));
    }

    let txid = u16::from_be_bytes([data[0], data[1]]);

    // Walk the QNAME labels starting at byte 12
    let mut pos = 12usize;
    let mut labels: Vec<&str> = Vec::new();

    loop {
        if pos >= data.len() {
            return Err(anyhow::anyhow!("Truncated DNS QNAME"));
        }
        let len = data[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            return Err(anyhow::anyhow!(
                "DNS pointer compression unsupported in client queries"
            ));
        }
        pos += 1;
        if pos + len > data.len() {
            return Err(anyhow::anyhow!("DNS label extends beyond packet"));
        }
        labels.push(
            std::str::from_utf8(&data[pos..pos + len])
                .map_err(|_| anyhow::anyhow!("Invalid UTF-8 in DNS label"))?,
        );
        pos += len;
    }

    let domain = labels.join(".");

    if pos + 4 > data.len() {
        return Err(anyhow::anyhow!("Truncated DNS QTYPE/QCLASS"));
    }
    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);

    Ok((txid, domain, qtype))
}

/// Build a DNS wire-format response from a resolved DnsResponse.
///
/// `query` is the original raw wire-format query packet (for extracting the question section).
/// `txid` is the DNS transaction ID (from `parse_dns_query`).
fn build_dns_response(query: &[u8], txid: u16, response: &DnsResponse) -> Vec<u8> {
    // Server has no IPv6 upstream — strip AAAA records to prevent applications
    // from attempting IPv6 connections that will fail with "Network is unreachable".
    let ancount = response.ipv4_addrs.len() as u16;
    let mut out = Vec::with_capacity(64 + 16 * ancount as usize);

    // Header
    out.extend_from_slice(&txid.to_be_bytes());
    // Flags: QR=1 (response), RD=1 (recursion desired, mirrored), RA=1 (available)
    out.extend_from_slice(&[0x81, 0x80]);
    out.extend_from_slice(&[0x00, 0x01]);           // QDCOUNT = 1
    out.extend_from_slice(&ancount.to_be_bytes());  // ANCOUNT
    out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // NSCOUNT=0, ARCOUNT=0

    // Question section: properly parse QNAME length and copy only the question bytes
    // (not the OPT record that may be present in the original query)
    let question_end = find_question_end(query, 12);
    out.extend_from_slice(&query[12..question_end]);

    // Answer records — pointer 0xC00C refers to QNAME at offset 12
    let ttl = response.ttl.max(30).to_be_bytes();

    for addr in &response.ipv4_addrs {
        out.extend_from_slice(&[0xC0, 0x0C]); // name pointer → offset 12
        out.extend_from_slice(&[0x00, 0x01]); // Type A
        out.extend_from_slice(&[0x00, 0x01]); // Class IN
        out.extend_from_slice(&ttl);
        out.extend_from_slice(&[0x00, 0x04]); // RDLENGTH = 4
        out.extend_from_slice(&addr.octets());
    }

    // AAAA records intentionally omitted — server lacks IPv6 connectivity.

    out
}

/// Find the end of the question section in a DNS wire-format query.
///
/// Starts at the given offset (after the 12-byte header) and walks the QNAME
/// to find where QTYPE/QCLASS begin. This correctly handles QNAME encoding
/// and stops before any OPT record.
fn find_question_end(query: &[u8], mut pos: usize) -> usize {
    // Walk the QNAME: each label is [length: 1 byte][label: length bytes]
    // Terminated by a null byte (0x00)
    while pos < query.len() {
        let len = query[pos];
        if len == 0 {
            // Null terminator found - QNAME ends, QTYPE/QCLASS follow (4 bytes)
            return pos + 5; // 1 (null) + 2 (QTYPE) + 2 (QCLASS)
        }
        pos += 1 + len as usize; // Skip length byte + label bytes
    }
    // Malformed query - just return query.len()
    query.len()
}

/// Resolve a domain locally (for split-tunnel bypass domains) via direct UDP to public nameservers.
///
/// When the DNS proxy is the system DNS resolver, calling `resolver.resolve()` would loop back
/// to ourselves. Instead, we send the raw DNS query directly to public nameservers via UDP
/// and return the raw response bytes. This breaks the circular dependency that locks the
/// entire connection when the tunnel WebSocket is dead.
async fn resolve_locally(
    query: &[u8],
    txid: u16,
    domain: &str,
    _qtype: u16,
    nameservers: &[SocketAddr],
) -> Result<Vec<u8>> {
    if nameservers.is_empty() {
        return Err(anyhow::anyhow!("No public nameservers configured for bypass domain resolution"));
    }
    match resolve_via_udp_forward(query, txid, nameservers).await {
        Ok(response) => Ok(response),
        Err(e) => {
            warn!("DNS proxy: UDP forward failed for bypass domain {}: {}", domain, e);
            Err(e)
        }
    }
}

/// Forward a raw DNS query to public nameservers via UDP.
/// Returns the raw DNS response bytes with the transaction ID set to `txid`.
async fn resolve_via_udp_forward(
    query: &[u8],
    txid: u16,
    nameservers: &[SocketAddr],
) -> Result<Vec<u8>> {
    for ns in nameservers {
        match query_nameserver_udp_raw(*ns, query).await {
            Ok(mut response_bytes) => {
                // Ensure transaction ID matches the client's query
                if response_bytes.len() >= 2 {
                    response_bytes[0] = (txid >> 8) as u8;
                    response_bytes[1] = (txid & 0xFF) as u8;
                }
                return Ok(response_bytes);
            }
            Err(e) => {
                debug!("Nameserver {} failed: {}", ns, e);
            }
        }
    }
    Err(anyhow::anyhow!("All public nameservers failed for UDP forward"))
}

/// Send a raw DNS query to a nameserver and return the raw response bytes.
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
            // Brief backoff before retry: 200ms, then 500ms
            tokio::time::sleep(std::time::Duration::from_millis(200 * attempt as u64)).await;
        }

        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("Failed to bind UDP socket for DNS forward")?;

        if let Err(e) = socket.send_to(query, nameserver).await {
            last_error = Some(format!("send failed: {}", e));
            continue;
        }

        let mut buf = [0u8; 4096];
        match tokio::time::timeout(
            std::time::Duration::from_secs(TIMEOUT_SECS),
            socket.recv_from(&mut buf),
        )
        .await
        {
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

/// Build a minimal DNS NXDOMAIN response (for blocked ad/tracker domains)
fn build_dns_nxdomain(_query: &[u8], txid: u16) -> Vec<u8> {
    let mut out = vec![0u8; 12];
    out[0] = (txid >> 8) as u8;
    out[1] = (txid & 0xFF) as u8;
    out[2] = 0x81; // QR=1, RD=1
    out[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)
    out
}

/// Build a minimal DNS SERVFAIL response
fn build_dns_servfail(_query: &[u8], txid: u16) -> Vec<u8> {
    let mut out = vec![0u8; 12];
    out[0] = (txid >> 8) as u8;
    out[1] = (txid & 0xFF) as u8;
    out[2] = 0x81; // QR=1, RD=1
    out[3] = 0x82; // RA=1, RCODE=2 (SERVFAIL)
    // QDCOUNT=0, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0 (zeros from vec! init)
    out
}
