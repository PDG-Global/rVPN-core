// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DNS-over-WebSocket client
//
// Maintains a persistent WebSocket connection to the server's /dns endpoint.
// Resolves domains by sending DnsQuery messages and receiving DnsResponse messages.
// Uses the X3DH handshake + Double Ratchet for encryption.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use futures::SinkExt;
use futures::StreamExt;
use futures_util::stream::SplitSink;
use tokio::sync::{Mutex, oneshot};
use tokio::time::timeout;
use tokio_tungstenite::{client_async, tungstenite::Message, WebSocketStream};
use tracing::{debug, error, info, warn};
use tungstenite::handshake::client::generate_key;
use rvpn_client::tls_boring::{connect_chrome_like, ChromeTlsStream};

use rvpn_core::crypto::{DoubleRatchet, IdentityKey, X3DHPublicBundle};
use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::crypto::ratchet::RatchetMessage;
use rvpn_core::protocol::HandshakeMessage;
use rvpn_core::protocol::message::{DnsQuery, DnsResponse};

use crate::flow_connector::FlowConnectorConfig;

/// Payload type bytes for DNS messages
const PAYLOAD_TYPE_DNS_QUERY: u8 = 0x08;
const PAYLOAD_TYPE_DNS_RESPONSE: u8 = 0x09;

/// Minimum TTL for successful DoH cache entries. Some DNS responses advertise
/// very short TTLs (e.g., 5s), which causes repeated DoH round-trips and makes
/// the VPN feel slow. Cap successful entries to at least this long.
const MIN_CACHE_TTL: Duration = Duration::from_secs(60);
/// Maximum TTL to avoid stale entries when upstream returns extremely long TTLs.
const MAX_CACHE_TTL: Duration = Duration::from_secs(3600);

/// Pending DNS query waiting for a response
struct PendingQuery {
    reply_tx: oneshot::Sender<DnsResponse>,
}

/// Cache entry for resolved DNS names
struct CacheEntry {
    addresses: Vec<IpAddr>,
    expires_at: Instant,
    /// If true, this is a negative cache entry (resolution failed).
    failed: bool,
}

/// DNS-over-WebSocket client
///
/// Maintains a persistent encrypted WebSocket connection to the server and
/// resolves DNS queries through it.
pub struct DohClient {
    config: FlowConnectorConfig,
    dns_path: String,
    /// Pre-resolved server IP to avoid DNS circular dependency during reconnect.
    /// When the VPN is active, system DNS is redirected to our DNS proxy (127.0.0.1:53).
    /// If the DoH connection dies and tries to reconnect, resolving the server hostname
    /// would go through our proxy → dead connection → resolution fails forever.
    server_ip: std::net::IpAddr,
    /// Pending queries indexed by query_id
    pending: Arc<Mutex<HashMap<u64, PendingQuery>>>,
    /// DNS response cache
    cache: Arc<Mutex<HashMap<String, CacheEntry>>>,
    /// Maximum number of entries in the DNS cache
    max_cache_size: usize,
    /// Channel to send outgoing DNS queries to the connection task
    query_tx: Arc<Mutex<Option<tokio::sync::mpsc::UnboundedSender<DnsQuery>>>>,
    /// Next query ID counter
    next_id: Arc<Mutex<u64>>,
}

impl DohClient {
    /// Create a new DoH client
    pub fn new(config: FlowConnectorConfig, dns_path: String) -> Self {
        // Pre-resolve server hostname to IP to avoid DNS circular dependency during reconnect.
        // When the VPN is active, system DNS is redirected to our DNS proxy (127.0.0.1:53).
        // If the DoH connection dies and tries to reconnect, resolving the server hostname would
        // go through our proxy → dead connection → resolution fails forever.
        // By resolving here (while the VPN is connected and DNS works), we cache the IP for all
        // subsequent reconnects.
        let server_ip = if let Ok(ip) = config.server_host.parse::<std::net::IpAddr>() {
            ip
        } else {
            let addrs_result = std::net::ToSocketAddrs::to_socket_addrs(
                &format!("{}:{}", config.server_host, config.server_port)
            );
            match addrs_result {
                Ok(mut addrs) => match addrs.next() {
                    Some(addr) => addr.ip(),
                    None => {
                        error!("[DohClient] DNS resolution returned no addresses for {}", config.server_host);
                        // Fallback: we'll try to resolve at connection time (will fail if DNS is hijacked)
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
                    }
                },
                Err(e) => {
                    error!("[DohClient] Failed to resolve server hostname {}: {}", config.server_host, e);
                    std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
                }
            }
        };
        info!("[DohClient] Server {} resolved to {}", config.server_host, server_ip);

        Self {
            config,
            dns_path,
            server_ip,
            pending: Arc::new(Mutex::new(HashMap::new())),
            cache: Arc::new(Mutex::new(HashMap::new())),
            max_cache_size: 1000,
            query_tx: Arc::new(Mutex::new(None)),
            next_id: Arc::new(Mutex::new(1)),
        }
    }

    /// Start the background connection task
    pub async fn start(&self) -> Result<()> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<DnsQuery>();
        *self.query_tx.lock().await = Some(tx);

        let config = self.config.clone();
        let dns_path = self.dns_path.clone();
        let pending = self.pending.clone();

        let server_ip = self.server_ip;
        tokio::spawn(async move {
            let mut rx = rx;
            loop {
                match Self::run_connection(&config, server_ip, &dns_path, &pending, &mut rx).await {
                    Ok(_) => {
                        info!("[DohClient] Connection closed, reconnecting in 1s...");
                    }
                    Err(e) => {
                        warn!("[DohClient] Connection error: {}, reconnecting in 2s...", e);
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        Ok(())
    }

    /// Check the DoH client's cache for a previously resolved domain.
    /// Returns Some(addrs) if cached and not expired, None otherwise.
    /// Returns None for negative cache entries (failed lookups).
    pub async fn lookup_cached(&self, domain: &str, query_type: u16) -> Option<Vec<IpAddr>> {
        let cache_key = format!("{}:{}", domain, query_type);
        let cache = self.cache.lock().await;
        if let Some(entry) = cache.get(&cache_key) {
            if entry.expires_at > Instant::now() && !entry.failed {
                return Some(entry.addresses.clone());
            }
        }
        None
    }

    /// Get the remaining TTL (in seconds) for a cached entry.
    /// Returns None if not cached, expired, or negative entry.
    pub async fn get_cached_ttl(&self, domain: &str, query_type: u16) -> Option<u32> {
        let cache_key = format!("{}:{}", domain, query_type);
        let cache = self.cache.lock().await;
        if let Some(entry) = cache.get(&cache_key) {
            if entry.failed {
                return None;
            }
            let remaining = entry.expires_at.saturating_duration_since(Instant::now());
            if remaining > Duration::ZERO {
                return Some(remaining.as_secs().max(30) as u32);
            }
        }
        None
    }

    /// Resolve a domain name to IP addresses
    pub async fn resolve(&self, domain: &str, query_type: u16) -> Result<Vec<IpAddr>> {
        // Check cache first (including negative entries)
        let cache_key = format!("{}:{}", domain, query_type);
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = cache.get(&cache_key) {
                if entry.expires_at > Instant::now() {
                    if entry.failed {
                        debug!("[DohClient] Negative cache hit for {}", domain);
                        anyhow::bail!("DNS resolution failed for {}: cached failure", domain);
                    }
                    debug!("[DohClient] Cache hit for {}", domain);
                    return Ok(entry.addresses.clone());
                }
            }
        }

        // Generate query ID
        let query_id = {
            let mut id = self.next_id.lock().await;
            let current = *id;
            *id = id.wrapping_add(1);
            current
        };

        let query = DnsQuery {
            query_id,
            domain: domain.to_string(),
            query_type,
        };

        // Register pending query
        let (reply_tx, reply_rx) = oneshot::channel();
        {
            let mut pending = self.pending.lock().await;
            pending.insert(query_id, PendingQuery { reply_tx });
        }

        // Send query via channel
        {
            let query_tx = self.query_tx.lock().await;
            if let Some(tx) = query_tx.as_ref() {
                if tx.send(query).is_err() {
                    self.pending.lock().await.remove(&query_id);
                    anyhow::bail!("DNS connection channel closed");
                }
            } else {
                self.pending.lock().await.remove(&query_id);
                anyhow::bail!("DNS client not started");
            }
        }

        // Wait for response with timeout
        let response = tokio::time::timeout(Duration::from_secs(5), reply_rx)
            .await
            .context("DNS query timeout")?
            .context("DNS reply channel closed")?;

        if !response.success {
            // Cache failure to suppress retry storms
            self.insert_cache_entry(
                cache_key, vec![], true, Duration::from_secs(30)).await;
            anyhow::bail!(
                "DNS resolution failed for {}: {}",
                domain,
                response.error.unwrap_or_else(|| "unknown error".to_string())
            );
        }

        let mut addresses: Vec<IpAddr> = Vec::new();
        addresses.extend(response.ipv4_addrs.iter().map(|a| IpAddr::V4(*a)));
        addresses.extend(response.ipv6_addrs.iter().map(|a| IpAddr::V6(*a)));

        info!("[DohClient] Resolved {} -> {} addresses (ipv4={}, ipv6={}) success={}",
              domain, addresses.len(), response.ipv4_addrs.len(), response.ipv6_addrs.len(), response.success);

        // Cache the result
        let ttl = Duration::from_secs(response.ttl as u64);
        self.insert_cache_entry(cache_key, addresses.clone(), false, ttl).await;

        Ok(addresses)
    }

    /// Insert an entry into the cache with size-limit enforcement.
    async fn insert_cache_entry(
        &self,
        cache_key: String,
        addresses: Vec<IpAddr>,
        failed: bool,
        ttl: Duration,
    ) {
        // Clamp successful-entry TTL to avoid stale data and excessive re-querying.
        // Failed-entry TTL is intentionally short and is left as-is.
        let ttl = if failed {
            ttl
        } else {
            ttl.clamp(MIN_CACHE_TTL, MAX_CACHE_TTL)
        };

        let mut cache = self.cache.lock().await;

        // Remove expired entries if over limit
        if cache.len() >= self.max_cache_size {
            let now = Instant::now();
            cache.retain(|_, e| e.expires_at > now);

            // If still over limit, evict oldest entries
            if cache.len() >= self.max_cache_size {
                let mut entries: Vec<(String, Instant)> = cache
                    .iter()
                    .map(|(k, e)| (k.clone(), e.expires_at))
                    .collect();
                entries.sort_by(|a, b| a.1.cmp(&b.1));
                let to_remove = cache.len().saturating_sub(self.max_cache_size - 1);
                for (key, _) in entries.into_iter().take(to_remove) {
                    cache.remove(&key);
                }
            }
        }

        cache.insert(cache_key, CacheEntry {
            addresses,
            expires_at: Instant::now() + ttl,
            failed,
        });
    }

    /// Start a background task that periodically cleans expired cache entries.
    pub fn start_cleanup_task(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(300));
            loop {
                interval.tick().await;
                let mut cache = self.cache.lock().await;
                let before = cache.len();
                let now = Instant::now();
                cache.retain(|_, e| e.expires_at > now);
                let after = cache.len();
                if before != after {
                    debug!("[DohClient] cache cleanup: removed {} expired entries", before - after);
                }
            }
        });
    }

    /// Resolve A records (IPv4)
    pub async fn resolve_a(&self, domain: &str) -> Result<Vec<Ipv4Addr>> {
        let addrs = self.resolve(domain, 1).await?;
        Ok(addrs.into_iter()
            .filter_map(|a| if let IpAddr::V4(v4) = a { Some(v4) } else { None })
            .collect())
    }

    /// Resolve AAAA records (IPv6)
    #[allow(dead_code)]
    pub async fn resolve_aaaa(&self, domain: &str) -> Result<Vec<Ipv6Addr>> {
        let addrs = self.resolve(domain, 28).await?;
        Ok(addrs.into_iter()
            .filter_map(|a| if let IpAddr::V6(v6) = a { Some(v6) } else { None })
            .collect())
    }

    /// Run a single WebSocket connection session
    async fn run_connection(
        config: &FlowConnectorConfig,
        server_ip: std::net::IpAddr,
        dns_path: &str,
        pending: &Arc<Mutex<HashMap<u64, PendingQuery>>>,
        query_rx: &mut tokio::sync::mpsc::UnboundedReceiver<DnsQuery>,
    ) -> Result<()> {
        let url = format!("wss://{}:{}{}", config.server_host, config.server_port, dns_path);
        info!("[DohClient] Connecting to {} (via IP {})", url, server_ip);

        // Establish TLS connection with Chrome fingerprint via boring.
        // We connect to the pre-resolved IP for TCP, but use the original
        // hostname for TLS SNI to avoid DNS circular dependency during reconnect.
        let tls_stream = timeout(
            Duration::from_secs(5),
            connect_chrome_like(
                &server_ip.to_string(),
                config.server_port,
                config.tls_fingerprint,
                Some(&config.server_host),
            )
        )
        .await
        .context("DNS TLS connect timeout (5s)")?
        .context("Failed to establish Chrome-fingerprinted TLS connection for DNS")?;

        // Build Chrome-like WebSocket upgrade request with 15 headers.
        let ws_key = generate_key();
        let authority = format!("{}:{}", config.server_host, config.server_port);
        let request = tungstenite::http::Request::builder()
            .method("GET")
            .uri(&url)
            .header("Host", &authority)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", &ws_key)
            .header(
                "User-Agent",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            )
            .header("Accept", "*/*")
            .header("Accept-Encoding", "gzip, deflate, br")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Cache-Control", "no-cache")
            .header("Pragma", "no-cache")
            .header("Sec-Fetch-Dest", "websocket")
            .header("Sec-Fetch-Mode", "websocket")
            .header("Sec-Fetch-Site", "same-origin")
            .body(())
            .context("Failed to build DNS WebSocket upgrade request")?;

        let (ws_stream, _) = timeout(
            Duration::from_secs(3),
            client_async(request, tls_stream)
        )
        .await
        .context("DNS WebSocket handshake timeout (3s)")?
        .context("DNS WebSocket handshake failed")?;

        let (mut write, mut read) = ws_stream.split();

        // Perform X3DH handshake
        let ratchet = perform_handshake(
            &mut read,
            &mut write,
            &config.identity_key,
            &config.server_bundle,
        )
        .await
        .context("X3DH handshake failed for DNS connection")?;

        info!("[DohClient] DNS connection established");

        let ratchet = Arc::new(Mutex::new(ratchet));
        let ratchet_recv = ratchet.clone();

        // Run send/receive concurrently
        let send_loop = async {
            while let Some(query) = query_rx.recv().await {
                let query_bytes = match serde_json::to_vec(&query) {
                    Ok(b) => b,
                    Err(e) => {
                        error!("[DohClient] Failed to serialize query: {}", e);
                        continue;
                    }
                };

                let encrypted = {
                    let mut r = ratchet.lock().await;
                    match r.encrypt(&query_bytes, &[PAYLOAD_TYPE_DNS_QUERY]) {
                        Ok(m) => m,
                        Err(e) => {
                            error!("[DohClient] Failed to encrypt query: {}", e);
                            continue;
                        }
                    }
                };

                let serialized = match encrypted.to_bytes() {
                    Ok(b) => b,
                    Err(e) => {
                        error!("[DohClient] Failed to serialize encrypted query: {}", e);
                        continue;
                    }
                };

                if let Err(e) = write.send(Message::Binary(serialized)).await {
                    debug!("[DohClient] Send error: {}", e);
                    break;
                }
            }
        };

        let recv_loop = async {
            loop {
                let msg = match timeout(Duration::from_secs(15), read.next()).await {
                    Ok(Some(msg)) => msg,
                    Ok(None) => {
                        debug!("[DohClient] Connection closed");
                        break;
                    }
                    Err(_) => {
                        warn!("[DohClient] WebSocket read timeout (15s), connection appears dead");
                        break;
                    }
                };

                match msg {
                    Ok(Message::Binary(data)) => {
                        let ratchet_msg: RatchetMessage = match RatchetMessage::from_bytes(&data) {
                            Ok(m) => m,
                            Err(e) => {
                                warn!("[DohClient] Failed to parse ratchet message: {}", e);
                                continue;
                            }
                        };

                        let plaintext = {
                            let mut r = ratchet_recv.lock().await;
                            match r.decrypt(&ratchet_msg, &[PAYLOAD_TYPE_DNS_RESPONSE]) {
                                Ok(p) => p,
                                Err(e) => {
                                    warn!("[DohClient] Decryption failed: {}", e);
                                    continue;
                                }
                            }
                        };

                        let response: DnsResponse = match serde_json::from_slice(&plaintext) {
                            Ok(r) => r,
                            Err(e) => {
                                warn!("[DohClient] Failed to parse DnsResponse: {}", e);
                                continue;
                            }
                        };

                        debug!("[DohClient] Received response for query_id={}", response.query_id);

                        let mut pending_guard = pending.lock().await;
                        if let Some(pending_query) = pending_guard.remove(&response.query_id) {
                            let _ = pending_query.reply_tx.send(response);
                        } else {
                            warn!("[DohClient] No pending query for id={}", response.query_id);
                        }
                    }
                    Ok(Message::Ping(_)) => {}
                    Ok(Message::Close(_)) | Err(_) => break,
                    _ => {}
                }
            }
        };

        tokio::select! {
            _ = send_loop => {
                debug!("[DohClient] Send loop ended");
            }
            _ = recv_loop => {
                debug!("[DohClient] Receive loop ended");
            }
        }

        Ok(())
    }
}

/// Perform X3DH handshake with the server
async fn perform_handshake(
    ws_reader: &mut futures_util::stream::SplitStream<WebSocketStream<ChromeTlsStream>>,
    ws_writer: &mut SplitSink<WebSocketStream<ChromeTlsStream>, Message>,
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
    ws_writer.send(Message::Binary(hello_bytes)).await.context("Failed to send Hello")?;

    let response = timeout(Duration::from_secs(3), ws_reader.next())
        .await
        .context("DNS handshake timeout (3s)")?
        .ok_or_else(|| anyhow::anyhow!("WebSocket closed during handshake"))?
        .context("WebSocket error during handshake")?;

    match response {
        Message::Binary(data) => {
            let server_hello: HandshakeMessage = serde_json::from_slice(&data)
                .context("Failed to parse ServerHello")?;

            match server_hello {
                HandshakeMessage::ServerHello { ephemeral_key: _server_ephemeral, .. } => {
                    let (shared_secret, _) = initiator
                        .agree(server_bundle)
                        .context("X3DH key agreement failed")?;

                    // In X3DH, the server (Bob) doesn't generate an ephemeral key.
                    // The _server_ephemeral field is empty - init_alice doesn't use this parameter.
                    Ok(DoubleRatchet::init_alice(shared_secret, [0u8; 32]))
                }
                _ => Err(anyhow::anyhow!("Unexpected handshake message")),
            }
        }
        _ => Err(anyhow::anyhow!("Expected binary message during handshake")),
    }
}
