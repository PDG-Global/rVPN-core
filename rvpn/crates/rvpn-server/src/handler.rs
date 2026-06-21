//! Simplified Brook-style connection handler
//! One WebSocket = One SOCKS5 connection (1:1 mapping)
//! Uses X3DH handshake + Double Ratchet encryption

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use ip_network::IpNetwork;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::lookup_host;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_tungstenite::{accept_async, tungstenite::protocol::Message};
use tracing::{debug, error, info, trace, warn};

use crate::config::{ServerConfig, TunNetworkConfig};
use crate::TunWriter;
use rvpn_core::crypto::ratchet::RatchetMessage;
use rvpn_core::crypto::{DoubleRatchet, IdentityKey, X3DHResponder};
use rvpn_core::protocol::multiplex::ControlMessage;
use rvpn_core::protocol::HandshakeMessage;
use rvpn_core::protocol::{AuthMethod, MultiplexedFrame, PayloadType, ProtocolVersion};

/// Check if an IP address is private or reserved (and should be blocked for outbound connections).
///
/// Returns `true` if the address should be blocked. If `allowed_cidr` is provided,
/// addresses falling within that CIDR range are allowed (returns `false`).
fn should_block_address(addr: &IpAddr, allowed_cidr: Option<&str>) -> bool {
    // Check if address is within the allowed CIDR (e.g., tunnel subnet)
    let is_allowed = allowed_cidr.and_then(|cidr| {
        let network = cidr.parse::<IpNetwork>().ok()?;
        Some(network.contains(*addr))
    });

    if is_allowed == Some(true) {
        return false;
    }

    match addr {
        IpAddr::V4(ipv4) => {
            // Loopback: 127.0.0.0/8
            if ipv4.is_loopback() {
                return true;
            }
            // Private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            if ipv4.is_private() {
                return true;
            }
            // Link-local: 169.254.0.0/16
            if ipv4.is_link_local() {
                return true;
            }
            // Multicast: 224.0.0.0/4
            if ipv4.is_multicast() {
                return true;
            }
            // Unspecified: 0.0.0.0
            if ipv4.is_unspecified() {
                return true;
            }
            // IPv4-mapped IPv6 handled in IpAddr::V6 branch
            false
        }
        IpAddr::V6(ipv6) => {
            // Loopback: ::1
            if ipv6.is_loopback() {
                return true;
            }
            // Private (ULA): fc00::/7
            if (ipv6.segments()[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // Link-local: fe80::/10
            if (ipv6.segments()[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Multicast: ff00::/8
            if ipv6.is_multicast() {
                return true;
            }
            // Unspecified: ::
            if ipv6.is_unspecified() {
                return true;
            }
            // IPv4-mapped IPv6: ::ffff:0:0/96 — check inner IPv4
            if let Some(mapped_ipv4) = ipv6.to_ipv4_mapped() {
                return should_block_address(&IpAddr::V4(mapped_ipv4), allowed_cidr);
            }
            false
        }
    }
}

/// Connect to the first available address in parallel (Happy Eyeballs-style).
///
/// Spawns a task per address with a 5-second timeout. Returns the first
/// successful `TcpStream`. Prevents a single blackholed address from stalling
/// the entire flow for 10 seconds.
async fn connect_fastest(
    addrs: Vec<SocketAddr>,
    allowed_cidr: Option<&str>,
    target: &str,
) -> Result<TcpStream> {
    let mut join_set = JoinSet::new();
    let mut blocked_count = 0;

    for addr in addrs {
        if should_block_address(&addr.ip(), allowed_cidr) {
            blocked_count += 1;
            continue;
        }
        join_set.spawn(async move {
            match timeout(Duration::from_secs(5), TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => Ok(stream),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Connection timeout",
                )),
            }
        });
    }

    let mut last_error = None;
    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => last_error = Some(e),
            Err(_) => {}
        }
    }

    if blocked_count > 0 && last_error.is_none() {
        return Err(anyhow::anyhow!(
            "All addresses blocked for {}",
            target
        ));
    }

    Err(anyhow::anyhow!(
        "Failed to connect to {}: {:?}",
        target,
        last_error
    ))
}

/// Protocol type for target connection
#[derive(Debug, Clone, Copy, PartialEq)]
enum ProtocolType {
    Tcp,
    Udp,
}

/// Target address specification from client
#[derive(Debug, Clone)]
struct TargetAddress {
    host: String,
    port: u16,
    protocol: ProtocolType,
}

/// DNS cache entry with TTL
struct DnsEntry {
    addrs: Vec<SocketAddr>,
    cached_at: Instant,
    #[allow(dead_code)]
    ttl: Duration,
}

/// DNS resolver with caching
type DnsCache = std::sync::Arc<tokio::sync::Mutex<std::collections::HashMap<String, DnsEntry>>>;

/// Simplified VPN handler - Brook-style architecture with X3DH + Double Ratchet
pub struct VpnHandler {
    #[allow(dead_code)]
    config: ServerConfig,
    rate_limiter: RwLock<RateLimiter>,
    dns_cache: DnsCache,
    x3dh_responder: Option<X3DHResponder>,
}

impl VpnHandler {
    pub fn new(config: ServerConfig) -> Result<Self> {
        // Load identity key and create X3DH responder
        let x3dh_responder = if config.identity_key_file.exists() {
            match IdentityKey::load(&config.identity_key_file) {
                Ok(identity) => {
                    info!(
                        "Loaded server identity key from {:?}",
                        config.identity_key_file
                    );

                    // Try to load signed_prekey from private key file
                    // The private key is stored in prekey-bundle.private.json alongside the public bundle
                    let signed_prekey = config.prekey_bundle_file.as_ref()
                        .and_then(|bundle_path| {
                            // Derive the private key file path from the bundle path
                            let private_key_path = bundle_path.with_extension("private.json");
                            if private_key_path.exists() {
                                match Self::load_signed_prekey_private(&private_key_path) {
                                    Ok(key) => {
                                        info!("Loaded signed_prekey from private key file: {:?}", private_key_path);
                                        Some(key)
                                    }
                                    Err(e) => {
                                        warn!("Failed to load private key file: {}. Generating new signed_prekey.", e);
                                        None
                                    }
                                }
                            } else if bundle_path.exists() {
                                // Fallback: try to load from the old format (public bundle - this won't work correctly!)
                                warn!("Private key file not found at {:?}. Cannot use deterministic prekey.", private_key_path);
                                None
                            } else {
                                None
                            }
                        });

                    match signed_prekey {
                        Some(prekey) => {
                            info!("Using existing signed_prekey from prekey bundle");
                            Some(X3DHResponder::from_identity_with_bundle(identity, prekey))
                        }
                        None => {
                            warn!("No prekey bundle found. Generating new signed_prekey (clients will need updated bundle!)");
                            Some(X3DHResponder::from_identity(identity))
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to load identity key: {}. X3DH handshake will not be available.",
                        e
                    );
                    None
                }
            }
        } else {
            warn!(
                "No identity key file found at {:?}. X3DH handshake will not be available.",
                config.identity_key_file
            );
            None
        };

        // Read rate limit values before moving config into the struct
        let max_connections_per_ip = config.rate_limit.max_connections_per_ip;
        let max_handshakes_per_minute = config.rate_limit.max_handshakes_per_minute;

        Ok(Self {
            config,
            rate_limiter: RwLock::new(RateLimiter::new(
                max_connections_per_ip,
                max_handshakes_per_minute,
            )),
            dns_cache: std::sync::Arc::new(tokio::sync::Mutex::new(
                std::collections::HashMap::new(),
            )),
            x3dh_responder,
        })
    }

    /// Load signed_prekey private key from private key JSON file
    fn load_signed_prekey_private(private_key_path: &std::path::Path) -> Result<[u8; 32]> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

        let content = std::fs::read_to_string(private_key_path).with_context(|| {
            format!(
                "Failed to read private key file from {:?}",
                private_key_path
            )
        })?;

        #[derive(serde::Deserialize)]
        struct PrivateKeyJson {
            #[serde(rename = "signed_prekey_private")]
            signed_prekey_private: String,
        }

        let private_key: PrivateKeyJson = serde_json::from_str(&content).with_context(|| {
            format!(
                "Failed to parse private key file from {:?}",
                private_key_path
            )
        })?;

        let decoded = BASE64
            .decode(&private_key.signed_prekey_private)
            .with_context(|| "Failed to decode base64 signed_prekey_private")?;

        if decoded.len() != 32 {
            anyhow::bail!(
                "signed_prekey_private must be 32 bytes, got {}",
                decoded.len()
            );
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&decoded);
        Ok(result)
    }

    /// Handle incoming WebSocket connection (Brook-style 1:1)
    #[allow(dead_code)]
    pub async fn handle_connection(&self, stream: TcpStream, peer_addr: SocketAddr) -> Result<()> {
        debug!("New connection from {}", peer_addr);

        // Rate limit check
        {
            let mut limiter = self.rate_limiter.write().await;
            if !limiter.check_and_record(&peer_addr.ip()) {
                debug!("Rate limited: {}", peer_addr);
                return Ok(());
            }
        }

        // Perform WebSocket handshake
        let ws_stream = accept_async(stream)
            .await
            .context("WebSocket handshake failed")?;

        self.handle_websocket(ws_stream, peer_addr).await
    }

    /// Handle an already-established WebSocket connection (used with TLS)
    pub async fn handle_ws_connection<S>(
        &self,
        ws_stream: tokio_tungstenite::WebSocketStream<S>,
        peer_addr: SocketAddr,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        debug!("New WebSocket connection from {}", peer_addr);

        // Rate limit check
        {
            let mut limiter = self.rate_limiter.write().await;
            if !limiter.check_and_record(&peer_addr.ip()) {
                debug!("Rate limited: {}", peer_addr);
                return Ok(());
            }
        }

        self.handle_websocket(ws_stream, peer_addr).await
    }

    /// Main WebSocket handler - Brook-style simplified flow
    async fn handle_websocket<S>(
        &self,
        ws_stream: tokio_tungstenite::WebSocketStream<S>,
        peer_addr: SocketAddr,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut ws_write, mut ws_read) = ws_stream.split();

        // 1. Perform X3DH handshake
        let mut ratchet = match self
            .perform_handshake(&mut ws_write, &mut ws_read, peer_addr)
            .await?
        {
            Some(r) => r,
            None => return Ok(()), // Handshake failed or rejected
        };

        // 2. Read first encrypted frame (contains target address)
        let target_addr = match self.read_target_address(&mut ws_read, &mut ratchet).await? {
            Some(addr) => addr,
            None => {
                info!("No target address received from {}", peer_addr);
                return Ok(());
            }
        };

        info!(
            "Connecting to target {}:{} ({:?}) for {}",
            target_addr.host, target_addr.port, target_addr.protocol, peer_addr
        );

        // 3. Connect to target based on protocol
        match target_addr.protocol {
            ProtocolType::Tcp => {
                let target = match self.connect_to_target(&target_addr).await {
                    Ok(stream) => stream,
                    Err(e) => {
                        error!(
                            "Failed to connect to {}:{}: {}",
                            target_addr.host, target_addr.port, e
                        );
                        return Ok(());
                    }
                };

                info!(
                    "Connected to {}:{} for {}",
                    target_addr.host, target_addr.port, peer_addr
                );

                // 4. Relay bidirectionally for TCP
                match self.relay_tcp(ws_write, ws_read, target, ratchet).await {
                    Ok(_) => info!("Relay completed for {}", peer_addr),
                    Err(e) => debug!("Relay ended for {}: {}", peer_addr, e),
                }
            }
            ProtocolType::Udp => {
                // For UDP, use UDP relay
                match self
                    .relay_udp(ws_write, ws_read, &target_addr, ratchet)
                    .await
                {
                    Ok(_) => info!("UDP Relay completed for {}", peer_addr),
                    Err(e) => debug!("UDP Relay ended for {}: {}", peer_addr, e),
                }
            }
        }

        Ok(())
    }

    /// Perform X3DH handshake with client
    async fn perform_handshake<W, R, E>(
        &self,
        ws_write: &mut W,
        ws_read: &mut R,
        peer_addr: SocketAddr,
    ) -> Result<Option<DoubleRatchet>>
    where
        W: SinkExt<Message, Error = E> + Unpin,
        R: StreamExt<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
            + Unpin,
        E: std::fmt::Debug,
    {
        // Wait for Hello message
        let msg = timeout(Duration::from_secs(5), ws_read.next()).await;
        let msg = match msg {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => {
                debug!("WebSocket error from {}: {}", peer_addr, e);
                return Ok(None);
            }
            Ok(None) => {
                debug!("Connection closed by {} before handshake", peer_addr);
                return Ok(None);
            }
            Err(_) => {
                debug!("Handshake timeout from {}", peer_addr);
                return Ok(None);
            }
        };

        // Parse Hello
        let hello: HandshakeMessage = match serde_json::from_slice(&msg.into_data()) {
            Ok(h) => h,
            Err(e) => {
                info!("Failed to parse Hello message from {}: {}", peer_addr, e);
                return Ok(None);
            }
        };

        match hello {
            HandshakeMessage::Hello {
                version,
                auth_method,
                ephemeral_key,
                identity_key,
                ..
            } => {
                // Protocol version detection and compatibility check
                info!(
                    "Client protocol version from {}: {} (server: {})",
                    peer_addr,
                    version,
                    ProtocolVersion::CURRENT
                );

                // Check protocol version compatibility
                // V2 clients (1.x) use oneshot synchronization
                // V1 clients (legacy) may have race conditions
                if !version.is_compatible_with(&ProtocolVersion::CURRENT) {
                    warn!(
                        "Protocol version mismatch from {}: {} (expected {})",
                        peer_addr,
                        version,
                        ProtocolVersion::CURRENT
                    );
                    let error_response = HandshakeMessage::Error {
                        code: 1,
                        message: "Protocol version mismatch".to_string(),
                    };
                    let _ = ws_write
                        .send(Message::Binary(serde_json::to_vec(&error_response)?))
                        .await;
                    return Ok(None);
                }

                // Log client type for debugging
                if version.minor >= 1 {
                    info!(
                        "V2 client detected from {} (enhanced synchronization)",
                        peer_addr
                    );
                } else {
                    info!("V1 client detected from {} (legacy mode)", peer_addr);
                }

                // Check authentication method
                if auth_method != AuthMethod::X3DH {
                    warn!(
                        "Unsupported auth method from {}: {:?}",
                        peer_addr, auth_method
                    );
                    let error_response = HandshakeMessage::Error {
                        code: 2,
                        message: "Unsupported authentication method".to_string(),
                    };
                    let _ = ws_write
                        .send(Message::Binary(serde_json::to_vec(&error_response)?))
                        .await;
                    return Ok(None);
                }

                // Get X3DH responder
                let responder = match self.x3dh_responder.as_ref() {
                    Some(r) => r,
                    None => {
                        error!("X3DH not configured on server");
                        let error_response = HandshakeMessage::Error {
                            code: 3,
                            message: "X3DH not available".to_string(),
                        };
                        let _ = ws_write
                            .send(Message::Binary(serde_json::to_vec(&error_response)?))
                            .await;
                        return Ok(None);
                    }
                };

                // Extract keys from Hello message
                let client_ephemeral = match ephemeral_key {
                    Some(key) if key.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&key);
                        arr
                    }
                    _ => {
                        info!("Invalid or missing ephemeral key from {}", peer_addr);
                        return Ok(None);
                    }
                };

                let client_identity = match identity_key {
                    Some(key) if key.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&key);
                        arr
                    }
                    _ => {
                        info!("Invalid or missing identity key from {}", peer_addr);
                        return Ok(None);
                    }
                };

                // Perform X3DH agreement
                let shared_secret =
                    match responder.agree(&client_identity, &client_ephemeral, false) {
                        Ok(secret) => secret,
                        Err(e) => {
                            info!("X3DH agreement failed from {}: {}", peer_addr, e);
                            return Ok(None);
                        }
                    };

                info!("X3DH handshake successful from {}", peer_addr);

                // Initialize Double Ratchet as Bob (responder)
                let ratchet = DoubleRatchet::init_bob(shared_secret);

                // Send ServerHello response
                // Note: Server doesn't generate an ephemeral key in X3DH - only the client does.
                // The ephemeral_key field is kept for protocol compatibility but is empty.
                let public_bundle = responder.get_public_bundle();
                let response = HandshakeMessage::ServerHello {
                    ephemeral_key: Vec::new(),
                    signed_prekey: public_bundle.signed_prekey.to_vec(),
                    prekey_signature: public_bundle.prekey_signature.to_vec(),
                    identity_key: public_bundle.identity_key.to_vec(),
                };

                ws_write
                    .send(Message::Binary(serde_json::to_vec(&response)?))
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to send ServerHello: {:?}", e))?;

                info!("X3DH handshake completed with {}", peer_addr);

                Ok(Some(ratchet))
            }
            _ => {
                debug!(
                    "Unexpected message type from {} during handshake",
                    peer_addr
                );
                Ok(None)
            }
        }
    }

    /// Read target address from first encrypted frame
    ///
    /// # Protocol Version Support
    /// - V2 clients: Use oneshot synchronization, target address sent immediately after handshake
    /// - V1 clients (legacy): May have timing issues, require longer timeout
    ///
    /// Timeout: 5 seconds (reduced from 30s for faster failure detection)
    async fn read_target_address<R>(
        &self,
        ws_read: &mut R,
        ratchet: &mut DoubleRatchet,
    ) -> Result<Option<TargetAddress>>
    where
        R: StreamExt<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
            + Unpin,
    {
        // Wait for first encrypted frame with 5 second timeout
        // This timeout is critical for detecting dead/hung connections quickly
        let data = loop {
            let msg = timeout(Duration::from_secs(5), ws_read.next()).await;

            match msg {
                Ok(Some(Ok(Message::Binary(data)))) => break data,
                Ok(Some(Ok(Message::Close(_)))) | Ok(None) => {
                    debug!("Connection closed before target address received");
                    return Ok(None);
                }
                Ok(Some(Ok(Message::Ping(_)))) => {
                    // Ignore ping frames and continue waiting
                    debug!("Received ping while waiting for target address, continuing...");
                    continue;
                }
                Ok(Some(Ok(_))) => {
                    // Ignore other non-binary messages and continue
                    debug!("Received non-binary message while waiting for target address, continuing...");
                    continue;
                }
                Ok(Some(Err(e))) => {
                    return Err(anyhow::anyhow!(
                        "WebSocket error waiting for target address: {}",
                        e
                    ));
                }
                Err(_) => {
                    return Err(anyhow::anyhow!("Timeout (5s) waiting for target address - client may be stuck or sending data out of order"));
                }
            }
        };

        // Decrypt the frame using Double Ratchet
        let decrypted = Self::decrypt_frame(&data, ratchet)?;
        // Strip 1KB boundary padding (client always pads before encryption)
        let plaintext = rvpn_core::protocol::padding::unpad_packet(&decrypted)
            .map_err(|e| anyhow::anyhow!("Failed to unpad target address frame: {}", e))?;

        // Debug: Log the decrypted plaintext
        tracing::debug!(
            "Received target address frame ({} bytes): {:?}",
            plaintext.len(),
            plaintext
        );
        if !plaintext.is_empty() {
            let host_len = plaintext[0] as usize;
            tracing::debug!(
                "Host length byte: {}, plaintext length: {}",
                host_len,
                plaintext.len()
            );
        }

        // Try parsing as target address format first: [host_len: u8][host_bytes][port: u16]
        // If that fails, try parsing as raw IP packet (for iOS multiplexed mode)
        let target_addr = if let Some(addr) = Self::parse_target_format(&plaintext) {
            Some(addr)
        } else if let Some((host, port, protocol)) =
            Self::parse_ip_packet_for_destination(&plaintext)
        {
            tracing::debug!(
                "Falling back to IP packet parsing for target: {}:{} ({:?})",
                host,
                port,
                protocol
            );
            Some(TargetAddress {
                host,
                port,
                protocol,
            })
        } else {
            tracing::error!("Failed to parse target address in any known format");
            return Err(anyhow::anyhow!("Invalid target address format"));
        };

        Ok(target_addr)
    }

    /// Parse target address: [host_len: u8][host_bytes][port: u16]
    fn parse_target_format(plaintext: &[u8]) -> Option<TargetAddress> {
        if plaintext.len() < 3 {
            return None;
        }

        let host_len = plaintext[0] as usize;

        // Validate hostname is not empty
        if host_len == 0 {
            return None;
        }

        // Validate hostname length per DNS spec (max 253 bytes total)
        const MAX_HOSTNAME_LEN: usize = 253;
        if host_len > MAX_HOSTNAME_LEN {
            debug!("Rejecting target: hostname too long ({} bytes, max {})", host_len, MAX_HOSTNAME_LEN);
            return None;
        }

        if plaintext.len() < 1 + host_len + 2 {
            return None;
        }

        let host = String::from_utf8(plaintext[1..1 + host_len].to_vec()).ok()?;
        let port = u16::from_be_bytes([plaintext[1 + host_len], plaintext[1 + host_len + 1]]);

        Some(TargetAddress {
            host,
            port,
            protocol: ProtocolType::Tcp,
        })
    }

    /// Parse IP packet to extract destination (fallback for iOS multiplexed mode)
    fn parse_ip_packet_for_destination(plaintext: &[u8]) -> Option<(String, u16, ProtocolType)> {
        if plaintext.len() < 20 {
            return None;
        }

        let version = plaintext[0] >> 4;

        if version == 4 && plaintext.len() >= 20 {
            let ihl = (plaintext[0] & 0x0F) as usize;
            if ihl < 5 || plaintext.len() < ihl * 4 + 4 {
                return None;
            }
            let protocol = plaintext[9]; // IP protocol field
            let dst_ip = format!(
                "{}.{}.{}.{}",
                plaintext[16], plaintext[17], plaintext[18], plaintext[19]
            );
            let dst_port = u16::from_be_bytes([plaintext[ihl * 4 + 2], plaintext[ihl * 4 + 3]]);
            let proto_type = if protocol == 17 {
                ProtocolType::Udp
            } else {
                ProtocolType::Tcp
            };
            Some((dst_ip, dst_port, proto_type))
        } else if version == 6 && plaintext.len() >= 40 {
            let next_header = plaintext[6]; // Next header field
            let dst_ip = format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                plaintext[24], plaintext[25], plaintext[26], plaintext[27],
                plaintext[28], plaintext[29], plaintext[30], plaintext[31],
                plaintext[32], plaintext[33], plaintext[34], plaintext[35],
                plaintext[36], plaintext[37], plaintext[38], plaintext[39]);
            let dst_port = u16::from_be_bytes([plaintext[42], plaintext[43]]);
            let proto_type = if next_header == 17 {
                ProtocolType::Udp
            } else {
                ProtocolType::Tcp
            };
            Some((dst_ip, dst_port, proto_type))
        } else {
            None
        }
    }

    /// Connect to target server
    async fn connect_to_target(&self, target: &TargetAddress) -> Result<TcpStream> {
        let cache_key = format!("{}:{}", target.host, target.port);
        let allowed_cidr = Some(self.config.tun.tun_ip.as_str());

        // Check DNS cache
        let addrs: Vec<SocketAddr> = {
            let cache = self.dns_cache.lock().await;
            if let Some(entry) = cache.get(&cache_key) {
                if entry.cached_at.elapsed() < Duration::from_secs(300) {
                    debug!("DNS cache hit for {}", target.host);
                    entry.addrs.clone()
                } else {
                    drop(cache);
                    self.resolve_and_cache(&target.host, target.port).await?
                }
            } else {
                drop(cache);
                self.resolve_and_cache(&target.host, target.port).await?
            }
        };

        // Connect to the first available address in parallel
        connect_fastest(addrs, allowed_cidr, &target.host).await
    }

    /// Resolve hostname and cache results
    async fn resolve_and_cache(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        debug!("DNS lookup for {}:{}", host, port);

        let mut addrs: Vec<SocketAddr> = lookup_host(format!("{}:{}", host, port)).await?.collect();

        if addrs.is_empty() {
            return Err(anyhow::anyhow!("No addresses found for {}:{}", host, port));
        }

        // Prefer IPv4 over IPv6 for faster connections on most networks
        addrs.sort_by_key(|a| match a.ip() {
            std::net::IpAddr::V4(_) => 0,
            std::net::IpAddr::V6(_) => 1,
        });

        let entry = DnsEntry {
            addrs: addrs.clone(),
            cached_at: Instant::now(),
            ttl: Duration::from_secs(300),
        };

        let mut cache = self.dns_cache.lock().await;
        cache.insert(format!("{}:{}", host, port), entry);

        Ok(addrs)
    }

    /// Relay data bidirectionally between WebSocket and TCP target
    async fn relay_tcp<S>(
        &self,
        mut ws_write: futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<S>,
            Message,
        >,
        mut ws_read: futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<S>>,
        target: TcpStream,
        ratchet: DoubleRatchet,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let (mut target_read, mut target_write) = target.into_split();

        // Share ratchet between tasks using Arc<Mutex>
        let ratchet = std::sync::Arc::new(tokio::sync::Mutex::new(ratchet));

        // Channel for target -> WebSocket direction
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);

        // Use JoinSet so ALL tasks are aborted when any one completes
        let mut tasks: JoinSet<Result<()>> = JoinSet::new();

        // Clone ratchet for the spawned tasks
        let ratchet_for_ws = ratchet.clone();
        let ratchet_for_send = ratchet.clone();

        // Task 1: WebSocket -> Target (decrypt and forward)
        tasks.spawn(async move {
            let mut last_activity = Instant::now();
            let timeout = Duration::from_secs(300); // 5 minute idle timeout

            loop {
                tokio::select! {
                    msg = ws_read.next() => {
                        match msg {
                            Some(Ok(Message::Binary(data))) => {
                                last_activity = Instant::now();

                                // Decrypt frame using Double Ratchet
                                let decrypted = {
                                    let mut ratchet_guard = ratchet_for_ws.lock().await;
                                    match Self::decrypt_frame(&data, &mut ratchet_guard) {
                                        Ok(data) => data,
                                        Err(e) => {
                                            error!("Decryption error: {}", e);
                                            break;
                                        }
                                    }
                                };

                                // Strip padding
                                let plaintext = match rvpn_core::protocol::padding::unpad_packet(&decrypted) {
                                    Ok(data) => data,
                                    Err(e) => {
                                        error!("Unpad error: {}", e);
                                        break;
                                    }
                                };

                                // Write to target
                                if let Err(e) = target_write.write_all(&plaintext).await {
                                    error!("Write to target failed: {}", e);
                                    break;
                                }
                            }
                            Some(Ok(Message::Ping(_))) => {
                                // Pong handled by tungstenite automatically
                                last_activity = Instant::now();
                            }
                            Some(Ok(Message::Close(_))) | None => {
                                break;
                            }
                            Some(Ok(_)) => {
                                // Ignore other message types
                            }
                            Some(Err(e)) => {
                                debug!("WebSocket read error: {}", e);
                                break;
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {
                        if last_activity.elapsed() > timeout {
                            debug!("Idle timeout, closing connection");
                            break;
                        }
                    }
                }
            }
            Ok(())
        });

        // Task 2: Target -> Channel (read and send to channel)
        tasks.spawn(async move {
            // 8190, not 8192 — pad_packet reserves 2 bytes for padding-length field
            let mut buf = [0u8; 8190];

            loop {
                match target_read.read(&mut buf).await {
                    Ok(0) => {
                        // Connection closed
                        break;
                    }
                    Ok(n) => {
                        if tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Read from target failed: {}", e);
                        break;
                    }
                }
            }
            Ok(())
        });

        // Task 3: Channel -> WebSocket (encrypt and send)
        tasks.spawn(async move {
            while let Some(data) = rx.recv().await {
                let mut ratchet_guard = ratchet_for_send.lock().await;
                match Self::encrypt_frame(&data, &mut ratchet_guard) {
                    Ok(encrypted) => {
                        if let Err(e) = ws_write.send(Message::Binary(encrypted)).await {
                            error!("WebSocket send error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Encryption error: {}", e);
                        break;
                    }
                }
            }
            Ok(())
        });

        // Wait for the first task to complete; all remaining tasks are then aborted.
        if let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {
                    debug!("Relay sub-task completed normally");
                }
                Ok(Err(e)) => {
                    debug!("Relay sub-task error: {}", e);
                }
                Err(je) => {
                    // Task was aborted — this is normal during shutdown
                    debug!("Relay sub-task aborted: {:?}", je);
                }
            }
            tasks.abort_all();
        }

        // Graceful shutdown: give TLS time to send close_notify
        tokio::time::sleep(Duration::from_millis(50)).await;

        Ok(())
    }

    /// Relay data bidirectionally between WebSocket and UDP target
    async fn relay_udp<S>(
        &self,
        mut ws_write: futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<S>,
            Message,
        >,
        mut ws_read: futures_util::stream::SplitStream<tokio_tungstenite::WebSocketStream<S>>,
        target_addr: &TargetAddress,
        ratchet: DoubleRatchet,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        use tokio::net::UdpSocket;

        // Bind a local UDP socket
        let local_addr = SocketAddr::from(([0, 0, 0, 0], 0));
        let udp_socket = UdpSocket::bind(local_addr).await?;

        // Resolve target address
        let target_socket_addr = match self
            .resolve_and_cache(&target_addr.host, target_addr.port)
            .await
        {
            Ok(addrs) => {
                if let Some(addr) = addrs.first() {
                    *addr
                } else {
                    return Err(anyhow::anyhow!(
                        "No addresses resolved for {}:{}",
                        target_addr.host,
                        target_addr.port
                    ));
                }
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to resolve {}:{}: {}",
                    target_addr.host,
                    target_addr.port,
                    e
                ));
            }
        };

        // Block connections to private/reserved addresses (except tunnel subnet)
        let allowed_cidr = Some(self.config.tun.tun_ip.as_str());
        if should_block_address(&target_socket_addr.ip(), allowed_cidr) {
            debug!(
                "Blocking UDP relay to private/reserved address {} for {}",
                target_socket_addr.ip(),
                target_addr.host
            );
            return Err(anyhow::anyhow!(
                "Connection to private/reserved address {} is not allowed",
                target_socket_addr.ip()
            ));
        }

        info!("UDP relay to {} ({})", target_socket_addr, target_addr.host);

        // Share ratchet between tasks using Arc<Mutex>
        let ratchet = std::sync::Arc::new(tokio::sync::Mutex::new(ratchet));

        // Clone ratchet for the spawned tasks
        let ratchet_for_ws = ratchet.clone();
        let ratchet_for_send = ratchet.clone();
        let udp_socket = std::sync::Arc::new(udp_socket);
        let udp_socket_for_recv = udp_socket.clone();

        // Channel for UDP -> WebSocket direction
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);

        // Use JoinSet so ALL tasks are aborted when any one completes
        let mut tasks: JoinSet<Result<()>> = JoinSet::new();

        // Task 1: WebSocket -> UDP (decrypt and forward)
        tasks.spawn(async move {
            let mut last_activity = Instant::now();
            let timeout = Duration::from_secs(60); // 1 minute idle timeout for UDP

            loop {
                tokio::select! {
                    msg = ws_read.next() => {
                        match msg {
                            Some(Ok(Message::Binary(data))) => {
                                last_activity = Instant::now();

                                // Decrypt frame using Double Ratchet
                                let decrypted = {
                                    let mut ratchet_guard = ratchet_for_ws.lock().await;
                                    match Self::decrypt_frame(&data, &mut ratchet_guard) {
                                        Ok(data) => data,
                                        Err(e) => {
                                            error!("Decryption error: {}", e);
                                            continue;
                                        }
                                    }
                                };

                                // Strip padding
                                let plaintext = match rvpn_core::protocol::padding::unpad_packet(&decrypted) {
                                    Ok(data) => data,
                                    Err(e) => {
                                        error!("Unpad error: {}", e);
                                        continue;
                                    }
                                };

                                // Send to UDP target
                                if let Err(e) = udp_socket.send_to(&plaintext, target_socket_addr).await {
                                    error!("UDP send failed: {}", e);
                                    break;
                                }
                            }
                            Some(Ok(Message::Ping(_))) => {
                                last_activity = Instant::now();
                            }
                            Some(Ok(Message::Close(_))) | None => {
                                break;
                            }
                            Some(Ok(_)) => {}
                            Some(Err(e)) => {
                                debug!("WebSocket read error: {}", e);
                                break;
                            }
                        }
                    }
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {
                        if last_activity.elapsed() > timeout {
                            debug!("UDP idle timeout, closing connection");
                            break;
                        }
                    }
                }
            }
            Ok(())
        });

        // Task 2: UDP -> Channel (receive and send to channel)
        tasks.spawn(async move {
            // 8190, not 8192 — pad_packet reserves 2 bytes for padding-length field
            let mut buf = [0u8; 8190];

            loop {
                match udp_socket_for_recv.recv_from(&mut buf).await {
                    Ok((n, _from)) => {
                        if tx.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        error!("UDP recv failed: {}", e);
                        break;
                    }
                }
            }
            Ok(())
        });

        // Task 3: Channel -> WebSocket (encrypt and send)
        tasks.spawn(async move {
            while let Some(data) = rx.recv().await {
                let mut ratchet_guard = ratchet_for_send.lock().await;
                match Self::encrypt_frame(&data, &mut ratchet_guard) {
                    Ok(encrypted) => {
                        if let Err(e) = ws_write.send(Message::Binary(encrypted)).await {
                            error!("WebSocket send error: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Encryption error: {}", e);
                        break;
                    }
                }
            }
            Ok(())
        });

        // Wait for the first task to complete; all remaining tasks are then aborted.
        if let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {
                    debug!("UDP relay sub-task completed normally");
                }
                Ok(Err(e)) => {
                    debug!("UDP relay sub-task error: {}", e);
                }
                Err(je) => {
                    debug!("UDP relay sub-task aborted: {:?}", je);
                }
            }
            tasks.abort_all();
        }

        Ok(())
    }

    /// Encrypt a frame using Double Ratchet
    /// Format: [serialized RatchetMessage]
    fn encrypt_frame(data: &[u8], ratchet: &mut DoubleRatchet) -> Result<Vec<u8>> {
        // Pad to 1KB boundary before encryption
        let padded = rvpn_core::protocol::padding::pad_packet(data)
            .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;

        // Encrypt with Double Ratchet
        let message = ratchet
            .encrypt(&padded, &[0x01]) // 0x01 = ProxyData payload type
            .map_err(|e| anyhow::anyhow!("Double Ratchet encryption failed: {}", e))?;

        // Serialize the RatchetMessage
        let serialized = message
            .to_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize RatchetMessage: {}", e))?;

        Ok(serialized)
    }

    /// Decrypt a frame using Double Ratchet
    fn decrypt_frame(data: &[u8], ratchet: &mut DoubleRatchet) -> Result<Vec<u8>> {
        tracing::trace!("Decrypting frame: {} bytes", data.len());

        // Deserialize the RatchetMessage
        let message = RatchetMessage::from_bytes(data).map_err(|e| {
            tracing::error!(
                "Failed to deserialize RatchetMessage: {}. Raw data (first 100 bytes): {:?}",
                e,
                &data[..data.len().min(100)]
            );
            anyhow::anyhow!("Failed to deserialize RatchetMessage: {}", e)
        })?;

        tracing::trace!(
            "Deserialized RatchetMessage: header.message_number={}, payload_type={}",
            message.header.message_number,
            message.header.payload_type
        );

        // Use appropriate AAD based on payload_type from header
        // Must match client's AAD logic for successful decryption
        // 0x00 = Desktop protocol (V1 legacy), 0x01+ = Multiplexed protocol (V2)
        let aad: &[u8] = match message.header.payload_type {
            0x00 => &[0x00], // Desktop protocol (V1 legacy) - raw packet mode
            0x01 => &[0x01], // Data
            0x02 => &[0x02], // Admin
            0x03 => &[0x03], // KeepAlive
            0x04 => &[0x04], // Padding
            0x05 => &[0x05], // ProxyConnect
            0x06 => &[0x06], // ProxyResponse
            0x07 => &[0x07], // ProxyData
            0x08 => &[0x08], // DnsQuery
            0x09 => &[0x09], // DnsResponse
            0x0A => &[0x0A], // ProxyDataBatch
            0x0B => &[0x0B], // UdpInit
            0x0C => &[0x0C], // UdpData
            _ => {
                error!(
                    "[SERVER] Unknown payload type: {}",
                    message.header.payload_type
                );
                return Err(anyhow::anyhow!(
                    "Unknown payload type: {}",
                    message.header.payload_type
                ));
            }
        };

        // Decrypt with Double Ratchet
        let plaintext = ratchet.decrypt(&message, aad).map_err(|e| {
            tracing::error!("Double Ratchet decryption failed (AAD={:?}): {:?}", aad, e);
            anyhow::anyhow!("Double Ratchet decryption failed: {}", e)
        })?;

        tracing::trace!("Decrypted plaintext: {} bytes", plaintext.len());
        Ok(plaintext)
    }
}

/// Simple rate limiter
#[derive(Debug)]
pub struct RateLimiter {
    max_per_minute: u32,
    max_connections: u32,
    requests: std::collections::HashMap<std::net::IpAddr, (u32, Instant)>,
}

impl RateLimiter {
    pub fn new(max_connections_per_ip: u32, max_handshakes_per_minute: u32) -> Self {
        Self {
            max_per_minute: max_handshakes_per_minute,
            max_connections: max_connections_per_ip,
            requests: std::collections::HashMap::new(),
        }
    }

    pub fn check(&self, ip: &std::net::IpAddr) -> bool {
        let now = Instant::now();

        if let Some((count, start)) = self.requests.get(ip) {
            let elapsed = now.duration_since(*start);
            if elapsed.as_secs() < 60 {
                return *count < self.max_per_minute && *count < self.max_connections;
            }
        }

        true
    }

    /// Atomically check rate limit and record the request if allowed.
    /// Performs lazy cleanup of stale entries (older than 60 seconds).
    pub fn check_and_record(&mut self, ip: &std::net::IpAddr) -> bool {
        let now = Instant::now();

        // Lazy cleanup: remove stale entries older than 60 seconds
        self.requests.retain(|_, (_, start)| {
            now.duration_since(*start).as_secs() < 60
        });

        if let Some((count, start)) = self.requests.get(ip) {
            let elapsed = now.duration_since(*start);
            if elapsed.as_secs() < 60 {
                if *count >= self.max_per_minute || *count >= self.max_connections {
                    return false;
                }
                self.requests.insert(*ip, (count + 1, now));
                return true;
            }
        }

        // New entry or expired window
        self.requests.insert(*ip, (1, now));
        true
    }

    pub fn record(&mut self, ip: std::net::IpAddr) {
        let now = Instant::now();

        if let Some((count, start)) = self.requests.get_mut(&ip) {
            let elapsed = now.duration_since(*start);
            if elapsed.as_secs() < 60 {
                *count += 1;
                return;
            }
        }

        self.requests.insert(ip, (1, now));
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new(5, 10)
    }
}

/// Multiplexed VPN handler - One WebSocket = Multiple TCP connections
/// Uses X3DH handshake + Double Ratchet encryption
/// Frame format: [flow_id: u32 (BE)][payload_len: u16 (BE)][payload: bytes]
pub struct MultiplexerHandler {
    #[allow(dead_code)]
    config: ServerConfig,
    x3dh_responder: Option<Arc<X3DHResponder>>,
    dns_cache: DnsCache,
}

impl MultiplexerHandler {
    pub fn new(config: ServerConfig) -> Result<Self> {
        // Load identity key and create X3DH responder (same as VpnHandler)
        let x3dh_responder = if config.identity_key_file.exists() {
            match IdentityKey::load(&config.identity_key_file) {
                Ok(identity) => {
                    info!(
                        "Loaded server identity key from {:?}",
                        config.identity_key_file
                    );

                    // Try to load signed_prekey from private key file
                    let signed_prekey = config.prekey_bundle_file.as_ref()
                        .and_then(|bundle_path| {
                            let private_key_path = bundle_path.with_extension("private.json");
                            if private_key_path.exists() {
                                match Self::load_signed_prekey_private(&private_key_path) {
                                    Ok(key) => {
                                        info!("Loaded signed_prekey from private key file: {:?}", private_key_path);
                                        Some(key)
                                    }
                                    Err(e) => {
                                        warn!("Failed to load private key file: {}. Generating new signed_prekey.", e);
                                        None
                                    }
                                }
                            } else {
                                None
                            }
                        });

                    match signed_prekey {
                        Some(prekey) => {
                            info!("Using existing signed_prekey from prekey bundle");
                            Some(Arc::new(X3DHResponder::from_identity_with_bundle(
                                identity, prekey,
                            )))
                        }
                        None => {
                            warn!("No prekey bundle found. Generating new signed_prekey (clients will need updated bundle!)");
                            Some(Arc::new(X3DHResponder::from_identity(identity)))
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to load identity key: {}. X3DH handshake will not be available.",
                        e
                    );
                    None
                }
            }
        } else {
            warn!(
                "No identity key file found at {:?}. X3DH handshake will not be available.",
                config.identity_key_file
            );
            None
        };

        Ok(Self {
            config,
            x3dh_responder,
            dns_cache: std::sync::Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        })
    }

    /// Load signed_prekey private key from private key JSON file
    fn load_signed_prekey_private(private_key_path: &std::path::Path) -> Result<[u8; 32]> {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

        let content = std::fs::read_to_string(private_key_path).with_context(|| {
            format!(
                "Failed to read private key file from {:?}",
                private_key_path
            )
        })?;

        #[derive(serde::Deserialize)]
        struct PrivateKeyJson {
            #[serde(rename = "signed_prekey_private")]
            signed_prekey_private: String,
        }

        let private_key: PrivateKeyJson = serde_json::from_str(&content).with_context(|| {
            format!(
                "Failed to parse private key file from {:?}",
                private_key_path
            )
        })?;

        let decoded = BASE64
            .decode(&private_key.signed_prekey_private)
            .with_context(|| "Failed to decode base64 signed_prekey_private")?;

        if decoded.len() != 32 {
            anyhow::bail!(
                "signed_prekey_private must be 32 bytes, got {}",
                decoded.len()
            );
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&decoded);
        Ok(result)
    }

    /// Handle multiplexed WebSocket connection
    pub async fn handle_connection<S>(
        &self,
        ws_stream: tokio_tungstenite::WebSocketStream<S>,
        peer_addr: SocketAddr,
        tun_server: Option<Arc<dyn TunWriter>>,
        tun_config: TunNetworkConfig,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        info!("MUX: New multiplexed connection from {}", peer_addr);

        // Create and run the session handler
        let session = MultiplexerSession::new(
            ws_stream,
            self.x3dh_responder.clone(),
            self.dns_cache.clone(),
            peer_addr,
            tun_server,
            tun_config,
        );

        session.run().await
    }
}

pub struct TunHandler {
    inner: MultiplexerHandler,
    tun_server: Option<Arc<dyn TunWriter>>,
    tun_config: TunNetworkConfig,
}

impl TunHandler {
    pub fn new(config: ServerConfig, tun_server: Option<Arc<dyn TunWriter>>) -> Result<Self> {
        Ok(Self {
            inner: MultiplexerHandler::new(config.clone())?,
            tun_server,
            tun_config: config.tun,
        })
    }

    pub async fn handle_connection<S>(
        &self,
        ws_stream: tokio_tungstenite::WebSocketStream<S>,
        peer_addr: SocketAddr,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        self.inner
            .handle_connection(
                ws_stream,
                peer_addr,
                self.tun_server.clone(),
                self.tun_config.clone(),
            )
            .await
    }
}

/// Message for sending data back to the WebSocket
enum MuxMessage {
    Data { flow_id: u32, data: Vec<u8> },
    Control(ControlMessage),
}

type FlowMap = Arc<Mutex<HashMap<u32, Arc<Mutex<OwnedWriteHalf>>>>>;

/// Pending per-flow data buffered before a flow is established.
/// Maps flow ID to a queue of (payload, sequence_number, age).
type PendingFlows = tokio::sync::Mutex<std::collections::HashMap<u32, Vec<(Vec<u8>, u64, Duration)>>>;

/// Pre-created TCP connections ready for immediate use.
/// Key: "target:port", Value: queue of fresh TcpStreams.
/// Avoids repeated DNS resolution + TCP connect to the same CDN hosts.
type TcpPool = Arc<Mutex<HashMap<String, VecDeque<tokio::net::TcpStream>>>>;

/// Individual multiplexed session handler
#[allow(dead_code)]
pub struct MultiplexerSession<S> {
    ws: tokio_tungstenite::WebSocketStream<S>,
    ratchet: Option<DoubleRatchet>,
    flows: FlowMap,
    x3dh_responder: Option<Arc<X3DHResponder>>,
    dns_cache: DnsCache,
    peer_addr: SocketAddr,
    tx: tokio::sync::mpsc::Sender<MuxMessage>,
    rx: Option<tokio::sync::mpsc::Receiver<MuxMessage>>,
    /// Channel for sending TO TUN (write path)
    /// process_incoming_frame_static sends to this, TUN device receives via tun_write_rx
    tun_write_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    tun_write_rx: Option<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    tun_server: Option<Arc<dyn TunWriter>>,
    tun_config: TunNetworkConfig,
    tcp_pool: TcpPool,
}

impl<S> MultiplexerSession<S>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    fn new(
        ws: tokio_tungstenite::WebSocketStream<S>,
        x3dh_responder: Option<Arc<X3DHResponder>>,
        dns_cache: DnsCache,
        peer_addr: SocketAddr,
        tun_server: Option<Arc<dyn TunWriter>>,
        tun_config: TunNetworkConfig,
    ) -> Self {
        let (tx, rx) = tokio::sync::mpsc::channel(2000);
        // TUN write channel: process_incoming_frame_static sends to this, TUN device receives
        let (tun_write_tx, tun_write_rx) = tokio::sync::mpsc::channel(2000);
        Self {
            ws,
            ratchet: None,
            flows: Arc::new(Mutex::new(HashMap::new())),
            x3dh_responder,
            dns_cache,
            peer_addr,
            tx,
            rx: Some(rx),
            tun_write_tx,
            tun_write_rx: Some(tun_write_rx),
            tun_server,
            tun_config,
            tcp_pool: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn run(mut self) -> Result<()> {
        // 1. Perform X3DH handshake
        let mut ratchet = match self.perform_handshake().await? {
            Some(r) => r,
            None => {
                info!("Handshake failed or rejected for {}", self.peer_addr);
                return Ok(());
            }
        };

        info!("Multiplexed session established for {}", self.peer_addr);

        debug!("MultiplexerSession: peer={}, tun_enabled={}, tun_server_some={}, dns_count={}, mtu={}",
            self.peer_addr, self.tun_config.enabled, self.tun_server.is_some(),
            self.tun_config.dns_servers.len(), self.tun_config.mtu);

        // 2. In TUN mode: allocate IP and send VirtualIp after X3DH
        //    Do this BEFORE splitting the WebSocket so we can send directly
        let mut allocated_ip_for_tun: Option<std::net::IpAddr> = None;
        if self.tun_config.enabled {
            info!("TUN_MODE: tun_config.enabled=true for client {}", self.peer_addr);
            if let Some(ref tun_server) = self.tun_server {
                info!("TUN_MODE: tun_server is Some, proceeding with allocation for {}", self.peer_addr);
                // Allocate IP from pool
                let client_id = self.peer_addr.to_string();
                match tun_server.allocate_ip(client_id).await {
                    Ok(allocated_ip) => {
                        info!(
                            "Allocated IP {} for client {}",
                            allocated_ip, self.peer_addr
                        );
                        allocated_ip_for_tun = Some(allocated_ip);

                        // Build VirtualIp message
                        // Parse gateway IP from tun_ip (e.g., "10.200.0.1/24" -> "10.200.0.1")
                        let gateway_ip: Option<std::net::Ipv4Addr> = self
                            .tun_config
                            .tun_ip
                            .split('/')
                            .next()
                            .and_then(|ip| ip.parse().ok());

                        let virtual_ip = rvpn_core::protocol::VirtualIp {
                            ipv4: if let std::net::IpAddr::V4(v4) = allocated_ip {
                                Some(v4)
                            } else {
                                None
                            },
                            ipv6: None,
                            gateway_ip,
                            dns_servers: self.tun_config.dns_servers.clone(),
                            mtu: self.tun_config.mtu,
                        };

                        // Serialize VirtualIp as JSON
                        let virtual_ip_bytes = serde_json::to_vec(&virtual_ip)
                            .context("Failed to serialize VirtualIp")?;

                        // Use PayloadType::VirtualIp (0x0D) for IP assignment messages
                        let padded = rvpn_core::protocol::padding::pad_packet(&virtual_ip_bytes)
                            .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;
                        let encrypted = ratchet
                            .encrypt(&padded, &[PayloadType::VirtualIp as u8])
                            .context("Failed to encrypt VirtualIp")?;
                        let serialized = encrypted
                            .to_bytes()
                            .context("Failed to serialize VirtualIp RatchetMessage")?;

                        // Send VirtualIp to client (before splitting WebSocket)
                        if let Err(e) = self.ws.send(Message::Binary(serialized)).await {
                            error!("Failed to send VirtualIp: {}", e);
                        } else {
                            info!(
                                "Sent VirtualIp {} to client {}",
                                allocated_ip, self.peer_addr
                            );
                        }
                    }
                    Err(e) => {
                        error!("Failed to allocate IP for client {}: {}", self.peer_addr, e);
                    }
                }
            }
        }

        // Store ratchet in self for later use
        self.ratchet = Some(ratchet);

        // 3. Run WebSocket reader and writer concurrently
        let flows = self.flows.clone();
        let pending_flows: Arc<PendingFlows> =
            Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
        let peer_addr = self.peer_addr;
        let tx = self.tx.clone();
        let dns_cache = self.dns_cache.clone();
        let tun_server = self.tun_server.clone();
        let tun_config = self.tun_config.clone();
        let tun_write_tx = self.tun_write_tx.clone();
        let (ws_write, mut ws_read) = self.ws.split();
        let mut rx = self.rx.take().expect("rx should be present");
        let mut tun_write_rx = self
            .tun_write_rx
            .take()
            .expect("tun_write_rx should be present");

        // Wrap ws_write in Arc<Mutex> for sharing between tasks
        let ws_write = Arc::new(Mutex::new(ws_write));
        let ws_write_for_sender = ws_write.clone();
        let ws_write_for_tun = ws_write.clone();
        let ws_write_for_ping = ws_write.clone();

        // Wrap ratchet in Arc<Mutex> for sharing between tasks
        let ratchet = Arc::new(Mutex::new(self.ratchet.take().unwrap()));
        let ratchet_for_sender = ratchet.clone();
        let ratchet_for_tun = ratchet.clone();

        // Create channel for TUN response packets
        // TunServer sends raw packets here, we encrypt and send via WebSocket
        let (tun_response_tx, mut tun_response_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);

        // Register client with TunServer for TUN response routing
        if let Some(allocated_ip) = allocated_ip_for_tun {
            info!("About to register client {} with TUN server", allocated_ip);
            if let Some(ref ts) = tun_server {
                info!("tun_server is Some, calling register_client for {}", allocated_ip);
                match ts.register_client(allocated_ip, tun_response_tx).await {
                    Ok(()) => {
                        info!("Successfully registered client {} with TUN server", allocated_ip);
                    }
                    Err(e) => {
                        error!(
                            "Failed to register client {} with TUN server: {}",
                            allocated_ip, e
                        );
                    }
                }
            } else {
                warn!("Cannot register client {} - tun_server is None!", allocated_ip);
            }
        } else {
            warn!("Cannot register client - allocated_ip_for_tun is None!");
        }

        // Task to receive TUN response packets, encrypt, and send via WebSocket.
        //
        // IMPORTANT: Do NOT hold the ratchet lock during the WebSocket send.
        // If the send blocks (TCP backpressure from client), holding the ratchet
        // lock prevents ws_receiver from decrypting incoming packets, which
        // freezes the entire session. Encrypt first (with ratchet lock), then
        // release it, then send (with ws_write lock only).
        let tun_response_task = async move {
            while let Some(packet) = tun_response_rx.recv().await {
                // Step 1: Encrypt — hold ratchet lock only during this fast operation
                let encrypted = {
                    let mut ratchet_guard = ratchet_for_tun.lock().await;
                    match Self::encrypt_data_frame(&mut ratchet_guard, &packet) {
                        Ok(enc) => enc,
                        Err(e) => {
                            error!("Failed to encrypt TUN response: {}", e);
                            break;
                        }
                    }
                };
                // ratchet_guard dropped here — ws_receiver / ws_sender can encrypt/decrypt

                // Step 2: Send — hold ws_write lock only
                {
                    let mut ws_write_guard = ws_write_for_tun.lock().await;
                    if let Err(e) = ws_write_guard.send(Message::Binary(encrypted)).await {
                        error!("Failed to send TUN response via WebSocket: {}", e);
                        break;
                    } else {
                        debug!("Sent encrypted TUN response ({} bytes packet)", packet.len());
                    }
                }
            }
            debug!("TUN response task ended");
        };

        // Task to receive from flows and send to WebSocket.
        // Locks are held briefly: ratchet only during encrypt, ws_write only
        // during send. This prevents a slow WebSocket write from blocking
        // other tasks that need the ratchet (like the receive path).
        let ws_sender = async move {
            while let Some(msg) = rx.recv().await {
                // Step 1: Build plaintext frame (no locks needed)
                let (plaintext, aad) = match &msg {
                    MuxMessage::Data { flow_id, data } => {
                        let mut pt = Vec::with_capacity(6 + data.len());
                        pt.extend_from_slice(&flow_id.to_be_bytes());
                        pt.extend_from_slice(&(data.len() as u16).to_be_bytes());
                        pt.extend_from_slice(data);
                        (pt, vec![0x01u8])
                    }
                    MuxMessage::Control(control) => {
                        let frame = match rvpn_core::protocol::MultiplexedFrame::new_control(control) {
                            Ok(f) => f,
                            Err(e) => { error!("Failed to create control frame: {}", e); break; }
                        };
                        let encoded = match frame.encode() {
                            Ok(e) => e,
                            Err(e) => { error!("Failed to encode control frame: {}", e); break; }
                        };
                        (encoded.to_vec(), vec![0x02u8])
                    }
                };

                // Step 2: Pad (no locks needed)
                let padded = match rvpn_core::protocol::padding::pad_packet(&plaintext) {
                    Ok(p) => p,
                    Err(e) => { error!("Padding failed: {}", e); break; }
                };

                // Step 3: Encrypt — hold ratchet lock only during this fast operation
                let serialized = {
                    let mut ratchet_guard = ratchet_for_sender.lock().await;
                    match ratchet_guard.encrypt(&padded, &aad) {
                        Ok(message) => match message.to_bytes() {
                            Ok(bytes) => bytes,
                            Err(e) => { error!("Serialization failed: {}", e); break; }
                        },
                        Err(e) => { error!("Encryption failed: {}", e); break; }
                    }
                };
                // ratchet_guard dropped here — other tasks can encrypt now

                // Step 4: Send — hold ws_write lock only during this async send
                {
                    let mut ws_write_guard = ws_write_for_sender.lock().await;
                    if let Err(e) = ws_write_guard.send(Message::Binary(serialized)).await {
                        error!("WebSocket send failed: {:?}", e);
                        break;
                    }
                }
                // ws_write_guard dropped here — tun_response_task / ping_task can send now
            }
        };

        // Task to consume packets from tun_write_rx and write to TUN device
        // process_incoming_frame_static sends to tun_write_tx, we forward to tun_server
        let tun_server_for_write = tun_server.clone();
        let tun_write_task = async move {
            while let Some(packet) = tun_write_rx.recv().await {
                if let Some(ref ts) = tun_server_for_write {
                    if let Err(e) = ts.write_to_tun(&packet).await {
                        error!("Failed to write to TUN device: {}", e);
                        break;
                    }
                } else {
                    error!("tun_server not available for TUN write");
                    break;
                }
            }
        };

        // Track last time we received any traffic from the client. TUN clients
        // send keepalives every 15s; if we see nothing for 90s the client is
        // likely dead (suspended process, dropped NAT mapping, etc.).
        let last_activity = Arc::new(std::sync::Mutex::new(Instant::now()));
        let last_activity_for_receiver = last_activity.clone();
        let last_activity_for_ping = last_activity.clone();

        // Task to receive from WebSocket and process.
        // The ratchet lock is held only during decrypt (fast), then released
        // before dispatching to flows. This prevents a slow target TCP write
        // from blocking the entire receive path.
        let ws_receiver = {
            let tx = tx.clone();
            let flows = flows.clone();
            let ratchet = ratchet.clone();
            let tun_server_for_receiver = tun_server.clone();
            let tcp_pool = self.tcp_pool.clone();
            let session_start = Instant::now();
            let frame_counter = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let frame_counter_clone = frame_counter.clone();
            let last_activity = last_activity_for_receiver;

            async move {
                let idle_timeout = Duration::from_secs(90);
                loop {
                    let remaining = idle_timeout
                        .saturating_sub(last_activity.lock().unwrap().elapsed());
                    if remaining.is_zero() {
                        warn!(
                            "TUN client {} idle timeout (no traffic for {}s), closing",
                            peer_addr,
                            idle_timeout.as_secs()
                        );
                        break;
                    }
                    let msg = tokio::time::timeout(remaining, ws_read.next()).await;
                    match msg {
                        Ok(Some(Ok(Message::Binary(data)))) => {
                            *last_activity.lock().unwrap() = Instant::now();
                            let frame_num = frame_counter_clone
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                                + 1;
                            let elapsed = session_start.elapsed();

                            // Step 1: Decrypt — hold ratchet lock only during this fast operation
                            let decrypt_result = {
                                let mut ratchet_guard = ratchet.lock().await;
                                Self::decrypt_and_parse_frame(
                                    &data,
                                    &mut ratchet_guard,
                                    frame_num,
                                    peer_addr,
                                    elapsed,
                                )
                            };
                            // ratchet_guard dropped here — ws_sender / tun_response can encrypt

                            // Step 2: Dispatch — may block on TCP write, but doesn't block ratchet
                            match decrypt_result {
                                Ok(frames) => {
                                    let batch_size = frames.len();
                                    for (idx, (flow_id, payload, aad_type)) in frames.into_iter().enumerate() {
                                        if let Err(e) = Self::dispatch_decrypted_frame(
                                            flow_id,
                                            &payload,
                                            aad_type,
                                            &flows,
                                            &tx,
                                            &tun_write_tx,
                                            peer_addr,
                                            &dns_cache,
                                            tun_server_for_receiver.as_ref(),
                                            &tun_config,
                                            &pending_flows,
                                            &tcp_pool,
                                            frame_num,
                                            elapsed,
                                        ).await {
                                            error!(
                                                "FRAME: [#{:05}] dispatch {}/{} failed: {}",
                                                frame_num, idx + 1, batch_size, e
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("Frame decrypt error: {}", e);
                                }
                            }
                        }
                        Ok(Some(Ok(Message::Ping(_)))) => {
                            *last_activity.lock().unwrap() = Instant::now();
                        }
                        Ok(Some(Ok(Message::Pong(_)))) => {
                            *last_activity.lock().unwrap() = Instant::now();
                        }
                        Ok(Some(Ok(Message::Close(_)))) |
                        Ok(None) |
                        Ok(Some(Err(_))) => {
                            break;
                        }
                        Ok(Some(Ok(_))) => {
                            *last_activity.lock().unwrap() = Instant::now();
                        }
                        Err(_) => {
                            // Timeout already checked at the top of the loop;
                            // this arm handles timeout while waiting for a frame.
                            break;
                        }
                    }
                }
            }
        };

        // Ping task — sends WebSocket-level pings to keep connection alive
        // and detect asymmetric path failures (client can still send but
        // cannot receive).
        let ping_task = async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                // If the client has been idle for most of the timeout, skip the
                // ping and let the receiver time out cleanly instead of sending
                // on a potentially dead socket.
                if last_activity_for_ping.lock().unwrap().elapsed() > Duration::from_secs(75) {
                    warn!("Skipping ping for {}: client idle too long", peer_addr);
                    break;
                }
                let mut guard = ws_write_for_ping.lock().await;
                if let Err(e) = guard.send(Message::Ping(vec![])).await {
                    trace!("Ping send failed for {}: {}", peer_addr, e);
                    break;
                }
                trace!("Sent WebSocket ping to {}", peer_addr);
            }
        };

        // Run all tasks concurrently
        tokio::select! {
            _ = ws_sender => {
                debug!("WebSocket sender task ended for {}", peer_addr);
            }
            _ = ws_receiver => {
                debug!("WebSocket receiver task ended for {}", peer_addr);
            }
            _ = tun_write_task => {
                debug!("TUN write task ended for {}", peer_addr);
            }
            _ = tun_response_task => {
                debug!("TUN response task ended for {}", peer_addr);
            }
            _ = ping_task => {
                debug!("Ping task ended for {}", peer_addr);
            }
        }

        // Clean up flows
        let mut flows_guard = flows.lock().await;
        let count = flows_guard.len();
        flows_guard.clear();
        if count > 0 {
            info!("Cleaned up {} flows for {}", count, peer_addr);
        }

        // Clean up connection pool
        self.tcp_pool.lock().await.clear();

        // Release IP lease and unregister client from TUN server
        // This prevents IP pool exhaustion when sessions end
        if let Some(ref ts) = tun_server {
            if let Some(client_ip) = allocated_ip_for_tun {
                let client_id = peer_addr.to_string();
                if let Err(e) = ts.unregister_client(client_ip, &client_id).await {
                    warn!("Failed to unregister client {} from TUN server: {}", client_ip, e);
                }
            }
        }

        Ok(())
    }

    #[allow(dead_code)]
    async fn send_data_frame(
        ws_write: &mut futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<S>,
            Message,
        >,
        ratchet: &mut DoubleRatchet,
        flow_id: u32,
        data: &[u8],
    ) -> Result<()> {
        // Build plaintext frame
        let mut plaintext = Vec::with_capacity(6 + data.len());
        plaintext.extend_from_slice(&flow_id.to_be_bytes());
        plaintext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(data);

        // Pad to 1KB boundary before encryption
        let padded = rvpn_core::protocol::padding::pad_packet(&plaintext)
            .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;

        // Encrypt
        let message = ratchet
            .encrypt(&padded, &[0x01])
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        let serialized = message
            .to_bytes()
            .map_err(|e| anyhow::anyhow!("Serialization failed: {}", e))?;

        ws_write
            .send(Message::Binary(serialized))
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket send failed: {:?}", e))?;

        Ok(())
    }

    #[allow(dead_code)]
    async fn send_control_frame(
        ws_write: &mut futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<S>,
            Message,
        >,
        ratchet: &mut DoubleRatchet,
        control: &ControlMessage,
    ) -> Result<()> {
        let data = bincode::serialize(control)
            .map_err(|e| anyhow::anyhow!("Control serialization failed: {}", e))?;

        // Build plaintext frame for flow_id = 0
        let mut plaintext = Vec::with_capacity(6 + data.len());
        plaintext.extend_from_slice(&0u32.to_be_bytes());
        plaintext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        plaintext.extend_from_slice(&data);

        // Pad to 1KB boundary before encryption
        let padded = rvpn_core::protocol::padding::pad_packet(&plaintext)
            .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;

        // Encrypt
        let message = ratchet
            .encrypt(&padded, &[0x01])
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        let serialized = message
            .to_bytes()
            .map_err(|e| anyhow::anyhow!("Serialization failed: {}", e))?;

        ws_write
            .send(Message::Binary(serialized))
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket send failed: {:?}", e))?;

        Ok(())
    }

    /// Encrypt a data frame (for TUN responses)
    /// Wraps the packet in a MultiplexedFrame with flow_id=1 before encrypting
    fn encrypt_data_frame(ratchet: &mut DoubleRatchet, data: &[u8]) -> Result<Vec<u8>> {
        // Wrap the raw packet in a MultiplexedFrame
        // flow_id=1 for TUN data (control messages use flow_id=0)
        let frame = MultiplexedFrame::new_data(1, data.to_vec());
        let encoded = frame.encode()
            .map_err(|e| anyhow::anyhow!("Failed to encode multiplexed frame: {}", e))?;

        // Pad to 1KB boundary before encryption
        let padded = rvpn_core::protocol::padding::pad_packet(&encoded)
            .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;

        // Encrypt with Data payload type (0x01)
        let message = ratchet
            .encrypt(&padded, &[0x01])
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        // Serialize the RatchetMessage
        let serialized = message
            .to_bytes()
            .map_err(|e| anyhow::anyhow!("Failed to serialize RatchetMessage: {}", e))?;

        Ok(serialized)
    }

    /// Process incoming encrypted frame from WebSocket
    /// This is called for EVERY frame received from the client
    /// Added frame_number and elapsed parameters for ordering verification
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    async fn process_incoming_frame_static(
        data: &[u8],
        flows: &FlowMap,
        tx: &tokio::sync::mpsc::Sender<MuxMessage>,
        _tun_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
        peer_addr: SocketAddr,
        ratchet: &mut DoubleRatchet,
        dns_cache: &DnsCache,
        tun_server: Option<&Arc<dyn TunWriter>>,
        tun_config: &TunNetworkConfig,
        pending_flows: &PendingFlows,
        frame_number: u64,
        elapsed: Duration,
    ) -> Result<()> {
        // Debug: Log raw frame info
        tracing::trace!(
            "FRAME: [#{:05}] Raw frame received from {} after {:.3}s ({} bytes)",
            frame_number,
            peer_addr,
            elapsed.as_secs_f64(),
            data.len()
        );

        // Deserialize the RatchetMessage to check payload_type
        let message = RatchetMessage::from_bytes(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize RatchetMessage: {}", e))?;

        // Log the payload_type from the RatchetMessage header
        tracing::trace!(
            "FRAME: [#{:05}] RatchetMessage header: message_number={}, payload_type={}",
            frame_number,
            message.header.message_number,
            message.header.payload_type
        );

        // Use appropriate AAD based on payload_type from header
        // Must match client's AAD logic for successful decryption
        // 0x00 = Desktop protocol (V1 legacy), 0x01+ = Multiplexed protocol (V2)
        let aad: &[u8] = match message.header.payload_type {
            0x00 => &[0x00], // Desktop protocol (V1 legacy) - raw packet mode
            0x01 => &[0x01], // Data
            0x02 => &[0x02], // Admin
            0x03 => &[0x03], // KeepAlive
            0x04 => &[0x04], // Padding
            0x05 => &[0x05], // ProxyConnect
            0x06 => &[0x06], // ProxyResponse
            0x07 => &[0x07], // ProxyData
            0x08 => &[0x08], // DnsQuery
            0x09 => &[0x09], // DnsResponse
            0x0A => &[0x0A], // ProxyDataBatch
            0x0B => &[0x0B], // UdpInit
            0x0C => &[0x0C], // UdpData
            _ => {
                error!(
                    "[SERVER] Unknown payload type: {}",
                    message.header.payload_type
                );
                return Err(anyhow::anyhow!(
                    "Unknown payload type: {}",
                    message.header.payload_type
                ));
            }
        };

        trace!("Decrypting frame with AAD: {:?}", aad);

        let decrypted = ratchet
            .decrypt(&message, aad)
            .map_err(|e| anyhow::anyhow!("Decryption failed (AAD={:?}): {}", aad, e))?;

        // Strip 1KB boundary padding
        let plaintext = rvpn_core::protocol::padding::unpad_packet(&decrypted)
            .map_err(|e| anyhow::anyhow!("Unpad failed: {}", e))?;

        // Parse multiplexed frame: [flow_id: u32][payload_len: u16][payload]
        if plaintext.len() < 6 {
            warn!("Frame too short: {} bytes (min 6)", plaintext.len());
            return Ok(());
        }

        let flow_id = u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
        let payload_len = u16::from_be_bytes([plaintext[4], plaintext[5]]) as usize;

        // Log the parsed flow_id and classification decision
        let is_control = flow_id == 0;
        tracing::trace!(
            "FRAME: [#{:05}] CLASSIFICATION: flow_id={} -> {} (payload_type in header was {})",
            frame_number,
            flow_id,
            if is_control { "CONTROL" } else { "DATA" },
            message.header.payload_type
        );

        if plaintext.len() < 6 + payload_len {
            warn!(
                "Frame payload truncated: expected {} bytes, got {}",
                payload_len,
                plaintext.len() - 6
            );
            return Ok(());
        }

        let payload = &plaintext[6..6 + payload_len];

        // Detailed frame reception logging with timing information
        if flow_id == 0 {
            // Control message
            info!(
                "FRAME: [#{:05}] RECEIVED CONTROL frame from {} after {:.3}s (msg_num: {}, payload_type: {})",
                frame_number, peer_addr, elapsed.as_secs_f64(),
                message.header.message_number, message.header.payload_type
            );
            // Dead code path — pass empty pool (this function is #[allow(dead_code)])
            let dummy_pool: TcpPool = Arc::new(Mutex::new(HashMap::new()));
            Self::handle_control(payload, flows, tx, peer_addr, dns_cache, tun_config, pending_flows, &dummy_pool).await
        } else {
            // Data for existing flow
            info!(
                "FRAME: [#{:05}] RECEIVED DATA frame for flow_id {} from {} after {:.3}s ({} bytes, msg_num: {}, payload_type: {})",
                frame_number, flow_id, peer_addr, elapsed.as_secs_f64(), payload.len(),
                message.header.message_number, message.header.payload_type
            );

            // Check if flow exists before handling data
            let flows_guard = flows.lock().await;
            let flow_exists = flows_guard.contains_key(&flow_id);
            drop(flows_guard);

            info!(
                "FRAME: [#{:05}] flow_exists={}, tun_enabled={}, tun_server={}",
                frame_number, flow_exists, tun_config.enabled, tun_server.is_some()
            );

            if flow_exists {
                Self::handle_flow_data(flow_id, payload, flows).await
            } else if tun_config.enabled {
                // TUN mode: write packet directly to TUN interface instead of creating TCP flow
                // Extract source IP from packet to identify the client for response routing
                info!(
                    "FRAME: [#{:05}] TUN mode: attempting to route {} bytes (tun_server is {})",
                    frame_number,
                    payload.len(),
                    if tun_server.is_some() { "Some" } else { "None" }
                );

                // First check if tun_server is available
                let ts = match tun_server {
                    Some(ts) => ts,
                    None => {
                        warn!(
                            "FRAME: [#{:05}] TUN mode: tun_server is None - cannot route packet",
                            frame_number
                        );
                        return Err(anyhow::anyhow!("TUN mode: tun_server not available"));
                    }
                };

                // Now try to extract source IP
                let client_ip_str = match Self::extract_source_ip(payload) {
                    Some(ip) => ip,
                    None => {
                        // Log first bytes of payload for debugging
                        let preview: String = payload.iter().take(20)
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        warn!(
                            "FRAME: [#{:05}] TUN mode: failed to extract source IP from packet (first 20 bytes: {})",
                            frame_number, preview
                        );
                        return Err(anyhow::anyhow!("TUN mode: cannot extract source IP from packet"));
                    }
                };

                info!(
                    "FRAME: [#{:05}] TUN mode: writing {} bytes to TUN (client IP: {})",
                    frame_number, payload.len(), client_ip_str
                );

                if let Err(e) = ts.write_to_tun(payload).await {
                    error!(
                        "FRAME: [#{:05}] Failed to write to TUN: {}",
                        frame_number, e
                    );
                    return Err(e);
                }
                info!(
                    "FRAME: [#{:05}] Successfully wrote packet to TUN",
                    frame_number
                );
                // NOTE: Do NOT unregister client here - session stays alive for bidirectional TUN traffic
                Ok(())
            } else {
                // TCP mode: try to auto-create flow from the packet data
                // This supports mobile clients that send data without explicit CreateFlow
                if let Some((target, port)) = Self::parse_packet_for_destination(payload) {
                    info!(
                        "FRAME: [#{:05}] Auto-creating flow {} for {}:{} (client sent data without CreateFlow)",
                        frame_number, flow_id, target, port
                    );
                    tx.send(MuxMessage::Control(ControlMessage::CreateFlow {
                        flow_id,
                        target,
                        port,
                    }))
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to queue auto-CreateFlow: {}", e))?;
                    Ok(())
                } else if let Some((target, port)) = Self::parse_legacy_connect_payload(payload) {
                    // Fallback to legacy CONNECT format parsing
                    warn!(
                        "FRAME: [#{:05}] Legacy CONNECT payload detected for unknown flow_id {} from {} -> {}:{}",
                        frame_number, flow_id, peer_addr, target, port
                    );
                    tx.send(MuxMessage::Control(ControlMessage::CreateFlow {
                        flow_id,
                        target,
                        port,
                    }))
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to queue legacy CreateFlow: {}", e))?;
                    Ok(())
                } else {
                    // Data arrived before CreateFlow was processed — buffer it.
                    // This is a normal ordering issue with multiplexed SOCKS5 clients
                    // that send data immediately after CreateFlow.
                    debug!(
                        "FRAME: [#{:05}] DATA frame for pending flow_id {} from {} — buffering for later",
                        frame_number, flow_id, peer_addr
                    );
                    let mut pending = pending_flows.lock().await;
                    pending.entry(flow_id).or_default().push((
                        payload.to_vec(),
                        frame_number,
                        elapsed,
                    ));
                    // Cap buffer at 100 frames per flow to prevent memory exhaustion
                    if pending.get(&flow_id).map_or(0, |v| v.len()) > 100 {
                        pending.remove(&flow_id);
                        warn!(
                            "FRAME: [#{:05}] Buffer overflow for flow {} — dropping {} pending frames",
                            frame_number, flow_id, 100
                        );
                    }
                    Ok(())
                }
            }
        }
    }

    /// Parse IP packet to extract destination address and port
    /// Supports IPv4 and IPv6 UDP/TCP packets
    #[allow(dead_code)]
    fn parse_packet_for_destination(payload: &[u8]) -> Option<(String, u16)> {
        if payload.len() < 20 {
            return None;
        }

        // Check IP version
        let version = payload[0] >> 4;

        if version == 4 {
            // IPv4: minimum header is 20 bytes
            if payload.len() < 20 {
                return None;
            }

            let ihl = (payload[0] & 0x0F) as usize;
            if ihl < 5 {
                return None;
            }

            let _protocol = payload[9];
            let dst_ip = format!(
                "{}.{}.{}.{}",
                payload[16], payload[17], payload[18], payload[19]
            );

            // For UDP (17) and TCP (6), extract destination port
            if payload.len() >= ihl * 4 + 4 {
                let dst_port = u16::from_be_bytes([payload[ihl * 4 + 2], payload[ihl * 4 + 3]]);
                return Some((dst_ip, dst_port));
            }
            None
        } else if version == 6 {
            // IPv6: minimum header is 40 bytes
            if payload.len() < 40 {
                return None;
            }

            let _next_header = payload[6];
            let dst_ip = format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                payload[24], payload[25], payload[26], payload[27],
                payload[28], payload[29], payload[30], payload[31],
                payload[32], payload[33], payload[34], payload[35],
                payload[36], payload[37], payload[38], payload[39]);

            // For UDP (17) and TCP (6), extract destination port
            if payload.len() >= 44 {
                let dst_port = u16::from_be_bytes([payload[42], payload[43]]);
                return Some((dst_ip, dst_port));
            }
            None
        } else {
            None
        }
    }

    #[allow(dead_code)]
    fn parse_legacy_connect_payload(payload: &[u8]) -> Option<(String, u16)> {
        if payload.len() < 4 {
            return None;
        }
        let host_len = payload[0] as usize;
        if host_len == 0 || payload.len() != 1 + host_len + 2 {
            return None;
        }
        let host_bytes = &payload[1..1 + host_len];
        let host = std::str::from_utf8(host_bytes).ok()?.to_string();
        let port_idx = 1 + host_len;
        let port = u16::from_be_bytes([payload[port_idx], payload[port_idx + 1]]);
        Some((host, port))
    }

    /// Extract source IP from IP packet payload (for TUN mode client identification)
    #[allow(dead_code)]
    fn extract_source_ip(payload: &[u8]) -> Option<String> {
        if payload.len() < 20 {
            return None;
        }

        let version = payload[0] >> 4;
        if version == 4 {
            // IPv4: source IP at bytes 12-15
            let src_ip = format!(
                "{}.{}.{}.{}",
                payload[12], payload[13], payload[14], payload[15]
            );
            Some(src_ip)
        } else if version == 6 && payload.len() >= 40 {
            // IPv6: source IP at bytes 8-23
            let src_ip = format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                payload[8], payload[9], payload[10], payload[11],
                payload[12], payload[13], payload[14], payload[15],
                payload[16], payload[17], payload[18], payload[19],
                payload[20], payload[21], payload[22], payload[23]);
            Some(src_ip)
        } else {
            None
        }
    }

    /// Parse a target string as an IP literal SocketAddr.
    /// Handles IPv4 ("1.2.3.4:80") and bracketed IPv6 ("[::1]:80").
    /// Returns None for hostnames that require DNS resolution.
    fn parse_socket_addr_literal(target: &str) -> Option<SocketAddr> {
        // Try direct parse first (covers IPv4)
        if let Ok(addr) = target.parse() {
            return Some(addr);
        }

        // Handle bracketed IPv6 like "[2001:db8::1]:80"
        let (host, port_str) = target.rsplit_once(':')?;
        let port: u16 = port_str.parse().ok()?;
        let host = host.strip_prefix('[')?.strip_suffix(']')?;
        let ip: std::net::IpAddr = host.parse().ok()?;
        Some(SocketAddr::new(ip, port))
    }

    /// Connect to target with DNS caching
    async fn connect_with_dns_cache(
        target: &str,
        dns_cache: &DnsCache,
        tun_config: &TunNetworkConfig,
    ) -> Result<TcpStream> {
        let allowed_cidr = if tun_config.enabled {
            Some(tun_config.tun_ip.as_str())
        } else {
            None
        };

        // If target is an IP literal, use it directly without DNS resolution
        let addrs: Vec<SocketAddr> = if let Some(addr) = Self::parse_socket_addr_literal(target) {
            vec![addr]
        } else {
            let cache_key = target.to_string();
            let cache = dns_cache.lock().await;
            if let Some(entry) = cache.get(&cache_key) {
                if entry.cached_at.elapsed() < Duration::from_secs(300) {
                    debug!("DNS cache hit for {}", target);
                    entry.addrs.clone()
                } else {
                    drop(cache);
                    Self::resolve_and_cache(target, dns_cache).await?
                }
            } else {
                drop(cache);
                Self::resolve_and_cache(target, dns_cache).await?
            }
        };

        // Connect to the first available address in parallel
        connect_fastest(addrs, allowed_cidr, target).await
    }

    /// Resolve hostname and cache results
    async fn resolve_and_cache(target: &str, dns_cache: &DnsCache) -> Result<Vec<SocketAddr>> {
        debug!("DNS lookup for {}", target);

        let mut addrs: Vec<SocketAddr> = lookup_host(target.to_string()).await?.collect();

        if addrs.is_empty() {
            return Err(anyhow::anyhow!("No addresses found for {}", target));
        }

        // Prefer IPv4 over IPv6 for faster connections on most networks,
        // but keep IPv6 addresses for servers that do have IPv6 connectivity.
        addrs.sort_by_key(|a| match a.ip() {
            std::net::IpAddr::V4(_) => 0,
            std::net::IpAddr::V6(_) => 1,
        });

        let entry = DnsEntry {
            addrs: addrs.clone(),
            cached_at: Instant::now(),
            ttl: Duration::from_secs(300),
        };

        let mut cache = dns_cache.lock().await;
        cache.insert(target.to_string(), entry);

        Ok(addrs)
    }

    /// Perform X3DH handshake with client
    async fn perform_handshake(&mut self) -> Result<Option<DoubleRatchet>> {
        // Wait for Hello message
        let msg = timeout(Duration::from_secs(5), self.ws.next()).await;
        let msg = match msg {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => {
                info!("WebSocket error during handshake from {}: {}", self.peer_addr, e);
                return Ok(None);
            }
            Ok(None) => {
                info!("Connection closed by {} before handshake", self.peer_addr);
                return Ok(None);
            }
            Err(_) => {
                info!("Handshake timeout from {}", self.peer_addr);
                return Ok(None);
            }
        };

        // Parse Hello
        let hello: HandshakeMessage = match serde_json::from_slice(&msg.into_data()) {
            Ok(h) => h,
            Err(e) => {
                debug!(
                    "Failed to parse Hello message from {}: {}",
                    self.peer_addr, e
                );
                return Ok(None);
            }
        };

        match hello {
            HandshakeMessage::Hello {
                version,
                auth_method,
                ephemeral_key,
                identity_key,
                ..
            } => {
                info!(
                    "Client protocol version from {}: {} (server: {})",
                    self.peer_addr,
                    version,
                    ProtocolVersion::CURRENT
                );

                // Check protocol version compatibility
                if !version.is_compatible_with(&ProtocolVersion::CURRENT) {
                    warn!(
                        "Protocol version mismatch from {}: {} (expected {})",
                        self.peer_addr,
                        version,
                        ProtocolVersion::CURRENT
                    );
                    let error_response = HandshakeMessage::Error {
                        code: 1,
                        message: "Protocol version mismatch".to_string(),
                    };
                    let _ = self
                        .ws
                        .send(Message::Binary(serde_json::to_vec(&error_response)?))
                        .await;
                    return Ok(None);
                }

                // Check authentication method
                if auth_method != AuthMethod::X3DH {
                    warn!(
                        "Unsupported auth method from {}: {:?}",
                        self.peer_addr, auth_method
                    );
                    let error_response = HandshakeMessage::Error {
                        code: 2,
                        message: "Unsupported authentication method".to_string(),
                    };
                    let _ = self
                        .ws
                        .send(Message::Binary(serde_json::to_vec(&error_response)?))
                        .await;
                    return Ok(None);
                }

                // Get X3DH responder
                let responder = match self.x3dh_responder.as_ref() {
                    Some(r) => r,
                    None => {
                        error!("X3DH not configured on server");
                        let error_response = HandshakeMessage::Error {
                            code: 3,
                            message: "X3DH not available".to_string(),
                        };
                        let _ = self
                            .ws
                            .send(Message::Binary(serde_json::to_vec(&error_response)?))
                            .await;
                        return Ok(None);
                    }
                };

                // Extract keys from Hello message
                let client_ephemeral = match ephemeral_key {
                    Some(key) if key.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&key);
                        arr
                    }
                    _ => {
                        info!("Invalid or missing ephemeral key from {}", self.peer_addr);
                        return Ok(None);
                    }
                };

                let client_identity = match identity_key {
                    Some(key) if key.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&key);
                        arr
                    }
                    _ => {
                        info!("Invalid or missing identity key from {}", self.peer_addr);
                        return Ok(None);
                    }
                };

                // Perform X3DH agreement
                let shared_secret =
                    match responder.agree(&client_identity, &client_ephemeral, false) {
                        Ok(secret) => secret,
                        Err(e) => {
                            info!("X3DH agreement failed from {}: {}", self.peer_addr, e);
                            return Ok(None);
                        }
                    };

                info!("X3DH handshake successful from {}", self.peer_addr);

                // Initialize Double Ratchet as Bob (responder)
                info!("Initializing DoubleRatchet as Bob for {}", self.peer_addr);
                let ratchet = DoubleRatchet::init_bob(shared_secret);

                // Send ServerHello response
                info!("Preparing ServerHello for {}", self.peer_addr);
                let public_bundle = responder.get_public_bundle();
                let response = HandshakeMessage::ServerHello {
                    ephemeral_key: Vec::new(),
                    signed_prekey: public_bundle.signed_prekey.to_vec(),
                    prekey_signature: public_bundle.prekey_signature.to_vec(),
                    identity_key: public_bundle.identity_key.to_vec(),
                };

                info!("Serializing ServerHello for {} (signed_prekey={} bytes, sig={} bytes, identity={} bytes)",
                    self.peer_addr,
                    public_bundle.signed_prekey.len(),
                    public_bundle.prekey_signature.len(),
                    public_bundle.identity_key.len());

                let response_bytes = match serde_json::to_vec(&response) {
                    Ok(b) => b,
                    Err(e) => {
                        info!("Failed to serialize ServerHello for {}: {}", self.peer_addr, e);
                        return Ok(None);
                    }
                };

                info!("ServerHello serialized ({} bytes), sending to {}", response_bytes.len(), self.peer_addr);

                if let Err(e) = self.ws.send(Message::Binary(response_bytes)).await {
                    info!("Failed to send ServerHello to {}: {:?}", self.peer_addr, e);
                    return Ok(None);
                }

                info!("ServerHello sent to {}", self.peer_addr);
                info!("X3DH handshake completed with {}", self.peer_addr);

                Ok(Some(ratchet))
            }
            _ => {
                debug!(
                    "Unexpected message type from {} during handshake",
                    self.peer_addr
                );
                Ok(None)
            }
        }
    }

    /// Handle control message (flow_id = 0)
    #[allow(clippy::too_many_arguments)]
    async fn handle_control(
        data: &[u8],
        flows: &FlowMap,
        tx: &tokio::sync::mpsc::Sender<MuxMessage>,
        peer_addr: SocketAddr,
        dns_cache: &DnsCache,
        tun_config: &TunNetworkConfig,
        // Buffer for data frames that arrived before their CreateFlow was processed.
        // Keyed by flow_id, value is a list of (data, frame_number, elapsed) tuples.
        pending_flows: &PendingFlows,
        tcp_pool: &TcpPool,
    ) -> Result<()> {
        let message: ControlMessage = bincode::deserialize(data)
            .map_err(|e| anyhow::anyhow!("Failed to parse control message: {}", e))?;

        // Log what type of control message was received
        let msg_type = match &message {
            ControlMessage::CreateFlow { flow_id, .. } => {
                format!("CreateFlow(flow_id={})", flow_id)
            }
            ControlMessage::CloseFlow { flow_id } => format!("CloseFlow(flow_id={})", flow_id),
            ControlMessage::FlowCreated { flow_id, .. } => {
                format!("FlowCreated(flow_id={})", flow_id)
            }
            ControlMessage::FlowFailed { flow_id, .. } => {
                format!("FlowFailed(flow_id={})", flow_id)
            }
            ControlMessage::Ping { timestamp } => format!("Ping(ts={})", timestamp),
            ControlMessage::Pong { timestamp } => format!("Pong(ts={})", timestamp),
            ControlMessage::WindowUpdate { flow_id, .. } => {
                format!("WindowUpdate(flow_id={})", flow_id)
            }
        };

        tracing::debug!("CONTROL: Received {} from {}", msg_type, peer_addr);

        match message {
            ControlMessage::CreateFlow {
                flow_id,
                target,
                port,
            } => {
                // Enforce per-connection flow limit to prevent resource exhaustion
                const MAX_FLOWS_PER_SESSION: usize = 2000;
                let flow_count = {
                    let guard = flows.lock().await;
                    guard.len()
                };
                if flow_count >= MAX_FLOWS_PER_SESSION {
                    warn!(
                        "CONTROL: [CreateFlow] Rejecting flow_id={} from {} — too many flows ({} active, limit {})",
                        flow_id, peer_addr, flow_count, MAX_FLOWS_PER_SESSION
                    );
                    // Send FlowFailed back to client
                    let _ = tx.send(MuxMessage::Control(ControlMessage::FlowFailed {
                        flow_id,
                        error: format!("Too many flows: {} (limit {})", flow_count, MAX_FLOWS_PER_SESSION),
                    })).await;
                    return Ok(());
                }

                info!(
                    "CONTROL: [CreateFlow] Received flow_id={} -> {}:{} from {}",
                    flow_id, target, port, peer_addr
                );

                // Use DNS cache to resolve and connect
                let connect_target = format!("{}:{}", target, port);

                // Check connection pool first — avoids DNS + TCP connect overhead
                // for repeated connections to the same CDN host (e.g. Instagram, YouTube)
                let stream = {
                    let mut pool = tcp_pool.lock().await;
                    if let Some(queue) = pool.get_mut(&connect_target) {
                        queue.pop_front()
                    } else {
                        None
                    }
                };

                let stream = match stream {
                    Some(s) => {
                        info!(
                            "CONTROL: [CreateFlow] TCP pool hit for {} (flow_id={})",
                            connect_target, flow_id
                        );
                        s
                    }
                    None => {
                        info!(
                            "CONTROL: [CreateFlow] Starting DNS resolution and TCP connection for {}",
                            connect_target
                        );
                        Self::connect_with_dns_cache(&connect_target, dns_cache, tun_config).await?
                    }
                };

                // Pre-connect: start creating one more connection to the same target
                // in the background, so the next CreateFlow can use it immediately.
                {
                    let pool_clone = tcp_pool.clone();
                    let target_clone = connect_target.clone();
                    let dns_clone = dns_cache.clone();
                    let tun_clone = tun_config.clone();
                    tokio::spawn(async move {
                        // Cap pool size to prevent resource exhaustion
                        const MAX_POOL_PER_TARGET: usize = 5;
                        let pool_size = {
                            let pool = pool_clone.lock().await;
                            pool.get(&target_clone).map_or(0, |q| q.len())
                        };
                        if pool_size < MAX_POOL_PER_TARGET {
                            match Self::connect_with_dns_cache(&target_clone, &dns_clone, &tun_clone).await {
                                Ok(s) => {
                                    let mut pool = pool_clone.lock().await;
                                    pool.entry(target_clone).or_default().push_back(s);
                                }
                                Err(e) => {
                                    debug!("Pre-connect failed for {}: {}", target_clone, e);
                                }
                            }
                        }
                    });
                }

                match Ok::<_, anyhow::Error>(stream) {
                    Ok(stream) => {
                        info!(
                            "CONTROL: [CreateFlow] TCP connection established for flow_id={}",
                            flow_id
                        );
                        let (read_half, write_half) = stream.into_split();

                        // Store the flow
                        let mut flows_guard = flows.lock().await;
                        flows_guard.insert(flow_id, Arc::new(Mutex::new(write_half)));
                        let flow_count = flows_guard.len();
                        drop(flows_guard);

                        info!(
                            "CONTROL: [CreateFlow] Flow {} stored in map (total flows: {})",
                            flow_id, flow_count
                        );

                        // Send FlowCreated ACK
                        let ack = MuxMessage::Control(ControlMessage::FlowCreated {
                            flow_id,
                            local_port: None,
                        });

                        if let Err(e) = tx.send(ack).await {
                            error!(
                                "CONTROL: [CreateFlow] Failed to send FlowCreated for flow_id={}: {}",
                                flow_id, e
                            );
                        }

                        // Spawn task to relay data from target back to client
                        info!(
                            "CONTROL: [CreateFlow] Spawning relay task for flow_id={}",
                            flow_id
                        );
                        Self::spawn_flow_relay(
                            flow_id,
                            read_half,
                            flows.clone(),
                            tx.clone(),
                            peer_addr,
                        );
                        info!(
                            "CONTROL: [CreateFlow] Flow {} created successfully for {}",
                            flow_id, peer_addr
                        );

                        // Flush any pending data that arrived before CreateFlow.
                        // Only flush the first few frames to avoid blocking the receiver.
                        // Remaining buffered frames will be dropped — TCP will retransmit if needed.
                        const MAX_FLUSH_FRAMES: usize = 5;
                        let pending_data = {
                            let mut pending = pending_flows.lock().await;
                            pending.remove(&flow_id)
                        };
                        if let Some(pending) = pending_data {
                            let flushed = pending.len().min(MAX_FLUSH_FRAMES);
                            if pending.len() > MAX_FLUSH_FRAMES {
                                debug!(
                                    "CONTROL: [CreateFlow] Dropping {} excess buffered frames for flow {}",
                                    pending.len() - MAX_FLUSH_FRAMES, flow_id
                                );
                            }
                            for (data, _frame_num, _elapsed) in pending.into_iter().take(MAX_FLUSH_FRAMES) {
                                if let Err(e) = Self::handle_flow_data(flow_id, &data, flows).await {
                                    debug!("Failed to flush pending data for flow {}: {}", flow_id, e);
                                }
                            }
                            if flushed > 0 {
                                info!(
                                    "CONTROL: [CreateFlow] Flushed {} pending data frames for flow {}",
                                    flushed, flow_id
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!(
                            "CONTROL: [CreateFlow] Connection failed for flow_id={} to {}:{}: {}",
                            flow_id, target, port, e
                        );
                        let err = MuxMessage::Control(ControlMessage::FlowFailed {
                            flow_id,
                            error: e.to_string(),
                        });
                        let _ = tx.send(err).await;
                        error!(
                            "CONTROL: [CreateFlow] FlowFailed sent for flow_id={}",
                            flow_id
                        );
                    }
                }
            }
            ControlMessage::CloseFlow { flow_id } => {
                info!("Closing flow {} for {}", flow_id, peer_addr);
                let mut flows_guard = flows.lock().await;
                if flows_guard.remove(&flow_id).is_some() {
                    info!("Flow {} closed for {}", flow_id, peer_addr);
                }
            }
            ControlMessage::FlowCreated { flow_id, .. } => {
                // Client should not send this, but handle gracefully
                warn!(
                    "Received unexpected FlowCreated for flow {} from {}",
                    flow_id, peer_addr
                );
            }
            ControlMessage::FlowFailed { flow_id, error } => {
                warn!(
                    "Received unexpected FlowFailed for flow {} from {}: {}",
                    flow_id, peer_addr, error
                );
            }
            ControlMessage::Ping { timestamp } => {
                trace!("Received ping from {}: {}, sending pong", peer_addr, timestamp);
                let _ = tx.send(MuxMessage::Control(ControlMessage::Pong { timestamp })).await;
            }
            ControlMessage::Pong { timestamp } => {
                trace!("Received pong from {}: {}", peer_addr, timestamp);
            }
            ControlMessage::WindowUpdate {
                flow_id,
                window_size,
            } => {
                trace!(
                    "Received window update for flow {} from {}: {}",
                    flow_id,
                    peer_addr,
                    window_size
                );
            }
        }

        Ok(())
    }

    /// Handle data for an existing flow
    async fn handle_flow_data(flow_id: u32, data: &[u8], flows: &FlowMap) -> Result<()> {
        let write_half = {
            let flows_guard = flows.lock().await;
            flows_guard.get(&flow_id).cloned()
        };

        if let Some(write_half) = write_half {
            trace!("DATA: Writing {} bytes to flow {}", data.len(), flow_id);
            let mut writer_guard = write_half.lock().await;
            writer_guard
                .write_all(data)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to write to flow {}: {}", flow_id, e))?;
            trace!(
                "DATA: Successfully wrote {} bytes to flow {}",
                data.len(),
                flow_id
            );
            Ok(())
        } else {
            // This should be handled in process_incoming_frame with detailed logging
            // But we keep this as a fallback
            error!("DATA: Received data for unknown flow {} (this shouldn't happen with proper ordering checks)", flow_id);
            Err(anyhow::anyhow!("Unknown flow ID: {}", flow_id))
        }
    }

    /// Decrypt and parse an incoming WebSocket message.
    ///
    /// The decrypted plaintext may contain multiple concatenated
    /// [`MultiplexedFrame`]s (client-side batching). Returns a vector of
    /// `(flow_id, payload, aad_type)` for each parsed frame.
    /// Called from ws_receiver with the ratchet lock held.
    fn decrypt_and_parse_frame(
        data: &[u8],
        ratchet: &mut DoubleRatchet,
        frame_number: u64,
        peer_addr: SocketAddr,
        _elapsed: Duration,
    ) -> Result<Vec<(u32, Vec<u8>, u8)>> {
        let message = RatchetMessage::from_bytes(data)
            .map_err(|e| anyhow::anyhow!("Failed to deserialize RatchetMessage: {}", e))?;

        let aad_byte = message.header.payload_type;
        let aad: &[u8] = match aad_byte {
            0x00 => &[0x00],
            0x01 => &[0x01],
            0x02 => &[0x02],
            0x03 => &[0x03],
            0x04 => &[0x04],
            0x05 => &[0x05],
            0x06 => &[0x06],
            0x07 => &[0x07],
            0x08 => &[0x08],
            0x09 => &[0x09],
            0x0A => &[0x0A],
            0x0B => &[0x0B],
            0x0C => &[0x0C],
            _ => return Err(anyhow::anyhow!("Unknown payload type: {}", aad_byte)),
        };

        let decrypted = ratchet
            .decrypt(&message, aad)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        let plaintext = rvpn_core::protocol::padding::unpad_packet(&decrypted)
            .map_err(|e| anyhow::anyhow!("Unpad failed: {}", e))?;

        if plaintext.is_empty() {
            return Err(anyhow::anyhow!("Decrypted plaintext is empty"));
        }

        let (frames, consumed) = rvpn_core::protocol::multiplex::parse_frames(&plaintext);
        if frames.is_empty() {
            return Err(anyhow::anyhow!("No valid frames in decrypted plaintext"));
        }
        if consumed != plaintext.len() {
            tracing::warn!(
                "FRAME: [#{:05}] Parsed {} bytes out of {} ({} frames); trailing data ignored",
                frame_number, consumed, plaintext.len(), frames.len()
            );
        }

        let parsed: Vec<(u32, Vec<u8>, u8)> = frames
            .into_iter()
            .map(|f| (f.flow_id, f.payload.to_vec(), aad_byte))
            .collect();

        tracing::trace!(
            "FRAME: [#{:05}] Decrypted {} frame(s) from {} ({} bytes)",
            frame_number, parsed.len(), peer_addr, consumed
        );

        Ok(parsed)
    }

    /// Dispatch a decrypted frame to the appropriate handler.
    /// May block on TCP write for data frames, but the ratchet lock is NOT held.
    #[allow(clippy::too_many_arguments)]
    async fn dispatch_decrypted_frame(
        flow_id: u32,
        payload: &[u8],
        _aad_type: u8,
        flows: &FlowMap,
        tx: &tokio::sync::mpsc::Sender<MuxMessage>,
        _tun_tx: &tokio::sync::mpsc::Sender<Vec<u8>>,
        peer_addr: SocketAddr,
        dns_cache: &DnsCache,
        _tun_server: Option<&Arc<dyn TunWriter>>,
        tun_config: &TunNetworkConfig,
        pending_flows: &PendingFlows,
        tcp_pool: &TcpPool,
        frame_number: u64,
        elapsed: Duration,
    ) -> Result<()> {
        if flow_id == 0 {
            // Control message
            info!(
                "FRAME: [#{:05}] RECEIVED CONTROL frame from {} after {:.3}s",
                frame_number, peer_addr, elapsed.as_secs_f64()
            );
            Self::handle_control(payload, flows, tx, peer_addr, dns_cache, tun_config, pending_flows, tcp_pool).await
        } else {
            // Data for existing flow
            info!(
                "FRAME: [#{:05}] RECEIVED DATA frame for flow_id {} from {} after {:.3}s ({} bytes)",
                frame_number, flow_id, peer_addr, elapsed.as_secs_f64(), payload.len()
            );

            let flow_write = {
                let guard = flows.lock().await;
                guard.get(&flow_id).cloned()
            };

            if let Some(write_half) = flow_write {
                let mut writer = write_half.lock().await;
                writer.write_all(payload).await
                    .map_err(|e| anyhow::anyhow!("Write to target failed for flow {}: {}", flow_id, e))?;
            } else if tun_config.enabled {
                // TUN mode: write packet directly to TUN interface
                info!(
                    "FRAME: [#{:05}] TUN mode: attempting to route {} bytes (tun_server is {})",
                    frame_number,
                    payload.len(),
                    if _tun_server.is_some() { "Some" } else { "None" }
                );

                let ts = match _tun_server {
                    Some(ts) => ts,
                    None => {
                        warn!(
                            "FRAME: [#{:05}] TUN mode: tun_server is None - cannot route packet",
                            frame_number
                        );
                        return Err(anyhow::anyhow!("TUN mode: tun_server not available"));
                    }
                };

                let client_ip_str = match Self::extract_source_ip(payload) {
                    Some(ip) => ip,
                    None => {
                        let preview: String = payload.iter().take(20)
                            .map(|b| format!("{:02x}", b))
                            .collect::<Vec<_>>()
                            .join(" ");
                        warn!(
                            "FRAME: [#{:05}] TUN mode: failed to extract source IP from packet (first 20 bytes: {})",
                            frame_number, preview
                        );
                        return Err(anyhow::anyhow!("TUN mode: cannot extract source IP from packet"));
                    }
                };

                info!(
                    "FRAME: [#{:05}] TUN mode: writing {} bytes to TUN (client IP: {})",
                    frame_number, payload.len(), client_ip_str
                );

                if let Err(e) = ts.write_to_tun(payload).await {
                    error!(
                        "FRAME: [#{:05}] Failed to write to TUN: {}",
                        frame_number, e
                    );
                    return Err(e);
                }
                info!(
                    "FRAME: [#{:05}] Successfully wrote packet to TUN",
                    frame_number
                );
            } else {
                // Unknown flow — may be data that arrived before CreateFlow was processed
                // (0-RTT optimization). Buffer it for later.
                debug!(
                    "FRAME: [#{:05}] DATA frame for unknown flow {} — buffering",
                    frame_number, flow_id
                );
                let mut pending = pending_flows.lock().await;
                pending.entry(flow_id).or_default().push((
                    payload.to_vec(),
                    frame_number,
                    elapsed,
                ));
            }
            Ok(())
        }
    }

    /// Spawn a task to relay data from target back to client.
    /// Returns a JoinHandle so the caller can abort it on session end.
    fn spawn_flow_relay(
        flow_id: u32,
        mut read_half: OwnedReadHalf,
        flows: FlowMap,
        tx: tokio::sync::mpsc::Sender<MuxMessage>,
        peer_addr: SocketAddr,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            // 8190, not 8192 — pad_packet reserves 2 bytes for padding-length field
            let mut buf = [0u8; 8190];

            loop {
                let read_result = match read_half.read(&mut buf).await {
                    Ok(0) => {
                        let mut flows_guard = flows.lock().await;
                        flows_guard.remove(&flow_id);
                        info!("Flow {} closed by remote for {}", flow_id, peer_addr);
                        None
                    }
                    Ok(n) => Some(n),
                    Err(e) => {
                        error!("Read error on flow {} for {}: {}", flow_id, peer_addr, e);
                        let mut flows_guard = flows.lock().await;
                        flows_guard.remove(&flow_id);
                        None
                    }
                };

                let bytes_read = if let Some(n) = read_result {
                    n
                } else {
                    let _ = tx
                        .send(MuxMessage::Control(ControlMessage::CloseFlow { flow_id }))
                        .await;
                    break;
                };

                // Send data back to client via channel
                let data = buf[..bytes_read].to_vec();
                if tx.send(MuxMessage::Data { flow_id, data }).await.is_err() {
                    error!(
                        "Failed to send data to WebSocket channel for flow {}",
                        flow_id
                    );
                    break;
                }
            }
        })
    }
}

// ============================================================================
// DNS Handler - Handles DNS-over-WebSocket connections on /connect/dns
// ============================================================================

use rvpn_core::protocol::message::{DnsQuery as ProtoDnsQuery, DnsResponse as ProtoDnsResponse};

/// Handler for DNS-over-WebSocket connections
pub struct DnsHandler {
    x3dh_responder: Option<X3DHResponder>,
    rate_limiter: RwLock<RateLimiter>,
}

impl DnsHandler {
    pub fn new(config: ServerConfig) -> Result<Self> {
        // Reuse the same X3DH loading logic as VpnHandler
        let x3dh_responder = if config.identity_key_file.exists() {
            match IdentityKey::load(&config.identity_key_file) {
                Ok(identity) => {
                    let signed_prekey =
                        config.prekey_bundle_file.as_ref().and_then(|bundle_path| {
                            let private_key_path = bundle_path.with_extension("private.json");
                            if private_key_path.exists() {
                                match VpnHandler::load_signed_prekey_private(&private_key_path) {
                                    Ok(key) => Some(key),
                                    Err(e) => {
                                        warn!("DnsHandler: failed to load prekey private: {}", e);
                                        None
                                    }
                                }
                            } else {
                                None
                            }
                        });
                    match signed_prekey {
                        Some(prekey) => {
                            Some(X3DHResponder::from_identity_with_bundle(identity, prekey))
                        }
                        None => Some(X3DHResponder::from_identity(identity)),
                    }
                }
                Err(e) => {
                    warn!("DnsHandler: failed to load identity key: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(Self {
            x3dh_responder,
            rate_limiter: RwLock::new(RateLimiter::new(
                config.rate_limit.max_connections_per_ip,
                config.rate_limit.max_handshakes_per_minute,
            )),
        })
    }

    pub async fn handle_connection<S>(
        &self,
        ws_stream: tokio_tungstenite::WebSocketStream<S>,
        peer_addr: SocketAddr,
    ) -> Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        info!("DNS WebSocket connection from {}", peer_addr);

        // Rate limit check
        {
            let limiter = self.rate_limiter.read().await;
            if !limiter.check(&peer_addr.ip()) {
                debug!("DNS handler: rate limited {}", peer_addr);
                return Ok(());
            }
        }

        let (mut ws_write, mut ws_read) = ws_stream.split();

        // Perform X3DH handshake (same as VpnHandler)
        let mut ratchet = match self
            .perform_handshake(&mut ws_write, &mut ws_read, peer_addr)
            .await?
        {
            Some(r) => r,
            None => return Ok(()),
        };

        info!("DNS handler: handshake complete for {}", peer_addr);

        // DNS query/response loop
        while let Some(msg) = ws_read.next().await {
            match msg {
                Ok(Message::Binary(data)) => {
                    // Decrypt the DNS query
                    let ratchet_msg =
                        match rvpn_core::crypto::ratchet::RatchetMessage::from_bytes(&data) {
                            Ok(m) => m,
                            Err(e) => {
                                warn!("DNS handler: failed to parse ratchet message: {}", e);
                                continue;
                            }
                        };

                    let plaintext = match ratchet.decrypt(&ratchet_msg, &[0x08]) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("DNS handler: decryption failed: {}", e);
                            continue;
                        }
                    };

                    let query: ProtoDnsQuery = match serde_json::from_slice(&plaintext) {
                        Ok(q) => q,
                        Err(e) => {
                            warn!("DNS handler: failed to parse DnsQuery: {}", e);
                            continue;
                        }
                    };

                    debug!(
                        "DNS query from {}: {} (type={})",
                        peer_addr, query.domain, query.query_type
                    );

                    // Resolve the domain
                    let response = Self::resolve_domain(&query).await;

                    // Encrypt and send response
                    let response_bytes = match serde_json::to_vec(&response) {
                        Ok(b) => b,
                        Err(e) => {
                            error!("DNS handler: failed to serialize response: {}", e);
                            continue;
                        }
                    };

                    let encrypted = match ratchet.encrypt(&response_bytes, &[0x09]) {
                        Ok(m) => m,
                        Err(e) => {
                            error!("DNS handler: encryption failed: {}", e);
                            continue;
                        }
                    };

                    let serialized = match encrypted.to_bytes() {
                        Ok(b) => b,
                        Err(e) => {
                            error!("DNS handler: failed to serialize encrypted response: {}", e);
                            continue;
                        }
                    };

                    if let Err(e) = ws_write.send(Message::Binary(serialized)).await {
                        debug!("DNS handler: send error for {}: {}", peer_addr, e);
                        break;
                    }
                }
                Ok(Message::Ping(_)) => {}
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }

        info!("DNS handler: connection closed for {}", peer_addr);
        Ok(())
    }

    async fn resolve_domain(query: &ProtoDnsQuery) -> ProtoDnsResponse {
        let target = format!("{}:0", query.domain);
        let result = lookup_host(target.as_str()).await;
        match result {
            Ok(addrs) => {
                let mut ipv4_addrs = Vec::new();
                let mut ipv6_addrs = Vec::new();

                for addr in addrs {
                    match addr.ip() {
                        std::net::IpAddr::V4(v4) => ipv4_addrs.push(v4),
                        std::net::IpAddr::V6(v6) => ipv6_addrs.push(v6),
                    }
                }

                // Filter based on query type: 1=A (IPv4), 28=AAAA (IPv6)
                if query.query_type == 28 {
                    ipv4_addrs.clear();
                } else if query.query_type == 1 {
                    ipv6_addrs.clear();
                }

                info!(
                    "DNS resolved {} (type={}): ipv4={}, ipv6={}",
                    query.domain, query.query_type, ipv4_addrs.len(), ipv6_addrs.len()
                );

                ProtoDnsResponse {
                    query_id: query.query_id,
                    success: true,
                    ipv4_addrs,
                    ipv6_addrs,
                    ttl: 300,
                    error: None,
                }
            }
            Err(e) => {
                info!("DNS resolution failed for {}: {}", query.domain, e);
                ProtoDnsResponse {
                    query_id: query.query_id,
                    success: false,
                    ipv4_addrs: vec![],
                    ipv6_addrs: vec![],
                    ttl: 0,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    /// Perform X3DH handshake (matches VpnHandler's implementation)
    async fn perform_handshake<W, R, E>(
        &self,
        ws_write: &mut W,
        ws_read: &mut R,
        peer_addr: SocketAddr,
    ) -> Result<Option<DoubleRatchet>>
    where
        W: SinkExt<Message, Error = E> + Unpin,
        R: StreamExt<Item = std::result::Result<Message, tokio_tungstenite::tungstenite::Error>>
            + Unpin,
        E: std::fmt::Debug,
    {
        let msg = timeout(Duration::from_secs(10), ws_read.next()).await;
        let msg = match msg {
            Ok(Some(Ok(m))) => m,
            Ok(Some(Err(e))) => {
                debug!("DNS handler: WebSocket error from {}: {}", peer_addr, e);
                return Ok(None);
            }
            Ok(None) => {
                debug!(
                    "DNS handler: connection closed by {} before handshake",
                    peer_addr
                );
                return Ok(None);
            }
            Err(_) => {
                debug!("DNS handler: handshake timeout from {}", peer_addr);
                return Ok(None);
            }
        };

        let hello: HandshakeMessage = match serde_json::from_slice(&msg.into_data()) {
            Ok(h) => h,
            Err(e) => {
                debug!(
                    "DNS handler: failed to parse Hello from {}: {}",
                    peer_addr, e
                );
                return Ok(None);
            }
        };

        match hello {
            HandshakeMessage::Hello {
                version,
                auth_method,
                ephemeral_key,
                identity_key,
                ..
            } => {
                if !version.is_compatible_with(&ProtocolVersion::CURRENT) {
                    warn!("DNS handler: protocol version mismatch from {}", peer_addr);
                    return Ok(None);
                }

                if auth_method != AuthMethod::X3DH {
                    warn!("DNS handler: unsupported auth method from {}", peer_addr);
                    return Ok(None);
                }

                let responder = match self.x3dh_responder.as_ref() {
                    Some(r) => r,
                    None => {
                        error!("DNS handler: X3DH not configured");
                        return Ok(None);
                    }
                };

                let client_ephemeral: [u8; 32] = match ephemeral_key {
                    Some(key) if key.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&key);
                        arr
                    }
                    _ => {
                        warn!("DNS handler: invalid ephemeral key from {}", peer_addr);
                        return Ok(None);
                    }
                };

                let client_identity: [u8; 32] = match identity_key {
                    Some(key) if key.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&key);
                        arr
                    }
                    _ => {
                        warn!("DNS handler: invalid identity key from {}", peer_addr);
                        return Ok(None);
                    }
                };

                let shared_secret =
                    match responder.agree(&client_identity, &client_ephemeral, false) {
                        Ok(s) => s,
                        Err(e) => {
                            warn!(
                                "DNS handler: X3DH agreement failed for {}: {}",
                                peer_addr, e
                            );
                            return Ok(None);
                        }
                    };

                let ratchet = DoubleRatchet::init_bob(shared_secret);

                let public_bundle = responder.get_public_bundle();
                let server_hello = HandshakeMessage::ServerHello {
                    ephemeral_key: Vec::new(),
                    signed_prekey: public_bundle.signed_prekey.to_vec(),
                    prekey_signature: public_bundle.prekey_signature.to_vec(),
                    identity_key: public_bundle.identity_key.to_vec(),
                };

                let hello_bytes = serde_json::to_vec(&server_hello)
                    .context("DNS handler: failed to serialize ServerHello")?;

                ws_write
                    .send(Message::Binary(hello_bytes))
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("DNS handler: failed to send ServerHello: {:?}", e)
                    })?;

                info!("DNS handler: X3DH handshake complete for {}", peer_addr);
                Ok(Some(ratchet))
            }
            _ => {
                warn!("DNS handler: unexpected message type from {}", peer_addr);
                Ok(None)
            }
        }
    }
}
