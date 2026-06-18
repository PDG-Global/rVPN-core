// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! iOS Direct TUN Client - True TUN-to-TUN tunneling via WebSocket
//!
//! This module provides a client for iOS Direct TUN mode where:
//! - iOS connects to `/api/v1/ws/tun` endpoint
//! - Server assigns a tunnel IP via `VirtualIp` message after X3DH
//! - Raw IP packets flow bidirectionally through the WebSocket
//!
//! Architecture:
//! - Swift TUN interface captures raw IP packets
//! - This client exchanges packets with Swift via channels
//! - X3DH handshake establishes Double Ratchet
//! - Server sends VirtualIp with assigned IP
//! - Raw IP packets are encrypted and relayed

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use futures::SinkExt;
use futures::StreamExt;
use futures_util::stream::SplitSink;
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::time::timeout;
use bytes::BytesMut;
use tokio_tungstenite::{client_async, tungstenite::Message, WebSocketStream};
use tracing::{debug, error, info, trace, warn};
use tungstenite::handshake::client::generate_key;
use rvpn_client::tls_boring::{connect_chrome_like, ChromeTlsStream, TlsFingerprint};

use ed25519_dalek::Verifier;
use rvpn_core::crypto::ratchet::RatchetMessage;
use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::crypto::{DoubleRatchet, EphemeralKey, IdentityKey, X3DHPublicBundle};
use rvpn_core::protocol::{ControlMessage, HandshakeMessage, MultiplexedFrame, PayloadType, VirtualIp};
use rvpn_core::protocol::padding::{pad_packet, unpad_packet};

use crate::ffi::TunConfig;

/// WebSocket writer type
type WsSink = SplitSink<WebSocketStream<ChromeTlsStream>, Message>;
type WsStream = futures_util::stream::SplitStream<WebSocketStream<ChromeTlsStream>>;

/// Outgoing packet batching limits.
///
/// Multiple TUN packets are coalesced into a single WebSocket/Ratchet message
/// to reduce per-packet overhead. The batch is capped well below the 16 KB
/// maximum padded size to leave room for frame headers and padding length.
const OUTGOING_BATCH_MAX_FRAMES: usize = 16;
const OUTGOING_BATCH_MAX_BYTES: usize = 14 * 1024;
const OUTGOING_BATCH_TIMEOUT_MS: u64 = 5;

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TunClientState {
    Init = 0,
    Connecting = 1,
    IpAssigned = 2,
    Connected = 3,
    Error = 4,
}

impl From<i32> for TunClientState {
    fn from(v: i32) -> Self {
        match v {
            0 => TunClientState::Init,
            1 => TunClientState::Connecting,
            2 => TunClientState::IpAssigned,
            3 => TunClientState::Connected,
            _ => TunClientState::Error,
        }
    }
}

/// State callback type for Swift notifications
/// Called when state changes: (state: i32, ip: *const c_char, message: *const c_char)
pub type StateCallback =
    Option<unsafe extern "C" fn(state: i32, ip: *const std::os::raw::c_char, msg: *const std::os::raw::c_char)>;

/// IosTunClient - Direct TUN mode client for iOS
///
/// Connects to the VPN server's `/tun` endpoint, performs X3DH handshake,
/// receives a VirtualIp assignment, and relays raw IP packets bidirectionally.
///
/// # Channel Design
/// - Swift sends packets to server via `from_swift_sender` (mpsc::Sender)
/// - Swift receives packets from server via `to_swift_receiver` (mpsc::Receiver)
/// Both are exposed via getters for Swift to use.
pub struct IosTunClient {
    /// Tokio runtime handle
    runtime: Arc<tokio::runtime::Runtime>,
    /// Configuration (kept for debugging and future reconnection support)
    /// Note: fields are extracted on construction to avoid per-packet locking
    #[allow(dead_code)]
    config: TunConfig,
    /// Server host (original hostname for TLS SNI)
    server_host: String,
    /// Server IP (pre-resolved to avoid DNS circular dependency during reconnect)
    server_ip: std::net::IpAddr,
    /// Server port
    server_port: u16,
    /// WebSocket path (base path, will append /tun)
    server_path: String,
    /// Connection state
    state: Arc<AtomicI32>,
    /// Assigned tunnel IP (set after VirtualIp received)
    tunnel_ip: Arc<Mutex<Option<String>>>,
    /// Assigned gateway IP (set after VirtualIp received)
    gateway_ip: Arc<Mutex<Option<String>>>,
    /// Sender for packets to Swift (Swift receives via recv_packet_from_server)
    to_swift_sender: mpsc::Sender<Vec<u8>>,
    /// Signalled whenever a packet is pushed to to_swift_sender, so the Swift
    /// write loop can wait event-driven instead of polling.
    /// Uses a std channel so the FFI wait function can block without entering
    /// the Tokio runtime.
    packet_notify_tx: std::sync::mpsc::SyncSender<()>,
    packet_notify_rx: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    /// Receiver for packets from Swift (Swift sends via send_packet_to_server)
    from_swift_receiver: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    /// Sender for Swift to use (Swift calls send_packet_to_server with this)
    pub from_swift_sender: mpsc::Sender<Vec<u8>>,
    /// Receiver for packets to Swift
    pub to_swift_receiver: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    /// Shutdown signal
    shutdown_tx: broadcast::Sender<()>,
    /// Identity key for X3DH
    identity_key: IdentityKey,
    /// Server prekey bundle for X3DH
    server_bundle: X3DHPublicBundle,
    /// DNS servers from VirtualIp
    dns_servers: Arc<Mutex<Vec<std::net::IpAddr>>>,
    /// MTU from VirtualIp
    mtu: Arc<Mutex<u16>>,
    /// State callback for Swift notifications
    state_callback: Arc<RwLock<StateCallback>>,
    /// Start/reconnect loop running flag (prevents duplicate loops)
    is_started: AtomicBool,
    /// Reconnection enabled flag
    reconnect_enabled: AtomicBool,
    /// Maximum reconnection attempts (0 = unlimited)
    reconnect_max_attempts: AtomicU32,
    /// Initial delay between reconnection attempts (ms)
    reconnect_initial_delay_ms: AtomicU64,
    /// Maximum delay between reconnection attempts (ms)
    reconnect_max_delay_ms: AtomicU64,
    /// Last time a reconnect was requested via network change (debounces rapid calls)
    last_reconnect_request: std::sync::Mutex<std::time::Instant>,
    /// TLS fingerprint to use for stealth connections
    tls_fingerprint: TlsFingerprint,
}

impl IosTunClient {
    /// Create a new IosTunClient from configuration
    pub fn new(config: &TunConfig) -> Result<Self> {
        // Parse server URL
        let (host, port, path) = Self::parse_server_url(&config.server_address)?;

        // Pre-resolve server hostname to IP to avoid DNS circular dependency during reconnect.
        // When the VPN is active, system DNS is redirected to our DNS proxy (127.0.0.1:53).
        // If the TUN tunnel dies and tries to reconnect, resolving the server hostname would
        // go through our proxy → DoH client → dead connection → resolution fails forever.
        // By resolving here (before DNS is hijacked), we use the IP directly for all reconnects.
        let server_ip = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            ip
        } else {
            let mut addrs = std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", host, port))
                .with_context(|| format!("Failed to resolve server hostname: {}", host))?;
            addrs.next()
                .map(|a| a.ip())
                .context("DNS resolution returned no addresses for server")?
        };
        info!("[IosTun] Server {} resolved to {}", host, server_ip);

        // Load identity key (blocking I/O)
        let identity_key_path = std::path::PathBuf::from(&config.identity_key_path);
        let identity_key = IdentityKey::load(&identity_key_path)
            .context("Failed to load identity key")?;

        // Load prekey bundle
        let bundle_json = std::fs::read_to_string(&config.prekey_bundle_path)
            .context("Failed to read prekey bundle")?;
        let server_bundle: X3DHPublicBundle =
            serde_json::from_str(&bundle_json).context("Failed to parse prekey bundle JSON")?;

        // Parse TLS fingerprint (default to Chrome for stealth)
        let tls_fingerprint = config.tls_fingerprint.as_deref()
            .and_then(rvpn_client::tls_boring::fingerprint_from_str)
            .unwrap_or(TlsFingerprint::Chrome);

        // Create channels for Swift TUN communication
        // 1000 packets * ~1500 bytes avg = ~1.5MB buffer, well within iOS Network
        // Extension memory limits and reduces packet drops under load.
        // to_swift_receiver is used by Swift to receive packets from server (via recv_packet_from_server)
        let (to_swift_sender, to_swift_receiver) = mpsc::channel::<Vec<u8>>(1000);
        // from_swift_receiver is used by Swift to send packets to server (via send_packet_to_server)
        let (from_swift_sender, from_swift_receiver) = mpsc::channel::<Vec<u8>>(1000);

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel::<()>(1);

        // Notification channel used to wake the Swift write loop when packets arrive.
        // std channel allows the FFI wait function to block without entering Tokio.
        let (packet_notify_tx, packet_notify_rx) = std::sync::mpsc::sync_channel(1);

        // Set initial state
        let state = Arc::new(AtomicI32::new(TunClientState::Init as i32));

        // Create runtime
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("rvpn-ios-tun")
            .build()
            .context("Failed to create Tokio runtime")?;

        Ok(Self {
            runtime: Arc::new(runtime),
            config: config.clone(),
            server_host: host,
            server_ip,
            server_port: port,
            server_path: path,
            state,
            tunnel_ip: Arc::new(Mutex::new(None)),
            gateway_ip: Arc::new(Mutex::new(None)),
            to_swift_sender,
            packet_notify_tx,
            packet_notify_rx: std::sync::Mutex::new(packet_notify_rx),
            from_swift_receiver: Arc::new(Mutex::new(from_swift_receiver)),
            from_swift_sender,
            to_swift_receiver: Arc::new(Mutex::new(to_swift_receiver)),
            shutdown_tx,
            identity_key,
            server_bundle,
            dns_servers: Arc::new(Mutex::new(Vec::new())),
            mtu: Arc::new(Mutex::new(1420)),
            state_callback: Arc::new(RwLock::new(None)),
            is_started: AtomicBool::new(false),
            reconnect_enabled: AtomicBool::new(false), // Disabled by default, enable via setter
            reconnect_max_attempts: AtomicU32::new(0),
            last_reconnect_request: std::sync::Mutex::new(std::time::Instant::now() - std::time::Duration::from_secs(60)),
            reconnect_initial_delay_ms: AtomicU64::new(1000),
            reconnect_max_delay_ms: AtomicU64::new(5000),
            tls_fingerprint,
        })
    }

    /// Parse server URL into (host, port, path)
    fn parse_server_url(server_address: &str) -> Result<(String, u16, String)> {
        let parsed =
            url::Url::parse(server_address).context("Invalid server_address URL")?;
        let host = parsed
            .host_str()
            .context("Missing host in server_address")?
            .to_string();
        let port = parsed
            .port_or_known_default()
            .context("Missing port in server_address")?;
        let mut path = parsed.path().to_string();
        if path.is_empty() {
            path = "/".to_string();
        }
        Ok((host, port, path))
    }

    /// Set the state callback for Swift notifications
    pub fn set_state_callback(&self, callback: StateCallback) {
        let state_callback = Arc::clone(&self.state_callback);
        self.runtime.spawn(async move {
            let mut guard = state_callback.write().await;
            *guard = callback;
        });
    }

    /// Call the state callback if set
    async fn notify_state(&self, new_state: TunClientState, ip: Option<&str>, message: &str) {
        let callback = { self.state_callback.read().await.clone() };
        if let Some(cb) = callback {
            let ip_cstring = ip.map(|s| std::ffi::CString::new(s).unwrap());
            let msg_cstring = std::ffi::CString::new(message).unwrap();
            let ip_ptr = ip_cstring.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null());
            let msg_ptr = msg_cstring.as_ptr();
            unsafe {
                cb(new_state as i32, ip_ptr, msg_ptr);
            }
            // Leaking the CStrings here is safe because:
            // 1. Swift's trampoline copies the strings immediately using String(cString:)
            // 2. Swift never stores the raw pointers
            // 3. The memory will be reclaimed when the process exits
            // Leaking is preferred over from_raw because we don't want Swift to try to free our memory
            std::mem::forget(ip_cstring);
            std::mem::forget(msg_cstring);
        }
        self.state.store(new_state as i32, Ordering::SeqCst);
    }

    /// Connect to the VPN server and perform X3DH handshake
    pub async fn connect(&self) -> Result<()> {
        // Early exit if reconnect was disabled (e.g. stopTunnel() called while we were in backoff)
        if !self.reconnect_enabled.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Connection cancelled by stop"));
        }

        // Set state to Connecting
        self.state.store(TunClientState::Connecting as i32, Ordering::SeqCst);
        self.notify_state(TunClientState::Connecting, None, "Connecting to server").await;

        // Build WebSocket URL for TUN endpoint
        // Swift may already append /tun, so only add if not present
        let tun_path = if self.server_path.ends_with("/tun") || self.server_path.ends_with("/tun/") {
            self.server_path.trim_end_matches('/').to_string()
        } else if self.server_path.ends_with("/") {
            format!("{}tun", self.server_path)
        } else {
            format!("{}/tun", self.server_path)
        };
        let url = format!(
            "wss://{}:{}{}",
            self.server_host, self.server_port, tun_path
        );

        info!("[IosTun] Connecting to {}", url);

        // Establish TLS connection with Chrome fingerprint via boring.
        // We connect to the pre-resolved IP for TCP, but use the original
        // hostname for TLS SNI to avoid DNS circular dependency during reconnect.
        let tls_stream = timeout(
            std::time::Duration::from_secs(5),
            connect_chrome_like(
                &self.server_ip.to_string(),
                self.server_port,
                self.tls_fingerprint,
                Some(&self.server_host),
            )
        )
        .await
        .context("TLS connect timeout (5s)")?
        .context("Failed to establish Chrome-fingerprinted TLS connection")?;

        // Check again after TLS connect (stop may have been requested during the 5s timeout)
        if !self.reconnect_enabled.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Connection cancelled by stop after TLS connect"));
        }

        // Build Chrome-like WebSocket upgrade request with 15 headers.
        let ws_key = generate_key();
        let authority = format!("{}:{}", self.server_host, self.server_port);
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
            .context("Failed to build WebSocket upgrade request")?;

        let (ws_stream, _) = timeout(
            std::time::Duration::from_secs(3),
            client_async(request, tls_stream)
        )
        .await
        .context("WebSocket handshake timeout (3s)")?
        .context("WebSocket handshake failed")?;

        info!("[IosTun] WebSocket connected (TLS verified)");

        // Check again after WS handshake
        if !self.reconnect_enabled.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Connection cancelled by stop after WS handshake"));
        }

        // Split into reader/writer
        let (mut write, mut read) = ws_stream.split();

        // Perform X3DH handshake
        let mut ratchet = self.perform_handshake(&mut read, &mut write).await
            .context("X3DH handshake failed")?;

        info!("[IosTun] X3DH handshake complete");

        // Check again after X3DH
        if !self.reconnect_enabled.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Connection cancelled by stop after X3DH"));
        }

        // Receive VirtualIp message
        let virtual_ip = self.receive_virtual_ip(&mut read, &mut ratchet).await
            .context("Failed to receive VirtualIp")?;

        // Extract IP address
        let ipv4_str = virtual_ip
            .ipv4
            .map(|v4| v4.to_string())
            .context("No IPv4 address in VirtualIp")?;

        info!("[IosTun] Assigned IP: {}", ipv4_str);

        // Store tunnel IP, gateway IP, DNS servers, and MTU
        {
            let mut tunnel_ip = self.tunnel_ip.lock().await;
            *tunnel_ip = Some(ipv4_str.clone());
        }
        {
            let mut gateway_ip = self.gateway_ip.lock().await;
            *gateway_ip = virtual_ip.gateway_ip.map(|v4| v4.to_string());
        }
        {
            let mut dns = self.dns_servers.lock().await;
            *dns = virtual_ip.dns_servers.clone();
        }
        {
            let mut mtu = self.mtu.lock().await;
            *mtu = virtual_ip.mtu;
        }

        // Set state to IpAssigned and notify Swift
        self.notify_state(TunClientState::IpAssigned, Some(&ipv4_str), "IP assigned").await;

        // Set state to Connected
        self.notify_state(TunClientState::Connected, Some(&ipv4_str), "Connected").await;

        // Start packet relay loop
        let (ws_write, ws_read) = (write, read);
        info!("[IosTun] connect() entering run_packet_relay()");
        self.run_packet_relay(ws_write, ws_read, ratchet).await;
        info!("[IosTun] connect() run_packet_relay() returned, connection ended");

        Ok(())
    }

    /// Perform X3DH handshake with server
    async fn perform_handshake(
        &self,
        ws_reader: &mut WsStream,
        ws_writer: &mut WsSink,
    ) -> Result<DoubleRatchet> {
        // Generate ephemeral key
        let ephemeral_key = EphemeralKey::generate();

        // Create X3DH initiator
        let initiator = X3DHInitiator {
            identity_key: self.identity_key.clone(),
            ephemeral_key,
        };

        // Get the X25519 public key derived from the client's Ed25519 identity
        let identity_public = initiator.identity_key.x25519_public_key();

        // Get public key bytes for the handshake
        let ephemeral_public = initiator.ephemeral_key.public_key.to_bytes();

        // Send Hello message with X3DH parameters
        let hello = HandshakeMessage::Hello {
            version: rvpn_core::protocol::ProtocolVersion::CURRENT,
            auth_method: rvpn_core::protocol::AuthMethod::X3DH,
            ephemeral_key: Some(ephemeral_public.to_vec()),
            identity_key: Some(identity_public.to_vec()),
            session_token: None,
            connection_nonce: None,
        };

        let hello_bytes = serde_json::to_vec(&hello)
            .context("Failed to serialize Hello message")?;
        ws_writer
            .send(Message::Binary(hello_bytes))
            .await
            .context("Failed to send Hello message")?;

        debug!("[IosTun] Sent X3DH Hello message");

        // Receive ServerHello response
        // ws_reader.next() returns Option<Result<Message, Error>>
        let msg_opt = timeout(std::time::Duration::from_secs(5), ws_reader.next())
            .await
            .context("WebSocket timeout during handshake (5s)")?
            .context("WebSocket closed during handshake")?;

        let msg = msg_opt.context("WebSocket error during handshake")?;

        match msg {
            Message::Binary(data) => {
                // ServerHello received, extract keys
                let server_hello: HandshakeMessage =
                    serde_json::from_slice(&data)
                        .context("Failed to parse ServerHello message")?;

                match server_hello {
                    HandshakeMessage::ServerHello {
                        ephemeral_key: _server_ephemeral,
                        identity_key: server_identity_key,
                        signed_prekey: server_signed_prekey,
                        prekey_signature: server_prekey_signature,
                    } => {
                        debug!("[IosTun] Received ServerHello with ephemeral key");

                        // Build a bundle from the SERVER'S ACTUAL KEYS (not the pre-loaded bundle)
                        let server_identity_key: [u8; 32] = server_identity_key
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Server identity key has invalid length"))?;
                        let server_signed_prekey: [u8; 32] = server_signed_prekey
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Server signed prekey has invalid length"))?;
                        let prekey_signature: [u8; 64] = server_prekey_signature
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Prekey signature has invalid length"))?;

                        // Verify the Ed25519 signature on signed_prekey using the server's identity_key
                        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&server_identity_key)
                            .map_err(|e| anyhow::anyhow!("Invalid server identity key: {}", e))?;
                        let signature = ed25519_dalek::Signature::from_bytes(&prekey_signature);
                        verifying_key.verify(&server_signed_prekey, &signature)
                            .map_err(|e| anyhow::anyhow!("Invalid prekey signature: {}", e))?;
                        debug!("[IosTun] Server prekey signature verified");

                        // For the X3DH key agreement, we need the server's identity_x25519_key which is
                        // derived from the server's Ed25519 *private* key. We can't derive it from the
                        // Ed25519 *public* key sent in ServerHello, so use the pre-loaded bundle's value.
                        let server_identity_x25519_key = self.server_bundle.identity_x25519_key;

                        // Bundle for X3DH key agreement — uses pre-loaded identity_x25519_key
                        // but the actual signed_prekey from the ServerHello (signature-verified above)
                        let server_bundle_from_hello = X3DHPublicBundle {
                            identity_key: server_identity_key,
                            identity_x25519_key: server_identity_x25519_key,
                            signed_prekey: server_signed_prekey,
                            prekey_signature: prekey_signature,
                            one_time_prekey: None,
                        };

                        // Complete X3DH agreement using the SERVER'S ACTUAL bundle
                        let (shared_secret, _x3dh_material) = initiator
                            .agree(&server_bundle_from_hello)
                            .context("X3DH key agreement failed")?;

                        debug!("[IosTun] X3DH shared secret derived successfully");

                        // Initialize Double Ratchet as Alice (initiator)
                        // In X3DH, the server (Bob) doesn't generate an ephemeral key.
                        // The _server_ephemeral field is empty - init_alice doesn't use this parameter.
                        let ratchet = DoubleRatchet::init_alice(shared_secret, [0u8; 32]);

                        info!("[IosTun] Double Ratchet initialized as Alice (initiator)");

                        Ok(ratchet)
                    }
                    _ => Err(anyhow::anyhow!(
                        "Unexpected handshake message type from server"
                    )),
                }
            }
            _ => Err(anyhow::anyhow!("Expected binary message during handshake")),
        }
    }

    /// Receive and process VirtualIp message
    async fn receive_virtual_ip(
        &self,
        ws_reader: &mut WsStream,
        ratchet: &mut DoubleRatchet,
    ) -> Result<VirtualIp> {
        // Wait for first encrypted frame after X3DH
        // ws_reader.next() returns Option<Result<Message, Error>>
        let msg_opt = timeout(std::time::Duration::from_secs(5), ws_reader.next())
            .await
            .context("Timeout waiting for VirtualIp (5s)")?
            .context("WebSocket closed during VirtualIp wait")?;

        let msg = msg_opt.context("WebSocket error during VirtualIp wait")?;

        match msg {
            Message::Binary(data) => {
                debug!("[IosTun] Received {} bytes, decrypting VirtualIp", data.len());

                // Deserialize RatchetMessage
                let ratchet_msg = RatchetMessage::from_bytes(&data)
                    .context("Failed to deserialize RatchetMessage")?;

                // Decrypt with VirtualIp payload type as AAD
                let decrypted = ratchet
                    .decrypt(&ratchet_msg, &[PayloadType::VirtualIp as u8])
                    .context("Failed to decrypt VirtualIp")?;

                // Unpad the frame
                let unpadded = unpad_packet(&decrypted)
                    .map_err(|e| anyhow::anyhow!("Failed to unpad VirtualIp: {}", e))?;

                // Parse VirtualIp from JSON
                let virtual_ip: VirtualIp = serde_json::from_slice(&unpadded)
                    .context("Failed to parse VirtualIp JSON")?;

                info!(
                    "[IosTun] VirtualIp received: ipv4={:?}, dns={:?}, mtu={}",
                    virtual_ip.ipv4, virtual_ip.dns_servers, virtual_ip.mtu
                );

                Ok(virtual_ip)
            }
            _ => Err(anyhow::anyhow!("Expected binary message for VirtualIp")),
        }
    }

    /// Main packet relay loop
    async fn run_packet_relay(
        &self,
        ws_write: WsSink,
        mut ws_read: WsStream,
        ratchet: DoubleRatchet,
    ) {
        info!("[IosTun] run_packet_relay STARTING");

        // Clone for server->swift
        let to_swift_sender = self.to_swift_sender.clone();
        let shutdown_tx = self.shutdown_tx.clone();
        let from_swift_receiver = Arc::clone(&self.from_swift_receiver);

        // Wrap ratchet and WebSocket writer in Arc<Mutex> for safe sharing between
        // concurrent tasks. Multiple tasks may need to send (data path + keepalive).
        let ratchet = Arc::new(Mutex::new(ratchet));
        let ws_write = Arc::new(Mutex::new(ws_write));
        let ws_write_for_swift = ws_write.clone();
        let ws_write_for_keepalive = ws_write.clone();
        let ratchet_for_keepalive = ratchet.clone();

        // SWIFT -> SERVER direction
        let swift_to_server = async {
            let mut shutdown_rx = self.shutdown_tx.subscribe();
            let mut packet_count = 0u64;
            let mut batch_count = 0u64;
            let mut pending_packet: Option<Vec<u8>> = None;
            info!("[IosTun] swift_to_server task STARTED");
            'outer: loop {
                // Acquire the first packet for this batch (either a packet that
                // did not fit in the previous batch or a fresh one from Swift).
                let mut batch = Vec::with_capacity(OUTGOING_BATCH_MAX_FRAMES);
                let mut batch_bytes = 0usize;

                let first = match pending_packet.take() {
                    Some(p) => p,
                    None => {
                        tokio::select! {
                            _ = shutdown_rx.recv() => {
                                info!("[IosTun] Swift->Server relay: shutdown received, breaking");
                                break 'outer;
                            }
                            packet = async {
                                let mut r = from_swift_receiver.lock().await;
                                r.recv().await
                            } => {
                                match packet {
                                    Some(p) => p,
                                    None => {
                                        info!("[IosTun] Swift->Server: from_swift_receiver closed, breaking (sent {} packets)", packet_count);
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }
                };

                batch.push(first);
                batch_bytes += batch[0].len();
                packet_count += 1;

                // Collect additional packets until we hit a size/time limit.
                let deadline = tokio::time::Instant::now()
                    + std::time::Duration::from_millis(OUTGOING_BATCH_TIMEOUT_MS);
                let mut receiver_closed = false;
                while batch.len() < OUTGOING_BATCH_MAX_FRAMES && batch_bytes < OUTGOING_BATCH_MAX_BYTES {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }

                    let packet = tokio::select! {
                        _ = shutdown_rx.recv() => {
                            info!("[IosTun] Swift->Server relay: shutdown received while collecting, breaking");
                            break 'outer;
                        }
                        packet = timeout(remaining, async {
                            let mut r = from_swift_receiver.lock().await;
                            r.recv().await
                        }) => packet,
                    };

                    match packet {
                        Ok(Some(data)) => {
                            // Account for the 6-byte MultiplexedFrame header.
                            if batch_bytes + 6 + data.len() > OUTGOING_BATCH_MAX_BYTES {
                                pending_packet = Some(data);
                                break;
                            }
                            batch_bytes += data.len();
                            batch.push(data);
                            packet_count += 1;
                        }
                        Ok(None) => {
                            receiver_closed = true;
                            break;
                        }
                        Err(_) => break,
                    }
                }

                batch_count += 1;
                if batch_count <= 5 || batch_count % 100 == 0 {
                    info!(
                        "[IosTun] Swift->Server: encrypting batch of {} frames, {} bytes (batch #{}, total packets {})",
                        batch.len(), batch_bytes, batch_count, packet_count
                    );
                }

                // Encrypt while holding the ratchet lock, then release the lock
                // before the async WebSocket send so decryption is not blocked.
                let encrypt_start = tokio::time::Instant::now();
                let encrypted = {
                    let mut ratchet_guard = ratchet.lock().await;
                    match Self::encrypt_data_batch(&mut *ratchet_guard, &batch) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            error!("[IosTun] Swift->Server: encrypt_data_batch failed: {}, sending shutdown", e);
                            let _ = shutdown_tx.send(());
                            break 'outer;
                        }
                    }
                };
                let encrypt_elapsed = encrypt_start.elapsed();
                if encrypt_elapsed.as_millis() > 50 {
                    warn!(
                        "[IosTun] Swift->Server: slow batch encryption ({:?}) for {} frames",
                        encrypt_elapsed, batch.len()
                    );
                }

                let mut ws_guard = ws_write_for_swift.lock().await;
                if let Err(e) = ws_guard.send(Message::Binary(encrypted)).await {
                    error!("[IosTun] Swift->Server: WebSocket send failed: {}, sending shutdown", e);
                    drop(ws_guard);
                    let _ = shutdown_tx.send(());
                    break 'outer;
                }

                if receiver_closed {
                    info!("[IosTun] Swift->Server: from_swift_receiver closed after batch, breaking (sent {} packets)", packet_count);
                    break 'outer;
                }
            }
            info!("[IosTun] swift_to_server task ENDED");
        };

        // SERVER -> SWIFT direction
        let packet_notify_tx = self.packet_notify_tx.clone();
        let server_to_swift = async {
            let mut shutdown_rx = self.shutdown_tx.subscribe();
            let mut packet_count = 0u64;
            info!("[IosTun] server_to_swift task STARTED");
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("[IosTun] Server->Swift relay: shutdown received, breaking");
                        break;
                    }
                    msg = timeout(std::time::Duration::from_secs(60), ws_read.next()) => {
                        match msg {
                            Ok(Some(Ok(Message::Binary(data)))) => {
                                packet_count += 1;
                                if packet_count <= 5 || packet_count % 100 == 0 {
                                    info!("[IosTun] Server->Swift: received {} bytes Binary (packet #{})", data.len(), packet_count);
                                }

                                // Deserialize and decrypt while holding the ratchet lock, then
                                // release the lock before the async channel send.
                                let decrypted = match RatchetMessage::from_bytes(&data) {
                                    Ok(ratchet_msg) => {
                                        let mut ratchet_guard = ratchet.lock().await;
                                        match ratchet_guard.decrypt(&ratchet_msg, &[PayloadType::Data as u8]) {
                                            Ok(plaintext) => Some(plaintext),
                                            Err(e) => {
                                                error!("[IosTun] Server->Swift: Failed to decrypt packet: {}", e);
                                                None
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("[IosTun] Server->Swift: Failed to deserialize RatchetMessage: {}", e);
                                        None
                                    }
                                };

                                if let Some(decrypted) = decrypted {
                                    match unpad_packet(&decrypted) {
                                        Ok(unpadded) => {
                                            match MultiplexedFrame::decode(&unpadded) {
                                                Ok(frame) => {
                                                    if frame.flow_id == 0 {
                                                        // Control message (e.g., Pong). Parse and handle;
                                                        // do not forward to Swift.
                                                        match frame.parse_control() {
                                                            Ok(ControlMessage::Pong { timestamp }) => {
                                                                trace!("[IosTun] Server->Swift: received Pong(ts={})", timestamp);
                                                            }
                                                            Ok(other) => {
                                                                trace!("[IosTun] Server->Swift: received control {:?}", other);
                                                            }
                                                            Err(e) => {
                                                                error!("[IosTun] Server->Swift: Failed to parse control frame: {}", e);
                                                            }
                                                        }
                                                    } else {
                                                        if packet_count <= 5 || packet_count % 100 == 0 {
                                                            info!("[IosTun] Server->Swift: flow_id={} sending {} bytes to Swift (packet #{})", frame.flow_id, frame.payload.len(), packet_count);
                                                        }
                                                        if to_swift_sender.send(frame.payload.to_vec()).await.is_err() {
                                                            info!("[IosTun] Server->Swift: to_swift_sender closed, breaking");
                                                            break;
                                                        }
                                                        // Wake the Swift write loop. If the previous signal has not
                                                        // yet been consumed, dropping the send is fine: recv_timeout
                                                        // will return immediately for the pending signal.
                                                        let _ = packet_notify_tx.try_send(());
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("[IosTun] Server->Swift: Failed to decode MultiplexedFrame: {}", e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("[IosTun] Server->Swift: Failed to unpad packet: {}", e);
                                        }
                                    }
                                }
                            }
                            Ok(Some(Ok(Message::Close(frame)))) => {
                                info!("[IosTun] Server->Swift: received Close frame ({:?}), sending shutdown and breaking", frame);
                                let _ = shutdown_tx.send(());
                                break;
                            }
                            Ok(None) => {
                                info!("[IosTun] Server->Swift: ws_read returned None (stream ended), sending shutdown and breaking");
                                let _ = shutdown_tx.send(());
                                break;
                            }
                            Ok(Some(Err(e))) => {
                                error!("[IosTun] Server->Swift: WebSocket error: {}, sending shutdown and breaking", e);
                                let _ = shutdown_tx.send(());
                                break;
                            }
                            Err(_) => {
                                error!("[IosTun] Server->Swift: WebSocket read timeout (60s), sending shutdown and breaking");
                                let _ = shutdown_tx.send(());
                                break;
                            }
                            Ok(Some(Ok(Message::Ping(_)))) => {
                                debug!("[IosTun] Server->Swift: received Ping");
                            }
                            Ok(Some(Ok(Message::Pong(_)))) => {
                                debug!("[IosTun] Server->Swift: received Pong");
                            }
                            Ok(Some(Ok(other))) => {
                                info!("[IosTun] Server->Swift: received unexpected message type: {:?}", other);
                            }
                        }
                    }
                }
            }
            info!("[IosTun] server_to_swift task ENDED (received {} packets)", packet_count);
        };

        // Keepalive task — sends a Ping every 15 seconds to prevent the server's
        // 60-second WebSocket idle timeout and to keep the extension runnable.
        let keepalive = {
            let shutdown_tx = shutdown_tx.clone();
            async move {
                let ratchet = ratchet_for_keepalive;
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                // Skip the immediate first tick.
                interval.tick().await;
                loop {
                    interval.tick().await;

                    let encrypted = {
                        let mut ratchet_guard = ratchet.lock().await;
                        match Self::build_keepalive_packet(&mut *ratchet_guard) {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                error!("[IosTun] Keepalive: build_keepalive_packet failed: {}", e);
                                continue;
                            }
                        }
                    };

                    let mut ws_guard = ws_write_for_keepalive.lock().await;
                    if let Err(e) = ws_guard.send(Message::Binary(encrypted)).await {
                        error!("[IosTun] Keepalive: WebSocket send failed: {}, sending shutdown", e);
                        drop(ws_guard);
                        let _ = shutdown_tx.send(());
                        break;
                    }
                    trace!("[IosTun] Keepalive: Ping sent");
                }
            }
        };

        // Run all tasks concurrently
        tokio::select! {
            _ = swift_to_server => {
                info!("[IosTun] tokio::select! swift_to_server completed first");
            }
            _ = server_to_swift => {
                info!("[IosTun] tokio::select! server_to_swift completed first");
            }
            _ = keepalive => {
                info!("[IosTun] tokio::select! keepalive completed first");
            }
        }

        info!("[IosTun] run_packet_relay ENDING");
        self.notify_state(TunClientState::Error, None, "Connection closed").await;
    }

    /// Encrypt a batch of TUN packets into a single WebSocket/Ratchet message.
    ///
    /// Each packet is wrapped in a `MultiplexedFrame` with `flow_id=1`; the
    /// encoded frames are concatenated, padded once, and encrypted once. The
    /// server parses the decrypted plaintext with `parse_frames`.
    fn encrypt_data_batch(ratchet: &mut DoubleRatchet, packets: &[Vec<u8>]) -> Result<Vec<u8>> {
        if packets.is_empty() {
            return Err(anyhow::anyhow!("Cannot encrypt empty batch"));
        }

        let mut plaintext = BytesMut::new();
        for packet in packets {
            let frame = MultiplexedFrame::new_data(1, packet.clone());
            frame
                .encode_to(&mut plaintext)
                .context("Failed to encode MultiplexedFrame")?;
        }

        // Pad the concatenated frames to a 1KB boundary for traffic analysis mitigation
        let padded = pad_packet(&plaintext)
            .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;

        // Encrypt with Data payload type as AAD
        let encrypted = ratchet
            .encrypt(&padded, &[PayloadType::Data as u8])
            .context("Failed to encrypt data batch")?;

        // Serialize to bytes
        encrypted
            .to_bytes()
            .context("Failed to serialize RatchetMessage")
    }

    /// Build an encrypted keepalive (Ping) frame.
    ///
    /// The server expects Ping on flow_id=0 as a ControlMessage. We send it with
    /// Data payload type so the existing receive path decrypts it correctly.
    fn build_keepalive_packet(ratchet: &mut DoubleRatchet) -> Result<Vec<u8>> {
        let ping = ControlMessage::Ping {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };
        let frame = MultiplexedFrame::new_control(&ping)
            .context("Failed to create keepalive frame")?;
        let frame_bytes = frame
            .encode()
            .context("Failed to encode keepalive frame")?;
        let padded = pad_packet(&frame_bytes)
            .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;
        let encrypted = ratchet
            .encrypt(&padded, &[PayloadType::Data as u8])
            .context("Failed to encrypt keepalive")?;
        encrypted
            .to_bytes()
            .context("Failed to serialize keepalive RatchetMessage")
    }

    /// Get the assigned tunnel IP
    pub async fn get_tunnel_ip(&self) -> Option<String> {
        let guard = self.tunnel_ip.lock().await;
        guard.clone()
    }

    /// Get the assigned gateway IP
    pub async fn get_gateway_ip(&self) -> Option<String> {
        let guard = self.gateway_ip.lock().await;
        guard.clone()
    }

    /// Get the DNS servers from VirtualIp
    pub async fn get_dns_servers(&self) -> Vec<std::net::IpAddr> {
        let guard = self.dns_servers.lock().await;
        guard.clone()
    }

    /// Get the MTU from VirtualIp
    pub async fn get_mtu(&self) -> u16 {
        let guard = self.mtu.lock().await;
        *guard
    }

    /// Get current state
    pub fn get_state(&self) -> TunClientState {
        TunClientState::from(self.state.load(Ordering::SeqCst))
    }

    /// Check if DNS proxy is enabled in config
    pub fn is_dns_proxy_enabled(&self) -> bool {
        self.config.enable_dns_proxy
    }

    /// Get DNS bind address from config
    pub fn get_dns_bind_addr(&self) -> &str {
        &self.config.dns_bind_addr
    }

    /// Get builtin bypass countries from config
    pub fn get_builtin_bypass_countries(&self) -> &[String] {
        &self.config.builtin_bypass_countries
    }

    /// Check if block ads is enabled in config
    pub fn is_block_ads_enabled(&self) -> bool {
        self.config.block_ads
    }

    /// Get identity key reference
    pub(crate) fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    /// Get server bundle reference
    pub(crate) fn server_bundle(&self) -> &X3DHPublicBundle {
        &self.server_bundle
    }

    /// Get server host
    pub fn server_host(&self) -> &str {
        &self.server_host
    }

    /// Get server port
    pub fn server_port(&self) -> u16 {
        self.server_port
    }

    /// Get server path
    pub fn server_path(&self) -> &str {
        &self.server_path
    }

    /// Get pre-resolved server IP address
    pub fn server_ip(&self) -> std::net::IpAddr {
        self.server_ip
    }

    /// Get TLS fingerprint
    pub fn tls_fingerprint(&self) -> TlsFingerprint {
        self.tls_fingerprint
    }

    /// Send a packet to the server (call this from Swift)
    /// Swift calls this to send packets to be relayed to the server
    pub async fn send_packet_to_server(&self, packet: Vec<u8>) -> Result<()> {
        self.from_swift_sender
            .send(packet)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send packet: {}", e))
    }

    /// Non-blocking send for FFI hot path (avoids block_on deadlock)
    /// Returns TrySendError if the channel is full or disconnected
    pub fn try_send_packet(&self, packet: Vec<u8>) -> Result<(), tokio::sync::mpsc::error::TrySendError<Vec<u8>>> {
        self.from_swift_sender.try_send(packet)
    }

    /// Receive a packet from the server (call this from Swift)
    /// Swift calls this to receive packets that came from the server
    /// Non-blocking - returns None if no packet is available
    pub fn recv_packet_from_server(&self) -> Option<Vec<u8>> {
        let mut rx = self.to_swift_receiver.try_lock().ok()?;
        rx.try_recv().ok()
    }

    /// Wait until a packet may be available, or the timeout elapses.
    /// Called from Swift's write loop so it can sleep event-driven instead
    /// of polling every millisecond.
    /// Returns 1 if a packet may be available, 0 on timeout/disconnect.
    pub fn wait_for_packet(&self, timeout_ms: u64) -> i32 {
        // Use a std channel instead of tokio::sync::Notify so we can block
        // synchronously here without entering the Tokio runtime. The Swift
        // write loop runs on its own dispatch queue, not a Tokio worker.
        let rx = self.packet_notify_rx.lock().unwrap();
        match rx.recv_timeout(std::time::Duration::from_millis(timeout_ms)) {
            Ok(()) => 1,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => 0,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => 0,
        }
    }

    /// Start the client (runs connect and relay in background)
    /// Implements reconnection loop when enabled via set_reconnect_enabled()
    ///
    /// This method is idempotent — calling it multiple times has no effect.
    pub fn start(self: &Arc<Self>) {
        // Atomically check and set is_started to prevent duplicate reconnect loops
        if self.is_started.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
            warn!("[IosTun] start() called but reconnect loop already running, ignoring");
            return;
        }

        let client = Arc::clone(self);
        self.runtime.spawn(async move {
            let mut attempts: u32 = 0;
            let mut had_successful_session = false;
            loop {
                // Check if reconnection is enabled
                if !client.reconnect_enabled.load(Ordering::Relaxed) {
                    info!("[IosTun] Reconnection disabled, exiting reconnect loop");
                    break;
                }

                // Check max attempts (0 = unlimited)
                let max_attempts = client.reconnect_max_attempts.load(Ordering::Relaxed);
                if max_attempts > 0 && attempts >= max_attempts {
                    error!("[IosTun] Max reconnection attempts ({}) reached", max_attempts);
                    client.notify_state(TunClientState::Error, None, "Max reconnection attempts reached").await;
                    break;
                }

                // Delay before reconnecting: none after a successful session (the
                // network path is already up), exponential backoff after failures.
                if had_successful_session {
                    had_successful_session = false;
                    // Immediate reconnect — previous session was healthy, this is
                    // a network transition (e.g. WiFi→5G), not a flaky server.
                } else if attempts > 0 {
                    let initial_delay = client.reconnect_initial_delay_ms.load(Ordering::Relaxed);
                    let max_delay = client.reconnect_max_delay_ms.load(Ordering::Relaxed);
                    let delay = std::cmp::min(
                        initial_delay.saturating_mul(2u64.saturating_pow(attempts - 1)),
                        max_delay,
                    );
                    let max_attempts_str = if max_attempts > 0 { max_attempts.to_string() } else { "unlimited".to_string() };
                    info!("[IosTun] Reconnecting in {}ms (attempt {}/{})", delay, attempts + 1, max_attempts_str);

                    // Sleep in small chunks so we can check reconnect_enabled mid-sleep
                    let sleep_start = tokio::time::Instant::now();
                    let sleep_duration = tokio::time::Duration::from_millis(delay);
                    while tokio::time::Instant::now().duration_since(sleep_start) < sleep_duration {
                        if !client.reconnect_enabled.load(Ordering::Relaxed) {
                            info!("[IosTun] Reconnection disabled during backoff, stopping");
                            return;
                        }
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }

                match client.connect().await {
                    Ok(()) => {
                        // Connection completed normally (had a successful session)
                        info!("[IosTun] Connection ended, reconnecting immediately...");
                        attempts = 0;
                        had_successful_session = true;
                    }
                    Err(e) => {
                        error!("[IosTun] Connection failed (attempt {}): {}", attempts + 1, e);
                        attempts += 1;
                    }
                }

                // Check if reconnection was disabled while we were connected
                if !client.reconnect_enabled.load(Ordering::Relaxed) {
                    info!("[IosTun] Reconnection disabled after connection end, stopping");
                    break;
                }
            }
        });
    }

    /// Set whether reconnection is enabled
    pub fn set_reconnect_enabled(&self, enabled: bool) {
        self.reconnect_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Check if reconnection is enabled
    pub fn is_reconnect_enabled(&self) -> bool {
        self.reconnect_enabled.load(Ordering::Relaxed)
    }

    /// Set maximum reconnection attempts (0 = unlimited)
    pub fn set_reconnect_max_attempts(&self, attempts: u32) {
        self.reconnect_max_attempts.store(attempts, Ordering::Relaxed);
    }

    /// Set initial reconnection delay (ms)
    pub fn set_reconnect_initial_delay_ms(&self, delay_ms: u64) {
        self.reconnect_initial_delay_ms.store(delay_ms, Ordering::Relaxed);
    }

    /// Set maximum reconnection delay (ms)
    pub fn set_reconnect_max_delay_ms(&self, delay_ms: u64) {
        self.reconnect_max_delay_ms.store(delay_ms, Ordering::Relaxed);
    }

    /// Stop the client
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
        // Reset is_started so the client can be restarted after a full stop
        self.is_started.store(false, Ordering::SeqCst);
    }

    /// Request a gentle reconnect without disabling the reconnect loop.
    ///
    /// This sends a shutdown signal to the current packet relay, causing
    /// `connect()` to return and the reconnect loop to start a new connection.
    /// Unlike `stop()`, this does NOT reset `is_started` or disable reconnect,
    /// so the reconnect loop continues naturally.
    ///
    /// A 5-second cooldown prevents reconnect storms from rapid network
    /// change notifications (especially on macOS where NWPathMonitor fires
    /// frequently).
    pub fn request_reconnect(&self) {
        let now = std::time::Instant::now();
        let mut last = self.last_reconnect_request.lock().unwrap();
        if now.duration_since(*last) < std::time::Duration::from_secs(5) {
            info!("[IosTun] Reconnect requested too soon (cooldown active), ignoring");
            return;
        }
        *last = now;
        drop(last);

        let _ = self.shutdown_tx.send(());
        info!("[IosTun] Reconnect requested via gentle shutdown signal");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_client_state_from_i32() {
        assert_eq!(TunClientState::from(0), TunClientState::Init);
        assert_eq!(TunClientState::from(1), TunClientState::Connecting);
        assert_eq!(TunClientState::from(2), TunClientState::IpAssigned);
        assert_eq!(TunClientState::from(3), TunClientState::Connected);
        assert_eq!(TunClientState::from(4), TunClientState::Error);
        assert_eq!(TunClientState::from(99), TunClientState::Error);
    }

    #[test]
    fn test_parse_server_url() {
        let (host, port, path) = IosTunClient::parse_server_url(
            "wss://test.example.com:443/api/v1/ws"
        ).unwrap();
        assert_eq!(host, "test.example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api/v1/ws");

        let (host, port, path) = IosTunClient::parse_server_url(
            "wss://test.example.com:443/api/v1/ws/"
        ).unwrap();
        assert_eq!(host, "test.example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api/v1/ws/");
    }
}