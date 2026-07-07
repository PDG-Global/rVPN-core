// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Android Direct TUN Client - True TUN-to-TUN tunneling via WebSocket
//!
//! This module provides a client for Android Direct TUN mode where:
//! - Android connects to `/api/v1/ws/tun` endpoint
//! - Server assigns a tunnel IP via `VirtualIp` message after X3DH
//! - Raw IP packets flow bidirectionally through the WebSocket
//!
//! Architecture:
//! - Android TUN interface captures raw IP packets
//! - This client exchanges packets with Android via channels
//! - X3DH handshake establishes Double Ratchet
//! - Server sends VirtualIp with assigned IP
//! - Raw IP packets are encrypted and relayed

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use futures::SinkExt;
use futures::StreamExt;
use futures_util::stream::SplitSink;
use parking_lot::RwLock;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::time::timeout;
use bytes::BytesMut;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tokio::net::TcpStream;
use tungstenite::handshake::client::generate_key;
use rvpn_tls::TlsFingerprint;

// Use logcat macros for Android logging
macro_rules! tun_log {
    ($($arg:tt)*) => {
        android_log("rvpn_mobile", &format!($($arg)*), 4);
    };
}
macro_rules! tun_log_error {
    ($($arg:tt)*) => {
        android_log("rvpn_mobile", &format!("ERROR: {}", format!($($arg)*)), 6);
    };
}

#[cfg(target_os = "android")]
extern "C" {
    fn __android_log_write(prio: i32, tag: *const std::ffi::c_char, msg: *const std::ffi::c_char) -> i32;
}

#[cfg(target_os = "android")]
pub fn android_log(tag: &str, msg: &str, prio: i32) {
    use std::ffi::CString;
    if let (Ok(tag_c), Ok(msg_c)) = (CString::new(tag), CString::new(msg)) {
        unsafe { __android_log_write(prio, tag_c.as_ptr(), msg_c.as_ptr()) };
    }
}

use rvpn_core::crypto::ratchet::RatchetMessage;
use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::crypto::{DoubleRatchet, EphemeralKey, IdentityKey, X3DHPublicBundle};
use rvpn_core::protocol::{ControlMessage, HandshakeMessage, MultiplexedFrame, PayloadType, VirtualIp};
use rvpn_core::protocol::padding::{pad_packet, unpad_packet};

use crate::ffi::TunConfig;

/// WebSocket writer type
type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type WsStream = futures_util::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

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

/// State callback type for Android notifications
/// Called when state changes: (state: i32, ip: *const c_char, message: *const c_char)
pub type StateCallback =
    Option<unsafe extern "C" fn(state: i32, ip: *const std::os::raw::c_char, msg: *const std::os::raw::c_char)>;

/// AndroidTunClient - Direct TUN mode client for Android
///
/// Connects to the VPN server's `/tun` endpoint, performs X3DH handshake,
/// receives a VirtualIp assignment, and relays raw IP packets bidirectionally.
///
/// # Channel Design
/// - Android sends packets to server via `from_swift_sender` (mpsc::Sender)
/// - Android receives packets from server via `to_swift_receiver` (mpsc::Receiver)
/// Both are exposed via getters for Android to use.
pub struct AndroidTunClient {
    /// Tokio runtime handle
    runtime: Arc<tokio::runtime::Runtime>,
    /// Configuration (kept for debugging and future reconnection support)
    /// Note: fields are extracted on construction to avoid per-packet locking
    #[allow(dead_code)]
    config: TunConfig,
    /// Server host
    server_host: String,
    /// Server port
    server_port: u16,
    /// WebSocket path (base path, will append /tun)
    server_path: String,
    /// Connection state
    state: Arc<AtomicI32>,
    /// Assigned tunnel IP (set after VirtualIp received)
    tunnel_ip: Arc<Mutex<Option<String>>>,
    /// Sender for packets to Android (Android receives via recv_packet_from_server)
    to_swift_sender: mpsc::Sender<Vec<u8>>,
    /// Receiver for packets from Android (Android sends via send_packet_to_server)
    from_swift_receiver: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    /// Sender for Android to use (Android calls send_packet_to_server with this)
    pub from_swift_sender: mpsc::Sender<Vec<u8>>,
    /// Receiver for packets to Android
    pub to_swift_receiver: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    /// Shutdown signal
    shutdown_tx: broadcast::Sender<()>,
    /// Identity key for X3DH
    identity_key: IdentityKey,
    /// Server prekey bundle for X3DH
    server_bundle: X3DHPublicBundle,
    /// Canonical `ik:1:<base32>` pin of the server's identity key, computed
    /// at construction from `server_bundle.identity_key`. Kotlin reads this
    /// via the JNI wrapper for `rvpn_tun_get_server_identity()` after the
    /// tunnel reaches `Connected` to capture the TOFU pin.
    server_identity_pin_actual: String,
    /// DNS servers from VirtualIp
    dns_servers: Arc<Mutex<Vec<std::net::IpAddr>>>,
    /// MTU from VirtualIp
    mtu: Arc<Mutex<u16>>,
    /// State callback for Android notifications (sync RwLock to avoid deadlock on 2-thread runtime)
    state_callback: Arc<RwLock<StateCallback>>,
    /// Stealth TLS fingerprint to use for the ClientHello (browser mimicry).
    /// Renamed from `tls_fingerprint` on the wire; keeps the same name here
    /// because it drives the actual TLS handshake code.
    tls_fingerprint: TlsFingerprint,
    /// Start/reconnect loop running flag (prevents duplicate loops)
    is_started: AtomicBool,
    /// Whether the reconnect loop should keep retrying
    reconnect_enabled: AtomicBool,
    /// Maximum reconnection attempts (0 = unlimited)
    reconnect_max_attempts: AtomicU32,
    /// Initial delay between reconnection attempts (ms)
    reconnect_initial_delay_ms: AtomicU64,
    /// Maximum delay between reconnection attempts (ms)
    reconnect_max_delay_ms: AtomicU64,
    /// Last time a reconnect was requested via network change (debounces rapid calls)
    last_reconnect_request: std::sync::Mutex<std::time::Instant>,
}

impl AndroidTunClient {
    /// Returns a clone of the Tokio runtime used by this client.
    pub fn runtime(&self) -> Arc<tokio::runtime::Runtime> {
        self.runtime.clone()
    }

    /// Create a new AndroidTunClient from configuration
    pub fn new(config: &TunConfig) -> Result<Self> {
        // Parse server URL
        let (host, port, path) = Self::parse_server_url(&config.server_address)?;

        // Load identity key (blocking I/O)
        let identity_key_path = std::path::PathBuf::from(&config.identity_key_path);
        let identity_key = IdentityKey::load(&identity_key_path)
            .context("Failed to load identity key")?;

        // Load prekey bundle
        let bundle_json = std::fs::read_to_string(&config.prekey_bundle_path)
            .context("Failed to read prekey bundle")?;
        let server_bundle: X3DHPublicBundle =
            serde_json::from_str(&bundle_json).context("Failed to parse prekey bundle JSON")?;

        // Compute + optionally enforce the TOFU pin (see ios_tun.rs for the
        // full rationale — same code shape). Failing here means we never
        // open a TCP socket to a mis-identified server.
        let server_identity_pin_actual =
            rvpn_core::identity_pin::encode_identity_pin(&server_bundle.identity_key)
                .context("Failed to encode server identity pin")?;
        if let Some(expected) = config.server_identity_pin.as_deref() {
            let matched = rvpn_core::identity_pin::pins_match(expected, &server_bundle.identity_key)
                .context("Configured server_identity_pin is not a valid pin string")?;
            if !matched {
                return Err(anyhow::Error::from(rvpn_core::Error::ServerIdentityMismatch {
                    expected: expected.to_string(),
                    actual: server_identity_pin_actual,
                }));
            }
        }

        // Parse stealth ClientHello fingerprint (default to Chrome).
        let tls_fingerprint = config.stealth_fingerprint.as_deref()
            .and_then(rvpn_tls::fingerprint_from_str)
            .unwrap_or(TlsFingerprint::Chrome);

        // Create channels for Android TUN communication
        // to_swift_receiver is used by Android to receive packets from server (via recv_packet_from_server)
        let (to_swift_sender, to_swift_receiver) = mpsc::channel::<Vec<u8>>(1000);
        // from_swift_receiver is used by Android to send packets to server (via send_packet_to_server)
        let (from_swift_sender, from_swift_receiver) = mpsc::channel::<Vec<u8>>(1000);

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel::<()>(1);

        // Set initial state
        let state = Arc::new(AtomicI32::new(TunClientState::Init as i32));

        // Create runtime
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("rvpn-android-tun")
            .build()
            .context("Failed to create Tokio runtime")?;

        Ok(Self {
            runtime: Arc::new(runtime),
            config: config.clone(),
            server_host: host,
            server_port: port,
            server_path: path,
            state,
            tunnel_ip: Arc::new(Mutex::new(None)),
            to_swift_sender,
            from_swift_receiver: Arc::new(Mutex::new(from_swift_receiver)),
            from_swift_sender,
            to_swift_receiver: Arc::new(Mutex::new(to_swift_receiver)),
            shutdown_tx,
            identity_key,
            server_bundle,
            server_identity_pin_actual,
            dns_servers: Arc::new(Mutex::new(Vec::new())),
            mtu: Arc::new(Mutex::new(1420)),
            state_callback: Arc::new(RwLock::new(None)),
            tls_fingerprint,
            is_started: AtomicBool::new(false),
            reconnect_enabled: AtomicBool::new(false), // Disabled by default; FFI start enables
            reconnect_max_attempts: AtomicU32::new(0), // 0 = unlimited
            reconnect_initial_delay_ms: AtomicU64::new(1000),
            reconnect_max_delay_ms: AtomicU64::new(5000),
            last_reconnect_request: std::sync::Mutex::new(
                std::time::Instant::now() - std::time::Duration::from_secs(60),
            ),
        })
    }

    /// Parse server URL into (host, port, path) — no url crate dependency
    fn parse_server_url(server_address: &str) -> Result<(String, u16, String)> {
        let rest = server_address
            .strip_prefix("wss://")
            .or_else(|| server_address.strip_prefix("ws://"))
            .unwrap_or(server_address);
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let path = if path.is_empty() { "/".to_string() } else { format!("/{}", path) };
        let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
            let port: u16 = p.parse().context("Invalid port in server_address")?;
            (h.to_string(), port)
        } else {
            (authority.to_string(), 443)
        };
        if host.is_empty() {
            anyhow::bail!("Missing host in server_address");
        }
        Ok((host, port, path))
    }

    /// Set the state callback for Android notifications
    pub fn set_state_callback(&self, callback: StateCallback) {
        let mut guard = self.state_callback.write();
        *guard = callback;
    }

    /// Call the state callback if set
    async fn notify_state(&self, new_state: TunClientState, ip: Option<&str>, message: &str) {
        tun_log!("[AndroidTun] notify_state: {:?}, ip={:?}, msg={}", new_state, ip, message);
        let callback = { self.state_callback.read().clone() };
        tun_log!("[AndroidTun] notify_state: callback={}", if callback.is_some() { "SET" } else { "NONE" });
        if let Some(cb) = callback {
            let ip_cstring = ip.map(|s| std::ffi::CString::new(s).unwrap());
            let msg_cstring = std::ffi::CString::new(message).unwrap();
            let ip_ptr = ip_cstring.as_ref().map(|s| s.as_ptr()).unwrap_or(std::ptr::null());
            let msg_ptr = msg_cstring.as_ptr();
            tun_log!("[AndroidTun] notify_state: calling callback...");
            unsafe {
                cb(new_state as i32, ip_ptr, msg_ptr);
            }
            tun_log!("[AndroidTun] notify_state: callback returned");
            std::mem::forget(ip_cstring);
            std::mem::forget(msg_cstring);
        }
        self.state.store(new_state as i32, Ordering::SeqCst);
        tun_log!("[AndroidTun] notify_state: done");
    }

    /// Connect to the VPN server and perform X3DH handshake
    pub async fn connect(&self) -> Result<()> {
        // Set state to Connecting
        self.state.store(TunClientState::Connecting as i32, Ordering::SeqCst);
        self.notify_state(TunClientState::Connecting, None, "Connecting to server").await;

        // Build WebSocket URL for TUN endpoint
        // Android may already append /tun, so only add if not present
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

        tun_log!("[AndroidTun] Connecting to {}", url);

        // Use rustls with bundled webpki-roots (same approach as iOS).
        // BoringSSL's static linking is broken on Android NDK (X509_free
        // and 150+ symbols left undefined in the .so). rustls works
        // reliably with no native C dependency.
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(tls_config));

        // Connect TCP to the server.
        let tcp_addr = format!("{}:{}", self.server_host, self.server_port);
        let tcp_stream = timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(&tcp_addr)
        )
        .await
        .context("TCP connect timeout (5s)")?
        .context("Failed to connect TCP stream")?;

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
            std::time::Duration::from_secs(5),
            tokio_tungstenite::client_async_tls_with_config(
                request,
                tcp_stream,
                None,
                Some(connector),
            )
        )
        .await
        .context("WebSocket handshake timeout (5s)")?
        .context("WebSocket handshake failed")?;

        tun_log!("[AndroidTun] WebSocket connected (TLS verified)");

        // Split into reader/writer
        let (mut write, mut read) = ws_stream.split();

        // Perform X3DH handshake
        let mut ratchet = self.perform_handshake(&mut read, &mut write).await
            .context("X3DH handshake failed")?;

        tun_log!("[AndroidTun] X3DH handshake complete");

        // Receive VirtualIp message
        let virtual_ip = self.receive_virtual_ip(&mut read, &mut ratchet).await
            .context("Failed to receive VirtualIp")?;

        // Extract IP address
        let ipv4_str = virtual_ip
            .ipv4
            .map(|v4| v4.to_string())
            .context("No IPv4 address in VirtualIp")?;

        tun_log!("[AndroidTun] Assigned IP: {}", ipv4_str);

        // Store tunnel IP, DNS servers, and MTU
        {
            let mut tunnel_ip = self.tunnel_ip.lock().await;
            *tunnel_ip = Some(ipv4_str.clone());
        }
        {
            let mut dns = self.dns_servers.lock().await;
            *dns = virtual_ip.dns_servers.clone();
        }
        {
            let mut mtu = self.mtu.lock().await;
            *mtu = virtual_ip.mtu;
        }

        // Set state to IpAssigned and notify Android
        self.notify_state(TunClientState::IpAssigned, Some(&ipv4_str), "IP assigned").await;

        // Set state to Connected
        self.notify_state(TunClientState::Connected, Some(&ipv4_str), "Connected").await;

        // Start packet relay loop
        let (ws_write, ws_read) = (write, read);
        self.run_packet_relay(ws_write, ws_read, ratchet).await;

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

        tun_log!("[AndroidTun] Sent X3DH Hello message");

        // Receive ServerHello response
        // ws_reader.next() returns Option<Result<Message, Error>>
        let msg_opt = timeout(std::time::Duration::from_secs(10), ws_reader.next())
            .await
            .context("WebSocket timeout during handshake")?
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
                        tun_log!("[AndroidTun] Received ServerHello with ephemeral key");

                        // Use wire values for X3DH. Ignoring them and running
                        // agreement against the pre-loaded on-disk bundle
                        // silently breaks every connection whenever the disk
                        // copy drifts from what the server is actually running
                        // (e.g. after any `rvpn-server prekey-bundle` run).
                        // Mirrors the working pattern in ios_tun.rs.
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

                        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
                            &server_identity_key,
                        )
                        .map_err(|e| anyhow::anyhow!("Invalid server identity key: {}", e))?;
                        let signature = ed25519_dalek::Signature::from_bytes(&prekey_signature);
                        ed25519_dalek::Verifier::verify(
                            &verifying_key,
                            &server_signed_prekey,
                            &signature,
                        )
                        .map_err(|e| anyhow::anyhow!("Invalid prekey signature: {}", e))?;
                        tun_log!("[AndroidTun] Server prekey signature verified");

                        let server_bundle_from_hello = X3DHPublicBundle {
                            identity_key: server_identity_key,
                            identity_x25519_key: self.server_bundle.identity_x25519_key,
                            signed_prekey: server_signed_prekey,
                            prekey_signature,
                            one_time_prekey: None,
                            identity_key_version: self.server_bundle.identity_key_version,
                            rotation_signature: self.server_bundle.rotation_signature,
                        };

                        let (shared_secret, _x3dh_material) = initiator
                            .agree(&server_bundle_from_hello)
                            .context("X3DH key agreement failed")?;

                        tun_log!("[AndroidTun] X3DH shared secret derived successfully");

                        // Initialize Double Ratchet as Alice (initiator)
                        // In X3DH, the server (Bob) doesn't generate an ephemeral key.
                        // The _server_ephemeral field is empty - init_alice doesn't use this parameter.
                        let ratchet = DoubleRatchet::init_alice(shared_secret, [0u8; 32]);

                        tun_log!("[AndroidTun] Double Ratchet initialized as Alice (initiator)");

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
        let msg_opt = timeout(std::time::Duration::from_secs(30), ws_reader.next())
            .await
            .context("Timeout waiting for VirtualIp")?
            .context("WebSocket closed during VirtualIp wait")?;

        let msg = msg_opt.context("WebSocket error during VirtualIp wait")?;

        match msg {
            Message::Binary(data) => {
                tun_log!("[AndroidTun] Received {} bytes, decrypting VirtualIp", data.len());

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

                tun_log!(
                    "[AndroidTun] VirtualIp received: ipv4={:?}, dns={:?}, mtu={}",
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
        tun_log!("[AndroidTun] === Packet relay loop STARTING ===");

        // Clone for server->android
        let to_swift_sender = self.to_swift_sender.clone();
        let shutdown_tx = self.shutdown_tx.clone();
        let from_swift_receiver = Arc::clone(&self.from_swift_receiver);

        // Wrap ratchet and WebSocket writer in Arc<Mutex> for safe sharing between
        // concurrent tasks. Multiple tasks may need to send (data path + keepalive).
        let ratchet = Arc::new(Mutex::new(ratchet));
        let ws_write = Arc::new(Mutex::new(ws_write));
        let ws_write_for_swift = ws_write.clone();
        let ws_write_for_keepalive = ws_write.clone();

        // DNS interception is handled in the Kotlin read loop — Rust just forwards packets.

        // ANDROID -> SERVER direction
        let swift_to_server = async {
            let mut shutdown_rx = self.shutdown_tx.subscribe();
            let mut packet_count = 0u64;
            let mut batch_count = 0u64;
            let mut pending_packet: Option<Vec<u8>> = None;

            'outer: loop {
                // Acquire the first packet for this batch (either a packet that
                // did not fit in the previous batch or a fresh one from Android).
                let mut batch = Vec::with_capacity(OUTGOING_BATCH_MAX_FRAMES);
                let mut batch_bytes = 0usize;

                let first = match pending_packet.take() {
                    Some(p) => p,
                    None => {
                        tokio::select! {
                            _ = shutdown_rx.recv() => {
                                tun_log!("[AndroidTun] Android->Server relay: shutdown received");
                                break 'outer;
                            }
                            packet = async {
                                let mut r = from_swift_receiver.lock().await;
                                r.recv().await
                            } => {
                                match packet {
                                    Some(p) => p,
                                    None => {
                                        tun_log!("[AndroidTun] Android->Server: channel closed");
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
                            tun_log!("[AndroidTun] Android->Server relay: shutdown received while collecting");
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
                    tun_log!(
                        "[AndroidTun] Android->Server: encrypting batch of {} frames, {} bytes (batch #{}, total packets {})",
                        batch.len(), batch_bytes, batch_count, packet_count
                    );
                }

                // Encrypt while holding the ratchet lock, then release the lock
                // before the async WebSocket send so decryption is not blocked.
                let encrypted = {
                    let mut ratchet_guard = ratchet.lock().await;
                    match Self::encrypt_data_batch(&mut *ratchet_guard, &batch) {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            tun_log_error!("[AndroidTun] Failed to encrypt batch: {}", e);
                            let _ = shutdown_tx.send(());
                            break 'outer;
                        }
                    }
                };

                let mut ws_guard = ws_write_for_swift.lock().await;
                if let Err(e) = ws_guard.send(Message::Binary(encrypted)).await {
                    tun_log_error!("[AndroidTun] WebSocket send failed: {}", e);
                    drop(ws_guard);
                    let _ = shutdown_tx.send(());
                    break 'outer;
                }

                if receiver_closed {
                    tun_log!("[AndroidTun] Android->Server: channel closed after batch (sent {} packets)", packet_count);
                    break 'outer;
                }
            }
        };

        // SERVER -> ANDROID direction
        let server_to_swift = async {
            let mut shutdown_rx = self.shutdown_tx.subscribe();
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tun_log!("[AndroidTun] Server->Android relay: shutdown received");
                        break;
                    }
                    msg = ws_read.next() => {
                        match msg {
                            Some(Ok(Message::Binary(data))) => {
                                tun_log!("[AndroidTun] Server->Android: received {} bytes", data.len());

                                // Deserialize and decrypt while holding the ratchet lock, then
                                // release the lock before the async channel send.
                                let decrypted = match RatchetMessage::from_bytes(&data) {
                                    Ok(ratchet_msg) => {
                                        let mut ratchet_guard = ratchet.lock().await;
                                        match ratchet_guard.decrypt(&ratchet_msg, &[PayloadType::Data as u8]) {
                                            Ok(plaintext) => Some(plaintext),
                                            Err(e) => {
                                                tun_log_error!("[AndroidTun] Failed to decrypt packet: {}", e);
                                                None
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        tun_log_error!("[AndroidTun] Failed to deserialize RatchetMessage: {}", e);
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
                                                        // do not forward to Android.
                                                        match frame.parse_control() {
                                                            Ok(ControlMessage::Pong { timestamp }) => {
                                                                tun_log!("[AndroidTun] Server->Android: received Pong(ts={})", timestamp);
                                                            }
                                                            Ok(other) => {
                                                                tun_log!("[AndroidTun] Server->Android: received control {:?}", other);
                                                            }
                                                            Err(e) => {
                                                                tun_log_error!("[AndroidTun] Failed to parse control frame: {}", e);
                                                            }
                                                        }
                                                    } else {
                                                        tun_log!("[AndroidTun] Server->Android: flow_id={} sending {} bytes to Android", frame.flow_id, frame.payload.len());
                                                        if to_swift_sender.send(frame.payload.to_vec()).await.is_err() {
                                                            tun_log!("[AndroidTun] Server->Android: Android receiver closed");
                                                            break;
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    tun_log_error!("[AndroidTun] Failed to decode MultiplexedFrame: {}", e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            tun_log_error!("[AndroidTun] Failed to unpad packet: {}", e);
                                        }
                                    }
                                }
                            }
                            Some(Ok(Message::Close(_))) | None => {
                                tun_log!("[AndroidTun] Server->Android: connection closed");
                                let _ = shutdown_tx.send(());
                                break;
                            }
                            Some(Err(e)) => {
                                tun_log_error!("[AndroidTun] WebSocket error: {}", e);
                                let _ = shutdown_tx.send(());
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
        };

        // Keepalive task — sends a Ping every 15 seconds to prevent the server's
        // 60-second WebSocket idle timeout and to keep the extension runnable.
        let keepalive = {
            let shutdown_tx = shutdown_tx.clone();
            let ratchet = Arc::clone(&ratchet);
            async move {
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
                                tun_log_error!("[AndroidTun] Keepalive build failed: {}", e);
                                continue;
                            }
                        }
                    };

                    let mut ws_guard = ws_write_for_keepalive.lock().await;
                    if let Err(e) = ws_guard.send(Message::Binary(encrypted)).await {
                        tun_log_error!("[AndroidTun] Keepalive WebSocket send failed: {}", e);
                        drop(ws_guard);
                        let _ = shutdown_tx.send(());
                        break;
                    }
                    tun_log!("[AndroidTun] Keepalive: Ping sent");
                }
            }
        };

        // Run all tasks concurrently
        tokio::select! {
            _ = swift_to_server => {
                tun_log!("[AndroidTun] Android->Server relay ended");
            }
            _ = server_to_swift => {
                tun_log!("[AndroidTun] Server->Android relay ended");
            }
            _ = keepalive => {
                tun_log!("[AndroidTun] Keepalive relay ended");
            }
        }

        tun_log!("[AndroidTun] Packet relay ended");
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

    /// Get bypass networks from config
    pub fn get_bypass_networks(&self) -> &[String] {
        &self.config.bypass_networks
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

    /// Get TLS fingerprint
    pub fn tls_fingerprint(&self) -> TlsFingerprint {
        self.tls_fingerprint
    }

    /// Canonical `ik:1:<base32>` pin of the server this client was
    /// constructed against — read by the JNI wrapper for
    /// `rvpn_tun_get_server_identity()` after `Connected`.
    pub fn server_identity_pin(&self) -> &str {
        &self.server_identity_pin_actual
    }

    /// Send a packet to the server (call this from Android)
    /// Android calls this to send packets to be relayed to the server
    pub async fn send_packet_to_server(&self, packet: Vec<u8>) -> Result<()> {
        self.from_swift_sender
            .send(packet)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send packet: {}", e))
    }

    /// Non-blocking send for FFI hot path (avoids block_on deadlock)
    pub fn try_send_packet(&self, packet: Vec<u8>) -> Result<(), tokio::sync::mpsc::error::TrySendError<Vec<u8>>> {
        self.from_swift_sender.try_send(packet)
    }

    /// Receive a packet from the server (call this from Android)
    /// Android calls this to receive packets that came from the server
    /// Non-blocking - returns None if no packet is available
    pub fn recv_packet_from_server(&self) -> Option<Vec<u8>> {
        let mut rx = self.to_swift_receiver.try_lock().ok()?;
        rx.try_recv().ok()
    }

    /// Start the client (runs connect and relay in background).
    ///
    /// Implements a reconnect loop with exponential backoff. Enabled by the
    /// FFI `rvpnTunStart` entry. Idempotent — repeated calls are no-ops while
    /// the loop is already running (guarded by `is_started`).
    pub fn start(self: &Arc<Self>) {
        if self
            .is_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            tun_log!("[AndroidTun] start() called but reconnect loop already running, ignoring");
            return;
        }

        let client = Arc::clone(self);
        self.runtime.spawn(async move {
            let mut attempts: u32 = 0;
            let mut had_successful_session = false;
            loop {
                if !client.reconnect_enabled.load(Ordering::Relaxed) {
                    tun_log!("[AndroidTun] Reconnection disabled, exiting reconnect loop");
                    break;
                }

                let max_attempts = client.reconnect_max_attempts.load(Ordering::Relaxed);
                if max_attempts > 0 && attempts >= max_attempts {
                    tun_log_error!(
                        "[AndroidTun] Max reconnection attempts ({}) reached",
                        max_attempts
                    );
                    client
                        .notify_state(
                            TunClientState::Error,
                            None,
                            "Max reconnection attempts reached",
                        )
                        .await;
                    break;
                }

                // No delay after a successful session (network transition, e.g. WiFi→5G).
                // Exponential backoff after failures.
                if had_successful_session {
                    had_successful_session = false;
                } else if attempts > 0 {
                    let initial = client.reconnect_initial_delay_ms.load(Ordering::Relaxed);
                    let max_delay = client.reconnect_max_delay_ms.load(Ordering::Relaxed);
                    let delay = std::cmp::min(
                        initial.saturating_mul(2u64.saturating_pow(attempts - 1)),
                        max_delay,
                    );
                    tun_log!("[AndroidTun] Reconnecting in {}ms (attempt {})", delay, attempts + 1);

                    // Chunked sleep so a mid-backoff `set_reconnect_enabled(false)` is
                    // honoured within 100ms instead of blocking for the whole delay.
                    let start = tokio::time::Instant::now();
                    let dur = tokio::time::Duration::from_millis(delay);
                    while tokio::time::Instant::now().duration_since(start) < dur {
                        if !client.reconnect_enabled.load(Ordering::Relaxed) {
                            tun_log!("[AndroidTun] Reconnection disabled during backoff, stopping");
                            return;
                        }
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }

                match client.connect().await {
                    Ok(()) => {
                        tun_log!("[AndroidTun] Connection ended, reconnecting immediately...");
                        attempts = 0;
                        had_successful_session = true;
                    }
                    Err(e) => {
                        tun_log_error!("[AndroidTun] Connection failed (attempt {}): {}", attempts + 1, e);
                        attempts += 1;
                    }
                }

                if !client.reconnect_enabled.load(Ordering::Relaxed) {
                    tun_log!("[AndroidTun] Reconnection disabled after session end, stopping");
                    break;
                }
            }

            // Loop exited — clear is_started so a future start() can proceed.
            client.is_started.store(false, Ordering::SeqCst);
        });
    }

    /// Stop the client (disables reconnection and tears down the current relay).
    pub fn stop(&self) {
        self.reconnect_enabled.store(false, Ordering::Relaxed);
        let _ = self.shutdown_tx.send(());
        // Note: is_started is cleared by the reconnect loop itself when it exits.
    }

    /// Enable / disable the reconnect loop. FFI `rvpnTunStart` calls this with
    /// `true` before spawning `start()`.
    pub fn set_reconnect_enabled(&self, enabled: bool) {
        self.reconnect_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Request a gentle reconnect without disabling the reconnect loop.
    ///
    /// Called from `rvpnNetworkChanged` when the Android NetworkCallback reports
    /// a network transition. Sends `shutdown_tx` — the current `run_packet_relay`
    /// exits, `connect()` returns, and the reconnect loop starts a fresh session
    /// on the new interface.
    ///
    /// 5-second cooldown prevents reconnect storms from rapid NetworkCallback
    /// notifications during handoffs.
    pub fn request_reconnect(&self) {
        let now = std::time::Instant::now();
        let mut last = self.last_reconnect_request.lock().unwrap();
        if now.duration_since(*last) < std::time::Duration::from_secs(5) {
            tun_log!("[AndroidTun] Reconnect requested too soon (cooldown active), ignoring");
            return;
        }
        *last = now;
        drop(last);

        let _ = self.shutdown_tx.send(());
        tun_log!("[AndroidTun] Reconnect requested via gentle shutdown signal");
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
        let (host, port, path) = AndroidTunClient::parse_server_url(
            "wss://test.example.com:443/api/v1/ws"
        ).unwrap();
        assert_eq!(host, "test.example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api/v1/ws");

        let (host, port, path) = AndroidTunClient::parse_server_url(
            "wss://test.example.com:443/api/v1/ws/"
        ).unwrap();
        assert_eq!(host, "test.example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api/v1/ws/");
    }
}