// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of R-VPN.
//
// R-VPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Per-server-connection session for the Android Direct TUN client.
//!
//! `AndroidServerSession` owns every piece of state that belongs to ONE
//! exit-server connection: server endpoint, X3DH bundle, connection state,
//! assigned tunnel parameters (IP/DNS/MTU), reconnect machinery, and the
//! uplink (Kotlin → server) packet channel.
//!
//! `AndroidTunClient` (in `android_tun.rs`) holds the shared plumbing
//! (`AndroidSharedContext`) plus one session per exit server (`"default"`
//! plus one per `TunConfig.extra_servers` entry) and demultiplexes uplink
//! packets across them. This mirrors the iOS/macOS `ServerSession` split —
//! see `server_session.rs` and the "Multi-server Direct TUN routing" section
//! of AGENTS.md for the design contract.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use futures_util::stream::SplitSink;
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio::time::timeout;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tungstenite::handshake::client::generate_key;

use rvpn_core::crypto::ratchet::RatchetMessage;
use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::crypto::{DoubleRatchet, EphemeralKey, IdentityKey, X3DHPublicBundle};
use rvpn_core::protocol::padding::{pad_packet, unpad_packet};
use rvpn_core::protocol::{
    ControlMessage, HandshakeMessage, MultiplexedFrame, PayloadType, VirtualIp,
};

use crate::android_tun::{android_log, TunClientState};

// tun_log!/tun_log_error! come from android_tun.rs via #[macro_use] in lib.rs.

/// WebSocket writer/reader types (rustls backend — BoringSSL's static linking
/// is broken on the Android NDK; see the TLS note in `connect()`).
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

/// Maximum packets stashed per secondary session while it connects (before
/// its VirtualIp). 32 × ~1.5 KB ≈ 48 KB worst case. Oldest packet is dropped
/// past the cap. Mirrors `PENDING_UPLINK_CAP` in server_session.rs (iOS).
const PENDING_UPLINK_CAP: usize = 32;

/// Shared, per-client context handed to every `AndroidServerSession`.
///
/// Holds the pieces that are identical across server connections: the tokio
/// runtime handle (NEVER the `Runtime` itself — it is owned by
/// `android_tun_ffi::TUN_RUNTIME`; see the runtime-ownership section in
/// AGENTS.md), the client identity key for X3DH, the downlink channel to
/// Kotlin, and the state callback. `AndroidTunClient` builds this once and
/// shares it with every session.
pub(crate) struct AndroidSharedContext {
    /// Handle to the tokio runtime that runs session tasks. Only a `Handle`
    /// (never `Arc<Runtime>`) so the last `Arc<AndroidServerSession>` dropped
    /// on a worker thread cannot transitively drop the Runtime and panic in
    /// `BlockingPool::shutdown` (the exact iOS crash of 2026-07-03).
    pub handle: tokio::runtime::Handle,
    /// Client identity key for X3DH.
    pub identity_key: IdentityKey,
    /// Sender for packets to Kotlin (Kotlin receives via recv_packet_from_server)
    pub to_swift_sender: mpsc::Sender<Vec<u8>>,
    /// The primary (default) session's assigned tunnel IPv4 address. Set by
    /// the default session when its VirtualIp arrives. Secondary sessions'
    /// downlink (`run_rx`) rewrites each packet's destination to this address
    /// so the OS network stack — whose tun interface carries only the
    /// primary address — accepts packets that arrived via a secondary exit.
    /// `None` until the default session's first VirtualIp.
    pub primary_tunnel_ip: Arc<std::sync::Mutex<Option<std::net::Ipv4Addr>>>,
}

/// AndroidServerSession - all state and logic for ONE exit-server connection.
///
/// Everything here is per-server: endpoint coordinates, X3DH bundle, the
/// connection state machine, the VirtualIp-assigned tunnel parameters, the
/// reconnect loop, and the uplink packet channel. Shared resources are
/// reached through `shared`.
pub(crate) struct AndroidServerSession {
    /// Shared per-client context (runtime handle, identity key, downlink
    /// plumbing, state callback).
    shared: Arc<AndroidSharedContext>,
    /// Server host (original hostname for TLS SNI and the HTTP Host header)
    server_host: String,
    /// Server IP (pre-resolved to avoid the DNS circular dependency during
    /// reconnect: with the DNS proxy active, resolving the server hostname
    /// would go through our own proxy → dead tunnel → resolution fails
    /// forever. See IosTunClient::new for the full rationale.)
    server_ip: std::net::IpAddr,
    /// Server port
    server_port: u16,
    /// WebSocket path (base path, will append /tun)
    server_path: String,
    /// Connection state
    state: Arc<AtomicI32>,
    /// Assigned tunnel IP (set after VirtualIp received). std::sync::Mutex so
    /// the uplink hot path (`enqueue_uplink`) can read it synchronously.
    tunnel_ip: Arc<std::sync::Mutex<Option<String>>>,
    /// DNS servers from VirtualIp
    dns_servers: Arc<std::sync::Mutex<Vec<std::net::IpAddr>>>,
    /// MTU from VirtualIp
    mtu: Arc<std::sync::Mutex<u16>>,
    /// Shutdown signal
    shutdown_tx: broadcast::Sender<()>,
    /// Server prekey bundle for X3DH
    server_bundle: X3DHPublicBundle,
    /// Canonical `ik:1:<base32>` pin of the server's identity key, computed
    /// at construction from `server_bundle.identity_key`. Kotlin reads this
    /// via the JNI wrapper after the tunnel reaches `Connected` to capture
    /// the TOFU pin on first connect.
    server_identity_pin_actual: String,
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
    /// Receiver for packets from Kotlin (Kotlin sends via send_packet_to_server)
    from_swift_receiver: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    /// Sender for Kotlin to use (Kotlin calls send_packet_to_server with this)
    pub(crate) from_swift_sender: mpsc::Sender<Vec<u8>>,
    /// Whether this is the default (primary) exit session. The default
    /// session publishes its VirtualIp address into
    /// `AndroidSharedContext::primary_tunnel_ip` and needs no downlink
    /// rewrite; secondary sessions stash pre-VirtualIp uplink packets and
    /// rewrite both directions (see `nat_rewrite`).
    is_default: bool,
    /// TLS session resumption store for this exit server. Held per session so
    /// every reconnect offers the cached TLS 1.3 ticket (1-RTT resume, no
    /// certificate flight) instead of a full handshake. Mirrors
    /// `ServerSession::resumption` on iOS/macOS.
    resumption: rvpn_tls::ResumptionStore,
    /// Packets the uplink demux routed to this session before its VirtualIp
    /// arrived (secondary exits start lazily, so the first routed packets
    /// race the connect). They cannot be sent yet — the source address must
    /// be rewritten to this session's tunnel IP, which is unknown until
    /// VirtualIp. Flushed (rewrite + enqueue) by `connect()` right after the
    /// tunnel IP is stored; dropped on session failure/stop. Bounded —
    /// drop-oldest past `PENDING_UPLINK_CAP`.
    pending_uplink: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
}

impl AndroidServerSession {
    /// Create a new session for one exit server.
    ///
    /// All fallible setup (URL parsing, DNS pre-resolution, identity/bundle
    /// loading, TOFU pin enforcement) happens in `AndroidTunClient::new`;
    /// this constructor receives plain values. `chan_cap` is the uplink
    /// channel capacity.
    #[allow(clippy::too_many_arguments)] // Per-server endpoint tuple; mirrors the iOS ServerSession::new shape.
    pub(crate) fn new(
        shared: Arc<AndroidSharedContext>,
        server_host: String,
        server_ip: std::net::IpAddr,
        server_port: u16,
        server_path: String,
        server_bundle: X3DHPublicBundle,
        server_identity_pin_actual: String,
        chan_cap: usize,
        is_default: bool,
    ) -> Self {
        let (from_swift_sender, from_swift_receiver) = mpsc::channel::<Vec<u8>>(chan_cap);
        let (shutdown_tx, _) = broadcast::channel::<()>(1);

        Self {
            shared,
            server_host,
            server_ip,
            server_port,
            server_path,
            state: Arc::new(AtomicI32::new(TunClientState::Init as i32)),
            tunnel_ip: Arc::new(std::sync::Mutex::new(None)),
            dns_servers: Arc::new(std::sync::Mutex::new(Vec::new())),
            mtu: Arc::new(std::sync::Mutex::new(1420)),
            shutdown_tx,
            server_bundle,
            server_identity_pin_actual,
            is_started: AtomicBool::new(false),
            reconnect_enabled: AtomicBool::new(false), // Disabled by default; FFI start enables
            reconnect_max_attempts: AtomicU32::new(0), // 0 = unlimited
            reconnect_initial_delay_ms: AtomicU64::new(1000),
            reconnect_max_delay_ms: AtomicU64::new(5000),
            last_reconnect_request: std::sync::Mutex::new(
                std::time::Instant::now() - std::time::Duration::from_secs(60),
            ),
            from_swift_receiver: Arc::new(Mutex::new(from_swift_receiver)),
            from_swift_sender,
            is_default,
            resumption: rvpn_tls::ResumptionStore::new(),
            pending_uplink: std::sync::Mutex::new(std::collections::VecDeque::new()),
        }
    }

    /// Canonical `ik:1:<base32>` pin of the server this session was
    /// constructed against.
    pub(crate) fn server_identity_pin(&self) -> &str {
        &self.server_identity_pin_actual
    }

    /// Record a state transition. Kotlin learns state by polling
    /// `rvpnTunGetState` (see RvpnTunnelService) — the old C state-callback
    /// path was never wired correctly on the JNI side (Kotlin passed a
    /// `StateCallback` jobject to a native function whose signature expected
    /// a C function pointer, with no JNIEnv/jclass params) and was removed;
    /// it was never invoked in practice.
    async fn notify_state(&self, new_state: TunClientState, ip: Option<&str>, message: &str) {
        if self.is_default {
            tun_log!(
                "[AndroidTun] notify_state: {:?}, ip={:?}, msg={}",
                new_state,
                ip,
                message
            );
        }
        self.state.store(new_state as i32, Ordering::SeqCst);
    }

    /// WebSocket URL for the TUN endpoint. The config path may already append
    /// /tun, so only add it if not present.
    fn tun_url(&self) -> String {
        Self::tun_url_for(&self.server_host, self.server_port, &self.server_path)
    }

    /// Pure helper behind [`tun_url`] — split out for unit testing.
    fn tun_url_for(server_host: &str, server_port: u16, server_path: &str) -> String {
        let tun_path = if server_path.ends_with("/tun") || server_path.ends_with("/tun/") {
            server_path.trim_end_matches('/').to_string()
        } else if server_path.ends_with('/') {
            format!("{}tun", server_path)
        } else {
            format!("{}/tun", server_path)
        };
        format!("wss://{}:{}{}", server_host, server_port, tun_path)
    }

    /// Build the rustls client config for this session's connects.
    ///
    /// The session's [`rvpn_tls::ResumptionStore`] is installed as the rustls
    /// session store, so TLS 1.3 tickets the server issues survive across
    /// reconnects (each `connect()` builds a fresh `ClientConfig`) and the
    /// next handshake offers one as a PSK — 1-RTT resume, no certificate
    /// flight, and a ClientHello that looks like a returning browser.
    fn tls_client_config(&self) -> Arc<rustls::ClientConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        config.resumption =
            rustls::client::Resumption::store(self.resumption.rustls_session_store());
        Arc::new(config)
    }

    /// Connect to the VPN server and perform X3DH handshake
    pub(crate) async fn connect(self: &Arc<Self>) -> Result<()> {
        // Early exit if reconnect was disabled (e.g. stopTunnel() called while
        // we were in backoff)
        if !self.reconnect_enabled.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Connection cancelled by stop"));
        }

        // Set state to Connecting
        self.state
            .store(TunClientState::Connecting as i32, Ordering::SeqCst);
        self.notify_state(TunClientState::Connecting, None, "Connecting to server")
            .await;

        let url = self.tun_url();
        tun_log!("[AndroidTun] Connecting to {}", url);

        // Use rustls with bundled webpki-roots (same approach as iOS).
        // BoringSSL's static linking is broken on Android NDK (X509_free
        // and 150+ symbols left undefined in the .so). rustls works
        // reliably with no native C dependency.
        let tls_config = self.tls_client_config();
        let connector = tokio_tungstenite::Connector::Rustls(tls_config);

        // Connect TCP to the pre-resolved server IP (the URL keeps the
        // original hostname, so TLS SNI and the HTTP Host header are
        // unaffected).
        let tcp_addr = format!("{}:{}", self.server_ip, self.server_port);
        let tcp_stream = timeout(
            std::time::Duration::from_secs(5),
            tokio::net::TcpStream::connect(&tcp_addr),
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
            ),
        )
        .await
        .context("WebSocket handshake timeout (5s)")?
        .context("WebSocket handshake failed")?;

        tun_log!("[AndroidTun] WebSocket connected (TLS verified)");

        // Check again after transport
        if !self.reconnect_enabled.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!(
                "Connection cancelled by stop after WS handshake"
            ));
        }

        // Split into reader/writer
        let (mut write, mut read) = ws_stream.split();

        // Perform X3DH handshake
        let mut ratchet = self
            .perform_handshake(&mut read, &mut write)
            .await
            .context("X3DH handshake failed")?;

        tun_log!("[AndroidTun] X3DH handshake complete");

        // Check again after X3DH
        if !self.reconnect_enabled.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Connection cancelled by stop after X3DH"));
        }

        // Receive VirtualIp message
        let virtual_ip = self
            .receive_virtual_ip(&mut read, &mut ratchet)
            .await
            .context("Failed to receive VirtualIp")?;

        // Extract IP address
        let ipv4_str = virtual_ip
            .ipv4
            .map(|v4| v4.to_string())
            .context("No IPv4 address in VirtualIp")?;

        tun_log!("[AndroidTun] Assigned IP: {}", ipv4_str);

        // Store tunnel IP, DNS servers, and MTU
        {
            let mut tunnel_ip = self.tunnel_ip.lock().unwrap();
            *tunnel_ip = Some(ipv4_str.clone());
        }
        {
            let mut dns = self.dns_servers.lock().unwrap();
            *dns = virtual_ip.dns_servers.clone();
        }
        {
            let mut mtu = self.mtu.lock().unwrap();
            *mtu = virtual_ip.mtu;
        }

        // The default session's tunnel IP is the address the OS tun interface
        // carries — publish it so secondary sessions can rewrite their
        // downlink packets back to it.
        if self.is_default {
            if let Ok(v4) = ipv4_str.parse::<std::net::Ipv4Addr>() {
                *self.shared.primary_tunnel_ip.lock().unwrap() = Some(v4);
            }
        }

        // Secondary exits start lazily, so the first routed packets may have
        // been stashed while this session connected. Now that the tunnel IP
        // is known, rewrite + enqueue them (see enqueue_uplink).
        self.flush_pending();

        // Set state to IpAssigned and notify Android
        self.notify_state(TunClientState::IpAssigned, Some(&ipv4_str), "IP assigned")
            .await;

        // Set state to Connected
        self.notify_state(TunClientState::Connected, Some(&ipv4_str), "Connected")
            .await;

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
            identity_key: self.shared.identity_key.clone(),
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

        let hello_bytes =
            serde_json::to_vec(&hello).context("Failed to serialize Hello message")?;
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
                    serde_json::from_slice(&data).context("Failed to parse ServerHello message")?;

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
                        let server_identity_key: [u8; 32] =
                            server_identity_key.as_slice().try_into().map_err(|_| {
                                anyhow::anyhow!("Server identity key has invalid length")
                            })?;
                        let server_signed_prekey: [u8; 32] =
                            server_signed_prekey.as_slice().try_into().map_err(|_| {
                                anyhow::anyhow!("Server signed prekey has invalid length")
                            })?;
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
                tun_log!(
                    "[AndroidTun] Received {} bytes, decrypting VirtualIp",
                    data.len()
                );

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
                let virtual_ip: VirtualIp =
                    serde_json::from_slice(&unpadded).context("Failed to parse VirtualIp JSON")?;

                tun_log!(
                    "[AndroidTun] VirtualIp received: ipv4={:?}, dns={:?}, mtu={}",
                    virtual_ip.ipv4,
                    virtual_ip.dns_servers,
                    virtual_ip.mtu
                );

                Ok(virtual_ip)
            }
            _ => Err(anyhow::anyhow!("Expected binary message for VirtualIp")),
        }
    }

    /// Main packet relay loop.
    ///
    /// The three arms (`run_tx`, `run_rx`, `run_keepalive`) are
    /// `tokio::spawn`ed as independent tasks, mirroring the iOS
    /// `ServerSession::run_packet_relay` structure: a stalled arm (e.g. the
    /// Kotlin-facing channel send blocking on backpressure) can no longer
    /// starve the ws_write / keepalive path — each task has independent poll
    /// budget.
    async fn run_packet_relay(
        self: &Arc<Self>,
        ws_write: WsSink,
        ws_read: WsStream,
        ratchet: DoubleRatchet,
    ) {
        tun_log!("[AndroidTun] === Packet relay loop STARTING ===");

        // Wrap ratchet and WebSocket writer in Arc<Mutex> for safe sharing between
        // the three spawned tasks. All three may need the writer (data path,
        // keepalive); TX and keepalive both hold the ratchet.
        //
        // `send_lock` serializes encrypt→enqueue across the two encrypting
        // tasks (TX and keepalive): the Double Ratchet assigns message
        // numbers at encrypt time, so wire order must match encrypt order.
        // Without it, a keepalive encrypted after a data batch can overtake
        // it into the writer, and the server's ratchet drops the reordered
        // frame ("Message too old").
        let ratchet = Arc::new(Mutex::new(ratchet));
        let ws_write = Arc::new(Mutex::new(ws_write));
        let send_lock = Arc::new(Mutex::new(()));

        // DNS interception is handled in the Kotlin read loop — Rust just forwards packets.

        // --- Android → Server (TX) task ---
        let tx_task = {
            let this = Arc::clone(self);
            let ratchet = ratchet.clone();
            let ws_write = ws_write.clone();
            let send_lock = send_lock.clone();
            tokio::spawn(async move {
                Self::run_tx(this, ratchet, ws_write, send_lock).await;
            })
        };

        // --- Server → Android (RX) task ---
        let rx_task = {
            let this = Arc::clone(self);
            let ratchet = ratchet.clone();
            tokio::spawn(async move {
                Self::run_rx(this, ws_read, ratchet).await;
            })
        };

        // --- keepalive task ---
        let ka_task = {
            let this = Arc::clone(self);
            let ratchet = ratchet.clone();
            let ws_write = ws_write.clone();
            let send_lock = send_lock.clone();
            tokio::spawn(async move {
                Self::run_keepalive(this, ratchet, ws_write, send_lock).await;
            })
        };

        // Wait for the first task to finish. That task should have already
        // sent a shutdown signal on its way out (all error paths do); we send
        // one here defensively so the other two arms unblock even if the first
        // exited by clean channel close.
        tokio::select! {
            _ = tx_task => {
                tun_log!("[AndroidTun] Android->Server relay ended");
            }
            _ = rx_task => {
                tun_log!("[AndroidTun] Server->Android relay ended");
            }
            _ = ka_task => {
                tun_log!("[AndroidTun] Keepalive relay ended");
            }
        }
        let _ = self.shutdown_tx.send(());

        tun_log!("[AndroidTun] Packet relay ended");
        self.notify_state(TunClientState::Error, None, "Connection closed")
            .await;
    }

    /// Android → Server (TX) task body. Batches TUN packets into a single
    /// encrypted WebSocket message (see `encrypt_data_batch`).
    async fn run_tx(
        this: Arc<Self>,
        ratchet: Arc<Mutex<DoubleRatchet>>,
        ws_write: Arc<Mutex<WsSink>>,
        send_lock: Arc<Mutex<()>>,
    ) {
        let from_swift_receiver = Arc::clone(&this.from_swift_receiver);
        let shutdown_tx = this.shutdown_tx.clone();

        let mut shutdown_rx = shutdown_tx.subscribe();
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
            while batch.len() < OUTGOING_BATCH_MAX_FRAMES && batch_bytes < OUTGOING_BATCH_MAX_BYTES
            {
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

            // Serialize encrypt→enqueue against the keepalive arm: the
            // ratchet assigns message numbers at encrypt time, so the frame
            // must reach the writer before any later-encrypted frame.
            // The ratchet lock is released BEFORE the ws send await so a
            // blocked writer never stalls RX decrypts.
            let _send_guard = send_lock.lock().await;

            // Encrypt while holding the ratchet lock, then release the lock
            // before the async WebSocket send so decryption is not blocked.
            let encrypted = {
                let mut ratchet_guard = ratchet.lock().await;
                match Self::encrypt_data_batch(&mut ratchet_guard, &batch) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        tun_log_error!("[AndroidTun] Failed to encrypt batch: {}", e);
                        let _ = shutdown_tx.send(());
                        break 'outer;
                    }
                }
            };

            let mut ws_guard = ws_write.lock().await;
            if let Err(e) = ws_guard.send(Message::Binary(encrypted)).await {
                tun_log_error!("[AndroidTun] WebSocket send failed: {}", e);
                drop(ws_guard);
                let _ = shutdown_tx.send(());
                break 'outer;
            }
            drop(ws_guard);
            drop(_send_guard);

            if receiver_closed {
                tun_log!(
                    "[AndroidTun] Android->Server: channel closed after batch (sent {} packets)",
                    packet_count
                );
                break 'outer;
            }
        }
    }

    /// Server → Android (RX) task body. Decrypts each WebSocket message and
    /// forwards every data frame to Kotlin. Secondary sessions rewrite each
    /// packet's destination to the primary tunnel IP first (the OS tun
    /// interface carries only that address).
    async fn run_rx(this: Arc<Self>, mut ws_read: WsStream, ratchet: Arc<Mutex<DoubleRatchet>>) {
        let to_swift_sender = this.shared.to_swift_sender.clone();
        let shutdown_tx = this.shutdown_tx.clone();

        let mut shutdown_rx = shutdown_tx.subscribe();
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
                                        // Parse ALL frames in the message: the server
                                        // batches multiple downlink packets into one
                                        // padded+encrypted message (padding amortises
                                        // over the batch instead of inflating every
                                        // packet ~46%).
                                        let (frames, consumed) =
                                            rvpn_core::protocol::multiplex::parse_frames(&unpadded);
                                        if consumed < unpadded.len() {
                                            tun_log_error!(
                                                "[AndroidTun] Partially decoded frames ({} of {} bytes)",
                                                consumed, unpadded.len()
                                            );
                                        }
                                        let mut send_failed = false;
                                        for frame in frames {
                                            if frame.flow_id == 0 {
                                                // Control message (e.g., Pong). Parse and
                                                // handle; do not forward to Android.
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
                                                let mut packet = frame.payload.to_vec();
                                                if !this.is_default {
                                                    // Secondary exit: the OS tun
                                                    // interface carries only the primary
                                                    // (default) session's address, so
                                                    // rewrite dst session-IP → primary.
                                                    let primary = *this.shared.primary_tunnel_ip.lock().unwrap();
                                                    match primary {
                                                        Some(primary) => {
                                                            crate::nat_rewrite::rewrite_dst_ip(&mut packet, primary);
                                                        }
                                                        None => {
                                                            // Startup race: a secondary
                                                            // downlink packet arrived before
                                                            // the primary session's
                                                            // VirtualIp. Drop it.
                                                            tun_log!("[AndroidTun] Downlink packet on secondary exit dropped: primary tunnel IP not yet assigned");
                                                            continue;
                                                        }
                                                    }
                                                }
                                                tun_log!("[AndroidTun] Server->Android: flow_id={} sending {} bytes to Android", frame.flow_id, packet.len());
                                                if to_swift_sender.send(packet).await.is_err() {
                                                    tun_log!("[AndroidTun] Server->Android: Android receiver closed");
                                                    send_failed = true;
                                                    break;
                                                }
                                            }
                                        }
                                        if send_failed {
                                            break;
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
    }

    /// Keepalive task body. Sends a Ping every 15 seconds to prevent the
    /// server's 60-second WebSocket idle timeout and to keep the tunnel
    /// runnable.
    async fn run_keepalive(
        this: Arc<Self>,
        ratchet: Arc<Mutex<DoubleRatchet>>,
        ws_write: Arc<Mutex<WsSink>>,
        send_lock: Arc<Mutex<()>>,
    ) {
        let shutdown_tx = this.shutdown_tx.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate first tick.
        interval.tick().await;
        loop {
            // Exit when this connection ends via another arm; otherwise the
            // keepalive outlives its connection as a zombie holding Arc<Self>
            // and can fire shutdown into the live successor connection.
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tun_log!("[AndroidTun] Keepalive: shutdown received, exiting");
                    break;
                }
                _ = interval.tick() => {}
            }

            // Serialize encrypt→enqueue against run_tx: a keepalive encrypted
            // after a data batch must not overtake it on the wire, or the
            // server's ratchet drops a frame ("Message too old").
            let _send_guard = send_lock.lock().await;

            let encrypted = {
                let mut ratchet_guard = ratchet.lock().await;
                match Self::build_keepalive_packet(&mut ratchet_guard) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        tun_log_error!("[AndroidTun] Keepalive build failed: {}", e);
                        continue;
                    }
                }
            };

            let mut ws_guard = ws_write.lock().await;
            if let Err(e) = ws_guard.send(Message::Binary(encrypted)).await {
                tun_log_error!("[AndroidTun] Keepalive WebSocket send failed: {}", e);
                drop(ws_guard);
                let _ = shutdown_tx.send(());
                break;
            }
            tun_log!("[AndroidTun] Keepalive: Ping sent");
        }
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
        let padded =
            pad_packet(&plaintext).map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;

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
        let frame =
            MultiplexedFrame::new_control(&ping).context("Failed to create keepalive frame")?;
        let frame_bytes = frame.encode().context("Failed to encode keepalive frame")?;
        let padded =
            pad_packet(&frame_bytes).map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;
        let encrypted = ratchet
            .encrypt(&padded, &[PayloadType::Data as u8])
            .context("Failed to encrypt keepalive")?;
        encrypted
            .to_bytes()
            .context("Failed to serialize keepalive RatchetMessage")
    }

    /// Get the assigned tunnel IP
    pub(crate) fn get_tunnel_ip(&self) -> Option<String> {
        self.tunnel_ip.lock().unwrap().clone()
    }

    /// Get the DNS servers from VirtualIp
    #[allow(dead_code)] // Retained for API parity with the default session's FFI getters.
    pub(crate) fn get_dns_servers(&self) -> Vec<std::net::IpAddr> {
        self.dns_servers.lock().unwrap().clone()
    }

    /// Get the MTU from VirtualIp
    pub(crate) fn get_mtu(&self) -> u16 {
        *self.mtu.lock().unwrap()
    }

    /// Get current state
    pub(crate) fn get_state(&self) -> TunClientState {
        TunClientState::from(self.state.load(Ordering::SeqCst))
    }

    /// Get server bundle reference (used by the DNS proxy's DoH client pool)
    #[allow(dead_code)] // Used by AndroidTunClient::extra_session_dns_info (dns feature)
    pub(crate) fn server_bundle(&self) -> &X3DHPublicBundle {
        &self.server_bundle
    }

    /// Get server host
    pub(crate) fn server_host(&self) -> &str {
        &self.server_host
    }

    /// Get server port
    pub(crate) fn server_port(&self) -> u16 {
        self.server_port
    }

    /// Get server path
    pub(crate) fn server_path(&self) -> &str {
        &self.server_path
    }

    /// Get pre-resolved server IP address
    #[allow(dead_code)] // Used for diagnostics parity with iOS; the connect path reads the field directly.
    pub(crate) fn server_ip(&self) -> std::net::IpAddr {
        self.server_ip
    }

    /// Send a packet to the server (call this from Kotlin)
    /// Kotlin calls this to send packets to be relayed to the server
    pub(crate) async fn send_packet_to_server(&self, packet: Vec<u8>) -> Result<()> {
        self.from_swift_sender
            .send(packet)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send packet: {}", e))
    }

    /// Non-blocking send for FFI hot path (avoids block_on deadlock)
    /// Returns TrySendError if the channel is full or disconnected
    pub(crate) fn try_send_packet(
        &self,
        packet: Vec<u8>,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<Vec<u8>>> {
        self.from_swift_sender.try_send(packet)
    }

    /// Enqueue an uplink packet that the demux routed to this (secondary)
    /// session.
    ///
    /// The source address must be rewritten to this session's tunnel IP so
    /// the exit server writes a packet its own TUN stack owns; that address
    /// is only known after VirtualIp. Before then, packets are stashed in
    /// `pending_uplink` (bounded, drop-oldest) and flushed by `connect()`.
    /// Packets are NEVER rerouted to the default session — a routed flow
    /// silently falling back to another exit would defeat the routing rules.
    pub(crate) fn enqueue_uplink(
        &self,
        mut packet: Vec<u8>,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<Vec<u8>>> {
        let mut pending = self.pending_uplink.lock().unwrap();
        let ip = self
            .tunnel_ip
            .lock()
            .unwrap()
            .as_deref()
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok());
        match ip {
            Some(ip) => {
                drop(pending);
                if !crate::nat_rewrite::rewrite_src_ip(&mut packet, ip) {
                    // choose_exit_name only routes parseable IPv4 packets, so
                    // this means a malformed header (bad IHL). Drop — sending
                    // it unrewritten would break the exit's NAT.
                    tun_log!("[AndroidTun] Uplink packet for secondary exit has unusable IPv4 header, dropped");
                    return Ok(());
                }
                self.from_swift_sender.try_send(packet)
            }
            None => {
                if pending.len() >= PENDING_UPLINK_CAP {
                    pending.pop_front();
                    tun_log!(
                        "[AndroidTun] Pending uplink queue full ({}), dropped oldest packet",
                        PENDING_UPLINK_CAP
                    );
                }
                pending.push_back(packet);
                Ok(())
            }
        }
    }

    /// Rewrite + enqueue every packet stashed before this session's VirtualIp
    /// arrived. Called from `connect()` right after the tunnel IP is stored,
    /// so flushed packets precede anything the demux enqueues afterwards.
    /// No-op when the queue is empty (always the case for the default
    /// session, which never stashes).
    fn flush_pending(&self) {
        let ip = match self
            .get_tunnel_ip()
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
        {
            Some(ip) => ip,
            None => return,
        };
        let mut pending = self.pending_uplink.lock().unwrap();
        if pending.is_empty() {
            return;
        }
        let n = pending.len();
        while let Some(mut pkt) = pending.pop_front() {
            if crate::nat_rewrite::rewrite_src_ip(&mut pkt, ip)
                && self.from_swift_sender.try_send(pkt).is_err()
            {
                tun_log!("[AndroidTun] Pending flush: uplink channel full, packet dropped");
            }
        }
        tun_log!(
            "[AndroidTun] Flushed {} pending uplink packets after VirtualIp",
            n
        );
    }

    /// Drop any stashed uplink packets, e.g. when the session's reconnect
    /// attempts are exhausted or it is stopped. Logged loudly: these were
    /// routed packets with nowhere to go.
    fn drop_pending(&self, reason: &str) {
        let mut pending = self.pending_uplink.lock().unwrap();
        if !pending.is_empty() {
            tun_log_error!(
                "[AndroidTun] Dropping {} pending uplink packets ({})",
                pending.len(),
                reason
            );
            pending.clear();
        }
    }

    /// Whether the start/reconnect loop is running.
    pub(crate) fn is_started(&self) -> bool {
        self.is_started.load(Ordering::SeqCst)
    }

    /// Start the session (runs connect and relay in background).
    ///
    /// Implements a reconnect loop with exponential backoff. Enabled by
    /// `set_reconnect_enabled(true)`. Idempotent — repeated calls are no-ops
    /// while the loop is already running (guarded by `is_started`). Each
    /// session's backoff/reconnect lifecycle is fully independent — a
    /// secondary exit flapping never tears down the default.
    pub(crate) fn start(self: &Arc<Self>) {
        if self
            .is_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            tun_log!("[AndroidTun] start() called but reconnect loop already running, ignoring");
            return;
        }

        let client = Arc::clone(self);
        self.shared.handle.spawn(async move {
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
                    // Routed packets stashed for this session have no exit
                    // left — drop them rather than stalling flows forever.
                    client.drop_pending("max reconnection attempts reached");
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
                    tun_log!(
                        "[AndroidTun] Reconnecting in {}ms (attempt {})",
                        delay,
                        attempts + 1
                    );

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
                        tun_log_error!(
                            "[AndroidTun] Connection failed (attempt {}): {}",
                            attempts + 1,
                            e
                        );
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

    /// Stop the session (disables reconnection and tears down the current relay).
    pub(crate) fn stop(&self) {
        self.reconnect_enabled.store(false, Ordering::Relaxed);
        let _ = self.shutdown_tx.send(());
        self.drop_pending("session stopped");
        // Note: is_started is cleared by the reconnect loop itself when it exits.
    }

    /// Enable / disable the reconnect loop. FFI `rvpnTunStart` calls this with
    /// `true` (fanned out to all sessions) before spawning `start()`.
    pub(crate) fn set_reconnect_enabled(&self, enabled: bool) {
        self.reconnect_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Check if reconnection is enabled
    pub(crate) fn is_reconnect_enabled(&self) -> bool {
        self.reconnect_enabled.load(Ordering::Relaxed)
    }

    /// Set maximum reconnection attempts (0 = unlimited)
    pub(crate) fn set_reconnect_max_attempts(&self, attempts: u32) {
        self.reconnect_max_attempts
            .store(attempts, Ordering::Relaxed);
    }

    /// Set initial reconnection delay (ms)
    pub(crate) fn set_reconnect_initial_delay_ms(&self, delay_ms: u64) {
        self.reconnect_initial_delay_ms
            .store(delay_ms, Ordering::Relaxed);
    }

    /// Set maximum reconnection delay (ms)
    pub(crate) fn set_reconnect_max_delay_ms(&self, delay_ms: u64) {
        self.reconnect_max_delay_ms
            .store(delay_ms, Ordering::Relaxed);
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
    pub(crate) fn request_reconnect(&self) {
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

    /// The TUN endpoint URL must gain a /tun suffix exactly once, however
    /// the profile's path is written (Kotlin profiles sometimes already
    /// include it).
    #[test]
    fn test_tun_url_suffix_handling() {
        assert_eq!(
            AndroidServerSession::tun_url_for("s.example.com", 443, "/api/v1/ws"),
            "wss://s.example.com:443/api/v1/ws/tun"
        );
        assert_eq!(
            AndroidServerSession::tun_url_for("s.example.com", 443, "/api/v1/ws/"),
            "wss://s.example.com:443/api/v1/ws/tun"
        );
        assert_eq!(
            AndroidServerSession::tun_url_for("s.example.com", 443, "/api/v1/ws/tun"),
            "wss://s.example.com:443/api/v1/ws/tun"
        );
        assert_eq!(
            AndroidServerSession::tun_url_for("s.example.com", 443, "/api/v1/ws/tun/"),
            "wss://s.example.com:443/api/v1/ws/tun"
        );
    }

    /// Build a non-default `AndroidServerSession` over a throwaway runtime for
    /// pending-queue tests. The runtime is only needed for the `Handle` in
    /// `AndroidSharedContext`; nothing is spawned on it.
    fn test_session() -> (Arc<AndroidServerSession>, tokio::runtime::Runtime) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (to_swift_sender, _to_swift_rx) = mpsc::channel(16);
        let shared = Arc::new(AndroidSharedContext {
            handle: rt.handle().clone(),
            identity_key: IdentityKey::generate(),
            to_swift_sender,
            primary_tunnel_ip: Arc::new(std::sync::Mutex::new(None)),
        });
        let bundle = X3DHPublicBundle {
            identity_key: [0u8; 32],
            identity_x25519_key: [0u8; 32],
            signed_prekey: [0u8; 32],
            prekey_signature: [0u8; 64],
            one_time_prekey: None,
            identity_key_version: 1,
            rotation_signature: None,
        };
        let session = Arc::new(AndroidServerSession::new(
            shared,
            "127.0.0.1".to_string(),
            "127.0.0.1".parse().unwrap(),
            443,
            "/connect".to_string(),
            bundle,
            "ik:1:test".to_string(),
            64,    // chan_cap
            false, // is_default
        ));
        (session, rt)
    }

    /// Minimal IPv4 packet with the given src/dst and a marker byte at the
    /// end so queue order can be observed.
    fn v4_packet(src: std::net::Ipv4Addr, dst: std::net::Ipv4Addr, marker: u8) -> Vec<u8> {
        let mut p = vec![0u8; 21];
        p[0] = 0x45;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20] = marker;
        p
    }

    const PRIMARY: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 200, 0, 2);
    const SESSION_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 200, 0, 7);

    #[test]
    fn enqueue_uplink_stashes_until_virtual_ip_then_flushes() {
        let (session, _rt) = test_session();
        let dst: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();

        // Pre-VirtualIp: packets stash in the pending queue, nothing reaches
        // the uplink channel.
        session.enqueue_uplink(v4_packet(PRIMARY, dst, 1)).unwrap();
        session.enqueue_uplink(v4_packet(PRIMARY, dst, 2)).unwrap();
        assert_eq!(session.pending_uplink.lock().unwrap().len(), 2);
        {
            let mut rx = session.from_swift_receiver.blocking_lock();
            assert!(
                rx.try_recv().is_err(),
                "channel must stay empty pre-VirtualIp"
            );
        }

        // VirtualIp arrives → flush rewrites src and enqueues in order.
        *session.tunnel_ip.lock().unwrap() = Some(SESSION_IP.to_string());
        session.flush_pending();
        assert!(session.pending_uplink.lock().unwrap().is_empty());
        let mut rx = session.from_swift_receiver.blocking_lock();
        for marker in [1u8, 2u8] {
            let pkt = rx.try_recv().expect("flushed packet missing");
            assert_eq!(&pkt[12..16], &SESSION_IP.octets(), "src must be rewritten");
            assert_eq!(&pkt[16..20], &dst.octets(), "dst untouched");
            assert_eq!(pkt[20], marker, "flush must preserve order");
        }
    }

    #[test]
    fn enqueue_uplink_rewrites_immediately_once_ip_known() {
        let (session, _rt) = test_session();
        *session.tunnel_ip.lock().unwrap() = Some(SESSION_IP.to_string());
        let dst: std::net::Ipv4Addr = "1.1.1.1".parse().unwrap();
        session.enqueue_uplink(v4_packet(PRIMARY, dst, 9)).unwrap();
        assert!(session.pending_uplink.lock().unwrap().is_empty());
        let mut rx = session.from_swift_receiver.blocking_lock();
        let pkt = rx
            .try_recv()
            .expect("packet should go straight to the channel");
        assert_eq!(&pkt[12..16], &SESSION_IP.octets());
    }

    #[test]
    fn enqueue_uplink_cap_drops_oldest() {
        let (session, _rt) = test_session();
        let dst: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();
        for i in 0..(PENDING_UPLINK_CAP + 8) {
            session
                .enqueue_uplink(v4_packet(PRIMARY, dst, i as u8))
                .unwrap();
        }
        let pending = session.pending_uplink.lock().unwrap();
        assert_eq!(pending.len(), PENDING_UPLINK_CAP);
        assert_eq!(
            pending.front().unwrap()[20],
            8,
            "the 8 oldest packets must have been dropped"
        );
    }

    #[test]
    fn drop_pending_clears_queue() {
        let (session, _rt) = test_session();
        let dst: std::net::Ipv4Addr = "8.8.8.8".parse().unwrap();
        session.enqueue_uplink(v4_packet(PRIMARY, dst, 1)).unwrap();
        assert_eq!(session.pending_uplink.lock().unwrap().len(), 1);
        session.drop_pending("test");
        assert!(session.pending_uplink.lock().unwrap().is_empty());
    }

    /// The session's TLS config must carry its per-exit resumption store so
    /// reconnects (fresh `ClientConfig` each time) can still offer the cached
    /// TLS 1.3 ticket as a PSK. rustls 0.22 exposes no accessor for the
    /// installed store, so assert on its `Debug` (our store formats as
    /// `ResumptionStore { .. }`; the default `ClientSessionMemoryCache` and
    /// `NoClientSessionStorage` format differently).
    #[test]
    fn tls_client_config_attaches_resumption_store() {
        let (session, _rt) = test_session();
        let config = session.tls_client_config();
        let debug = format!("{:?}", config.resumption);
        assert!(
            debug.contains("ResumptionStore"),
            "session resumption store must be attached to the rustls config, got: {}",
            debug
        );
    }
}
