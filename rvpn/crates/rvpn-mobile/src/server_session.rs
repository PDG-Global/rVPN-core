// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of R-VPN.
//
// R-VPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Per-server-connection session for the iOS/macOS Direct TUN client.
//!
//! `ServerSession` owns every piece of state that belongs to ONE exit-server
//! connection: server endpoint, X3DH bundle, connection state, assigned
//! tunnel parameters (IP/gateway/DNS/MTU), reconnect machinery, preconnect
//! warmer, and the uplink (Swift → server) packet channel.
//!
//! `IosTunClient` (in `ios_tun.rs`) holds the shared plumbing
//! (`SharedContext`) plus one `default_session`. This split is a pure
//! refactor so a later change can run N sessions (one per exit server) for
//! multi-server routing by constructing additional sessions from the same
//! `Arc<SharedContext>`.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use bytes::BytesMut;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

use crate::ws::{FrameType, MinimalWebSocket, MinimalWsReader, MinimalWsWriter};

use ed25519_dalek::Verifier;
use rvpn_core::crypto::ratchet::{RatchetMessage, RatchetMessageRef};
use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::crypto::{DoubleRatchet, EphemeralKey, IdentityKey, X3DHPublicBundle};
use rvpn_core::protocol::padding::{pad_packet, unpad_packet, unpad_packet_slice};
use rvpn_core::protocol::{
    ControlMessage, HandshakeMessage, MultiplexedFrame, PayloadType, VirtualIp,
};

use crate::ios_tun::{
    all_zones_pressure_relief, headroom_bytes_now, rss_bytes_now, StateCallback, TunClientState,
    VecPool,
};
#[cfg(feature = "diagnostics")]
use crate::ios_tun::{
    all_zones_size_in_use, get_rss_bytes, jetsam_headroom_bytes, mi_commit_after_collect,
    mi_committed_bytes, mi_peak_commit_bytes, vm_internal_compressed,
};

/// WebSocket writer type.
///
/// iOS uses the rustls backend (`rvpn_tls::RustlsTlsStream`) — native-tls
/// (Security.framework) cannot negotiate TLS 1.3 on iOS, and the protocol
/// requires TLS 1.3. macOS (same file, `macos-direct-tun` feature) keeps
/// the boring backend for Chrome ClientHello fingerprint mimicry.
#[cfg(feature = "ios-direct-tun")]
type WsReader = MinimalWsReader<rvpn_tls::RustlsTlsStream>;
#[cfg(feature = "ios-direct-tun")]
type WsWriter = MinimalWsWriter<rvpn_tls::RustlsTlsStream>;
#[cfg(feature = "ios-direct-tun")]
type TunnelWs = rvpn_tls::RustlsTlsStream;
#[cfg(not(feature = "ios-direct-tun"))]
type WsReader = MinimalWsReader<rvpn_tls::ChromeTlsStream>;
#[cfg(not(feature = "ios-direct-tun"))]
type WsWriter = MinimalWsWriter<rvpn_tls::ChromeTlsStream>;
#[cfg(not(feature = "ios-direct-tun"))]
type TunnelWs = rvpn_tls::ChromeTlsStream;

/// Maximum age of a preconnected transport before connect() discards it.
/// Must stay under the server's handshake-wait timeout (15 s) so a warm
/// connection is never consumed after the server killed it; 4 s also keeps
/// it safe against older servers that still use the original 5 s timeout.
const PRECONNECT_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(4);

/// DIAGNOSTIC: when true, the inbound (server→client) relay decrypts each
/// frame but discards it instead of forwarding to Swift. This silences the
/// Swift/NE write path so we can tell whether the per-frame memory leak is in
/// BoringSSL (read path) or downstream in Swift/NE. Set false for normal use.
const BISECT_DROP_INBOUND: bool = false;

/// Outgoing packet batching limits.
///
/// Multiple TUN packets are coalesced into a single WebSocket/Ratchet message
/// to reduce per-packet overhead. The batch is capped well below the 16 KB
/// maximum padded size to leave room for frame headers and padding length.
const OUTGOING_BATCH_MAX_FRAMES: usize = 16;
const OUTGOING_BATCH_MAX_BYTES: usize = 14 * 1024;
const OUTGOING_BATCH_TIMEOUT_MS: u64 = 5;

/// Maximum packets stashed per secondary session while it connects (before
/// its VirtualIp). 32 × ~1.5 KB ≈ 48 KB worst case — bounded memory under
/// the iOS 50 MB NE limit. Oldest packet is dropped past the cap.
const PENDING_UPLINK_CAP: usize = 32;

/// Pre-allocated buffers for the encrypt path to avoid per-batch allocations.
/// Under YouTube traffic (~416 batches/sec), allocating and dropping 14KB buffers
/// every 5ms causes massive heap fragmentation and RSS growth.
struct EncryptBuffers {
    plaintext: BytesMut,
    padded: Vec<u8>,
    ciphertext: Vec<u8>,
    serialized: Vec<u8>,
}

impl EncryptBuffers {
    fn new() -> Self {
        Self {
            plaintext: BytesMut::with_capacity(OUTGOING_BATCH_MAX_BYTES),
            padded: Vec::with_capacity(OUTGOING_BATCH_MAX_BYTES + 2),
            ciphertext: Vec::with_capacity(OUTGOING_BATCH_MAX_BYTES + 128),
            serialized: Vec::with_capacity(OUTGOING_BATCH_MAX_BYTES + 256),
        }
    }

    fn clear(&mut self) {
        self.plaintext.clear();
        self.padded.clear();
        self.ciphertext.clear();
        self.serialized.clear();
    }
}

/// Pre-allocated buffers for the decrypt path.
///
/// Mirrors `EncryptBuffers` for the server→swift direction.  The `plaintext`
/// buffer is passed to `DoubleRatchet::decrypt_to_ref` so its allocation is
/// reused across messages instead of creating a new `Vec` per frame.
///
/// The `batch_buf` accumulates multiple decoded packets from a single
/// WebSocket frame into one `Bytes` allocation (u16-LE length-prefixed
/// format), reducing per-packet heap churn from ~1000/s to ~60/s.
struct DecryptBuffers {
    plaintext: Vec<u8>,
    batch_buf: BytesMut,
}

impl DecryptBuffers {
    fn new() -> Self {
        Self {
            plaintext: Vec::with_capacity(2048),
            batch_buf: BytesMut::with_capacity(OUTGOING_BATCH_MAX_BYTES),
        }
    }
}

/// Shared, per-client context handed to every `ServerSession`.
///
/// Holds the pieces that are identical across server connections: the tokio
/// runtime handle (NEVER the `Runtime` itself — it is owned by
/// `ios_tun_ffi::TUN_RUNTIME`; see the runtime-ownership section in
/// AGENTS.md), the client identity key for X3DH, the downlink plumbing to
/// Swift (packet channel + wakeup notification), the uplink buffer pool, and
/// the Swift state callback. `IosTunClient` builds this once and shares it
/// with every session so a later multi-server change can spawn N sessions
/// from the same context.
pub(crate) struct SharedContext {
    /// Handle to the tokio runtime that runs session tasks. Only a `Handle`
    /// (never `Arc<Runtime>`) so the last `Arc<ServerSession>` dropped on a
    /// worker thread cannot transitively drop the Runtime and panic in
    /// `BlockingPool::shutdown`.
    pub handle: tokio::runtime::Handle,
    /// Client identity key for X3DH.
    pub identity_key: IdentityKey,
    /// Sender for packets to Swift (Swift receives via recv_packet_from_server)
    pub to_swift_sender: mpsc::Sender<bytes::Bytes>,
    /// Signalled whenever a packet is pushed to to_swift_sender, so the Swift
    /// write loop can wait event-driven instead of polling.
    /// Uses a std channel so the FFI wait function can block without entering
    /// the Tokio runtime.
    pub packet_notify_tx: std::sync::mpsc::SyncSender<()>,
    /// Object pool for Vec<u8> packets from Swift to reduce heap churn.
    /// Shared with FFI write functions via `Arc<Mutex>`.
    pub packet_pool: Arc<Mutex<VecPool>>,
    /// State callback for Swift notifications
    pub state_callback: Arc<RwLock<StateCallback>>,
    /// The primary (default) session's assigned tunnel IPv4 address. Set by
    /// the default session when its VirtualIp arrives. Secondary sessions'
    /// downlink (`run_rx`) rewrites each packet's destination to this address
    /// so the OS network stack — whose utun interface carries only the
    /// primary address — accepts packets that arrived via a secondary exit.
    /// `None` until the default session's first VirtualIp.
    pub primary_tunnel_ip: Arc<std::sync::Mutex<Option<std::net::Ipv4Addr>>>,
}

/// ServerSession - all state and logic for ONE exit-server connection.
///
/// Everything here is per-server: endpoint coordinates, X3DH bundle, the
/// connection state machine, the VirtualIp-assigned tunnel parameters, the
/// reconnect loop, the preconnect warmer, and the uplink packet channel.
/// Shared resources are reached through `shared`.
pub(crate) struct ServerSession {
    /// Shared per-client context (runtime handle, identity key, downlink
    /// plumbing, buffer pool, state callback).
    shared: Arc<SharedContext>,
    /// Server host (original hostname for TLS SNI and the WS Host header)
    server_host: String,
    /// Server IP (pre-resolved at client creation to avoid the DNS circular
    /// dependency during reconnect — the tunnel's matchDomains=[""] capture
    /// would route tokio's getaddrinfo into our own DNS proxy). Used as
    /// the TCP dial target only; SNI/Host stay `server_host`. `None` when
    /// startup resolution failed — connects then fall back to dialing the
    /// hostname, and each connect attempt retries the resolution (the DNS
    /// proxy answers server-hostname queries via direct UDP even while the
    /// tunnel is down, so this self-heals once the proxy is up).
    server_ip: std::sync::Mutex<Option<std::net::IpAddr>>,
    /// Server port
    server_port: u16,
    /// WebSocket path (base path, will append /tun)
    server_path: String,
    /// Connection state
    state: Arc<AtomicI32>,
    /// Assigned tunnel IP (set after VirtualIp received)
    tunnel_ip: Arc<std::sync::Mutex<Option<String>>>,
    /// Assigned gateway IP (set after VirtualIp received)
    gateway_ip: Arc<std::sync::Mutex<Option<String>>>,
    /// DNS servers from VirtualIp
    dns_servers: Arc<std::sync::Mutex<Vec<std::net::IpAddr>>>,
    /// MTU from VirtualIp
    mtu: Arc<std::sync::Mutex<u16>>,
    /// Shutdown signal
    shutdown_tx: broadcast::Sender<()>,
    /// Server prekey bundle for X3DH
    server_bundle: X3DHPublicBundle,
    /// Canonical `ik:1:<base32>` pin of the server's identity key, computed
    /// from `server_bundle.identity_key` at construction. The app FFI reads
    /// this via `rvpn_tun_get_server_identity()` after `Connected` to
    /// capture the TOFU pin on first-ever connect.
    server_identity_pin_actual: String,
    /// Last time any traffic was received from the server (Unix seconds).
    /// Updated on every WebSocket frame, including encrypted data and WS
    /// control frames, so Swift can distinguish a healthy idle tunnel from
    /// a suspended/dead one.
    last_rx_time: Arc<AtomicU64>,
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
    /// Sliding window of recent reconnect attempt start times, used to detect
    /// network flap on iOS. Under jetsam, a runaway reconnect storm during a
    /// metro-tunnel WiFi/cellular flap can trip the ~50 MB extension memory
    /// limit within seconds; enforcing a minimum backoff after N reconnects in
    /// 30 s throttles the storm and gives the runtime time to reclaim memory.
    reconnect_history: std::sync::Mutex<std::collections::VecDeque<std::time::Instant>>,
    /// Warm transport (TLS + WebSocket upgraded, NO protocol handshake yet)
    /// established in parallel with reconnect backoff. Consumed by
    /// `connect()` so the reconnect skips the TCP + TLS + WS-upgrade round
    /// trips entirely. Never holds keys or identity data — nothing sensitive
    /// is sent until X3DH runs.
    preconnect: tokio::sync::Mutex<Option<(MinimalWebSocket<TunnelWs>, std::time::Instant)>>,
    /// Guards against running more than one preconnect warmer at a time.
    preconnect_warming: AtomicBool,
    /// Receiver for packets from Swift (Swift sends via send_packet_to_server)
    from_swift_receiver: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    /// Sender for Swift to use (Swift calls send_packet_to_server with this)
    pub(crate) from_swift_sender: mpsc::Sender<Vec<u8>>,
    /// Whether this is the default (primary) exit session. The default
    /// session publishes its VirtualIp address into
    /// `SharedContext::primary_tunnel_ip` and needs no downlink rewrite;
    /// secondary sessions stash pre-VirtualIp uplink packets and rewrite
    /// both directions (see `nat_rewrite`).
    is_default: bool,
    /// TLS SNI hostname override (defaults to `server_host` when None).
    server_sni: Option<String>,
    /// TLS session resumption store for this exit server. Held per session so
    /// every reconnect — including preconnect-warmer handshakes — offers the
    /// cached TLS 1.3 ticket (1-RTT resume, no certificate flight) instead of
    /// a full handshake, which also looks like a returning browser to DPI.
    resumption: rvpn_tls::ResumptionStore,
    /// Packets the uplink demux routed to this session before its VirtualIp
    /// arrived (secondary exits start lazily, so the first routed packets
    /// race the connect). They cannot be sent yet — the source address must
    /// be rewritten to this session's tunnel IP, which is unknown until
    /// VirtualIp. Flushed (rewrite + enqueue) by `connect()` right after the
    /// tunnel IP is stored; dropped on session failure/stop. Bounded —
    /// drop-oldest past `PENDING_UPLINK_CAP`.
    pending_uplink: std::sync::Mutex<std::collections::VecDeque<Vec<u8>>>,
    /// Optional file path for memory-growth diagnostics (RSS snapshots from
    /// the relay loop). Written to the app-group container so it survives the
    /// jetsam kill and can be pulled off afterward. `None` when the container
    /// path can't be derived.
    #[cfg(feature = "diagnostics")]
    mem_log_path: Option<std::path::PathBuf>,
}

impl ServerSession {
    /// Create a new session for one exit server.
    ///
    /// All fallible setup (URL parsing, DNS pre-resolution, identity/bundle
    /// loading, TOFU pin enforcement) happens in `IosTunClient::new`; this
    /// constructor receives plain values. `chan_cap` is the uplink channel
    /// capacity (see the channel-sizing note in `IosTunClient::new`).
    #[allow(clippy::too_many_arguments)] // Per-server endpoint tuple; grouped into config in the multi-server pass.
    pub(crate) fn new(
        shared: Arc<SharedContext>,
        server_host: String,
        server_ip: Option<std::net::IpAddr>,
        server_port: u16,
        server_path: String,
        server_bundle: X3DHPublicBundle,
        server_identity_pin_actual: String,
        chan_cap: usize,
        is_default: bool,
        server_sni: Option<String>,
        #[cfg(feature = "diagnostics")] mem_log_path: Option<std::path::PathBuf>,
    ) -> Self {
        // from_swift_receiver is used by Swift to send packets to server (via send_packet_to_server)
        let (from_swift_sender, from_swift_receiver) = mpsc::channel::<Vec<u8>>(chan_cap);

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel::<()>(1);

        Self {
            shared,
            server_host,
            server_ip: std::sync::Mutex::new(server_ip),
            server_port,
            server_path,
            state: Arc::new(AtomicI32::new(TunClientState::Init as i32)),
            tunnel_ip: Arc::new(std::sync::Mutex::new(None)),
            gateway_ip: Arc::new(std::sync::Mutex::new(None)),
            dns_servers: Arc::new(std::sync::Mutex::new(Vec::new())),
            mtu: Arc::new(std::sync::Mutex::new(1420)),
            shutdown_tx,
            server_bundle,
            server_identity_pin_actual,
            last_rx_time: Arc::new(AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )),
            is_started: AtomicBool::new(false),
            reconnect_enabled: AtomicBool::new(false), // Disabled by default, enable via setter
            reconnect_max_attempts: AtomicU32::new(0),
            reconnect_initial_delay_ms: AtomicU64::new(1000),
            reconnect_max_delay_ms: AtomicU64::new(5000),
            last_reconnect_request: std::sync::Mutex::new(
                std::time::Instant::now() - std::time::Duration::from_secs(60),
            ),
            reconnect_history: std::sync::Mutex::new(std::collections::VecDeque::with_capacity(16)),
            preconnect: tokio::sync::Mutex::new(None),
            preconnect_warming: AtomicBool::new(false),
            from_swift_receiver: Arc::new(Mutex::new(from_swift_receiver)),
            from_swift_sender,
            is_default,
            server_sni,
            resumption: rvpn_tls::ResumptionStore::new(),
            pending_uplink: std::sync::Mutex::new(std::collections::VecDeque::new()),
            #[cfg(feature = "diagnostics")]
            mem_log_path,
        }
    }

    /// Canonical `ik:1:<base32>` pin of the server this session was constructed
    /// against. Computed at construction from the loaded prekey bundle's
    /// identity key. The app FFI reads this via
    /// `rvpn_tun_get_server_identity()` after the tunnel reaches `Connected`
    /// to persist the TOFU pin on the first connect.
    pub(crate) fn server_identity_pin(&self) -> &str {
        &self.server_identity_pin_actual
    }

    /// This exit's TLS session resumption store (a cheap `Arc` clone sharing
    /// the session's state). The DNS layer's per-exit DoH client installs it
    /// on its own TLS configs so the persistent `/dns` WebSocket's reconnects
    /// resume from the same tickets the tunnel connection earned.
    #[allow(dead_code)] // Used by the DNS proxy startup in ios_tun_ffi.rs (dns feature)
    pub(crate) fn resumption_store(&self) -> rvpn_tls::ResumptionStore {
        self.resumption.clone()
    }

    /// Call the state callback if set
    async fn notify_state(&self, new_state: TunClientState, ip: Option<&str>, message: &str) {
        // Only the default session reports to Swift — secondary exits are an
        // internal routing detail; their Connecting/Error churn must not
        // perturb the app's view of the tunnel (FFI state accessors also
        // read only the default session).
        if self.is_default {
            let callback = { *self.shared.state_callback.read().await };
            if let Some(cb) = callback {
                let ip_cstring = ip.map(|s| std::ffi::CString::new(s).unwrap());
                let msg_cstring = std::ffi::CString::new(message).unwrap();
                let ip_ptr = ip_cstring
                    .as_ref()
                    .map(|s| s.as_ptr())
                    .unwrap_or(std::ptr::null());
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
        }
        self.state.store(new_state as i32, Ordering::SeqCst);
    }

    /// WebSocket URL for the TUN endpoint. Swift may already append /tun,
    /// so only add it if not present.
    fn tun_url(&self) -> String {
        Self::tun_url_for(&self.server_host, self.server_port, &self.server_path)
    }

    /// Pure helper behind [`tun_url`] — split out for unit testing.
    fn tun_url_for(server_host: &str, server_port: u16, server_path: &str) -> String {
        let tun_path = if server_path.ends_with("/tun") || server_path.ends_with("/tun/") {
            server_path.trim_end_matches('/').to_string()
        } else if server_path.ends_with("/") {
            format!("{}tun", server_path)
        } else {
            format!("{}/tun", server_path)
        };
        format!("wss://{}:{}{}", server_host, server_port, tun_path)
    }

    /// Establish the transport (TCP + TLS + WebSocket upgrade) without
    /// running any protocol handshake. Shared by connect() and the
    /// preconnect warmer. Nothing sensitive is sent here — no keys, no
    /// identity, no Hello — so warming a connection ahead of time leaks
    /// nothing; the server only sees an upgraded WebSocket waiting for a
    /// handshake, which its handshake-wait timeout cleans up if abandoned.
    async fn establish_transport(self: &Arc<Self>) -> Result<MinimalWebSocket<TunnelWs>> {
        let url = self.tun_url();

        // If startup resolution failed (e.g. the client was recreated by a
        // Swift-level restart while the tunnel's DNS capture was already
        // live, racing the DNS proxy's bind), retry the resolution now. The
        // DNS proxy answers server-hostname queries via direct UDP even
        // while the tunnel is down, so this self-heals once the proxy is
        // up; before it is, the attempts below fail fast on the hostname
        // dial and the backoff loop retries.
        if self.server_ip.lock().unwrap().is_none() {
            self.try_resolve_server_ip().await;
        }

        match &*self.server_ip.lock().unwrap() {
            Some(ip) => info!("[IosTun] Connecting to {} (via {})", url, ip),
            None => info!(
                "[IosTun] Connecting to {} (no pre-resolved IP, dialing hostname)",
                url
            ),
        }

        // TLS connect.
        //
        // iOS: rustls backend — pure-Rust TLS with TLS 1.3 support.
        // native-tls (Security.framework) cannot negotiate TLS 1.3 on iOS;
        // boring (BoringSSL) leaks anonymous VM. rustls is the only viable
        // option. Cert verification uses bundled Mozilla roots
        // (webpki-roots) — the NE sandbox blocks /etc/ssl/ and trustd was
        // unreliable from the extension.
        // macOS: boring backend — retains Chrome ClientHello fingerprint
        // mimicry.
        let sni = self.server_sni.as_deref().unwrap_or(&self.server_host);

        // Dial the pre-resolved IP instead of the hostname: tokio's blocking
        // getaddrinfo would otherwise run on EVERY connect attempt while the
        // tunnel's matchDomains=[""] DNS capture is live. The IP was
        // resolved at client creation (or by the retry above). SNI and the
        // WS Host header stay the hostname — only the TCP dial target
        // changes. Falls back to the hostname while no IP is known.
        let dial_ip;
        let dial_target: &str = match &*self.server_ip.lock().unwrap() {
            Some(ip) => {
                dial_ip = ip.to_string();
                &dial_ip
            }
            None => &self.server_host,
        };

        // Bound the whole transport-establishment step (TCP connect + TLS
        // handshake) at 10s. Without this, a blackholing path (captive
        // portal, dead interface after a 4G/5G↔WiFi flap) hangs one attempt
        // for the OS TCP timeout (~75s); on expiry this produces a normal
        // connect error that the existing backoff loop handles.
        #[cfg(feature = "ios-direct-tun")]
        let tls_stream = timeout(
            std::time::Duration::from_secs(10),
            rvpn_tls::connect_rustls_with_store(
                dial_target,
                self.server_port,
                Some(sni),
                Some(&self.resumption),
            ),
        )
        .await
        .context("TCP connect + TLS handshake timeout (10s)")?
        .context("TLS handshake failed")?;

        #[cfg(not(feature = "ios-direct-tun"))]
        let tls_stream = timeout(
            std::time::Duration::from_secs(10),
            rvpn_tls::connect_chrome_like_with_resumption(
                dial_target,
                self.server_port,
                rvpn_tls::TlsFingerprint::Chrome,
                Some(sni),
                Some(&self.resumption),
            ),
        )
        .await
        .context("TCP connect + TLS handshake timeout (10s)")?
        .context("TLS handshake failed")?;

        info!(
            "[IosTun] TLS connected ({})",
            if cfg!(feature = "ios-direct-tun") {
                "rustls"
            } else {
                "Chrome fingerprint"
            }
        );

        // Perform WebSocket handshake over the TLS stream using minimal parser
        let ws = timeout(
            std::time::Duration::from_secs(5),
            MinimalWebSocket::connect(tls_stream, &url),
        )
        .await
        .context("WebSocket handshake timeout (5s)")?
        .context("WebSocket handshake failed")?;

        info!("[IosTun] WebSocket connected (TLS verified, minimal parser)");
        Ok(ws)
    }

    /// Resolve the server hostname and cache the IP for future dials.
    ///
    /// Called from `establish_transport` when startup resolution left
    /// `server_ip` unset. Uses tokio's `lookup_host` (getaddrinfo on a
    /// blocking thread); under the tunnel's DNS capture the query lands in
    /// our own DNS proxy, which answers server-hostname queries via direct
    /// UDP — so this works even while the tunnel is down. Failures are
    /// non-fatal: the caller falls back to dialing the hostname.
    async fn try_resolve_server_ip(&self) {
        let result = timeout(
            std::time::Duration::from_secs(5),
            tokio::net::lookup_host((self.server_host.as_str(), self.server_port)),
        )
        .await;
        match result {
            Ok(Ok(mut addrs)) => match addrs.next() {
                Some(addr) => {
                    let ip = addr.ip();
                    info!(
                        "[IosTun] Server {} resolved to {} (deferred resolution)",
                        self.server_host, ip
                    );
                    *self.server_ip.lock().unwrap() = Some(ip);
                }
                None => warn!(
                    "[IosTun] Deferred resolution of {} returned no addresses",
                    self.server_host
                ),
            },
            Ok(Err(e)) => warn!(
                "[IosTun] Deferred resolution of {} failed: {}",
                self.server_host, e
            ),
            Err(_) => warn!(
                "[IosTun] Deferred resolution of {} timed out (5s)",
                self.server_host
            ),
        }
    }

    /// Warm a transport during reconnect backoff so the next connect()
    /// skips the TCP + TLS + WS-upgrade round trips. The warmer keeps one
    /// warm connection ready and re-establishes it before it goes stale
    /// (the server kills upgraded-but-unhandshaked connections after its
    /// handshake-wait timeout). It stops once the warm transport is
    /// consumed, a session becomes Connected, or reconnection is disabled.
    /// Safe to call repeatedly — at most one warmer runs at a time.
    fn spawn_preconnect_warmer(self: &Arc<Self>) {
        if self
            .preconnect_warming
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }
        let client = Arc::clone(self);
        self.shared.handle.spawn(async move {
            loop {
                if !client.reconnect_enabled.load(Ordering::Relaxed)
                    || client.state.load(Ordering::SeqCst) == TunClientState::Connected as i32
                {
                    break;
                }
                match client.establish_transport().await {
                    Ok(ws) => {
                        let created = std::time::Instant::now();
                        *client.preconnect.lock().await = Some((ws, created));
                        info!("[IosTun] Preconnect: warm transport ready");
                        // Hold it until consumed or stale.
                        loop {
                            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                            if !client.reconnect_enabled.load(Ordering::Relaxed)
                                || client.state.load(Ordering::SeqCst)
                                    == TunClientState::Connected as i32
                            {
                                break;
                            }
                            if client.preconnect.lock().await.is_none() {
                                // Consumed by connect() — our job is done.
                                client.preconnect_warming.store(false, Ordering::SeqCst);
                                return;
                            }
                            if created.elapsed() >= PRECONNECT_MAX_AGE {
                                break; // stale — discard below and re-establish
                            }
                        }
                        *client.preconnect.lock().await = None;
                    }
                    Err(e) => {
                        // Network likely still down — back off briefly and retry.
                        debug!("[IosTun] Preconnect attempt failed: {}", e);
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
            *client.preconnect.lock().await = None;
            client.preconnect_warming.store(false, Ordering::SeqCst);
        });
    }

    /// Connect to the VPN server and perform X3DH handshake
    pub(crate) async fn connect(self: &Arc<Self>) -> Result<()> {
        // Early exit if reconnect was disabled (e.g. stopTunnel() called while we were in backoff)
        if !self.reconnect_enabled.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Connection cancelled by stop"));
        }

        // Set state to Connecting
        self.state
            .store(TunClientState::Connecting as i32, Ordering::SeqCst);
        self.notify_state(TunClientState::Connecting, None, "Connecting to server")
            .await;

        // Reuse a warm transport if the preconnect warmer prepared one during
        // backoff (skips the TCP + TLS + WS-upgrade round trips). Stale ones
        // are discarded. The transport carries no secrets — nothing sensitive
        // is sent until X3DH runs.
        let mut used_preconnect = false;
        let ws: MinimalWebSocket<TunnelWs> = {
            let taken = self.preconnect.lock().await.take();
            match taken {
                Some((ws, created)) if created.elapsed() <= PRECONNECT_MAX_AGE => {
                    info!(
                        "[IosTun] Reusing preconnected transport (age {} ms)",
                        created.elapsed().as_millis()
                    );
                    used_preconnect = true;
                    ws
                }
                Some((_, created)) => {
                    debug!(
                        "[IosTun] Preconnected transport stale ({} ms), connecting fresh",
                        created.elapsed().as_millis()
                    );
                    self.establish_transport().await?
                }
                None => self.establish_transport().await?,
            }
        };

        // Check again after transport
        if !self.reconnect_enabled.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!(
                "Connection cancelled by stop after WS handshake"
            ));
        }

        // Split into independent reader/writer halves
        let (mut ws_read, mut ws_write) = ws.split();

        // Perform X3DH handshake. If we reused a warm transport and the
        // handshake fails (the connection can die between warming and
        // consumption — server handshake timeout, NAT rebind), retry once
        // with a fresh transport.
        let mut ratchet = match self.perform_handshake(&mut ws_read, &mut ws_write).await {
            Ok(r) => r,
            Err(e) if used_preconnect => {
                warn!(
                    "[IosTun] X3DH failed on preconnected transport ({}); retrying fresh",
                    e
                );
                let fresh = self.establish_transport().await?;
                let (r, w) = fresh.split();
                ws_read = r;
                ws_write = w;
                self.perform_handshake(&mut ws_read, &mut ws_write)
                    .await
                    .context("X3DH handshake failed")?
            }
            Err(e) => return Err(e).context("X3DH handshake failed"),
        };

        info!("[IosTun] X3DH handshake complete");

        // Check again after X3DH
        if !self.reconnect_enabled.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Connection cancelled by stop after X3DH"));
        }

        // Receive VirtualIp message
        let virtual_ip = self
            .receive_virtual_ip(&mut ws_read, &mut ratchet)
            .await
            .context("Failed to receive VirtualIp")?;

        // Extract IP address
        let ipv4_str = virtual_ip
            .ipv4
            .map(|v4| v4.to_string())
            .context("No IPv4 address in VirtualIp")?;

        info!("[IosTun] Assigned IP: {}", ipv4_str);

        // Store tunnel IP, gateway IP, DNS servers, and MTU
        {
            let mut tunnel_ip = self.tunnel_ip.lock().unwrap();
            *tunnel_ip = Some(ipv4_str.clone());
        }
        {
            let mut gateway_ip = self.gateway_ip.lock().unwrap();
            *gateway_ip = virtual_ip.gateway_ip.map(|v4| v4.to_string());
        }
        {
            let mut dns = self.dns_servers.lock().unwrap();
            *dns = virtual_ip.dns_servers.clone();
        }
        {
            let mut mtu = self.mtu.lock().unwrap();
            *mtu = virtual_ip.mtu;
        }

        // The default session's tunnel IP is the address the OS utun
        // interface carries — publish it so secondary sessions can rewrite
        // their downlink packets back to it.
        if self.is_default {
            if let Ok(v4) = ipv4_str.parse::<std::net::Ipv4Addr>() {
                *self.shared.primary_tunnel_ip.lock().unwrap() = Some(v4);
            }
        }

        // Secondary exits start lazily, so the first routed packets may have
        // been stashed while this session connected. Now that the tunnel IP
        // is known, rewrite + enqueue them (see enqueue_uplink).
        self.flush_pending();

        // Set state to IpAssigned and notify Swift
        self.notify_state(TunClientState::IpAssigned, Some(&ipv4_str), "IP assigned")
            .await;

        // Set state to Connected
        self.notify_state(TunClientState::Connected, Some(&ipv4_str), "Connected")
            .await;

        // Start packet relay loop
        info!("[IosTun] connect() entering run_packet_relay()");
        self.run_packet_relay(ws_write, ws_read, ratchet).await;
        info!("[IosTun] connect() run_packet_relay() returned, connection ended");

        Ok(())
    }

    /// Perform X3DH handshake with server
    async fn perform_handshake(
        &self,
        ws_reader: &mut WsReader,
        ws_writer: &mut WsWriter,
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
            .send_binary(&hello_bytes)
            .await
            .context("Failed to send Hello message")?;

        debug!("[IosTun] Sent X3DH Hello message");

        // Receive ServerHello response
        let mut frame_buf = vec![0u8; 16384];
        let (frame_type, frame_len) = timeout(
            std::time::Duration::from_secs(5),
            ws_reader.next_frame(&mut frame_buf),
        )
        .await
        .context("WebSocket timeout during handshake (5s)")?
        .context("WebSocket error during handshake")?;

        match frame_type {
            FrameType::Binary => {
                // ServerHello received, extract keys
                let server_hello: HandshakeMessage =
                    serde_json::from_slice(&frame_buf[..frame_len])
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

                        // Verify the Ed25519 signature on signed_prekey using the server's identity_key
                        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
                            &server_identity_key,
                        )
                        .map_err(|e| anyhow::anyhow!("Invalid server identity key: {}", e))?;
                        let signature = ed25519_dalek::Signature::from_bytes(&prekey_signature);
                        verifying_key
                            .verify(&server_signed_prekey, &signature)
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
                            prekey_signature,
                            one_time_prekey: None,
                            // Handshake path doesn't propagate rotation
                            // metadata (yet); the pre-loaded bundle from
                            // disk carries those fields and drives TOFU
                            // enforcement in IosTunClient::new.
                            identity_key_version: self.server_bundle.identity_key_version,
                            rotation_signature: self.server_bundle.rotation_signature,
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
        ws_reader: &mut WsReader,
        ratchet: &mut DoubleRatchet,
    ) -> Result<VirtualIp> {
        // Wait for first encrypted frame after X3DH
        let mut frame_buf = vec![0u8; 16384];
        let (frame_type, frame_len) = timeout(
            std::time::Duration::from_secs(5),
            ws_reader.next_frame(&mut frame_buf),
        )
        .await
        .context("Timeout waiting for VirtualIp (5s)")?
        .context("WebSocket error during VirtualIp wait")?;

        match frame_type {
            FrameType::Binary => {
                debug!(
                    "[IosTun] Received {} bytes, decrypting VirtualIp",
                    frame_len
                );

                // Deserialize RatchetMessage
                let ratchet_msg = RatchetMessage::from_bytes(&frame_buf[..frame_len])
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

                info!(
                    "[IosTun] VirtualIp received: ipv4={:?}, dns={:?}, mtu={}",
                    virtual_ip.ipv4, virtual_ip.dns_servers, virtual_ip.mtu
                );

                Ok(virtual_ip)
            }
            _ => Err(anyhow::anyhow!("Expected binary message for VirtualIp")),
        }
    }

    /// Truncate the diagnostics CSV at the start of a relay so the file holds
    /// only the current (about-to-run) session's data. The jetsam kill happens
    /// mid-relay, so the file left behind is the killed session's trajectory.
    #[cfg(feature = "diagnostics")]
    fn reset_mem_log(&self) {
        let Some(path) = self.mem_log_path.as_ref() else {
            return;
        };
        use std::io::Write;
        if let Ok(mut f) = std::fs::File::create(path) {
            let _ = f.write_all(b"elapsed_sec,rss_bytes,commit_bytes,peak_commit,commit_after_collect,allzones_in_use,internal,compressed,headroom_bytes,direction,frame_count\n");
            let _ = f.flush();
        }
    }

    /// Append a memory-growth snapshot to the diagnostics CSV (best-effort;
    /// failures are swallowed so this never disrupts the relay). Fires only at
    /// the periodic RSS checkpoints, so the blocking file I/O is infrequent.
    ///
    /// Columns (CSV): `elapsed_sec,rss_bytes,commit_bytes,allzones_in_use,headroom_bytes,direction,frame_count`
    /// - `rss_bytes`: OS resident (overstates jetsam; trust the trend).
    /// - `commit_bytes`: mimalloc live bytes (Rust heap).
    /// - `allzones_in_use`: sum of size_in_use across ALL malloc zones (C heap).
    ///   Flat here while headroom declines ⇒ growth is NOT in any malloc zone
    ///   (it's in vm/mmap regions or compressed pages).
    /// - `headroom_bytes`: `os_proc_available_memory()` — bytes before jetsam.
    #[cfg(feature = "diagnostics")]
    fn append_mem_log(&self, relay_start: std::time::Instant, direction: &str, frame_count: u64) {
        let Some(path) = self.mem_log_path.as_ref() else {
            return;
        };
        let elapsed = relay_start.elapsed().as_secs_f64();
        let rss = get_rss_bytes();
        let commit = mi_committed_bytes();
        let peak_commit = mi_peak_commit_bytes();
        // Force mimalloc to return freed pages BEFORE measuring.  If
        // commit_after_collect < commit, the gap is deferred-free hoarding.
        let commit_after = mi_commit_after_collect();
        let allzones = all_zones_size_in_use();
        let (internal, compressed) = vm_internal_compressed();
        let headroom = jetsam_headroom_bytes();
        let line = format!(
            "{:.1},{},{},{},{},{},{},{},{},{},{}\n",
            elapsed,
            rss,
            commit,
            peak_commit,
            commit_after,
            allzones,
            internal,
            compressed,
            headroom,
            direction,
            frame_count
        );
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }

    /// Main packet relay loop.
    ///
    /// The three arms (`swift_to_server`, `server_to_swift`, `keepalive`) are
    /// `tokio::spawn`ed as independent tasks. This is important for two reasons:
    ///
    /// 1. **Diagnostic attribution.** The MEMDELTA `vm_internal_compressed()`
    ///    samples inside each arm are only meaningful if that arm's samples are
    ///    adjacent in wall-clock time. When all three arms share a single task
    ///    (as they did under `tokio::select!`), a poll of arm A can be
    ///    arbitrarily separated by polls of arms B and C, so `prev_internal`
    ///    absorbs growth from every arm. Independent tasks are polled
    ///    concurrently by the multi-thread runtime; the samples in a given arm
    ///    are still not perfectly isolated from process-wide anonymous VM, but
    ///    the arm's own operations dominate the observed delta.
    /// 2. **Progress.** A slow ObjC callback into Swift (e.g. writePackets
    ///    stalling behind kernel-IPC backpressure) can no longer starve the
    ///    ws_write / keepalive path — each task has independent poll budget.
    async fn run_packet_relay(
        self: &Arc<Self>,
        ws_write: WsWriter,
        ws_read: WsReader,
        ratchet: DoubleRatchet,
    ) {
        info!("[IosTun] run_packet_relay STARTING");
        #[cfg(feature = "diagnostics")]
        let relay_start = std::time::Instant::now();
        #[cfg(feature = "diagnostics")]
        self.reset_mem_log();

        // Wrap ratchet and WebSocket writer in Arc<Mutex> for safe sharing between
        // the three spawned tasks. All three may need the writer (data path,
        // pong replies, keepalive); TX and keepalive both hold the ratchet.
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

        // --- swift_to_server task ---
        let tx_task = {
            let this = Arc::clone(self);
            let ratchet = ratchet.clone();
            let ws_write = ws_write.clone();
            let send_lock = send_lock.clone();
            #[cfg(feature = "diagnostics")]
            let relay_start = relay_start;
            tokio::spawn(async move {
                Self::run_tx(
                    this,
                    ratchet,
                    ws_write,
                    send_lock,
                    #[cfg(feature = "diagnostics")]
                    relay_start,
                )
                .await;
            })
        };

        // --- server_to_swift task ---
        let rx_task = {
            let this = Arc::clone(self);
            let ratchet = ratchet.clone();
            let ws_write = ws_write.clone();
            #[cfg(feature = "diagnostics")]
            let relay_start = relay_start;
            tokio::spawn(async move {
                Self::run_rx(
                    this,
                    ws_read,
                    ratchet,
                    ws_write,
                    #[cfg(feature = "diagnostics")]
                    relay_start,
                )
                .await;
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
            _ = tx_task => info!("[IosTun] tx task completed first"),
            _ = rx_task => info!("[IosTun] rx task completed first"),
            _ = ka_task => info!("[IosTun] keepalive task completed first"),
        }
        let _ = self.shutdown_tx.send(());

        info!("[IosTun] run_packet_relay ENDING");
        self.notify_state(TunClientState::Error, None, "Connection closed")
            .await;
    }

    /// Swift → Server (TX) task body. Spawned by `run_packet_relay` so its
    /// `prev_internal_tx` samples aren't interleaved with the RX/keepalive
    /// polls on the same task.
    async fn run_tx(
        this: Arc<Self>,
        ratchet: Arc<Mutex<DoubleRatchet>>,
        ws_write: Arc<Mutex<WsWriter>>,
        send_lock: Arc<Mutex<()>>,
        #[cfg(feature = "diagnostics")] relay_start: std::time::Instant,
    ) {
        let mut encrypt_bufs = EncryptBuffers::new();
        let packet_pool = Arc::clone(&this.shared.packet_pool);
        let from_swift_receiver = Arc::clone(&this.from_swift_receiver);
        let shutdown_tx = this.shutdown_tx.clone();
        let ws_write_for_swift = ws_write;

        let mut shutdown_rx = shutdown_tx.subscribe();
        let mut packet_count = 0u64;
        let mut batch_count = 0u64;
        let mut pending_packet: Option<Vec<u8>> = None;
        // Reuse the batch Vec across iterations to avoid a heap allocation
        // on every outgoing batch (~416/sec under heavy traffic).
        let mut batch = Vec::with_capacity(OUTGOING_BATCH_MAX_FRAMES);
        #[cfg(feature = "diagnostics")]
        let mut prev_internal_tx: u64 = 0;
        info!("[IosTun] swift_to_server task STARTED");
        'outer: loop {
            // Acquire the first packet for this batch (either a packet that
            // did not fit in the previous batch or a fresh one from Swift).
            batch.clear();
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
            //
            // Open the collection window ONLY when another packet is already
            // queued: interactive single-packet sends (TCP SYN/ACK, DNS
            // queries) used to pay the full 5 ms even with an empty queue,
            // adding a 5 ms floor to every uplink round trip. Bursts still
            // coalesce because their packets are queued by the time we check.
            let has_more_queued = {
                let r = from_swift_receiver.lock().await;
                !r.is_empty()
            };
            let deadline = if has_more_queued {
                tokio::time::Instant::now()
                    + std::time::Duration::from_millis(OUTGOING_BATCH_TIMEOUT_MS)
            } else {
                tokio::time::Instant::now()
            };
            let mut receiver_closed = false;
            while batch.len() < OUTGOING_BATCH_MAX_FRAMES && batch_bytes < OUTGOING_BATCH_MAX_BYTES
            {
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

            // Serialize encrypt→enqueue against the keepalive arm: the
            // ratchet assigns message numbers at encrypt time, so the frame
            // must reach the writer before any later-encrypted frame.
            // The ratchet lock is released BEFORE the ws send await so a
            // blocked writer never stalls RX decrypts.
            let _send_guard = send_lock.lock().await;

            let encrypted = {
                #[cfg(feature = "diagnostics")]
                {
                    let (internal, _) = vm_internal_compressed();
                    let delta = internal.wrapping_sub(prev_internal_tx);
                    if delta > 0 {
                        info!(
                            "[IosTun] MEMDELTA tx:pre_encrypt +{} B (internal={})",
                            delta, internal
                        );
                    }
                    prev_internal_tx = internal;
                }
                let mut ratchet_guard = ratchet.lock().await;
                match Self::encrypt_data_batch(&mut ratchet_guard, &batch, &mut encrypt_bufs) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        // Return Vecs to pool before breaking
                        let mut pool = packet_pool.lock().await;
                        for v in batch.drain(..) {
                            pool.put(v);
                        }
                        error!("[IosTun] Swift->Server: encrypt_data_batch failed: {}, sending shutdown", e);
                        let _ = shutdown_tx.send(());
                        break 'outer;
                    }
                }
            };

            // Return Vecs to pool for reuse (data is now in `encrypted`)
            {
                let mut pool = packet_pool.lock().await;
                for v in batch.drain(..) {
                    pool.put(v);
                }
            }

            let mut ws_guard = ws_write_for_swift.lock().await;
            if let Err(e) = ws_guard.send_binary(&encrypted).await {
                error!(
                    "[IosTun] Swift->Server: WebSocket send failed: {}, sending shutdown",
                    e
                );
                drop(ws_guard);
                let _ = shutdown_tx.send(());
                break 'outer;
            }
            drop(ws_guard);
            drop(_send_guard);

            #[cfg(feature = "diagnostics")]
            {
                let (internal, _) = vm_internal_compressed();
                let delta = internal.wrapping_sub(prev_internal_tx);
                if delta > 0 {
                    info!(
                        "[IosTun] MEMDELTA tx:ws_send +{} B (internal={})",
                        delta, internal
                    );
                }
                prev_internal_tx = internal;
            }

            // Reclaim freed C-heap pages every 100 batches (~4×/sec).
            // The leak is iOS libmalloc retaining BoringSSL's per-record
            // freed allocations. The 15s keepalive call isn't frequent
            // enough; calling here keeps internal growth bounded.
            if batch_count % 100 == 0 {
                all_zones_pressure_relief();
                #[cfg(feature = "diagnostics")]
                {
                    let rss = get_rss_bytes();
                    info!(
                        "[IosTun] RSS: {} bytes ({:.1} MB) after {} batches, {} packets sent",
                        rss,
                        rss as f64 / (1024.0 * 1024.0),
                        batch_count,
                        packet_count
                    );
                    this.append_mem_log(relay_start, "tx", batch_count);
                }
            }

            if receiver_closed {
                info!("[IosTun] Swift->Server: from_swift_receiver closed after batch, breaking (sent {} packets)", packet_count);
                break 'outer;
            }
        }
        info!("[IosTun] swift_to_server task ENDED");
    }

    /// Server → Swift (RX) task body.
    async fn run_rx(
        this: Arc<Self>,
        mut ws_read: WsReader,
        ratchet: Arc<Mutex<DoubleRatchet>>,
        ws_write: Arc<Mutex<WsWriter>>,
        #[cfg(feature = "diagnostics")] relay_start: std::time::Instant,
    ) {
        let mut decrypt_bufs = DecryptBuffers::new();
        let to_swift_sender = this.shared.to_swift_sender.clone();
        let shutdown_tx = this.shutdown_tx.clone();
        let packet_notify_tx = this.shared.packet_notify_tx.clone();
        let ws_write_for_pong = ws_write;

        // SERVER -> SWIFT direction
        let mut shutdown_rx = shutdown_tx.subscribe();
        let mut packet_count = 0u64;
        let mut frame_buf = vec![0u8; 16384];
        #[cfg(feature = "diagnostics")]
        let mut prev_internal_rx: u64 = 0;
        info!("[IosTun] server_to_swift task STARTED");
        loop {
            tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("[IosTun] Server->Swift relay: shutdown received, breaking");
                break;
            }
            result = timeout(std::time::Duration::from_secs(60), ws_read.next_frame(&mut frame_buf)) => {
                #[cfg(feature = "diagnostics")]
                {
                    let (internal, _) = vm_internal_compressed();
                    let delta = internal.wrapping_sub(prev_internal_rx);
                    if delta > 0 {
                        info!("[IosTun] MEMDELTA rx:ws_read +{} B (internal={})", delta, internal);
                    }
                    prev_internal_rx = internal;
                }
                match result {
                    Ok(Ok((FrameType::Binary, len))) => {
                        this.update_last_rx_time();
                        packet_count += 1;

                        // Log RSS every 500 packets to trace memory growth
                        #[cfg(feature = "diagnostics")]
                        if packet_count % 500 == 0 {
                            let rss = get_rss_bytes();
                            info!("[IosTun] RX RSS: {} bytes ({:.1} MB) after {} packets",
                                  rss, rss as f64 / (1024.0 * 1024.0), packet_count);
                            this.append_mem_log(relay_start, "rx", packet_count);
                        }

                            // Deserialize and decrypt — zero-copy: RatchetMessageRef
                            // borrows ciphertext from the WebSocket frame instead of
                            // allocating a new Vec per message.
                            let decrypted_len = match RatchetMessageRef::from_bytes(&frame_buf[..len]) {
                                Ok(ratchet_msg) => {
                                    let mut ratchet_guard = ratchet.lock().await;
                                    match ratchet_guard.decrypt_to_ref(&ratchet_msg, &[PayloadType::Data as u8], &mut decrypt_bufs.plaintext) {
                                        Ok(len) => {
                                            #[cfg(feature = "diagnostics")]
                                            {
                                                let (internal, _) = vm_internal_compressed();
                                                let delta = internal.wrapping_sub(prev_internal_rx);
                                                if delta > 0 {
                                                    info!("[IosTun] MEMDELTA rx:decrypt +{} B (internal={})", delta, internal);
                                                }
                                                prev_internal_rx = internal;
                                            }
                                            Some(len)
                                        }
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

                            if let Some(len) = decrypted_len {
                                match unpad_packet_slice(&decrypt_bufs.plaintext[..len]) {
                                    Ok(unpadded) => {
                                        // Parse all MultiplexedFrame packets from the
                                        // decrypted plaintext and batch data packets into a
                                        // single Bytes allocation with u16-LE length prefixes.
                                        // This reduces per-packet heap churn from N to 1.
                                        decrypt_bufs.batch_buf.clear();
                                        let mut offset = 0usize;
                                        let mut has_data = false;
                                        while offset + 6 <= unpadded.len() {
                                            let flow_id = u32::from_be_bytes([unpadded[offset], unpadded[offset + 1], unpadded[offset + 2], unpadded[offset + 3]]);
                                            let payload_len = u16::from_be_bytes([unpadded[offset + 4], unpadded[offset + 5]]) as usize;
                                            if offset + 6 + payload_len > unpadded.len() {
                                                error!("[IosTun] Server->Swift: frame truncated at offset {} (need {} got {})", offset, 6 + payload_len, unpadded.len());
                                                break;
                                            }
                                            if flow_id == 0 {
                                                // Control frame — parse and handle
                                                if let Ok(ctrl) = MultiplexedFrame::decode(&unpadded[offset..]) {
                                                    if let Ok(msg) = ctrl.parse_control() {
                                                        trace!("[IosTun] Server->Swift: control {:?}", msg);
                                                    }
                                                }
                                            } else {
                                                // Data frame — accumulate into batch buffer
                                                let prefix_at = decrypt_bufs.batch_buf.len();
                                                let len_bytes = (payload_len as u16).to_le_bytes();
                                                decrypt_bufs.batch_buf.extend_from_slice(&len_bytes);
                                                decrypt_bufs.batch_buf.extend_from_slice(&unpadded[offset + 6..offset + 6 + payload_len]);
                                                if this.is_default {
                                                    has_data = true;
                                                } else {
                                                    // Secondary exit: the OS utun
                                                    // interface carries only the primary
                                                    // (default) session's address, so
                                                    // rewrite dst session-IP → primary.
                                                    let primary = *this.shared.primary_tunnel_ip.lock().unwrap();
                                                    match primary {
                                                        Some(primary) => {
                                                            let pkt_range = prefix_at + 2..decrypt_bufs.batch_buf.len();
                                                            crate::nat_rewrite::rewrite_dst_ip(
                                                                &mut decrypt_bufs.batch_buf[pkt_range],
                                                                primary,
                                                            );
                                                            has_data = true;
                                                        }
                                                        None => {
                                                            // Startup race: a secondary
                                                            // downlink packet arrived before
                                                            // the primary session's VirtualIp.
                                                            // Drop it and keep the batch valid.
                                                            debug!("[IosTun] Downlink packet on secondary exit dropped: primary tunnel IP not yet assigned");
                                                            decrypt_bufs.batch_buf.truncate(prefix_at);
                                                        }
                                                    }
                                                }
                                            }
                                            offset += 6 + payload_len;
                                        }
                                        if has_data {
                                            if BISECT_DROP_INBOUND {
                                                // BISECTION: discard the decrypted batch so the
                                                // Swift/NE write path stays idle, while BoringSSL
                                                // read + Rust decrypt keep running. If jetsam
                                                // headroom still declines ~per frame → BoringSSL;
                                                // if flat → Swift/NE write path.
                                                decrypt_bufs.batch_buf.clear();
                                            } else {
                                                // Zero-copy: split() takes the filled portion
                                                // of the BytesMut, freeze() converts to Bytes
                                                // without copying. The original batch_buf is
                                                // left empty and reusable on the next frame.
                                                let batch = decrypt_bufs.batch_buf.split().freeze();
                                                if to_swift_sender.send(batch).await.is_err() {
                                                    info!("[IosTun] Server->Swift: to_swift_sender closed, breaking");
                                                    break;
                                                }
                                                let _ = packet_notify_tx.try_send(());
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("[IosTun] Server->Swift: Failed to unpad packet: {}", e);
                                    }
                                }
                            }
                        }
                        Ok(Ok((FrameType::Close, _))) => {
                            this.update_last_rx_time();
                            info!("[IosTun] Server->Swift: received Close frame, sending shutdown and breaking");
                            let _ = shutdown_tx.send(());
                            break;
                        }
                        Ok(Ok((FrameType::Ping, len))) => {
                            this.update_last_rx_time();
                            debug!("[IosTun] Server->Swift: received Ping");
                            if let Ok(mut ws_guard) = ws_write_for_pong.try_lock() {
                                let _ = ws_guard.send_pong(&frame_buf[..len]).await;
                            }
                        }
                        Ok(Err(e)) => {
                            error!("[IosTun] Server->Swift: WebSocket error: {}, sending shutdown and breaking", e);
                            let _ = shutdown_tx.send(());
                            break;
                        }
                        Err(_) => {
                            error!("[IosTun] Server->Swift: WebSocket read timeout (60s), sending shutdown and breaking");
                            let _ = shutdown_tx.send(());
                            break;
                        }
                    }
                }
            }
        }
        info!(
            "[IosTun] server_to_swift task ENDED (received {} packets)",
            packet_count
        );
    }

    /// Keepalive task body. Sends a WebSocket Ping every 15 seconds to keep the
    /// server-side idle timeout from firing, plus an encrypted keepalive over
    /// the ratchet. Also detects process suspension (>30s wall-clock skip) and
    /// server silence (>30s since last RX) and signals shutdown on either.
    async fn run_keepalive(
        this: Arc<Self>,
        ratchet: Arc<Mutex<DoubleRatchet>>,
        ws_write: Arc<Mutex<WsWriter>>,
        send_lock: Arc<Mutex<()>>,
    ) {
        let shutdown_tx = this.shutdown_tx.clone();
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate first tick.
        interval.tick().await;
        // Pre-allocate reusable buffers for keepalive packets.
        let mut ka_frame = Vec::with_capacity(128);
        let mut ka_padded = Vec::with_capacity(1024);
        let mut ka_encrypted = Vec::with_capacity(1152);
        let mut ka_serialized = Vec::with_capacity(1280);
        // Track wall-clock time to detect iOS process suspension.
        // Must use SystemTime (CLOCK_REALTIME) — Instant (CLOCK_MONOTONIC)
        // pauses during iOS suspension, making elapsed time unreliable.
        let mut last_wall = std::time::SystemTime::now();
        loop {
            interval.tick().await;

            // Return freed C-heap pages to the OS across ALL malloc zones
            // (default zone alone misses the nano zone where small allocations
            // live). Non-disruptive (no tunnel drop). Vestigial from the
            // BoringSSL era but harmless — a no-op with rustls.
            all_zones_pressure_relief();

            // Detect process suspension: if wall clock advanced >30s
            // since last keepalive, iOS froze us and the server's
            // 60-second timeout already expired. Force reconnect.
            let now = std::time::SystemTime::now();
            let elapsed = now.duration_since(last_wall).unwrap_or_default();
            last_wall = now;
            if elapsed > std::time::Duration::from_secs(30) {
                error!("[IosTun] Keepalive: process was suspended for {:.0}s, connection dead. Reconnecting.", elapsed.as_secs_f64());
                let _ = shutdown_tx.send(());
                break;
            }

            // Check if server is still sending data. If no data received
            // for 60s, the connection is dead (server closed it, network
            // changed, etc.). Force reconnect.
            let rx_elapsed = this.last_rx_time.load(Ordering::Relaxed);
            if rx_elapsed > 0 {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let since_rx = now_secs.saturating_sub(rx_elapsed);
                if since_rx > 30 {
                    error!("[IosTun] Keepalive: no server data for {}s, connection dead. Reconnecting.", since_rx);
                    let _ = shutdown_tx.send(());
                    break;
                }
            }

            // Send WS ping using try_lock — non-blocking.
            // Under high traffic, the data path holds ws_write continuously.
            // Blocking on lock().await would stall the keepalive for seconds.
            // The data path's own send_binary calls already update
            // last_activity on the server, so a missed ping is fine
            // when data is flowing.
            if let Ok(mut ws_guard) = ws_write.try_lock() {
                let _ = ws_guard.send_ping(b"").await;
            }

            // Try encrypted keepalive (non-blocking on all three locks).
            // send_lock serializes encrypt→enqueue against run_tx: a
            // keepalive encrypted after a data batch must not overtake it
            // on the wire, or the server's ratchet drops a frame
            // ("Message too old"). Skipping when busy is fine — the data
            // path's own sends keep the server-side activity timer alive.
            if let Ok(send_guard) = send_lock.try_lock() {
                if let Ok(mut ratchet_guard) = ratchet.try_lock() {
                    match Self::build_keepalive_to(
                        &mut ratchet_guard,
                        &mut ka_frame,
                        &mut ka_padded,
                        &mut ka_encrypted,
                        &mut ka_serialized,
                    ) {
                        Ok(_len) => {
                            drop(ratchet_guard);
                            let payload = std::mem::take(&mut ka_serialized);
                            let mut ws_guard = ws_write.lock().await;
                            if let Err(e) = ws_guard.send_binary(&payload).await {
                                error!("[IosTun] Keepalive: send failed: {}", e);
                                drop(ws_guard);
                                let _ = shutdown_tx.send(());
                                break;
                            }
                        }
                        Err(e) => {
                            error!("[IosTun] Keepalive: build failed: {}", e);
                        }
                    }
                }
                drop(send_guard);
            }
        }
    }

    /// Encrypt a batch of TUN packets into a single WebSocket/Ratchet message.
    ///
    /// Each packet is wrapped in a `MultiplexedFrame` with `flow_id=1`; the
    /// encoded frames are concatenated, padded once, and encrypted once. The
    /// server parses the decrypted plaintext with `parse_frames`.
    ///
    /// Uses pre-allocated `EncryptBuffers` to avoid per-batch heap allocations.
    /// Frame headers are written directly into the plaintext buffer to avoid
    /// cloning each packet into a `MultiplexedFrame` struct.
    ///
    /// Returns a borrow of `bufs.serialized` rather than an owned `Vec` so the
    /// pre-allocated buffer is genuinely reused across batches. Taking the
    /// buffer out (`mem::take`) would empty its allocation and force a fresh
    /// ~14 KB reallocation on every call (~416/sec under heavy traffic).
    fn encrypt_data_batch<'a>(
        ratchet: &mut DoubleRatchet,
        packets: &[Vec<u8>],
        bufs: &'a mut EncryptBuffers,
    ) -> Result<&'a [u8]> {
        if packets.is_empty() {
            return Err(anyhow::anyhow!("Cannot encrypt empty batch"));
        }

        bufs.clear();

        // Encode frame headers + payload directly into the plaintext buffer.
        // Format: [flow_id: u32 BE] [payload_len: u16 BE] [payload: N bytes]
        // This avoids MultiplexedFrame::new_data() which would clone each packet.
        for packet in packets {
            bufs.plaintext.extend_from_slice(&1u32.to_be_bytes());
            bufs.plaintext
                .extend_from_slice(&(packet.len() as u16).to_be_bytes());
            bufs.plaintext.extend_from_slice(packet);
        }

        // Pad the concatenated frames to a 1KB boundary for traffic analysis mitigation
        // Write padding directly into the pre-allocated buffer
        let data_len = bufs.plaintext.len();
        let target_size = (data_len + 2).div_ceil(1024) * 1024;
        let max_data_len = target_size.saturating_sub(2);
        let padding_len = max_data_len.saturating_sub(data_len);

        bufs.padded.clear();
        bufs.padded.extend_from_slice(&bufs.plaintext);
        if padding_len > 0 {
            let old_len = bufs.padded.len();
            bufs.padded.resize(old_len + padding_len, 0);
            StdRng::from_entropy().fill_bytes(&mut bufs.padded[old_len..]);
        }
        bufs.padded
            .extend_from_slice(&(padding_len as u16).to_be_bytes());

        // Encrypt with Data payload type as AAD — reuse ciphertext buffer
        let (nonce, header) = ratchet
            .encrypt_to(
                &bufs.padded,
                &[PayloadType::Data as u8],
                &mut bufs.ciphertext,
            )
            .context("Failed to encrypt data batch")?;

        // Build RatchetMessage and serialize directly into reuse buffer
        let msg = RatchetMessage {
            header,
            nonce,
            ciphertext: std::mem::take(&mut bufs.ciphertext),
        };
        bufs.serialized.clear();
        bincode::serialize_into(&mut bufs.serialized, &msg)
            .map_err(|e| anyhow::anyhow!("RatchetMessage serialize: {}", e))?;
        // Put the ciphertext buffer back for next batch
        bufs.ciphertext = msg.ciphertext;

        Ok(&bufs.serialized)
    }

    /// Build an encrypted keepalive (Ping) frame into pre-allocated buffers.
    ///
    /// Same as `build_keepalive_packet` but writes the serialized result
    /// into `out` instead of allocating a new `Vec` each time.
    /// Returns the number of bytes written.
    fn build_keepalive_to(
        ratchet: &mut DoubleRatchet,
        frame_buf: &mut Vec<u8>,
        padded_buf: &mut Vec<u8>,
        encrypted_buf: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> Result<usize> {
        let ping = ControlMessage::Ping {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };
        let frame =
            MultiplexedFrame::new_control(&ping).context("Failed to create keepalive frame")?;

        // Encode frame directly into buffer (6-byte header + payload)
        frame_buf.clear();
        frame_buf.extend_from_slice(&frame.flow_id.to_be_bytes());
        frame_buf.extend_from_slice(&(frame.payload.len() as u16).to_be_bytes());
        frame_buf.extend_from_slice(&frame.payload);

        let padded = pad_packet(frame_buf).map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;
        padded_buf.clear();
        padded_buf.extend_from_slice(&padded);

        let (nonce, header) = ratchet
            .encrypt_to(padded_buf, &[PayloadType::Data as u8], encrypted_buf)
            .context("Failed to encrypt keepalive")?;

        let msg = RatchetMessage {
            header,
            nonce,
            ciphertext: std::mem::take(encrypted_buf),
        };
        out.clear();
        bincode::serialize_into(&mut *out, &msg)
            .map_err(|e| anyhow::anyhow!("RatchetMessage serialize: {}", e))?;
        *encrypted_buf = msg.ciphertext;

        Ok(out.len())
    }

    /// Get the assigned tunnel IP
    pub(crate) fn get_tunnel_ip(&self) -> Option<String> {
        let guard = self.tunnel_ip.lock().unwrap();
        guard.clone()
    }

    /// Get the assigned gateway IP
    pub(crate) fn get_gateway_ip(&self) -> Option<String> {
        let guard = self.gateway_ip.lock().unwrap();
        guard.clone()
    }

    /// Get the DNS servers from VirtualIp
    pub(crate) fn get_dns_servers(&self) -> Vec<std::net::IpAddr> {
        let guard = self.dns_servers.lock().unwrap();
        guard.clone()
    }

    /// Get the MTU from VirtualIp
    pub(crate) fn get_mtu(&self) -> u16 {
        let guard = self.mtu.lock().unwrap();
        *guard
    }

    /// Get current state
    pub(crate) fn get_state(&self) -> TunClientState {
        TunClientState::from(self.state.load(Ordering::SeqCst))
    }

    /// Update the last-received timestamp to the current wall-clock time.
    fn update_last_rx_time(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_rx_time.store(now, Ordering::Relaxed);
    }

    /// Get the last time any traffic was received from the server, in Unix seconds.
    pub(crate) fn last_rx_time(&self) -> u64 {
        self.last_rx_time.load(Ordering::Relaxed)
    }

    /// Get server bundle reference
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

    /// Get pre-resolved server IP address (`None` while no resolution has
    /// succeeded — connects then dial the hostname and retry resolution)
    pub(crate) fn server_ip(&self) -> Option<std::net::IpAddr> {
        *self.server_ip.lock().unwrap()
    }

    /// Send a packet to the server (call this from Swift)
    /// Swift calls this to send packets to be relayed to the server
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
                    debug!("[IosTun] Uplink packet for secondary exit has unusable IPv4 header, dropped");
                    return Ok(());
                }
                self.from_swift_sender.try_send(packet)
            }
            None => {
                if pending.len() >= PENDING_UPLINK_CAP {
                    pending.pop_front();
                    debug!(
                        "[IosTun] Pending uplink queue full ({}), dropped oldest packet",
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
                debug!("[IosTun] Pending flush: uplink channel full, packet dropped");
            }
        }
        info!(
            "[IosTun] Flushed {} pending uplink packets after VirtualIp",
            n
        );
    }

    /// Drop any stashed uplink packets, e.g. when the session's reconnect
    /// attempts are exhausted or it is stopped. Logged loudly: these were
    /// routed packets with nowhere to go.
    fn drop_pending(&self, reason: &str) {
        let mut pending = self.pending_uplink.lock().unwrap();
        if !pending.is_empty() {
            warn!(
                "[IosTun] Dropping {} pending uplink packets ({})",
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

    /// Start the session (runs connect and relay in background)
    /// Implements reconnection loop when enabled via set_reconnect_enabled()
    ///
    /// This method is idempotent — calling it multiple times has no effect.
    pub(crate) fn start(self: &Arc<Self>) {
        // Atomically check and set is_started to prevent duplicate reconnect loops
        if self
            .is_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            warn!("[IosTun] start() called but reconnect loop already running, ignoring");
            return;
        }

        let client = Arc::clone(self);
        self.shared.handle.spawn(async move {
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
                    error!(
                        "[IosTun] Max reconnection attempts ({}) reached",
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

                // Track reconnect frequency in a 30 s sliding window. Under a
                // metro-tunnel network flap the previous code path (immediate
                // reconnect after a successful session) could churn 10+
                // reconnects in a minute, each allocating a fresh TLS session
                // + ratchet + tokio tasks. That's how the iOS extension trips
                // the per-process jetsam limit even when no single session is
                // heavy — the cumulative in-flight state from overlapping
                // teardowns pushes us past the cap.
                let recent_reconnects = {
                    let now = std::time::Instant::now();
                    let mut history = client.reconnect_history.lock().unwrap();
                    while let Some(&front) = history.front() {
                        if now.duration_since(front) > std::time::Duration::from_secs(30) {
                            history.pop_front();
                        } else {
                            break;
                        }
                    }
                    let n = history.len();
                    history.push_back(now);
                    n
                };

                // Base delay: none after a successful session (the network
                // path is fresh), exponential backoff after failures.
                let base_delay_ms: u64 = if had_successful_session {
                    had_successful_session = false;
                    0
                } else if attempts > 0 {
                    let initial_delay = client.reconnect_initial_delay_ms.load(Ordering::Relaxed);
                    let max_delay = client.reconnect_max_delay_ms.load(Ordering::Relaxed);
                    std::cmp::min(
                        initial_delay.saturating_mul(2u64.saturating_pow(attempts - 1)),
                        max_delay,
                    )
                } else {
                    0
                };

                // Flap-aware minimum backoff: after N reconnects in 30 s,
                // enforce a growing minimum delay regardless of whether the
                // previous session was "successful". The escalation stays
                // bounded by max_delay so a legitimate transition still
                // recovers quickly, but a signal-drop storm gets throttled
                // hard: 3 → 1s, 4 → 4s, 5 → 9s, 6 → 16s, 7 → 25s, …
                let max_delay = client.reconnect_max_delay_ms.load(Ordering::Relaxed);
                let flap_min_ms: u64 = if recent_reconnects >= 3 {
                    let n = (recent_reconnects - 2) as u64;
                    (1000u64.saturating_mul(n).saturating_mul(n)).min(max_delay.max(1000))
                } else {
                    0
                };
                let delay_ms = base_delay_ms.max(flap_min_ms);

                // Snapshot memory before the connect so we can attribute any
                // leak to a specific reconnect (Rust panics don't fire on
                // jetsam kills — this log is our only signal).
                let rss_before_kb = rss_bytes_now() / 1024;
                let headroom_before_kb = headroom_bytes_now() / 1024;
                info!(
                    "[IosTun] Reconnect: attempt={} recent_reconnects_30s={} delay={}ms (base={} flap_min={}) rss={}KB headroom={}KB",
                    attempts + 1,
                    recent_reconnects,
                    delay_ms,
                    base_delay_ms,
                    flap_min_ms,
                    rss_before_kb,
                    headroom_before_kb,
                );

                if delay_ms > 0 {
                    // Warm a transport in parallel with the backoff so the
                    // reconnect after the delay skips TCP + TLS + WS-upgrade.
                    client.spawn_preconnect_warmer();

                    // Sleep in small chunks so we can check reconnect_enabled mid-sleep
                    let sleep_start = tokio::time::Instant::now();
                    let sleep_duration = tokio::time::Duration::from_millis(delay_ms);
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
                        let rss_after_kb = rss_bytes_now() / 1024;
                        let headroom_after_kb = headroom_bytes_now() / 1024;
                        info!(
                            "[IosTun] Session ended: rss={}KB (Δ{:+}KB) headroom={}KB (Δ{:+}KB)",
                            rss_after_kb,
                            rss_after_kb as i64 - rss_before_kb as i64,
                            headroom_after_kb,
                            headroom_after_kb as i64 - headroom_before_kb as i64,
                        );
                        info!("[IosTun] Connection ended, reconnecting immediately...");
                        attempts = 0;
                        had_successful_session = true;
                    }
                    Err(e) => {
                        let rss_after_kb = rss_bytes_now() / 1024;
                        let headroom_after_kb = headroom_bytes_now() / 1024;
                        error!(
                            "[IosTun] Connection failed (attempt {}): {} — rss={}KB (Δ{:+}KB) headroom={}KB (Δ{:+}KB)",
                            attempts + 1,
                            e,
                            rss_after_kb,
                            rss_after_kb as i64 - rss_before_kb as i64,
                            headroom_after_kb,
                            headroom_after_kb as i64 - headroom_before_kb as i64,
                        );
                        attempts += 1;
                        // Surface the failure so the app can distinguish
                        // "retrying" from "connecting" — without this the
                        // state stays Connecting across every retry and the
                        // UI pins on "Reconnecting…" with no signal. The
                        // next attempt's connect() immediately flips the
                        // state back to Connecting, so the UI does not flap
                        // (Swift's .error handler only logs + reasserts).
                        // Skipped when reconnection was disabled mid-attempt
                        // (stopTunnel cancellation) to avoid a spurious error
                        // during teardown.
                        if client.reconnect_enabled.load(Ordering::Relaxed) {
                            client
                                .notify_state(
                                    TunClientState::Error,
                                    None,
                                    &format!(
                                        "Connection failed (attempt {}): {}",
                                        attempts, e
                                    ),
                                )
                                .await;
                        }
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

    /// Stop the session
    pub(crate) fn stop(&self) {
        let _ = self.shutdown_tx.send(());
        self.drop_pending("session stopped");
        // Reset is_started so the session can be restarted after a full stop
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
    pub(crate) fn request_reconnect(&self) {
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

    /// The TUN endpoint URL must gain a /tun suffix exactly once, however
    /// the profile's path is written (Swift profiles sometimes already
    /// include it).
    #[test]
    fn test_tun_url_suffix_handling() {
        assert_eq!(
            ServerSession::tun_url_for("s.example.com", 443, "/api/v1/ws"),
            "wss://s.example.com:443/api/v1/ws/tun"
        );
        assert_eq!(
            ServerSession::tun_url_for("s.example.com", 443, "/api/v1/ws/"),
            "wss://s.example.com:443/api/v1/ws/tun"
        );
        assert_eq!(
            ServerSession::tun_url_for("s.example.com", 443, "/api/v1/ws/tun"),
            "wss://s.example.com:443/api/v1/ws/tun"
        );
        assert_eq!(
            ServerSession::tun_url_for("s.example.com", 443, "/api/v1/ws/tun/"),
            "wss://s.example.com:443/api/v1/ws/tun"
        );
    }

    /// Build a non-default `ServerSession` over a throwaway runtime for
    /// pending-queue tests. The runtime is only needed for the `Handle` in
    /// `SharedContext`; nothing is spawned on it.
    fn test_session() -> (Arc<ServerSession>, tokio::runtime::Runtime) {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (to_swift_sender, _to_swift_rx) = mpsc::channel(16);
        let (packet_notify_tx, _notify_rx) = std::sync::mpsc::sync_channel(1);
        let shared = Arc::new(SharedContext {
            handle: rt.handle().clone(),
            identity_key: IdentityKey::generate(),
            to_swift_sender,
            packet_notify_tx,
            packet_pool: Arc::new(Mutex::new(VecPool::new(4))),
            state_callback: Arc::new(RwLock::new(None)),
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
        let session = Arc::new(ServerSession::new(
            shared,
            "127.0.0.1".to_string(),
            Some("127.0.0.1".parse().unwrap()),
            443,
            "/connect".to_string(),
            bundle,
            "ik:1:test".to_string(),
            64,    // chan_cap
            false, // is_default
            None,  // server_sni
            #[cfg(feature = "diagnostics")]
            None,
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
        session
            .enqueue_uplink(v4_packet(PRIMARY, dst, 1))
            .unwrap();
        session
            .enqueue_uplink(v4_packet(PRIMARY, dst, 2))
            .unwrap();
        assert_eq!(session.pending_uplink.lock().unwrap().len(), 2);
        {
            let mut rx = session.from_swift_receiver.blocking_lock();
            assert!(rx.try_recv().is_err(), "channel must stay empty pre-VirtualIp");
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
        session
            .enqueue_uplink(v4_packet(PRIMARY, dst, 9))
            .unwrap();
        assert!(session.pending_uplink.lock().unwrap().is_empty());
        let mut rx = session.from_swift_receiver.blocking_lock();
        let pkt = rx.try_recv().expect("packet should go straight to the channel");
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
        session
            .enqueue_uplink(v4_packet(PRIMARY, dst, 1))
            .unwrap();
        assert_eq!(session.pending_uplink.lock().unwrap().len(), 1);
        session.drop_pending("test");
        assert!(session.pending_uplink.lock().unwrap().is_empty());
    }
}
