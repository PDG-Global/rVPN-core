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
//!
//! State split: `AndroidTunClient` is the session manager — it holds only
//! the shared plumbing (runtime handle, config, identity key, downlink
//! channel to Kotlin, state callback) plus a `sessions` map with one
//! [`crate::android_server_session::AndroidServerSession`] per exit server
//! (`"default"` plus one per `TunConfig.extra_servers` entry). All
//! per-exit-server state and logic (connect, X3DH, packet relay, reconnect
//! loop) lives in `AndroidServerSession`. This mirrors the iOS/macOS
//! multi-server Direct TUN routing design — see the corresponding section in
//! AGENTS.md.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use parking_lot::RwLock;
use tokio::sync::{mpsc, Mutex};

use rvpn_core::crypto::{IdentityKey, X3DHPublicBundle};
use rvpn_split_tunnel::{Router, DEFAULT_SERVER_NAME};
use rvpn_tls::TlsFingerprint;

use crate::android_server_session::{AndroidServerSession, AndroidSharedContext};
use crate::ffi::{MobileServerEntry, TunConfig};
use crate::route_map::RouteMap;

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
    fn __android_log_write(
        prio: i32,
        tag: *const std::ffi::c_char,
        msg: *const std::ffi::c_char,
    ) -> i32;
}

#[cfg(target_os = "android")]
pub fn android_log(tag: &str, msg: &str, prio: i32) {
    use std::ffi::CString;
    if let (Ok(tag_c), Ok(msg_c)) = (CString::new(tag), CString::new(msg)) {
        unsafe { __android_log_write(prio, tag_c.as_ptr(), msg_c.as_ptr()) };
    }
}

/// Non-Android fallback so the session/demux code (and its unit tests)
/// compiles and runs on desktop hosts — the JNI layer itself stays
/// Android-target-only.
#[cfg(not(target_os = "android"))]
pub fn android_log(tag: &str, msg: &str, _prio: i32) {
    eprintln!("[{}] {}", tag, msg);
}

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
pub type StateCallback = Option<
    unsafe extern "C" fn(
        state: i32,
        ip: *const std::os::raw::c_char,
        msg: *const std::os::raw::c_char,
    ),
>;

/// AndroidTunClient - Direct TUN mode client for Android
///
/// Connects to the VPN server's `/tun` endpoint, performs X3DH handshake,
/// receives a VirtualIp assignment, and relays raw IP packets bidirectionally.
///
/// # Channel Design
/// - Android sends packets to server via `from_swift_sender` (mpsc::Sender)
/// - Android receives packets from server via `to_swift_receiver` (mpsc::Receiver)
///
/// Both are exposed via getters for Android to use.
///
/// # State Split
/// All per-exit-server state lives in [`AndroidServerSession`]; this struct
/// holds only the shared plumbing (runtime handle, config, identity key,
/// downlink channel to Kotlin, state callback) plus the `sessions` map, and
/// delegates every per-session operation. With `extra_servers` configured it
/// additionally demultiplexes uplink packets across exits (see
/// [`choose_exit_name`]).
pub struct AndroidTunClient {
    /// Configuration (kept for debugging and future reconnection support)
    /// Note: fields are extracted on construction to avoid per-packet locking
    #[allow(dead_code)]
    config: TunConfig,
    /// Receiver for packets to Android
    pub to_swift_receiver: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    /// Shared context handed to every `AndroidServerSession`: tokio runtime
    /// handle (NEVER the Runtime itself — it is owned by
    /// `android_tun_ffi::TUN_RUNTIME`; see the runtime-ownership section in
    /// AGENTS.md), client identity key, downlink sender, state callback.
    shared: Arc<AndroidSharedContext>,
    /// The single default exit-server session. All per-server state and
    /// logic (connect, X3DH, packet relay, reconnect loop) lives here.
    default_session: Arc<AndroidServerSession>,
    /// All sessions keyed by exit name: `"default"` (the same Arc as
    /// `default_session`) plus one per `extra_servers` entry. Extra sessions
    /// are created eagerly (cheap — no sockets) but started lazily via
    /// `ensure_session_started`.
    sessions: HashMap<String, Arc<AndroidServerSession>>,
    /// Compiled static routing rules (domain + CIDR). `None` when
    /// `extra_servers` is empty — the single-server fast path, where the
    /// uplink demux short-circuits before parsing anything.
    router: Option<Arc<Router>>,
    /// Dynamic per-IP exit routes learned from routed DNS answers, shared
    /// with the DNS layer (which inserts) and consulted by the uplink demux
    /// before the static table. `None` together with `router`.
    route_map: Option<Arc<std::sync::Mutex<RouteMap>>>,
    /// Stealth TLS fingerprint to use for the ClientHello (browser mimicry).
    /// Renamed from `tls_fingerprint` on the wire; kept at the client level
    /// because it drives the DNS proxy's FlowConnectorConfig (the tunnel
    /// transport itself is always rustls on Android).
    tls_fingerprint: TlsFingerprint,
}

impl AndroidTunClient {
    /// Create a new AndroidTunClient from configuration.
    ///
    /// `handle` must come from a `Runtime` owned by the FFI layer (see
    /// `android_tun_ffi::TUN_RUNTIME`). Storing only the Handle here prevents
    /// the Runtime from being transitively dropped inside a tokio worker,
    /// which would panic in `BlockingPool::shutdown`.
    pub fn new(config: &TunConfig, handle: tokio::runtime::Handle) -> Result<Self> {
        // Parse server URL
        let (host, port, path) = Self::parse_server_url(&config.server_address)?;

        // Pre-resolve server hostname to IP to avoid DNS circular dependency during reconnect.
        // When the VPN is active, system DNS is redirected to our DNS proxy (127.0.0.1:5353).
        // If the TUN tunnel dies and tries to reconnect, resolving the server hostname would
        // go through our proxy → DoH client → dead connection → resolution fails forever.
        // By resolving here (before DNS is hijacked), we use the IP directly for all reconnects.
        let server_ip = if let Ok(ip) = host.parse::<IpAddr>() {
            ip
        } else {
            let mut addrs = std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", host, port))
                .with_context(|| format!("Failed to resolve server hostname: {}", host))?;
            addrs
                .next()
                .map(|a| a.ip())
                .context("DNS resolution returned no addresses for server")?
        };
        tun_log!("[AndroidTun] Server {} resolved to {}", host, server_ip);

        // Load identity key (blocking I/O)
        let identity_key_path = std::path::PathBuf::from(&config.identity_key_path);
        let identity_key =
            IdentityKey::load(&identity_key_path).context("Failed to load identity key")?;

        // Load prekey bundle and enforce the TOFU pin (if configured) for the
        // default server.
        let (server_bundle, server_identity_pin_actual) = Self::load_bundle_and_pin(
            &config.prekey_bundle_path,
            config.server_identity_pin.as_deref(),
        )?;

        // Parse stealth ClientHello fingerprint (default to Chrome).
        let tls_fingerprint = config
            .stealth_fingerprint
            .as_deref()
            .and_then(rvpn_tls::fingerprint_from_str)
            .unwrap_or(TlsFingerprint::Chrome);

        // Create channels for Android TUN communication.
        // to_swift_receiver is used by Android to receive packets from server (via recv_packet_from_server)
        let (to_swift_sender, to_swift_receiver) = mpsc::channel::<Vec<u8>>(1000);

        // Uplink channel capacity per session.
        let chan_cap = 1000;

        // NOTE: Runtime is created by the FFI layer (see
        // `android_tun_ffi::create_tun_client_impl`) and passed in as
        // `handle`. Keeping the Runtime out of this struct (and out of
        // `AndroidSharedContext` / `AndroidServerSession`) prevents it from
        // being dropped on a tokio worker thread when the last Arc ref drops,
        // which would panic in `BlockingPool::shutdown`.
        let shared = Arc::new(AndroidSharedContext {
            handle,
            identity_key,
            to_swift_sender,
            state_callback: Arc::new(RwLock::new(None)),
            primary_tunnel_ip: Arc::new(std::sync::Mutex::new(None)),
        });

        let default_session = Arc::new(AndroidServerSession::new(
            Arc::clone(&shared),
            host,
            server_ip,
            port,
            path,
            server_bundle,
            server_identity_pin_actual,
            chan_cap,
            true, // is_default
        ));

        // --- Multi-server setup (no-op when extra_servers is empty) ---
        let mut sessions: HashMap<String, Arc<AndroidServerSession>> = HashMap::new();
        sessions.insert(
            DEFAULT_SERVER_NAME.to_string(),
            Arc::clone(&default_session),
        );

        let mut router: Option<Arc<Router>> = None;
        let mut route_map: Option<Arc<std::sync::Mutex<RouteMap>>> = None;
        if !config.extra_servers.is_empty() {
            Self::validate_extra_server_names(&config.extra_servers)?;

            let mut known: Vec<&str> = vec![DEFAULT_SERVER_NAME];
            for entry in &config.extra_servers {
                let (host, port, path) = Self::parse_server_url(&entry.address)
                    .with_context(|| format!("extraServers[{}]: invalid address", entry.name))?;
                // Pre-resolve to an IP for the same DNS-circularity reason as
                // the default server (see above). Blocking I/O is fine here —
                // this runs before the tunnel hijacks DNS.
                let server_ip = if let Ok(ip) = host.parse::<IpAddr>() {
                    ip
                } else {
                    let mut addrs =
                        std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", host, port))
                            .with_context(|| {
                                format!("extraServers[{}]: failed to resolve {}", entry.name, host)
                            })?;
                    addrs.next().map(|a| a.ip()).with_context(|| {
                        format!("extraServers[{}]: DNS returned no addresses", entry.name)
                    })?
                };
                tun_log!(
                    "[AndroidTun] Extra exit '{}' ({}): resolved to {}",
                    entry.name,
                    host,
                    server_ip
                );

                let (bundle, pin) = Self::load_bundle_and_pin(
                    &entry.prekey_bundle_path,
                    entry.server_identity_pin.as_deref(),
                )
                .with_context(|| format!("extraServers[{}]", entry.name))?;

                let session = Arc::new(AndroidServerSession::new(
                    Arc::clone(&shared),
                    host,
                    server_ip,
                    port,
                    path,
                    bundle,
                    pin,
                    chan_cap,
                    false, // is_default
                ));
                sessions.insert(entry.name.clone(), session);
                known.push(entry.name.as_str());
            }

            let built = Router::build(&known, &config.routing)
                .context("invalid multi-server routing rules")?;
            let (domain_rules, ip_rules) = built.rule_count();
            tun_log!(
                "[AndroidTun] Multi-server routing: {} extra exit(s), {} domain rule(s), {} IP rule(s)",
                config.extra_servers.len(),
                domain_rules,
                ip_rules
            );
            router = Some(Arc::new(built));
            route_map = Some(Arc::new(std::sync::Mutex::new(RouteMap::new())));
        } else if !config.routing.is_empty() {
            anyhow::bail!(
                "routing rules require extraServers entries; with a single server every flow already uses it"
            );
        }

        Ok(Self {
            config: config.clone(),
            to_swift_receiver: Arc::new(Mutex::new(to_swift_receiver)),
            shared,
            default_session,
            sessions,
            router,
            route_map,
            tls_fingerprint,
        })
    }

    /// Load a server prekey bundle from disk and compute its canonical TOFU
    /// pin. If `expected_pin` is set, enforce equality before proceeding —
    /// after this point we start opening TCP + WebSocket connections to the
    /// server, so failing fast keeps a wrong-identity connection from ever
    /// going on the wire. The `Error::ServerIdentityMismatch` variant is what
    /// the FFI layer downcasts to produce the `IDENTITY_MISMATCH
    /// expected=... actual=...` prefix the app parses.
    fn load_bundle_and_pin(
        prekey_bundle_path: &str,
        expected_pin: Option<&str>,
    ) -> Result<(X3DHPublicBundle, String)> {
        let bundle_json =
            std::fs::read_to_string(prekey_bundle_path).context("Failed to read prekey bundle")?;
        let server_bundle: X3DHPublicBundle =
            serde_json::from_str(&bundle_json).context("Failed to parse prekey bundle JSON")?;

        let pin_actual = rvpn_core::identity_pin::encode_identity_pin(&server_bundle.identity_key)
            .context("Failed to encode server identity pin")?;
        if let Some(expected) = expected_pin {
            let matched =
                rvpn_core::identity_pin::pins_match(expected, &server_bundle.identity_key)
                    .context("Configured server_identity_pin is not a valid pin string")?;
            if !matched {
                return Err(anyhow::Error::from(
                    rvpn_core::Error::ServerIdentityMismatch {
                        expected: expected.to_string(),
                        actual: pin_actual,
                    },
                ));
            }
        }
        Ok((server_bundle, pin_actual))
    }

    /// Validate extra-server names: non-empty, unique, and not the reserved
    /// `"default"` (the top-level server_address already occupies that name).
    fn validate_extra_server_names(entries: &[MobileServerEntry]) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for entry in entries {
            if entry.name.is_empty() {
                anyhow::bail!("extraServers entry with empty name");
            }
            if entry.name == DEFAULT_SERVER_NAME {
                anyhow::bail!(
                    "extraServers name '{}' is reserved for the top-level server",
                    DEFAULT_SERVER_NAME
                );
            }
            if !seen.insert(entry.name.as_str()) {
                anyhow::bail!("duplicate extraServers name '{}'", entry.name);
            }
        }
        Ok(())
    }

    /// Parse server URL into (host, port, path) — no url crate dependency
    pub fn parse_server_url(server_address: &str) -> Result<(String, u16, String)> {
        let rest = server_address
            .strip_prefix("wss://")
            .or_else(|| server_address.strip_prefix("ws://"))
            .unwrap_or(server_address);
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", path)
        };
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

    /// Get the runtime handle for spawning tasks
    pub fn runtime_handle(&self) -> tokio::runtime::Handle {
        self.shared.handle.clone()
    }

    /// Set the state callback for Android notifications
    pub fn set_state_callback(&self, callback: StateCallback) {
        let mut guard = self.shared.state_callback.write();
        *guard = callback;
    }

    /// Get the assigned tunnel IP (default session)
    pub fn get_tunnel_ip(&self) -> Option<String> {
        self.default_session.get_tunnel_ip()
    }

    /// Get the DNS servers from VirtualIp (default session)
    pub fn get_dns_servers(&self) -> Vec<std::net::IpAddr> {
        self.default_session.get_dns_servers()
    }

    /// Get the MTU from VirtualIp (default session)
    pub fn get_mtu(&self) -> u16 {
        self.default_session.get_mtu()
    }

    /// Get current state (default session — secondary exits are an internal
    /// routing detail and never perturb the app's view of the tunnel)
    pub fn get_state(&self) -> TunClientState {
        self.default_session.get_state()
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
    #[allow(dead_code)] // Used by the DNS proxy startup in android_tun_ffi.rs (dns feature)
    pub(crate) fn identity_key(&self) -> &IdentityKey {
        &self.shared.identity_key
    }

    /// Get server bundle reference (default session)
    #[allow(dead_code)] // Used by the DNS proxy startup in android_tun_ffi.rs (dns feature)
    pub(crate) fn server_bundle(&self) -> &X3DHPublicBundle {
        self.default_session.server_bundle()
    }

    /// Get server host (default session)
    pub fn server_host(&self) -> &str {
        self.default_session.server_host()
    }

    /// Get server port (default session)
    pub fn server_port(&self) -> u16 {
        self.default_session.server_port()
    }

    /// Get server path (default session)
    pub fn server_path(&self) -> &str {
        self.default_session.server_path()
    }

    /// Get TLS fingerprint
    pub fn tls_fingerprint(&self) -> TlsFingerprint {
        self.tls_fingerprint
    }

    /// Canonical `ik:1:<base32>` pin of the server this client was
    /// constructed against — read by the JNI wrapper for
    /// `rvpn_tun_get_server_identity()` after `Connected`.
    pub fn server_identity_pin(&self) -> &str {
        self.default_session.server_identity_pin()
    }

    /// Canonical `ik:1:<base32>` pin of the named exit server, for per-exit
    /// TOFU pin capture. Returns `None` for unknown names.
    pub fn server_identity_pin_for(&self, name: &str) -> Option<String> {
        self.sessions
            .get(name)
            .map(|s| s.server_identity_pin().to_string())
    }

    /// The compiled multi-server router, if any (shared with the DNS layer).
    #[allow(dead_code)] // Used by the DNS proxy startup in android_tun_ffi.rs (dns feature)
    pub(crate) fn router(&self) -> Option<Arc<Router>> {
        self.router.clone()
    }

    /// The dynamic route map, if any (shared with the DNS layer).
    #[allow(dead_code)] // Used by the DNS proxy startup in android_tun_ffi.rs (dns feature)
    pub(crate) fn route_map(&self) -> Option<Arc<std::sync::Mutex<RouteMap>>> {
        self.route_map.clone()
    }

    /// Per-extra-exit connection info for the DNS layer's DoH client pool:
    /// (name, host, port, base path, prekey bundle). Empty when single-server.
    #[allow(dead_code)] // Used by the DNS proxy startup in android_tun_ffi.rs (dns feature)
    pub(crate) fn extra_session_dns_info(
        &self,
    ) -> Vec<(String, String, u16, String, X3DHPublicBundle)> {
        self.sessions
            .iter()
            .filter(|(name, _)| name.as_str() != DEFAULT_SERVER_NAME)
            .map(|(name, s)| {
                (
                    name.clone(),
                    s.server_host().to_string(),
                    s.server_port(),
                    s.server_path().to_string(),
                    s.server_bundle().clone(),
                )
            })
            .collect()
    }

    /// Send a packet to the server (call this from Android)
    /// Android calls this to send packets to be relayed to the server
    pub async fn send_packet_to_server(&self, packet: Vec<u8>) -> Result<()> {
        match self.choose_exit(&packet) {
            None => self.default_session.send_packet_to_server(packet).await,
            Some(name) => {
                self.ensure_session_started(&name);
                match self.sessions.get(&name) {
                    Some(session) => session
                        .enqueue_uplink(packet)
                        .map_err(|e| anyhow::anyhow!("Failed to send packet: {}", e)),
                    None => self.default_session.send_packet_to_server(packet).await,
                }
            }
        }
    }

    /// Non-blocking send for FFI hot path (avoids block_on deadlock)
    pub fn try_send_packet(
        &self,
        packet: Vec<u8>,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<Vec<u8>>> {
        match self.choose_exit(&packet) {
            // Single-server fast path (router is None) and default-routed
            // packets take exactly today's path — no rewrite, no stash.
            None => self.default_session.try_send_packet(packet),
            Some(name) => {
                self.ensure_session_started(&name);
                match self.sessions.get(&name) {
                    Some(session) => session.enqueue_uplink(packet),
                    None => self.default_session.try_send_packet(packet),
                }
            }
        }
    }

    /// Decide which exit session an Android-originated packet should use.
    /// Returns `None` for the default exit (single-server configs, non-IPv4
    /// or unparseable packets, and anything no rule matches).
    fn choose_exit(&self, packet: &[u8]) -> Option<String> {
        choose_exit_name(self.router.as_deref(), self.route_map.as_deref(), packet)
    }

    /// Start the named session's connect/reconnect loop if it isn't running
    /// yet (lazy start for secondary exits). Idempotent — `start()` guards
    /// with a compare-exchange; the early `is_started` check just avoids log
    /// noise. Called from the uplink demux on the first routed packet and
    /// from the DNS layer's pre-warm hook when a routed domain is resolved.
    pub fn ensure_session_started(&self, name: &str) {
        let Some(session) = self.sessions.get(name) else {
            return;
        };
        if session.is_started() {
            return;
        }
        tun_log!("[AndroidTun] Lazy-starting session for exit '{}'", name);
        session.set_reconnect_enabled(true);
        session.start();
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
    /// Starts the default session's reconnect loop; secondary sessions start
    /// lazily via `ensure_session_started` on the first routed packet.
    /// Idempotent — repeated calls are no-ops while the loop is running.
    pub fn start(self: &Arc<Self>) {
        self.default_session.start();
    }

    /// Stop the client (disables reconnection and tears down the relays).
    pub fn stop(&self) {
        // Fan out to every session: a lazy secondary loop must be silenced
        // too, not just the default.
        for session in self.sessions.values() {
            session.stop();
        }
    }

    /// Enable / disable the reconnect loop. FFI `rvpnTunStart` calls this with
    /// `true` before spawning `start()`.
    pub fn set_reconnect_enabled(&self, enabled: bool) {
        // Applies to every session: disabling on stop must silence lazy
        // secondary loops too; enabling on start is harmless for sessions
        // that haven't been started yet (the flag is only read by start()).
        for session in self.sessions.values() {
            session.set_reconnect_enabled(enabled);
        }
    }

    /// Check if reconnection is enabled
    pub fn is_reconnect_enabled(&self) -> bool {
        self.default_session.is_reconnect_enabled()
    }

    /// Set maximum reconnection attempts (0 = unlimited)
    #[allow(dead_code)] // JNI surface parity with iOS; no Kotlin caller yet.
    pub fn set_reconnect_max_attempts(&self, attempts: u32) {
        self.default_session.set_reconnect_max_attempts(attempts);
    }

    /// Set initial reconnection delay (ms)
    #[allow(dead_code)] // JNI surface parity with iOS; no Kotlin caller yet.
    pub fn set_reconnect_initial_delay_ms(&self, delay_ms: u64) {
        self.default_session
            .set_reconnect_initial_delay_ms(delay_ms);
    }

    /// Set maximum reconnection delay (ms)
    #[allow(dead_code)] // JNI surface parity with iOS; no Kotlin caller yet.
    pub fn set_reconnect_max_delay_ms(&self, delay_ms: u64) {
        self.default_session.set_reconnect_max_delay_ms(delay_ms);
    }

    /// Request a gentle reconnect without disabling the reconnect loop.
    ///
    /// Called from `rvpnNetworkChanged` when the Android NetworkCallback reports
    /// a network transition. A network change kills every open connection, so
    /// this nudges every session that has been started; each session has its
    /// own 5-second cooldown against reconnect storms from rapid
    /// NetworkCallback notifications during handoffs.
    pub fn request_reconnect(&self) {
        for session in self.sessions.values() {
            if session.is_started() {
                session.request_reconnect();
            }
        }
    }
}

/// Decide which named exit an Android-originated uplink packet should use.
///
/// Lookup order: (a) dynamic route map (unexpired DNS-learned entries),
/// (b) static CIDR rules via `router.choose_ip`, (c) `None` = default exit.
///
/// Returns `None` immediately when `router` is `None` (single-server config)
/// so the Play-Store-shipped fast path pays only one Option check — no packet
/// parsing at all. Non-IPv4 or unparseable packets also return `None`.
///
/// Free function (not a method) so the demux policy is unit-testable without
/// constructing an `AndroidTunClient` (which needs keys, bundles, and DNS).
/// Mirrors `choose_exit_name` in ios_tun.rs — keep the two in sync.
pub(crate) fn choose_exit_name(
    router: Option<&Router>,
    route_map: Option<&std::sync::Mutex<RouteMap>>,
    packet: &[u8],
) -> Option<String> {
    let router = router?;
    // IPv4 base header: version nibble + enough bytes for the dst address.
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let dst = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));

    // (a) Dynamic DNS-learned routes win over static CIDR rules: the exit
    // that resolved the domain knows the answer's addresses freshest.
    if let Some(route_map) = route_map {
        if let Some(name) = route_map.lock().unwrap().lookup(&dst) {
            return Some(name);
        }
    }

    // (b) Static CIDR rules.
    let chosen = router.choose_ip(dst);
    if chosen == DEFAULT_SERVER_NAME {
        None
    } else {
        Some(chosen.to_string())
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
        let (host, port, path) =
            AndroidTunClient::parse_server_url("wss://test.example.com:443/api/v1/ws").unwrap();
        assert_eq!(host, "test.example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api/v1/ws");

        let (host, port, path) =
            AndroidTunClient::parse_server_url("wss://test.example.com:443/api/v1/ws/").unwrap();
        assert_eq!(host, "test.example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api/v1/ws/");
    }

    fn extra_entry(name: &str) -> MobileServerEntry {
        MobileServerEntry {
            name: name.to_string(),
            address: "wss://127.0.0.1:443/connect".to_string(),
            prekey_bundle_path: "/nonexistent/bundle.json".to_string(),
            server_identity_pin: None,
            sni_hostname: None,
        }
    }

    #[test]
    fn test_validate_extra_server_names() {
        // Valid: distinct, non-reserved names.
        assert!(AndroidTunClient::validate_extra_server_names(&[
            extra_entry("sg"),
            extra_entry("us")
        ])
        .is_ok());

        // Reserved name rejected.
        let err = AndroidTunClient::validate_extra_server_names(&[extra_entry("default")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("reserved"), "unexpected error: {}", err);

        // Duplicates rejected.
        let err =
            AndroidTunClient::validate_extra_server_names(&[extra_entry("sg"), extra_entry("sg")])
                .unwrap_err()
                .to_string();
        assert!(err.contains("duplicate"), "unexpected error: {}", err);

        // Empty name rejected.
        let err = AndroidTunClient::validate_extra_server_names(&[extra_entry("")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty"), "unexpected error: {}", err);
    }

    /// Minimal IPv4 packet (header only) with the given dst address.
    fn v4_packet(dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[16..20].copy_from_slice(&dst.octets());
        p
    }

    fn test_router() -> Router {
        let mut routing: HashMap<String, rvpn_split_tunnel::RoutingRule> = HashMap::new();
        routing.insert(
            "sg".to_string(),
            rvpn_split_tunnel::RoutingRule {
                domains: vec!["routed.example.com".to_string()],
                ips: vec!["8.8.8.0/24".to_string()],
            },
        );
        Router::build(&[DEFAULT_SERVER_NAME, "sg"], &routing).unwrap()
    }

    #[test]
    fn test_choose_exit_name_fast_path() {
        // No router (single-server): always default, even for a packet that
        // would match a rule — this is the zero-overhead Play Store path.
        let packet = v4_packet(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(choose_exit_name(None, None, &packet), None);

        // Non-IPv4 and truncated packets go to default.
        let router = test_router();
        let route_map = std::sync::Mutex::new(RouteMap::new());
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        assert_eq!(choose_exit_name(Some(&router), Some(&route_map), &v6), None);
        assert_eq!(
            choose_exit_name(Some(&router), Some(&route_map), &packet[..10]),
            None
        );
    }

    #[test]
    fn test_choose_exit_name_static_rule() {
        let router = test_router();
        let route_map = std::sync::Mutex::new(RouteMap::new());
        // Static CIDR rule match.
        assert_eq!(
            choose_exit_name(
                Some(&router),
                Some(&route_map),
                &v4_packet(Ipv4Addr::new(8, 8, 8, 8))
            )
            .as_deref(),
            Some("sg")
        );
        // No match → default.
        assert_eq!(
            choose_exit_name(
                Some(&router),
                Some(&route_map),
                &v4_packet(Ipv4Addr::new(9, 9, 9, 9))
            ),
            None
        );
    }

    #[test]
    fn test_choose_exit_name_dynamic_overrides_static() {
        let router = test_router();
        let route_map = std::sync::Mutex::new(RouteMap::new());
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        // A DNS-learned route to a different exit beats the static CIDR rule.
        route_map.lock().unwrap().insert(
            IpAddr::V4(dst),
            "hk",
            std::time::Duration::from_secs(300),
        );
        assert_eq!(
            choose_exit_name(Some(&router), Some(&route_map), &v4_packet(dst)).as_deref(),
            Some("hk")
        );
    }

    #[test]
    fn test_choose_exit_name_expired_dynamic_falls_through() {
        let router = test_router();
        let route_map = std::sync::Mutex::new(RouteMap::new());
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        route_map
            .lock()
            .unwrap()
            .insert(IpAddr::V4(dst), "hk", std::time::Duration::from_secs(0));
        // Expired dynamic entry → static rule decides.
        assert_eq!(
            choose_exit_name(Some(&router), Some(&route_map), &v4_packet(dst)).as_deref(),
            Some("sg")
        );
        // And with no static match, an expired entry falls back to default.
        let other = Ipv4Addr::new(1, 2, 3, 4);
        route_map.lock().unwrap().insert(
            IpAddr::V4(other),
            "hk",
            std::time::Duration::from_secs(0),
        );
        assert_eq!(
            choose_exit_name(Some(&router), Some(&route_map), &v4_packet(other)),
            None
        );
    }
}
