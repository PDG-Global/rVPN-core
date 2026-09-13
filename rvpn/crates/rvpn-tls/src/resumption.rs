// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Shared TLS session resumption store.
//
// R-VPN clients reconnect to the same exit server frequently (connection-pool
// rotation, network flaps). Without resumption every reconnect is a full TLS
// handshake: 2-RTT, a certificate flight, and — just as important for a stealth
// VPN — a ClientHello with no ticket, which no real returning browser sends.
//
// [`ResumptionStore`] is a cheaply-cloneable (`Arc` inside), bounded, in-memory
// cache of TLS session state, intended to be held **per exit server** by the
// caller and passed to the backend connect functions:
//
// * rustls backend: the store implements [`rustls::client::ClientSessionStore`]
//   and is installed via [`rustls::client::Resumption::store`] on a dedicated
//   `ClientConfig` (see `tls_rustls::connect_rustls_with_store`).
// * boring backend: the store keeps the latest `SSL_SESSION` (TLS 1.3 ticket)
//   per server name, captured through BoringSSL's new-session callback, and the
//   connect path offers it via `SSL_set_session` on the next handshake (see
//   `tls_boring::connect_chrome_like_with_resumption`).
//
// Both backends fall back to a full handshake transparently when no ticket is
// cached or the server declines resumption, so attaching a store is always
// safe. Default behavior (no store) is unchanged.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

/// Default bound on the number of server entries kept in a [`ResumptionStore`].
///
/// The store is meant to be per-exit-server, so even a handful of entries
/// suffices; 128 leaves generous headroom for callers that share one store
/// across exits.
pub const DEFAULT_CAPACITY: usize = 128;

/// Maximum TLS 1.3 tickets kept per server name (mirrors rustls's own
/// `ClientSessionMemoryCache`). Servers typically hand out 2–4 tickets per
/// connection; each resumed handshake replenishes the pool.
#[cfg(feature = "rustls")]
const MAX_TICKETS_PER_SERVER: usize = 8;

/// A shared, bounded, in-memory TLS session resumption store.
///
/// Clone freely — all clones share the same underlying state. See the module
/// documentation for how each backend consumes it.
#[derive(Clone)]
pub struct ResumptionStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    capacity: usize,
    #[cfg(feature = "rustls")]
    rustls: RustlsSide,
    #[cfg(all(feature = "boring", not(target_os = "android")))]
    boring: BoringSide,
}

impl ResumptionStore {
    /// Create a store with the default capacity ([`DEFAULT_CAPACITY`] server
    /// entries).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create a store that keeps at most `capacity` server entries. When the
    /// bound is exceeded, the least recently *inserted* server entry is
    /// evicted (simple FIFO eviction — resumption state is ephemeral by
    /// nature, tickets expire within hours anyway).
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Arc::new(StoreInner {
                capacity: capacity.max(1),
                #[cfg(feature = "rustls")]
                rustls: RustlsSide::new(),
                #[cfg(all(feature = "boring", not(target_os = "android")))]
                boring: BoringSide::new(),
            }),
        }
    }

    /// The configured bound on server entries.
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }
}

impl Default for ResumptionStore {
    fn default() -> Self {
        Self::new()
    }
}

// Deliberately print only structure — never key material. rustls requires
// `Debug` on `ClientSessionStore` implementors.
impl fmt::Debug for ResumptionStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("ResumptionStore");
        d.field("capacity", &self.inner.capacity);
        #[cfg(feature = "rustls")]
        d.field("rustls_servers", &self.inner.rustls.server_count());
        #[cfg(all(feature = "boring", not(target_os = "android")))]
        d.field("boring_sessions", &self.inner.boring.session_count());
        d.finish()
    }
}

// ---------------------------------------------------------------------------
// rustls backend
// ---------------------------------------------------------------------------

#[cfg(feature = "rustls")]
struct RustlsSide {
    state: Mutex<RustlsState>,
    /// Per-store cached `ClientConfig`, built by
    /// `tls_rustls::build_client_config` on first use. Reusing one config per
    /// store avoids rebuilding the bundled root store and Chrome-order
    /// `CryptoProvider` on every reconnect.
    config: std::sync::OnceLock<Arc<rustls::ClientConfig>>,
}

#[cfg(feature = "rustls")]
#[derive(Default)]
struct RustlsState {
    /// FIFO of server names for eviction, oldest first.
    order: VecDeque<rustls::pki_types::ServerName<'static>>,
    kx_hints: HashMap<rustls::pki_types::ServerName<'static>, rustls::NamedGroup>,
    tls12: HashMap<rustls::pki_types::ServerName<'static>, rustls::client::Tls12ClientSessionValue>,
    tls13: HashMap<
        rustls::pki_types::ServerName<'static>,
        VecDeque<rustls::client::Tls13ClientSessionValue>,
    >,
}

#[cfg(feature = "rustls")]
impl RustlsSide {
    fn new() -> Self {
        Self {
            state: Mutex::new(RustlsState::default()),
            config: std::sync::OnceLock::new(),
        }
    }

    fn server_count(&self) -> usize {
        self.state.lock().unwrap().order.len()
    }
}

#[cfg(feature = "rustls")]
impl RustlsState {
    /// Register `name` in the eviction FIFO if it carries no state yet, then
    /// evict oldest servers until within `capacity`.
    fn note_server(&mut self, name: &rustls::pki_types::ServerName<'static>, capacity: usize) {
        let known = self.kx_hints.contains_key(name)
            || self.tls12.contains_key(name)
            || self.tls13.contains_key(name);
        if !known {
            self.order.push_back(name.clone());
        }
        while self.order.len() > capacity {
            if let Some(old) = self.order.pop_front() {
                self.kx_hints.remove(&old);
                self.tls12.remove(&old);
                self.tls13.remove(&old);
            }
        }
    }

    /// Drop `name` from the eviction FIFO once it carries no state at all
    /// (e.g. its last ticket was taken and spent).
    fn forget_if_empty(&mut self, name: &rustls::pki_types::ServerName<'static>) {
        let empty = !self.kx_hints.contains_key(name)
            && !self.tls12.contains_key(name)
            && self.tls13.get(name).map_or(true, VecDeque::is_empty);
        if empty {
            self.order.retain(|n| n != name);
        }
    }
}

#[cfg(feature = "rustls")]
impl ResumptionStore {
    /// View this store as a rustls [`rustls::client::ClientSessionStore`],
    /// ready to install via [`rustls::client::Resumption::store`].
    pub fn rustls_session_store(&self) -> Arc<dyn rustls::client::ClientSessionStore> {
        Arc::new(self.clone())
    }

    /// Return the cached `ClientConfig` for this store, building it with
    /// `build` on first use. If two threads race, the winner's instance is
    /// kept so all connections through one store share one config.
    pub(crate) fn rustls_config_or_init(
        &self,
        build: impl FnOnce() -> anyhow::Result<Arc<rustls::ClientConfig>>,
    ) -> anyhow::Result<Arc<rustls::ClientConfig>> {
        if let Some(config) = self.inner.rustls.config.get() {
            return Ok(Arc::clone(config));
        }
        let config = build()?;
        Ok(Arc::clone(self.inner.rustls.config.get_or_init(|| config)))
    }

    /// Number of TLS 1.3 tickets cached for `server_name`. Test helper.
    #[cfg(test)]
    pub(crate) fn rustls_tls13_ticket_count(
        &self,
        server_name: &rustls::pki_types::ServerName<'static>,
    ) -> usize {
        self.inner
            .rustls
            .state
            .lock()
            .unwrap()
            .tls13
            .get(server_name)
            .map_or(0, VecDeque::len)
    }
}

#[cfg(feature = "rustls")]
impl rustls::client::ClientSessionStore for ResumptionStore {
    fn set_kx_hint(
        &self,
        server_name: rustls::pki_types::ServerName<'static>,
        group: rustls::NamedGroup,
    ) {
        let mut state = self.inner.rustls.state.lock().unwrap();
        state.note_server(&server_name, self.inner.capacity);
        state.kx_hints.insert(server_name, group);
    }

    fn kx_hint(
        &self,
        server_name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::NamedGroup> {
        self.inner
            .rustls
            .state
            .lock()
            .unwrap()
            .kx_hints
            .get(server_name)
            .copied()
    }

    fn set_tls12_session(
        &self,
        server_name: rustls::pki_types::ServerName<'static>,
        value: rustls::client::Tls12ClientSessionValue,
    ) {
        let mut state = self.inner.rustls.state.lock().unwrap();
        state.note_server(&server_name, self.inner.capacity);
        state.tls12.insert(server_name, value);
    }

    fn tls12_session(
        &self,
        server_name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        self.inner
            .rustls
            .state
            .lock()
            .unwrap()
            .tls12
            .get(server_name)
            .cloned()
    }

    fn remove_tls12_session(&self, server_name: &rustls::pki_types::ServerName<'static>) {
        let mut state = self.inner.rustls.state.lock().unwrap();
        state.tls12.remove(server_name);
        state.forget_if_empty(server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: rustls::pki_types::ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        let mut state = self.inner.rustls.state.lock().unwrap();
        state.note_server(&server_name, self.inner.capacity);
        let tickets = state.tls13.entry(server_name).or_default();
        if tickets.len() >= MAX_TICKETS_PER_SERVER {
            tickets.pop_front();
        }
        tickets.push_back(value);
    }

    fn take_tls13_ticket(
        &self,
        server_name: &rustls::pki_types::ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        // The trait contract requires each ticket to be returned at most once
        // (TLS 1.3 tickets are single-use by design), so pop rather than peek.
        let mut state = self.inner.rustls.state.lock().unwrap();
        let ticket = state
            .tls13
            .get_mut(server_name)
            .and_then(VecDeque::pop_front);
        state.forget_if_empty(server_name);
        ticket
    }
}

// ---------------------------------------------------------------------------
// boring (BoringSSL) backend
// ---------------------------------------------------------------------------

#[cfg(all(feature = "boring", not(target_os = "android")))]
struct BoringSide {
    state: Mutex<BoringState>,
    /// Per-store cached `SslConnector`, built by `tls_boring` on first use.
    ///
    /// Sessions are only ever offered to `Ssl` objects minted from THIS
    /// context, which is what makes the `unsafe` `SslRef::set_session` call
    /// in `tls_boring` sound (its contract requires session and connection
    /// to share the `SslContext`).
    connector: std::sync::OnceLock<boring::ssl::SslConnector>,
}

#[cfg(all(feature = "boring", not(target_os = "android")))]
#[derive(Default)]
struct BoringState {
    /// FIFO of server names for eviction, oldest first.
    order: VecDeque<String>,
    /// Latest TLS 1.3 ticket per server name (keyed by SNI hostname).
    sessions: HashMap<String, boring::ssl::SslSession>,
}

#[cfg(all(feature = "boring", not(target_os = "android")))]
impl BoringSide {
    fn new() -> Self {
        Self {
            state: Mutex::new(BoringState::default()),
            connector: std::sync::OnceLock::new(),
        }
    }

    fn session_count(&self) -> usize {
        self.state.lock().unwrap().sessions.len()
    }
}

#[cfg(all(feature = "boring", not(target_os = "android")))]
impl ResumptionStore {
    /// Slot holding the `SslConnector` sessions from this store belong to.
    /// `tls_boring` initializes it lazily on first resumable connect.
    pub(crate) fn boring_connector_slot(&self) -> &std::sync::OnceLock<boring::ssl::SslConnector> {
        &self.inner.boring.connector
    }

    /// Record the newest ticket for `server_name` (called from the
    /// new-session callback; may fire multiple times per connection).
    fn boring_record_session(&self, server_name: &str, session: boring::ssl::SslSession) {
        let mut state = self.inner.boring.state.lock().unwrap();
        if !state.sessions.contains_key(server_name) {
            state.order.push_back(server_name.to_owned());
        }
        state.sessions.insert(server_name.to_owned(), session);
        while state.sessions.len() > self.inner.capacity {
            if let Some(old) = state.order.pop_front() {
                state.sessions.remove(&old);
            }
        }
    }

    /// Take the cached ticket for `server_name`, if any.
    ///
    /// The ticket is removed (single-use, like rustls's `take_tls13_ticket`):
    /// a successfully resumed connection receives fresh tickets from the
    /// server, which the new-session callback records back into the store.
    pub(crate) fn boring_take_session(&self, server_name: &str) -> Option<boring::ssl::SslSession> {
        let mut state = self.inner.boring.state.lock().unwrap();
        let session = state.sessions.remove(server_name);
        if session.is_some() {
            state.order.retain(|n| n != server_name);
        }
        session
    }

    /// Number of cached boring-side sessions. Test helper.
    #[cfg(test)]
    pub(crate) fn boring_session_count(&self) -> usize {
        self.inner.boring.session_count()
    }
}

/// Build the BoringSSL new-session callback recording tickets into `store`.
///
/// BoringSSL invokes it for every negotiated session — for TLS 1.3 that means
/// once per NewSessionTicket post-handshake message, which is exactly when
/// tickets become available (unlike TLS 1.2, `SslRef::session` right after the
/// handshake does NOT hold a resumable ticket).
#[cfg(all(feature = "boring", not(target_os = "android")))]
pub(crate) fn boring_new_session_callback(
    store: &ResumptionStore,
) -> impl Fn(&mut boring::ssl::SslRef, boring::ssl::SslSession) + Send + Sync + 'static {
    // Weak, not strong: the callback is owned by the connector, which is
    // cached inside the store — a strong capture would be a reference cycle.
    let weak = Arc::downgrade(&store.inner);
    move |ssl, session| {
        let Some(inner) = weak.upgrade() else {
            return;
        };
        // Key by SNI hostname — that is what identifies the exit server at
        // the TLS layer and what the connect path will look up.
        let Some(name) = ssl.servername(boring::ssl::NameType::HOST_NAME) else {
            return;
        };
        ResumptionStore { inner }.boring_record_session(name, session);
    }
}
