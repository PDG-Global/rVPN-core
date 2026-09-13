// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pooled multiplex mode — per-exit pool of multiplexed WebSocket tunnels.

//! Per-exit tunnel pool for pooled SOCKS5 mode.
//!
//! Each exit server gets a [`TunnelPool`] holding `pool_size` live
//! [`Socks5Tunnel`]s. New flows are striped least-loaded across live tunnels;
//! a dead tunnel is pruned and its replacement handshake is kicked off in the
//! background (pre-warm) so later flows never wait on TCP+TLS+X3DH. When all
//! tunnels reach the `max_flows_per_conn` soft cap the pool grows toward
//! `pool_max`; shrink-back is implicit — a tunnel that dies while the pool is
//! above target is not replaced.
//!
//! Rotation: each tunnel carries per-creation jittered age and byte
//! thresholds. When either fires the tunnel enters **draining** — no new
//! flows are assigned, existing flows run to completion, and a replacement
//! handshake is spawned in the same critical section (the remaining
//! assignable tunnels absorb new flows while it completes). A draining
//! tunnel is shut down once empty, or after the drain backstop
//! ([`DEFAULT_DRAIN_BACKSTOP`]), which fails its remaining flows. Rotation
//! and failure replacement share the same `spawn_connect` path.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};
use std::time::Duration;

use anyhow::Result;
use rand::{Rng, SeedableRng};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use rvpn_core::crypto::IdentityKey;
use rvpn_tls::TlsFingerprint;

use crate::config::Socks5Config;
use crate::server_pool::{ResolvedServer, ServerPool, DEFAULT_SERVER_NAME};
use crate::socks5_tunnel::Socks5Tunnel;

/// Pool metrics cadence, matching the spec ("INFO every 60 s").
const METRICS_INTERVAL: Duration = Duration::from_secs(60);

/// Default drain backstop for rotating tunnels.
///
/// A draining tunnel serves its existing flows until they finish — no new
/// flows are assigned. Browser connections (YouTube, keep-alive, speed
/// tests) routinely live far longer than 5 minutes, so a short hard cap
/// mass-fails in-flight connections on every rotation cycle. The backstop
/// exists only to reap a tunnel whose flows are genuinely STUCK: a flow
/// still active on a draining tunnel after an hour is not going to finish.
const DEFAULT_DRAIN_BACKSTOP: Duration = Duration::from_secs(3600);

/// Liveness + load view of a pooled tunnel.
///
/// Abstracted into a trait so the pool's striping/refill/rotation logic is
/// unit-testable without real WebSocket handshakes.
pub trait PoolTunnel: Send + Sync + 'static {
    /// Whether the tunnel's receive loop is still running.
    fn is_alive(&self) -> bool;
    /// Number of flows currently open on the tunnel.
    fn active_flow_count(&self) -> usize;
    /// How long ago the tunnel was established.
    fn age(&self) -> Duration;
    /// Total payload bytes relayed through the tunnel (both directions).
    fn bytes_relayed(&self) -> u64;
    /// Force-close the tunnel, failing its remaining flows. Called when a
    /// draining tunnel empties or hits the drain backstop.
    fn shutdown(&self) -> impl std::future::Future<Output = ()> + Send;
}

impl PoolTunnel for Socks5Tunnel {
    fn is_alive(&self) -> bool {
        Socks5Tunnel::is_alive(self)
    }

    fn active_flow_count(&self) -> usize {
        Socks5Tunnel::active_flow_count(self)
    }

    fn age(&self) -> Duration {
        Socks5Tunnel::age(self)
    }

    fn bytes_relayed(&self) -> u64 {
        Socks5Tunnel::bytes_relayed(self)
    }

    async fn shutdown(&self) {
        Socks5Tunnel::shutdown(self).await
    }
}

/// Rotation thresholds and timing for pooled tunnels.
#[derive(Debug, Clone, Copy)]
pub struct RotationConfig {
    /// Base age threshold; the per-tunnel value is jittered ±`jitter`.
    pub rotate_after: Duration,
    /// Base byte threshold; the per-tunnel value is jittered ±`jitter`.
    pub rotate_after_bytes: u64,
    /// Jitter fraction applied per tunnel at creation (0.0–0.5). A
    /// metronome rotation schedule is itself a traffic pattern.
    pub jitter: f64,
    /// Backstop on drain time; remaining flows are failed afterwards.
    /// Defaults to [`DEFAULT_DRAIN_BACKSTOP`] — drains normally complete
    /// when the last flow ends, however long that takes.
    pub drain_timeout: Duration,
    /// Watcher poll interval (liveness + rotation threshold checks).
    pub poll_interval: Duration,
}

impl Default for RotationConfig {
    fn default() -> Self {
        Self {
            rotate_after: Duration::from_secs(600),
            rotate_after_bytes: 256 * 1024 * 1024,
            jitter: 0.2,
            drain_timeout: DEFAULT_DRAIN_BACKSTOP,
            poll_interval: Duration::from_secs(1),
        }
    }
}

/// Factory for establishing one pooled tunnel. Boxed so tests can inject
/// mock tunnels without network I/O.
type Connector<T> =
    Arc<dyn Fn() -> Pin<Box<dyn Future<Output = Result<Arc<T>>> + Send>> + Send + Sync>;

/// Apply ±jitter to a base value: result in `[base*(1-j), base*(1+j)]`.
fn jittered(base: f64, jitter: f64) -> f64 {
    if jitter <= 0.0 {
        return base;
    }
    let mut rng = rand::rngs::StdRng::from_entropy();
    base * rng.gen_range((1.0 - jitter)..=(1.0 + jitter))
}

/// A pooled tunnel plus its rotation bookkeeping.
struct PoolEntry<T: PoolTunnel> {
    tunnel: Arc<T>,
    /// Jittered age threshold at which this tunnel starts draining.
    rotate_at_age: Duration,
    /// Jittered byte threshold at which this tunnel starts draining.
    rotate_at_bytes: u64,
    /// Set when a rotation threshold fired: no new flows are assigned.
    draining: bool,
    /// When draining started (for the drain backstop). Uses tokio's clock
    /// so paused-time tests can exercise drain timing.
    draining_since: Option<tokio::time::Instant>,
}

impl<T: PoolTunnel> PoolEntry<T> {
    /// Whether this entry can take new flows (alive and not draining).
    fn assignable(&self) -> bool {
        !self.draining && self.tunnel.is_alive()
    }
}

/// Wrap a freshly connected tunnel in a pool entry with jittered
/// rotation thresholds.
fn new_entry<T: PoolTunnel>(tunnel: Arc<T>, rotation: &RotationConfig) -> PoolEntry<T> {
    PoolEntry {
        tunnel,
        rotate_at_age: Duration::from_secs_f64(jittered(
            rotation.rotate_after.as_secs_f64(),
            rotation.jitter,
        )),
        rotate_at_bytes: jittered(rotation.rotate_after_bytes as f64, rotation.jitter) as u64,
        draining: false,
        draining_since: None,
    }
}

/// Mutable pool state, locked on every pick/refill/rotation check.
struct PoolInner<T: PoolTunnel> {
    /// Live plus not-yet-detected-dead tunnels (dead ones are pruned lazily).
    tunnels: Vec<PoolEntry<T>>,
    /// In-flight background handshakes (pre-warm/replacement), counted so
    /// `ensure_target` never over-spawns.
    connecting: usize,
    /// Consecutive background-connect failures; drives the backoff delay.
    backoff_attempt: u32,
    /// Successful tunnel handshakes since pool creation (metrics).
    handshakes: u64,
    /// Rotation events (drain starts) since pool creation (metrics).
    rotations: u64,
}

impl<T: PoolTunnel> PoolInner<T> {
    /// Number of tunnels that can take new flows (alive, not draining).
    /// Draining tunnels keep serving existing flows but don't count here,
    /// so starting a drain makes `ensure_target` spawn a replacement.
    fn assignable_count(&self) -> usize {
        self.tunnels.iter().filter(|e| e.assignable()).count()
    }

    /// Number of tunnels whose receive loop is still running, draining or
    /// not (metrics and diagnostics).
    fn alive_count(&self) -> usize {
        self.tunnels.iter().filter(|e| e.tunnel.is_alive()).count()
    }

    /// Drop dead tunnels; returns how many were removed. Dead draining
    /// tunnels are pruned too — their flows were already failed by the
    /// tunnel's own death path.
    fn prune_dead(&mut self) -> usize {
        let before = self.tunnels.len();
        self.tunnels.retain(|e| e.tunnel.is_alive());
        before - self.tunnels.len()
    }
}

/// Cloneable context handed to background tasks. Holds the pool state by
/// `Weak` so a spawned task can never keep a dropped pool alive.
struct PoolCtx<T: PoolTunnel> {
    inner: Weak<Mutex<PoolInner<T>>>,
    connector: Connector<T>,
    name: String,
    pool_size: usize,
    rotation: RotationConfig,
}

// Manual impl: derive(Clone) would add an unwanted `T: Clone` bound.
impl<T: PoolTunnel> Clone for PoolCtx<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Weak::clone(&self.inner),
            connector: Arc::clone(&self.connector),
            name: self.name.clone(),
            pool_size: self.pool_size,
            rotation: self.rotation,
        }
    }
}

/// A per-exit pool of multiplexed tunnels.
pub struct TunnelPool<T: PoolTunnel> {
    inner: Arc<Mutex<PoolInner<T>>>,
    connector: Connector<T>,
    /// Exit server name, used in log lines.
    name: String,
    pool_size: usize,
    pool_max: usize,
    max_flows_per_conn: usize,
    rotation: RotationConfig,
}

impl<T: PoolTunnel> TunnelPool<T> {
    /// Create an empty pool; tunnels are established lazily on first flow.
    ///
    /// Must be called from within a tokio runtime — spawns the pool's
    /// metrics task.
    pub fn new(
        name: String,
        pool_size: usize,
        pool_max: usize,
        max_flows_per_conn: usize,
        rotation: RotationConfig,
        connector: Connector<T>,
    ) -> Self {
        let pool = Self {
            inner: Arc::new(Mutex::new(PoolInner {
                tunnels: Vec::new(),
                connecting: 0,
                backoff_attempt: 0,
                handshakes: 0,
                rotations: 0,
            })),
            connector,
            name,
            pool_size,
            pool_max,
            max_flows_per_conn,
            rotation,
        };
        spawn_metrics(pool.ctx());
        pool
    }

    fn ctx(&self) -> PoolCtx<T> {
        PoolCtx {
            inner: Arc::downgrade(&self.inner),
            connector: Arc::clone(&self.connector),
            name: self.name.clone(),
            pool_size: self.pool_size,
            rotation: self.rotation,
        }
    }

    /// Pick the tunnel for a new flow.
    ///
    /// Least-loaded assignable (alive, non-draining) tunnel wins. If all
    /// assignable tunnels are at the soft flow cap, a background grow toward
    /// `pool_max` is kicked off and the flow still lands on the least-loaded
    /// tunnel (soft cap — it may be briefly exceeded). If no tunnel is
    /// assignable, one is established synchronously (first-flow latency)
    /// and the pool is then pre-warmed up to `pool_size` in the background.
    pub async fn pick_tunnel(&self) -> Result<Arc<T>> {
        {
            let mut inner = self.inner.lock().await;
            let pruned = inner.prune_dead();
            if pruned > 0 {
                info!(
                    "pool '{}': pruned {} dead tunnel(s), {} live",
                    self.name,
                    pruned,
                    inner.tunnels.len()
                );
            }

            // Fast path: least-loaded assignable tunnel under the soft cap.
            let under_cap = inner
                .tunnels
                .iter()
                .filter(|e| {
                    e.assignable() && e.tunnel.active_flow_count() < self.max_flows_per_conn
                })
                .min_by_key(|e| e.tunnel.active_flow_count());
            if let Some(e) = under_cap {
                let t = Arc::clone(&e.tunnel);
                ensure_target(&self.ctx(), &mut inner);
                return Ok(t);
            }

            let assignable = inner.assignable_count();
            if assignable > 0 {
                // All assignable tunnels at cap: grow toward pool_max in the
                // background, assign to least-loaded anyway (soft cap).
                if assignable + inner.connecting < self.pool_max {
                    info!(
                        "pool '{}': all {} tunnel(s) at cap {}, growing",
                        self.name, assignable, self.max_flows_per_conn
                    );
                    spawn_connect(self.ctx(), &mut inner, Duration::ZERO);
                }
                let t = inner
                    .tunnels
                    .iter()
                    .filter(|e| e.assignable())
                    .min_by_key(|e| e.tunnel.active_flow_count())
                    .map(|e| Arc::clone(&e.tunnel))
                    .expect("assignable non-empty");
                ensure_target(&self.ctx(), &mut inner);
                return Ok(t);
            }

            // No assignable tunnels: reserve a connecting slot so concurrent
            // picks don't stampede the handshake path, then connect
            // synchronously.
            inner.connecting += 1;
        }

        let result = (self.connector)().await;
        let mut inner = self.inner.lock().await;
        inner.connecting = inner.connecting.saturating_sub(1);
        match result {
            Ok(t) => {
                inner.backoff_attempt = 0;
                inner.handshakes += 1;
                inner
                    .tunnels
                    .push(new_entry(Arc::clone(&t), &self.rotation));
                info!("pool '{}': first tunnel established", self.name);
                spawn_watcher(self.ctx(), &t);
                ensure_target(&self.ctx(), &mut inner);
                Ok(t)
            }
            Err(e) => {
                inner.backoff_attempt += 1;
                let attempt = inner.backoff_attempt;
                warn!(
                    "pool '{}': connect failed (attempt {}): {}",
                    self.name, attempt, e
                );
                // Background retry so the next flow finds a warm tunnel.
                if inner.assignable_count() + inner.connecting < self.pool_size {
                    spawn_connect(self.ctx(), &mut inner, backoff_delay(attempt));
                }
                Err(e)
            }
        }
    }
}

/// Spawn background handshakes until assignable + connecting reaches the
/// target. Tunnels above target that later die are NOT replaced — that is
/// the shrink-back path after a grow.
fn ensure_target<T: PoolTunnel>(ctx: &PoolCtx<T>, inner: &mut PoolInner<T>) {
    let deficit = ctx
        .pool_size
        .saturating_sub(inner.assignable_count() + inner.connecting);
    for _ in 0..deficit {
        debug!("pool '{}': pre-warming tunnel (below target)", ctx.name);
        spawn_connect(ctx.clone(), inner, Duration::ZERO);
    }
}

/// Spawn one background connect. `inner.connecting` is incremented before
/// the task starts and decremented when it finishes; failures reschedule
/// themselves with capped exponential backoff while the pool is below target.
///
/// This is the shared replacement path for both failure and rotation.
fn spawn_connect<T: PoolTunnel>(ctx: PoolCtx<T>, inner: &mut PoolInner<T>, delay: Duration) {
    inner.connecting += 1;
    tokio::spawn(async move {
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        let Some(inner_arc) = ctx.inner.upgrade() else {
            return;
        };
        let result = (ctx.connector)().await;
        let mut guard = inner_arc.lock().await;
        guard.connecting = guard.connecting.saturating_sub(1);
        match result {
            Ok(t) => {
                guard.backoff_attempt = 0;
                guard.handshakes += 1;
                guard.tunnels.push(new_entry(Arc::clone(&t), &ctx.rotation));
                info!(
                    "pool '{}': tunnel established ({} live)",
                    ctx.name,
                    guard.tunnels.len()
                );
                spawn_watcher(ctx.clone(), &t);
                ensure_target(&ctx, &mut guard);
            }
            Err(e) => {
                guard.backoff_attempt += 1;
                let attempt = guard.backoff_attempt;
                warn!(
                    "pool '{}': background connect failed (attempt {}): {}",
                    ctx.name, attempt, e
                );
                if guard.assignable_count() + guard.connecting < ctx.pool_size {
                    spawn_connect(ctx.clone(), &mut guard, backoff_delay(attempt));
                }
            }
        }
    });
}

/// Watch a tunnel: detect death, fire rotation thresholds, and complete
/// drains. Polls at `rotation.poll_interval` — cheap at pool sizes of 2–8.
fn spawn_watcher<T: PoolTunnel>(ctx: PoolCtx<T>, tunnel: &Arc<T>) {
    let weak_tunnel = Arc::downgrade(tunnel);
    let rotation = ctx.rotation;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(rotation.poll_interval).await;
            let Some(t) = weak_tunnel.upgrade() else {
                return;
            };
            let Some(inner_arc) = ctx.inner.upgrade() else {
                return;
            };
            let mut guard = inner_arc.lock().await;

            // Death path: prune all dead entries and top up.
            if !t.is_alive() {
                let pruned = guard.prune_dead();
                if pruned > 0 {
                    info!(
                        "pool '{}': tunnel died, pruned {} ({} live), topping up",
                        ctx.name,
                        pruned,
                        guard.tunnels.len()
                    );
                    ensure_target(&ctx, &mut guard);
                }
                return;
            }

            let Some(idx) = guard
                .tunnels
                .iter()
                .position(|e| Arc::ptr_eq(&e.tunnel, &t))
            else {
                // Entry already removed (drain completed elsewhere).
                return;
            };

            // Rotation threshold: mark draining and spawn the replacement
            // under the same lock, so no observer ever sees a drain without
            // a replacement already in flight. New flows stripe onto the
            // remaining assignable tunnels while the handshake completes.
            {
                let entry = &guard.tunnels[idx];
                let threshold_hit = !entry.draining
                    && (t.age() >= entry.rotate_at_age
                        || t.bytes_relayed() >= entry.rotate_at_bytes);
                if threshold_hit {
                    let entry = &mut guard.tunnels[idx];
                    entry.draining = true;
                    entry.draining_since = Some(tokio::time::Instant::now());
                    guard.rotations += 1;
                    info!(
                        "pool '{}': tunnel hit rotation threshold (age {:.0}s, {} bytes) — draining",
                        ctx.name,
                        t.age().as_secs_f64(),
                        t.bytes_relayed()
                    );
                    ensure_target(&ctx, &mut guard);
                }
            }

            // Drain completion: close when empty, or fail remaining flows
            // after the backstop.
            let entry = &guard.tunnels[idx];
            if entry.draining {
                let empty = t.active_flow_count() == 0;
                let overdue = entry
                    .draining_since
                    .map(|since| since.elapsed() >= rotation.drain_timeout)
                    .unwrap_or(false);
                if empty || overdue {
                    let removed = guard.tunnels.remove(idx);
                    if overdue {
                        warn!(
                            "pool '{}': drain exceeded {:?} — failing {} remaining flow(s)",
                            ctx.name,
                            rotation.drain_timeout,
                            removed.tunnel.active_flow_count()
                        );
                    } else {
                        debug!(
                            "pool '{}': drained tunnel closed ({} live)",
                            ctx.name,
                            guard.tunnels.len()
                        );
                    }
                    drop(guard);
                    removed.tunnel.shutdown().await;
                    return;
                }
            }
        }
    });
}

/// Per-exit metrics, logged at INFO every 60 s (spec's metrics cadence).
fn spawn_metrics<T: PoolTunnel>(ctx: PoolCtx<T>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(METRICS_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let Some(inner_arc) = ctx.inner.upgrade() else {
                return;
            };
            let guard = inner_arc.lock().await;
            let flows_per_tunnel: Vec<usize> = guard
                .tunnels
                .iter()
                .map(|e| e.tunnel.active_flow_count())
                .collect();
            let draining = guard.tunnels.iter().filter(|e| e.draining).count();
            info!(
                "pool '{}': {} live ({} draining, {} connecting), flows/tunnel {:?}, \
                 {} handshakes, {} rotations",
                ctx.name,
                guard.alive_count(),
                draining,
                guard.connecting,
                flows_per_tunnel,
                guard.handshakes,
                guard.rotations,
            );
        }
    });
}

/// Capped exponential backoff for background tunnel replacement:
/// 500ms, 1s, 2s, ... capped at 30s.
fn backoff_delay(attempt: u32) -> Duration {
    let shift = attempt.saturating_sub(1).min(6);
    Duration::from_millis((500u64 << shift).min(30_000))
}

/// Derive the multiplexed endpoint path. Mirrors the derivation in
/// `proxy_common::handle_tunnel_multiplexed`: explicit `mux_path` override
/// wins, otherwise `{server_path}/mux`.
fn derive_mux_path(server_path: &str, mux_path_override: &str) -> String {
    if !mux_path_override.is_empty() {
        return mux_path_override.to_string();
    }
    let base = server_path.trim_end_matches('/');
    if base.ends_with("/mux") {
        base.to_string()
    } else {
        format!("{}/mux", base)
    }
}

/// Build the connector closure for a real [`Socks5Tunnel`] against one exit.
///
/// The exit's TLS resumption store (`server.resumption`) is captured through
/// the `Arc<ResolvedServer>`, so every tunnel handshake this pool runs —
/// first connect, failure replacement, rotation replacement — resumes the
/// previous session's TLS 1.3 ticket instead of doing a full handshake.
fn socks5_connector(
    server: Arc<ResolvedServer>,
    mux_path: String,
    tls_fingerprint: TlsFingerprint,
    identity_key: Arc<IdentityKey>,
) -> Connector<Socks5Tunnel> {
    Arc::new(move || {
        let server = Arc::clone(&server);
        let mux_path = mux_path.clone();
        let identity_key = Arc::clone(&identity_key);
        Box::pin(async move {
            Socks5Tunnel::connect(
                &server.host,
                server.port,
                &mux_path,
                tls_fingerprint,
                server.sni_hostname.as_deref(),
                &identity_key,
                &server.bundle,
                Some(&server.identity_config),
                Some(&server.resumption),
            )
            .await
        })
    })
}

/// Registry of per-exit tunnel pools keyed by server name; `"default"` is
/// always present. The Router picks the exit name; this resolves the pool.
pub struct TunnelPools {
    pools: HashMap<String, Arc<TunnelPool<Socks5Tunnel>>>,
    default_name: String,
}

impl TunnelPools {
    /// Create one (still empty) pool per configured server. Tunnels connect
    /// lazily on the first flow routed to that exit.
    pub fn from_server_pool(
        server_pool: &ServerPool,
        socks5: &Socks5Config,
        identity_key: Arc<IdentityKey>,
        tls_fingerprint: TlsFingerprint,
    ) -> Self {
        let rotation = RotationConfig {
            rotate_after: Duration::from_secs(socks5.rotate_after_secs),
            rotate_after_bytes: socks5.rotate_after_mb.saturating_mul(1024 * 1024),
            jitter: socks5.rotation_jitter,
            ..RotationConfig::default()
        };
        let mut pools = HashMap::new();
        for server in server_pool.iter() {
            let mux_path = derive_mux_path(&server.path, &socks5.mux_path);
            let connector = socks5_connector(
                Arc::clone(server),
                mux_path,
                tls_fingerprint,
                Arc::clone(&identity_key),
            );
            pools.insert(
                server.name.clone(),
                Arc::new(TunnelPool::new(
                    server.name.clone(),
                    socks5.pool_size,
                    socks5.pool_max,
                    socks5.max_flows_per_conn,
                    rotation,
                    connector,
                )),
            );
        }
        Self {
            pools,
            default_name: DEFAULT_SERVER_NAME.to_string(),
        }
    }

    /// Return the pool for `name`, falling back to the default exit.
    pub fn get_or_default(&self, name: &str) -> Arc<TunnelPool<Socks5Tunnel>> {
        self.pools
            .get(name)
            .or_else(|| self.pools.get(&self.default_name))
            .map(Arc::clone)
            .expect("TunnelPools always contains the default entry")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

    #[derive(Debug)]
    struct MockTunnel {
        id: u32,
        alive: AtomicBool,
        flows: AtomicUsize,
        /// Controllable age in milliseconds (real tunnels use a clock).
        age_ms: AtomicU64,
        bytes: AtomicU64,
        shutdown_called: AtomicBool,
    }

    impl PoolTunnel for MockTunnel {
        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::SeqCst)
        }

        fn active_flow_count(&self) -> usize {
            self.flows.load(Ordering::SeqCst)
        }

        fn age(&self) -> Duration {
            Duration::from_millis(self.age_ms.load(Ordering::SeqCst))
        }

        fn bytes_relayed(&self) -> u64 {
            self.bytes.load(Ordering::SeqCst)
        }

        async fn shutdown(&self) {
            self.shutdown_called.store(true, Ordering::SeqCst);
            self.alive.store(false, Ordering::SeqCst);
        }
    }

    struct MockState {
        attempts: AtomicUsize,
        next_id: AtomicU32,
        fail: AtomicBool,
    }

    fn mock_connector(state: &Arc<MockState>) -> Connector<MockTunnel> {
        let state = Arc::clone(state);
        Arc::new(move || {
            let state = Arc::clone(&state);
            Box::pin(async move {
                state.attempts.fetch_add(1, Ordering::SeqCst);
                if state.fail.load(Ordering::SeqCst) {
                    anyhow::bail!("mock connect failure");
                }
                let id = state.next_id.fetch_add(1, Ordering::SeqCst);
                Ok(Arc::new(MockTunnel {
                    id,
                    alive: AtomicBool::new(true),
                    flows: AtomicUsize::new(0),
                    age_ms: AtomicU64::new(0),
                    bytes: AtomicU64::new(0),
                    shutdown_called: AtomicBool::new(false),
                }))
            })
        })
    }

    fn mock_pool(
        pool_size: usize,
        pool_max: usize,
        max_flows_per_conn: usize,
    ) -> (TunnelPool<MockTunnel>, Arc<MockState>) {
        mock_pool_rot(
            pool_size,
            pool_max,
            max_flows_per_conn,
            RotationConfig::default(),
        )
    }

    fn mock_pool_rot(
        pool_size: usize,
        pool_max: usize,
        max_flows_per_conn: usize,
        rotation: RotationConfig,
    ) -> (TunnelPool<MockTunnel>, Arc<MockState>) {
        let state = Arc::new(MockState {
            attempts: AtomicUsize::new(0),
            next_id: AtomicU32::new(1),
            fail: AtomicBool::new(false),
        });
        let pool = TunnelPool::new(
            "test".to_string(),
            pool_size,
            pool_max,
            max_flows_per_conn,
            rotation,
            mock_connector(&state),
        );
        (pool, state)
    }

    /// Rotation knobs tuned for tests: 60s age / 1 MB byte thresholds, no
    /// jitter, 5s drain cap, 20ms watcher poll.
    fn test_rotation() -> RotationConfig {
        RotationConfig {
            rotate_after: Duration::from_secs(60),
            rotate_after_bytes: 1024 * 1024,
            jitter: 0.0,
            drain_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(20),
        }
    }

    /// Poll until the pool holds at least `n` assignable tunnels (5s timeout).
    async fn wait_for_live(pool: &TunnelPool<MockTunnel>, n: usize) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if pool.inner.lock().await.assignable_count() >= n {
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for {} live tunnels",
                n
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Poll until `cond` holds (5s timeout).
    async fn wait_until(cond: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !cond() {
            assert!(std::time::Instant::now() < deadline, "timed out waiting");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn first_flow_connects_sync_and_prewarms_to_target() {
        let (pool, state) = mock_pool(3, 8, 64);
        let t = pool.pick_tunnel().await.expect("first pick");
        assert!(t.is_alive());
        // One synchronous connect; the remaining two are background pre-warm.
        assert_eq!(pool.inner.lock().await.assignable_count(), 1);
        wait_for_live(&pool, 3).await;
        assert_eq!(state.attempts.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn least_loaded_selection_picks_fewest_flows() {
        let (pool, _state) = mock_pool(2, 8, 64);
        pool.pick_tunnel().await.expect("first pick");
        wait_for_live(&pool, 2).await;

        // Load the tunnels unevenly, then the next pick must land on the
        // less-loaded one.
        {
            let inner = pool.inner.lock().await;
            inner.tunnels[0].tunnel.flows.store(5, Ordering::SeqCst);
            inner.tunnels[1].tunnel.flows.store(2, Ordering::SeqCst);
        }
        let picked = pool.pick_tunnel().await.expect("pick");
        let expected_id = {
            let inner = pool.inner.lock().await;
            inner.tunnels[1].tunnel.id
        };
        assert_eq!(picked.id, expected_id);
    }

    #[tokio::test]
    async fn grows_when_all_tunnels_at_cap() {
        let (pool, state) = mock_pool(1, 3, 1);
        let t0 = pool.pick_tunnel().await.expect("first pick");
        assert_eq!(pool.inner.lock().await.assignable_count(), 1);
        t0.flows.store(1, Ordering::SeqCst); // at cap

        // All assignable tunnels at cap → background grow, flow still assigned.
        let picked = pool.pick_tunnel().await.expect("pick at cap");
        assert_eq!(picked.id, t0.id, "soft cap: flow lands on least-loaded");
        wait_for_live(&pool, 2).await;
        assert!(state.attempts.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn shrink_skips_replacement_above_target() {
        let (pool, state) = mock_pool(1, 3, 1);
        let t0 = pool.pick_tunnel().await.expect("first pick");
        t0.flows.store(1, Ordering::SeqCst); // at cap → forces grow on next pick
        pool.pick_tunnel().await.expect("grow pick");
        wait_for_live(&pool, 2).await;
        let attempts_after_grow = state.attempts.load(Ordering::SeqCst);

        // Drain flows, then kill one tunnel while above target. The pool
        // must NOT replace it (shrink back toward pool_size).
        {
            let inner = pool.inner.lock().await;
            for e in &inner.tunnels {
                e.tunnel.flows.store(0, Ordering::SeqCst);
            }
            inner.tunnels[0].tunnel.alive.store(false, Ordering::SeqCst);
        }
        let picked = pool.pick_tunnel().await.expect("pick after death");
        assert!(picked.is_alive());
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            state.attempts.load(Ordering::SeqCst),
            attempts_after_grow,
            "no replacement connect above target"
        );
        assert_eq!(pool.inner.lock().await.assignable_count(), 1);
    }

    #[tokio::test]
    async fn dead_tunnel_pruned_and_replaced() {
        let (pool, state) = mock_pool(2, 8, 64);
        pool.pick_tunnel().await.expect("first pick");
        wait_for_live(&pool, 2).await;
        let attempts_full = state.attempts.load(Ordering::SeqCst);

        // Kill one tunnel; the next pick prunes it and pre-warms a
        // replacement in the background.
        pool.inner.lock().await.tunnels[0]
            .tunnel
            .alive
            .store(false, Ordering::SeqCst);
        let picked = pool.pick_tunnel().await.expect("failover pick");
        assert!(picked.is_alive());
        assert_eq!(pool.inner.lock().await.assignable_count(), 1);

        wait_for_live(&pool, 2).await;
        assert!(state.attempts.load(Ordering::SeqCst) > attempts_full);
    }

    #[tokio::test]
    async fn failed_connect_retries_with_backoff() {
        let (pool, state) = mock_pool(1, 8, 64);
        state.fail.store(true, Ordering::SeqCst);
        let err = pool.pick_tunnel().await.expect_err("connect fails");
        assert!(err.to_string().contains("mock connect failure"));

        // The failure schedules a background retry (500ms first backoff).
        // Clear the failure flag; the retry must succeed and fill the pool.
        state.fail.store(false, Ordering::SeqCst);
        wait_for_live(&pool, 1).await;
        assert!(state.attempts.load(Ordering::SeqCst) >= 2);
    }

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_delay(1), Duration::from_millis(500));
        assert_eq!(backoff_delay(2), Duration::from_millis(1000));
        assert_eq!(backoff_delay(3), Duration::from_millis(2000));
        assert_eq!(backoff_delay(100), Duration::from_millis(30_000));
    }

    #[test]
    fn mux_path_derivation() {
        assert_eq!(derive_mux_path("/api/v1/ws", ""), "/api/v1/ws/mux");
        assert_eq!(derive_mux_path("/api/v1/ws/mux", ""), "/api/v1/ws/mux");
        assert_eq!(derive_mux_path("/api/v1/ws", "/custom"), "/custom");
    }

    // ── Rotation (slice 2) ────────────────────────────────────────────

    #[test]
    fn jitter_stays_within_bounds() {
        // Zero jitter → exact base value.
        assert_eq!(jittered(600.0, 0.0), 600.0);

        // 1000 samples must all land in [base*(1-j), base*(1+j)] and show
        // real variance (a constant output would defeat the purpose).
        let mut min = f64::MAX;
        let mut max = f64::MIN;
        for _ in 0..1000 {
            let v = jittered(600.0, 0.2);
            assert!(
                (480.0..=720.0).contains(&v),
                "jittered value {} out of bounds",
                v
            );
            min = min.min(v);
            max = max.max(v);
        }
        assert!(
            min < 550.0 && max > 650.0,
            "no variance: [{}, {}]",
            min,
            max
        );
    }

    #[tokio::test]
    async fn rotation_triggered_on_age() {
        let (pool, _state) = mock_pool_rot(2, 8, 64, test_rotation());
        let t0 = pool.pick_tunnel().await.expect("first pick");
        wait_for_live(&pool, 2).await;

        // Age the first tunnel past its (unjittered) 60s threshold.
        t0.age_ms.store(61_000, Ordering::SeqCst);

        // The watcher must mark it draining and count the rotation.
        wait_until(|| t0.shutdown_called.load(Ordering::SeqCst)).await;
        let inner = pool.inner.lock().await;
        assert_eq!(inner.rotations, 1);
        assert!(inner.tunnels.iter().all(|e| e.tunnel.id != t0.id));
    }

    #[tokio::test]
    async fn rotation_triggered_on_bytes() {
        let (pool, _state) = mock_pool_rot(2, 8, 64, test_rotation());
        let t0 = pool.pick_tunnel().await.expect("first pick");
        wait_for_live(&pool, 2).await;

        // Exceed the 1 MB byte threshold.
        t0.bytes.store(2 * 1024 * 1024, Ordering::SeqCst);

        wait_until(|| t0.shutdown_called.load(Ordering::SeqCst)).await;
        assert_eq!(pool.inner.lock().await.rotations, 1);
    }

    #[tokio::test]
    async fn draining_tunnel_gets_no_new_flows_and_replacement_precedes_drain() {
        let (pool, state) = mock_pool_rot(2, 8, 64, test_rotation());
        let t0 = pool.pick_tunnel().await.expect("first pick");
        wait_for_live(&pool, 2).await;
        let attempts_before = state.attempts.load(Ordering::SeqCst);

        // One in-flight flow keeps the drain from completing instantly.
        t0.flows.store(1, Ordering::SeqCst);
        t0.age_ms.store(61_000, Ordering::SeqCst);

        // Wait until t0 is draining; a replacement connect must already be
        // in flight or done (spawned under the same lock as the drain mark).
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let draining = pool
                .inner
                .lock()
                .await
                .tunnels
                .iter()
                .any(|e| e.tunnel.id == t0.id && e.draining);
            if draining {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for t0 to start draining"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            state.attempts.load(Ordering::SeqCst) > attempts_before,
            "replacement connect must be spawned when the drain starts"
        );

        // Picks must never land on the draining tunnel, and the pool tops
        // back up to target with fresh tunnels.
        wait_for_live(&pool, 2).await;
        for _ in 0..8 {
            let picked = pool.pick_tunnel().await.expect("pick");
            assert_ne!(picked.id, t0.id, "draining tunnel must not be picked");
        }
    }

    #[tokio::test]
    async fn draining_tunnel_closes_when_empty() {
        let (pool, _state) = mock_pool_rot(1, 8, 64, test_rotation());
        let t0 = pool.pick_tunnel().await.expect("first pick");

        t0.age_ms.store(61_000, Ordering::SeqCst);
        // Zero flows → the drain completes on the next watcher tick.
        wait_until(|| t0.shutdown_called.load(Ordering::SeqCst)).await;
        assert!(!t0.is_alive(), "shutdown marks the tunnel dead");

        // Entry removed; only the replacement remains.
        let inner = pool.inner.lock().await;
        assert!(inner.tunnels.iter().all(|e| e.tunnel.id != t0.id));
    }

    #[tokio::test]
    async fn drain_hard_cap_fails_remaining_flows() {
        let rotation = RotationConfig {
            drain_timeout: Duration::from_millis(100),
            ..test_rotation()
        };
        let (pool, _state) = mock_pool_rot(1, 8, 64, rotation);
        let t0 = pool.pick_tunnel().await.expect("first pick");

        // One flow that never completes.
        t0.flows.store(1, Ordering::SeqCst);
        t0.age_ms.store(61_000, Ordering::SeqCst);

        // The tunnel must survive the drain briefly, then the 100ms
        // backstop fires shutdown, failing the stuck flow.
        wait_until(|| t0.shutdown_called.load(Ordering::SeqCst)).await;
        assert!(!t0.is_alive());
        let inner = pool.inner.lock().await;
        assert!(inner.tunnels.iter().all(|e| e.tunnel.id != t0.id));
    }

    /// A draining tunnel with a live flow must survive past the old 300s
    /// hard cap and close only when the flow ends. Paused clock: the sleeps
    /// below fast-forward through minutes of watcher ticks.
    #[tokio::test(start_paused = true)]
    async fn draining_tunnel_with_active_flow_survives_until_flow_ends() {
        let rotation = RotationConfig {
            rotate_after: Duration::from_secs(60),
            rotate_after_bytes: 1024 * 1024,
            jitter: 0.0,
            drain_timeout: DEFAULT_DRAIN_BACKSTOP,
            poll_interval: Duration::from_millis(100),
        };
        let (pool, _state) = mock_pool_rot(1, 8, 64, rotation);
        let t0 = pool.pick_tunnel().await.expect("first pick");

        // One long-lived flow; the tunnel starts draining on age.
        t0.flows.store(1, Ordering::SeqCst);
        t0.age_ms.store(61_000, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await; // a few watcher ticks

        // Well past the old 300s hard cap, the live flow must keep the
        // draining tunnel alive.
        tokio::time::sleep(Duration::from_secs(301)).await;
        assert!(
            !t0.shutdown_called.load(Ordering::SeqCst),
            "active flow must survive past the old 300s cap"
        );
        assert!(t0.is_alive());

        // The flow ends — the drain completes on the next watcher tick.
        t0.flows.store(0, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            t0.shutdown_called.load(Ordering::SeqCst),
            "drained tunnel must close once its last flow ends"
        );
    }

    /// The 3600s backstop still fails a flow that is genuinely stuck on a
    /// draining tunnel.
    #[tokio::test(start_paused = true)]
    async fn drain_backstop_fails_stuck_flows() {
        let rotation = RotationConfig {
            rotate_after: Duration::from_secs(60),
            rotate_after_bytes: 1024 * 1024,
            jitter: 0.0,
            drain_timeout: DEFAULT_DRAIN_BACKSTOP,
            poll_interval: Duration::from_millis(100),
        };
        let (pool, _state) = mock_pool_rot(1, 8, 64, rotation);
        let t0 = pool.pick_tunnel().await.expect("first pick");

        // One flow that never completes.
        t0.flows.store(1, Ordering::SeqCst);
        t0.age_ms.store(61_000, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_secs(1)).await; // drain starts
        assert!(!t0.shutdown_called.load(Ordering::SeqCst));

        // Advance to the backstop: the stuck flow is failed.
        tokio::time::sleep(DEFAULT_DRAIN_BACKSTOP + Duration::from_secs(1)).await;
        assert!(
            t0.shutdown_called.load(Ordering::SeqCst),
            "backstop must fire for a flow stuck past 3600s"
        );
        assert!(!t0.is_alive());
    }

    #[tokio::test]
    async fn jittered_thresholds_differ_per_tunnel() {
        let rotation = RotationConfig {
            jitter: 0.2,
            ..test_rotation()
        };
        let (pool, _state) = mock_pool_rot(4, 8, 64, rotation);
        pool.pick_tunnel().await.expect("first pick");
        wait_for_live(&pool, 4).await;

        let inner = pool.inner.lock().await;
        let base = test_rotation().rotate_after;
        for e in &inner.tunnels {
            // Every threshold within ±20% of the base.
            let secs = e.rotate_at_age.as_secs_f64();
            let base_secs = base.as_secs_f64();
            assert!(secs >= base_secs * 0.8 && secs <= base_secs * 1.2);
            let bytes = e.rotate_at_bytes as f64;
            let base_bytes = test_rotation().rotate_after_bytes as f64;
            assert!(bytes >= base_bytes * 0.8 && bytes <= base_bytes * 1.2);
        }
        // With jitter 0.2 over 4 tunnels, identical thresholds across the
        // whole pool are vanishingly unlikely — assert not all equal.
        let first = inner.tunnels[0].rotate_at_age;
        assert!(inner.tunnels.iter().any(|e| e.rotate_at_age != first));
    }
}
