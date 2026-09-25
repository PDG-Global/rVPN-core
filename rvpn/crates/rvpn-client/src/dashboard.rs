// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of R-VPN.
//
// R-VPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Embedded MRTG/RRD-style stats dashboard (client-only, opt-in).
//!
//! When `[dashboard] enabled = true` (or `--dashboard-listen` is given), the
//! client keeps an in-memory 5-second-resolution time series (24 h ring) plus
//! cumulative counters, and serves a single self-contained HTML+SVG page and a
//! JSON API from a localhost-bound HTTP listener. No JavaScript, no external
//! assets; the page reloads itself via `<meta http-equiv="refresh">`.
//!
//! Hot-path instrumentation goes through the `record_*` free functions, which
//! read a global `OnceLock` and use atomics only — they are branch-cheap
//! no-ops when the dashboard is disabled. Ring-buffer writes happen once per
//! 5 s sampler tick under a `std::sync::Mutex`.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ip_network::IpNetwork;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, warn};

/// Sampling resolution (seconds).
pub const SAMPLE_INTERVAL_SECS: u64 = 5;
/// Ring capacity: 24 h of 5 s buckets.
pub const BUCKET_CAP: usize = 17_280;
/// Handshake-RTT sample ring capacity.
pub const RTT_CAP: usize = 4096;
/// Buckets returned by `/api/stats.json` (30 min).
pub const JSON_BUCKET_COUNT: usize = 360;
/// Max HTTP request header bytes read per connection.
const MAX_REQUEST_BYTES: usize = 8192;

// Brand palette (design/Brand Assets/colors.css, same as scripts/lab/dashboard.py)
const BRAND_BLUE: &str = "#1B4DF5";
const BRAND_SKY: &str = "#5E86FF";
const BRAND_INK: &str = "#0B1A33";
const BRAND_PAPER: &str = "#FAFAF7";
const BRAND_SLATE: &str = "#5B6B85";
const BRAND_HAIRLINE: &str = "#E6E7E2";
const BRAND_TINT: &str = "#EAF0FF";
const BRAND_AMBER: &str = "#F2A413";
// MRTG/RRDtool palette, brand-tuned
const MRTG_GREEN: &str = "#00a000";
const MRTG_GREEN_DARK: &str = "#006600";
const GRID: &str = "#e3e6e0";
const PLOT_BORDER: &str = "#9aa4b2";

/// Reversed horizontal rVPN logo, inlined so the HTML stays self-contained.
/// Ported from scripts/lab/dashboard.py (LOGO_SVG); the header band supplies
/// the ink background.
const LOGO_SVG: &str = concat!(
    "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 196 56\" ",
    "class=\"logo\" role=\"img\" aria-label=\"rVPN\">",
    "<g transform=\"translate(2,4)\">",
    "<rect x=\"6\" y=\"6\" width=\"25\" height=\"25\" rx=\"8\" fill=\"none\" ",
    "stroke=\"#5E86FF\" stroke-width=\"3\"></rect>",
    "<rect x=\"17\" y=\"17\" width=\"25\" height=\"25\" rx=\"8\" fill=\"#ffffff\"></rect>",
    "<path d=\"M23.5 29.5 H35 M30 24.5 L35 29.5 L30 34.5\" fill=\"none\" ",
    "stroke=\"#1B4DF5\" stroke-width=\"3\" stroke-linecap=\"round\" ",
    "stroke-linejoin=\"round\"></path></g>",
    "<text x=\"64\" y=\"39\" font-family=\"Helvetica Neue, Helvetica, Arial, ",
    "sans-serif\" font-weight=\"500\" font-size=\"40\" letter-spacing=\"-0.8\" ",
    "fill=\"#FAFAF7\">rVPN</text></svg>"
);

/// Routing decision for a DNS query, for dashboard accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsDecision {
    /// Query was resolved through the VPN tunnel.
    Tunnel,
    /// Query was resolved locally (bypass).
    Bypass,
    /// Query was blocked (ad/tracker NXDOMAIN).
    Block,
}

/// One 5-second sample bucket: per-bucket deltas plus the connection gauge.
#[derive(Debug, Clone, Copy, Default)]
pub struct Bucket {
    /// Bucket end timestamp (unix seconds, aligned to the sample grid).
    pub ts: u64,
    /// Bytes relayed client → server in this bucket.
    pub bytes_up: u64,
    /// Bytes relayed server → client in this bucket.
    pub bytes_down: u64,
    /// Connections accepted in this bucket.
    pub conns_accepted: u64,
    /// Active connections gauge at sample time (accepted − completed).
    pub conns_active: i64,
    /// DNS queries resolved through the tunnel in this bucket.
    pub dns_tunnel: u64,
    /// DNS queries resolved locally in this bucket.
    pub dns_bypass: u64,
    /// DNS queries blocked in this bucket.
    pub dns_block: u64,
    /// Successful tunnel handshakes in this bucket.
    pub handshakes_ok: u64,
    /// Failed tunnel handshakes in this bucket.
    pub handshakes_fail: u64,
    /// Tunnel reconnect attempts in this bucket.
    pub reconnects: u64,
}

/// Point-in-time snapshot of the cumulative counters, used by the sampler to
/// compute per-bucket deltas.
#[derive(Debug, Clone, Copy, Default)]
struct Counters {
    bytes_up: u64,
    bytes_down: u64,
    conns_accepted: u64,
    conns_completed: u64,
    dns_tunnel: u64,
    dns_bypass: u64,
    dns_block: u64,
    handshakes_ok: u64,
    handshakes_fail: u64,
    reconnects: u64,
}

/// In-memory dashboard state: cumulative counters plus ring buffers.
///
/// Counters are atomics so hot paths never take a lock; the ring buffers are
/// only touched by the 5 s sampler and the (rare) HTTP render, under a
/// `std::sync::Mutex` held for a memcpy-scale duration.
pub struct DashboardState {
    /// Cumulative bytes relayed client → server.
    pub bytes_up: AtomicU64,
    /// Cumulative bytes relayed server → client.
    pub bytes_down: AtomicU64,
    /// Cumulative proxied connections accepted.
    pub conns_accepted: AtomicU64,
    /// Cumulative proxied connections finished.
    pub conns_completed: AtomicU64,
    /// Cumulative connections routed through the tunnel.
    pub conns_tunneled: AtomicU64,
    /// Cumulative connections bypassed (direct).
    pub conns_bypassed: AtomicU64,
    /// Cumulative connections blocked (ad/tracker).
    pub conns_blocked: AtomicU64,
    /// Cumulative DNS queries resolved through the tunnel.
    pub dns_tunnel: AtomicU64,
    /// Cumulative DNS queries resolved locally.
    pub dns_bypass: AtomicU64,
    /// Cumulative DNS queries blocked.
    pub dns_block: AtomicU64,
    /// Cumulative DNS cache hits.
    pub dns_cache_hits: AtomicU64,
    /// Cumulative DNS latency, microseconds (all recorded queries).
    pub dns_latency_us_total: AtomicU64,
    /// Cumulative successful tunnel handshakes.
    pub handshakes_ok: AtomicU64,
    /// Cumulative failed tunnel handshakes.
    pub handshakes_fail: AtomicU64,
    /// Cumulative tunnel reconnect attempts.
    pub reconnects: AtomicU64,
    /// Process start (unix seconds) for uptime.
    pub started_at: AtomicU64,
    /// 5 s sample ring (newest at the back).
    buckets: Mutex<VecDeque<Bucket>>,
    /// Handshake RTT samples: (unix ts, rtt micros).
    rtt_samples: Mutex<VecDeque<(u64, u64)>>,
}

impl DashboardState {
    /// Create empty state with `started_at = now`.
    pub fn new() -> Self {
        Self {
            bytes_up: AtomicU64::new(0),
            bytes_down: AtomicU64::new(0),
            conns_accepted: AtomicU64::new(0),
            conns_completed: AtomicU64::new(0),
            conns_tunneled: AtomicU64::new(0),
            conns_bypassed: AtomicU64::new(0),
            conns_blocked: AtomicU64::new(0),
            dns_tunnel: AtomicU64::new(0),
            dns_bypass: AtomicU64::new(0),
            dns_block: AtomicU64::new(0),
            dns_cache_hits: AtomicU64::new(0),
            dns_latency_us_total: AtomicU64::new(0),
            handshakes_ok: AtomicU64::new(0),
            handshakes_fail: AtomicU64::new(0),
            reconnects: AtomicU64::new(0),
            started_at: AtomicU64::new(now_unix()),
            buckets: Mutex::new(VecDeque::with_capacity(BUCKET_CAP)),
            rtt_samples: Mutex::new(VecDeque::with_capacity(RTT_CAP)),
        }
    }

    fn bump(&self, counter: &AtomicU64, n: u64) {
        counter.fetch_add(n, Ordering::Relaxed);
    }

    fn push_bucket(&self, bucket: Bucket) {
        let mut guard = self.buckets.lock().unwrap();
        if guard.len() >= BUCKET_CAP {
            guard.pop_front();
        }
        guard.push_back(bucket);
    }

    fn push_rtt(&self, ts: u64, rtt: Duration) {
        let mut guard = self.rtt_samples.lock().unwrap();
        if guard.len() >= RTT_CAP {
            guard.pop_front();
        }
        guard.push_back((ts, rtt.as_micros() as u64));
    }

    /// Snapshot the cumulative counters.
    fn snapshot_counters(&self) -> Counters {
        Counters {
            bytes_up: self.bytes_up.load(Ordering::Relaxed),
            bytes_down: self.bytes_down.load(Ordering::Relaxed),
            conns_accepted: self.conns_accepted.load(Ordering::Relaxed),
            conns_completed: self.conns_completed.load(Ordering::Relaxed),
            dns_tunnel: self.dns_tunnel.load(Ordering::Relaxed),
            dns_bypass: self.dns_bypass.load(Ordering::Relaxed),
            dns_block: self.dns_block.load(Ordering::Relaxed),
            handshakes_ok: self.handshakes_ok.load(Ordering::Relaxed),
            handshakes_fail: self.handshakes_fail.load(Ordering::Relaxed),
            reconnects: self.reconnects.load(Ordering::Relaxed),
        }
    }

    /// Compute the bucket for `now` from the deltas vs `prev`, and return the
    /// new `prev`. Pure (no ring push) so it is directly unit-testable.
    fn sample(&self, prev: &Counters, now: u64) -> (Bucket, Counters) {
        let cur = self.snapshot_counters();
        let bucket = Bucket {
            ts: now - (now % SAMPLE_INTERVAL_SECS),
            bytes_up: cur.bytes_up.saturating_sub(prev.bytes_up),
            bytes_down: cur.bytes_down.saturating_sub(prev.bytes_down),
            conns_accepted: cur.conns_accepted.saturating_sub(prev.conns_accepted),
            conns_active: cur.conns_accepted as i64 - cur.conns_completed as i64,
            dns_tunnel: cur.dns_tunnel.saturating_sub(prev.dns_tunnel),
            dns_bypass: cur.dns_bypass.saturating_sub(prev.dns_bypass),
            dns_block: cur.dns_block.saturating_sub(prev.dns_block),
            handshakes_ok: cur.handshakes_ok.saturating_sub(prev.handshakes_ok),
            handshakes_fail: cur.handshakes_fail.saturating_sub(prev.handshakes_fail),
            reconnects: cur.reconnects.saturating_sub(prev.reconnects),
        };
        (bucket, cur)
    }

    /// Copy out the buckets with `ts >= since` (ascending by ts).
    fn buckets_since(&self, since: u64) -> Vec<Bucket> {
        let guard = self.buckets.lock().unwrap();
        guard.iter().filter(|b| b.ts >= since).cloned().collect()
    }

    /// Copy out RTT samples within `[t0, t1)`.
    fn rtt_in_window(&self, t0: u64, t1: u64) -> Vec<(u64, u64)> {
        let guard = self.rtt_samples.lock().unwrap();
        guard
            .iter()
            .filter(|(ts, _)| *ts >= t0 && *ts < t1)
            .cloned()
            .collect()
    }
}

impl Default for DashboardState {
    fn default() -> Self {
        Self::new()
    }
}

/// Global dashboard handle, set once at startup when the dashboard is enabled.
static DASHBOARD: OnceLock<Arc<DashboardState>> = OnceLock::new();

/// Install the global dashboard state. Called once at startup; a second call
/// is ignored (the first state stays authoritative).
pub fn init(state: Arc<DashboardState>) {
    let _ = DASHBOARD.set(state);
}

/// Get the global dashboard state, if the dashboard is enabled.
pub fn global() -> Option<Arc<DashboardState>> {
    DASHBOARD.get().cloned()
}

#[inline]
fn with_state(f: impl FnOnce(&DashboardState)) {
    if let Some(state) = DASHBOARD.get() {
        f(state);
    }
}

/// Record `n` bytes relayed client → server.
#[inline]
pub fn record_bytes_up(n: u64) {
    with_state(|s| s.bump(&s.bytes_up, n));
}

/// Record `n` bytes relayed server → client.
#[inline]
pub fn record_bytes_down(n: u64) {
    with_state(|s| s.bump(&s.bytes_down, n));
}

/// Record a newly accepted proxied connection.
#[inline]
pub fn record_conn_accepted() {
    with_state(|s| s.bump(&s.conns_accepted, 1));
}

/// Record a finished proxied connection.
#[inline]
pub fn record_conn_completed() {
    with_state(|s| s.bump(&s.conns_completed, 1));
}

/// Record a connection routed through the tunnel.
#[inline]
pub fn record_conn_tunneled() {
    with_state(|s| s.bump(&s.conns_tunneled, 1));
}

/// Record a connection bypassed (direct).
#[inline]
pub fn record_conn_bypassed() {
    with_state(|s| s.bump(&s.conns_bypassed, 1));
}

/// Record a connection blocked (ad/tracker).
#[inline]
pub fn record_conn_blocked() {
    with_state(|s| s.bump(&s.conns_blocked, 1));
}

/// Record a DNS query decision, cache-hit flag, and end-to-end latency.
#[inline]
pub fn record_dns(decision: DnsDecision, cache_hit: bool, latency: Duration) {
    with_state(|s| {
        let counter = match decision {
            DnsDecision::Tunnel => &s.dns_tunnel,
            DnsDecision::Bypass => &s.dns_bypass,
            DnsDecision::Block => &s.dns_block,
        };
        s.bump(counter, 1);
        if cache_hit {
            s.bump(&s.dns_cache_hits, 1);
        }
        s.bump(&s.dns_latency_us_total, latency.as_micros() as u64);
    });
}

/// Record a successful tunnel handshake and its RTT.
#[inline]
pub fn record_handshake_ok(rtt: Duration) {
    with_state(|s| {
        s.bump(&s.handshakes_ok, 1);
        s.push_rtt(now_unix(), rtt);
    });
}

/// Record a failed tunnel handshake.
#[inline]
pub fn record_handshake_fail() {
    with_state(|s| s.bump(&s.handshakes_fail, 1));
}

/// Record a tunnel reconnect attempt.
#[inline]
pub fn record_reconnect() {
    with_state(|s| s.bump(&s.reconnects, 1));
}

/// RAII handshake timer: records `record_handshake_fail` on drop unless
/// [`HandshakeProbe::success`] was called first. Lets connect functions with
/// many `?` early-returns get ok/fail accounting without restructuring.
pub struct HandshakeProbe {
    start: Instant,
    succeeded: bool,
}

impl HandshakeProbe {
    /// Start timing a handshake.
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
            succeeded: false,
        }
    }

    /// Mark the handshake as successful; records `record_handshake_ok` with
    /// the elapsed RTT. Consumes the probe (no drop-side recording).
    pub fn success(mut self) {
        self.succeeded = true;
        record_handshake_ok(self.start.elapsed());
    }
}

impl Drop for HandshakeProbe {
    fn drop(&mut self) {
        if !self.succeeded {
            record_handshake_fail();
        }
    }
}

/// Current unix time in seconds (0 on clock-before-epoch, which never
/// happens on a real system).
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Sampler task: every 5 s, turn cumulative counters into one ring bucket.
/// Runs until the runtime shuts down.
pub async fn run_sampler(state: Arc<DashboardState>) {
    let mut interval = tokio::time::interval(Duration::from_secs(SAMPLE_INTERVAL_SECS));
    interval.tick().await; // skip immediate first tick
    let mut prev = Counters::default();
    loop {
        interval.tick().await;
        let (bucket, cur) = state.sample(&prev, now_unix());
        prev = cur;
        state.push_bucket(bucket);
    }
}

/// Sampler variant that exits cleanly when `shutdown` flips to true.
pub async fn run_sampler_until(
    state: Arc<DashboardState>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(SAMPLE_INTERVAL_SECS));
    interval.tick().await;
    let mut prev = Counters::default();
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let (bucket, cur) = state.sample(&prev, now_unix());
                prev = cur;
                state.push_bucket(bucket);
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// HTTP accept loop: serves the dashboard until the runtime shuts down.
/// Connections from outside `allow` get a bare 403.
pub async fn serve(listener: TcpListener, state: Arc<DashboardState>, allow: Arc<Vec<IpNetwork>>) {
    loop {
        match listener.accept().await {
            Ok((socket, peer)) => {
                let st = Arc::clone(&state);
                let al = Arc::clone(&allow);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(socket, peer, &st, &al).await {
                        debug!("dashboard connection error: {}", e);
                    }
                });
            }
            Err(e) => warn!("dashboard accept error: {}", e),
        }
    }
}

/// HTTP accept loop variant that exits cleanly when `shutdown` flips to true.
pub async fn serve_until(
    listener: TcpListener,
    state: Arc<DashboardState>,
    allow: Arc<Vec<IpNetwork>>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((socket, peer)) => {
                        let st = Arc::clone(&state);
                        let al = Arc::clone(&allow);
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(socket, peer, &st, &al).await {
                                debug!("dashboard connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => warn!("dashboard accept error: {}", e),
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// Check a peer address against the allowlist CIDRs.
fn ip_allowed(ip: &std::net::IpAddr, allow: &[IpNetwork]) -> bool {
    allow.iter().any(|net| net.contains(*ip))
}

/// Handle one HTTP/1.0-ish request: read bounded headers, route, respond with
/// `Connection: close`.
async fn handle_connection(
    mut socket: TcpStream,
    peer: std::net::SocketAddr,
    state: &DashboardState,
    allow: &[IpNetwork],
) -> std::io::Result<()> {
    let mut buf = [0u8; MAX_REQUEST_BYTES];
    let mut filled = 0;
    loop {
        if filled >= buf.len() {
            // Headers too large — just 404 it.
            return write_response(&mut socket, "404 Not Found", "text/plain", b"not found", 9)
                .await;
        }
        let n = socket.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Ok(()); // peer went away
        }
        filled += n;
        if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }

    // Allowlist check happens after the header read: closing with unread
    // request data in the receive buffer would RST the connection and destroy
    // the 403 before the client sees it.
    if !ip_allowed(&peer.ip(), allow) {
        return write_response(&mut socket, "403 Forbidden", "text/plain", b"forbidden", 9).await;
    }

    let request = String::from_utf8_lossy(&buf[..filled]);
    let request_line = request.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("").split('?').next().unwrap_or("");
    let head_only = method == "HEAD";

    match (method, path) {
        ("GET", "/") | ("HEAD", "/") => {
            let body = render_page(state, now_unix());
            write_response(
                &mut socket,
                "200 OK",
                "text/html; charset=utf-8",
                if head_only { b"" } else { body.as_bytes() },
                body.len(),
            )
            .await
        }
        ("GET", "/api/stats.json") | ("HEAD", "/api/stats.json") => {
            let body = render_stats_json(state, now_unix());
            write_response(
                &mut socket,
                "200 OK",
                "application/json",
                if head_only { b"" } else { body.as_bytes() },
                body.len(),
            )
            .await
        }
        _ => write_response(&mut socket, "404 Not Found", "text/plain", b"not found", 9).await,
    }
}

/// Write a complete HTTP/1.1 response with correct length and close semantics.
/// `content_length` is the logical body length; `body` is empty for HEAD.
async fn write_response(
    socket: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &[u8],
    content_length: usize,
) -> std::io::Result<()> {
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status, content_type, content_length
    );
    socket.write_all(head.as_bytes()).await?;
    socket.write_all(body).await
}

/// Build the JSON stats payload: current counters, uptime, last 30 min of
/// 5 s buckets.
fn render_stats_json(state: &DashboardState, now: u64) -> String {
    let uptime = now.saturating_sub(state.started_at.load(Ordering::Relaxed));
    let buckets: Vec<serde_json::Value> = state
        .buckets_since(now.saturating_sub((JSON_BUCKET_COUNT as u64) * SAMPLE_INTERVAL_SECS))
        .iter()
        .map(|b| {
            serde_json::json!({
                "ts": b.ts,
                "bytes_up": b.bytes_up,
                "bytes_down": b.bytes_down,
                "conns_accepted": b.conns_accepted,
                "conns_active": b.conns_active,
                "dns_tunnel": b.dns_tunnel,
                "dns_bypass": b.dns_bypass,
                "dns_block": b.dns_block,
                "handshakes_ok": b.handshakes_ok,
                "handshakes_fail": b.handshakes_fail,
                "reconnects": b.reconnects,
            })
        })
        .collect();

    serde_json::json!({
        "uptime_secs": uptime,
        "counters": {
            "bytes_up": state.bytes_up.load(Ordering::Relaxed),
            "bytes_down": state.bytes_down.load(Ordering::Relaxed),
            "conns_accepted": state.conns_accepted.load(Ordering::Relaxed),
            "conns_completed": state.conns_completed.load(Ordering::Relaxed),
            "conns_tunneled": state.conns_tunneled.load(Ordering::Relaxed),
            "conns_bypassed": state.conns_bypassed.load(Ordering::Relaxed),
            "conns_blocked": state.conns_blocked.load(Ordering::Relaxed),
            "dns_tunnel": state.dns_tunnel.load(Ordering::Relaxed),
            "dns_bypass": state.dns_bypass.load(Ordering::Relaxed),
            "dns_block": state.dns_block.load(Ordering::Relaxed),
            "dns_cache_hits": state.dns_cache_hits.load(Ordering::Relaxed),
            "handshakes_ok": state.handshakes_ok.load(Ordering::Relaxed),
            "handshakes_fail": state.handshakes_fail.load(Ordering::Relaxed),
            "reconnects": state.reconnects.load(Ordering::Relaxed),
        },
        "bucket_secs": SAMPLE_INTERVAL_SECS,
        "buckets": buckets,
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// HTML/SVG rendering (MRTG/RRD style; ported from scripts/lab/dashboard.py)
// ---------------------------------------------------------------------------

/// Escape text for HTML/SVG content.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Format a unix timestamp in Asia/Hong_Kong (fixed +08:00, no DST).
fn fmt_hkt(ts: u64, with_date: bool) -> String {
    let Some(dt) = chrono::DateTime::from_timestamp(ts as i64, 0) else {
        return String::new();
    };
    let hkt = dt.with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap());
    if with_date {
        hkt.format("%m-%d %H:%M").to_string()
    } else {
        hkt.format("%H:%M").to_string()
    }
}

/// Humanize a byte count (1024-based).
fn humanize_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = bytes as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit < UNITS.len() - 1 {
        size /= 1024.0;
        unit += 1;
    }
    format!("{:.2} {}", size, UNITS[unit])
}

/// Humanize a bits-per-second rate (SI).
fn fmt_bps(v: f64) -> String {
    if v >= 1_000_000.0 {
        format!("{:.2} Mbps", v / 1_000_000.0)
    } else if v >= 1_000.0 {
        format!("{:.1} Kbps", v / 1_000.0)
    } else {
        format!("{:.0} bps", v)
    }
}

/// Format seconds for the RTT axis.
fn fmt_secs(v: f64) -> String {
    format!("{:.3} s", v)
}

/// Format a plain count/rate for axes.
fn fmt_count(v: f64) -> String {
    if v >= 100.0 {
        format!("{:.0}", v)
    } else {
        format!("{:.1}", v)
    }
}

/// Format uptime as `Dd HH:MM:SS` or `HH:MM:SS`.
fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let h = (secs % 86400) / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if days > 0 {
        format!("{}d {:02}:{:02}:{:02}", days, h, m, s)
    } else {
        format!("{:02}:{:02}:{:02}", h, m, s)
    }
}

/// Round up to a "nice" axis max: 1/2/2.5/5 × 10^k.
fn nice_ceil(v: f64) -> f64 {
    if v <= 0.0 || !v.is_finite() {
        return 1.0;
    }
    let mag = 10_f64.powf(v.log10().floor());
    for m in [1.0, 2.0, 2.5, 5.0, 10.0] {
        if m * mag >= v {
            return m * mag;
        }
    }
    10.0 * mag
}

/// Linear-interpolation percentile (same math as dashboard.py).
fn percentile(values: &mut [f64], p: f64) -> Option<f64> {
    if values.is_empty() {
        return None;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let k = (values.len() - 1) as f64 * p / 100.0;
    let lo = k as usize;
    let hi = (lo + 1).min(values.len() - 1);
    Some(values[lo] + (values[hi] - values[lo]) * (k - lo as f64))
}

/// Shared time→x mapping with nice tick selection, aligned to HKT midnight.
struct XAxis {
    t0: f64,
    t1: f64,
    x0: f64,
    x1: f64,
}

impl XAxis {
    const NICE_STEPS: [i64; 9] = [300, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400];

    fn new(t0: f64, t1: f64, x0: f64, x1: f64) -> Self {
        Self { t0, t1, x0, x1 }
    }

    fn x(&self, t: f64) -> f64 {
        self.x0 + (t - self.t0) / (self.t1 - self.t0) * (self.x1 - self.x0)
    }

    fn ticks(&self, target: i64) -> Vec<i64> {
        let span = (self.t1 - self.t0) as i64;
        let mut step = Self::NICE_STEPS[Self::NICE_STEPS.len() - 1];
        for s in Self::NICE_STEPS {
            if span / s <= target {
                step = s;
                break;
            }
        }
        // Align to HKT (UTC+8) midnight boundaries.
        let base = ((self.t0 as i64 + 8 * 3600) / 86400) * 86400 - 8 * 3600;
        let mut ticks = Vec::new();
        let mut t = base;
        while t <= self.t1 as i64 {
            if t >= self.t0 as i64 {
                ticks.push(t);
            }
            t += step;
        }
        ticks
    }

    fn grid_and_labels(&self, y_top: f64, y_bot: f64, label_y: f64, with_date: bool) -> String {
        let mut out = String::new();
        for t in self.ticks(9) {
            let x = self.x(t as f64);
            let _ = write!(
                out,
                "<line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"{}\" stroke-width=\"1\"/>",
                x, y_top, x, y_bot, GRID
            );
            let _ = write!(
                out,
                "<text x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"middle\" class=\"ax\">{}</text>",
                x,
                label_y,
                esc(&fmt_hkt(t as u64, with_date))
            );
        }
        out
    }
}

/// One series to draw: optional filled area plus a stroke line, with per-point
/// tooltip circles.
struct Series {
    /// (unix ts, value) points, ascending by ts.
    points: Vec<(f64, f64)>,
    stroke: &'static str,
    stroke_width: f64,
    /// (fill color, opacity) if this series is an area.
    fill: Option<(&'static str, f64)>,
    /// Series name for tooltips.
    label: &'static str,
}

/// Render one MRTG-style chart: white plot area, hairline grid, x time axis
/// (HKT), y axis auto-scaled to the max series value.
fn render_chart(
    t0: u64,
    t1: u64,
    series: &[Series],
    fmt_val: fn(f64) -> String,
    y_unit: &str,
) -> String {
    let (w, h, pad_l, pad_t, pad_b) = (1360.0_f64, 130.0, 68.0, 10.0, 20.0);
    let baseline = h - pad_b;
    let axis = XAxis::new(t0 as f64, t1 as f64, pad_l, w - 8.0);
    let with_date = t1.saturating_sub(t0) > 20 * 3600;

    let max_val = series
        .iter()
        .flat_map(|s| s.points.iter().map(|p| p.1))
        .fold(0.0_f64, f64::max);
    let y_max = nice_ceil(max_val * 1.15);
    let y = |v: f64| pad_t + (1.0 - v / y_max) * (h - pad_t - pad_b);

    let mut svg = String::new();
    let _ = write!(
        svg,
        "<svg viewBox=\"0 0 {:.0} {:.0}\" class=\"chart\" role=\"img\">",
        w, h
    );
    let _ = write!(
        svg,
        "<rect x=\"{:.1}\" y=\"{:.1}\" width=\"{:.1}\" height=\"{:.1}\" fill=\"#ffffff\" stroke=\"{}\" stroke-width=\"1\"/>",
        pad_l, pad_t, w - 8.0 - pad_l, h - pad_t - pad_b, PLOT_BORDER
    );
    svg.push_str(&axis.grid_and_labels(pad_t, baseline, h - 6.0, with_date));
    // y gridlines at 0 / mid / max
    for v in [0.0, y_max / 2.0, y_max] {
        let _ = write!(
            svg,
            "<line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"{}\" stroke-width=\"1\"/>",
            pad_l, y(v), w - 8.0, y(v), GRID
        );
        let _ = write!(
            svg,
            "<text x=\"{:.1}\" y=\"{:.1}\" text-anchor=\"end\" class=\"ax\">{}</text>",
            pad_l - 6.0,
            y(v) + 3.0,
            esc(&fmt_val(v))
        );
    }
    if !y_unit.is_empty() {
        let _ = write!(
            svg,
            "<text x=\"{:.1}\" y=\"{:.1}\" class=\"ax\">{}</text>",
            pad_l + 4.0,
            pad_t + 9.0,
            esc(y_unit)
        );
    }

    let any_points = series.iter().any(|s| !s.points.is_empty());
    if !any_points {
        let _ = write!(
            svg,
            "<text x=\"{:.0}\" y=\"{:.0}\" text-anchor=\"middle\" class=\"ax\">no data in window yet</text>",
            (pad_l + w) / 2.0,
            h / 2.0
        );
    }

    for s in series {
        if s.points.is_empty() {
            continue;
        }
        if let Some((fill, opacity)) = s.fill {
            let mut pts = String::new();
            let _ = write!(pts, "{:.1},{:.1} ", axis.x(s.points[0].0), baseline);
            for (t, v) in &s.points {
                let _ = write!(pts, "{:.1},{:.1} ", axis.x(*t), y(*v));
            }
            let _ = write!(
                pts,
                "{:.1},{:.1}",
                axis.x(s.points[s.points.len() - 1].0),
                baseline
            );
            let _ = write!(
                svg,
                "<polygon points=\"{}\" fill=\"{}\" fill-opacity=\"{}\" stroke=\"none\"/>",
                pts, fill, opacity
            );
        }
        let mut line = String::new();
        for (t, v) in &s.points {
            let _ = write!(line, "{:.1},{:.1} ", axis.x(*t), y(*v));
        }
        let _ = write!(
            svg,
            "<polyline points=\"{}\" fill=\"none\" stroke=\"{}\" stroke-width=\"{:.1}\"/>",
            line.trim_end(),
            s.stroke,
            s.stroke_width
        );
        // Invisible tooltip targets on each data point.
        for (t, v) in &s.points {
            let _ = write!(
                svg,
                "<circle cx=\"{:.1}\" cy=\"{:.1}\" r=\"4\" fill=\"{}\" fill-opacity=\"0\">",
                axis.x(*t),
                y(*v),
                s.stroke
            );
            let _ = write!(
                svg,
                "<title>{} {} — {}</title></circle>",
                esc(s.label),
                esc(&fmt_hkt(*t as u64, with_date)),
                esc(&fmt_val(*v))
            );
        }
    }
    svg.push_str("</svg>");
    svg
}

/// Re-bucket 5 s buckets into `width`-second buckets (sums deltas, keeps the
/// last gauge). Bucket timestamps must be ascending.
fn rebucket(buckets: &[Bucket], width: u64) -> Vec<Bucket> {
    let mut out: Vec<Bucket> = Vec::new();
    for b in buckets {
        let slot = b.ts / width;
        if let Some(last) = out.last_mut() {
            if last.ts / width == slot {
                last.bytes_up += b.bytes_up;
                last.bytes_down += b.bytes_down;
                last.conns_accepted += b.conns_accepted;
                last.conns_active = b.conns_active;
                last.dns_tunnel += b.dns_tunnel;
                last.dns_bypass += b.dns_bypass;
                last.dns_block += b.dns_block;
                last.handshakes_ok += b.handshakes_ok;
                last.handshakes_fail += b.handshakes_fail;
                last.reconnects += b.reconnects;
                last.ts = b.ts;
                continue;
            }
        }
        out.push(*b);
    }
    out
}

/// Per-bucket rate series: delta × `scale` / bucket width, plotted at the
/// bucket midpoint.
fn rate_points(
    buckets: &[Bucket],
    width: u64,
    field: fn(&Bucket) -> u64,
    scale: f64,
) -> Vec<(f64, f64)> {
    buckets
        .iter()
        .map(|b| {
            (
                (b.ts - width / 2) as f64,
                field(b) as f64 * scale / width as f64,
            )
        })
        .collect()
}

/// (median, p95) per-slot series in seconds: (unix ts, value) points each.
type PercentileSeries = (Vec<(f64, f64)>, Vec<(f64, f64)>);

/// Per-slot RTT percentiles (median, p95) in seconds from the sample ring.
fn rtt_points(state: &DashboardState, t0: u64, t1: u64, slot_width: u64) -> PercentileSeries {
    let samples = state.rtt_in_window(t0, t1);
    let mut slots: std::collections::BTreeMap<u64, Vec<f64>> = std::collections::BTreeMap::new();
    for (ts, micros) in samples {
        slots
            .entry(ts / slot_width)
            .or_default()
            .push(micros as f64 / 1e6);
    }
    let mut median = Vec::new();
    let mut p95 = Vec::new();
    for (slot, mut vals) in slots {
        let mid_ts = (slot * slot_width + slot_width / 2) as f64;
        if let Some(m) = percentile(&mut vals, 50.0) {
            median.push((mid_ts, m));
        }
        if let Some(p) = percentile(&mut vals, 95.0) {
            p95.push((mid_ts, p));
        }
    }
    (median, p95)
}

/// Classic MRTG footer row: cur/avg/max for inbound and outbound rates.
fn mrtg_footer(in_pts: &[(f64, f64)], out_pts: &[(f64, f64)]) -> String {
    fn stats(pts: &[(f64, f64)]) -> (f64, f64, f64) {
        let cur = pts.last().map(|p| p.1).unwrap_or(0.0);
        let avg = if pts.is_empty() {
            0.0
        } else {
            pts.iter().map(|p| p.1).sum::<f64>() / pts.len() as f64
        };
        let max = pts.iter().map(|p| p.1).fold(0.0_f64, f64::max);
        (cur, avg, max)
    }
    let (ic, ia, im) = stats(in_pts);
    let (oc, oa, om) = stats(out_pts);
    format!(
        "<table class=\"mrtg\"><thead><tr><th></th><th>Cur</th><th>Avg</th><th>Max</th></tr></thead><tbody>\
         <tr><td class=\"in\">In</td><td>{}</td><td>{}</td><td>{}</td></tr>\
         <tr><td class=\"out\">Out</td><td>{}</td><td>{}</td><td>{}</td></tr>\
         </tbody></table>",
        fmt_bps(ic), fmt_bps(ia), fmt_bps(im), fmt_bps(oc), fmt_bps(oa), fmt_bps(om)
    )
}

/// Render one chart in both windows (last 30 min from raw 5 s buckets, last
/// 24 h re-bucketed to 5 min) plus per-window extras from `footer`.
fn render_windowed(
    state: &DashboardState,
    now: u64,
    title_30m: &str,
    title_24h: &str,
    build: impl Fn(&[Bucket], u64, u64, u64) -> (Vec<Series>, fn(f64) -> String, &'static str),
    footer: impl Fn(&[Bucket], u64) -> String,
) -> String {
    let mut out = String::new();
    for (span, width, title) in [
        (30 * 60_u64, SAMPLE_INTERVAL_SECS, title_30m),
        (24 * 3600_u64, 300_u64, title_24h),
    ] {
        let t1 = now;
        let t0 = now.saturating_sub(span);
        let raw = state.buckets_since(t0);
        let buckets = if width == SAMPLE_INTERVAL_SECS {
            raw
        } else {
            rebucket(&raw, width)
        };
        let (series, fmt_val, unit) = build(&buckets, t0, t1, width);
        let _ = write!(out, "<h3>{}</h3>", esc(title));
        out.push_str(&render_chart(t0, t1, &series, fmt_val, unit));
        out.push_str(&footer(&buckets, width));
    }
    out
}

/// Summary strip: uptime, totals, connections, reconnects, handshake failures.
fn render_summary(state: &DashboardState, now: u64) -> String {
    let uptime = now.saturating_sub(state.started_at.load(Ordering::Relaxed));
    let accepted = state.conns_accepted.load(Ordering::Relaxed);
    let completed = state.conns_completed.load(Ordering::Relaxed);
    let active = accepted as i64 - completed as i64;
    let cards = [
        ("uptime", format_uptime(uptime)),
        (
            "down",
            humanize_bytes(state.bytes_down.load(Ordering::Relaxed)),
        ),
        ("up", humanize_bytes(state.bytes_up.load(Ordering::Relaxed))),
        (
            "connections",
            format!("{} active / {} total", active, accepted),
        ),
        (
            "reconnects",
            state.reconnects.load(Ordering::Relaxed).to_string(),
        ),
        (
            "handshake failures",
            state.handshakes_fail.load(Ordering::Relaxed).to_string(),
        ),
    ];
    let mut out = String::from("<section class=\"summary\">");
    for (label, value) in cards {
        let _ = write!(
            out,
            "<div class=\"card\"><div class=\"card-value\">{}</div><div class=\"card-label\">{}</div></div>",
            esc(&value),
            esc(label)
        );
    }
    out.push_str("</section>");
    out
}

/// Render the full self-contained HTML page.
fn render_page(state: &DashboardState, now: u64) -> String {
    let gen_hkt = chrono::DateTime::from_timestamp(now as i64, 0)
        .map(|d| {
            d.with_timezone(&chrono::FixedOffset::east_opt(8 * 3600).unwrap())
                .format("%Y-%m-%d %H:%M:%S HKT")
                .to_string()
        })
        .unwrap_or_default();

    // --- Throughput: green area = inbound, blue line = outbound (bits/s)
    let throughput = render_windowed(
        state,
        now,
        "last 30 minutes (5 s buckets)",
        "last 24 hours (5 min buckets)",
        |buckets, _t0, _t1, width| {
            let in_pts = rate_points(buckets, width, |b| b.bytes_down, 8.0);
            let out_pts = rate_points(buckets, width, |b| b.bytes_up, 8.0);
            (
                vec![
                    Series {
                        points: in_pts,
                        stroke: MRTG_GREEN_DARK,
                        stroke_width: 1.0,
                        fill: Some((MRTG_GREEN, 0.55)),
                        label: "in",
                    },
                    Series {
                        points: out_pts,
                        stroke: BRAND_BLUE,
                        stroke_width: 1.5,
                        fill: None,
                        label: "out",
                    },
                ],
                fmt_bps as fn(f64) -> String,
                "bits/s",
            )
        },
        |buckets, width| {
            mrtg_footer(
                &rate_points(buckets, width, |b| b.bytes_down, 8.0),
                &rate_points(buckets, width, |b| b.bytes_up, 8.0),
            )
        },
    );

    // --- Active connections gauge (blue line)
    let conns = render_windowed(
        state,
        now,
        "last 30 minutes (5 s buckets)",
        "last 24 hours (5 min buckets)",
        |buckets, _t0, _t1, width| {
            let pts = rate_points(buckets, width, |b| b.conns_active.max(0) as u64, 1.0);
            (
                vec![Series {
                    points: pts,
                    stroke: BRAND_BLUE,
                    stroke_width: 1.5,
                    fill: None,
                    label: "active",
                }],
                fmt_count as fn(f64) -> String,
                "connections",
            )
        },
        |_buckets, _width| String::new(),
    );

    // --- DNS queries/min: tunneled (green area), bypassed (blue), blocked (amber)
    let dns = render_windowed(
        state,
        now,
        "last 30 minutes (5 s buckets)",
        "last 24 hours (5 min buckets)",
        |buckets, _t0, _t1, width| {
            (
                vec![
                    Series {
                        points: rate_points(buckets, width, |b| b.dns_tunnel, 60.0),
                        stroke: MRTG_GREEN_DARK,
                        stroke_width: 1.0,
                        fill: Some((MRTG_GREEN, 0.55)),
                        label: "tunneled",
                    },
                    Series {
                        points: rate_points(buckets, width, |b| b.dns_bypass, 60.0),
                        stroke: BRAND_BLUE,
                        stroke_width: 1.5,
                        fill: None,
                        label: "bypassed",
                    },
                    Series {
                        points: rate_points(buckets, width, |b| b.dns_block, 60.0),
                        stroke: BRAND_AMBER,
                        stroke_width: 1.5,
                        fill: None,
                        label: "blocked",
                    },
                ],
                fmt_count as fn(f64) -> String,
                "queries/min",
            )
        },
        |_buckets, _width| String::new(),
    );

    // --- Handshake RTT: p95 green area + median blue line (seconds)
    let mut rtt = String::new();
    for (span, slot, title) in [
        (
            30 * 60_u64,
            SAMPLE_INTERVAL_SECS,
            "last 30 minutes (5 s slots)",
        ),
        (24 * 3600_u64, 300_u64, "last 24 hours (5 min slots)"),
    ] {
        let t1 = now;
        let t0 = now.saturating_sub(span);
        let (median, p95) = rtt_points(state, t0, t1, slot);
        let series = [
            Series {
                points: p95,
                stroke: MRTG_GREEN_DARK,
                stroke_width: 1.0,
                fill: Some((MRTG_GREEN, 0.55)),
                label: "p95",
            },
            Series {
                points: median,
                stroke: BRAND_BLUE,
                stroke_width: 1.5,
                fill: None,
                label: "median",
            },
        ];
        let _ = write!(rtt, "<h3>{}</h3>", esc(title));
        rtt.push_str(&render_chart(t0, t1, &series, fmt_secs, "seconds"));
    }

    let css = format!(
        "* {{ box-sizing: border-box; }}\
         body {{ font-family: \"Helvetica Neue\", Helvetica, Arial, sans-serif; color: {INK}; background: {PAPER}; margin: 0; padding: 24px 20px; }}\
         .wrap {{ max-width: 1420px; margin: 0 auto; }}\
         h1 {{ font-size: 19px; margin: 0; font-weight: 600; letter-spacing: -0.01em; color: {PAPER}; }}\
         h2 {{ font-size: 11.5px; margin: 0 0 10px; color: {INK}; text-transform: uppercase; letter-spacing: .07em; font-weight: 700; padding-left: 9px; border-left: 3px solid {BLUE}; }}\
         h3 {{ font-size: 12px; margin: 10px 0 4px; font-family: ui-monospace, Menlo, Consolas, monospace; font-weight: 600; }}\
         .hdr {{ background: {INK}; border-radius: 8px; padding: 14px 22px; margin-bottom: 16px; display: flex; align-items: center; justify-content: space-between; gap: 24px; }}\
         .hdr .brand {{ display: flex; align-items: center; gap: 18px; }}\
         .hdr .logo {{ height: 40px; width: auto; display: block; }}\
         .hdr .rule {{ width: 1px; height: 34px; background: {SKY}; opacity: .35; }}\
         .hdr .meta {{ text-align: right; color: {SKY}; font-size: 11px; line-height: 1.6; font-family: ui-monospace, Menlo, Consolas, monospace; }}\
         .hdr .meta b {{ color: {PAPER}; font-weight: 500; }}\
         section {{ background: #fff; border: 1px solid {HAIRLINE}; border-radius: 8px; padding: 14px 18px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(11, 26, 51, 0.04); }}\
         section.summary {{ display: flex; flex-wrap: wrap; gap: 10px 24px; }}\
         .card {{ min-width: 120px; }}\
         .card-value {{ font-size: 18px; font-weight: 600; font-family: ui-monospace, Menlo, Consolas, monospace; font-variant-numeric: tabular-nums; }}\
         .card-label {{ font-size: 10px; color: {SLATE}; text-transform: uppercase; letter-spacing: .05em; }}\
         .chart {{ width: 100%; height: auto; display: block; }}\
         .ax {{ font-size: 9px; fill: {SLATE}; font-family: ui-monospace, Menlo, Consolas, monospace; }}\
         table.mrtg {{ border-collapse: collapse; margin: 6px 0 4px; font-size: 11px; font-family: ui-monospace, Menlo, Consolas, monospace; }}\
         table.mrtg th, table.mrtg td {{ border: 1px solid {HAIRLINE}; padding: 2px 14px; text-align: right; }}\
         table.mrtg th {{ background: {TINT}; font-size: 9px; text-transform: uppercase; letter-spacing: .05em; }}\
         table.mrtg td.in {{ color: {GREEN_DARK}; font-weight: 600; text-align: left; }}\
         table.mrtg td.out {{ color: {BLUE}; font-weight: 600; text-align: left; }}\
         .note {{ font-size: 11px; color: {SLATE}; margin: 0 0 6px; }}\
         footer {{ color: {SLATE}; font-size: 10px; margin-top: 10px; text-align: center; font-family: ui-monospace, Menlo, Consolas, monospace; }}",
        INK = BRAND_INK,
        PAPER = BRAND_PAPER,
        BLUE = BRAND_BLUE,
        SKY = BRAND_SKY,
        SLATE = BRAND_SLATE,
        HAIRLINE = BRAND_HAIRLINE,
        TINT = BRAND_TINT,
        GREEN_DARK = MRTG_GREEN_DARK,
    );

    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\
         <meta http-equiv=\"refresh\" content=\"30\">\
         <title>rVPN client</title><style>{css}</style></head><body><div class=\"wrap\">\
         <div class=\"hdr\"><div class=\"brand\">{logo}<div class=\"rule\"></div><h1>rVPN client</h1></div>\
         <div class=\"meta\">generated <b>{gen}</b><br>axes in HKT (UTC+8) &middot; auto-reloads every 30 s</div></div>\
         {summary}\
         <section><h2>Throughput</h2><p class=\"note\">Green area: inbound bits/s; blue line: outbound bits/s.</p>{throughput}</section>\
         <section><h2>Active connections</h2>{conns}</section>\
         <section><h2>DNS</h2><p class=\"note\">Green area: tunneled queries/min; blue line: bypassed; amber line: blocked.</p>{dns}</section>\
         <section><h2>Handshake RTT</h2><p class=\"note\">Green area: p95; blue line: median.</p>{rtt}</section>\
         <footer>rvpn client dashboard &middot; served by the embedded listener (allowlisted networks only)</footer>\
         </div></body></html>",
        css = css,
        logo = LOGO_SVG,
        gen = esc(&gen_hkt),
        summary = render_summary(state, now),
        throughput = throughput,
        conns = conns,
        dns = dns,
        rtt = rtt,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bucket_at(ts: u64) -> Bucket {
        Bucket {
            ts,
            ..Default::default()
        }
    }

    #[test]
    fn ring_buffer_wraps_and_keeps_newest() {
        let state = DashboardState::new();
        for i in 0..(BUCKET_CAP + 100) {
            state.push_bucket(bucket_at(i as u64));
        }
        let buckets = state.buckets_since(0);
        assert_eq!(buckets.len(), BUCKET_CAP);
        assert_eq!(buckets[0].ts, 100);
        assert_eq!(buckets[BUCKET_CAP - 1].ts, (BUCKET_CAP + 99) as u64);
    }

    #[test]
    fn rtt_ring_wraps_and_keeps_newest() {
        let state = DashboardState::new();
        for i in 0..(RTT_CAP + 10) {
            state.push_rtt(i as u64, Duration::from_micros(i as u64));
        }
        let samples = state.rtt_in_window(0, u64::MAX);
        assert_eq!(samples.len(), RTT_CAP);
        assert_eq!(samples[0].0, 10);
        assert_eq!(samples[RTT_CAP - 1].0, (RTT_CAP + 9) as u64);
    }

    #[test]
    fn sample_computes_deltas_and_gauge() {
        let state = DashboardState::new();
        state.bump(&state.bytes_up, 1000);
        state.bump(&state.bytes_down, 5000);
        state.bump(&state.conns_accepted, 3);
        state.bump(&state.conns_completed, 1);
        state.bump(&state.dns_tunnel, 7);
        state.bump(&state.handshakes_ok, 2);

        let prev = Counters::default();
        let (b, prev) = state.sample(&prev, 1_700_000_003);
        assert_eq!(b.ts, 1_700_000_000); // aligned to 5 s grid
        assert_eq!(b.bytes_up, 1000);
        assert_eq!(b.bytes_down, 5000);
        assert_eq!(b.conns_accepted, 3);
        assert_eq!(b.conns_active, 2);
        assert_eq!(b.dns_tunnel, 7);
        assert_eq!(b.handshakes_ok, 2);

        // Second sample: deltas vs the previous sample, not from zero.
        state.bump(&state.bytes_up, 500);
        state.bump(&state.conns_completed, 2);
        let (b2, _) = state.sample(&prev, 1_700_000_007);
        assert_eq!(b2.ts, 1_700_000_005);
        assert_eq!(b2.bytes_up, 500);
        assert_eq!(b2.bytes_down, 0);
        assert_eq!(b2.conns_accepted, 0);
        assert_eq!(b2.conns_active, 0);
    }

    #[test]
    fn rebucket_sums_deltas_and_keeps_last_gauge() {
        let buckets: Vec<Bucket> = (0..120)
            .map(|i| Bucket {
                ts: (i + 1) * 5,
                bytes_up: 10,
                conns_active: i as i64,
                dns_tunnel: 1,
                ..Default::default()
            })
            .collect();
        let wide = rebucket(&buckets, 300);
        // ts 5..=295 → slot 0 (59 buckets), ts 300..=595 → slot 1 (60),
        // ts 600 → slot 2 (1).
        assert_eq!(wide.len(), 3);
        assert_eq!(wide[0].bytes_up, 590);
        assert_eq!(wide[0].conns_active, 58);
        assert_eq!(wide[0].dns_tunnel, 59);
        assert_eq!(wide[0].ts, 295);
        assert_eq!(wide[1].bytes_up, 600);
        assert_eq!(wide[1].conns_active, 118);
        assert_eq!(wide[2].bytes_up, 10);
        assert_eq!(wide[2].conns_active, 119);
        assert_eq!(wide[2].ts, 600);
    }

    #[test]
    fn percentile_math_matches_reference() {
        let mut vals: Vec<f64> = (1..=100).map(|v| v as f64).collect();
        assert!((percentile(&mut vals, 50.0).unwrap() - 50.5).abs() < 1e-9);
        assert!((percentile(&mut vals, 95.0).unwrap() - 95.05).abs() < 1e-9);
        assert!(percentile(&mut [], 50.0).is_none());
        let mut one = vec![42.0];
        assert_eq!(percentile(&mut one, 95.0), Some(42.0));
    }

    #[test]
    fn nice_ceil_picks_nice_steps() {
        assert_eq!(nice_ceil(0.0), 1.0);
        assert_eq!(nice_ceil(0.9), 1.0);
        assert_eq!(nice_ceil(1.1), 2.0);
        assert_eq!(nice_ceil(2.2), 2.5);
        assert_eq!(nice_ceil(4.0), 5.0);
        assert_eq!(nice_ceil(6.0), 10.0);
        assert_eq!(nice_ceil(1150.0), 2000.0);
    }

    #[test]
    fn render_page_smoke() {
        let state = DashboardState::new();
        state.bump(&state.bytes_up, 12345);
        state.bump(&state.bytes_down, 67890);
        state.push_bucket(Bucket {
            ts: 1_700_000_000,
            bytes_up: 100,
            bytes_down: 200,
            conns_active: 3,
            dns_tunnel: 2,
            dns_bypass: 1,
            dns_block: 1,
            ..Default::default()
        });
        state.push_rtt(1_700_000_000, Duration::from_millis(120));
        let html = render_page(&state, 1_700_000_100);
        assert!(html.contains("<svg"));
        assert!(html.contains("rVPN"));
        assert!(html.contains("http-equiv=\"refresh\""));
        assert!(html.contains("Throughput"));
        assert!(html.contains("Handshake RTT"));
    }

    #[test]
    fn stats_json_smoke() {
        let state = DashboardState::new();
        state.bump(&state.bytes_up, 42);
        state.push_bucket(bucket_at(1_700_000_000));
        let json = render_stats_json(&state, 1_700_000_100);
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid json");
        assert_eq!(v["counters"]["bytes_up"], 42);
        assert!(v["uptime_secs"].is_number());
        assert_eq!(v["buckets"].as_array().unwrap().len(), 1);
    }

    async fn http_get(addr: std::net::SocketAddr, path: &str) -> String {
        let mut sock = TcpStream::connect(addr).await.expect("connect");
        let req = format!("GET {} HTTP/1.1\r\nHost: localhost\r\n\r\n", path);
        sock.write_all(req.as_bytes()).await.expect("write");
        let mut out = Vec::new();
        sock.read_to_end(&mut out).await.expect("read");
        String::from_utf8_lossy(&out).into_owned()
    }

    #[tokio::test]
    async fn http_server_serves_both_routes_and_404() {
        let state = Arc::new(DashboardState::new());
        state.push_bucket(Bucket {
            ts: now_unix(),
            bytes_down: 1024,
            ..Default::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let allow = Arc::new(vec!["127.0.0.0/8".parse().expect("valid cidr")]);
        tokio::spawn(serve(listener, Arc::clone(&state), allow));

        let page = http_get(addr, "/").await;
        assert!(
            page.starts_with("HTTP/1.1 200 OK"),
            "page status: {}",
            &page[..page.len().min(80)]
        );
        assert!(page.contains("Content-Type: text/html"));
        assert!(page.contains("<svg"));
        assert!(page.contains("rVPN client"));

        let json = http_get(addr, "/api/stats.json").await;
        assert!(json.starts_with("HTTP/1.1 200 OK"));
        assert!(json.contains("Content-Type: application/json"));
        let body = json.split("\r\n\r\n").nth(1).expect("json body");
        let v: serde_json::Value = serde_json::from_str(body).expect("valid json");
        assert!(v["counters"]["bytes_up"].is_number());

        let missing = http_get(addr, "/nope").await;
        assert!(missing.starts_with("HTTP/1.1 404 Not Found"));
    }

    #[test]
    fn ip_allowed_matches_cidrs() {
        let allow: Vec<IpNetwork> = vec![
            "127.0.0.0/8".parse().unwrap(),
            "192.168.10.0/24".parse().unwrap(),
            "::1/128".parse().unwrap(),
        ];
        let v4 = |a, b, c, d| std::net::IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d));
        assert!(ip_allowed(&v4(127, 0, 0, 1), &allow));
        assert!(ip_allowed(&v4(192, 168, 10, 77), &allow));
        assert!(!ip_allowed(&v4(192, 168, 11, 1), &allow));
        assert!(!ip_allowed(&v4(8, 8, 8, 8), &allow));
        assert!(ip_allowed(&std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), &allow));
        assert!(!ip_allowed(&"2606:4700::1".parse().unwrap(), &allow));
    }

    #[tokio::test]
    async fn http_server_rejects_disallowed_peer() {
        let state = Arc::new(DashboardState::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        // Allow only a LAN range we are not connecting from.
        let allow = Arc::new(vec!["192.168.10.0/24".parse().unwrap()]);
        tokio::spawn(serve(listener, Arc::clone(&state), allow));

        let page = http_get(addr, "/").await;
        assert!(
            page.starts_with("HTTP/1.1 403 Forbidden"),
            "status: {}",
            &page[..page.len().min(80)]
        );
    }
}
