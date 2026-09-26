# Changelog

All notable changes to rVPN are documented in this file.

## [1.3.6] — 2026-09-25

Patch release: a built-in stats dashboard for the CLI client, and a round
of mobile memory and reconnect-stability fixes.

### Added

- **MRTG/RRD-style stats dashboard (client).** The CLI can now serve a
  self-contained HTML page with live graphs (throughput, connections) and
  a JSON endpoint at `/api/stats.json` from a small embedded HTTP
  listener. History is kept in memory for 24 hours. Enable with
  `--dashboard-listen 127.0.0.1:9800` or `[dashboard] enabled = true`.
- **Dashboard access control.** `allow_cidrs` restricts which client IPs
  may view the dashboard (localhost only by default), so it can be shared
  safely on a LAN.

### Fixed

- **Memory leak at the Rust/Swift packet boundary (mobile).** The tunnel
  write loop now wraps the entire iteration (packet drain, packet write
  and status write) in an autoreleasepool. Previously the periodic status
  write autoreleased several KB per call on a thread whose pool never
  drained, leaking ~600 KB/min into the default malloc zone.
- **Stack corruption in the mobile memory diagnostics.** A hand-declared
  `malloc_statistics_t` was 16 bytes short of the platform struct; the C
  write smashed the stack and segfaulted the process at the next session
  end. The declaration now matches the platform header.
- **Overnight extension kills (iOS).** `wake()` no longer tears down the
  Rust core on every maintenance wake, `sleep()` keeps it alive, and
  zombie keepalive tasks no longer send shutdowns into successor
  connections.
- **Reconnect resilience.** The keepalive probes before declaring a
  session dead after a doze, a background assertion is held across every
  reconnect, and the platform health check no longer races the client's
  own reconnect logic.

### Changed

- **Removed the dead Android JNI state-callback path.**

## [1.3.5] — 2026-09-13

Patch release: seamless mobile roaming, pooled multiplexing with TLS
session resumption, and per-instance decoy login pages.

### Added

- **Pooled multiplex mode (client).** Many flows now share a small set of
  long-lived WebSocket connections instead of one connection per flow, with
  credit-based per-flow flow control (256 KiB initial window) and strict
  wire ordering: every encrypt→send path on a shared ratchet is
  serialized, since the Double Ratchet drops reordered frames.
- **TLS 1.3 session resumption (client + mobile).** Reconnects offer the
  cached session ticket (1-RTT PSK), skipping the certificate flight.
- **Per-instance decoy login pages (server).** Non-VPN HTTPS requests are
  served a realistic, randomly chosen login page (webmail, NAS, photo
  sharing, and more) generated per server instance, so no two servers
  present the same face to a prober.
- **Multi-server Direct TUN routing (mobile).** Profiles can carry extra
  exit servers, each with its own route domains and route IPs. Each exit
  resolves names through its own in-tunnel DNS-over-HTTPS channel, and
  every answer teaches the router which exit owns those IPs. Shipped in the
  iOS / macOS / Android apps as v1.2.9.

### Fixed

- **Sticky TUN IP leases across reconnects (server).** Tunnel IPs are now
  leased by the client's X25519 identity key instead of its source IP and
  port. Roaming between Wi-Fi and cellular hands back the same tunnel
  address. Previously the new connection got a fresh IP while the OS kept
  routing to the old one, leaving the tunnel "connected" but passing no
  traffic until a manual reconnect.
- **Pooled-tunnel reliability (multiplex).** Flow-control, wire-order, and
  drain-handling fixes; pooled TCP connections are validated before reuse,
  and control frames travel on a priority channel so bulk data can't delay
  flow lifecycle or credit grants.
- **Ad-block false positive.** The blocklist no longer swallows
  graph.instagram.com.

## [1.3.4] — 2026-08-24

Patch release: DNS resilience and correctness, and a permanent fix for
long-running memory growth in the CLI client.

### Fixed

- **DNS resolver fallback chain (client).** When every configured
  nameserver drops queries (observed in the field on both major CN public
  resolvers, 223.6.6.6 and 114.114.114.114), the client now falls through
  to last-resort public resolvers (1.1.1.1, 8.8.8.8) instead of answering
  SERVFAIL. Fixes the recurring "everything stops resolving roughly once an
  hour" report. The system-resolver fallback also no longer loops back into
  the client's own DNS proxy when rvpn is the system resolver.
- **Non-A/AAAA queries answered properly (client + server).** NS, TXT, MX,
  HTTPS and PTR queries are now resolved locally via raw UDP forward.
  Previously the tunnel DNS protocol (A/AAAA only) returned empty NODATA for
  these, or A records that did not match the question type, so tools like
  `dig` got empty or bogus answers through the proxy.
- **Honest failure signalling (client).** A server-side resolution failure
  is now returned as SERVFAIL instead of a NOERROR with zero answers, which
  had wrongly told stub resolvers the name existed with no such record.
- **Query-type filtering (server).** The DNS handler now returns NODATA for
  qtypes other than A/AAAA instead of unfiltered address lists.
- **Memory growth (client).** The CLI now uses mimalloc as its global
  allocator. glibc's malloc arenas never returned memory under the client's
  allocation churn, growing a long-running gateway by ~5 MB/hour (850 MB
  after one week). The same workload now holds flat at ~25 MB RSS
  indefinitely, with no environment workarounds. Build with
  `--no-default-features` to use the system allocator for diagnostics.

## [1.3.3] — 2026-08

Patch release: server-side DNS relay robustness and a client memory-leak
fix in WebSocket backpressure handling.

### Fixed

- The server-side DNS relay resolved queries one at a time with no timeout;
  a single stalled lookup silently stopped all DNS answers on the tunnel
  until the client gave up and reconnected. Queries now resolve concurrently
  with a 5 s ceiling, a saturated server fails fast instead of silently
  dropping queries, and the client detects a blackholed DNS tunnel in ~10 s
  instead of 60 and reconnects in about a tenth of a second.
- AAAA lookups are answered locally (the tunnel has no IPv6 upstream),
  halving DNS tunnel traffic and keeping name resolution alive while the
  tunnel path is being interfered with.
- Server DNS response TTL raised from 300 s to 900 s, cutting tunnel
  round-trips and lengthening outage survival.
- A client memory leak in WebSocket backpressure handling that grew `rvpn`
  by hundreds of MB over a week.

For earlier releases, see the git history and release notes.
