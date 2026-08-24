# Changelog

All notable changes to rVPN are documented in this file.

## [1.3.4] — 2026-08-24

Patch release: DNS resilience and correctness, and a permanent fix for
long-running memory growth in the CLI client.

### Fixed

- **DNS resolver fallback chain (client).** When every configured
  nameserver drops queries — observed in the field on both major CN public
  resolvers (223.6.6.6, 114.114.114.114) — the client now falls through to
  last-resort public resolvers (1.1.1.1, 8.8.8.8) instead of answering
  SERVFAIL. Fixes the recurring "everything stops resolving roughly once an
  hour" report. The system-resolver fallback also no longer loops back into
  the client's own DNS proxy when rvpn is the system resolver.
- **Non-A/AAAA queries answered properly (client + server).** NS, TXT, MX,
  HTTPS and PTR queries are now resolved locally via raw UDP forward.
  Previously the tunnel DNS protocol (A/AAAA only) returned empty NODATA for
  these, or A records that did not match the question type — so tools like
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
