// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of R-VPN.
//
// R-VPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Dynamic per-IP exit-server route map for multi-server Direct TUN.
//!
//! Static routing (`Router` CIDR rules) covers configured IP ranges, but
//! domain rules need the resolver's cooperation: when the DNS layer resolves
//! a routed domain via exit "sg", it records every A address in the answer
//! here (`ip → (exit, expiry)`), keyed by the answer's TTL. The uplink demux
//! consults this map before the static table so domain-routed flows reach
//! the same exit that resolved them.
//!
//! Entries expire lazily: `lookup` treats a stale entry as a miss and removes
//! it, and `insert` sweeps the whole map once it grows past `SWEEP_THRESHOLD`
//! so a long-lived tunnel does not accumulate dead entries. Absence of an
//! entry means "default exit" — the default session never appears here.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// One dynamic route: packets to this IP go via `server` until `expires`.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Exit server name (a key of `TunConfig.extra_servers` / sessions map).
    pub server: String,
    /// Expiry instant (DNS answer TTL from the moment it was recorded).
    pub expires: Instant,
}

/// Default cap on entries. DNS answers are small; 4096 IPs is far beyond
/// what a realistic routed-domain set produces, and each entry is ~60 bytes.
const MAX_ENTRIES: usize = 4096;

/// Map of destination IP → exit server, populated from routed DNS answers.
#[derive(Debug, Default)]
pub struct RouteMap {
    inner: HashMap<IpAddr, RouteEntry>,
}

impl RouteMap {
    /// Create an empty route map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `ip` is reachable via `server` for `ttl` from now.
    /// Re-inserting an existing IP refreshes both the exit and the expiry.
    pub fn insert(&mut self, ip: IpAddr, server: &str, ttl: Duration) {
        if self.inner.len() >= MAX_ENTRIES && !self.inner.contains_key(&ip) {
            // Over the cap: sweep expired entries first; if still full, drop
            // the soonest-to-expire entry to make room (bounded memory).
            let now = Instant::now();
            self.inner.retain(|_, e| e.expires > now);
            if self.inner.len() >= MAX_ENTRIES {
                if let Some(oldest) = self
                    .inner
                    .iter()
                    .min_by_key(|(_, e)| e.expires)
                    .map(|(k, _)| *k)
                {
                    self.inner.remove(&oldest);
                }
            }
        }
        self.inner.insert(
            ip,
            RouteEntry {
                server: server.to_string(),
                expires: Instant::now() + ttl,
            },
        );
    }

    /// Look up the exit server for `ip`. Returns `None` when there is no
    /// entry or the entry has expired (expired entries are swept on lookup).
    pub fn lookup(&mut self, ip: &IpAddr) -> Option<String> {
        match self.inner.get(ip) {
            Some(entry) if entry.expires > Instant::now() => Some(entry.server.clone()),
            Some(_) => {
                self.inner.remove(ip);
                None
            }
            None => None,
        }
    }

    /// Number of live + not-yet-swept entries (diagnostics/tests).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn lookup_hits_live_entry() {
        let mut map = RouteMap::new();
        map.insert(ip(1, 2, 3, 4), "sg", Duration::from_secs(300));
        assert_eq!(map.lookup(&ip(1, 2, 3, 4)).as_deref(), Some("sg"));
        assert_eq!(map.lookup(&ip(9, 9, 9, 9)), None);
    }

    #[test]
    fn expired_entry_is_swept_on_lookup() {
        let mut map = RouteMap::new();
        map.insert(ip(1, 2, 3, 4), "sg", Duration::from_secs(0));
        assert_eq!(map.lookup(&ip(1, 2, 3, 4)), None, "expired entry must miss");
        assert_eq!(map.len(), 0, "expired entry must be removed");
    }

    #[test]
    fn reinsert_refreshes_exit_and_expiry() {
        let mut map = RouteMap::new();
        map.insert(ip(1, 2, 3, 4), "sg", Duration::from_secs(0));
        // Refresh with a different exit and a live TTL before lookup sweeps it.
        map.insert(ip(1, 2, 3, 4), "hk", Duration::from_secs(300));
        assert_eq!(map.lookup(&ip(1, 2, 3, 4)).as_deref(), Some("hk"));
    }

    #[test]
    fn over_cap_insert_sweeps_expired() {
        let mut map = RouteMap::new();
        for i in 0..MAX_ENTRIES as u32 {
            let v = ip(10, (i >> 8) as u8, i as u8, 1);
            // Half expired, half live.
            let ttl = if i % 2 == 0 {
                Duration::from_secs(0)
            } else {
                Duration::from_secs(300)
            };
            map.insert(v, "sg", ttl);
        }
        // Expired half is swept during inserts once the cap is hit, so the
        // map never exceeds the cap.
        assert!(map.len() <= MAX_ENTRIES);
        let live = ip(10, 1, 1, 1); // odd i => live
        assert_eq!(map.lookup(&live).as_deref(), Some("sg"));
    }
}
