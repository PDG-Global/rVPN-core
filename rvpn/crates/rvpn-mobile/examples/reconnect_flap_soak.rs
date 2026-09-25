// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of R-VPN.
//
// R-VPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Failure-path per-reconnect leak harness (macOS/iOS-host only).
//!
//! Companion to `reconnect_soak.rs`: instead of clean reconnects against a
//! healthy server, this points the client at a blackholed endpoint (a local
//! sink that accepts TCP and never answers), so every connect attempt fails
//! with "TCP connect + TLS handshake timeout" — the dominant failure mode in
//! the 2026-09-16/17 overnight on-device churn, which grew ~500 KB/cycle in
//! the SYSTEM malloc zones (allzones) while mimalloc commit stayed flat.
//!
//! The client's own reconnect loop flaps with backoff for the whole run;
//! we sample RSS and malloc-zone bytes and print CSV. A rising zone slope
//! across failed attempts reproduces the on-device leak without a phone.
//!
//! Usage (sink listener required, see below):
//! ```sh
//! python3 -c '
//! import socket, threading
//! def hold(c, a):
//!     try: c.recv(1 << 20)
//!     except OSError: pass
//!     c.close()
//! s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
//! s.bind(("127.0.0.1", 18443)); s.listen(128)
//! while True:
//!     c, a = s.accept(); threading.Thread(target=hold, args=(c, a), daemon=True).start()
//! ' &
//! cargo run -p rvpn-mobile --example reconnect_flap_soak \
//!   --features ios-direct-tun,dns --release -- \
//!   --identity /path/to/identity.key --bundle /path/to/bundle.json \
//!   --minutes 15 --interval-secs 15
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use rvpn_mobile::ffi::TunConfig;
use rvpn_mobile::ios_tun::IosTunClient;

/// Resident set size via Mach task_info (same as reconnect_soak).
fn get_rss_bytes() -> u64 {
    const MACH_TASK_BASIC_INFO: u32 = 20;
    const INFO_COUNT: u32 = 12;
    let mut buf = [0i32; 12];
    let mut count = INFO_COUNT;
    #[allow(deprecated)]
    let task = unsafe { libc::mach_task_self() };
    let kr = unsafe { libc::task_info(task, MACH_TASK_BASIC_INFO, buf.as_mut_ptr(), &mut count) };
    if kr != 0 {
        return 0;
    }
    let lo = buf[2] as u32 as u64;
    let hi = buf[3] as u32 as u64;
    (hi << 32) | lo
}

// libmalloc zone enumeration (macOS host has the same API as iOS). Matches
// <malloc/malloc.h> — malloc_statistics_t is 32 bytes on 64-bit; declaring it
// smaller is a stack smash (the build-19..21 reconnect segfault).
#[repr(C)]
struct MallocStatistics {
    blocks_in_use: libc::c_uint,
    _pad: u32,
    size_in_use: usize,
    max_size_in_use: usize,
    size_allocated: usize,
}

extern "C" {
    fn malloc_get_all_zones(
        task: libc::mach_port_t,
        reader: *mut std::ffi::c_void,
        addresses: *mut *mut usize,
        count: *mut u32,
    ) -> libc::c_int;
    fn malloc_zone_statistics(zone: *mut std::ffi::c_void, stats: *mut MallocStatistics);
}

/// Sum of live bytes-in-use across all malloc zones (the metric that grew
/// ~500 KB per failed reconnect on-device).
fn all_zones_size_in_use() -> u64 {
    unsafe {
        let mut array: *mut usize = std::ptr::null_mut();
        let mut count: u32 = 0;
        #[allow(deprecated)]
        let task = libc::mach_task_self();
        let kr = malloc_get_all_zones(task, std::ptr::null_mut(), &mut array, &mut count);
        if kr != 0 || array.is_null() || count == 0 {
            return 0;
        }
        let zones = std::slice::from_raw_parts(array, count as usize);
        let mut total = 0u64;
        for &addr in zones {
            if addr == 0 {
                continue;
            }
            let mut stats = MallocStatistics {
                blocks_in_use: 0,
                _pad: 0,
                size_in_use: 0,
                max_size_in_use: 0,
                size_allocated: 0,
            };
            malloc_zone_statistics(addr as *mut std::ffi::c_void, &mut stats);
            total += stats.size_in_use as u64;
        }
        total
    }
}

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let server = arg_value(&args, "--server")
        .unwrap_or_else(|| "wss://127.0.0.1:18443/api/v1/ws/tun".to_string());
    let identity = arg_value(&args, "--identity").expect("--identity <path> required");
    let bundle = arg_value(&args, "--bundle").expect("--bundle <path> required");
    let minutes: u64 = arg_value(&args, "--minutes")
        .and_then(|v| v.parse().ok())
        .unwrap_or(15);
    let interval_secs: u64 = arg_value(&args, "--interval-secs")
        .and_then(|v| v.parse().ok())
        .unwrap_or(15);

    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::INFO)
        .init();

    let config = TunConfig {
        server_address: server,
        identity_key_path: identity,
        prekey_bundle_path: bundle,
        dns_servers: vec![],
        bypass_networks: vec![],
        mtu: 1420,
        split_tunnel_enabled: true,
        builtin_bypass_countries: vec![],
        bypass_domains: vec![],
        tunnel_domains: vec![],
        block_ads: false,
        // Distinct port from reconnect_soak so both can run side by side.
        dns_bind_addr: "127.0.0.1:15354".to_string(),
        enable_dns_proxy: true,
        stealth_fingerprint: None,
        server_identity_pin: None,
        country_ips_file: None,
        extra_servers: vec![],
        routing: Default::default(),
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let handle = runtime.handle().clone();

    let client = Arc::new(IosTunClient::new(&config, handle).expect("IosTunClient::new failed"));
    client.set_reconnect_enabled(true);
    client.start();

    println!("sample,elapsed_secs,rss_bytes,allzones_bytes");
    let start = Instant::now();
    let samples = (minutes * 60) / interval_secs;
    for i in 0..samples {
        std::thread::sleep(Duration::from_secs(interval_secs));
        println!(
            "{},{},{},{}",
            i,
            start.elapsed().as_secs(),
            get_rss_bytes(),
            all_zones_size_in_use()
        );
    }

    client.stop();
    std::thread::sleep(Duration::from_secs(2));
}
