// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of R-VPN.
//
// R-VPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Local per-reconnect memory leak harness (macOS/iOS-host only).
//!
//! Drives an [`IosTunClient`] through N lightweight reconnects
//! (`request_reconnect`, the same internal path the keepalive suspension
//! detector uses overnight on-device) and samples RSS after each cycle,
//! printing CSV to stdout. A rising RSS slope across cycles reproduces the
//! on-device per-reconnect leak (~200 KB/session) without needing a phone.
//!
//! Usage:
//! ```sh
//! cargo run -p rvpn-mobile --example reconnect_soak \
//!   --features ios-direct-tun,dns --release -- \
//!   --server wss://003.hk.97688.io/api/v1/ws/tun \
//!   --identity /path/to/identity.key \
//!   --bundle /path/to/hk.prekey-bundle.json \
//!   --cycles 100 --interval-secs 10
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use rvpn_mobile::ffi::TunConfig;
use rvpn_mobile::ios_tun::{IosTunClient, TunClientState};

/// Resident set size in bytes via Mach task_info (same flavor the on-device
/// diagnostics use). Reimplemented here so the harness doesn't need the
/// `diagnostics` feature — its per-frame sampling would pollute the leak
/// measurement itself.
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

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn wait_for_state(client: &Arc<IosTunClient>, want: TunClientState, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if client.get_state() == want {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    false
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let server = arg_value(&args, "--server")
        .unwrap_or_else(|| "wss://003.hk.97688.io/api/v1/ws/tun".to_string());
    let identity = arg_value(&args, "--identity").expect("--identity <path> required");
    let bundle = arg_value(&args, "--bundle").expect("--bundle <path> required");
    let cycles: u32 = arg_value(&args, "--cycles")
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let interval_secs: u64 = arg_value(&args, "--interval-secs")
        .and_then(|v| v.parse().ok())
        .unwrap_or(10);

    // Errors/warnings to stderr; the CSV on stdout stays clean.
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
        dns_bind_addr: "127.0.0.1:15353".to_string(),
        enable_dns_proxy: true,
        stealth_fingerprint: None,
        server_identity_pin: None,
        country_ips_file: None,
        extra_servers: vec![],
        routing: Default::default(),
    };

    // Runtime is owned by main, never by anything captured into a task —
    // same ownership discipline as ios_tun_ffi::TUN_RUNTIME.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let handle = runtime.handle().clone();

    let client = Arc::new(IosTunClient::new(&config, handle).expect("IosTunClient::new failed"));
    // The FFI start path enables the reconnect loop before starting; mirror it.
    client.set_reconnect_enabled(true);
    client.start();

    if !wait_for_state(&client, TunClientState::Connected, Duration::from_secs(30)) {
        eprintln!("initial connect did not reach Connected within 30s");
        std::process::exit(1);
    }

    println!("cycle,rss_bytes,rss_delta_bytes");
    let mut prev_rss = get_rss_bytes();
    println!("0,{},0", prev_rss);

    for cycle in 1..=cycles {
        let cycle_start = Instant::now();
        client.request_reconnect();
        if !wait_for_state(&client, TunClientState::Connected, Duration::from_secs(30)) {
            eprintln!("cycle {}: reconnect did not reach Connected within 30s", cycle);
            std::process::exit(1);
        }
        // Hold the remainder of the interval so each cycle spans a
        // consistent wall-clock window, like on-device doze/reconnect churn.
        let elapsed = cycle_start.elapsed();
        if elapsed < Duration::from_secs(interval_secs) {
            std::thread::sleep(Duration::from_secs(interval_secs) - elapsed);
        }
        let rss = get_rss_bytes();
        println!("{},{},{}", cycle, rss, rss as i64 - prev_rss as i64);
        prev_rss = rss;
    }

    client.stop();
    // Give tasks a moment to unwind so a clean exit doesn't mask a
    // shutdown-path panic in the output.
    std::thread::sleep(Duration::from_secs(2));
}
