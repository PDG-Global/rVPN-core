// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// R-VPN Client Implementation - Brook-style Architecture
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! R-VPN Client Implementation - Brook-style simplified architecture

mod config;
mod dns;
mod dns_cache;
mod dns_proxy;
mod http_proxy;
mod identity_verification;
mod metrics;
mod proxy_common;
mod router;
mod server_pool;
mod socks5;
mod socks5_tunnel;
mod split_tunnel;
mod stats;
mod stream_relay;
// TLS re-exported from rvpn-tls crate
mod tun;
mod tunnel;
mod websocket;

/// Maximum reconnection attempts before giving up
const MAX_RECONNECT_ATTEMPTS: u32 = 10;
/// Initial delay between reconnection attempts (ms)
const INITIAL_RECONNECT_DELAY_MS: u64 = 1000;
/// Maximum delay between reconnection attempts (ms)
const MAX_RECONNECT_DELAY_MS: u64 = 30000;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::id as process_id;

use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use config::ClientConfig;
use socks5::Socks5Proxy;

/// Helper to run cleanup on drop
struct OnDrop<F: FnMut()>(F);

impl<F: FnMut()> OnDrop<F> {
    fn new(f: F) -> Self {
        Self(f)
    }
}

impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        self.0();
    }
}

/// CLI arguments
#[derive(Parser, Debug)]
#[command(name = "rvpn")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "R-VPN Client - A stealth VPN with Double Ratchet encryption")]
struct Args {
    /// Configuration file
    #[arg(short, long, default_value = "client.toml")]
    config: PathBuf,

    /// Server address (overrides config)
    #[arg(long)]
    server: Option<String>,

    /// Path to server prekey bundle JSON file
    #[arg(long)]
    bundle: Option<PathBuf>,

    /// TLS fingerprint for DPI resistance (chrome, firefox, safari, ios, android, edge, none)
    #[arg(long)]
    fingerprint: Option<String>,

    /// Enable verbose logging
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Subcommands
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate new identity key
    Keygen {
        /// Key type (ed25519)
        #[arg(long, default_value = "ed25519")]
        key_type: String,
        /// Output file path
        #[arg(short, long, default_value = "identity.key")]
        output: PathBuf,
    },
    /// Extract public key from identity file
    Pubkey {
        /// Input identity key file
        #[arg(short, long)]
        key: PathBuf,
        /// Output public key file
        #[arg(short, long, default_value = "public.key")]
        output: PathBuf,
    },
    /// Show VPN status
    Status {
        /// Number of historical entries to show
        #[arg(short, long, default_value_t = 5)]
        entries: usize,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Setup logging
    let log_level = match args.verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(true)
        .with_line_number(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("Failed to set tracing subscriber");

    info!("R-VPN Client v{}", env!("CARGO_PKG_VERSION"));

    // Load configuration
    let config = if args.config.exists() {
        info!("Loading configuration from {:?}", args.config);
        ClientConfig::load(&args.config)?
    } else {
        info!("No config file found, using defaults");
        ClientConfig::default()
    };

    // Override with CLI arguments
    let mut config = config;
    if let Some(server) = args.server {
        config.server_address = server;
    }
    if let Some(bundle) = args.bundle {
        config.prekey_bundle = Some(bundle);
    }
    if let Some(fingerprint) = args.fingerprint {
        if let Some(fp) = rvpn_tls::fingerprint_from_str(&fingerprint) {
            config.tls_fingerprint = fp;
        }
    }

    // Handle subcommands
    match args.command {
        Some(Commands::Keygen { output, .. }) => {
            return keygen(output);
        }
        Some(Commands::Pubkey { key, output }) => {
            return pubkey(key, output);
        }
        Some(Commands::Status { entries }) => {
            return show_status(entries).await;
        }
        _ => {}
    }

    // Run in appropriate mode based on config
    if config.tun.enabled {
        // Run in TUN mode (full VPN)
        run_tun(config).await
    } else {
        // Run SOCKS5 proxy (Brook-style: each connection manages its own WebSocket)
        run_socks5(config).await
    }
}

/// Run in SOCKS5 proxy mode (Brook-style)
async fn run_socks5(config: ClientConfig) -> Result<()> {
    info!("Starting R-VPN Client in SOCKS5 mode (Brook-style)");
    info!("Server: {}", config.server_address);

    // Save PID file
    let pid_file = config.data_dir.join("rvpn.pid");
    tokio::fs::create_dir_all(&config.data_dir).await?;
    tokio::fs::write(&pid_file, process_id().to_string()).await?;
    info!("Saved PID to {:?}", pid_file);

    // Set up cleanup on exit
    let pid_file_clone = pid_file.clone();
    let _guard = OnDrop::new(move || {
        let _ = std::fs::remove_file(&pid_file_clone);
    });

    let socks_addr: SocketAddr = config.socks5.listen_address.parse()?;

    // Initialize stats manager for historical tracking
    let stats_manager = stats::init_global_stats_manager_with_dir(config.data_dir.clone()).await;
    let _stats_handle = stats_manager.start_collection();

    // Create SOCKS5 proxy (each connection manages its own WebSocket)
    let proxy = Socks5Proxy::new(socks_addr, &config).await?;

    // Optionally start DNS proxy (forwards UDP DNS through the tunnel's /dns endpoint)
    if config.dns_proxy.enabled {
        let dns_listen: std::net::SocketAddr =
            config.dns_proxy.listen_address.parse().with_context(|| {
                format!(
                    "Invalid DNS proxy listen address: {}",
                    config.dns_proxy.listen_address
                )
            })?;

        // Parse nameservers — accept both "ip:port" and bare "ip" (defaults to :53)
        let mut nameservers: Vec<std::net::SocketAddr> = Vec::new();
        for ns_str in &config.dns_proxy.nameservers {
            let parsed: Result<std::net::SocketAddr, _> = ns_str.parse();
            match parsed {
                Ok(addr) => nameservers.push(addr),
                Err(_) => {
                    // Try parsing as bare IP and append :53
                    let with_port = format!("{}:53", ns_str);
                    match with_port.parse() {
                        Ok(addr) => nameservers.push(addr),
                        Err(e) => {
                            warn!("Failed to parse DNS nameserver '{}': {}. Expected format: ip:port or bare ip", ns_str, e);
                        }
                    }
                }
            }
        }
        if nameservers.is_empty() && !config.dns_proxy.nameservers.is_empty() {
            warn!("All configured DNS nameservers failed to parse. Using defaults.");
            nameservers = vec![
                "223.5.5.5:53".parse().unwrap(),
                "1.1.1.1:53".parse().unwrap(),
                "8.8.8.8:53".parse().unwrap(),
            ];
        }

        let dns_proxy = std::sync::Arc::new(dns_proxy::DnsProxy::new(
            dns_listen,
            proxy.server_host().to_string(),
            proxy.server_port(),
            proxy.server_path(),
            proxy.tls_fingerprint(),
            proxy.identity_key(),
            proxy.server_bundle(),
            proxy.split_tunnel(),
            proxy.dns_resolver(),
            nameservers,
        ));

        tokio::spawn(async move {
            if let Err(e) = dns_proxy.run().await {
                error!("DNS proxy fatal error: {}", e);
            }
        });
    }

    // Optionally start HTTP proxy (shares mux tunnel with SOCKS5)
    if config.http_proxy.enabled {
        let http_listen: SocketAddr = config.http_proxy.listen_address.parse().with_context(|| {
            format!(
                "Invalid HTTP proxy listen address: {}",
                config.http_proxy.listen_address
            )
        })?;

        let http_proxy = http_proxy::HttpProxy::new(
            http_listen,
            &config,
            proxy.identity_key(),
            proxy.server_bundle(),
            proxy.split_tunnel(),
            proxy.dns_resolver(),
            proxy.mux_tunnel(),
            proxy.pool(),
            proxy.router(),
        )
        .await?;

        tokio::spawn(async move {
            if let Err(e) = http_proxy.run().await {
                error!("HTTP proxy fatal error: {}", e);
            }
        });
    }

    // Run SOCKS5 proxy (never returns unless error)
    proxy.run().await?;

    Ok(())
}

/// Run in TUN mode (full VPN)
async fn run_tun(config: ClientConfig) -> Result<()> {
    use tun::TunDevice;
    use tunnel::VpnTunnel;

    // Multi-server routing is per-flow SOCKS5 only. TUN mode wraps the
    // whole network stack in one tunnel, so per-domain routing has no
    // meaningful hook. Refuse rather than silently ignoring the config.
    if !config.extra_servers.is_empty() || !config.routing.is_empty() {
        anyhow::bail!(
            "multi-server routing ([[server]] / [routing.<name>]) is only supported in SOCKS5 mode; \
             remove those sections or disable TUN mode"
        );
    }

    info!("Starting R-VPN Client in TUN mode (full VPN)");
    info!("Server: {}", config.server_address);
    let if_name = config.tun.interface_name.as_deref().unwrap_or("(auto-assigned by OS)");
    info!("TUN interface: {} (IP will be assigned by server)", if_name);

    // Save PID file
    let pid_file = config.data_dir.join("rvpn.pid");
    tokio::fs::create_dir_all(&config.data_dir).await?;
    tokio::fs::write(&pid_file, process_id().to_string()).await?;
    info!("Saved PID to {:?}", pid_file);

    // Set up cleanup on exit
    let pid_file_clone = pid_file.clone();
    let _guard = OnDrop::new(move || {
        let _ = std::fs::remove_file(&pid_file_clone);
    });

    // Parse server URL
    let (host, port, path) = parse_server_url(&config.server_address);

    // Initialize stats manager for historical tracking
    let stats_manager = stats::init_global_stats_manager_with_dir(config.data_dir.clone()).await;
    let _stats_handle = stats_manager.start_collection();

    // Reconnection state
    let mut reconnect_attempts: u32 = 0;
    let tun_config = config.tun.clone();

    // Set up signal handling for graceful shutdown
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Spawn signal handler task
    tokio::spawn(async move {
        handle_signals(shutdown_tx).await;
    });

    // Main reconnection loop
    loop {
        // Check shutdown signal first
        if *shutdown_rx.borrow() {
            info!("Shutdown signal received, exiting TUN mode");
            break;
        }

        // Connect VPN tunnel
        info!(
            "Connecting VPN tunnel to {}:{}{} (attempt {})",
            host, port, path, reconnect_attempts + 1
        );

        let tunnel = match VpnTunnel::connect(
            &host,
            port,
            &path,
            config.tls_fingerprint,
            config.sni_hostname.as_deref(),
            &config.identity_key_file,
            config.prekey_bundle.as_deref(),
            &config.server_identity,
        )
        .await
        {
            Ok(t) => {
                info!("VPN tunnel established successfully");
                reconnect_attempts = 0; // Reset on successful connection
                t
            }
            Err(e) => {
                error!("Failed to connect VPN tunnel: {}", e);
                reconnect_attempts += 1;
                if reconnect_attempts >= MAX_RECONNECT_ATTEMPTS {
                    error!("Max connection attempts ({}) reached, giving up", MAX_RECONNECT_ATTEMPTS);
                    return Err(anyhow::anyhow!("Failed to connect after {} attempts: {}", MAX_RECONNECT_ATTEMPTS, e));
                }
                let delay_ms = std::cmp::min(
                    INITIAL_RECONNECT_DELAY_MS * (2_u64.pow(reconnect_attempts.min(5))),
                    MAX_RECONNECT_DELAY_MS,
                );
                warn!("Retrying in {} ms (attempt {}/{})", delay_ms, reconnect_attempts, MAX_RECONNECT_ATTEMPTS);
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                continue;
            }
        };

        // Get the server-assigned virtual IP and gateway
        let (virtual_ip, gateway_ip, mtu) = {
            let tunnel_guard = tunnel.read().await;
            (tunnel_guard.virtual_ip, tunnel_guard.gateway_ip, tunnel_guard.mtu)
        };

        // Build the IP CIDR string from the server-assigned IP
        let ip_cidr = match virtual_ip {
            Some(ip) => {
                format!("{}/24", ip)
            }
            None => {
                error!("No IP address assigned by server - TUN mode requires server-assigned IP");
                reconnect_attempts += 1;
                continue;
            }
        };

        // Log gateway info (gateway is derived if not sent by server)
        if let Some(gw) = gateway_ip {
            info!("Server assigned IP: {}, Gateway: {}, MTU: {}", ip_cidr, gw, mtu);
        } else {
            info!("Server assigned IP: {}, MTU: {} (gateway will be derived)", ip_cidr, mtu);
        }

        // Create TUN device with server-assigned IP
        let tun_device = match TunDevice::create_with_ip(&tun_config, &ip_cidr)
            .with_context(|| "Failed to create TUN device")
        {
            Ok(d) => d,
            Err(e) => {
                error!("Failed to create TUN device: {}", e);
                reconnect_attempts += 1;
                let delay_ms = std::cmp::min(
                    INITIAL_RECONNECT_DELAY_MS * (2_u64.pow(reconnect_attempts.min(5))),
                    MAX_RECONNECT_DELAY_MS,
                );
                warn!("Retrying TUN device creation in {} ms", delay_ms);
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
                continue;
            }
        };

        info!("TUN device ready");

        // Run TUN device until tunnel disconnects OR shutdown signal received
        // Use tokio::select! to wait on both simultaneously
        let (local_shutdown_tx, local_shutdown_rx) = tokio::sync::watch::channel(false);
        let run_result = tokio::select! {
            result = tun_device.run(tunnel, local_shutdown_rx) => {
                Some(result)
            }
            _ = shutdown_rx_changed(&shutdown_rx) => {
                info!("Shutdown signal received during tunnel run");
                let _ = local_shutdown_tx.send(true);
                None
            }
        };

        // Check if we exited due to shutdown
        if *shutdown_rx.borrow() {
            info!("Shutdown signal received, exiting TUN mode");
            break;
        }

        match run_result {
            Some(Ok(())) => {
                info!("TUN device run completed normally");
                break;
            }
            Some(Err(e)) => {
                error!("TUN device error: {}", e);
                reconnect_attempts += 1;

                if reconnect_attempts >= MAX_RECONNECT_ATTEMPTS {
                    error!("Max reconnection attempts ({}) reached, giving up", MAX_RECONNECT_ATTEMPTS);
                    return Err(anyhow::anyhow!("Tunnel disconnected after {} reconnection attempts: {}", MAX_RECONNECT_ATTEMPTS, e));
                }

                let delay_ms = std::cmp::min(
                    INITIAL_RECONNECT_DELAY_MS * (2_u64.pow(reconnect_attempts.min(5))),
                    MAX_RECONNECT_DELAY_MS,
                );
                warn!("Tunnel disconnected, reconnecting in {} ms (attempt {}/{})", delay_ms, reconnect_attempts, MAX_RECONNECT_ATTEMPTS);

                // Brief pause before reconnect
                tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
            }
            None => {
                // Shutdown was triggered
                break;
            }
        }
    }

    info!("TUN mode shutdown complete");
    Ok(())
}

/// Handle shutdown signals (SIGINT, SIGTERM on Unix; Ctrl+C on Windows)
async fn handle_signals(shutdown_tx: tokio::sync::watch::Sender<bool>) {
    #[cfg(unix)]
    {
        let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .expect("Failed to create SIGINT handler");
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("Failed to create SIGTERM handler");

        tokio::select! {
            _ = sigint.recv() => {
                info!("Received SIGINT, initiating graceful shutdown...");
            }
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown...");
            }
        }
    }

    #[cfg(windows)]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        info!("Received Ctrl+C, initiating graceful shutdown...");
    }

    let _ = shutdown_tx.send(true);
}

/// Wait for shutdown signal to be received
async fn shutdown_rx_changed(shutdown_rx: &tokio::sync::watch::Receiver<bool>) {
    // This helper waits until the shutdown signal changes from false to true
    // It uses the watch::Channel's changed() method
    let mut rx = shutdown_rx.clone();
    // If already true, return immediately
    if *rx.borrow() {
        return;
    }
    // Otherwise wait for change
    let _ = rx.changed().await;
}

/// Parse server URL into (host, port, path) components
fn parse_server_url(url: &str) -> (String, u16, String) {
    // Handle ws:// and wss:// URLs
    let url = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url);

    // Split path
    let (host_port, path) = url
        .split_once('/')
        .map(|(hp, p)| (hp, format!("/{}", p)))
        .unwrap_or((url, "/".to_string()));

    // Handle IPv6: [host]:port
    if host_port.starts_with('[') {
        if let Some(bracket_end) = host_port.find(']') {
            let host = host_port[1..bracket_end].to_string();
            let port = if bracket_end + 1 < host_port.len() && host_port.as_bytes()[bracket_end + 1] == b':' {
                host_port[bracket_end + 2..].parse().unwrap_or(443)
            } else {
                443
            };
            return (host, port, path);
        }
    }

    // IPv4 or hostname
    let (host, port) = host_port
        .split_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(443)))
        .unwrap_or_else(|| (host_port.to_string(), 443));

    (host, port, path)
}

/// Generate a new identity key
fn keygen(output: PathBuf) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use rvpn_core::crypto::IdentityKey;

    let identity = IdentityKey::generate();

    // Create a simple key file format
    let key_data = format!(
        "R-VPN-IDENTITY-v1\n{}\n{}\n",
        BASE64.encode(identity.verifying_key.as_bytes()),
        BASE64.encode(identity.signing_key.to_bytes())
    );

    // Write with restrictive permissions (owner read/write only) on Unix
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&output)?
            .write_all(key_data.as_bytes())?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&output, key_data)?;
    }

    info!("Generated identity key: {:?}", output);

    Ok(())
}

/// Extract public key from identity file
fn pubkey(key_path: PathBuf, output: PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(&key_path)?;
    let lines: Vec<&str> = content.lines().collect();

    if lines.len() < 3 || lines[0] != "R-VPN-IDENTITY-v1" {
        anyhow::bail!("Invalid key file format");
    }

    let public_key_b64 = lines[1];

    // Write public key file
    let key_data = format!("R-VPN-PUBLICKEY-v1\n{}\n", public_key_b64);
    std::fs::write(&output, key_data)?;
    info!("Extracted public key to: {:?}", output);

    Ok(())
}

/// Show connection status
async fn show_status(entries: usize) -> Result<()> {
    use crate::stats::StatsHistory;

    // Get data directory
    let data_dir = dirs::data_dir()
        .map(|d| d.join("rvpn"))
        .unwrap_or_else(|| PathBuf::from("."));

    // Check if client is running
    let pid_file = data_dir.join("rvpn.pid");
    let is_running = if pid_file.exists() {
        let pid_str = std::fs::read_to_string(&pid_file)?;
        let pid: u32 = pid_str.trim().parse()?;
        #[cfg(unix)]
        {
            // On Unix, signal 0 doesn't send anything but checks if process exists
            std::process::Command::new("kill")
                .args(["-0", &pid.to_string()])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        }
        #[cfg(windows)]
        {
            std::process::Command::new("tasklist")
                .args(["/FI", &format!("PID eq {}", pid), "/NH"])
                .output()
                .map(|o| {
                    let output = String::from_utf8_lossy(&o.stdout);
                    output.contains(&pid.to_string())
                })
                .unwrap_or(false)
        }
    } else {
        false
    };

    // Print status header
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║                    R-VPN Client Status                      ║");
    println!("╠══════════════════════════════════════════════════════════════╣");

    if is_running {
        println!(
            "║  Status: \x1b[32mRunning\x1b[0m                                              ║"
        );
        if pid_file.exists() {
            if let Ok(pid_str) = std::fs::read_to_string(&pid_file) {
                println!(
                    "║  PID: {}                                                 ║",
                    pid_str.trim()
                );
            }
        }
    } else {
        println!("║  Status: \x1b[31mStopped\x1b[0m                                             ║");
    }

    // Load and display historical stats
    match StatsHistory::load_from(&data_dir).await {
        Ok(history) => {
            println!("╠══════════════════════════════════════════════════════════════╣");
            println!(
                "║  Historical Stats ({:.0} entries)                               ║",
                history.len()
            );
            println!("╠══════════════════════════════════════════════════════════════╣");

            if let Some(latest) = history.latest() {
                let snapshot = &latest.snapshot;
                println!(
                    "║  Last Update: {}                                   ║",
                    latest.formatted_time()
                );
                println!(
                    "║  Connection Uptime: {}                              ║",
                    format_uptime(snapshot.connection_uptime_secs)
                );
                println!(
                    "║  Messages Sent: {}                                 ║",
                    format_number(snapshot.messages_sent_total)
                );
                println!(
                    "║  Messages Received: {}                             ║",
                    format_number(snapshot.messages_received_total)
                );
                println!(
                    "║  Data Sent: {}                                      ║",
                    format_bytes(snapshot.bytes_sent_total)
                );
                println!(
                    "║  Data Received: {}                                  ║",
                    format_bytes(snapshot.bytes_received_total)
                );
            } else {
                println!("║  No historical data available                              ║");
            }

            // Show recent entries if requested
            if entries > 0 && history.len() > 1 {
                println!("╠══════════════════════════════════════════════════════════════╣");
                println!(
                    "║  Recent Entries (last {})                                ║",
                    entries
                );
                println!("╠══════════════════════════════════════════════════════════════╣");

                let history_vec: Vec<_> = history.entries().iter().rev().take(entries).collect();
                for entry in history_vec {
                    println!(
                        "║  {} - {:.1} msg/s                           ║",
                        entry.formatted_time(),
                        entry.snapshot.messages_received_per_sec
                    );
                }
            }
        }
        Err(e) => {
            println!("╠══════════════════════════════════════════════════════════════╣");
            println!(
                "║  Error loading stats: {}                                  ║",
                e
            );
        }
    }

    println!("╚══════════════════════════════════════════════════════════════╝");

    Ok(())
}

/// Format uptime
fn format_uptime(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
}

/// Format number with commas
fn format_number(n: u64) -> String {
    n.to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .unwrap_or_default()
        .join(",")
}

/// Format bytes
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;
    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }
    format!("{:.2} {}", size, UNITS[unit_idx])
}
