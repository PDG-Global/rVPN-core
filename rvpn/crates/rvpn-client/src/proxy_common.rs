// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared proxy routing logic used by both SOCKS5 and HTTP proxy modules.
//!
//! After protocol-specific handshake, both produce a target `host:port` and a `TcpStream`.
//! This module handles the downstream routing: split tunnel decision → bypass/tunnel/block.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

use rvpn_core::crypto::{IdentityKey, X3DHPublicBundle};

use crate::config::ServerIdentityConfig;
use crate::socks5_tunnel::{self, Socks5Tunnel};
use crate::split_tunnel::{SplitTunnel, RoutingDecision};
use crate::stream_relay::StreamRelay;
use rvpn_tls::TlsFingerprint;

/// Lightweight handle passed to each connection handler.
/// Contains everything needed to route traffic through the VPN tunnel.
pub struct ProxyHandle {
    pub server_host: String,
    pub server_port: u16,
    pub server_path: String,
    pub tls_fingerprint: TlsFingerprint,
    pub sni_hostname: Option<String>,
    pub identity_key: Arc<IdentityKey>,
    pub server_bundle: Arc<X3DHPublicBundle>,
    pub server_identity: ServerIdentityConfig,
    pub split_tunnel: Arc<SplitTunnel>,
    pub multiplex: bool,
    pub mux_path: String,
    pub mux_tunnel: Arc<Mutex<Option<Arc<Socks5Tunnel>>>>,
}

/// Parse target address into host and port.
pub fn parse_target(target: &str) -> Result<(String, u16)> {
    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid target format"))?;
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid port"))?;
    Ok((host.to_string(), port))
}

/// Encode target address for server.
/// Format: [host_len: u8][host_bytes][port: u16_be]
pub fn encode_target_address(target: &str) -> Result<Vec<u8>> {
    let (host, port_str) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid target address format, expected host:port"))?;

    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid port number: {}", port_str))?;

    let host_bytes = host.as_bytes();
    if host_bytes.len() > 255 {
        return Err(anyhow::anyhow!("Hostname too long"));
    }

    let mut result = Vec::with_capacity(1 + host_bytes.len() + 2);
    result.push(host_bytes.len() as u8);
    result.extend_from_slice(host_bytes);
    result.extend_from_slice(&port.to_be_bytes());

    Ok(result)
}

/// Route a connection through the VPN tunnel or directly.
///
/// This is the shared routing logic after protocol-specific handshake is complete.
/// The `socket` should already have the protocol-specific success response sent
/// (SOCKS5 10-byte reply or HTTP "200 Connection Established").
pub async fn route_connection(
    socket: TcpStream,
    addr: SocketAddr,
    target_addr: &str,
    proxy: &ProxyHandle,
) -> Result<()> {
    let (target_host, target_port) = parse_target(target_addr)?;

    // Split tunnel decision
    let decision = proxy.split_tunnel.decide_by_host(&target_host).await;

    let final_decision = match decision {
        RoutingDecision::Bypass => {
            debug!("Host {} matched bypass domain list", target_host);
            RoutingDecision::Bypass
        }
        RoutingDecision::Block => {
            debug!("Host {} matched ad/tracker list - blocking", target_host);
            RoutingDecision::Block
        }
        RoutingDecision::Tunnel => {
            match proxy.split_tunnel.resolve_host_to_ips(&target_host).await {
                Some(ips) => {
                    let ip_decision = proxy.split_tunnel.decide(&target_host, &ips).await;
                    if ip_decision == RoutingDecision::Bypass {
                        info!(
                            "Host {} resolved to bypass IPs, bypassing VPN",
                            target_host
                        );
                    }
                    ip_decision
                }
                None => {
                    error!("Failed to resolve {}, routing through VPN", target_host);
                    RoutingDecision::Tunnel
                }
            }
        }
    };

    match final_decision {
        RoutingDecision::Bypass => {
            info!("Bypassing VPN for {}:{}", target_host, target_port);
            handle_direct_connection(socket, &target_host, target_port).await?;
        }
        RoutingDecision::Tunnel => {
            if proxy.multiplex {
                handle_tunnel_multiplexed(socket, addr, target_addr, proxy).await?;
            } else {
                handle_tunnel_legacy(socket, addr, target_addr, proxy).await?;
            }
        }
        RoutingDecision::Block => {
            info!("Blocking ad/tracker: {}:{}", target_host, target_port);
            // Caller should handle sending an error response to the client before
            // calling route_connection, but if we get here the socket is just dropped.
        }
    }

    Ok(())
}

/// Handle direct connection (bypass VPN).
async fn handle_direct_connection(
    mut socket: TcpStream,
    target_host: &str,
    target_port: u16,
) -> Result<()> {
    let target_addr = format!("{}:{}", target_host, target_port);
    let mut target = tokio::net::TcpStream::connect(&target_addr)
        .await
        .with_context(|| format!("Failed to connect to {}", target_addr))?;

    info!("Direct connection established to {}", target_addr);

    let (mut client_read, mut client_write) = socket.split();
    let (mut target_read, mut target_write) = target.split();

    tokio::try_join!(
        tokio::io::copy(&mut client_read, &mut target_write),
        tokio::io::copy(&mut target_read, &mut client_write)
    )?;

    Ok(())
}

/// Handle tunnel connection — multiplexed mode (single shared WebSocket).
async fn handle_tunnel_multiplexed(
    socket: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    target_addr: &str,
    proxy: &ProxyHandle,
) -> Result<()> {
    let tunnel = {
        let mux_path = if proxy.mux_path.is_empty() {
            let base = proxy.server_path.trim_end_matches('/');
            if base.ends_with("/mux") {
                base.to_string()
            } else {
                format!("{}/mux", base)
            }
        } else {
            proxy.mux_path.clone()
        };
        debug!("MUX path derived: '{}'", mux_path);
        let mut guard = proxy.mux_tunnel.lock().await;

        if let Some(ref t) = *guard {
            if !t.is_alive() {
                warn!("Multiplexed tunnel receive loop is dead — reconnecting");
                *guard = None;
            }
        }

        if guard.is_none() {
            // Retry tunnel creation up to 3 times if it dies immediately
            // (e.g. server closes connection right after X3DH)
            const MAX_TUNNEL_RETRIES: u32 = 3;
            let mut last_err = None;
            for attempt in 1..=MAX_TUNNEL_RETRIES {
                let t = match Socks5Tunnel::connect(
                    &proxy.server_host,
                    proxy.server_port,
                    &mux_path,
                    proxy.tls_fingerprint,
                    proxy.sni_hostname.as_deref(),
                    &proxy.identity_key,
                    &proxy.server_bundle,
                    Some(&proxy.server_identity),
                )
                .await
                {
                    Ok(t) => t,
                    Err(e) => {
                        warn!("Tunnel creation attempt {}/{} failed: {}", attempt, MAX_TUNNEL_RETRIES, e);
                        last_err = Some(e);
                        if attempt < MAX_TUNNEL_RETRIES {
                            tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
                        }
                        continue;
                    }
                };

                // Give the tunnel a moment to detect early death
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                if !t.is_alive() {
                    warn!("Tunnel died within 200ms of creation (attempt {}/{}), retrying",
                          attempt, MAX_TUNNEL_RETRIES);
                    last_err = Some(anyhow::anyhow!("Tunnel died immediately after creation"));
                    if attempt < MAX_TUNNEL_RETRIES {
                        tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
                    }
                    continue;
                }

                info!(
                    "Multiplexed tunnel connected to {}:{}{} (attempt {})",
                    proxy.server_host, proxy.server_port, mux_path, attempt
                );
                *guard = Some(t);
                last_err = None;
                break;
            }
            if guard.is_none() {
                return Err(last_err.unwrap_or_else(|| anyhow::anyhow!(
                    "Failed to create multiplexed tunnel after {} attempts", MAX_TUNNEL_RETRIES
                ))).context(format!("Failed to create multiplexed tunnel (mux_path='{}')", mux_path));
            }
        }
        Arc::clone(guard.as_ref().unwrap())
    };

    socks5_tunnel::handle_multiplexed_connection(socket, addr, target_addr, &tunnel).await
}

/// Handle tunnel connection — legacy mode (one WebSocket per flow).
async fn handle_tunnel_legacy(
    socket: TcpStream,
    addr: SocketAddr,
    target_addr: &str,
    proxy: &ProxyHandle,
) -> Result<()> {
    let (mut relay, ws_reader, ws_writer) = StreamRelay::connect(
        &proxy.server_host,
        proxy.server_port,
        &proxy.server_path,
        proxy.tls_fingerprint,
        proxy.sni_hostname.as_deref(),
        &proxy.identity_key,
        &proxy.server_bundle,
        Some(&proxy.server_identity),
    )
    .await
    .context("Failed to connect StreamRelay")?;

    let target_bytes = encode_target_address(target_addr)?;
    relay
        .send_frame(&ws_writer, &target_bytes)
        .await
        .context("Failed to send target address")?;

    debug!("Sent target address to server: {}", target_addr);

    relay.relay(socket, ws_reader, ws_writer).await?;

    debug!("Legacy tunnel connection closed for {}", addr);
    Ok(())
}
