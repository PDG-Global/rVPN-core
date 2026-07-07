// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// R-VPN Client Implementation - Brook-style Architecture
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! SOCKS5 Proxy Server
//!
//! Supports two modes:
//! - **Multiplexed** (default): All SOCKS5 flows share a single WebSocket with one
//!   DoubleRatchet. Lower overhead, no per-connection handshakes, bypasses rate limits.
//! - **Legacy**: Each SOCKS5 flow opens its own WebSocket + X3DH handshake (StreamRelay).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{info, debug, error, warn};

use rvpn_core::crypto::{IdentityKey, X3DHPublicBundle};

use crate::config::{ClientConfig, Socks5Config, ServerIdentityConfig};
use crate::proxy_common::{self, ProxyHandle};
use crate::split_tunnel::SplitTunnel;
use rvpn_tls::TlsFingerprint;
use crate::socks5_tunnel::Socks5Tunnel;
use crate::dns_cache::DnsResolver;

/// SOCKS5 Proxy server
pub struct Socks5Proxy {
    listen_addr: SocketAddr,
    server_host: String,
    server_port: u16,
    server_path: String,
    tls_fingerprint: TlsFingerprint,
    sni_hostname: Option<String>,
    identity_key: Arc<IdentityKey>,
    server_bundle: Arc<X3DHPublicBundle>,
    server_identity: ServerIdentityConfig,
    split_tunnel: Arc<SplitTunnel>,
    socks5_config: Socks5Config,
    mux_tunnel: Arc<Mutex<Option<Arc<Socks5Tunnel>>>>,
    dns_resolver: Arc<DnsResolver>,
}

impl Socks5Proxy {
    pub async fn new(listen_addr: SocketAddr, config: &ClientConfig) -> Result<Self> {
        let (host, port, path) = parse_server_url(&config.server_address);

        let key_path = config.identity_key_file.clone();
        let identity_key = tokio::task::spawn_blocking(move || IdentityKey::load(&key_path))
            .await
            .context("Identity key load task failed")?
            .context("Failed to load identity key")?;

        let bundle_path = config.prekey_bundle.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Prekey bundle file is required for X3DH authentication"))?;
        let bundle_json = tokio::fs::read_to_string(bundle_path).await
            .with_context(|| format!("Failed to read prekey bundle: {:?}", bundle_path))?;
        let server_bundle: X3DHPublicBundle = serde_json::from_str(&bundle_json)
            .context("Failed to parse prekey bundle")?;

        let nameserver_list = if config.network.dns_servers.is_empty() {
            &config.dns_proxy.nameservers
        } else {
            &config.network.dns_servers
        };
        let nameservers: Vec<SocketAddr> = nameserver_list
            .iter()
            .filter_map(|s| {
                let addr = if s.contains(':') {
                    s.parse::<SocketAddr>().ok()
                } else {
                    format!("{}:53", s).parse::<SocketAddr>().ok()
                };
                if addr.is_none() {
                    warn!("Invalid DNS server address: {}, skipping", s);
                }
                addr
            })
            .collect();

        let dns_resolver = Arc::new(DnsResolver::new(
            config.network.dns_cache_enabled,
            config.network.dns_cache_ttl,
            config.network.dns_cache_size,
            config.network.ipv6_enabled,
            config.network.prefer_ipv4,
            nameservers,
        ));
        dns_resolver.start_cleanup_task();

        let split_tunnel = match SplitTunnel::new(config.split_tunnel.clone(), Arc::clone(&dns_resolver)).await {
            Ok(st) => Arc::new(st),
            Err(e) => {
                warn!("Failed to initialize split tunnel: {}. Using disabled mode.", e);
                Arc::new(SplitTunnel::disabled())
            }
        };

        if config.split_tunnel.enabled {
            let stats = split_tunnel.get_stats().await;
            info!("Split tunnel enabled: {} bypass networks, {} bypass domains",
                  stats.bypass_networks_count, stats.bypass_domains_count);
        } else {
            info!("Split tunnel disabled - all traffic will go through VPN");
        }

        Ok(Self {
            listen_addr,
            server_host: host,
            server_port: port,
            server_path: path,
            tls_fingerprint: config.tls_fingerprint,
            sni_hostname: config.sni_hostname.clone(),
            identity_key: Arc::new(identity_key),
            server_bundle: Arc::new(server_bundle),
            server_identity: config.server_identity.clone(),
            split_tunnel,
            socks5_config: config.socks5.clone(),
            mux_tunnel: Arc::new(Mutex::new(None)),
            dns_resolver,
        })
    }

    // Accessors for sharing pre-loaded resources with other components (e.g. DnsProxy, HttpProxy)
    pub fn server_host(&self) -> &str { &self.server_host }
    pub fn server_port(&self) -> u16 { self.server_port }
    pub fn server_path(&self) -> &str { &self.server_path }
    pub fn tls_fingerprint(&self) -> TlsFingerprint { self.tls_fingerprint }
    #[allow(dead_code)]
    pub fn sni_hostname(&self) -> Option<&str> { self.sni_hostname.as_deref() }
    pub fn identity_key(&self) -> Arc<IdentityKey> { Arc::clone(&self.identity_key) }
    pub fn server_bundle(&self) -> Arc<X3DHPublicBundle> { Arc::clone(&self.server_bundle) }
    pub fn split_tunnel(&self) -> Arc<SplitTunnel> { Arc::clone(&self.split_tunnel) }
    pub fn dns_resolver(&self) -> Arc<DnsResolver> { Arc::clone(&self.dns_resolver) }
    pub fn mux_tunnel(&self) -> Arc<Mutex<Option<Arc<Socks5Tunnel>>>> { Arc::clone(&self.mux_tunnel) }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr).await
            .with_context(|| format!("Failed to bind SOCKS5 proxy to {}", self.listen_addr))?;

        info!("SOCKS5 proxy listening on {}", self.listen_addr);

        loop {
            let (socket, addr) = listener.accept().await?;
            let proxy = ProxyHandle {
                server_host: self.server_host.clone(),
                server_port: self.server_port,
                server_path: self.server_path.clone(),
                tls_fingerprint: self.tls_fingerprint,
                sni_hostname: self.sni_hostname.clone(),
                identity_key: Arc::clone(&self.identity_key),
                server_bundle: Arc::clone(&self.server_bundle),
                server_identity: self.server_identity.clone(),
                split_tunnel: Arc::clone(&self.split_tunnel),
                multiplex: self.socks5_config.multiplex,
                mux_path: self.socks5_config.mux_path.clone(),
                mux_tunnel: self.mux_tunnel.clone(),
            };

            tokio::spawn(async move {
                if let Err(e) = handle_connection(socket, addr, proxy).await {
                    error!("SOCKS5 connection error from {}: {}", addr, e);
                }
            });
        }
    }
}

/// Handle single SOCKS5 connection: handshake, send success, then route.
async fn handle_connection(
    mut socket: TcpStream,
    addr: SocketAddr,
    proxy: ProxyHandle,
) -> Result<()> {
    debug!("New SOCKS5 connection from {}", addr);

    // 1. SOCKS5 handshake (protocol-specific)
    let target_addr = socks5_handshake(&mut socket).await?;
    debug!("SOCKS5 target: {}", target_addr);

    // 2. Send SOCKS5 success response
    send_socks5_success(&mut socket).await?;

    // 3. Delegate to shared routing logic
    proxy_common::route_connection(socket, addr, &target_addr, &proxy).await?;

    debug!("SOCKS5 connection closed: {}", addr);
    Ok(())
}

/// SOCKS5 handshake - authenticate client (if configured) and parse target address
async fn socks5_handshake(socket: &mut TcpStream) -> Result<String> {
    // Read greeting
    let mut buf = [0u8; 2];
    socket.read_exact(&mut buf).await?;
    let version = buf[0];
    let nmethods = buf[1] as usize;

    if version != 0x05 {
        return Err(anyhow::anyhow!("Invalid SOCKS version: expected 5, got {}", version));
    }

    // Read methods
    let mut methods = vec![0u8; nmethods];
    socket.read_exact(&mut methods).await?;

    // No auth required
    socket.write_all(&[0x05, 0x00]).await?;

    // Read request
    let mut header = [0u8; 4];
    socket.read_exact(&mut header).await?;
    let cmd = header[1];
    let atyp = header[3];

    if cmd != 0x01 {
        socket.write_all(&[0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
        return Err(anyhow::anyhow!("Only CONNECT command supported, got {}", cmd));
    }

    let target = match atyp {
        0x01 => {
            let mut addr = [0u8; 4];
            socket.read_exact(&mut addr).await?;
            let port = read_port(socket).await?;
            format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], port)
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            socket.read_exact(&mut domain).await?;
            let port = read_port(socket).await?;
            format!("{}:{}", String::from_utf8_lossy(&domain), port)
        }
        0x04 => {
            let mut addr = [0u8; 16];
            socket.read_exact(&mut addr).await?;
            let _port = read_port(socket).await?;
            socket.write_all(&[0x05, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
            return Err(anyhow::anyhow!("IPv6 address type not supported (server has no IPv6 upstream)"));
        }
        _ => {
            socket.write_all(&[0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
            return Err(anyhow::anyhow!("Invalid address type: {}", atyp));
        }
    };

    Ok(target)
}

async fn read_port(socket: &mut TcpStream) -> Result<u16> {
    let mut port = [0u8; 2];
    socket.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

async fn send_socks5_success(socket: &mut TcpStream) -> Result<()> {
    socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
    Ok(())
}

/// Parse server URL into (host, port, path) components
fn parse_server_url(url: &str) -> (String, u16, String) {
    let url = url.strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url);

    let (host_port, path) = url.split_once('/')
        .map(|(hp, p)| (hp, format!("/{}", p)))
        .unwrap_or((url, "/".to_string()));

    let (host, port) = host_port.split_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(443)))
        .unwrap_or_else(|| (host_port.to_string(), 443));

    (host, port, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_server_url() {
        let (host, port, path) = parse_server_url("wss://example.com/api/v1/ws");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api/v1/ws");

        let (host, port, path) = parse_server_url("wss://example.com:8443/api/v1/ws");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8443);
        assert_eq!(path, "/api/v1/ws");

        let (host, port, path) = parse_server_url("wss://example.com");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/");

        let (host, port, path) = parse_server_url("ws://example.com:8080/ws");
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
        assert_eq!(path, "/ws");
    }
}
