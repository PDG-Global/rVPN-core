// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP/HTTPS Proxy Server
//!
//! Handles two request types:
//! - **HTTP CONNECT**: `CONNECT host:port HTTP/1.1` — tunnels HTTPS traffic
//! - **Plain HTTP**: `GET http://host/path HTTP/1.1` — forwards HTTP requests
//!
//! Compatible with `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` environment variables.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use rvpn_core::crypto::{IdentityKey, X3DHPublicBundle};

use crate::config::{ClientConfig, HttpProxyConfig, ServerIdentityConfig};
use crate::proxy_common::{self, ProxyHandle};
use crate::split_tunnel::{RoutingDecision, SplitTunnel};
use rvpn_tls::TlsFingerprint;
use crate::socks5_tunnel::Socks5Tunnel;
use crate::dns_cache::DnsResolver;

/// HTTP/HTTPS Proxy server
pub struct HttpProxy {
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
    http_config: HttpProxyConfig,
    mux_tunnel: Arc<Mutex<Option<Arc<Socks5Tunnel>>>>,
}

impl HttpProxy {
    pub async fn new(
        listen_addr: SocketAddr,
        config: &ClientConfig,
        identity_key: Arc<IdentityKey>,
        server_bundle: Arc<X3DHPublicBundle>,
        split_tunnel: Arc<SplitTunnel>,
        dns_resolver: Arc<DnsResolver>,
        mux_tunnel: Arc<Mutex<Option<Arc<Socks5Tunnel>>>>,
    ) -> Result<Self> {
        let (host, port, path) = parse_server_url(&config.server_address);

        dns_resolver.start_cleanup_task();

        Ok(Self {
            listen_addr,
            server_host: host,
            server_port: port,
            server_path: path,
            tls_fingerprint: config.tls_fingerprint,
            sni_hostname: config.sni_hostname.clone(),
            identity_key,
            server_bundle,
            server_identity: config.server_identity.clone(),
            split_tunnel,
            http_config: config.http_proxy.clone(),
            mux_tunnel,
        })
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .with_context(|| format!("Failed to bind HTTP proxy to {}", self.listen_addr))?;

        info!("HTTP proxy listening on {}", self.listen_addr);

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
                multiplex: self.http_config.multiplex,
                mux_path: self.http_config.mux_path.clone(),
                mux_tunnel: self.mux_tunnel.clone(),
            };

            let auth_config = if self.http_config.auth_enabled {
                Some(AuthConfig {
                    username: self
                        .http_config
                        .auth_username
                        .clone()
                        .unwrap_or_default(),
                    password: self
                        .http_config
                        .auth_password
                        .clone()
                        .unwrap_or_default(),
                })
            } else {
                None
            };

            tokio::spawn(async move {
                if let Err(e) = handle_connection(socket, addr, proxy, auth_config).await {
                    debug!("HTTP connection error from {}: {}", addr, e);
                }
            });
        }
    }
}

struct AuthConfig {
    username: String,
    password: String,
}

/// Handle a single HTTP proxy connection.
/// Supports connection keep-alive for multiple requests on the same TCP connection.
async fn handle_connection(
    mut socket: TcpStream,
    addr: SocketAddr,
    proxy: ProxyHandle,
    auth_config: Option<AuthConfig>,
) -> Result<()> {
    debug!("New HTTP proxy connection from {}", addr);

    loop {
        let mut reader = BufReader::new(socket);
        let mut request_line = String::new();
        match reader.read_line(&mut request_line).await {
            Ok(0) => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(e.into()),
        }

        let request_line = request_line.trim_end_matches(['\r', '\n']);
        if request_line.is_empty() {
            return Ok(());
        }

        debug!("HTTP request line: {}", request_line);

        let parts: Vec<&str> = request_line.splitn(3, ' ').collect();
        if parts.len() < 3 {
            return Err(anyhow::anyhow!("Invalid HTTP request line: {}", request_line));
        }

        let method = parts[0];
        let uri = parts[1];
        let _http_version = parts[2];

        // Read headers
        let mut headers = Vec::new();
        let mut content_length: usize = 0;
        let mut proxy_auth_value = String::new();
        let mut host_from_header = String::new();
        let mut keep_alive = true;

        loop {
            let mut header_buf = String::new();
            match reader.read_line(&mut header_buf).await {
                Ok(0) => return Ok(()),
                Ok(_) => {}
                Err(e) => return Err(e.into()),
            }

            let trimmed = header_buf.trim_end_matches(['\r', '\n']);
            if trimmed.is_empty() {
                break;
            }

            let lower = trimmed.to_lowercase();
            if lower.starts_with("content-length:") {
                if let Some(val) = trimmed.split_once(':').map(|x| x.1) {
                    content_length = val.trim().parse().unwrap_or(0);
                }
            }
            if lower.starts_with("proxy-authorization:") {
                if let Some(val) = trimmed.split_once(':').map(|x| x.1) {
                    proxy_auth_value = val.trim().to_string();
                }
            }
            if lower.starts_with("host:") {
                if let Some(val) = trimmed.split_once(':').map(|x| x.1) {
                    host_from_header = val.trim().to_string();
                }
            }
            if lower.starts_with("proxy-connection:") {
                keep_alive = lower.contains("keep-alive");
            }

            headers.push(trimmed.to_string());
        }

        // Check authentication
        if let Some(ref auth) = auth_config {
            if !check_basic_auth(&proxy_auth_value, &auth.username, &auth.password) {
                let response = "HTTP/1.1 407 Proxy Authentication Required\r\n\
                               Proxy-Authenticate: Basic realm=\"rvpn\"\r\n\
                               Connection: close\r\n\r\n";
                let mut socket = reader.into_inner();
                let _ = socket.write_all(response.as_bytes()).await;
                return Ok(());
            }
        }

        if method.eq_ignore_ascii_case("CONNECT") {
            return handle_connect(reader.into_inner(), addr, uri, &proxy).await;
        } else {
            let should_close = handle_http_forward(
                &mut reader,
                method,
                uri,
                &host_from_header,
                &headers,
                content_length,
                &proxy,
            )
            .await?;

            socket = reader.into_inner();

            if should_close || !keep_alive {
                return Ok(());
            }
        }
    }
}

/// Handle HTTP CONNECT request (HTTPS tunneling).
async fn handle_connect(
    mut socket: TcpStream,
    addr: SocketAddr,
    target: &str,
    proxy: &ProxyHandle,
) -> Result<()> {
    let target_addr = if target.contains(':') {
        target.to_string()
    } else {
        format!("{}:443", target)
    };

    debug!("HTTP CONNECT to {}", target_addr);

    let response = "HTTP/1.1 200 Connection Established\r\n\r\n";
    socket.write_all(response.as_bytes()).await?;

    proxy_common::route_connection(socket, addr, &target_addr, proxy).await
}

/// Handle plain HTTP forwarding (GET, POST, etc. with absolute URL).
/// Returns Ok(true) if the connection should be closed.
async fn handle_http_forward(
    reader: &mut BufReader<TcpStream>,
    method: &str,
    uri: &str,
    host_from_header: &str,
    headers: &[String],
    content_length: usize,
    proxy: &ProxyHandle,
) -> Result<bool> {
    // Extract host, port, path from URI or Host header
    let (target_host, target_port, path) = if let Some(without_scheme) = uri.strip_prefix("http://") {
        let (authority, path) = without_scheme
            .split_once('/')
            .map(|(a, p)| (a, format!("/{}", p)))
            .unwrap_or((without_scheme, "/".to_string()));
        let (host, port) = authority
            .split_once(':')
            .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(80u16)))
            .unwrap_or_else(|| (authority.to_string(), 80u16));
        (host, port, path)
    } else {
        let host = if !host_from_header.is_empty() {
            host_from_header.to_string()
        } else {
            return Err(anyhow::anyhow!("No host in request and no Host header"));
        };
        let (h, p) = host
            .split_once(':')
            .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(80u16)))
            .unwrap_or_else(|| (host, 80u16));
        (h, p, uri.to_string())
    };

    let target_addr = format!("{}:{}", target_host, target_port);
    debug!("HTTP {} {} → {}", method, uri, target_addr);

    // Read request body if present
    let body = if content_length > 0 {
        let mut body = vec![0u8; content_length];
        reader.read_exact(&mut body).await?;
        Some(body)
    } else {
        None
    };

    // Reconstruct the request with relative path and filtered headers
    let request = build_request(method, &path, headers);

    // Make split tunnel decision
    let decision = proxy.split_tunnel.decide_by_host(&target_host).await;
    let final_decision = match decision {
        RoutingDecision::Bypass | RoutingDecision::Block => decision,
        RoutingDecision::Tunnel => {
            match proxy.split_tunnel.resolve_host_to_ips(&target_host).await {
                Some(ips) => proxy.split_tunnel.decide(&target_host, &ips).await,
                None => RoutingDecision::Tunnel,
            }
        }
    };

    match final_decision {
        RoutingDecision::Block => {
            info!("Blocking ad/tracker HTTP: {}:{}", target_host, target_port);
            let socket = reader.get_mut();
            let _ = socket
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(true);
        }
        RoutingDecision::Bypass => {
            info!("Bypassing VPN for HTTP {}:{}", target_host, target_port);
            let mut target = TcpStream::connect(&target_addr)
                .await
                .with_context(|| format!("Failed to connect to {}", target_addr))?;

            target.write_all(request.as_bytes()).await?;
            if let Some(ref b) = body {
                target.write_all(b).await?;
            }

            let socket = reader.get_mut();
            relay_http_response(&mut target, socket).await?;
        }
        RoutingDecision::Tunnel => {
            forward_through_mux_tunnel(
                reader,
                &target_host,
                target_port,
                &request,
                body.as_deref(),
                proxy,
            )
            .await?;
        }
    }

    Ok(false)
}

/// Forward an HTTP request through the multiplexed VPN tunnel.
async fn forward_through_mux_tunnel(
    reader: &mut BufReader<TcpStream>,
    host: &str,
    port: u16,
    request: &str,
    body: Option<&[u8]>,
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

        let mut guard = proxy.mux_tunnel.lock().await;

        if let Some(ref t) = *guard {
            if !t.is_alive() {
                warn!("Multiplexed tunnel dead — reconnecting");
                *guard = None;
            }
        }

        if guard.is_none() {
            let t = Socks5Tunnel::connect(
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
            .context("Failed to create multiplexed tunnel")?;
            *guard = Some(t);
        }
        Arc::clone(guard.as_ref().unwrap())
    };

    let mut flow = tunnel
        .open_flow(host, port)
        .await
        .context("Failed to open mux flow")?;

    let send_tx = flow.take_send().unwrap();
    let mut recv_rx = flow.take_recv().unwrap();

    // Send the HTTP request through the mux flow
    send_tx
        .send(request.as_bytes().to_vec())
        .await
        .map_err(|_| anyhow::anyhow!("Mux flow send channel closed"))?;

    // Send body if present
    if let Some(b) = body {
        send_tx
            .send(b.to_vec())
            .await
            .map_err(|_| anyhow::anyhow!("Mux flow send channel closed"))?;
    }

    // Read response from mux flow and write back to client
    let socket = reader.get_mut();
    while let Some(data) = recv_rx.recv().await {
        socket.write_all(&data).await?;
    }

    Ok(())
}

/// Relay an HTTP response from target to client, handling Content-Length and chunked encoding.
/// Unlike `tokio::io::copy`, this reads exactly one response and returns, so keep-alive works.
async fn relay_http_response(
    target: &mut TcpStream,
    client: &mut TcpStream,
) -> Result<()> {
    use tokio::io::AsyncBufReadExt;

    let mut target_buf = BufReader::new(&mut *target);
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut connection_close = false;

    // Read status line
    let mut status_line = String::new();
    target_buf.read_line(&mut status_line).await?;
    client.write_all(status_line.as_bytes()).await?;

    // Read response headers
    loop {
        let mut header = String::new();
        target_buf.read_line(&mut header).await?;
        client.write_all(header.as_bytes()).await?;

        let trimmed = header.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }

        let lower = trimmed.to_lowercase();
        if lower.starts_with("content-length:") {
            if let Some(val) = trimmed.split_once(':').map(|x| x.1) {
                content_length = val.trim().parse().ok();
            }
        }
        if lower.starts_with("transfer-encoding:") && lower.contains("chunked") {
            chunked = true;
        }
        if lower.starts_with("connection:") && lower.contains("close") {
            connection_close = true;
        }
    }

    // Relay body
    if chunked {
        relay_chunked_response(&mut target_buf, client).await?;
    } else if let Some(len) = content_length {
        let mut remaining = len;
        while remaining > 0 {
            let buf = target_buf.fill_buf().await?;
            if buf.is_empty() {
                break;
            }
            let n = buf.len().min(remaining);
            client.write_all(&buf[..n]).await?;
            target_buf.consume(n);
            remaining -= n;
        }
    } else if connection_close || status_line.starts_with("HTTP/1.0") {
        // No length indicator — copy until EOF
        tokio::io::copy(&mut target_buf, client).await?;
    }
    // else: keep-alive with no content-length and not chunked — nothing to read

    Ok(())
}

/// Relay a chunked transfer-encoded response body.
async fn relay_chunked_response(
    target: &mut BufReader<&mut TcpStream>,
    client: &mut TcpStream,
) -> Result<()> {
    use tokio::io::AsyncBufReadExt;

    loop {
        // Read chunk size line
        let mut size_line = String::new();
        target.read_line(&mut size_line).await?;
        client.write_all(size_line.as_bytes()).await?;

        let size_str = size_line.trim().split(';').next().unwrap_or("0");
        let chunk_size = usize::from_str_radix(size_str, 16).unwrap_or(0);

        if chunk_size == 0 {
            // Read trailing headers and final CRLF
            loop {
                let mut trailer = String::new();
                target.read_line(&mut trailer).await?;
                client.write_all(trailer.as_bytes()).await?;
                if trailer.trim().is_empty() {
                    break;
                }
            }
            break;
        }

        // Read chunk data + trailing CRLF
        let mut remaining = chunk_size;
        while remaining > 0 {
            let buf = target.fill_buf().await?;
            if buf.is_empty() {
                return Err(anyhow::anyhow!("Unexpected EOF in chunked body"));
            }
            let n = buf.len().min(remaining);
            client.write_all(&buf[..n]).await?;
            target.consume(n);
            remaining -= n;
        }

        // Consume the \r\n after chunk data
        let mut crlf = String::new();
        target.read_line(&mut crlf).await?;
        client.write_all(crlf.as_bytes()).await?;
    }

    Ok(())
}

/// Build an HTTP request string with relative path and filtered headers.
fn build_request(method: &str, path: &str, headers: &[String]) -> String {
    let mut request = format!("{} {} HTTP/1.1\r\n", method, path);

    for header in headers {
        let lower = header.to_lowercase();
        if lower.starts_with("proxy-connection:") || lower.starts_with("proxy-authorization:") {
            continue;
        }
        request.push_str(header);
        request.push_str("\r\n");
    }

    if !headers
        .iter()
        .any(|h| h.to_lowercase().starts_with("connection:"))
    {
        request.push_str("Connection: keep-alive\r\n");
    }

    request.push_str("\r\n");
    request
}

/// Check Basic auth credentials using constant-time comparison.
fn check_basic_auth(header_value: &str, expected_user: &str, expected_pass: &str) -> bool {
    if !header_value.starts_with("Basic ") {
        return false;
    }

    let encoded = &header_value[6..];
    let decoded = match BASE64.decode(encoded) {
        Ok(d) => d,
        Err(_) => return false,
    };

    let decoded_str = match std::str::from_utf8(&decoded) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let (user, pass) = match decoded_str.split_once(':') {
        Some((u, p)) => (u, p),
        None => return false,
    };

    use subtle::ConstantTimeEq;
    let user_ok: bool = ConstantTimeEq::ct_eq(user.as_bytes(), expected_user.as_bytes()).into();
    let pass_ok: bool = ConstantTimeEq::ct_eq(pass.as_bytes(), expected_pass.as_bytes()).into();

    user_ok && pass_ok
}

/// Parse server URL into (host, port, path) components
fn parse_server_url(url: &str) -> (String, u16, String) {
    let url = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url);

    let (host_port, path) = url
        .split_once('/')
        .map(|(hp, p)| (hp, format!("/{}", p)))
        .unwrap_or((url, "/".to_string()));

    let (host, port) = host_port
        .split_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(443)))
        .unwrap_or_else(|| (host_port.to_string(), 443));

    (host, port, path)
}
