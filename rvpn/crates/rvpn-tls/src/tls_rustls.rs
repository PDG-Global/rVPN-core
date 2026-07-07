// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// rustls TLS backend.
//
// Used by iOS instead of BoringSSL: BoringSSL's C `SSL_read` leaks anonymous VM
// (~1,390 B per inbound TLS record) in the iOS NetworkExtension sandbox, which
// pushes the process toward the ~50 MB jetsam limit. rustls is pure Rust, so
// every allocation it makes is tracked by mimalloc (whose `commit_bytes` stays
// flat at ~10 MB across sustained traffic).
//
// Cost: no Chrome ClientHello fingerprint mimicry. macOS keeps the boring
// backend for stealth; iOS accepts this (same posture as Android).
//
// Certificate roots are bundled at compile time via `webpki-roots` (Mozilla CA
// set), mirroring the boring path's `ca-bundle.pem`. The iOS NE sandbox blocks
// `/etc/ssl/` and `trustd` XPC is unreliable from the extension, so a bundled
// root store is mandatory — `rustls-platform-verifier` would reintroduce the
// trustd dependency.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream as RustlsInner;
use tokio_rustls::TlsConnector;
use tracing::debug;

/// Enable TCP keepalive on a socket.
///
/// Detects dead connections (e.g. NAT evictions, middlebox drops) in ~90s
/// instead of relying on the OS default (~2h on Linux/macOS). Must be applied
/// to the raw TCP socket *before* the TLS handshake — keepalive is a TCP-layer
/// property and is unaffected by TLS layering.
fn enable_tcp_keepalive(tcp: TcpStream) -> Result<TcpStream> {
    let std_tcp = tcp
        .into_std()
        .context("Failed to convert tokio TcpStream to std")?;

    let socket = socket2::Socket::from(std_tcp);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10));
    socket
        .set_tcp_keepalive(&keepalive)
        .context("Failed to set TCP keepalive")?;

    let std_tcp = std::net::TcpStream::from(socket);
    std_tcp
        .set_nonblocking(true)
        .context("Failed to set non-blocking")?;

    TcpStream::from_std(std_tcp).context("Failed to convert std TcpStream back to tokio")
}

/// A rustls TLS connection.
///
/// Wraps `tokio_rustls::client::TlsStream<TcpStream>` and forwards
/// `AsyncRead`/`AsyncWrite`. This is the rustls analogue of
/// [`crate::ChromeTlsStream`] and is consumed by `MinimalWebSocket<S>` exactly
/// the same way (the bound is `S: AsyncRead + AsyncWrite + Unpin + 'static`).
pub struct RustlsTlsStream {
    inner: RustlsInner<TcpStream>,
}

impl RustlsTlsStream {
    pub fn new(stream: RustlsInner<TcpStream>) -> Self {
        Self { inner: stream }
    }
}

impl AsyncRead for RustlsTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RustlsTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Connect to a server via rustls.
///
/// 1. TCP connect (with keepalive: 60s time, 10s interval — parity with the
///    boring backend).
/// 2. TLS 1.3 handshake using Mozilla CA roots bundled at compile time
///    (`webpki-roots`).
/// 3. ALPN `http/1.1` only — forces nginx to negotiate HTTP/1.1 so the manual
///    WebSocket upgrade parses (advertising `h2` would let nginx pick HTTP/2
///    and break the upgrade).
///
/// # Arguments
/// * `host` - Hostname to connect to (TCP destination).
/// * `port` - TCP port.
/// * `sni_hostname` - Optional SNI override (defaults to `host`).
pub async fn connect_rustls(
    host: &str,
    port: u16,
    sni_hostname: Option<&str>,
) -> Result<RustlsTlsStream> {
    let sni = sni_hostname.unwrap_or(host);
    let addr = format!("{}:{}", host, port);

    // TCP connect + keepalive (parity with tls_boring::connect_chrome_like).
    let tcp = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("Failed to connect to {}", addr))?;
    let tcp = enable_tcp_keepalive(tcp).context("Failed to enable TCP keepalive")?;

    // Bundle Mozilla CA roots. iOS NE sandbox blocks /etc/ssl/ and trustd is
    // unreliable, so we cannot use rustls-platform-verifier here.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Workspace pins rustls with features=["tls12","ring"], so the ring CryptoProvider
    // is auto-installed as the default — ClientConfig::builder() works without an
    // explicit provider call (same as android_tun.rs).
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // ALPN: http/1.1 only (rustls 0.22 exposes this as a public field, not a
    // builder method). Matches the boring backend's set_alpn_protos(b"\x08http/1.1").
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let connector = TlsConnector::from(Arc::new(config));

    let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned())
        .map_err(|e| anyhow::anyhow!("Invalid SNI hostname {:?}: {}", sni, e))?;

    debug!(
        "rustls config: TLS 1.2/1.3 (ring), ALPN http/1.1, bundled Mozilla roots, SNI: {}",
        sni
    );

    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .context("rustls TLS handshake failed")?;

    debug!("rustls TLS handshake completed successfully");

    Ok(RustlsTlsStream::new(tls_stream))
}
