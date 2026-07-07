// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Platform-native TLS backend via `native-tls`.
//
// On iOS/macOS this uses Security.framework (SecureTransport) — Apple's own TLS
// implementation.  This completely eliminates BoringSSL and its C `SSL_read`
// anonymous-VM leak that jetsams the iOS NetworkExtension.
//
// Certificate verification goes through trustd (the system trust store).  The
// boring backend deliberately avoided this by bundling Mozilla CA roots, citing
// "trustd XPC service is unreliable from within the extension process."  That
// concern may be outdated — Apple's own NE sample code uses Security.framework.
// If trustd is flaky in practice, we'll see occasional TLS handshake failures
// (recoverable via reconnect) rather than guaranteed jetsam kills.
//
// TLS fingerprint: a native iOS/macOS ClientHello — the most natural fingerprint
// to see from an iOS device.  Better stealth than rustls (generic) or boring
// (Chrome mimicry).

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, Result};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_native_tls::TlsStream as NativeTlsInner;
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

/// A platform-native TLS connection.
///
/// Wraps `tokio_native_tls::TlsStream<TcpStream>` and forwards
/// `AsyncRead`/`AsyncWrite`.  This is the native-tls analogue of
/// [`crate::ChromeTlsStream`] and [`crate::RustlsTlsStream`].
pub struct NativeTlsStream {
    inner: NativeTlsInner<TcpStream>,
}

impl NativeTlsStream {
    pub fn new(stream: NativeTlsInner<TcpStream>) -> Self {
        Self { inner: stream }
    }
}

impl AsyncRead for NativeTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for NativeTlsStream {
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

/// Connect to a server via platform-native TLS.
///
/// On iOS/macOS this uses Security.framework (SecureTransport).  On Linux it
/// uses OpenSSL via the `openssl` crate.  On Windows it uses SChannel.
///
/// 1. TCP connect (with keepalive: 60s time, 10s interval — parity with the
///    boring and rustls backends).
/// 2. TLS handshake using the platform's native TLS stack.
/// 3. ALPN `http/1.1` only — forces nginx to negotiate HTTP/1.1 so the manual
///    WebSocket upgrade parses.
///
/// # Arguments
/// * `host` - Hostname to connect to (TCP destination and SNI).
/// * `port` - TCP port.
/// * `sni_hostname` - Optional SNI override (defaults to `host`).
pub async fn connect_native(
    host: &str,
    port: u16,
    sni_hostname: Option<&str>,
) -> Result<NativeTlsStream> {
    let sni = sni_hostname.unwrap_or(host);
    let addr = format!("{}:{}", host, port);

    // TCP connect + keepalive (parity with tls_boring / tls_rustls).
    let tcp = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("Failed to connect to {}", addr))?;
    let tcp = enable_tcp_keepalive(tcp).context("Failed to enable TCP keepalive")?;

    // Build native TLS connector with ALPN http/1.1.
    // NOTE: Do NOT set min_protocol_version(Tlsv13) — Security.framework on
    // iOS may not negotiate TLS 1.3 correctly with all servers. The test server
    // (003.hk) works with TLS 1.2. The production server's Caddy enforces
    // TLS 1.3 at the proxy level; if native-tls can't negotiate it, Caddy
    // handles the fallback. Set min_protocol_version only if Caddy rejects
    // TLS 1.2 from native-tls.
    let mut builder = native_tls::TlsConnector::builder();
    builder.request_alpns(&["http/1.1"]);

    // On iOS: Security.framework uses the system trust store (trustd) for cert
    // verification.  No bundled CA certs needed — Apple's root CAs are built
    // into the OS.  This is simpler than the boring path's ca-bundle.pem
    // approach, and avoids the trustd "unreliability" concern by using
    // Security.framework's own verification path (same as Safari, Mail, etc.).

    let connector = builder
        .build()
        .context("Failed to build native TLS connector")?;

    let connector = tokio_native_tls::TlsConnector::from(connector);

    debug!(
        "native-tls: platform TLS (Security.framework on iOS), ALPN http/1.1, SNI: {}",
        sni
    );

    let tls_stream = connector
        .connect(sni, tcp)
        .await
        .context("native-tls handshake failed")?;

    debug!("native-tls handshake completed successfully");

    Ok(NativeTlsStream::new(tls_stream))
}
