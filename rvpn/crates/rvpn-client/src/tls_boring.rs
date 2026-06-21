// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// TLS fingerprinting implementation mimicking Chrome
//
// Mimics Chrome's TLS fingerprint:
// - Sets ALPN to http/1.1 (tungstenite requires HTTP/1.1 for WebSocket upgrades)
// - BoringSSL's default extension ordering closely mirrors Chrome
// - Provides a raw TLS stream for manual WebSocket upgrade


use std::pin::Pin;
use std::task::{Context, Poll};

use anyhow::{Context as _, Result};
use boring::ssl::{SslConnector, SslMethod, SslVersion};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_boring::SslStream;
use tracing::debug;
use std::time::Duration;

/// Enable TCP keepalive on a socket.
///
/// Detects dead connections (e.g. NAT evictions, middlebox drops) in ~90s
/// instead of relying on the OS default (~2h on Linux/macOS).
fn enable_tcp_keepalive(tcp: TcpStream) -> Result<TcpStream> {
    let std_tcp = tcp.into_std()
        .context("Failed to convert tokio TcpStream to std")?;

    let socket = socket2::Socket::from(std_tcp);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(60))
        .with_interval(Duration::from_secs(10));
    socket.set_tcp_keepalive(&keepalive)
        .context("Failed to set TCP keepalive")?;

    let std_tcp = std::net::TcpStream::from(socket);
    std_tcp.set_nonblocking(true)
        .context("Failed to set non-blocking")?;

    TcpStream::from_std(std_tcp)
        .context("Failed to convert std TcpStream back to tokio")
}

/// TLS fingerprint types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum TlsFingerprint {
    /// Chrome 120+ fingerprint (most common)
    #[default]
    Chrome,
    /// Firefox fingerprint
    Firefox,
    /// Safari fingerprint
    Safari,
    /// No fingerprinting
    None,
}

/// A TLS connection that mimics Chrome's fingerprint
///
/// This is returned after the TLS handshake is complete.
/// The caller can then use this to send the WebSocket HTTP upgrade request.
pub struct ChromeTlsStream {
    inner: SslStream<TcpStream>,
}

impl ChromeTlsStream {
    pub fn new(stream: SslStream<TcpStream>) -> Self {
        Self { inner: stream }
    }
}

impl AsyncRead for ChromeTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChromeTlsStream {
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

/// On iOS the Network Extension sandbox blocks all filesystem access to /etc/ssl/,
/// and the trustd XPC service is unreliable from within the extension process.
/// We bundle Mozilla's CA root certificates as a PEM file and load them directly
/// into BoringSSL's certificate store, eliminating any dependency on the system
/// trust store or trustd.
#[cfg(target_os = "ios")]
fn set_ios_cert_verify(builder: &mut boring::ssl::SslConnectorBuilder, _hostname: &str) {
    use boring::x509::store::X509StoreBuilder;
    use boring::x509::X509;

    // Bundle includes 128 Mozilla CA root certificates
    static CA_BUNDLE: &str = include_str!("ca-bundle.pem");

    let certs = X509::stack_from_pem(CA_BUNDLE.as_bytes())
        .expect("Failed to parse bundled CA certificates");

    let mut store = X509StoreBuilder::new().expect("Failed to create X509 store");
    for cert in certs {
        store.add_cert(cert).ok();
    }

    builder.set_verify_cert_store(store.build()).ok();
    builder.set_verify(boring::ssl::SslVerifyMode::PEER);
}

/// Build a TLS connector that mimics Chrome
///
/// Key aspects of Chrome's TLS fingerprint:
/// - TLS 1.3 only (no TLS 1.2)
/// - ALPN with http/1.1 (required for tungstenite WebSocket; h2 causes HttparseError)
/// - BoringSSL's default TLS 1.3 ciphers already match Chrome's preference order
#[allow(unused_variables)]
fn build_chrome_connector(host: &str, sni_hostname: Option<&str>) -> Result<SslConnector> {
    let method = SslMethod::tls();
    let mut builder = SslConnector::builder(method)
        .context("Failed to create SSL connector")?;

    // TLS 1.3 only (Chrome default)
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // ALPN: http/1.1 only.
    // Ideally we'd advertise h2 + http/1.1 to match Chrome, but tungstenite only
    // supports HTTP/1.1 WebSocket upgrades — if the server (nginx) negotiates h2,
    // the response is HTTP/2 frames that tungstenite can't parse (HttparseError(Version)).
    // http/1.1-only ALPN was previously flagged as matching Brook's fingerprint, but
    // the server-side reverse proxy configuration ultimately controls ALPN negotiation,
    // and the other improvements (Chrome WS upgrade headers, jittered keepalives) provide
    // significant anti-fingerprint protection on their own.
    builder.set_alpn_protos(b"\x08http/1.1")?;

    // TLS 1.3 cipher suites: BoringSSL defaults already match Chrome's preference
    // order (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305). BoringSSL does not
    // implement set_ciphersuites(), and set_cipher_list() only controls TLS 1.2
    // ciphers which are disabled here (TLS 1.3 only).

    // Certificate verification.
    // On iOS: the Network Extension sandbox blocks /etc/ssl/ entirely, so we use a
    // custom callback that delegates to the iOS Security framework instead.
    // On other platforms: use boring's built-in CA store via set_default_verify_paths().
    #[cfg(target_os = "ios")]
    {
        let sni = sni_hostname.unwrap_or(host);
        set_ios_cert_verify(&mut builder, sni);
    }

    #[cfg(not(target_os = "ios"))]
    {
        builder.set_verify(boring::ssl::SslVerifyMode::PEER);
        builder.set_default_verify_paths()?;
    }

    Ok(builder.build())
}

/// Connect to a server with Chrome-like TLS fingerprint
///
/// This function:
/// 1. Connects via TCP
/// 2. Performs TLS handshake with Chrome-like fingerprint
/// 3. Sets ALPN to http/1.1 (tungstenite requires HTTP/1.1 for WebSocket)
/// 4. Returns the TLS stream for manual WebSocket upgrade
///
/// # Arguments
/// * `host` - The hostname to connect to (for TCP and SNI fallback)
/// * `port` - The port to connect to
/// * `fingerprint` - The TLS fingerprint to use
/// * `sni_hostname` - Optional SNI hostname override (uses `host` if None)
pub async fn connect_chrome_like(
    host: &str,
    port: u16,
    fingerprint: TlsFingerprint,
    sni_hostname: Option<&str>,
) -> Result<ChromeTlsStream> {
    let addr = format!("{}:{}", host, port);

    // Connect TCP
    let tcp = TcpStream::connect(&addr).await
        .with_context(|| format!("Failed to connect to {}", addr))?;
    let tcp = enable_tcp_keepalive(tcp)
        .context("Failed to enable TCP keepalive")?;

    if fingerprint == TlsFingerprint::None {
        // Standard TLS without fingerprinting
        return connect_standard(tcp, host, sni_hostname).await;
    }

    // Build Chrome-like SSL context
    let connector = build_chrome_connector(host, sni_hostname)?;

    // Determine actual SNI hostname for the TLS handshake
    let sni = sni_hostname.unwrap_or(host);

    // Configure SSL with SNI
    let config = connector.configure()
        .context("Failed to configure SSL")?;

    debug!("TLS config created with ALPN: http/1.1, TLS 1.3 only, SNI: {}", sni);

    // Connect with domain (this performs the TLS handshake)
    let stream = tokio_boring::connect(config, sni, tcp).await
        .context("TLS handshake failed")?;

    debug!("TLS handshake completed successfully");

    Ok(ChromeTlsStream::new(stream))
}

/// Standard TLS connection without fingerprinting
async fn connect_standard(tcp: TcpStream, host: &str, sni_hostname: Option<&str>) -> Result<ChromeTlsStream> {
    let tcp = enable_tcp_keepalive(tcp)
        .context("Failed to enable TCP keepalive")?;

    let method = SslMethod::tls();
    let mut builder = SslConnector::builder(method)
        .context("Failed to create SSL connector")?;

    // TLS 1.3
    builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // ALPN: http/1.1 only (must match build_chrome_connector — see comment there)
    builder.set_alpn_protos(b"\x08http/1.1")?;

    // SNI is set via tokio_boring::connect(config, sni, tcp)
    let sni = sni_hostname.unwrap_or(host);

    // Certificate verification — same iOS/non-iOS split as build_chrome_connector.
    #[cfg(target_os = "ios")]
    set_ios_cert_verify(&mut builder, sni);

    #[cfg(not(target_os = "ios"))]
    {
        builder.set_verify(boring::ssl::SslVerifyMode::PEER);
        builder.set_default_verify_paths()?;
    }

    let connector = builder.build();
    let config = connector.configure()?;

    debug!("Standard TLS config created with ALPN: http/1.1, TLS 1.3 only, SNI: {}", sni);

    let stream = tokio_boring::connect(config, sni, tcp).await?;

    debug!("Standard TLS handshake completed successfully");

    Ok(ChromeTlsStream::new(stream))
}

/// Connect with specific TLS fingerprint (legacy function for compatibility)
#[allow(dead_code)]
pub async fn connect_with_fingerprint(
    host: &str,
    port: u16,
    fingerprint: TlsFingerprint,
) -> Result<SslStream<TcpStream>> {
    let stream = connect_chrome_like(host, port, fingerprint, None).await?;
    // This is a bit of a hack - we return the inner stream
    // In practice, the new code should use connect_chrome_like directly
    Ok(stream.inner)
}

/// Parse fingerprint from string
pub fn fingerprint_from_str(s: &str) -> Option<TlsFingerprint> {
    match s.to_lowercase().as_str() {
        "chrome" | "chrome120" => Some(TlsFingerprint::Chrome),
        "firefox" | "firefox120" => Some(TlsFingerprint::Firefox),
        "safari" | "safari17" => Some(TlsFingerprint::Safari),
        "none" | "standard" => Some(TlsFingerprint::None),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_parsing() {
        assert_eq!(fingerprint_from_str("chrome"), Some(TlsFingerprint::Chrome));
        assert_eq!(fingerprint_from_str("Chrome"), Some(TlsFingerprint::Chrome));
        assert_eq!(fingerprint_from_str("none"), Some(TlsFingerprint::None));
        assert_eq!(fingerprint_from_str("invalid"), None);
    }

    #[test]
    fn test_chrome_connector_builds() {
        let connector = build_chrome_connector("example.com", None);
        assert!(connector.is_ok());
    }
}
