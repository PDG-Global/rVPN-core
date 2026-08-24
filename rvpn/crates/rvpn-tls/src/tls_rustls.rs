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
// Cost: partial Chrome ClientHello fingerprint mimicry. macOS keeps the boring
// backend for full mimicry; iOS gets the "best we can do inside stock rustls":
// TLS 1.3 only (no TLS 1.2 fallback path to differ from Chrome-on-1.3),
// cipher_suites reordered to Chrome's order (128-GCM first), and kx_groups
// reordered to lead with X25519. Extension order, GREASE, and padding are still
// rustls-native — a middlebox doing full JA3/JA4 hashing will still see a
// different fingerprint from Chrome, but crude cipher/curve-list classifiers
// pass through.
//
// Certificate roots are bundled at compile time via `webpki-roots` (Mozilla CA
// set), mirroring the boring path's `ca-bundle.pem`. The iOS NE sandbox blocks
// `/etc/ssl/` and `trustd` XPC is unreliable from the extension, so a bundled
// root store is mandatory — `rustls-platform-verifier` would reintroduce the
// trustd dependency.

use std::pin::Pin;
use std::sync::{Arc, OnceLock};
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
    // Disable Nagle: the tunnel writes small, latency-sensitive frames
    // (batched packets, keepalives) and Nagle + delayed-ACK interactions
    // stall them by tens of milliseconds.
    socket
        .set_nodelay(true)
        .context("Failed to set TCP_NODELAY")?;

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

/// Build the shared rustls client config.
///
/// TLS 1.3 only, Chrome-order cipher suites and kx groups, ALPN http/1.1,
/// bundled Mozilla roots. See the module docs for the fingerprint rationale.
fn build_client_config() -> Result<Arc<rustls::ClientConfig>> {
    // Bundle Mozilla CA roots. iOS NE sandbox blocks /etc/ssl/ and trustd is
    // unreliable, so we cannot use rustls-platform-verifier here.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Build a Chrome-order CryptoProvider on top of the ring provider so the
    // ClientHello's cipher_suites and kx_groups lists match Chrome-on-TLS-1.3.
    //
    // rustls's ring default offers TLS13_AES_256_GCM_SHA384 first; Chrome sends
    // TLS_AES_128_GCM_SHA256 first. Reordering these two lists is what makes
    // JA3-style hashers that key on cipher order stop distinguishing us from
    // Chrome. Extension order and GREASE we can't reach from rustls 0.22.
    let base = rustls::crypto::ring::default_provider();
    let provider = rustls::crypto::CryptoProvider {
        cipher_suites: vec![
            rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
            rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
            rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        ],
        kx_groups: vec![
            rustls::crypto::ring::kx_group::X25519,
            rustls::crypto::ring::kx_group::SECP256R1,
            rustls::crypto::ring::kx_group::SECP384R1,
        ],
        ..base
    };

    // TLS 1.3 only — Chrome-on-1.2 and Chrome-on-1.3 have very different
    // ClientHellos, and our server always speaks 1.3. Leaving 1.2 in the offer
    // set would balloon the fingerprint surface for zero real gain.
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("rustls ClientConfig with TLS 1.3-only")?
        .with_root_certificates(root_store)
        .with_no_client_auth();

    // ALPN: http/1.1 only (rustls 0.22 exposes this as a public field, not a
    // builder method). Matches the boring backend's set_alpn_protos(b"\x08http/1.1").
    // Advertising `h2` would let nginx pick HTTP/2 and break our manual WS upgrade.
    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    debug!(
        "rustls config: TLS 1.3 only (ring, Chrome cipher/KX order), ALPN http/1.1, \
         bundled Mozilla roots"
    );

    Ok(Arc::new(config))
}

/// The process-wide shared client config.
///
/// Reusing one config across every connect is what enables TLS 1.3 session
/// resumption: rustls's in-memory session store hangs off the ClientConfig,
/// so the NewSessionTickets the server sends (4 by default) are kept and
/// presented as a PSK on the NEXT connect. With a fresh config per connect
/// the tickets were thrown away and every reconnect paid a full handshake
/// (certificate exchange, verification and signature). Resumption also
/// skips rebuilding the root store and the Chrome-order CryptoProvider on
/// every reconnect, which matters inside the iOS NE memory budget.
fn shared_client_config() -> Result<&'static Arc<rustls::ClientConfig>> {
    static CONFIG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    if let Some(config) = CONFIG.get() {
        return Ok(config);
    }
    let config = build_client_config()?;
    // If another thread raced us, get_or_init keeps the winner's instance so
    // every connect still shares one config (and one session store).
    Ok(CONFIG.get_or_init(|| config))
}

/// Connect to a server via rustls.
///
/// 1. TCP connect (with keepalive: 60s time, 10s interval — parity with the
///    boring backend).
/// 2. TLS 1.3 handshake using Mozilla CA roots bundled at compile time
///    (`webpki-roots`). Reconnects resume via PSK using the shared session
///    store (see [`shared_client_config`]).
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

    let connector = TlsConnector::from(Arc::clone(shared_client_config()?));

    let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned())
        .map_err(|e| anyhow::anyhow!("Invalid SNI hostname {:?}: {}", sni, e))?;

    debug!("rustls connecting (shared config, PSK resumption if ticket held), SNI: {}", sni);

    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .context("rustls TLS handshake failed")?;

    debug!("rustls TLS handshake completed successfully");

    Ok(RustlsTlsStream::new(tls_stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Session resumption depends on every connect sharing ONE config: the
    /// session store lives on the ClientConfig, so two distinct configs can
    /// never resume each other's tickets.
    #[test]
    fn shared_client_config_is_reused_across_calls() {
        let a = shared_client_config().expect("config builds");
        let b = shared_client_config().expect("config builds again");
        assert!(Arc::ptr_eq(a, b), "config must be a single shared instance");
        assert_eq!(a.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }
}
