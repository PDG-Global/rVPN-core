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
#[cfg(not(target_os = "android"))]
use boring::ssl::{SslConnector, SslMethod, SslVersion};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
#[cfg(not(target_os = "android"))]
use tokio_boring::SslStream;
use tracing::debug;

use crate::resumption::ResumptionStore;
use crate::tls_fingerprint::TlsFingerprint;

/// Enable TCP keepalive on a socket.
///
/// Detects dead connections (e.g. NAT evictions, middlebox drops) in ~90s
/// instead of relying on the OS default (~2h on Linux/macOS).
#[cfg(not(target_os = "android"))]
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
    // Disable Nagle: the tunnel writes small, latency-sensitive frames and
    // Nagle + delayed-ACK interactions stall them by tens of milliseconds.
    socket
        .set_nodelay(true)
        .context("Failed to set TCP_NODELAY")?;

    let std_tcp = std::net::TcpStream::from(socket);
    std_tcp
        .set_nonblocking(true)
        .context("Failed to set non-blocking")?;

    TcpStream::from_std(std_tcp).context("Failed to convert std TcpStream back to tokio")
}

/// TLS fingerprint types are defined in [`crate::tls_fingerprint`] and
/// re-exported from the crate root. `connect_chrome_like` accepts the enum
/// here for back-compat with existing call sites.

/// A TLS connection that mimics Chrome's fingerprint
///
/// This is returned after the TLS handshake is complete.
/// The caller can then use this to send the WebSocket HTTP upgrade request.
#[cfg(not(target_os = "android"))]
pub struct ChromeTlsStream {
    inner: SslStream<TcpStream>,
}

#[cfg(not(target_os = "android"))]
impl ChromeTlsStream {
    pub fn new(stream: SslStream<TcpStream>) -> Self {
        Self { inner: stream }
    }

    /// Whether this connection resumed a previously cached TLS session
    /// (`SSL_session_reused`). `true` means the handshake was 1-RTT with no
    /// certificate flight; `false` means a full handshake. Useful for the
    /// "handshakes full vs resumed" metric.
    pub fn session_reused(&self) -> bool {
        self.inner.ssl().session_reused()
    }
}

#[cfg(not(target_os = "android"))]
impl AsyncRead for ChromeTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(not(target_os = "android"))]
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
#[cfg(not(target_os = "android"))]
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
#[cfg(not(target_os = "android"))]
fn build_chrome_connector(host: &str, sni_hostname: Option<&str>) -> Result<SslConnector> {
    build_chrome_connector_ext(host, sni_hostname, None, None)
}

/// Extended connector builder behind [`build_chrome_connector`].
///
/// * `resumption` — when `Some`, the client session cache is enabled and a
///   new-session callback records every negotiated session (TLS 1.3 ticket)
///   into the given [`ResumptionStore`]. Connectors built this way MUST be
///   cached inside the store (`boring_connector_slot`) so that sessions are
///   only ever offered to `Ssl` objects minted from the same `SslContext` —
///   that is the safety contract of `SslRef::set_session`.
/// * `trust_store_override` — replace the platform default CA paths with an
///   explicit cert store. Production always passes `None`; tests use it to
///   trust a self-signed server certificate.
#[allow(unused_variables)]
#[cfg(not(target_os = "android"))]
fn build_chrome_connector_ext(
    host: &str,
    sni_hostname: Option<&str>,
    resumption: Option<&ResumptionStore>,
    trust_store_override: Option<boring::x509::store::X509Store>,
) -> Result<SslConnector> {
    let method = SslMethod::tls();
    let mut builder = SslConnector::builder(method).context("Failed to create SSL connector")?;

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
        match trust_store_override {
            Some(store) => builder
                .set_verify_cert_store(store)
                .context("Failed to install TLS trust store")?,
            None => builder.set_default_verify_paths()?,
        }
    }

    // Session resumption: enable the client session cache (required for the
    // new-session callback to fire) and record every negotiated session —
    // for TLS 1.3 that's one callback per NewSessionTicket post-handshake
    // message, which is the only point a resumable ticket exists.
    if let Some(store) = resumption {
        builder.set_session_cache_mode(boring::ssl::SslSessionCacheMode::CLIENT);
        builder.set_new_session_callback(crate::resumption::boring_new_session_callback(store));
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
#[cfg(not(target_os = "android"))]
pub async fn connect_chrome_like(
    host: &str,
    port: u16,
    fingerprint: TlsFingerprint,
    sni_hostname: Option<&str>,
) -> Result<ChromeTlsStream> {
    connect_chrome_like_with_resumption(host, port, fingerprint, sni_hostname, None).await
}

/// Connect to a server with Chrome-like TLS fingerprint, optionally resuming
/// TLS sessions through a shared [`ResumptionStore`].
///
/// When `resumption` is `Some` (and `fingerprint` is not
/// [`TlsFingerprint::None`]):
///
/// * the Chrome-like `SslConnector` is built once per store and cached inside
///   it, with a BoringSSL new-session callback that records every TLS 1.3
///   ticket the server issues, keyed by SNI hostname;
/// * before the handshake, the cached ticket for this server (if any) is
///   attached via `SSL_set_session`, so the ClientHello carries a PSK like a
///   returning browser and a willing server completes a 1-RTT resumed
///   handshake with no certificate flight.
///
/// `None` reproduces today's behavior exactly (fresh connector, full
/// handshake every time). With [`TlsFingerprint::None`] the store is ignored
/// — the standard path builds a one-off connector, and sessions must never
/// cross `SslContext`s.
///
/// # Arguments
/// * `host` - The hostname to connect to (for TCP and SNI fallback)
/// * `port` - The port to connect to
/// * `fingerprint` - The TLS fingerprint to use
/// * `sni_hostname` - Optional SNI hostname override (uses `host` if None)
/// * `resumption` - Optional shared session store (per exit server)
#[cfg(not(target_os = "android"))]
pub async fn connect_chrome_like_with_resumption(
    host: &str,
    port: u16,
    fingerprint: TlsFingerprint,
    sni_hostname: Option<&str>,
    resumption: Option<&ResumptionStore>,
) -> Result<ChromeTlsStream> {
    let addr = format!("{}:{}", host, port);

    // Connect TCP
    let tcp = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("Failed to connect to {}", addr))?;
    let tcp = enable_tcp_keepalive(tcp).context("Failed to enable TCP keepalive")?;

    if fingerprint == TlsFingerprint::None {
        if resumption.is_some() {
            debug!("TLS resumption store ignored for TlsFingerprint::None");
        }
        // Standard TLS without fingerprinting
        return connect_standard(tcp, host, sni_hostname).await;
    }

    // Determine actual SNI hostname for the TLS handshake
    let sni = sni_hostname.unwrap_or(host);

    match resumption {
        None => {
            let connector = build_chrome_connector(host, sni_hostname)?;
            connect_with_connector(&connector, tcp, sni, None).await
        }
        Some(store) => {
            // One connector per store, so sessions recorded via this
            // connector's callback are only ever set on `Ssl`s minted from
            // the same `SslContext` (the `set_session` safety contract).
            let slot = store.boring_connector_slot();
            if slot.get().is_none() {
                let connector = build_chrome_connector_ext(host, sni_hostname, Some(store), None)?;
                // If another thread raced us, keep the winner's instance.
                let _ = slot.set(connector);
            }
            let connector = slot.get().expect("connector slot initialized above");
            connect_with_connector(connector, tcp, sni, Some(store)).await
        }
    }
}

/// Perform the TLS handshake over `tcp` using `connector`, attaching a cached
/// session from `resumption` when available.
#[cfg(not(target_os = "android"))]
async fn connect_with_connector(
    connector: &SslConnector,
    tcp: TcpStream,
    sni: &str,
    resumption: Option<&ResumptionStore>,
) -> Result<ChromeTlsStream> {
    // Configure SSL with SNI
    let mut config = connector.configure().context("Failed to configure SSL")?;

    if let Some(store) = resumption {
        if let Some(session) = store.boring_take_session(sni) {
            // SAFETY: sessions enter the store only through the new-session
            // callback installed on the connector cached in this same store
            // (see `connect_chrome_like_with_resumption`), so `session` is
            // always associated with `config`'s `SslContext`.
            if let Err(e) = unsafe { config.set_session(&session) } {
                // Never fail the connect over resumption state: log and fall
                // back to a full handshake.
                debug!(
                    "Could not attach cached TLS session ({}), full handshake",
                    e
                );
            }
        }
    }

    debug!(
        "TLS config created with ALPN: http/1.1, TLS 1.3 only, SNI: {}",
        sni
    );

    // Connect with domain (this performs the TLS handshake)
    let stream = tokio_boring::connect(config, sni, tcp)
        .await
        .context("TLS handshake failed")?;

    debug!(
        "TLS handshake completed successfully (session_reused={})",
        stream.ssl().session_reused()
    );

    Ok(ChromeTlsStream::new(stream))
}

/// Standard TLS connection without fingerprinting
async fn connect_standard(
    tcp: TcpStream,
    host: &str,
    sni_hostname: Option<&str>,
) -> Result<ChromeTlsStream> {
    let tcp = enable_tcp_keepalive(tcp).context("Failed to enable TCP keepalive")?;

    let method = SslMethod::tls();
    let mut builder = SslConnector::builder(method).context("Failed to create SSL connector")?;

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

    debug!(
        "Standard TLS config created with ALPN: http/1.1, TLS 1.3 only, SNI: {}",
        sni
    );

    let stream = tokio_boring::connect(config, sni, tcp).await?;

    debug!("Standard TLS handshake completed successfully");

    Ok(ChromeTlsStream::new(stream))
}

/// Connect with specific TLS fingerprint (legacy function for compatibility)
#[allow(dead_code)]
#[cfg(not(target_os = "android"))]
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
pub use crate::tls_fingerprint::fingerprint_from_str;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chrome_connector_builds() {
        let connector = build_chrome_connector("example.com", None);
        assert!(connector.is_ok());
    }

    #[cfg(not(target_os = "android"))]
    mod resumption {
        use super::*;
        use std::net::SocketAddr;
        use std::sync::Arc;

        use boring::pkey::PKey;
        use boring::ssl::SslAcceptor;
        use boring::x509::store::X509StoreBuilder;
        use boring::x509::X509;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        /// Spawn a BoringSSL TLS 1.3 server. BoringSSL sends 2 session
        /// tickets per connection by default. Returns the address and the
        /// self-signed certificate (for the client's trust store).
        async fn spawn_test_server() -> (SocketAddr, X509) {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("self-signed cert");
            let cert = X509::from_der(certified.cert.der().as_ref()).expect("parse cert");
            let pkey =
                PKey::private_key_from_der(&certified.key_pair.serialize_der()).expect("parse key");

            let mut builder =
                SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).expect("acceptor builder");
            builder
                .set_min_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder
                .set_max_proto_version(Some(SslVersion::TLS1_3))
                .unwrap();
            builder.set_certificate(&cert).unwrap();
            builder.set_private_key(&pkey).unwrap();
            builder.check_private_key().unwrap();
            let acceptor = Arc::new(builder.build());

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                loop {
                    let (tcp, _) = match listener.accept().await {
                        Ok(pair) => pair,
                        Err(_) => return,
                    };
                    let acceptor = Arc::clone(&acceptor);
                    tokio::spawn(async move {
                        let stream = tokio_boring::accept(&acceptor, tcp)
                            .await
                            .map_err(|e| std::io::Error::other(format!("tls accept: {e}")))?;
                        let (mut rd, mut wr) = tokio::io::split(stream);
                        wr.write_all(b"x").await?;
                        wr.flush().await?;
                        // Hold the connection open until the client goes away.
                        let mut buf = [0u8; 64];
                        loop {
                            match rd.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {}
                            }
                        }
                        Ok::<(), std::io::Error>(())
                    });
                }
            });
            (addr, cert)
        }

        /// Two sequential connections through one [`ResumptionStore`]: the
        /// second must report `session_reused() == true`.
        #[tokio::test]
        async fn second_connection_with_store_resumes() {
            let (addr, cert) = spawn_test_server().await;

            // Trust store pinning the self-signed server cert (test-only
            // override; production uses set_default_verify_paths).
            let mut trust = X509StoreBuilder::new().expect("x509 store builder");
            trust.add_cert(cert).expect("add cert");
            let trust = trust.build();

            let store = ResumptionStore::new();

            // Replicate the caching done by connect_chrome_like_with_resumption:
            // one connector per store, built through the SAME extended builder
            // as production, with the test trust override.
            let slot = store.boring_connector_slot();
            slot.set(
                build_chrome_connector_ext("localhost", None, Some(&store), Some(trust))
                    .expect("connector builds"),
            )
            .expect("slot empty");
            let connector = slot.get().unwrap();

            // Connection 1: full handshake; reading one byte lets BoringSSL
            // process the server's NewSessionTickets, which the new-session
            // callback records into the store.
            let tcp = TcpStream::connect(addr).await.expect("tcp connect 1");
            let mut stream1 = connect_with_connector(connector, tcp, "localhost", Some(&store))
                .await
                .expect("handshake 1");
            assert!(!stream1.session_reused(), "conn 1 must be a full handshake");
            let mut byte = [0u8; 1];
            stream1.read_exact(&mut byte).await.expect("read app byte");
            assert_eq!(
                store.boring_session_count(),
                1,
                "ticket must be recorded in the store"
            );
            drop(stream1);

            // Connection 2 via the SAME store: the ticket is attached with
            // SSL_set_session and the server must accept it.
            let tcp = TcpStream::connect(addr).await.expect("tcp connect 2");
            let mut stream2 = connect_with_connector(connector, tcp, "localhost", Some(&store))
                .await
                .expect("handshake 2");
            assert!(stream2.session_reused(), "conn 2 must be a resumed session");
            // The resumed connection receives fresh tickets, replenishing the
            // store for the next rotation.
            stream2
                .read_exact(&mut byte)
                .await
                .expect("read app byte 2");
            assert_eq!(
                store.boring_session_count(),
                1,
                "resumed conn must replenish the store"
            );
            drop(stream2);

            // Control: a FRESH store has no ticket — full handshake again.
            let fresh = ResumptionStore::new();
            let tcp = TcpStream::connect(addr).await.expect("tcp connect 3");
            let stream3 = connect_with_connector(connector, tcp, "localhost", Some(&fresh))
                .await
                .expect("handshake 3");
            assert!(
                !stream3.session_reused(),
                "fresh store must force a full handshake"
            );
        }
    }
}
