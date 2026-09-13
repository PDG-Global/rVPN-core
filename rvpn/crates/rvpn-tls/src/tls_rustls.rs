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

use crate::resumption::ResumptionStore;

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

/// Build a rustls client config.
///
/// TLS 1.3 only, Chrome-order cipher suites and kx groups, ALPN http/1.1,
/// bundled Mozilla roots. See the module docs for the fingerprint rationale.
///
/// When `resumption` is `Some`, the config's session store is replaced with
/// the shared [`ResumptionStore`]; otherwise rustls's default per-config
/// in-memory cache is used.
fn build_client_config(resumption: Option<&ResumptionStore>) -> Result<Arc<rustls::ClientConfig>> {
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

    // Session resumption: attach the caller-provided shared store so tickets
    // survive across connections that use DIFFERENT configs (per exit server).
    // Without a store, rustls's default per-config cache still resumes
    // reconnects made through the same config (see shared_client_config).
    if let Some(store) = resumption {
        config.resumption = rustls::client::Resumption::store(store.rustls_session_store());
    }

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
    let config = build_client_config(None)?;
    // If another thread raced us, get_or_init keeps the winner's instance so
    // every connect still shares one config (and one session store).
    Ok(CONFIG.get_or_init(|| config))
}

/// Build a rustls client config with an optional shared resumption store.
///
/// Production TLS settings are identical to the shared config (TLS 1.3 only,
/// Chrome-order suites, ALPN http/1.1, bundled Mozilla roots). With
/// `Some(store)`, TLS 1.3 tickets the server issues are recorded into `store`
/// and offered on subsequent connections built from configs carrying the same
/// store. Building the config is not free (root store + provider setup) —
/// callers connecting repeatedly should either cache the returned `Arc` or use
/// [`connect_rustls_with_store`], which caches one config per store.
pub fn build_client_config_with_store(
    resumption: Option<&ResumptionStore>,
) -> Result<Arc<rustls::ClientConfig>> {
    build_client_config(resumption)
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
    connect_rustls_with_store(host, port, sni_hostname, None).await
}

/// Connect to a server via rustls, optionally resuming TLS sessions through a
/// shared [`ResumptionStore`].
///
/// Identical to [`connect_rustls`] except that when `resumption` is `Some`,
/// the handshake is performed with a per-store `ClientConfig` whose session
/// store is the given [`ResumptionStore`]: tickets issued by the server are
/// recorded there and the next connect with the same store offers one as a
/// PSK (1-RTT resume, no certificate flight). The config is built once per
/// store and cached inside it. `None` reproduces today's behavior exactly
/// (process-wide shared config).
pub async fn connect_rustls_with_store(
    host: &str,
    port: u16,
    sni_hostname: Option<&str>,
    resumption: Option<&ResumptionStore>,
) -> Result<RustlsTlsStream> {
    let sni = sni_hostname.unwrap_or(host);
    let addr = format!("{}:{}", host, port);

    // TCP connect + keepalive (parity with tls_boring::connect_chrome_like).
    let tcp = TcpStream::connect(&addr)
        .await
        .with_context(|| format!("Failed to connect to {}", addr))?;
    let tcp = enable_tcp_keepalive(tcp).context("Failed to enable TCP keepalive")?;

    let config = match resumption {
        None => Arc::clone(shared_client_config()?),
        Some(store) => store.rustls_config_or_init(|| build_client_config(Some(store)))?,
    };
    let connector = TlsConnector::from(config);

    let server_name = rustls::pki_types::ServerName::try_from(sni.to_owned())
        .map_err(|e| anyhow::anyhow!("Invalid SNI hostname {:?}: {}", sni, e))?;

    debug!(
        "rustls connecting (shared config, PSK resumption if ticket held), SNI: {}",
        sni
    );

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

    /// The no-store public builder must yield the same settings as the shared
    /// config (TLS 1.3 only, ALPN http/1.1).
    #[test]
    fn build_client_config_with_store_none_matches_shared() {
        let config = build_client_config_with_store(None).expect("config builds");
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    mod resumption {
        use super::*;
        use std::net::SocketAddr;
        use std::sync::atomic::{AtomicUsize, Ordering};

        use rustls::client::danger::{
            HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
        };
        use rustls::client::WebPkiServerVerifier;
        use rustls::pki_types::{
            CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime,
        };
        use rustls::{DigitallySignedStruct, SignatureScheme};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        /// Verifier that counts how many times a certificate chain was
        /// verified. A resumed TLS 1.3 handshake carries NO Certificate
        /// message, so `verify_server_cert` is never invoked on a resume —
        /// the counter staying flat across a reconnect is positive proof of
        /// resumption (rustls 0.22 has no `is_resumed()` accessor).
        #[derive(Debug)]
        struct CountingVerifier {
            inner: Arc<WebPkiServerVerifier>,
            verify_calls: Arc<AtomicUsize>,
        }

        impl ServerCertVerifier for CountingVerifier {
            fn verify_server_cert(
                &self,
                end_entity: &CertificateDer<'_>,
                intermediates: &[CertificateDer<'_>],
                server_name: &ServerName<'_>,
                ocsp_response: &[u8],
                now: UnixTime,
            ) -> std::result::Result<ServerCertVerified, rustls::Error> {
                self.verify_calls.fetch_add(1, Ordering::SeqCst);
                self.inner.verify_server_cert(
                    end_entity,
                    intermediates,
                    server_name,
                    ocsp_response,
                    now,
                )
            }

            fn verify_tls12_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                self.inner.verify_tls12_signature(message, cert, dss)
            }

            fn verify_tls13_signature(
                &self,
                message: &[u8],
                cert: &CertificateDer<'_>,
                dss: &DigitallySignedStruct,
            ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
                self.inner.verify_tls13_signature(message, cert, dss)
            }

            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                self.inner.supported_verify_schemes()
            }
        }

        /// Self-signed "localhost" cert + matching root store.
        fn test_cert() -> (
            CertificateDer<'static>,
            PrivateKeyDer<'static>,
            rustls::RootCertStore,
        ) {
            let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
                .expect("self-signed cert");
            let cert_der = certified.cert.der().clone();
            let key_der =
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert_der.clone()).expect("add root");
            (cert_der, key_der, roots)
        }

        /// Spawn a rustls TLS 1.3 server that issues session tickets (rustls
        /// default: 4 NewSessionTickets per connection), writes one byte to
        /// each client, then hangs until disconnect.
        async fn spawn_test_server(config: rustls::ServerConfig) -> SocketAddr {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let acceptor = TlsAcceptor::from(Arc::new(config));
            tokio::spawn(async move {
                loop {
                    let (tcp, _) = match listener.accept().await {
                        Ok(pair) => pair,
                        Err(_) => return,
                    };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let mut stream = acceptor.accept(tcp).await?;
                        stream.write_all(b"x").await?;
                        stream.flush().await?;
                        // Hold the connection open until the client goes away.
                        let mut buf = [0u8; 64];
                        while let Ok(n) = stream.read(&mut buf).await {
                            if n == 0 {
                                break;
                            }
                        }
                        Ok::<(), std::io::Error>(())
                    });
                }
            });
            addr
        }

        /// Client config trusting the test roots, with the shared
        /// [`ResumptionStore`] installed exactly as production wiring does.
        fn test_client_config(
            verifier: &Arc<CountingVerifier>,
            store: &ResumptionStore,
        ) -> Arc<rustls::ClientConfig> {
            let provider = rustls::crypto::ring::default_provider();
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .expect("TLS 1.3-only")
                .dangerous()
                .with_custom_certificate_verifier(Arc::clone(verifier) as _)
                .with_no_client_auth();
            config.resumption = rustls::client::Resumption::store(store.rustls_session_store());
            config.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(config)
        }

        /// Connect, complete the handshake, then read one byte. The read is
        /// what lets rustls process the server's post-handshake
        /// NewSessionTicket messages (tickets do not exist at handshake
        /// completion in TLS 1.3).
        async fn connect_and_read(
            config: &Arc<rustls::ClientConfig>,
            addr: SocketAddr,
        ) -> tokio_rustls::client::TlsStream<TcpStream> {
            let tcp = TcpStream::connect(addr).await.expect("tcp connect");
            let server_name = ServerName::try_from("localhost").unwrap().to_owned();
            let mut stream = TlsConnector::from(Arc::clone(config))
                .connect(server_name, tcp)
                .await
                .expect("tls handshake");
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.expect("read app byte");
            stream
        }

        fn make_verifier(
            roots: rustls::RootCertStore,
            verify_calls: &Arc<AtomicUsize>,
        ) -> Arc<CountingVerifier> {
            Arc::new(CountingVerifier {
                inner: WebPkiServerVerifier::builder(Arc::new(roots))
                    .build()
                    .expect("verifier"),
                verify_calls: Arc::clone(verify_calls),
            })
        }

        #[tokio::test]
        async fn second_connection_with_store_resumes() {
            let (cert_der, key_der, roots) = test_cert();
            let verify_calls = Arc::new(AtomicUsize::new(0));

            let server_config = {
                let provider = rustls::crypto::ring::default_provider();
                rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .expect("TLS 1.3-only")
                    .with_no_client_auth()
                    .with_single_cert(vec![cert_der], key_der)
                    .expect("server config")
            };
            let addr = spawn_test_server(server_config).await;

            let store = ResumptionStore::new();
            let verifier = make_verifier(roots.clone(), &verify_calls);
            let config = test_client_config(&verifier, &store);
            let localhost = ServerName::try_from("localhost").unwrap().to_owned();

            // Connection 1: full handshake — certificate verified, and the
            // server's tickets land in the store once we read.
            let stream1 = connect_and_read(&config, addr).await;
            assert_eq!(
                verify_calls.load(Ordering::SeqCst),
                1,
                "conn 1 must verify the cert"
            );
            assert!(
                store.rustls_tls13_ticket_count(&localhost) > 0,
                "server tickets must be recorded in the store"
            );
            drop(stream1);

            // Connection 2 via the SAME store: rustls takes a ticket and
            // offers it as a PSK. A resumed handshake has no Certificate
            // flight, so the verifier must NOT run again.
            let stream2 = connect_and_read(&config, addr).await;
            assert_eq!(
                verify_calls.load(Ordering::SeqCst),
                1,
                "conn 2 must NOT verify a certificate — resumed handshake"
            );
            drop(stream2);

            // Control: a FRESH store has no ticket to offer, so its handshake
            // must be full and verify the certificate again.
            let fresh = ResumptionStore::new();
            let verifier3 = make_verifier(roots, &verify_calls);
            let config3 = test_client_config(&verifier3, &fresh);
            let stream3 = connect_and_read(&config3, addr).await;
            assert_eq!(
                verify_calls.load(Ordering::SeqCst),
                2,
                "fresh store must force a full handshake"
            );
            drop(stream3);
        }
    }
}
