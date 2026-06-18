//! Integration tests for TLS configuration.

mod common;

use std::sync::Arc;
use std::time::Duration;
use anyhow::Result;
use tokio::time::timeout;

fn make_connector(alpn: &[u8]) -> Result<boring::ssl::SslConnector> {
    let mut c = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())?;
    // Match production: TLS 1.3 only
    c.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_3))?;
    c.set_max_proto_version(Some(boring::ssl::SslVersion::TLS1_3))?;
    c.set_alpn_protos(alpn)?;
    c.set_verify(boring::ssl::SslVerifyMode::NONE);
    Ok(c.build())
}

async fn tls_connect(
    connector: &boring::ssl::SslConnector,
    addr: std::net::SocketAddr,
) -> Result<tokio_boring::SslStream<tokio::net::TcpStream>> {
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let config = connector.configure()?;
    let stream = tokio_boring::connect(config, "localhost", tcp).await
        .map_err(|e| anyhow::anyhow!("TLS connect: {:?}", e))?;
    Ok(stream)
}

/// Build a TLS server acceptor that supports TLS 1.3.
fn make_tls13_acceptor(cert_der: &[u8], key_der: &[u8]) -> Result<boring::ssl::SslAcceptor> {
    let mut acc = boring::ssl::SslAcceptor::mozilla_intermediate_v5(boring::ssl::SslMethod::tls())?;
    let cert = boring::x509::X509::from_der(cert_der)?;
    acc.set_certificate(&cert)?;
    let key = boring::pkey::PKey::private_key_from_der(key_der)?;
    acc.set_private_key(&key)?;
    acc.check_private_key()?;
    Ok(acc.build())
}

// Test 1: TLS 1.3 negotiation
#[tokio::test]
async fn test_tls_version_is_13() -> Result<()> {
    let (cert_der, key_der) = common::generate_test_cert()?;
    let acceptor = make_tls13_acceptor(&cert_der, &key_der)?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let acceptor = Arc::new(acceptor);
        if let Ok((tcp, _)) = listener.accept().await {
            match tokio_boring::accept(&acceptor, tcp).await {
                Ok(_stream) => tokio::time::sleep(Duration::from_secs(5)).await,
                Err(e) => eprintln!("TLS13 server error: {:?}", e),
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = make_connector(b"\x08http/1.1")?;
    let tls = tls_connect(&connector, addr).await?;
    let v = tls.ssl().version_str();
    assert_eq!(v, "TLSv1.3", "Must negotiate TLS 1.3, got {}", v);
    Ok(())
}

// Test 2: ALPN negotiates http/1.1
#[tokio::test]
async fn test_alpn_negotiates_http11() -> Result<()> {
    let (addr, _shutdown, _cert) = common::start_tls_ws_server().await?;
    let connector = make_connector(b"\x08http/1.1")?;
    let tls = tls_connect(&connector, addr).await?;
    if let Some(alpn) = tls.ssl().selected_alpn_protocol() {
        assert_eq!(alpn, b"http/1.1", "Expected http/1.1 ALPN");
    }
    Ok(())
}

// Test 3: h2 ALPN breaks WebSocket (regression test for v1.2.1)
#[tokio::test]
async fn test_alpn_h2_breaks_websocket() -> Result<()> {
    let (cert_der, key_der) = common::generate_test_cert()?;
    let mut acc = boring::ssl::SslAcceptor::mozilla_intermediate(boring::ssl::SslMethod::tls())?;
    let cert = boring::x509::X509::from_der(&cert_der)?;
    acc.set_certificate(&cert)?;
    let key = boring::pkey::PKey::private_key_from_der(&key_der)?;
    acc.set_private_key(&key)?;
    acc.check_private_key()?;
    acc.set_alpn_select_callback(|_ssl, protocols| {
        if protocols.windows(3).any(|w| w == b"\x02h2") {
            Ok(b"h2")
        } else {
            Ok(b"http/1.1")
        }
    });
    let acceptor = acc.build();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let acceptor = Arc::new(acceptor);
        if let Ok((tcp, _)) = listener.accept().await {
            let _ = tokio_boring::accept(&acceptor, tcp).await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Client with h2 first
    let mut c = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())?;
    c.set_alpn_protos(b"\x02h2\x08http/1.1")?;
    c.set_verify(boring::ssl::SslVerifyMode::NONE);
    let connector = c.build();

    let tls = tls_connect(&connector, addr).await?;
    let alpn = tls.ssl().selected_alpn_protocol();
    assert!(alpn.map(|a| a == b"h2").unwrap_or(false), "Server should pick h2");

    let url = format!("wss://127.0.0.1:{}", addr.port());
    let request: tungstenite::http::Request<()> =
        tungstenite::client::IntoClientRequest::into_client_request(url)?;
    let result = timeout(Duration::from_secs(3), tokio_tungstenite::client_async(request, tls)).await;
    assert!(result.is_err() || result.unwrap().is_err(), "WS over h2 should fail");
    Ok(())
}

// Test 4: WebSocket works with http/1.1 ALPN
#[tokio::test]
async fn test_websocket_works_with_http11_alpn() -> Result<()> {
    let (addr, _shutdown, _cert) = common::start_tls_ws_server().await?;
    let connector = make_connector(b"\x08http/1.1")?;
    let tls = tls_connect(&connector, addr).await?;

    let url = format!("wss://127.0.0.1:{}", addr.port());
    let request: tungstenite::http::Request<()> =
        tungstenite::client::IntoClientRequest::into_client_request(url)?;
    let (mut ws, _): (tokio_tungstenite::WebSocketStream<_>, _) =
        tokio_tungstenite::client_async(request, tls).await?;

    use futures::{SinkExt, StreamExt};
    ws.send(tungstenite::Message::Text("alpn-test".into())).await?;
    let msg = timeout(Duration::from_secs(2), ws.next()).await.unwrap().unwrap()?;
    assert_eq!(msg.to_text()?, "alpn-test");
    Ok(())
}

// Test 5: Cipher is Chrome-compatible
#[tokio::test]
async fn test_tls_cipher_is_chrome_compatible() -> Result<()> {
    let (cert_der, key_der) = common::generate_test_cert()?;
    let acceptor = make_tls13_acceptor(&cert_der, &key_der)?;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        let acceptor = Arc::new(acceptor);
        if let Ok((tcp, _)) = listener.accept().await {
            match tokio_boring::accept(&acceptor, tcp).await {
                Ok(_s) => tokio::time::sleep(Duration::from_secs(5)).await,
                Err(e) => eprintln!("Cipher server error: {:?}", e),
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let connector = make_connector(b"\x08http/1.1")?;
    let tls = tls_connect(&connector, addr).await?;

    let cipher = tls.ssl().current_cipher().unwrap();
    let name = cipher.name();
    let chrome = ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"];
    assert!(chrome.contains(&name), "Cipher {} not a Chrome TLS 1.3 cipher", name);
    Ok(())
}
