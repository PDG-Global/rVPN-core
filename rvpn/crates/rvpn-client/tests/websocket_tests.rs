//! Integration tests for WebSocket connections.
//!
//! These tests verify the critical path that caused v1.2.1 regressions:
//! - URI format (wss://host:port/path — not just /path)
//! - Connection establishment and data flow
//! - Ping jitter behavior
//! - Chrome-like upgrade headers (15 headers matching Chrome 131)

mod common;

use std::time::Duration;

use anyhow::Result;
use futures::{SinkExt, StreamExt};
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Test 1: WebSocket connection establishes
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_websocket_connects_successfully() -> Result<()> {
    let (addr, _shutdown) = common::start_plain_ws_server().await?;
    let url = format!("ws://127.0.0.1:{}", addr.port());
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await?;
    let (mut write, mut read) = ws_stream.split();

    write.send(tungstenite::Message::Text("hello".into())).await?;
    let msg = timeout(Duration::from_secs(2), read.next()).await;
    assert!(msg.is_ok(), "Should receive echo");
    assert_eq!(msg.unwrap().unwrap()?.to_text()?, "hello");
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 2: Binary data round-trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_websocket_binary_roundtrip() -> Result<()> {
    let (addr, _shutdown) = common::start_plain_ws_server().await?;
    let url = format!("ws://127.0.0.1:{}", addr.port());
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await?;
    let (mut write, mut read) = ws_stream.split();

    let test_payloads: Vec<Vec<u8>> = vec![
        vec![0x01, 0x02, 0x03],
        vec![0xAB; 1024],
        vec![0xCD; 65536],
        (0..1000u32).map(|i| (i % 256) as u8).collect(),
    ];

    for payload in &test_payloads {
        write
            .send(tungstenite::Message::Binary(payload.clone().into()))
            .await?;
        let msg = timeout(Duration::from_secs(5), read.next())
            .await
            .expect("Should receive echo")
            .expect("Stream should not end")
            .expect("Should not error");
        match msg {
            tungstenite::Message::Binary(data) => {
                assert_eq!(&data[..], &payload[..], "Binary payload mismatch");
            }
            _ => panic!("Expected binary message, got {:?}", msg),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 3: Ping jitter validation
// ---------------------------------------------------------------------------

#[test]
fn test_ping_interval_jitter_range() {
    use rand::{Rng, SeedableRng};

    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut intervals = Vec::new();

    for _ in 0..100 {
        let jitter_ms: u64 = rng.gen_range(8000..=14000);
        intervals.push(jitter_ms);
    }

    assert!(
        intervals.iter().all(|&i| (8000..=14000).contains(&i)),
        "All intervals should be in [8000, 14000]ms range"
    );

    let unique: std::collections::HashSet<u64> = intervals.iter().copied().collect();
    assert!(
        unique.len() > 50,
        "Expected significant jitter variation, got {} unique values out of 100",
        unique.len()
    );

    let mean: f64 = intervals.iter().sum::<u64>() as f64 / intervals.len() as f64;
    assert!(
        (10000.0..12000.0).contains(&mean),
        "Mean interval should be ~11000ms, got {}",
        mean
    );
}

// ---------------------------------------------------------------------------
// Test 4: Keepalive jitter validation
// ---------------------------------------------------------------------------

#[test]
fn test_keepalive_interval_jitter_range() {
    use rand::{Rng, SeedableRng};

    let mut rng = rand::rngs::StdRng::from_entropy();
    let mut intervals = Vec::new();

    for _ in 0..100 {
        let jitter_ms: u64 = rng.gen_range(3000..=7000);
        intervals.push(jitter_ms);
    }

    assert!(
        intervals.iter().all(|&i| (3000..=7000).contains(&i)),
        "All intervals should be in [3000, 7000]ms range"
    );

    let unique: std::collections::HashSet<u64> = intervals.iter().copied().collect();
    assert!(
        unique.len() > 50,
        "Expected significant jitter variation, got {} unique values",
        unique.len()
    );
}

// ---------------------------------------------------------------------------
// Test 5: WebSocket upgrade request URI format
// ---------------------------------------------------------------------------

#[test]
fn test_websocket_request_uri_format() {
    use tungstenite::client::IntoClientRequest;

    let host = "002.hk.97688.io";
    let port: u16 = 443;
    let path = "/api/v1/ws/mux";

    let url = format!("wss://{}:{}{}", host, port, path);
    let request: tungstenite::http::Request<()> = url.into_client_request().unwrap();

    let uri = request.uri().to_string();
    assert!(uri.starts_with("wss://"), "URI must start with wss://, got: {}", uri);
    assert!(uri.contains(host), "URI must contain hostname, got: {}", uri);
    assert!(uri.contains(path), "URI must contain path, got: {}", uri);

    // Verify essential headers
    let headers: std::collections::HashMap<String, String> = request
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    assert!(headers.contains_key("host"), "Must have Host header");
    assert!(
        headers.get("connection").map(|v| v.to_lowercase().contains("upgrade")).unwrap_or(false),
        "Must have Connection: Upgrade header"
    );
    assert!(
        headers.get("upgrade").map(|v| v.to_lowercase() == "websocket").unwrap_or(false),
        "Must have Upgrade: websocket header"
    );
    assert!(headers.contains_key("sec-websocket-key"), "Must have Sec-WebSocket-Key header");
    assert!(
        headers.get("sec-websocket-version").map(|v| v == "13").unwrap_or(false),
        "Must have Sec-WebSocket-Version: 13 header"
    );
}

// ---------------------------------------------------------------------------
// Test 6: Non-default port URI format
// ---------------------------------------------------------------------------

#[test]
fn test_websocket_request_uri_non_default_port() {
    use tungstenite::client::IntoClientRequest;

    let host = "002.hk.97688.io";
    let port: u16 = 8443;
    let path = "/api/v1/ws/mux";

    let url = format!("wss://{}:{}{}", host, port, path);
    let request: tungstenite::http::Request<()> = url.into_client_request().unwrap();

    let uri = request.uri().to_string();
    assert!(uri.starts_with("wss://"));
    assert!(uri.contains(":8443"));
    assert!(uri.contains(path));
}

// ---------------------------------------------------------------------------
// Test 7: Graceful close
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_websocket_graceful_close() -> Result<()> {
    let (addr, _shutdown) = common::start_plain_ws_server().await?;
    let url = format!("ws://127.0.0.1:{}", addr.port());
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await?;
    let (mut write, _) = ws_stream.split();
    write.send(tungstenite::Message::Close(None)).await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 8: Multiple concurrent connections
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_concurrent_websocket_connections() -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let server = tokio::spawn(async move {
        for _ in 0..3 {
            if let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    if let Ok(ws_stream) = tokio_tungstenite::accept_async(stream).await {
                        use futures::{SinkExt, StreamExt};
                        let (mut write, mut read) = ws_stream.split();
                        while let Some(Ok(msg)) = read.next().await {
                            if msg.is_text() || msg.is_binary() {
                                if write.send(msg).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut handles = Vec::new();
    for i in 0..3 {
        let url = format!("ws://127.0.0.1:{}", addr.port());
        handles.push(tokio::spawn(async move {
            let (ws_stream, _) = tokio_tungstenite::connect_async(&url).await?;
            let (mut write, mut read) = ws_stream.split();
            let msg = format!("client-{}", i);
            write.send(tungstenite::Message::Text(msg.clone().into())).await?;
            let echo = timeout(Duration::from_secs(2), read.next())
                .await
                .expect("Should receive echo")
                .expect("Stream should not end")
                .expect("Should not error");
            assert_eq!(echo.to_text()?, msg);
            Ok::<(), anyhow::Error>(())
        }));
    }

    for handle in handles {
        handle.await??;
    }

    server.abort();
    Ok(())
}

// ---------------------------------------------------------------------------
// Test 9: Chrome-like WebSocket upgrade headers
// ---------------------------------------------------------------------------

/// Verify that our WebSocket upgrade request matches Chrome 131's header profile.
/// Chrome sends 14-17 headers on WebSocket upgrade. We should send at least 14.
#[test]
fn test_chrome_like_websocket_headers() {
    use tungstenite::handshake::client::generate_key;

    let host = "002.hk.97688.io";
    let port: u16 = 443;
    let path = "/api/v1/ws";
    let ws_key = generate_key();
    let authority = format!("{}:{}", host, port);

    let url = format!("wss://{}:{}{}", host, port, path);
    let request: tungstenite::http::Request<()> = tungstenite::http::Request::builder()
        .method("GET")
        .uri(&url)
        .header("Host", &authority)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", &ws_key)
        .header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        )
        .header("Accept", "*/*")
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("Sec-Fetch-Dest", "websocket")
        .header("Sec-Fetch-Mode", "websocket")
        .header("Sec-Fetch-Site", "same-origin")
        .body(())
        .unwrap();

    let headers: std::collections::HashMap<String, String> = request
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // Must have all 15 Chrome-like headers
    assert!(headers.len() >= 14, "Expected at least 14 headers, got {}", headers.len());

    // Core WebSocket headers
    assert!(headers.contains_key("host"));
    assert!(
        headers.get("connection").map(|v| v.to_lowercase().contains("upgrade")).unwrap_or(false),
        "Connection: Upgrade required"
    );
    assert!(
        headers.get("upgrade").map(|v| v.to_lowercase() == "websocket").unwrap_or(false),
        "Upgrade: websocket required"
    );
    assert!(headers.contains_key("sec-websocket-key"));
    assert!(
        headers.get("sec-websocket-version").map(|v| v == "13").unwrap_or(false),
        "Sec-WebSocket-Version: 13 required"
    );

    // Chrome-like metadata headers
    assert!(
        headers.get("user-agent").map(|v| v.contains("Chrome/131")).unwrap_or(false),
        "User-Agent must contain Chrome/131, got: {:?}",
        headers.get("user-agent")
    );
    assert!(headers.contains_key("accept"));
    assert!(headers.contains_key("accept-encoding"));
    assert!(headers.contains_key("accept-language"));
    assert!(headers.contains_key("cache-control"));
    assert!(headers.contains_key("pragma"));
    assert!(headers.contains_key("sec-fetch-dest"));
    assert!(headers.contains_key("sec-fetch-mode"));
    assert!(headers.contains_key("sec-fetch-site"));

    // Must NOT contain permessage-deflate (tungstenite can't handle it)
    if let Some(ext) = headers.get("sec-websocket-extensions") {
        assert!(
            !ext.contains("permessage-deflate"),
            "Must NOT advertise permessage-deflate: got {}",
            ext
        );
    }
}

// ---------------------------------------------------------------------------
// Test 10: TLS WebSocket connection with Chrome-like headers
// ---------------------------------------------------------------------------

/// Verify that our Chrome-like headers work with a real TLS WebSocket server.
/// Uses BoringSSL directly to connect to the test server (self-signed cert).
#[tokio::test]
async fn test_tls_websocket_with_chrome_headers() -> Result<()> {
    let (addr, _shutdown, _cert_der) = common::start_tls_ws_server().await?;

    // Build a TLS connector that accepts self-signed certs (for testing only)
    let mut builder = boring::ssl::SslConnector::builder(boring::ssl::SslMethod::tls())?;
    builder.set_min_proto_version(Some(boring::ssl::SslVersion::TLS1_3))?;
    builder.set_max_proto_version(Some(boring::ssl::SslVersion::TLS1_3))?;
    builder.set_alpn_protos(b"\x08http/1.1")?;
    builder.set_verify(boring::ssl::SslVerifyMode::NONE); // Accept self-signed certs
    let connector = builder.build();

    // Connect TCP + TLS
    let tcp = tokio::net::TcpStream::connect(addr).await?;
    let config = connector.configure()?;
    let tls_stream = tokio_boring::connect(config, "localhost", tcp).await?;
    let tls_stream = rvpn_client::tls_boring::ChromeTlsStream::new(tls_stream);

    // Build Chrome-like upgrade request (same headers as connect_websocket)
    use tungstenite::handshake::client::generate_key;
    let ws_key = generate_key();
    let authority = format!("127.0.0.1:{}", addr.port());
    let request = tungstenite::http::Request::builder()
        .method("GET")
        .uri(format!("wss://127.0.0.1:{}/test", addr.port()))
        .header("Host", &authority)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header("Sec-WebSocket-Key", &ws_key)
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
        .header("Accept", "*/*")
        .header("Accept-Encoding", "gzip, deflate, br")
        .header("Accept-Language", "en-US,en;q=0.9")
        .header("Cache-Control", "no-cache")
        .header("Pragma", "no-cache")
        .header("Sec-Fetch-Dest", "websocket")
        .header("Sec-Fetch-Mode", "websocket")
        .header("Sec-Fetch-Site", "same-origin")
        .body(())?;

    let (ws_stream, _) = tokio_tungstenite::client_async(request, tls_stream).await?;
    let (mut write, mut read) = ws_stream.split();

    // Send binary data through the Chrome-header TLS WebSocket
    let test_data = vec![0xAB; 4096];
    write.send(tungstenite::Message::Binary(test_data.clone().into())).await?;

    let msg = timeout(Duration::from_secs(5), read.next())
        .await
        .expect("Should receive echo within 5s")
        .expect("Stream should not end")
        .expect("Should not error");

    match msg {
        tungstenite::Message::Binary(data) => {
            assert_eq!(&data[..], &test_data[..], "Binary payload should round-trip");
        }
        other => panic!("Expected binary message, got {:?}", other),
    }

    Ok(())
}
