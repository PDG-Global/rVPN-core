//! Server connection tests

use std::time::Duration;

use tokio::net::TcpListener;

use rvpn_core::protocol::{HandshakeMessage, ProtocolVersion, AuthMethod};

/// Test basic server startup
#[tokio::test]
async fn test_server_startup() -> anyhow::Result<()> {
    let config = crate::config::ServerConfig::default();
    let _handler = crate::handler::VpnHandler::new(config)?;

    // Just verify we can create the handler
    Ok(())
}

/// Test WebSocket connection
#[tokio::test]
async fn test_websocket_connection() -> anyhow::Result<()> {
    // Start a test server
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    // Spawn server task
    let server = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            use tokio_tungstenite::accept_async;
            if let Ok(mut ws) = accept_async(stream).await {
                let _ = ws.close(None).await;
            }
        }
    });

    // Give server time to start
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Try to connect
    let result = tokio_tungstenite::connect_async(format!("ws://{}", addr)).await;

    // Cleanup
    server.abort();

    assert!(result.is_ok(), "Should be able to connect to server");

    Ok(())
}

/// Test handshake message parsing
#[tokio::test]
async fn test_handshake_message() -> anyhow::Result<()> {
    // Create a Hello message
    let hello = HandshakeMessage::Hello {
        version: ProtocolVersion::CURRENT,
        auth_method: AuthMethod::X3DH,
        ephemeral_key: Some(vec![1, 2, 3]),
        identity_key: Some(vec![4, 5, 6]),
        session_token: None,
        connection_nonce: Some(vec![7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]),
    };

    // Serialize
    let bytes = serde_json::to_vec(&hello)?;

    // Deserialize
    let parsed: HandshakeMessage = serde_json::from_slice(&bytes)?;

    // Verify
    match parsed {
        HandshakeMessage::Hello { version, auth_method, ephemeral_key, .. } => {
            assert_eq!(version, ProtocolVersion::CURRENT);
            assert_eq!(auth_method, AuthMethod::X3DH);
            assert!(ephemeral_key.is_some());
        }
        _ => panic!("Expected Hello message"),
    }

    Ok(())
}

/// Test rate limiter
#[tokio::test]
async fn test_rate_limiter() -> anyhow::Result<()> {
    let mut limiter = crate::handler::RateLimiter::new(500, 2000);

    let ip = "127.0.0.1".parse()?;

    // First request should succeed
    assert!(limiter.check(&ip));

    limiter.record(ip);

    // Second request should also succeed (within limit)
    assert!(limiter.check(&ip));

    Ok(())
}

// ── Legacy TCP relay (relay_tcp) tests ─────────────────────────────
//
// Regression coverage for the "zombie flow" leak: flows whose client-side
// relay exited on an error path used to stay pinned on the server forever,
// because the client's ping task kept sending WebSocket pings and the
// server counted those pings as activity, defeating the idle timeout.

/// tokio-tungstenite's `connect_async` wraps plain TCP in `MaybeTlsStream`.
type ClientWsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

/// Encrypt a data frame the same way a legacy client does
/// (pad to 1KB boundary, ratchet-encrypt with payload type 0x01).
fn client_frame(ratchet: &mut rvpn_core::crypto::DoubleRatchet, data: &[u8]) -> Vec<u8> {
    let padded = rvpn_core::protocol::padding::pad_packet(data).expect("padding failed");
    let message = ratchet.encrypt(&padded, &[0x01]).expect("encryption failed");
    message.to_bytes().expect("serialization failed")
}

/// Wait up to 2s for a WebSocket Close frame, skipping anything else.
async fn wait_for_close(stream: &mut futures_util::stream::SplitStream<ClientWsStream>) -> bool {
    use futures_util::StreamExt;
    use tokio_tungstenite::tungstenite::Message;

    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(msg) = stream.next().await {
            match msg {
                Ok(Message::Close(_)) => return true,
                Ok(_) => continue,
                Err(_) => return false,
            }
        }
        false
    })
    .await
    .unwrap_or(false)
}

/// Scaffolding for the relay_tcp tests: a real loopback WebSocket pair plus
/// a TCP "origin" for the relay to target.
///
/// Returns the client-side (Alice) ratchet, the test client's WS sink and
/// stream halves, the spawned relay task, and the target peer task (which
/// returns the first bytes it read from the relay).
async fn relay_test_rig(
    idle_timeout: Duration,
    target_closes_immediately: bool,
) -> anyhow::Result<(
    rvpn_core::crypto::DoubleRatchet,
    futures_util::stream::SplitSink<ClientWsStream, tokio_tungstenite::tungstenite::Message>,
    futures_util::stream::SplitStream<ClientWsStream>,
    tokio::task::JoinHandle<anyhow::Result<()>>,
    tokio::task::JoinHandle<Vec<u8>>,
)> {
    use futures_util::StreamExt;
    use tokio::io::AsyncReadExt;

    let handler = crate::handler::VpnHandler::new(crate::config::ServerConfig::default())?;

    // TCP origin the relay will target.
    let target_listener = TcpListener::bind("127.0.0.1:0").await?;
    let target_addr = target_listener.local_addr()?;
    let target_peer = tokio::spawn(async move {
        let (mut socket, _) = target_listener.accept().await.unwrap();
        if target_closes_immediately {
            drop(socket); // FIN towards the relay
            return Vec::new();
        }
        let mut buf = vec![0u8; 4096];
        let n = socket.read(&mut buf).await.unwrap_or(0);
        buf.truncate(n);
        let first = buf;
        // Keep holding the connection so the relay can only end via the
        // WebSocket side (idle timeout / Close).
        let mut hold = vec![0u8; 4096];
        let _ = socket.read(&mut hold).await;
        first
    });

    // Loopback WebSocket pair: test client ↔ relay.
    let ws_listener = TcpListener::bind("127.0.0.1:0").await?;
    let ws_addr = ws_listener.local_addr()?;
    let accept_task = tokio::spawn(async move {
        let (stream, _) = ws_listener.accept().await.unwrap();
        tokio_tungstenite::accept_async(stream).await.unwrap()
    });

    let (client_ws, _resp) =
        tokio_tungstenite::connect_async(format!("ws://{}/", ws_addr)).await?;
    let server_ws = accept_task.await?;

    let (ws_write, ws_read) = server_ws.split();
    let (client_sink, client_stream) = client_ws.split();

    // Paired ratchets over a fixed shared secret (client = Alice, server = Bob).
    let secret = [42u8; 32];
    let alice = rvpn_core::crypto::DoubleRatchet::init_alice(secret, [0u8; 32]);
    let bob = rvpn_core::crypto::DoubleRatchet::init_bob(secret);

    let target_stream = tokio::net::TcpStream::connect(target_addr).await?;

    let relay_task = tokio::spawn(async move {
        handler
            .relay_tcp(ws_write, ws_read, target_stream, bob, idle_timeout)
            .await
    });

    Ok((alice, client_sink, client_stream, relay_task, target_peer))
}

/// WebSocket pings must NOT count as activity for the legacy idle timeout.
/// A buggy client's ping task keeps pinging long after its relay exited on
/// an error path; counting those pings pins zombie flows (and their target
/// connections) on the server forever. Also verifies the relay sends a WS
/// Close frame when it exits.
#[tokio::test]
async fn test_relay_tcp_idle_timeout_ignores_pings() -> anyhow::Result<()> {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    let (mut alice, mut client_sink, mut client_stream, relay_task, target_peer) =
        relay_test_rig(Duration::from_secs(1), false).await?;

    // One real data frame — must reach the target and refresh activity.
    let payload = b"hello relay";
    client_sink
        .send(Message::Binary(client_frame(&mut alice, payload)))
        .await?;

    // Keep pinging well past the 1s idle deadline.
    let pinger = tokio::spawn(async move {
        loop {
            if client_sink.send(Message::Ping(vec![])).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    });

    // The relay must terminate despite the continuous pings.
    let relay_result = tokio::time::timeout(Duration::from_secs(8), relay_task)
        .await
        .map_err(|_| anyhow::anyhow!("relay_tcp never exited — pings defeated the idle timeout"))?
        .expect("relay task panicked");
    pinger.abort();
    relay_result?;

    // The client must observe a WS Close (notify on every exit path).
    assert!(
        wait_for_close(&mut client_stream).await,
        "client did not receive WS Close after idle timeout"
    );

    // The data frame must have been relayed to the target before the timeout.
    let received = target_peer.await?;
    assert_eq!(received, payload.to_vec());

    Ok(())
}

/// When the target closes the connection, the relay must exit promptly and
/// send a WS Close to the client. Previously the socket was just dropped,
/// which surfaced on clients as Protocol(ResetWithoutClosingHandshake).
#[tokio::test]
async fn test_relay_tcp_sends_close_when_target_closes() -> anyhow::Result<()> {
    let (_alice, _client_sink, mut client_stream, relay_task, target_peer) =
        relay_test_rig(Duration::from_secs(300), true).await?;

    let relay_result = tokio::time::timeout(Duration::from_secs(5), relay_task)
        .await
        .map_err(|_| anyhow::anyhow!("relay_tcp did not exit after target EOF"))?
        .expect("relay task panicked");
    relay_result?;

    assert!(
        wait_for_close(&mut client_stream).await,
        "client did not receive WS Close after target EOF"
    );
    let _ = target_peer.await;

    Ok(())
}

// ── TUN downlink batching tests ────────────────────────────────────

/// append_tun_frame output must round-trip through the same multi-frame
/// parser the clients use (parse_frames / iOS run_rx walk).
#[test]
fn test_append_tun_frame_roundtrip() {
    let packets: Vec<Vec<u8>> = vec![
        vec![0x45, 0x00, 0x00, 0x14],          // tiny (ACK-like)
        vec![0xAB; 1400],                       // full MTU
        vec![0x01, 0x02, 0x03],                 // small
    ];

    let mut buf = Vec::new();
    for p in &packets {
        crate::handler::MultiplexerSession::<tokio::net::TcpStream>::append_tun_frame(&mut buf, p);
    }

    let (frames, consumed) = rvpn_core::protocol::multiplex::parse_frames(&buf);
    assert_eq!(consumed, buf.len(), "parser must consume the whole batch");
    assert_eq!(frames.len(), packets.len());
    for (frame, expected) in frames.iter().zip(packets.iter()) {
        assert_eq!(frame.flow_id, 1, "TUN data frames use flow_id 1");
        assert_eq!(&frame.payload[..], &expected[..]);
    }
}

/// The downlink loop must coalesce queued packets into batched messages
/// (≤16 frames each, padded+encrypted once per batch) and deliver every
/// packet in order.
#[tokio::test]
async fn test_tun_response_loop_batches_packets() -> anyhow::Result<()> {
    use futures_util::StreamExt;
    use rvpn_core::crypto::ratchet::RatchetMessage;
    use tokio_tungstenite::tungstenite::Message;

    // Loopback WebSocket pair: downlink loop ↔ test client.
    let ws_listener = TcpListener::bind("127.0.0.1:0").await?;
    let ws_addr = ws_listener.local_addr()?;
    let accept_task = tokio::spawn(async move {
        let (stream, _) = ws_listener.accept().await.unwrap();
        tokio_tungstenite::accept_async(stream).await.unwrap()
    });
    let (client_ws, _resp) =
        tokio_tungstenite::connect_async(format!("ws://{}/", ws_addr)).await?;
    let server_ws = accept_task.await?;

    let (ws_write, _server_read) = server_ws.split();
    let (_client_sink, mut client_stream) = client_ws.split();

    // Paired ratchets: server encrypts as Bob, test decrypts as Alice.
    let secret = [99u8; 32];
    let mut alice = rvpn_core::crypto::DoubleRatchet::init_alice(secret, [0u8; 32]);
    let bob = rvpn_core::crypto::DoubleRatchet::init_bob(secret);
    let bob = std::sync::Arc::new(tokio::sync::Mutex::new(bob));

    // Queue 20 packets BEFORE the loop starts so the first iterations find a
    // full queue and must batch.
    let (tx, rx) = tokio::sync::mpsc::channel::<Vec<u8>>(100);
    let packets: Vec<Vec<u8>> = (0..20u8).map(|i| vec![i; 100]).collect();
    for p in &packets {
        tx.send(p.clone()).await?;
    }
    drop(tx); // Disconnect so the loop drains everything and exits.

    let ws_write = std::sync::Arc::new(tokio::sync::Mutex::new(ws_write));
    let loop_task = tokio::spawn(
        crate::handler::MultiplexerSession::<tokio::net::TcpStream>::run_tun_response_loop(
            bob, rx, ws_write,
        ),
    );

    tokio::time::timeout(Duration::from_secs(5), loop_task)
        .await
        .map_err(|_| anyhow::anyhow!("run_tun_response_loop did not drain and exit"))?
        .expect("loop task panicked");

    // Collect every binary message the loop sent.
    let mut messages: Vec<Vec<u8>> = Vec::new();
    while let Ok(Some(Ok(msg))) =
        tokio::time::timeout(Duration::from_millis(500), client_stream.next()).await
    {
        if let Message::Binary(data) = msg {
            messages.push(data);
        }
    }

    assert!(!messages.is_empty(), "no downlink messages received");

    // Decrypt, unpad, parse — verify order, completeness, and batch caps.
    let mut received: Vec<Vec<u8>> = Vec::new();
    for msg in &messages {
        let ratchet_msg = RatchetMessage::from_bytes(msg)?;
        let decrypted = alice.decrypt(&ratchet_msg, &[0x01])?;
        let unpadded = rvpn_core::protocol::padding::unpad_packet(&decrypted)?;
        let (frames, consumed) = rvpn_core::protocol::multiplex::parse_frames(&unpadded);
        assert_eq!(consumed, unpadded.len(), "trailing bytes in batch plaintext");
        assert!(
            frames.len() <= 16,
            "batch exceeds TUN_BATCH_MAX_FRAMES: {}",
            frames.len()
        );
        for frame in frames {
            assert_eq!(frame.flow_id, 1);
            received.push(frame.payload.to_vec());
        }
    }

    assert_eq!(received, packets, "packets lost or reordered by batching");
    assert!(
        messages.len() < packets.len(),
        "expected coalescing: {} messages for {} packets",
        messages.len(),
        packets.len()
    );

    Ok(())
}
