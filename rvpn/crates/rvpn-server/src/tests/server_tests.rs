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
            bob,
            rx,
            ws_write,
            std::sync::Arc::new(tokio::sync::Mutex::new(())),
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

// ── Credit-based per-flow flow control ─────────────────────────────

use crate::handler::{FlowMap, MuxMessage, MultiplexerSession, ServerFlow};
use bytes::Bytes;
use rvpn_core::protocol::multiplex::{
    ControlMessage, FlowSendCredits, FLOW_CREDIT_STALL_TIMEOUT, INITIAL_FLOW_WINDOW,
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

type Session = MultiplexerSession<tokio::net::TcpStream>;

/// Loopback TCP pair: (peer end the test drives, server end handed to the
/// flow tasks).
async fn tcp_pair() -> anyhow::Result<(tokio::net::TcpStream, tokio::net::TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (client, accepted) = tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
    Ok((client?, accepted?.0))
}

fn test_peer_addr() -> std::net::SocketAddr {
    "127.0.0.1:55555".parse().expect("valid socket addr")
}

fn insert_test_flow(
    flows: &FlowMap,
    flow_id: u32,
    to_target_tx: mpsc::Sender<Bytes>,
    send_credits: Arc<FlowSendCredits>,
) -> tokio::task::JoinHandle<()> {
    let flows = flows.clone();
    tokio::spawn(async move {
        // Stand-in abort handles: this flow has no real tasks.
        let relay_task = tokio::spawn(std::future::pending::<()>()).abort_handle();
        let writer_task = tokio::spawn(std::future::pending::<()>()).abort_handle();
        flows.lock().await.insert(
            flow_id,
            Arc::new(ServerFlow {
                to_target_tx,
                send_credits,
                relay_task,
                writer_task,
            }),
        );
    })
}

/// Drain data frames for `flow_id` until `received` reaches `until` bytes.
async fn recv_data_until(
    rx: &mut mpsc::Receiver<MuxMessage>,
    flow_id: u32,
    expected_byte: u8,
    received: &mut usize,
    until: usize,
) {
    while *received < until {
        match rx.recv().await {
            Some(MuxMessage::Data { flow_id: fid, data }) => {
                assert_eq!(fid, flow_id);
                assert!(data.iter().all(|&b| b == expected_byte));
                *received += data.len();
            }
            Some(MuxMessage::Control(_)) => panic!("relay must not emit control frames here"),
            None => panic!("data channel closed early"),
        }
    }
}

/// The per-flow writer task must forward bytes to the target socket in order
/// and emit a WindowUpdate granting exactly the consumed byte count after
/// each write (receiver-side credit accounting).
#[tokio::test]
async fn test_flow_writer_emits_window_update() -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt as _;

    let (mut peer, target) = tcp_pair().await?;
    let (_read_half, write_half) = target.into_split();

    let flows: FlowMap = Arc::new(Mutex::new(HashMap::new()));
    let (to_target_tx, to_target_rx) = mpsc::channel::<Bytes>(8);
    let (control_tx, mut control_rx) = mpsc::channel::<ControlMessage>(16);
    let flow_id = 7u32;
    insert_test_flow(
        &flows,
        flow_id,
        to_target_tx.clone(),
        Arc::new(FlowSendCredits::new()),
    )
    .await?;

    let writer = Session::spawn_flow_writer(
        flow_id,
        write_half,
        to_target_rx,
        flows.clone(),
        control_tx,
        test_peer_addr(),
    );

    let chunks: Vec<Vec<u8>> = vec![vec![1u8; 1000], vec![2u8; 2000], vec![3u8; 500]];
    let mut expected = Vec::new();
    for chunk in &chunks {
        to_target_tx.send(Bytes::copy_from_slice(chunk)).await?;
        expected.extend_from_slice(chunk);
    }

    // The target receives the exact bytes in order.
    let mut received = vec![0u8; expected.len()];
    tokio::time::timeout(Duration::from_secs(5), peer.read_exact(&mut received)).await??;
    assert_eq!(received, expected);

    // Each write produced a WindowUpdate granting exactly the bytes written.
    for chunk in &chunks {
        let msg = tokio::time::timeout(Duration::from_secs(5), control_rx.recv())
            .await?
            .expect("control channel closed early");
        assert_eq!(
            msg,
            ControlMessage::WindowUpdate {
                flow_id,
                window_size: chunk.len() as u32
            }
        );
    }

    // Removing the flow drops the queue sender; the writer drains and exits.
    flows.lock().await.remove(&flow_id);
    drop(to_target_tx);
    tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .map_err(|_| anyhow::anyhow!("flow writer did not exit after flow removal"))??;

    Ok(())
}

/// A client over-sending beyond its credits (uplink queue full) must get its
/// flow closed — never block the WebSocket receive loop.
#[tokio::test]
async fn test_handle_flow_data_closes_flow_on_oversend() -> anyhow::Result<()> {
    let flows: FlowMap = Arc::new(Mutex::new(HashMap::new()));
    // No writer task draining: the queue stays full, simulating a client
    // that sends far beyond its credit window.
    let (to_target_tx, _to_target_rx) = mpsc::channel::<Bytes>(64);
    while to_target_tx.try_send(Bytes::from_static(b"x")).is_ok() {}
    let flow_id = 9u32;
    insert_test_flow(
        &flows,
        flow_id,
        to_target_tx,
        Arc::new(FlowSendCredits::new()),
    )
    .await?;

    let (control_tx, mut control_rx) = mpsc::channel::<ControlMessage>(4);
    let result = Session::handle_flow_data(flow_id, b"overflow", &flows, &control_tx).await;
    assert!(result.is_err(), "over-send past a full queue must fail");
    assert!(
        flows.lock().await.is_empty(),
        "over-sending flow must be removed from the flow map"
    );
    let msg = control_rx
        .recv()
        .await
        .expect("over-sending flow must be closed with CloseFlow");
    assert_eq!(msg, ControlMessage::CloseFlow { flow_id });

    Ok(())
}

/// The downlink relay must stop reading the target socket when the credit
/// window is exhausted and resume when WindowUpdate grants arrive. The
/// in-flight byte count per flow is bounded by INITIAL_FLOW_WINDOW.
#[tokio::test]
async fn test_flow_relay_respects_send_credits() -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let (mut peer, target) = tcp_pair().await?;
    let (read_half, _write_half) = target.into_split();

    let flows: FlowMap = Arc::new(Mutex::new(HashMap::new()));
    let (to_target_tx, _to_target_rx) = mpsc::channel::<Bytes>(1);
    let send_credits = Arc::new(FlowSendCredits::new());
    let flow_id = 11u32;
    insert_test_flow(&flows, flow_id, to_target_tx, send_credits.clone()).await?;

    let (tx, mut rx) = mpsc::channel::<MuxMessage>(2000);
    let (control_tx, _control_rx) = mpsc::channel::<ControlMessage>(16);
    let _relay = Session::spawn_flow_relay(
        flow_id,
        read_half,
        flows.clone(),
        tx,
        control_tx,
        send_credits.clone(),
        test_peer_addr(),
    );

    // The target sends twice the window.
    let window = INITIAL_FLOW_WINDOW as usize;
    let writer = tokio::spawn(async move {
        peer.write_all(&vec![0xABu8; window * 2]).await
    });

    // Exactly one window's worth of data may arrive; then the relay stalls.
    let mut received = 0usize;
    tokio::time::timeout(
        Duration::from_secs(5),
        recv_data_until(&mut rx, flow_id, 0xAB, &mut received, window),
    )
    .await?;
    assert_eq!(received, window, "relay forwarded more than the window");
    assert_eq!(send_credits.available(), 0, "window must be fully consumed");

    // No more data while credits are exhausted.
    assert!(
        tokio::time::timeout(Duration::from_millis(300), rx.recv())
            .await
            .is_err(),
        "relay sent data with zero credits"
    );

    // Grant the second window — the remainder flows.
    send_credits.grant(window as u64);
    tokio::time::timeout(
        Duration::from_secs(5),
        recv_data_until(&mut rx, flow_id, 0xAB, &mut received, window * 2),
    )
    .await?;
    assert_eq!(received, window * 2);
    tokio::time::timeout(Duration::from_secs(5), writer).await???;

    Ok(())
}

/// Regression: a peer that never sends WindowUpdate stalls the downlink at
/// zero credits; the stall valve must close the flow after
/// FLOW_CREDIT_STALL_TIMEOUT instead of hanging forever.
#[tokio::test(start_paused = true)]
async fn test_flow_relay_stall_valve_closes_flow() -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let (mut peer, target) = tcp_pair().await?;
    let (read_half, _write_half) = target.into_split();

    let flows: FlowMap = Arc::new(Mutex::new(HashMap::new()));
    let (to_target_tx, _to_target_rx) = mpsc::channel::<Bytes>(1);
    let send_credits = Arc::new(FlowSendCredits::new());
    let flow_id = 13u32;
    insert_test_flow(&flows, flow_id, to_target_tx, send_credits.clone()).await?;

    let (tx, mut rx) = mpsc::channel::<MuxMessage>(2000);
    let (control_tx, mut control_rx) = mpsc::channel::<ControlMessage>(16);
    let _relay = Session::spawn_flow_relay(
        flow_id,
        read_half,
        flows.clone(),
        tx,
        control_tx,
        send_credits,
        test_peer_addr(),
    );

    // Target sends more than the window; the relay drains exactly the
    // window and then stalls at zero credits.
    let window = INITIAL_FLOW_WINDOW as usize;
    tokio::spawn(async move { peer.write_all(&vec![0xCDu8; window + 8190]).await });

    let mut received = 0usize;
    while received < window {
        match rx.recv().await {
            Some(MuxMessage::Data { data, .. }) => received += data.len(),
            other => panic!("unexpected relay output: {:?}", other.map(|_| ())),
        }
    }
    assert_eq!(received, window);

    // Never grant credits: the valve must fire and close the flow. Under
    // the paused clock the 60s timeout auto-advances.
    let msg = control_rx
        .recv()
        .await
        .expect("stall valve must send CloseFlow");
    assert_eq!(msg, ControlMessage::CloseFlow { flow_id });
    assert!(
        flows.lock().await.is_empty(),
        "stalled flow must be removed from the flow map"
    );

    Ok(())
}

/// Regression: removing a flow (the CloseFlow path) must abort a relay
/// parked at zero credits immediately. Before `remove_flow` aborted the
/// flow's tasks, a parked relay lingered until the 60s stall valve fired —
/// logging a spurious stall warning and holding the target connection open
/// long after the client had closed the flow cleanly.
#[tokio::test(start_paused = true)]
async fn test_remove_flow_aborts_parked_relay() -> anyhow::Result<()> {
    let (_peer, target) = tcp_pair().await?;
    let (read_half, _write_half) = target.into_split();

    let flows: FlowMap = Arc::new(Mutex::new(HashMap::new()));
    let (to_target_tx, _to_target_rx) = mpsc::channel::<Bytes>(1);
    let send_credits = Arc::new(FlowSendCredits::new());
    let flow_id = 15u32;

    let (tx, _data_rx) = mpsc::channel::<MuxMessage>(8);
    let (control_tx, _control_rx) = mpsc::channel::<ControlMessage>(8);
    let relay = Session::spawn_flow_relay(
        flow_id,
        read_half,
        flows.clone(),
        tx,
        control_tx,
        send_credits.clone(),
        test_peer_addr(),
    );
    // Store the task abort handles in the flow, as the CreateFlow path does.
    let writer_task = tokio::spawn(std::future::pending::<()>()).abort_handle();
    flows.lock().await.insert(
        flow_id,
        Arc::new(ServerFlow {
            to_target_tx,
            send_credits: send_credits.clone(),
            relay_task: relay.abort_handle(),
            writer_task,
        }),
    );

    // Drain the credit window so the relay parks in wait_for_credit_or_stall.
    send_credits.try_consume(send_credits.available());
    assert_eq!(send_credits.available(), 0);
    tokio::task::yield_now().await;

    // Remove the flow via the same helper the CloseFlow arm uses.
    let start = tokio::time::Instant::now();
    crate::handler::remove_flow(&flows, flow_id).await;
    assert!(flows.lock().await.is_empty(), "flow must be removed");

    // The parked relay is aborted promptly — far below the 60s stall valve.
    let join = tokio::time::timeout(Duration::from_secs(5), relay).await?;
    let err = join.expect_err("parked relay must be aborted, not finish cleanly");
    assert!(err.is_cancelled(), "relay must die via abort");
    assert!(
        start.elapsed() < FLOW_CREDIT_STALL_TIMEOUT,
        "relay survived to the stall valve"
    );

    Ok(())
}

/// The WebSocket sender must drain control frames ahead of queued bulk data,
/// so WindowUpdate / CloseFlow / FlowCreated are never stuck behind a bulk
/// flow's backlog.
#[tokio::test]
async fn test_ws_sender_prioritizes_control() -> anyhow::Result<()> {
    use futures_util::StreamExt as _;
    use rvpn_core::crypto::ratchet::RatchetMessage;
    use tokio_tungstenite::tungstenite::Message;

    // Loopback WebSocket pair: run_ws_sender ↔ test client.
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
    let secret = [7u8; 32];
    let mut alice = rvpn_core::crypto::DoubleRatchet::init_alice(secret, [0u8; 32]);
    let bob = std::sync::Arc::new(tokio::sync::Mutex::new(
        rvpn_core::crypto::DoubleRatchet::init_bob(secret),
    ));

    let (tx, rx) = mpsc::channel::<MuxMessage>(64);
    let (control_tx, control_rx) = mpsc::channel::<ControlMessage>(16);

    // Queue bulk data FIRST, then one control frame behind it.
    for i in 0..8u8 {
        tx.send(MuxMessage::Data {
            flow_id: 1,
            data: vec![i; 1000],
        })
        .await?;
    }
    control_tx
        .send(ControlMessage::CloseFlow { flow_id: 2 })
        .await?;

    let ws_write = std::sync::Arc::new(tokio::sync::Mutex::new(ws_write));
    let sender = tokio::spawn(Session::run_ws_sender(
        rx,
        control_rx,
        bob,
        ws_write,
        std::sync::Arc::new(tokio::sync::Mutex::new(())),
    ));

    // The first frame on the wire must be the control frame (AAD 0x02),
    // even though eight data frames were queued before it.
    let first = tokio::time::timeout(Duration::from_secs(5), client_stream.next())
        .await?
        .expect("ws closed before first frame")?;
    let Message::Binary(data) = first else {
        panic!("expected binary frame");
    };
    let ratchet_msg = RatchetMessage::from_bytes(&data)?;
    let decrypted = alice.decrypt(&ratchet_msg, &[0x02])?;
    let unpadded = rvpn_core::protocol::padding::unpad_packet(&decrypted)?;
    let (frames, consumed) = rvpn_core::protocol::multiplex::parse_frames(&unpadded);
    assert_eq!(consumed, unpadded.len());
    assert_eq!(frames.len(), 1);
    assert!(frames[0].is_control(), "first frame must be control");
    assert_eq!(
        frames[0].parse_control()?,
        ControlMessage::CloseFlow { flow_id: 2 }
    );

    // The queued data must still arrive afterwards, in order.
    for i in 0..8u8 {
        let msg = tokio::time::timeout(Duration::from_secs(5), client_stream.next())
            .await?
            .expect("ws closed while draining data")?;
        let Message::Binary(data) = msg else {
            panic!("expected binary data frame");
        };
        let ratchet_msg = RatchetMessage::from_bytes(&data)?;
        let decrypted = alice.decrypt(&ratchet_msg, &[0x01])?;
        let unpadded = rvpn_core::protocol::padding::unpad_packet(&decrypted)?;
        let (frames, _) = rvpn_core::protocol::multiplex::parse_frames(&unpadded);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].flow_id, 1);
        assert_eq!(&frames[0].payload[..], &vec![i; 1000][..]);
    }

    drop(tx);
    drop(control_tx);
    tokio::time::timeout(Duration::from_secs(5), sender)
        .await
        .map_err(|_| anyhow::anyhow!("run_ws_sender did not exit after channels closed"))??;

    Ok(())
}

/// Regression: concurrent per-query DNS tasks must enqueue responses in
/// ratchet message-number order. Without the send_lock in
/// `DnsHandler::send_encrypted_response`, a response encrypted later could
/// overtake an earlier one into the writer channel and the client's ratchet
/// dropped it ("Message too old") — the periodic DNS breakage that ended in
/// "pending queries with no response for 10s, forcing reconnect".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_responses_preserve_wire_order_under_contention() -> anyhow::Result<()> {
    use rvpn_core::crypto::ratchet::RatchetMessage;
    use rvpn_core::crypto::DoubleRatchet;
    use tokio_tungstenite::tungstenite::Message;

    // Server encrypts as Bob; the test decrypts as Alice in wire order.
    let secret = [9u8; 32];
    let mut alice = DoubleRatchet::init_alice(secret, [0u8; 32]);
    let bob = Arc::new(tokio::sync::Mutex::new(DoubleRatchet::init_bob(secret)));
    let send_lock = Arc::new(tokio::sync::Mutex::new(()));
    // Capacity 1 forces send awaits → maximal interleaving between tasks.
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(1);

    const TASKS: usize = 8;
    const PER_TASK: usize = 50;
    const TOTAL: usize = TASKS * PER_TASK;

    let mut handles = Vec::new();
    for t in 0..TASKS {
        let bob = Arc::clone(&bob);
        let send_lock = Arc::clone(&send_lock);
        let out_tx = out_tx.clone();
        handles.push(tokio::spawn(async move {
            for i in 0..PER_TASK {
                let payload = format!("query-{}-{}", t, i).into_bytes();
                crate::handler::DnsHandler::send_encrypted_response(
                    &bob, &send_lock, &out_tx, &payload,
                )
                .await
                .expect("send_encrypted_response failed");
            }
        }));
    }
    drop(out_tx);

    let mut wire_numbers = Vec::new();
    let mut payloads = std::collections::HashSet::new();
    while let Some(msg) = out_rx.recv().await {
        let Message::Binary(data) = msg else {
            panic!("unexpected non-binary message");
        };
        let parsed = RatchetMessage::from_bytes(&data)?;
        wire_numbers.push(parsed.header.message_number);
        let plain = alice
            .decrypt(&parsed, &[0x09])
            .expect("decrypt failed — frame dropped or reordered");
        payloads.insert(String::from_utf8(plain).expect("payload not utf8"));
    }
    for h in handles {
        h.await.expect("sender task panicked");
    }

    // Every frame arrived and decrypted, in exact message-number order.
    assert_eq!(wire_numbers.len(), TOTAL, "frames lost on the wire");
    let mut sorted = wire_numbers.clone();
    sorted.sort_unstable();
    assert_eq!(
        wire_numbers, sorted,
        "wire order diverged from message-number order"
    );
    assert_eq!(wire_numbers[0], 0);
    assert_eq!(wire_numbers[TOTAL - 1], (TOTAL - 1) as u32);
    assert_eq!(payloads.len(), TOTAL, "payloads lost or duplicated");
    Ok(())
}
