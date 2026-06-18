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
    let _ = server.abort();

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
