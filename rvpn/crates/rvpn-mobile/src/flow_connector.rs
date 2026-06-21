// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Per-Flow Connector - Creates a new WebSocket connection per flow
//
// This module provides Brook-style architecture: each network flow (destination)
// gets its own WebSocket connection to the server. This is simpler and more
// reliable than multiplexing multiple flows over a single connection.

use anyhow::{Context as _, Result};
use futures::SinkExt;
use futures::StreamExt;
use futures_util::stream::SplitSink;
use std::sync::Arc;
use tokio_tungstenite::{tungstenite::Message, MaybeTlsStream, WebSocketStream};
use tokio::net::TcpStream;
use tracing::{debug, info};
use tungstenite::handshake::client::generate_key;

use rvpn_core::crypto::{DoubleRatchet, IdentityKey, X3DHPublicBundle};
use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::protocol::HandshakeMessage;

use rvpn_client::TlsFingerprint;

/// WebSocket writer type
type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type WsStream = futures_util::stream::SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

/// Configuration for connecting to VPN server
#[derive(Clone)]
pub struct FlowConnectorConfig {
    pub server_host: String,
    pub server_port: u16,
    pub server_path: String,
    pub tls_fingerprint: TlsFingerprint,
    pub identity_key: std::sync::Arc<rvpn_core::crypto::IdentityKey>,
    pub server_bundle: X3DHPublicBundle,
}

/// A per-flow connection to the VPN server
pub struct FlowConnection {
    /// Flow identifier for debugging
    pub flow_id: u64,
    /// Target host
    pub target_host: String,
    /// Target port
    pub target_port: u16,
    /// WebSocket writer for sending data
    writer: Option<tokio::sync::mpsc::UnboundedSender<Message>>,
    /// Ratchet for encryption
    ratchet: DoubleRatchet,
}

impl FlowConnection {
    /// Send encrypted data through the flow connection
    pub async fn send(&mut self, data: &[u8], payload_type: u8) -> Result<()> {
        // Pad to 1KB boundary before encryption
        let padded = rvpn_core::protocol::padding::pad_packet(data)
            .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;

        let encrypted = self.ratchet.encrypt(&padded, &[payload_type])
            .context("Failed to encrypt data")?;

        let message = serde_json::to_vec(&encrypted)
            .context("Failed to serialize encrypted data")?;

        // Send as binary message
        if let Some(sender) = &self.writer {
            sender.send(Message::Binary(message))
                .map_err(|_| anyhow::anyhow!("Flow connection closed"))?;
        }

        Ok(())
    }
}

/// Create a new WebSocket connection and send target address
pub async fn create_flow_connection(
    config: &FlowConnectorConfig,
    target_host: &str,
    target_port: u16,
) -> Result<FlowConnection> {
    let flow_id = rand_id();

    info!("[FlowConnector] Creating new connection for {}:{} (flow_id: {})",
          target_host, target_port, flow_id);

    // Step 1: Connect via rustls (same approach as iOS/Android TUN)
    let url = format!("wss://{}:{}{}", config.server_host, config.server_port, config.server_path);

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_tungstenite::Connector::Rustls(std::sync::Arc::new(tls_config));

    let tcp_addr = format!("{}:{}", config.server_host, config.server_port);
    let tcp_stream = tokio::net::TcpStream::connect(&tcp_addr)
        .await
        .context("Failed to connect TCP stream")?;

    let ws_key = generate_key();
    let authority = format!("{}:{}", config.server_host, config.server_port);
    let request = tungstenite::http::Request::builder()
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
        .context("Failed to build WebSocket upgrade request")?;

    let (ws_stream, _) = tokio_tungstenite::client_async_tls_with_config(
        request,
        tcp_stream,
        None,
        Some(connector),
    )
    .await
    .context("WebSocket upgrade failed")?;

    debug!("[FlowConnector] WebSocket connected for flow {}", flow_id);

    // Step 2: Split into reader/writer using futures
    let (mut write, mut read) = ws_stream.split();

    // Step 3: Perform X3DH handshake
    let ratchet = perform_handshake(
        &mut read,
        &mut write,
        &config.identity_key,
        &config.server_bundle,
    )
    .await
    .context("X3DH handshake failed")?;

    info!("[FlowConnector] X3DH handshake complete for flow {}", flow_id);

    // Step 4: Send target address
    let mut ratchet = ratchet;
    send_target_address(&mut write, &mut ratchet, target_host, target_port)
        .await
        .context("Failed to send target address")?;

    info!("[FlowConnector] Target {}:{} sent for flow {}", target_host, target_port, flow_id);

    // Step 5: Create writer channel (we need to keep the write half alive)
    let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<Message>();

    // Spawn a task to handle outgoing messages
    let writer = tx.clone();
    tokio::spawn(async move {
        let mut rx = _rx;
        while let Some(msg) = rx.recv().await {
            if let Err(e) = write.send(msg).await {
                debug!("Flow connector send error: {}", e);
                break;
            }
        }
    });

    // Now we're ready to relay data
    Ok(FlowConnection {
        flow_id,
        target_host: target_host.to_string(),
        target_port,
        writer: Some(writer),
        ratchet,
    })
}

/// Perform X3DH handshake with server
async fn perform_handshake(
    ws_reader: &mut WsStream,
    ws_writer: &mut WsSink,
    identity_key: &std::sync::Arc<IdentityKey>,
    server_bundle: &X3DHPublicBundle,
) -> Result<DoubleRatchet> {
    // Create X3DH initiator
    let initiator = X3DHInitiator::from_identity_key(Arc::clone(identity_key));

    // Get the X25519 public key derived from the client's Ed25519 identity
    let identity_public = initiator.identity_key.x25519_public_key();

    // Get public key bytes for the handshake
    let ephemeral_public = initiator.ephemeral_key.public_key.to_bytes();

    // Send Hello message with X3DH parameters
    let hello = HandshakeMessage::Hello {
        version: rvpn_core::protocol::ProtocolVersion::CURRENT,
        auth_method: rvpn_core::protocol::AuthMethod::X3DH,
        ephemeral_key: Some(ephemeral_public.to_vec()),
        identity_key: Some(identity_public.to_vec()),
        session_token: None,
        connection_nonce: None,
    };

    let hello_bytes = serde_json::to_vec(&hello)
        .context("Failed to serialize Hello message")?;
    ws_writer.send(Message::Binary(hello_bytes)).await
        .context("Failed to send Hello message")?;

    debug!("Sent X3DH Hello message");

    // Receive ServerHello response
    let response = ws_reader.next().await
        .ok_or_else(|| anyhow::anyhow!("WebSocket closed during handshake"))?
        .context("WebSocket error during handshake")?;

    match response {
        Message::Binary(data) => {
            // ServerHello received, extract keys
            let server_hello: HandshakeMessage = serde_json::from_slice(&data)
                .context("Failed to parse ServerHello message")?;

            match server_hello {
                HandshakeMessage::ServerHello {
                    ephemeral_key: _server_ephemeral,
                    identity_key: _server_identity_key,
                    signed_prekey: _,
                    prekey_signature: _,
                } => {
                    debug!("Received ServerHello with ephemeral key");

                    // Complete X3DH agreement to get shared secret
                    let (shared_secret, _x3dh_material) = initiator
                        .agree(server_bundle)
                        .context("X3DH key agreement failed")?;

                    debug!("X3DH shared secret derived successfully");

                    // Initialize Double Ratchet as Alice (initiator)
                    // In X3DH, the server (Bob) doesn't generate an ephemeral key.
                    // The _server_ephemeral field is empty - init_alice doesn't use this parameter.
                    let ratchet = DoubleRatchet::init_alice(shared_secret, [0u8; 32]);

                    info!("Double Ratchet initialized as Alice (initiator)");

                    Ok(ratchet)
                }
                _ => Err(anyhow::anyhow!(
                    "Unexpected handshake message type from server"
                )),
            }
        }
        _ => Err(anyhow::anyhow!(
            "Expected binary message during handshake"
        )),
    }
}

/// Send target address to server
async fn send_target_address(
    ws_writer: &mut WsSink,
    ratchet: &mut DoubleRatchet,
    target_host: &str,
    target_port: u16,
) -> Result<()> {
    // Encode target: [host_len:1][host_bytes][port:2]
    let host_bytes = target_host.as_bytes();
    if host_bytes.len() > 255 {
        anyhow::bail!("Hostname too long");
    }

    let mut target_data = Vec::with_capacity(1 + host_bytes.len() + 2);
    target_data.push(host_bytes.len() as u8);
    target_data.extend_from_slice(host_bytes);
    target_data.extend_from_slice(&target_port.to_be_bytes());

    // Encrypt with payload type 0x01 (Data)
    let message = ratchet.encrypt(&target_data, &[0x01])
        .context("Failed to encrypt target address")?;

    // Serialize to JSON
    let serialized = serde_json::to_vec(&message)
        .context("Failed to serialize RatchetMessage")?;

    // Send as binary
    ws_writer.send(Message::Binary(serialized)).await.context("Failed to send target address")?;
    ws_writer.flush().await.context("Failed to flush")?;

    Ok(())
}

/// Generate a random flow ID
fn rand_id() -> u64 {
    use rand::Rng;
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut rng = rand::thread_rng();
    let rand: u64 = rng.gen();
    now.wrapping_add(rand)
}
