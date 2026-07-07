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
use tokio_tungstenite::{tungstenite::Message, WebSocketStream};
use tracing::{debug, info};

use rvpn_core::crypto::{DoubleRatchet, IdentityKey, X3DHPublicBundle};
use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::protocol::HandshakeMessage;

use rvpn_tls::TlsFingerprint;

/// WebSocket reader/writer types — TLS backend selected by platform feature.
#[cfg(feature = "macos-direct-tun")]
type WsSink = SplitSink<WebSocketStream<rvpn_tls::ChromeTlsStream>, Message>;
#[cfg(feature = "macos-direct-tun")]
type WsStream = futures_util::stream::SplitStream<WebSocketStream<rvpn_tls::ChromeTlsStream>>;

#[cfg(feature = "ios-direct-tun")]
type WsSink = SplitSink<WebSocketStream<rvpn_tls::RustlsTlsStream>, Message>;
#[cfg(feature = "ios-direct-tun")]
type WsStream = futures_util::stream::SplitStream<WebSocketStream<rvpn_tls::RustlsTlsStream>>;

// Android: use tokio-tungstenite's built-in TLS (rustls)
#[cfg(feature = "android-direct-tun")]
type WsSink = SplitSink<WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>, Message>;
#[cfg(feature = "android-direct-tun")]
type WsStream = futures_util::stream::SplitStream<WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>>;

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

    // Step 1: Connect via TLS
    let url = format!("wss://{}:{}{}", config.server_host, config.server_port, config.server_path);

    // Android: connect_async_tls_with_config handles TLS + WebSocket in one step.
    // iOS/macOS: establish TLS first, then upgrade to WebSocket via client_async.
    #[cfg(feature = "android-direct-tun")]
    let (ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
        &url, None, false, None,
    )
    .await
    .context("FlowConnector connection failed")?;

    #[cfg(not(feature = "android-direct-tun"))]
    let (ws_stream, _) = {
        let tls_stream = {
            #[cfg(feature = "ios-direct-tun")]
            let s = rvpn_tls::connect_rustls(&config.server_host, config.server_port, Some(&config.server_host))
                .await
                .context("TLS handshake failed")?;
            #[cfg(not(feature = "ios-direct-tun"))]
            let s = rvpn_tls::connect_chrome_like(
                &config.server_host,
                config.server_port,
                rvpn_tls::TlsFingerprint::Chrome,
                Some(&config.server_host),
            )
            .await
            .context("TLS handshake failed")?;
            s
        };
        tokio_tungstenite::client_async(&url, tls_stream)
            .await
            .context("FlowConnector WebSocket handshake failed")?
    };

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
                    identity_key: server_identity_key,
                    signed_prekey: server_signed_prekey,
                    prekey_signature: server_prekey_signature,
                } => {
                    debug!("Received ServerHello with ephemeral key");

                    // Use wire values for X3DH (see stream_relay.rs / ios_tun.rs).
                    let server_identity_key: [u8; 32] = server_identity_key
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Server identity key has invalid length"))?;
                    let server_signed_prekey: [u8; 32] = server_signed_prekey
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Server signed prekey has invalid length"))?;
                    let prekey_signature: [u8; 64] = server_prekey_signature
                        .as_slice()
                        .try_into()
                        .map_err(|_| anyhow::anyhow!("Prekey signature has invalid length"))?;

                    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
                        &server_identity_key,
                    )
                    .map_err(|e| anyhow::anyhow!("Invalid server identity key: {}", e))?;
                    let signature = ed25519_dalek::Signature::from_bytes(&prekey_signature);
                    ed25519_dalek::Verifier::verify(
                        &verifying_key,
                        &server_signed_prekey,
                        &signature,
                    )
                    .map_err(|e| anyhow::anyhow!("Invalid prekey signature: {}", e))?;
                    debug!("Server prekey signature verified");

                    let server_bundle_from_hello = X3DHPublicBundle {
                        identity_key: server_identity_key,
                        identity_x25519_key: server_bundle.identity_x25519_key,
                        signed_prekey: server_signed_prekey,
                        prekey_signature,
                        one_time_prekey: None,
                        identity_key_version: server_bundle.identity_key_version,
                        rotation_signature: server_bundle.rotation_signature,
                    };

                    let (shared_secret, _x3dh_material) = initiator
                        .agree(&server_bundle_from_hello)
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
