//! VPN Tunnel - Persistent WebSocket connection for TUN mode
//!
//! Unlike the Brook-style SOCKS5 mode where each connection creates its own WebSocket,
//! TUN mode uses a single persistent WebSocket connection that carries all IP packets.
//!
//! Protocol for /connect/v2 (multiplexed):
//! - Frame format: [flow_id: 4 bytes][payload_len: 2 bytes][encrypted_payload]
//! - flow_id = 0 for TUN data
//! - The entire frame (including header) is encrypted with Double Ratchet

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{debug, error, info, trace, warn};

use ed25519_dalek::Verifier;
use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::crypto::{DoubleRatchet, IdentityKey, X3DHPublicBundle};
use rvpn_core::protocol::{ControlMessage, HandshakeMessage, MultiplexedFrame, PayloadType};

use crate::config::ServerIdentityConfig;
use crate::identity_verification::{verify_server_identity, KnownHosts, VerificationResult};
use crate::tls_boring::TlsFingerprint;
use crate::websocket::{
    connect_websocket, split_websocket, Message, WebSocketReader, WebSocketWriter,
};

/// VPN Tunnel for TUN mode
///
/// Manages a persistent WebSocket connection with X3DH + Double Ratchet encryption.
/// All IP packets are sent through this single connection.
pub struct VpnTunnel {
    /// WebSocket writer for sending data
    ws_writer: WebSocketWriter,
    /// Channel receiver for raw multiplexed frames
    recv_mux_rx: mpsc::UnboundedReceiver<MultiplexedFrame>,
    /// Double Ratchet for encryption/decryption
    ratchet: Arc<Mutex<DoubleRatchet>>,
    /// Connection state - atomic so receive_loop can set false on exit
    connected: Arc<AtomicBool>,
    /// Server-assigned virtual IP (received via VirtualIp message)
    pub virtual_ip: Option<std::net::Ipv4Addr>,
    /// Server-assigned gateway IP (received via VirtualIp message)
    pub gateway_ip: Option<std::net::Ipv4Addr>,
    /// MTU from server
    pub mtu: u16,
}

impl VpnTunnel {
    /// Connect to the VPN server and establish a persistent tunnel
    ///
    /// # Arguments
    /// * `host` - Server hostname
    /// * `port` - Server port
    /// * `path` - WebSocket path
    /// * `fingerprint` - TLS fingerprint to use
    /// * `sni_hostname` - Optional SNI hostname override
    /// * `identity_key_file` - Path to client's identity key file
    /// * `prekey_bundle_file` - Path to server's prekey bundle file
    /// * `server_identity_config` - Server identity verification config
    ///
    /// # Returns
    /// Arc<RwLock<VpnTunnel>> which can be used to send/receive data
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        host: &str,
        port: u16,
        path: &str,
        fingerprint: TlsFingerprint,
        sni_hostname: Option<&str>,
        identity_key_file: &Path,
        prekey_bundle_file: Option<&Path>,
        server_identity_config: &ServerIdentityConfig,
    ) -> Result<Arc<RwLock<VpnTunnel>>> {
        info!("Connecting VPN tunnel to {}:{}{}", host, port, path);

        // Load identity key
        let identity_key = Arc::new(IdentityKey::load(identity_key_file)
            .map_err(|e| anyhow::anyhow!("Failed to load identity key: {}", e))?);
        debug!("Loaded client identity key");

        // Load server prekey bundle
        let server_bundle = if let Some(bundle_path) = prekey_bundle_file {
            let bundle_json = tokio::fs::read_to_string(bundle_path)
                .await
                .with_context(|| format!("Failed to read prekey bundle file: {:?}", bundle_path))?;
            let bundle: X3DHPublicBundle = serde_json::from_str(&bundle_json)
                .with_context(|| format!("Failed to parse prekey bundle from {:?}", bundle_path))?;
            bundle
        } else {
            return Err(anyhow::anyhow!(
                "Prekey bundle file is required for X3DH authentication"
            ));
        };
        debug!("Loaded server prekey bundle");

        // Step 1: Establish WebSocket connection
        let ws_stream = connect_websocket(host, port, path, fingerprint, sni_hostname)
            .await
            .context("Failed to establish WebSocket connection")?;

        info!("WebSocket connection established");

        // Step 2: Split the WebSocket into reader and writer
        let (mut ws_reader, ws_writer) = split_websocket(ws_stream);

        // Step 3: Perform X3DH handshake and initialize Double Ratchet
        let ratchet = Self::perform_handshake(
            &mut ws_reader,
            &ws_writer,
            &identity_key,
            &server_bundle,
            host,
            port,
            server_identity_config,
        )
        .await?;

        info!("VPN tunnel X3DH handshake completed successfully");

        // Create channels for receiving data from tunnel
        let (recv_mux_tx, recv_mux_rx) = mpsc::unbounded_channel::<MultiplexedFrame>();
        // Channel to receive VirtualIp assignment from receive_loop
        let (virtual_ip_tx, mut virtual_ip_rx) = mpsc::channel::<rvpn_core::protocol::VirtualIp>(1);

        let ratchet = Arc::new(Mutex::new(ratchet));
        let connected = Arc::new(AtomicBool::new(true));

        // Spawn background task to handle incoming messages
        let ratchet_clone = Arc::clone(&ratchet);
        let connected_clone = Arc::clone(&connected);
        tokio::spawn(async move {
            if let Err(e) =
                Self::receive_loop(ws_reader, recv_mux_tx, ratchet_clone, virtual_ip_tx, connected_clone).await
            {
                error!("Tunnel receive loop error: {}", e);
            }
        });

        // Wait for VirtualIp assignment from server (with timeout)
        let virtual_ip_assignment = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            virtual_ip_rx.recv()
        ).await;

        let (virtual_ip, gateway_ip, mtu) = match virtual_ip_assignment {
            Ok(Some(vip)) => {
                info!("Received VirtualIp assignment: ipv4={:?}, gateway={:?}, dns={:?}, mtu={}",
                      vip.ipv4, vip.gateway_ip, vip.dns_servers, vip.mtu);
                (vip.ipv4, vip.gateway_ip, vip.mtu)
            }
            Ok(None) => {
                warn!("VirtualIp channel closed without receiving assignment");
                (None, None, 1420) // Default MTU
            }
            Err(_) => {
                warn!("Timeout waiting for VirtualIp assignment from server");
                (None, None, 1420) // Default MTU
            }
        };

        let tunnel = VpnTunnel {
            ws_writer,
            recv_mux_rx,
            ratchet,
            connected,
            virtual_ip,
            gateway_ip,
            mtu,
        };

        Ok(Arc::new(RwLock::new(tunnel)))
    }

    /// Perform X3DH handshake with server
    async fn perform_handshake(
        ws_reader: &mut WebSocketReader,
        ws_writer: &WebSocketWriter,
        identity_key: &Arc<IdentityKey>,
        server_bundle: &X3DHPublicBundle,
        host: &str,
        port: u16,
        server_identity_config: &ServerIdentityConfig,
    ) -> Result<DoubleRatchet> {
        // Create X3DH initiator (generates its own ephemeral key)
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

        let hello_bytes =
            serde_json::to_vec(&hello).context("Failed to serialize Hello message")?;
        ws_writer
            .send(Message::Binary(hello_bytes))
            .context("Failed to send Hello message")?;

        debug!("Sent X3DH Hello message");

        // Receive ServerHello response
        let response = ws_reader
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("WebSocket closed during handshake"))?;

        match response {
            Message::Binary(data) => {
                let server_hello: HandshakeMessage =
                    serde_json::from_slice(&data).context("Failed to parse ServerHello message")?;

                match server_hello {
                    HandshakeMessage::ServerHello {
                        ephemeral_key: _server_ephemeral,
                        identity_key: server_identity_key,
                        signed_prekey: server_signed_prekey,
                        prekey_signature: server_prekey_signature,
                    } => {
                        debug!("Received ServerHello with ephemeral key");

                        // Build a bundle from the SERVER'S ACTUAL KEYS (not the pre-loaded bundle)
                        // The ServerHello sends identity_key (Ed25519, 32 bytes) and signed_prekey (X25519, 32 bytes)
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

                        // Verify the Ed25519 signature on signed_prekey using the server's identity_key
                        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&server_identity_key)
                            .map_err(|e| anyhow::anyhow!("Invalid server identity key: {}", e))?;
                        let signature = ed25519_dalek::Signature::from_bytes(&prekey_signature);
                        verifying_key.verify(&server_signed_prekey, &signature)
                            .map_err(|e| anyhow::anyhow!("Invalid prekey signature: {}", e))?;
                        debug!("Server prekey signature verified");

                        // For the X3DH key agreement, we need the server's identity_x25519_key which is
                        // derived from the server's Ed25519 *private* key. We can't derive it from the
                        // Ed25519 *public* key sent in ServerHello, so use the pre-loaded bundle's value
                        // (which was generated by the server and published in the prekey bundle).
                        let server_identity_x25519_key = server_bundle.identity_x25519_key;

                        // Bundle for X3DH key agreement — uses pre-loaded identity_x25519_key
                        // but the actual signed_prekey from the ServerHello (signature-verified above)
                        let server_bundle_from_hello = X3DHPublicBundle {
                            identity_key: server_identity_key,
                            identity_x25519_key: server_identity_x25519_key,
                            signed_prekey: server_signed_prekey,
                            prekey_signature,
                            one_time_prekey: None,
                        };

                        // Verify server identity if configured
                        let server_addr = format!("{}:{}", host, port);

                        // Load known hosts
                        let known_hosts =
                            KnownHosts::load(&server_identity_config.known_hosts_file)
                                .unwrap_or_default();

                        // Bundle for identity verification — uses the Ed25519 key from ServerHello
                        // so the fingerprint matches what the operator sees
                        let received_bundle = X3DHPublicBundle {
                            identity_key: server_identity_key,
                            identity_x25519_key: server_bundle.identity_x25519_key,
                            signed_prekey: server_signed_prekey,
                            prekey_signature,
                            one_time_prekey: None,
                        };

                        // Verify the server identity
                        let (result, should_proceed) = verify_server_identity(
                            &server_addr,
                            &received_bundle,
                            &known_hosts,
                            server_identity_config.fingerprint.as_deref(),
                            server_identity_config.trust_on_first_use,
                            server_identity_config.strict_mode,
                        );

                        match result {
                            VerificationResult::Verified => {
                                info!("Server identity verified");
                            }
                            VerificationResult::New => {
                                info!("New server identity, accepting (TOFU mode)");
                                // Save to known hosts if TOFU is enabled
                                if server_identity_config.trust_on_first_use {
                                    let mut hosts = known_hosts;
                                    let fingerprint =
                                        hex::encode(&received_bundle.identity_key[..16]);
                                    hosts.add_server(server_addr.clone(), fingerprint);
                                    let _ = hosts.save(&server_identity_config.known_hosts_file);
                                }
                            }
                            VerificationResult::Mismatch { expected, got } => {
                                if server_identity_config.strict {
                                    return Err(anyhow::anyhow!(
                                        "Server identity mismatch! Expected {}, got {}. Connection rejected.",
                                        expected, got
                                    ));
                                } else {
                                    warn!("Server identity mismatch, but continuing (non-strict mode)");
                                }
                            }
                        }

                        if !should_proceed && server_identity_config.strict {
                            return Err(anyhow::anyhow!("Server identity verification failed"));
                        }

                        // Complete X3DH agreement using the SERVER'S ACTUAL bundle
                        let (shared_secret, _x3dh_material) = initiator
                            .agree(&server_bundle_from_hello)
                            .context("X3DH key agreement failed")?;

                        debug!("X3DH shared secret derived successfully");

                        // Initialize Double Ratchet as Alice (initiator)
                        // In X3DH, the server (Bob) doesn't generate an ephemeral key.
                        // The server_ephemeral field is empty - init_alice doesn't use this parameter.
                        let ratchet = DoubleRatchet::init_alice(shared_secret, [0u8; 32]);

                        info!("Double Ratchet initialized as Alice (initiator)");

                        Ok(ratchet)
                    }
                    _ => Err(anyhow::anyhow!(
                        "Unexpected handshake message type from server"
                    )),
                }
            }
            _ => Err(anyhow::anyhow!("Expected binary message during handshake")),
        }
    }

    /// Background loop to receive and decrypt messages from WebSocket
    ///
    /// Multiplexed protocol (/api/v1/ws/tun):
    /// - Parses MultiplexedFrame from decrypted plaintext
    /// - Sends frames to recv_mux_tx for consumption by TUN device
    async fn receive_loop(
        mut ws_reader: WebSocketReader,
        recv_mux_tx: mpsc::UnboundedSender<MultiplexedFrame>,
        ratchet: Arc<Mutex<DoubleRatchet>>,
        virtual_ip_tx: mpsc::Sender<rvpn_core::protocol::VirtualIp>,
        connected: Arc<AtomicBool>,
    ) -> Result<()> {
        use rvpn_core::crypto::ratchet::RatchetMessage;

        info!("Starting tunnel receive loop (multiplexed mode)");

        // Track if we've sent the VirtualIp (only need to send first one)
        let mut virtual_ip_sent = false;

        loop {
            match ws_reader.recv().await {
                Some(Message::Binary(data)) => {
                    // Deserialize RatchetMessage (server sends bincode format)
                    let message: RatchetMessage = match bincode::deserialize(&data) {
                        Ok(m) => m,
                        Err(e) => {
                            warn!("Failed to deserialize RatchetMessage: {}", e);
                            continue;
                        }
                    };

                    // Check payload_type to determine how to handle the message
                    let payload_type = message.header.payload_type;

                    // Determine AAD based on payload_type from header
                    let aad = match payload_type {
                        0x01 => [0x01], // Data
                        0x0D => [0x0D], // VirtualIp
                        _ => [0x01],    // Default to Data
                    };

                    // Decrypt with ratchet using payload-type-specific AAD
                    let plaintext = {
                        let mut ratchet_guard = ratchet.lock().await;
                        match ratchet_guard.decrypt(&message, &aad) {
                            Ok(pt) => pt,
                            Err(e) => {
                                warn!("Decryption failed: {:?}", e);
                                continue;
                            }
                        }
                    };

                    // Handle based on payload type
                    if payload_type == 0x0D {
                        // VirtualIp assignment message
                        // Server sends padded VirtualIp JSON, need to unpad first
                        match rvpn_core::protocol::padding::unpad_packet(&plaintext) {
                            Ok(unpadded) => {
                                match serde_json::from_slice::<rvpn_core::protocol::VirtualIp>(&unpadded) {
                                    Ok(virtual_ip) => {
                                        info!("Received VirtualIp assignment: ipv4={:?}, dns={:?}, mtu={}",
                                              virtual_ip.ipv4, virtual_ip.dns_servers, virtual_ip.mtu);
                                        // Send to the connect function via channel (only first time)
                                        if !virtual_ip_sent {
                                            if let Err(e) = virtual_ip_tx.send(virtual_ip).await {
                                                warn!("Failed to send VirtualIp to connect: {}", e);
                                            } else {
                                                virtual_ip_sent = true;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to deserialize VirtualIp: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to unpad VirtualIp frame: {}", e);
                            }
                        }
                        continue;
                    }

                    // Default: Data payload (0x01)
                    // Unpad the decrypted data
                    let data = match rvpn_core::protocol::padding::unpad_packet(&plaintext) {
                        Ok(data) => data,
                        Err(e) => {
                            warn!("Failed to unpad data frame: {}", e);
                            continue;
                        }
                    };

                    // Parse the multiplexed frame
                    let frame = match MultiplexedFrame::decode(&data) {
                        Ok(frame) => frame,
                        Err(e) => {
                            warn!("Failed to decode multiplexed frame: {}", e);
                            continue;
                        }
                    };

                    // Send frame to TUN device
                    if let Err(e) = recv_mux_tx.send(frame) {
                        warn!("Failed to send frame to TUN device: {}", e);
                        break;
                    }
                }
                Some(Message::Close(_)) => {
                    info!("WebSocket closed by server");
                    connected.store(false, Ordering::SeqCst);
                    break;
                }
                None => {
                    // Channel closed - this happens when the websocket reader task exited
                    // (either due to error or because sender was dropped)
                    info!("WebSocket channel closed - receive loop ending");
                    connected.store(false, Ordering::SeqCst);
                    break;
                }
                _ => {
                    // Ignore other message types (Ping, Pong, Text, etc.)
                    continue;
                }
            }
        }

        info!("Tunnel receive loop ended");
        Ok(())
    }

    /// Send data through the tunnel with specified payload type
    ///
    /// Uses multiplexed framing for /connect/v2:
    /// - Frame format: [flow_id: 4 bytes][payload_len: 2 bytes][payload]
    /// - flow_id = 0 for TUN data
    /// - Entire frame is encrypted with Double Ratchet using AAD = 0x01
    ///
    /// Note: The payload_type parameter determines flow_id:
    /// - KeepAlive (Ping): flow_id=0 (ControlMessage, server expects it)
    /// - Other data: flow_id=1 (DataPayload, server auto-creates flow)
    pub async fn send_with_payload_type(
        &mut self,
        data: &[u8],
        payload_type: PayloadType,
    ) -> Result<()> {
        // flow_id=0 is reserved for ControlMessages (Ping, CreateFlow, etc.)
        // Data packets use flow_id=1 so server routes them to data handler
        const CONTROL_FLOW_ID: u32 = 0;
        const DATA_FLOW_ID: u32 = 1;

        let (flow_id, payload) = if payload_type == PayloadType::KeepAlive {
            // Server expects ControlMessage::Ping on flow_id=0
            let ping = ControlMessage::Ping {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
            };
            let serialized = bincode::serialize(&ping).context("Failed to serialize Ping")?;
            (CONTROL_FLOW_ID, serialized)
        } else {
            (DATA_FLOW_ID, data.to_vec())
        };

        let frame = MultiplexedFrame::new_data(flow_id, payload);
        self.send_multiplexed_frame(frame).await
    }

    /// Send a raw multiplexed frame through the tunnel
    pub async fn send_multiplexed_frame(&mut self, frame: MultiplexedFrame) -> Result<()> {
        use rvpn_core::crypto::ratchet::RatchetMessage;

        trace!(
            "SEND_MUX: flow_id={}, payload_len={}",
            frame.flow_id,
            frame.payload.len()
        );

        let encoded = frame
            .encode()
            .map_err(|e| anyhow::anyhow!("Failed to encode multiplexed frame: {}", e))?;

        // Pad to 1KB boundary (must match server's unpad_packet)
        let padded = rvpn_core::protocol::padding::pad_packet(encoded.as_ref())
            .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;

        let message: RatchetMessage = {
            let mut ratchet_guard = self.ratchet.lock().await;
            ratchet_guard
                .encrypt(padded.as_ref(), &[0x01])
                .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?
        };

        let encrypted = message
            .to_bytes()
            .context("Failed to serialize RatchetMessage")?;

        self.ws_writer
            .send(Message::Binary(encrypted))
            .context("Failed to send through WebSocket")?;

        Ok(())
    }

    /// Receive the next raw multiplexed frame
    pub async fn recv_multiplexed_frame(&mut self) -> Result<MultiplexedFrame> {
        match self.recv_mux_rx.recv().await {
            Some(frame) => Ok(frame),
            None => Err(anyhow::anyhow!("Multiplexed frame receiver closed")),
        }
    }

    /// Send a raw IP packet through the tunnel (for TUN mode)
    ///
    /// This method wraps the raw IP packet in a MultiplexedFrame with flow_id=1
    /// and sends it through the encrypted tunnel.
    #[allow(dead_code)]
    pub async fn send_raw_packet(&mut self, packet: &[u8]) -> Result<()> {
        let frame = MultiplexedFrame::new_data(1, packet.to_vec());
        self.send_multiplexed_frame(frame).await
    }

    /// Receive a raw IP packet from the tunnel (for TUN mode)
    ///
    /// This method receives a MultiplexedFrame and returns the raw payload.
    /// For TUN mode, expects flow_id=1 containing raw IP packets.
    #[allow(dead_code)]
    pub async fn recv_raw_packet(&mut self) -> Result<Vec<u8>> {
        let frame = self.recv_multiplexed_frame().await?;
        Ok(frame.payload.to_vec())
    }

    /// Check if tunnel is connected
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Check if the WebSocket writer channel has been closed.
    /// This detects half-open connections where the writer task exited
    /// (e.g., due to a broken pipe) but the reader is still blocked.
    pub fn is_writer_closed(&self) -> bool {
        self.ws_writer.is_closed()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_vpn_tunnel_creation() {
        // This is a placeholder test
        // Real tests would require a mock server
    }
}
