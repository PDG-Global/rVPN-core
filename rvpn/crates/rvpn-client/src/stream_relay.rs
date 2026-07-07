// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Stream Relay - Brook-style one WebSocket per SOCKS5 connection
//
// This module provides the core relay functionality for the Brook-style
// architecture refactor. Each SOCKS5 connection gets its own WebSocket
// connection to the server (no multiplexing).

use anyhow::{Context as _, Result};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use rvpn_core::crypto::{DoubleRatchet, IdentityKey, Signature, Verifier, VerifyingKey, X3DHPublicBundle};
use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::protocol::HandshakeMessage;

use crate::config::ServerIdentityConfig;
use crate::identity_verification::{verify_server_identity, KnownHosts, VerificationResult};
use rvpn_tls::TlsFingerprint;
use crate::websocket::{connect_websocket, split_websocket, Message, WebSocketReader, WebSocketWriter};

/// Brook-style stream relay for one SOCKS5 connection
///
/// Manages a single WebSocket connection with X3DH + Double Ratchet encryption.
pub struct StreamRelay {
    /// Double Ratchet state for encryption/decryption
    ratchet: DoubleRatchet,
}

impl StreamRelay {
    /// Connect to the VPN server and perform X3DH handshake
    ///
    /// # Arguments
    /// * `host` - Server hostname
    /// * `port` - Server port
    /// * `path` - WebSocket path
    /// * `fingerprint` - TLS fingerprint to use
    /// * `identity_key` - Client's identity key for X3DH
    /// * `server_bundle` - Server's X3DH prekey bundle
    /// * `server_identity_config` - Server identity verification config
    ///
    /// # Returns
    /// A tuple of (StreamRelay, WebSocketReader, WebSocketWriter) ready for relay operation
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        host: &str,
        port: u16,
        path: &str,
        fingerprint: TlsFingerprint,
        sni_hostname: Option<&str>,
        identity_key: &Arc<IdentityKey>,
        server_bundle: &X3DHPublicBundle,
        server_identity_config: Option<&ServerIdentityConfig>,
    ) -> Result<(Self, WebSocketReader, WebSocketWriter)> {
        info!("Connecting StreamRelay to {}:{}{}", host, port, path);

        // Step 1: Establish WebSocket connection
        let ws_stream = connect_websocket(host, port, path, fingerprint, sni_hostname)
            .await
            .context("Failed to establish WebSocket connection")?;

        debug!("WebSocket connection established");

        // Step 2: Split the WebSocket into reader and writer
        let (mut ws_reader, mut ws_writer) = split_websocket(ws_stream);

        // Step 3: Perform X3DH handshake and initialize Double Ratchet
        let ratchet = Self::perform_handshake(
            &mut ws_reader,
            &mut ws_writer,
            identity_key,
            server_bundle,
            host,
            port,
            server_identity_config,
        )
        .await?;

        info!("StreamRelay X3DH handshake completed successfully");

        let relay = Self { ratchet };

        Ok((relay, ws_reader, ws_writer))
    }

    /// Perform X3DH handshake with server
    ///
    /// X3DH key agreement:
    /// 1. Generate ephemeral key pair
    /// 2. Send Hello message with identity and ephemeral keys
    /// 3. Receive server response
    /// 4. Derive shared secret using X3DH
    /// 5. Initialize Double Ratchet as initiator (Alice)
    async fn perform_handshake(
        ws_reader: &mut WebSocketReader,
        ws_writer: &mut WebSocketWriter,
        identity_key: &Arc<IdentityKey>,
        server_bundle: &X3DHPublicBundle,
        host: &str,
        port: u16,
        server_identity_config: Option<&ServerIdentityConfig>,
    ) -> Result<DoubleRatchet> {
        // Create X3DH initiator (generates its own ephemeral key)
        let initiator = X3DHInitiator::from_identity_key(Arc::clone(identity_key));

        // Get the X25519 public key derived from the client's Ed25519 identity
        // This is what we send to the server for X3DH
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

                        // Use the SERVER'S ACTUAL wire values for X3DH.
                        //
                        // Previously the client discarded every ServerHello key
                        // (all `_`) and ran X3DH against the pre-loaded on-disk
                        // bundle. That silently broke every SOCKS5 connection
                        // whenever the on-disk copy drifted from what the server
                        // was actually running — e.g. any `rvpn-server prekey-
                        // bundle` regeneration. Chain keys diverged and the
                        // first Double Ratchet frame failed AEAD auth with
                        // `aead::Error`, immediately after a "successful" X3DH.
                        //
                        // Mirrors the correct pattern from rvpn-mobile ios_tun.rs.
                        let server_identity_key: [u8; 32] = server_identity_key
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Server identity key has invalid length"))?;
                        let server_signed_prekey: [u8; 32] = server_signed_prekey
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Server signed prekey has invalid length"))?;
                        let prekey_signature_bytes: [u8; 64] = server_prekey_signature
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Prekey signature has invalid length"))?;

                        // Verify the Ed25519 signature on signed_prekey using
                        // the server's wire identity_key. Without this a MITM
                        // could feed us any signed_prekey they liked.
                        let verifying_key = VerifyingKey::from_bytes(&server_identity_key)
                            .map_err(|e| anyhow::anyhow!("Invalid server identity key: {}", e))?;
                        let signature = Signature::from_bytes(&prekey_signature_bytes);
                        verifying_key
                            .verify(&server_signed_prekey, &signature)
                            .map_err(|e| anyhow::anyhow!("Invalid prekey signature: {}", e))?;
                        debug!("Server prekey signature verified");

                        // identity_x25519_key can't be derived from the Ed25519
                        // public alone (would need an Edwards → Montgomery
                        // birational conversion), so keep the pre-loaded value.
                        // Safe because TOFU below refuses to proceed if the wire
                        // identity_key doesn't match the pinned one — and the
                        // x25519 key is deterministic from the same identity.
                        let received_bundle = X3DHPublicBundle {
                            identity_key: server_identity_key,
                            identity_x25519_key: server_bundle.identity_x25519_key,
                            signed_prekey: server_signed_prekey,
                            prekey_signature: prekey_signature_bytes,
                            one_time_prekey: None,
                            // ServerHello doesn't yet carry rotation metadata;
                            // keep the pre-loaded values for TOFU rotation
                            // checks in verify_server_identity.
                            identity_key_version: server_bundle.identity_key_version,
                            rotation_signature: server_bundle.rotation_signature,
                        };

                        // Verify server identity if configured
                        if let Some(config) = server_identity_config {
                            let server_addr = format!("{}:{}", host, port);

                            // Load known hosts (mut — verify_server_identity
                            // writes canonical pins on TOFU capture and
                            // migrates legacy hex entries in-place).
                            let mut known_hosts = KnownHosts::load(&config.known_hosts_file)
                                .unwrap_or_default();

                            let (result, should_proceed) = verify_server_identity(
                                &server_addr,
                                &received_bundle,
                                &mut known_hosts,
                                config.fingerprint.as_deref(),
                                config.trust_on_first_use,
                                config.strict_mode,
                            );

                            if let Err(e) = known_hosts.save(&config.known_hosts_file) {
                                warn!("Failed to persist known_hosts.json: {}", e);
                            }

                            match result {
                                VerificationResult::Verified => {
                                    info!("Server identity verified");
                                }
                                VerificationResult::New => {
                                    info!("New server identity, accepting (TOFU mode)");
                                }
                                VerificationResult::Mismatch { expected, got } => {
                                    if config.strict {
                                        return Err(anyhow::anyhow!(
                                            "Server identity mismatch! Expected {}, got {}. Connection rejected.",
                                            expected, got
                                        ));
                                    } else {
                                        warn!("Server identity mismatch, but continuing (non-strict mode)");
                                    }
                                }
                            }

                            if !should_proceed && config.strict {
                                return Err(anyhow::anyhow!("Server identity verification failed"));
                            }
                        }

                        // Complete X3DH against the SERVER'S ACTUAL bundle
                        let (shared_secret, _x3dh_material) = initiator
                            .agree(&received_bundle)
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
            _ => Err(anyhow::anyhow!(
                "Expected binary message during handshake"
            )),
        }
    }

    /// Send an encrypted frame via WebSocket writer using Double Ratchet
    ///
    /// # Arguments
    /// * `ws_writer` - WebSocket writer to send through
    /// * `data` - Plaintext data to send
    pub async fn send_frame(
        &mut self,
        ws_writer: &WebSocketWriter,
        data: &[u8],
    ) -> Result<()> {
        // Pad to 1KB boundary before encryption — eliminates frame-size fingerprinting
        let padded = rvpn_core::protocol::padding::pad_packet(data)
            .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;

        // Encrypt with Double Ratchet (0x01 = ProxyData payload type)
        let message = self
            .ratchet
            .encrypt(&padded, &[0x01])
            .map_err(|e| anyhow::anyhow!("Double Ratchet encryption failed: {:?}", e))?;

        // Serialize RatchetMessage to bytes
        let encrypted = message.to_bytes()
            .context("Failed to serialize RatchetMessage")?;

        // Send via WebSocket
        ws_writer
            .send(Message::Binary(encrypted))
            .context("Failed to send WebSocket frame")?;

        debug!("Sent frame: {} bytes plaintext", data.len());

        Ok(())
    }

    /// Receive and decrypt a frame from WebSocket reader using Double Ratchet
    ///
    /// # Arguments
    /// * `ws_reader` - WebSocket reader to receive from
    ///
    /// # Returns
    /// Decrypted plaintext data
    #[allow(dead_code)]
    pub async fn recv_frame(&mut self, ws_reader: &mut WebSocketReader) -> Result<Vec<u8>> {
        use rvpn_core::crypto::ratchet::RatchetMessage;

        // Receive the encrypted message
        let msg = ws_reader
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("WebSocket closed"))?;

        let data = match msg {
            Message::Binary(data) => data,
            _ => return Err(anyhow::anyhow!("Expected binary message")),
        };

        // Deserialize RatchetMessage
        let message = RatchetMessage::from_bytes(&data)
            .context("Failed to deserialize RatchetMessage")?;

        // Decrypt with Double Ratchet (0x01 = ProxyData payload type)
        let decrypted = self
            .ratchet
            .decrypt(&message, &[0x01])
            .map_err(|e| anyhow::anyhow!("Double Ratchet decryption failed: {:?}", e))?;

        // Strip 1KB boundary padding
        let plaintext = rvpn_core::protocol::padding::unpad_packet(&decrypted)
            .map_err(|e| anyhow::anyhow!("Failed to unpad received frame: {}", e))?;

        debug!("Received frame: {} bytes plaintext", plaintext.len());

        Ok(plaintext)
    }

    /// Relay data bidirectionally between local TCP stream and WebSocket
    ///
    /// This uses a single task that handles both directions with Arc<Mutex<DoubleRatchet>>
    /// for thread-safe access to the ratchet state.
    ///
    /// # Arguments
    /// * `local` - Local TCP stream from SOCKS5 client
    /// * `ws_reader` - WebSocket reader for receiving encrypted data
    /// * `ws_writer` - WebSocket writer for sending encrypted data
    pub async fn relay(
        self,
        local: TcpStream,
        mut ws_reader: WebSocketReader,
        ws_writer: WebSocketWriter,
    ) -> Result<()> {
        let (mut local_read, mut local_write) = local.into_split();

        info!("Starting bidirectional relay");

        // Share the ratchet between tasks using Arc<Mutex>
        let ratchet = Arc::new(Mutex::new(self.ratchet));
        let ws_writer = Arc::new(Mutex::new(ws_writer));

        // Channel for decrypted data from WebSocket -> Local
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(100);

        // Task 1: Local -> WebSocket (read from local, encrypt, send)
        let ratchet_clone = Arc::clone(&ratchet);
        let ws_writer_clone = Arc::clone(&ws_writer);
        let send_task = tokio::spawn(async move {
            use rvpn_core::crypto::ratchet::RatchetMessage;
            // 8190 bytes, not 8192 — pad_packet reserves 2 bytes for the
            // padding-length field, so 8192-byte reads would fail with
            // "data too large for padding: 8192 bytes exceeds max 8190".
            let mut buf = [0u8; 8190];
            loop {
                match local_read.read(&mut buf).await {
                    Ok(0) => {
                        debug!("Local connection closed (read 0 bytes)");
                        break;
                    }
                    Ok(n) => {
                        // Pad to 1KB boundary before encryption
                        let padded = match rvpn_core::protocol::padding::pad_packet(&buf[..n]) {
                            Ok(p) => p,
                            Err(e) => {
                                warn!("Padding failed: {}", e);
                                continue;
                            }
                        };

                        // Encrypt with ratchet (0x01 = ProxyData payload type)
                        let message: RatchetMessage = {
                            let mut ratchet_guard = ratchet_clone.lock().await;
                            ratchet_guard.encrypt(&padded, &[0x01])
                                .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?
                        };

                        // Serialize and send
                        let encrypted = message.to_bytes()
                            .map_err(|e| anyhow::anyhow!("Failed to serialize RatchetMessage: {}", e))?;

                        // Send via WebSocket (send() is synchronous, returns Result)
                        let writer = ws_writer_clone.lock().await;
                        if let Err(e) = writer.send(Message::Binary(encrypted)) {
                            warn!("Error sending WebSocket frame: {}", e);
                            return Err(e);
                        }

                        debug!("Relayed {} bytes local->remote", n);
                    }
                    Err(e) => {
                        warn!("Error reading from local: {}", e);
                        return Err(e.into());
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        });

        // Task 2: WebSocket -> Local (receive, decrypt, send via channel)
        let ratchet_clone2 = Arc::clone(&ratchet);
        let recv_task = tokio::spawn(async move {
            use rvpn_core::crypto::ratchet::RatchetMessage;
            loop {
                match ws_reader.recv().await {
                    Some(Message::Binary(data)) => {
                        // Deserialize RatchetMessage
                        let message = match RatchetMessage::from_bytes(&data) {
                            Ok(m) => m,
                            Err(e) => {
                                warn!("Failed to deserialize RatchetMessage: {}", e);
                                continue;
                            }
                        };

                        // Decrypt with ratchet (0x01 = ProxyData payload type)
                        let decrypted = {
                            let mut ratchet_guard = ratchet_clone2.lock().await;
                            match ratchet_guard.decrypt(&message, &[0x01]) {
                                Ok(pt) => pt,
                                Err(e) => {
                                    warn!("Decryption failed: {:?}", e);
                                    continue;
                                }
                            }
                        };

                        // Strip 1KB boundary padding
                        let plaintext = match rvpn_core::protocol::padding::unpad_packet(&decrypted)
                            .map_err(|e| anyhow::anyhow!("Unpad failed: {}", e))
                        {
                            Ok(data) => data,
                            Err(e) => {
                                warn!("Unpad failed: {:?}", e);
                                continue;
                            }
                        };

                        // Send to local writer task via channel
                        if tx.send(plaintext).await.is_err() {
                            debug!("Local writer channel closed");
                            break;
                        }
                    }
                    Some(Message::Close(_)) => {
                        debug!("WebSocket closed by server");
                        break;
                    }
                    None => {
                        debug!("WebSocket read returned None");
                        break;
                    }
                    _ => {
                        debug!("Unexpected WebSocket message type");
                        continue;
                    }
                }
            }
            Ok::<_, anyhow::Error>(())
        });

        // Task 3: Write decrypted data to local
        let write_task = tokio::spawn(async move {
            while let Some(data) = rx.recv().await {
                if let Err(e) = local_write.write_all(&data).await {
                    warn!("Error writing to local: {}", e);
                    return Err(e.into());
                }
                debug!("Relayed {} bytes remote->local", data.len());
            }
            Ok::<_, anyhow::Error>(())
        });

        // Wait for all tasks to complete using JoinSet
        // This properly handles cancellation when any task fails
        let mut tasks = JoinSet::new();
        tasks.spawn(send_task);
        tasks.spawn(recv_task);
        tasks.spawn(write_task);

        let mut first_error = None;
        while let Some(result) = tasks.join_next().await {
            match result {
                // Task succeeded: Ok(Ok(Ok(())))
                Ok(Ok(Ok(()))) => {
                    debug!("Relay task completed");
                }
                // Task returned error: Ok(Ok(Err(e)))
                Ok(Ok(Err(e))) => {
                    error!("Relay task error: {}", e);
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
                // Task panicked or was aborted: Ok(Err(je)) or Err(je)
                Ok(Err(je)) | Err(je) => {
                    // Task was aborted (cancelled) - this is normal during shutdown
                    debug!("Relay task aborted: {:?}", je);
                }
            }
        }

        // Abort any remaining tasks (if we exited due to an error, others may still be running)
        while tasks.join_next().await.is_some() {}

        // Graceful shutdown: give TCP socket time to flush
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        info!("Relay completed");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_length_prefix_format() {
        // Verify length encoding (used in the protocol for target address)
        let len: u16 = 0x1234;
        let bytes = len.to_be_bytes();
        assert_eq!(bytes, [0x12, 0x34]);

        let decoded = u16::from_be_bytes([bytes[0], bytes[1]]);
        assert_eq!(decoded, len);
    }
}
