// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// SOCKS5 Multiplexed Tunnel — single WebSocket, multiple TCP flows
//
// All SOCKS5 connections share one WebSocket connection to the server.
// Each SOCKS5 CONNECT creates a logical flow via CreateFlow/CloseFlow
// control messages. Data flows through multiplexed frames (flow_id + payload)
// encrypted with a single shared DoubleRatchet.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Weak};

use anyhow::{Context as _, Result};
use rand::{Rng, SeedableRng};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

use rvpn_core::crypto::{DoubleRatchet, IdentityKey, X3DHPublicBundle};
use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::protocol::{ControlMessage, HandshakeMessage, MultiplexedFrame, PayloadType};

use crate::config::ServerIdentityConfig;
use crate::identity_verification::{verify_server_identity, KnownHosts};
use crate::tls_boring::TlsFingerprint;
use crate::websocket::{
    connect_websocket, split_websocket, Message, WebSocketReader, WebSocketWriter,
};

// ── Internal types ──────────────────────────────────────────────────

/// Pending flow creation response
struct PendingFlow {
    tx: tokio::sync::oneshot::Sender<Result<()>>,
}

/// Server-side state for an active flow
struct FlowState {
    /// Sender for WS -> local data (feeds the Socks5Flow receiver)
    ws_to_local_tx: mpsc::Sender<Vec<u8>>,
}

// ── Public types ────────────────────────────────────────────────────

/// Shared multiplexed tunnel for all SOCKS5 flows.
pub struct Socks5Tunnel {
    ws_writer: WebSocketWriter,
    ratchet: Arc<Mutex<DoubleRatchet>>,
    next_flow_id: AtomicU32,
    pending_flows: Mutex<HashMap<u32, PendingFlow>>,
    flow_states: Mutex<HashMap<u32, FlowState>>,
    /// Set to false when the receive loop exits — signals callers to reconnect
    alive: AtomicBool,
    /// When this tunnel was created (for diagnostics)
    created_at: std::time::Instant,
}

/// Handle for a single multiplexed SOCKS5 flow.
pub struct Socks5Flow {
    /// Flow identifier
    pub flow_id: u32,
    /// Local TCP -> WS sender (taken out for relay, None after)
    local_to_ws_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// WS -> local TCP receiver (taken out for relay, None after)
    ws_to_local_rx: Option<mpsc::Receiver<Vec<u8>>>,
    tunnel: Weak<Socks5Tunnel>,
}

impl Socks5Flow {
    /// Take the send channel, consuming this part of the flow
    pub fn take_send(&mut self) -> Option<mpsc::Sender<Vec<u8>>> {
        self.local_to_ws_tx.take()
    }

    /// Take the receive channel, consuming this part of the flow
    pub fn take_recv(&mut self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.ws_to_local_rx.take()
    }
}

impl Socks5Flow {
    #[allow(dead_code)]
    pub async fn send_data(&self, data: &[u8]) -> Result<()> {
        let tx = self.local_to_ws_tx.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Flow send channel already taken"))?;
        tx.send(data.to_vec()).await
            .map_err(|_| anyhow::anyhow!("Flow send channel closed"))
    }

    #[allow(dead_code)]
    pub async fn recv_data(&mut self) -> Option<Vec<u8>> {
        self.ws_to_local_rx.as_mut()?.recv().await
    }
}

impl Drop for Socks5Flow {
    fn drop(&mut self) {
        let Some(tunnel) = self.tunnel.upgrade() else { return };
        let ws_writer = tunnel.ws_writer.clone();
        let ratchet = Arc::clone(&tunnel.ratchet);
        let flow_id = self.flow_id;
        tokio::spawn(async move {
            if let Err(e) = send_close_frame(&ws_writer, &ratchet, flow_id).await {
                debug!("Failed to send CloseFlow for flow {}: {}", flow_id, e);
            }
        });
    }
}

async fn send_close_frame(
    ws_writer: &WebSocketWriter,
    ratchet: &Mutex<DoubleRatchet>,
    flow_id: u32,
) -> Result<()> {
    let msg = ControlMessage::CloseFlow { flow_id };
    // Control messages MUST be sent on flow_id=0 (CONTROL_FLOW_ID)
    // with bincode-serialized payload
    let frame = MultiplexedFrame::new_control(&msg)
        .context("Failed to serialize CloseFlow control message")?;
    let encoded = frame.encode()?;
    let padded = rvpn_core::protocol::padding::pad_packet(&encoded)
        .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;
    let message = {
        let mut guard = ratchet.lock().await;
        guard.encrypt(&padded, &[PayloadType::Admin as u8])?
    };
    let encrypted = message.to_bytes()?;
    ws_writer.send(Message::Binary(encrypted))?;
    debug!("Sent CloseFlow for flow {}", flow_id);
    Ok(())
}

// ── Socks5Tunnel ────────────────────────────────────────────────────

impl Socks5Tunnel {
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
    ) -> Result<Arc<Self>> {
        info!("Connecting SOCKS5 multiplexed tunnel to {}:{}{}", host, port, path);

        debug!("WebSocket path for mux tunnel: {}", path);
        let ws_stream = connect_websocket(host, port, path, fingerprint, sni_hostname)
            .await
            .map_err(|e| {
                error!("MUX WebSocket connect failed: {}:{}", host, port);
                e
            })
            .context("Failed to establish multiplexed WebSocket connection")?;

        let (mut ws_reader, ws_writer) = split_websocket(ws_stream);

        let ratchet = Self::perform_handshake(
            &mut ws_reader,
            &ws_writer,
            identity_key,
            server_bundle,
            host,
            port,
            server_identity_config,
        )
        .await?;

        info!("SOCKS5 multiplexed tunnel X3DH handshake completed");

        let ratchet = Arc::new(Mutex::new(ratchet));

        let tunnel = Arc::new(Self {
            ws_writer,
            ratchet: Arc::clone(&ratchet),
            next_flow_id: AtomicU32::new(1),
            pending_flows: Mutex::new(HashMap::new()),
            flow_states: Mutex::new(HashMap::new()),
            alive: AtomicBool::new(true),
            created_at: std::time::Instant::now(),
        });

        // Background receive loop
        tokio::spawn({
            let tunnel = Arc::clone(&tunnel);
            async move {
                if let Err(e) = tunnel.receive_loop(ws_reader).await {
                    error!("SOCKS5 multiplexed tunnel receive loop ended: {}", e);
                }
                // Mark tunnel as dead so callers will reconnect
                tunnel.alive.store(false, Ordering::SeqCst);
                error!("SOCKS5 multiplexed tunnel marked as DEAD (age {:.1}s) — next flow will trigger reconnect",
                       tunnel.tunnel_age().as_secs_f64());

                // Fail all pending FlowCreated oneshots so waiting open_flow calls
                // return immediately instead of timing out after 10 seconds.
                let pending: HashMap<u32, PendingFlow> = {
                    let mut guard = tunnel.pending_flows.lock().await;
                    std::mem::take(&mut *guard)
                };
                let count = pending.len();
                for (flow_id, pending_flow) in pending {
                    let _ = pending_flow.tx.send(Err(anyhow::anyhow!(
                        "Mux tunnel disconnected while waiting for FlowCreated ACK for flow {}",
                        flow_id
                    )));
                }
                debug!("Cleared {} pending flow ACKs after tunnel disconnect", count);
            }
        });

        // Application-level keepalive — sends ControlMessage::Ping every ~5s
        // (jittered 3-7s). WebSocket-level pings may not be forwarded reliably
        // through reverse proxies (e.g. Caddy). Application-level pings travel
        // as regular encrypted data frames and are always proxied correctly.
        // The server responds with ControlMessage::Pong, which resets the
        // receive_loop's 21s timeout and keeps the tunnel alive.
        tokio::spawn({
            let tunnel = Arc::clone(&tunnel);
            async move {
                let mut rng = rand::rngs::StdRng::from_entropy();
                // Random initial delay to avoid burst at connection start
                tokio::time::sleep(std::time::Duration::from_millis(rng.gen_range(3000..=7000))).await;
                while tunnel.alive.load(Ordering::SeqCst) {
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let msg = ControlMessage::Ping { timestamp };
                    match MultiplexedFrame::new_control(&msg) {
                        Ok(frame) => {
                            if let Ok(encoded) = frame.encode() {
                                let padded = match rvpn_core::protocol::padding::pad_packet(&encoded) {
                                    Ok(p) => p,
                                    Err(e) => { debug!("Keepalive pad failed: {}", e); break; }
                                };
                                let encrypted = {
                                    let mut g = tunnel.ratchet.lock().await;
                                    g.encrypt(&padded, &[PayloadType::Admin as u8])
                                };
                                match encrypted {
                                    Ok(ciphertext) => {
                                        let _ = tunnel.ws_writer.send(Message::Binary(ciphertext.to_bytes().unwrap_or_default()));
                                    }
                                    Err(e) => {
                                        debug!("Keepalive encrypt failed: {}", e);
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            debug!("Keepalive frame creation failed: {}", e);
                            break;
                        }
                    }
                    // Jittered interval: 3-7s (nominal ~5s)
                    let jitter_ms = rng.gen_range(3000..=7000);
                    tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
                }
                debug!("Keepalive task ending");
            }
        });

        Ok(tunnel)
    }

    async fn perform_handshake(
        ws_reader: &mut WebSocketReader,
        ws_writer: &WebSocketWriter,
        identity_key: &Arc<IdentityKey>,
        server_bundle: &X3DHPublicBundle,
        host: &str,
        port: u16,
        server_identity_config: Option<&ServerIdentityConfig>,
    ) -> Result<DoubleRatchet> {
        let initiator = X3DHInitiator::from_identity_key(Arc::clone(identity_key));
        let identity_public = initiator.identity_key.x25519_public_key();
        let ephemeral_public = initiator.ephemeral_key.public_key.to_bytes();

        let hello = HandshakeMessage::Hello {
            version: rvpn_core::protocol::ProtocolVersion::CURRENT,
            auth_method: rvpn_core::protocol::AuthMethod::X3DH,
            ephemeral_key: Some(ephemeral_public.to_vec()),
            identity_key: Some(identity_public.to_vec()),
            session_token: None,
            connection_nonce: None,
        };
        ws_writer.send(Message::Binary(serde_json::to_vec(&hello)?))
            .context("Failed to send Hello")?;

        let response = ws_reader.recv().await
            .ok_or_else(|| anyhow::anyhow!("WebSocket closed during handshake"))?;

        let data = match response {
            Message::Binary(d) => d,
            Message::Close(_) => anyhow::bail!("WebSocket closed during handshake"),
            other => anyhow::bail!("Unexpected message during handshake: {:?}", other),
        };

        let server_hello: HandshakeMessage = serde_json::from_slice(&data)
            .context("Failed to parse ServerHello")?;

        match server_hello {
            HandshakeMessage::ServerHello {
                ephemeral_key: _,
                identity_key: server_identity_key,
                signed_prekey: server_signed_prekey,
                prekey_signature: server_prekey_signature,
            } => {
                let srv_id: [u8; 32] = server_identity_key.as_slice().try_into()
                    .map_err(|_| anyhow::anyhow!("Server identity key wrong length"))?;
                let srv_sp: [u8; 32] = server_signed_prekey.as_slice().try_into()
                    .map_err(|_| anyhow::anyhow!("Server signed prekey wrong length"))?;
                let sig: [u8; 64] = server_prekey_signature.as_slice().try_into()
                    .map_err(|_| anyhow::anyhow!("Prekey signature wrong length"))?;

                // Verify Ed25519 signature
                use ed25519_dalek::Verifier as _;
                let vk = ed25519_dalek::VerifyingKey::from_bytes(&srv_id)
                    .map_err(|e| anyhow::anyhow!("Invalid server identity key: {}", e))?;
                let signature = ed25519_dalek::Signature::from_bytes(&sig);
                vk.verify(&srv_sp, &signature)
                    .map_err(|e| anyhow::anyhow!("Invalid prekey signature: {}", e))?;

                // Use pre-loaded bundle's identity_x25519_key for X3DH
                let identity_x25519 = server_bundle.identity_x25519_key;

                let bundle = X3DHPublicBundle {
                    identity_key: srv_id,
                    identity_x25519_key: identity_x25519,
                    signed_prekey: srv_sp,
                    prekey_signature: sig,
                    one_time_prekey: None,
                };

                // Optional identity verification
                if let Some(cfg) = server_identity_config {
                    let addr = format!("{}:{}", host, port);
                    let known = KnownHosts::load(&cfg.known_hosts_file).unwrap_or_default();
                    let (_res, ok) = verify_server_identity(
                        &addr, &bundle, &known,
                        cfg.fingerprint.as_deref(),
                        cfg.trust_on_first_use,
                        cfg.strict_mode,
                    );
                    if !ok && cfg.strict_mode {
                        anyhow::bail!("Server identity verification failed");
                    }
                }

                let (shared, _) = initiator.agree(&bundle)
                    .context("X3DH key agreement failed")?;
                let ratchet = DoubleRatchet::init_alice(shared, [0u8; 32]);
                Ok(ratchet)
            }
            HandshakeMessage::Error { code, message } => {
                anyhow::bail!("Server rejected handshake: {} (code {})", message, code)
            }
            other => anyhow::bail!("Unexpected server response: {:?}", other),
        }
    }

    pub async fn open_flow(self: &Arc<Self>, target: &str, port: u16) -> Result<Socks5Flow> {
        // Check if the tunnel receive loop is still alive
        if !self.alive.load(Ordering::SeqCst) {
            anyhow::bail!("Mux tunnel receive loop is dead — reconnect required");
        }

        let flow_id = self.next_flow_id.fetch_add(1, Ordering::Relaxed);
        debug!("Opening flow {} to {}:{}", flow_id, target, port);

        // 0-RTT optimization: send CreateFlow and return immediately.
        // The server buffers data that arrives before the TCP connection to
        // the target is established, so the caller can start sending data
        // right away without waiting for FlowCreated ACK. This saves one
        // round-trip (~25-50ms to HK) per flow.
        //
        // Security: This is NOT TLS 0-RTT. The TLS handshake and X3DH key
        // exchange are already complete before any data flows. Replay
        // protection is provided by the Double Ratchet — each message has a
        // unique message_number, and the ratchet rejects messages with
        // number < current (see ratchet.rs:decrypt). Message keys are
        // consumed after use, so replays fail with "Message too old".
        //
        // Error handling: if the server sends FlowFailed, the receive_loop
        // will close the flow's channel, causing the relay to exit naturally.
        let (ack_tx, _ack_rx) = tokio::sync::oneshot::channel();
        {
            let mut pending = self.pending_flows.lock().await;
            pending.insert(flow_id, PendingFlow { tx: ack_tx });
        }

        self.send_create_flow(flow_id, target, port).await?;
        debug!("Flow {} CreateFlow sent (0-RTT mode — not waiting for ACK)", flow_id);

        let (local_to_ws_tx, local_to_ws_rx) = mpsc::channel::<Vec<u8>>(256);
        let (ws_to_local_tx, ws_to_local_rx) = mpsc::channel::<Vec<u8>>(256);

        {
            let mut states = self.flow_states.lock().await;
            states.insert(flow_id, FlowState { ws_to_local_tx });
        }

        let ws_writer = self.ws_writer.clone();
        let ratchet = Arc::clone(&self.ratchet);
        tokio::spawn(async move {
            if let Err(e) = Self::flow_to_ws_loop(flow_id, local_to_ws_rx, &ws_writer, &ratchet).await {
                debug!("Flow {} -> WS loop ended: {}", flow_id, e);
            }
        });

        Ok(Socks5Flow {
            flow_id,
            local_to_ws_tx: Some(local_to_ws_tx),
            ws_to_local_rx: Some(ws_to_local_rx),
            tunnel: Arc::downgrade(self),
        })
    }

    async fn send_create_flow(&self, flow_id: u32, target: &str, port: u16) -> Result<()> {
        let msg = ControlMessage::CreateFlow {
            flow_id,
            target: target.to_string(),
            port,
        };
        // Control messages MUST be sent on flow_id=0 (CONTROL_FLOW_ID)
        // with bincode-serialized payload
        let frame = MultiplexedFrame::new_control(&msg)
            .context("Failed to serialize CreateFlow control message")?;
        let encoded = frame.encode()?;
        let padded = rvpn_core::protocol::padding::pad_packet(&encoded)
            .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;
        let message = {
            let mut g = self.ratchet.lock().await;
            g.encrypt(&padded, &[PayloadType::Admin as u8])?
        };
        self.ws_writer.send(Message::Binary(message.to_bytes()?))?;
        debug!("Sent CreateFlow {} → {}:{}", flow_id, target, port);
        Ok(())
    }

    pub async fn close_flow(&self, flow_id: u32) {
        self.flow_states.lock().await.remove(&flow_id);
        self.pending_flows.lock().await.remove(&flow_id);
        // Notify the server immediately so it frees the flow slot
        if let Err(e) = send_close_frame(&self.ws_writer, &self.ratchet, flow_id).await {
            debug!("Failed to send CloseFlow for flow {}: {}", flow_id, e);
        }
    }

    // ── Background receive loop ─────────────────────────────────────

    async fn receive_loop(&self, mut ws_reader: WebSocketReader) -> Result<()> {
        loop {
            // Timeout on receive — if Caddy/proxy kills the upstream connection
            // the WebSocket reader may block forever without an error.
            // 21s = 3x max keepalive interval (7s), gives generous buffer for
            // network hiccups while still detecting dead connections promptly.
            let msg = tokio::time::timeout(
                std::time::Duration::from_secs(21),
                ws_reader.recv()
            ).await;

            let msg = match msg {
                Ok(Some(m)) => m,
                Ok(None) => anyhow::bail!("WebSocket closed"),
                Err(_) => anyhow::bail!("WebSocket receive timeout (21s) — connection appears dead"),
            };

            // If tunnel was marked dead externally (e.g. FlowCreated timeout),
            // exit so the background task ends and the WebSocket is closed.
            if !self.alive.load(Ordering::SeqCst) {
                anyhow::bail!("Tunnel marked dead, exiting receive loop");
            }

            let data = match msg {
                Message::Binary(d) => d,
                Message::Ping(_) | Message::Pong(_) => continue,
                Message::Close(_) => anyhow::bail!("Server closed connection"),
                other => { warn!("Unexpected mux msg: {:?}", other); continue; },
            };

            let message = match rvpn_core::crypto::RatchetMessage::from_bytes(&data) {
                Ok(m) => m,
                Err(e) => { warn!("Bad RatchetMessage: {}", e); continue; },
            };

            let plaintext = {
                let mut g = self.ratchet.lock().await;
                let aad: &[u8] = match message.header.payload_type {
                    0x01 => &[0x01],
                    0x02 => &[0x02],
                    0x07 => &[0x07],
                    _ => &[0x01],
                };
                match g.decrypt(&message, aad) {
                    Ok(pt) => pt,
                    Err(e) => {
                        // Ratchet desync is unrecoverable — the mux tunnel
                        // cannot decrypt any more messages. Mark dead and
                        // bail so the next open_flow triggers a reconnect.
                        error!("Ratchet desync on mux tunnel: {:?} — marking tunnel dead (age {:.1}s)",
                               e, self.tunnel_age().as_secs_f64());
                        self.alive.store(false, Ordering::SeqCst);

                        // Fail all pending FlowCreated oneshots immediately
                        let pending: HashMap<u32, PendingFlow> = {
                            let mut guard = self.pending_flows.lock().await;
                            std::mem::take(&mut *guard)
                        };
                        for (_flow_id, pf) in pending {
                            let _ = pf.tx.send(Err(anyhow::anyhow!(
                                "Mux tunnel ratchet desync — reconnect required"
                            )));
                        }

                        anyhow::bail!("Ratchet desync on mux tunnel");
                    }
                }
            };

            let unpadded = match rvpn_core::protocol::padding::unpad_packet(&plaintext) {
                Ok(d) => d,
                Err(e) => { warn!("Unpad fail: {}", e); continue; },
            };

            if unpadded.len() < 6 {
                warn!("Frame too short: {} bytes", unpadded.len());
                continue;
            }

            let flow_id = u32::from_be_bytes([unpadded[0], unpadded[1], unpadded[2], unpadded[3]]);
            let plen = u16::from_be_bytes([unpadded[4], unpadded[5]]) as usize;

            if unpadded.len() < 6 + plen {
                warn!("Frame truncated: need {}, have {}", 6 + plen, unpadded.len());
                continue;
            }

            let payload = &unpadded[6..6 + plen];

            if flow_id == 0 {
                self.handle_control_message(payload).await;
            } else {
                self.dispatch_data_frame(flow_id, payload.to_vec()).await;
            }
        }
    }

    /// Check if the tunnel receive loop is still alive
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    /// How long ago this tunnel was created
    fn tunnel_age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    async fn handle_control_message(&self, payload: &[u8]) {
        // Server sends bincode-serialized ControlMessage
        if let Ok(msg) = bincode::deserialize::<ControlMessage>(payload) {
            match msg {
                ControlMessage::FlowCreated { flow_id, .. } => {
                    trace!("FlowCreated {}", flow_id);
                    if let Some(p) = self.pending_flows.lock().await.remove(&flow_id) {
                        let _ = p.tx.send(Ok(()));
                    }
                }
                ControlMessage::FlowFailed { flow_id, error } => {
                    warn!("FlowFailed {}: {}", flow_id, error);
                    if let Some(p) = self.pending_flows.lock().await.remove(&flow_id) {
                        let _ = p.tx.send(Err(anyhow::anyhow!("Server rejected: {}", error)));
                    }
                    // In 0-RTT mode, the caller may already be sending data.
                    // Close the flow state so the relay loop exits cleanly.
                    self.flow_states.lock().await.remove(&flow_id);
                }
                ControlMessage::CloseFlow { flow_id } => {
                    trace!("Server sent CloseFlow {}", flow_id);
                    self.flow_states.lock().await.remove(&flow_id);
                }
                _ => {},
            }
        }
    }

    async fn dispatch_data_frame(&self, flow_id: u32, data: Vec<u8>) {
        let states = self.flow_states.lock().await;
        if let Some(state) = states.get(&flow_id) {
            // Use try_send to avoid blocking the receive loop when a flow's
            // consumer is slow (e.g. large Gemini response, Instagram images).
            // If the channel is full, spawn a background task to deliver the
            // data so the receive loop can continue dispatching to other flows.
            match state.ws_to_local_tx.try_send(data) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(data)) => {
                    let tx = state.ws_to_local_tx.clone();
                    tokio::spawn(async move {
                        let _ = tx.send(data).await;
                    });
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    trace!("Flow {} receiver dropped, cleaning up", flow_id);
                    drop(states);
                    self.close_flow(flow_id).await;
                }
            }
        } else {
            trace!("Data for unknown flow {}", flow_id);
        }
    }

    async fn flow_to_ws_loop(
        flow_id: u32,
        mut data_rx: mpsc::Receiver<Vec<u8>>,
        ws_writer: &WebSocketWriter,
        ratchet: &Mutex<DoubleRatchet>,
    ) -> Result<()> {
        while let Some(data) = data_rx.recv().await {
            let frame = MultiplexedFrame::new_data(flow_id, data);
            let encoded = frame.encode()?;
            let padded = rvpn_core::protocol::padding::pad_packet(&encoded)
                .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;
            let message = {
                let mut g = ratchet.lock().await;
                g.encrypt(&padded, &[PayloadType::Data as u8])?
            };
            ws_writer.send(Message::Binary(message.to_bytes()?))?;
            trace!("Flow {} → {} bytes", flow_id, frame.payload.len());
        }
        Ok(())
    }
}

/// Handle a single tunneled SOCKS5 connection through the multiplexed tunnel.
///
/// Called from `socks5.rs` — this function is defined here so it has access
/// to the `Socks5Tunnel` and `Socks5Flow` types.
pub async fn handle_multiplexed_connection(
    mut socket: tokio::net::TcpStream,
    addr: std::net::SocketAddr,
    target_addr: &str,
    tunnel: &Arc<Socks5Tunnel>,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    // The caller is responsible for sending the protocol-specific success response
    // (SOCKS5 reply or HTTP 200) before calling this function.

    // Parse target
    let (host, port) = target_addr.rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid target format"))?;
    let port: u16 = port.parse()
        .map_err(|_| anyhow::anyhow!("Invalid port"))?;

    let mut flow = tunnel.open_flow(host, port).await
        .context("Failed to open multiplexed flow")?;

    debug!("Flow {} opened to {}:{}", flow.flow_id, host, port);

    let flow_id = flow.flow_id;
    let send_tx = flow.take_send().unwrap();
    let mut recv_rx = flow.take_recv().unwrap();
    let (mut client_read, mut client_write) = socket.split();
    // 8190, not 8192 — pad_packet reserves 2 bytes for padding-length field
    let mut buf = vec![0u8; 8190];

    loop {
        tokio::select! {
            n = client_read.read(&mut buf) => {
                match n {
                    Ok(0) => break,
                    Ok(n) => {
                        if send_tx.send(buf[..n].to_vec()).await.is_err() { break; }
                    }
                    Err(_) => break,
                }
            }
            data = recv_rx.recv() => {
                match data {
                    Some(d) => {
                        if client_write.write_all(&d).await.is_err() { break; }
                    }
                    None => break,
                }
            }
        }
    }

    tracing::debug!("Multiplexed flow {} closed for {}", flow_id, addr);
    Ok(())
}
