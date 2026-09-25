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
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Weak};

use anyhow::{Context as _, Result};
use bytes::Bytes;
use rand::{Rng, SeedableRng};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, trace, warn};

use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::crypto::{DoubleRatchet, IdentityKey, X3DHPublicBundle};
use rvpn_core::protocol::multiplex::{CreditWait, FlowSendCredits, FLOW_CREDIT_STALL_TIMEOUT};
use rvpn_core::protocol::{ControlMessage, HandshakeMessage, MultiplexedFrame, PayloadType};

use crate::config::ServerIdentityConfig;
use crate::identity_verification::{verify_server_identity, KnownHosts};
use crate::websocket::{
    connect_websocket, split_websocket, Message, WebSocketReader, WebSocketTaskHandle,
    WebSocketWriter,
};
use rvpn_tls::{ResumptionStore, TlsFingerprint};

// ── Internal types ──────────────────────────────────────────────────

/// Pending flow creation response
struct PendingFlow {
    tx: tokio::sync::oneshot::Sender<Result<()>>,
}

/// Server-side state for an active flow
struct FlowState {
    /// Sender for WS -> local data (feeds the Socks5Flow receiver).
    /// Uses Bytes so payloads sliced out of the decrypted plaintext can be
    /// forwarded without allocating a fresh Vec per received frame.
    ws_to_local_tx: mpsc::Sender<Bytes>,
    /// Send credits for the local -> server (uplink) direction. Granted by
    /// server `WindowUpdate` control messages; consumed one byte per payload
    /// byte sent by `flow_to_ws_loop`.
    send_credits: Arc<FlowSendCredits>,
}

// ── Public types ────────────────────────────────────────────────────

/// Ordered encrypt+enqueue handle for one tunnel's WebSocket writer.
///
/// The Double Ratchet assigns message numbers at encrypt time, so wire order
/// MUST match encrypt order: a frame encrypted later (higher message number)
/// that overtakes an earlier one into the writer channel is dropped by the
/// receiving ratchet ("Message too old" — skipped-key pruning tolerates
/// almost no reordering) and its payload — e.g. a WindowUpdate credit
/// grant — is lost forever. Every send path on the tunnel (per-flow data,
/// WindowUpdate, CreateFlow/CloseFlow, keepalive) goes through this
/// serializer: hold `send_lock` across encrypt + enqueue, but release the
/// ratchet lock BEFORE the send await so a full writer channel never stalls
/// the receive loop's decrypts.
#[derive(Clone)]
struct TunnelSender {
    ws_writer: WebSocketWriter,
    ratchet: Arc<Mutex<DoubleRatchet>>,
    send_lock: Arc<Mutex<()>>,
}

impl TunnelSender {
    /// Encrypt `plaintext` (already padded) with the tunnel ratchet and
    /// enqueue it on the WebSocket writer, preserving
    /// wire order == ratchet message-number order.
    async fn send_encrypted(&self, plaintext: &[u8], aad: &[u8]) -> Result<()> {
        let _send_guard = self.send_lock.lock().await;
        let message = {
            let mut guard = self.ratchet.lock().await;
            guard.encrypt(plaintext, aad)?
        };
        // Ratchet lock released before the (potentially blocking) send.
        self.ws_writer
            .send(Message::Binary(message.to_bytes()?))
            .await
    }
}

/// Shared multiplexed tunnel for all SOCKS5 flows.
pub struct Socks5Tunnel {
    sender: TunnelSender,
    ratchet: Arc<Mutex<DoubleRatchet>>,
    next_flow_id: AtomicU32,
    pending_flows: Mutex<HashMap<u32, PendingFlow>>,
    flow_states: Mutex<HashMap<u32, FlowState>>,
    /// Set to false when the receive loop exits — signals callers to reconnect
    alive: AtomicBool,
    /// Number of flows currently registered in `flow_states`. Kept as an
    /// atomic mirror so pool striping (`tunnel_pool.rs`) can read the load
    /// without locking the flow map.
    flow_count: AtomicUsize,
    /// Total payload bytes relayed through this tunnel (both directions).
    /// Drives the byte-based rotation threshold in pooled mode.
    bytes_relayed: Arc<AtomicU64>,
    /// When this tunnel was created (for diagnostics and age-based rotation)
    created_at: std::time::Instant,
    /// Holds the reader/writer/ping helper tasks' shutdown signal. When this
    /// tunnel is dropped (replaced after death), the handle's Drop signals
    /// the tasks to stop so the ping task cannot keep the dead tunnel's
    /// WebSocket alive forever.
    _ws_tasks: WebSocketTaskHandle,
}

/// Handle for a single multiplexed SOCKS5 flow.
pub struct Socks5Flow {
    /// Flow identifier
    pub flow_id: u32,
    /// Local TCP -> WS sender (taken out for relay, None after)
    local_to_ws_tx: Option<mpsc::Sender<Vec<u8>>>,
    /// WS -> local TCP receiver (taken out for relay, None after).
    /// Carries Bytes (zero-copy view over the decrypted plaintext).
    ws_to_local_rx: Option<mpsc::Receiver<Bytes>>,
    tunnel: Weak<Socks5Tunnel>,
}

impl Socks5Flow {
    /// Take the send channel, consuming this part of the flow
    pub fn take_send(&mut self) -> Option<mpsc::Sender<Vec<u8>>> {
        self.local_to_ws_tx.take()
    }

    /// Take the receive channel, consuming this part of the flow
    pub fn take_recv(&mut self) -> Option<mpsc::Receiver<Bytes>> {
        self.ws_to_local_rx.take()
    }
}

impl Socks5Flow {
    #[allow(dead_code)]
    pub async fn send_data(&self, data: &[u8]) -> Result<()> {
        let tx = self
            .local_to_ws_tx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Flow send channel already taken"))?;
        tx.send(data.to_vec())
            .await
            .map_err(|_| anyhow::anyhow!("Flow send channel closed"))
    }

    #[allow(dead_code)]
    pub async fn recv_data(&mut self) -> Option<Bytes> {
        self.ws_to_local_rx.as_mut()?.recv().await
    }
}

impl Drop for Socks5Flow {
    fn drop(&mut self) {
        let Some(tunnel) = self.tunnel.upgrade() else {
            return;
        };
        let sender = tunnel.sender.clone();
        let flow_id = self.flow_id;
        tokio::spawn(async move {
            if let Err(e) = send_close_frame(&sender, flow_id).await {
                debug!("Failed to send CloseFlow for flow {}: {}", flow_id, e);
            }
        });
    }
}

async fn send_close_frame(sender: &TunnelSender, flow_id: u32) -> Result<()> {
    let msg = ControlMessage::CloseFlow { flow_id };
    // Control messages MUST be sent on flow_id=0 (CONTROL_FLOW_ID)
    // with bincode-serialized payload
    let frame = MultiplexedFrame::new_control(&msg)
        .context("Failed to serialize CloseFlow control message")?;
    let encoded = frame.encode()?;
    let padded = rvpn_core::protocol::padding::pad_packet(&encoded)
        .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;
    sender
        .send_encrypted(&padded, &[PayloadType::Admin as u8])
        .await?;
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
        resumption: Option<&ResumptionStore>,
    ) -> Result<Arc<Self>> {
        info!(
            "Connecting SOCKS5 multiplexed tunnel to {}:{}{}",
            host, port, path
        );
        let probe = crate::dashboard::HandshakeProbe::start();

        debug!("WebSocket path for mux tunnel: {}", path);
        let ws_stream = connect_websocket(host, port, path, fingerprint, sni_hostname, resumption)
            .await
            .map_err(|e| {
                error!("MUX WebSocket connect failed: {}:{}", host, port);
                e
            })
            .context("Failed to establish multiplexed WebSocket connection")?;

        let (mut ws_reader, ws_writer, ws_tasks) = split_websocket(ws_stream);

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
        probe.success();

        let ratchet = Arc::new(Mutex::new(ratchet));

        let tunnel = Arc::new(Self {
            sender: TunnelSender {
                ws_writer,
                ratchet: Arc::clone(&ratchet),
                send_lock: Arc::new(Mutex::new(())),
            },
            ratchet: Arc::clone(&ratchet),
            next_flow_id: AtomicU32::new(1),
            pending_flows: Mutex::new(HashMap::new()),
            flow_states: Mutex::new(HashMap::new()),
            alive: AtomicBool::new(true),
            flow_count: AtomicUsize::new(0),
            bytes_relayed: Arc::new(AtomicU64::new(0)),
            created_at: std::time::Instant::now(),
            _ws_tasks: ws_tasks,
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
                       tunnel.age().as_secs_f64());

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
                debug!(
                    "Cleared {} pending flow ACKs after tunnel disconnect",
                    count
                );
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
                tokio::time::sleep(std::time::Duration::from_millis(rng.gen_range(3000..=7000)))
                    .await;
                while tunnel.alive.load(Ordering::SeqCst) {
                    let timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let msg = ControlMessage::Ping { timestamp };
                    match MultiplexedFrame::new_control(&msg) {
                        Ok(frame) => {
                            if let Ok(encoded) = frame.encode() {
                                let padded =
                                    match rvpn_core::protocol::padding::pad_packet(&encoded) {
                                        Ok(p) => p,
                                        Err(e) => {
                                            debug!("Keepalive pad failed: {}", e);
                                            break;
                                        }
                                    };
                                if let Err(e) = tunnel
                                    .sender
                                    .send_encrypted(&padded, &[PayloadType::Admin as u8])
                                    .await
                                {
                                    debug!("Keepalive send failed: {}", e);
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
        ws_writer
            .send(Message::Binary(serde_json::to_vec(&hello)?))
            .await
            .context("Failed to send Hello")?;

        let response = ws_reader
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("WebSocket closed during handshake"))?;

        let data = match response {
            Message::Binary(d) => d,
            Message::Close(_) => anyhow::bail!("WebSocket closed during handshake"),
            other => anyhow::bail!("Unexpected message during handshake: {:?}", other),
        };

        let server_hello: HandshakeMessage =
            serde_json::from_slice(&data).context("Failed to parse ServerHello")?;

        match server_hello {
            HandshakeMessage::ServerHello {
                ephemeral_key: _,
                identity_key: server_identity_key,
                signed_prekey: server_signed_prekey,
                prekey_signature: server_prekey_signature,
            } => {
                let srv_id: [u8; 32] = server_identity_key
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Server identity key wrong length"))?;
                let srv_sp: [u8; 32] = server_signed_prekey
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("Server signed prekey wrong length"))?;
                let sig: [u8; 64] = server_prekey_signature
                    .as_slice()
                    .try_into()
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
                    identity_key_version: server_bundle.identity_key_version,
                    rotation_signature: server_bundle.rotation_signature,
                };

                // Optional identity verification. Load-mutate-save the
                // known_hosts file so a TOFU capture on first connect
                // and a legacy-to-canonical pin migration on subsequent
                // connects both persist without a caller-side rewrite.
                if let Some(cfg) = server_identity_config {
                    let addr = format!("{}:{}", host, port);
                    let mut known = KnownHosts::load(&cfg.known_hosts_file).unwrap_or_default();
                    let (_res, ok) = verify_server_identity(
                        &addr,
                        &bundle,
                        &mut known,
                        cfg.fingerprint.as_deref(),
                        cfg.trust_on_first_use,
                        cfg.strict_mode,
                    );
                    if let Err(e) = known.save(&cfg.known_hosts_file) {
                        tracing::warn!("Failed to persist known_hosts.json: {}", e);
                    }
                    if !ok && cfg.strict_mode {
                        anyhow::bail!("Server identity verification failed");
                    }
                }

                let (shared, _) = initiator
                    .agree(&bundle)
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
        debug!(
            "Flow {} CreateFlow sent (0-RTT mode — not waiting for ACK)",
            flow_id
        );

        let (local_to_ws_tx, local_to_ws_rx) = mpsc::channel::<Vec<u8>>(256);
        let (ws_to_local_tx, ws_to_local_rx) = mpsc::channel::<Bytes>(256);
        let send_credits = Arc::new(FlowSendCredits::new());

        {
            let mut states = self.flow_states.lock().await;
            states.insert(
                flow_id,
                FlowState {
                    ws_to_local_tx,
                    send_credits: Arc::clone(&send_credits),
                },
            );
        }
        self.flow_count.fetch_add(1, Ordering::Relaxed);

        let sender = self.sender.clone();
        let bytes_relayed = Arc::clone(&self.bytes_relayed);
        let tunnel_weak = Arc::downgrade(self);
        tokio::spawn(async move {
            if let Err(e) = Self::flow_to_ws_loop(
                flow_id,
                local_to_ws_rx,
                &sender,
                &bytes_relayed,
                &send_credits,
                &tunnel_weak,
            )
            .await
            {
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
        self.sender
            .send_encrypted(&padded, &[PayloadType::Admin as u8])
            .await?;
        debug!("Sent CreateFlow {} → {}:{}", flow_id, target, port);
        Ok(())
    }

    pub async fn close_flow(&self, flow_id: u32) {
        self.remove_flow_state(flow_id).await;
        self.pending_flows.lock().await.remove(&flow_id);
        // Notify the server immediately so it frees the flow slot
        if let Err(e) = send_close_frame(&self.sender, flow_id).await {
            debug!("Failed to send CloseFlow for flow {}: {}", flow_id, e);
        }
    }

    /// Grant the server `credits` bytes of send window for `flow_id`
    /// (downlink flow control).
    ///
    /// Called by the flow's local consumer after it has written that many
    /// bytes to the local application socket — i.e. when the flow's receive
    /// buffer occupancy actually decreases.
    pub async fn send_window_update(&self, flow_id: u32, credits: u32) {
        let msg = ControlMessage::WindowUpdate {
            flow_id,
            window_size: credits,
        };
        let result = async {
            let frame = MultiplexedFrame::new_control(&msg)
                .context("Failed to serialize WindowUpdate control message")?;
            let encoded = frame.encode()?;
            let padded = rvpn_core::protocol::padding::pad_packet(&encoded)
                .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;
            self.sender
                .send_encrypted(&padded, &[PayloadType::Admin as u8])
                .await
        }
        .await;
        if let Err(e) = result {
            // Non-fatal: the worst case is the flow stalling and hitting the
            // sender-side credit stall valve.
            debug!("Failed to send WindowUpdate for flow {}: {}", flow_id, e);
        }
    }

    /// Remove a flow's state, keeping the atomic flow counter in sync.
    ///
    /// Closing the flow's credit gate wakes a `flow_to_ws_loop` parked at
    /// zero credits immediately (it exits quietly with `CreditWait::Closed`)
    /// instead of lingering until the 60s stall valve and logging a
    /// misleading stall warning for an already-dead flow.
    async fn remove_flow_state(&self, flow_id: u32) {
        if let Some(state) = self.flow_states.lock().await.remove(&flow_id) {
            state.send_credits.close();
            self.flow_count.fetch_sub(1, Ordering::Relaxed);
        }
    }

    // ── Background receive loop ─────────────────────────────────────

    async fn receive_loop(&self, mut ws_reader: WebSocketReader) -> Result<()> {
        loop {
            // Timeout on receive — if Caddy/proxy kills the upstream connection
            // the WebSocket reader may block forever without an error.
            // 21s = 3x max keepalive interval (7s), gives generous buffer for
            // network hiccups while still detecting dead connections promptly.
            let msg =
                tokio::time::timeout(std::time::Duration::from_secs(21), ws_reader.recv()).await;

            let msg = match msg {
                Ok(Some(m)) => m,
                Ok(None) => anyhow::bail!("WebSocket closed"),
                Err(_) => {
                    anyhow::bail!("WebSocket receive timeout (21s) — connection appears dead")
                }
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
                other => {
                    warn!("Unexpected mux msg: {:?}", other);
                    continue;
                }
            };

            let message = match rvpn_core::crypto::RatchetMessage::from_bytes(&data) {
                Ok(m) => m,
                Err(e) => {
                    warn!("Bad RatchetMessage: {}", e);
                    continue;
                }
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
                        error!(
                            "Ratchet desync on mux tunnel: {:?} — marking tunnel dead (age {:.1}s)",
                            e,
                            self.age().as_secs_f64()
                        );
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
                Err(e) => {
                    warn!("Unpad fail: {}", e);
                    continue;
                }
            };

            if unpadded.len() < 6 {
                warn!("Frame too short: {} bytes", unpadded.len());
                continue;
            }

            let flow_id = u32::from_be_bytes([unpadded[0], unpadded[1], unpadded[2], unpadded[3]]);
            let plen = u16::from_be_bytes([unpadded[4], unpadded[5]]) as usize;

            if unpadded.len() < 6 + plen {
                warn!(
                    "Frame truncated: need {}, have {}",
                    6 + plen,
                    unpadded.len()
                );
                continue;
            }

            if flow_id == 0 {
                self.handle_control_message(&unpadded[6..6 + plen]).await;
            } else {
                // Zero-copy: Bytes::from(unpadded) transfers ownership of the
                // Vec's allocation (no memcpy), and slice() returns a refcount
                // view over the same buffer — avoiding the per-frame Vec
                // allocation that .to_vec() would incur.
                let payload = Bytes::from(unpadded).slice(6..6 + plen);
                self.dispatch_data_frame(flow_id, payload).await;
            }
        }
    }

    /// Check if the tunnel receive loop is still alive
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    /// Number of flows currently open on this tunnel.
    ///
    /// Used by the pooled-mode striping logic (`tunnel_pool.rs`) for
    /// least-loaded flow assignment.
    pub fn active_flow_count(&self) -> usize {
        self.flow_count.load(Ordering::Relaxed)
    }

    /// How long ago this tunnel was created. Drives the age-based rotation
    /// threshold in pooled mode (`tunnel_pool.rs`).
    pub fn age(&self) -> std::time::Duration {
        self.created_at.elapsed()
    }

    /// Total payload bytes relayed through this tunnel (both directions).
    /// Drives the byte-based rotation threshold in pooled mode.
    pub fn bytes_relayed(&self) -> u64 {
        self.bytes_relayed.load(Ordering::Relaxed)
    }

    /// Force-close the tunnel: mark dead, fail all pending flow-creation
    /// waiters, and drop every flow's receive channel so relay loops exit.
    ///
    /// Used by the pool's drain path (`tunnel_pool.rs`) — on the drain
    /// backstop this is what "fails the remaining flows fast" (their SOCKS5
    /// sockets close, the app's retry lands on a healthy tunnel).
    pub async fn shutdown(&self) {
        self.alive.store(false, Ordering::SeqCst);

        let pending: HashMap<u32, PendingFlow> = {
            let mut guard = self.pending_flows.lock().await;
            std::mem::take(&mut *guard)
        };
        for (flow_id, pf) in pending {
            let _ = pf.tx.send(Err(anyhow::anyhow!(
                "Mux tunnel shut down (flow {})",
                flow_id
            )));
        }

        // Close every flow's credit gate first so a flow_to_ws_loop parked
        // at zero credits wakes and exits quietly, then drop the senders to
        // close every flow's ws→local channel.
        {
            let mut states = self.flow_states.lock().await;
            for state in states.values() {
                state.send_credits.close();
            }
            states.clear();
        }
        self.flow_count.store(0, Ordering::Relaxed);
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
                        let _ =
                            p.tx.send(Err(anyhow::anyhow!("Server rejected: {}", error)));
                    }
                    // In 0-RTT mode, the caller may already be sending data.
                    // Close the flow state so the relay loop exits cleanly.
                    self.remove_flow_state(flow_id).await;
                }
                ControlMessage::CloseFlow { flow_id } => {
                    trace!("Server sent CloseFlow {}", flow_id);
                    self.remove_flow_state(flow_id).await;
                }
                ControlMessage::WindowUpdate {
                    flow_id,
                    window_size,
                } => {
                    // Server consumed `window_size` bytes of this flow's
                    // uplink data (written to the target socket) — grant the
                    // credits back to the send loop.
                    let states = self.flow_states.lock().await;
                    if let Some(state) = states.get(&flow_id) {
                        state.send_credits.grant(window_size as u64);
                    } else {
                        trace!("WindowUpdate for unknown flow {}", flow_id);
                    }
                }
                _ => {}
            }
        }
    }

    async fn dispatch_data_frame(&self, flow_id: u32, data: Bytes) {
        self.bytes_relayed
            .fetch_add(data.len() as u64, Ordering::Relaxed);
        let states = self.flow_states.lock().await;
        if let Some(state) = states.get(&flow_id) {
            // Use try_send to avoid blocking the receive loop when a flow's
            // consumer is slow. With credit-based flow control the server can
            // have at most INITIAL_FLOW_WINDOW bytes in flight per flow, so
            // the channel can never legitimately fill: a Full here means a
            // flow-control bug or a misbehaving peer. Log it (loudly, once
            // per frame) and drop — blocking the demux loop would stall
            // every other flow on the tunnel.
            match state.ws_to_local_tx.try_send(data) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    warn!(
                        "Flow {} dispatch channel full, dropping frame — peer is exceeding its credit window",
                        flow_id
                    );
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
        sender: &TunnelSender,
        bytes_relayed: &AtomicU64,
        send_credits: &Arc<FlowSendCredits>,
        tunnel: &Weak<Socks5Tunnel>,
    ) -> Result<()> {
        // Chunk that exceeded the remaining credit window; the unsent tail
        // is carried to the next iteration.
        let mut pending: Option<Vec<u8>> = None;

        loop {
            let data = match pending.take() {
                Some(d) => d,
                None => match data_rx.recv().await {
                    Some(d) => d,
                    None => break,
                },
            };
            if data.is_empty() {
                continue;
            }

            // Flow control: send at most the remaining credit window. At zero
            // credits, park until the server's WindowUpdate tops us up — the
            // local_to_ws channel then fills and the SOCKS5 relay stops
            // reading the app socket, so TCP backpressure throttles the app.
            let n = send_credits.try_consume(data.len() as u64) as usize;
            if n == 0 {
                match send_credits
                    .wait_for_credit_or_stall(FLOW_CREDIT_STALL_TIMEOUT)
                    .await
                {
                    CreditWait::Granted => {
                        pending = Some(data);
                        continue;
                    }
                    // The flow was closed while parked (CloseFlow, local
                    // socket closed, tunnel shutdown): exit quietly — this
                    // is normal teardown, not a stall.
                    CreditWait::Closed => {
                        debug!(
                            "Flow {} closed while parked at zero credits — exiting",
                            flow_id
                        );
                        return Ok(());
                    }
                    // Safety valve: peers built before flow control ignore
                    // WindowUpdate and never grant credits, which would stall
                    // this loop forever. Client and server are deployed
                    // together, so this is purely defensive.
                    CreditWait::Stalled => {
                        warn!(
                            "Flow {} stalled at zero credits for {:?} — closing (peer may not implement flow control)",
                            flow_id, FLOW_CREDIT_STALL_TIMEOUT
                        );
                        if let Some(tunnel) = tunnel.upgrade() {
                            tunnel.close_flow(flow_id).await;
                        }
                        anyhow::bail!("Flow {} closed: credit stall", flow_id);
                    }
                }
            }

            let frame = if n == data.len() {
                MultiplexedFrame::new_data(flow_id, data)
            } else {
                pending = Some(data[n..].to_vec());
                MultiplexedFrame::new_data(flow_id, Bytes::copy_from_slice(&data[..n]))
            };
            bytes_relayed.fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
            let encoded = frame.encode()?;
            let padded = rvpn_core::protocol::padding::pad_packet(&encoded)
                .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;
            sender
                .send_encrypted(&padded, &[PayloadType::Data as u8])
                .await?;
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
    let (host, port) = target_addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("Invalid target format"))?;
    let port: u16 = port.parse().map_err(|_| anyhow::anyhow!("Invalid port"))?;

    let mut flow = tunnel
        .open_flow(host, port)
        .await
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
                        crate::dashboard::record_bytes_up(n as u64);
                        if send_tx.send(buf[..n].to_vec()).await.is_err() { break; }
                    }
                    Err(_) => break,
                }
            }
            data = recv_rx.recv() => {
                match data {
                    Some(d) => {
                        crate::dashboard::record_bytes_down(d.len() as u64);
                        if client_write.write_all(&d).await.is_err() { break; }
                        // Flow control: grant the server credits for the
                        // bytes just handed to the local application socket.
                        tunnel.send_window_update(flow_id, d.len() as u32).await;
                    }
                    None => break,
                }
            }
        }
    }

    tracing::debug!("Multiplexed flow {} closed for {}", flow_id, addr);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvpn_core::crypto::RatchetMessage;
    use std::collections::HashSet;

    /// Regression test for the production "Message too old" stall (hk2):
    /// with many tasks encrypting concurrently on the shared tunnel ratchet,
    /// wire order MUST equal ratchet message-number order, and every frame
    /// must decrypt at the receiver. The writer channel capacity is 1 so
    /// sends genuinely await, maximizing interleaving between encrypt and
    /// enqueue — without the send_lock serialization this interleaving is
    /// exactly what let a later-encrypted frame overtake an earlier one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tunnel_sender_preserves_wire_order_under_contention() {
        const TASKS: usize = 8;
        const MSGS_PER_TASK: usize = 100;
        const TOTAL: usize = TASKS * MSGS_PER_TASK;

        let shared_secret = [0x42u8; 32];
        let alice = DoubleRatchet::init_alice(shared_secret, [0u8; 32]);
        let mut bob = DoubleRatchet::init_bob(shared_secret);

        let (tx, mut rx) = mpsc::channel::<Message>(1);
        let sender = TunnelSender {
            ws_writer: WebSocketWriter::from_sender(tx),
            ratchet: Arc::new(Mutex::new(alice)),
            send_lock: Arc::new(Mutex::new(())),
        };

        let mut handles = Vec::new();
        for t in 0..TASKS {
            let sender = sender.clone();
            handles.push(tokio::spawn(async move {
                for i in 0..MSGS_PER_TASK {
                    let payload = format!("task{}-msg{}", t, i).into_bytes();
                    sender
                        .send_encrypted(&payload, &[0x01])
                        .await
                        .expect("send_encrypted failed");
                }
            }));
        }
        // Drop the local handle so the channel closes when all tasks finish.
        drop(sender);

        let mut wire_numbers = Vec::new();
        let mut payloads = HashSet::new();
        while let Some(msg) = rx.recv().await {
            let Message::Binary(bytes) = msg else {
                panic!("unexpected non-binary message");
            };
            let parsed = RatchetMessage::from_bytes(&bytes).expect("deserialize failed");
            wire_numbers.push(parsed.header.message_number);
            let plain = bob
                .decrypt(&parsed, &[0x01])
                .expect("decrypt failed — frame dropped or reordered");
            payloads.insert(String::from_utf8(plain).expect("payload not utf8"));
        }

        for h in handles {
            h.await.expect("sender task panicked");
        }

        // Every frame arrived and decrypted.
        assert_eq!(wire_numbers.len(), TOTAL, "frames lost on the wire");
        // Wire order is exactly message-number order 0..TOTAL.
        let mut sorted = wire_numbers.clone();
        sorted.sort_unstable();
        assert_eq!(
            wire_numbers, sorted,
            "wire order diverged from message-number order"
        );
        assert_eq!(wire_numbers[0], 0);
        assert_eq!(wire_numbers[TOTAL - 1], (TOTAL - 1) as u32);
        // Every payload arrived intact.
        assert_eq!(payloads.len(), TOTAL, "payloads lost or duplicated");
        for t in 0..TASKS {
            for i in 0..MSGS_PER_TASK {
                assert!(payloads.contains(&format!("task{}-msg{}", t, i)));
            }
        }
    }
}
