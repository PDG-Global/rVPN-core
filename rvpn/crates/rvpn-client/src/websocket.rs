// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// WebSocket connection utilities
//
// Chrome-like TLS (BoringSSL) + Chrome-like WebSocket upgrade headers (15 headers).
// The traffic profile matches a real Chrome 131 browser connecting to a WebSocket endpoint.

use anyhow::{Context as _, Result};
use futures::SinkExt;
use rand::{Rng, SeedableRng};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio::time::Duration;
use tokio_tungstenite::WebSocketStream;
use tungstenite::handshake::client::generate_key;
use tracing::trace;

pub use tungstenite::Message;

#[cfg(not(target_os = "android"))]
use rvpn_tls::{ChromeTlsStream, TlsFingerprint, connect_chrome_like};

/// WebSocket reader type (receives messages)
pub type WebSocketReader = tokio::sync::mpsc::Receiver<Message>;

/// Capacity of the bounded channels created by [`split_websocket`].
///
/// Bounded on purpose: with unbounded channels a stalled local consumer let
/// the reader task ACK the server at line rate while frames piled up in
/// memory (~5 MB/h leak on long-running clients). The bound makes
/// backpressure reach TCP instead of the heap.
const WS_CHANNEL_CAPACITY: usize = 256;

/// WebSocket writer type (sends messages)
#[derive(Clone)]
pub struct WebSocketWriter {
    sender: tokio::sync::mpsc::Sender<Message>,
}

impl WebSocketWriter {
    /// Send a message to the WebSocket writer task.
    ///
    /// Async because the channel is bounded: when the writer task is
    /// backpressured by a slow TCP connection, this awaits until there is
    /// capacity, propagating that backpressure to the caller.
    pub async fn send(&self, msg: Message) -> Result<()> {
        self.sender
            .send(msg)
            .await
            .map_err(|_| anyhow::anyhow!("WebSocket sender closed"))?;
        Ok(())
    }

    /// Check if the underlying channel has been closed (writer task exited)
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
}

/// Handle for the helper tasks spawned by [`split_websocket`].
///
/// The reader, writer and ping tasks run independently of the relay tasks.
/// When a relay ends they must be told to stop: the ping task keeps sending
/// WebSocket pings, which holds the TCP connection open, and the server
/// counts those pings as activity, so neither side ever times the flow out.
/// A flow whose helper tasks outlive its relay leaks its full
/// TLS + WebSocket + ratchet stack forever ("zombie flow").
///
/// Call [`WebSocketTaskHandle::shutdown`] to stop the tasks and wait for
/// them. Dropping the handle without calling `shutdown` still signals the
/// tasks (without awaiting them) as a backstop for early-return paths.
pub struct WebSocketTaskHandle {
    shutdown_tx: broadcast::Sender<()>,
    joins: Vec<JoinHandle<()>>,
}

impl WebSocketTaskHandle {
    /// Signal all helper tasks to stop and wait for them to exit.
    pub async fn shutdown(mut self) {
        let _ = self.shutdown_tx.send(());
        for join in std::mem::take(&mut self.joins) {
            let _ = join.await;
        }
    }
}

impl Drop for WebSocketTaskHandle {
    fn drop(&mut self) {
        // Drop is synchronous so the tasks cannot be awaited here, but the
        // signal alone guarantees they exit on their next poll and can no
        // longer keep a dead flow's socket alive.
        let _ = self.shutdown_tx.send(());
    }
}

/// Connect to WebSocket server using Chrome-fingerprinted TLS (boring) + manual WebSocket upgrade.
///
/// This replaces the previous tokio-tungstenite `connect_async` path (which used rustls and had
/// a distinctive non-Chrome TLS fingerprint). The boring-based path mimics Chrome TLS 1.3,
/// making the connection much harder for DPI/GFW to fingerprint and block.
///
/// The WebSocket upgrade request sends Chrome-like headers (15 headers matching Chrome 131)
/// so the traffic profile matches a real browser connecting to a WebSocket endpoint.
///
/// NOTE: We do NOT include `permessage-deflate` in Sec-WebSocket-Extensions. tungstenite 0.21
/// cannot handle compressed WebSocket frames — if the server negotiates compression, the
/// connection breaks with `Protocol(ResetWithoutClosingHandshake)`. Chrome sends this
/// extension because it has native deflate support; we don't.
#[cfg(not(target_os = "android"))]
pub async fn connect_websocket(
    host: &str,
    port: u16,
    path: &str,
    fingerprint: TlsFingerprint,
    sni_hostname: Option<&str>,
) -> Result<WebSocketStream<ChromeTlsStream>> {
    // Establish TLS connection with Chrome fingerprint via boring
    let tls_stream = connect_chrome_like(host, port, fingerprint, sni_hostname)
        .await
        .context("Failed to establish Chrome-fingerprinted TLS connection")?;

    // Build Chrome-like WebSocket upgrade request with 15 headers.
    // Real Chrome 131 sends these on WebSocket upgrade — matching this profile makes
    // DPI/GFW traffic classification much harder.
    let ws_key = generate_key();
    let authority = format!("{}:{}", host, port);
    let url = format!("wss://{}:{}{}", host, port, path);
    let request = tungstenite::http::Request::builder()
        .method("GET")
        .uri(url)
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

    // Perform WebSocket HTTP/1.1 upgrade over the existing boring TLS stream
    let (ws_stream, _) = tokio_tungstenite::client_async(request, tls_stream)
        .await
        .map_err(|e| {
            tracing::error!("WebSocket upgrade failed for {}:{}{}: {:?}", host, port, path, e);
            anyhow::anyhow!("WebSocket upgrade failed: {}", e)
        })?;

    Ok(ws_stream)
}

/// Split WebSocket stream into reader and writer
///
/// Returns the reader, the writer, and a [`WebSocketTaskHandle`] controlling
/// the spawned helper tasks. The handle MUST be shut down (or dropped) when
/// the connection is no longer needed, otherwise the ping task keeps the
/// socket alive forever — see the handle's docs.
pub fn split_websocket<S>(
    ws_stream: WebSocketStream<S>,
) -> (WebSocketReader, WebSocketWriter, WebSocketTaskHandle)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use futures::stream::StreamExt;

    let (mut write, mut read) = ws_stream.split();

    let (tx_to_ws, mut rx_from_app) = tokio::sync::mpsc::channel::<Message>(WS_CHANNEL_CAPACITY);
    let (tx_to_app, rx_to_app) = tokio::sync::mpsc::channel::<Message>(WS_CHANNEL_CAPACITY);
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Writer task
    let writer_join = {
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    msg = rx_from_app.recv() => match msg {
                        Some(msg) => {
                            if let Err(e) = write.send(msg).await {
                                tracing::error!("WebSocket send error: {}", e);
                                break;
                            }
                        }
                        None => break,
                    },
                    _ = shutdown_rx.recv() => break,
                }
            }
            tracing::info!("WebSocket writer task ending");
        })
    };

    // Ping task - sends WebSocket-level pings to keep connection alive.
    // Uses jittered intervals to avoid perfectly periodic traffic patterns
    // that statistical classifiers can detect.
    let ping_join = {
        let mut shutdown_rx = shutdown_tx.subscribe();
        let ping_sender = tx_to_ws.clone();
        tokio::spawn(async move {
            let mut rng = rand::rngs::StdRng::from_entropy();
            // Random initial delay to avoid burst at connection start
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(rng.gen_range(5000..=8000))) => {}
                _ = shutdown_rx.recv() => {
                    tracing::info!("WebSocket ping task ending");
                    return;
                }
            }
            loop {
                // try_send on the bounded channel: a Full channel means the
                // writer is backpressured by TCP — skip this ping (the next
                // one in ~11s will get through) rather than block or break.
                match ping_sender.try_send(Message::Ping(vec![])) {
                    Ok(()) => trace!("WebSocket ping sent"),
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        trace!("WebSocket channel full, skipping ping");
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        tracing::debug!("Ping sender closed, stopping ping task");
                        break;
                    }
                }
                // Jittered interval: 8-14s (nominal ~11s, matching Chrome behavior)
                let jitter_ms = rng.gen_range(8000..=14000);
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_millis(jitter_ms)) => {}
                    _ = shutdown_rx.recv() => break,
                }
            }
            tracing::info!("WebSocket ping task ending");
        })
    };

    // Reader task - note: mpsc channel drops tx_to_app when task exits
    let reader_join = {
        let mut shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = read.next() => match result {
                        Some(Ok(msg)) => {
                            if let Message::Pong(_) = &msg {
                                trace!("WebSocket pong received");
                            }
                            if tx_to_app.send(msg).await.is_err() {
                                tracing::debug!("WebSocket reader: channel receiver dropped, exiting");
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            tracing::error!("WebSocket receive error: {:?}, closing connection", e);
                            // Don't send anything - just let the task exit which drops the sender
                            break;
                        }
                        None => break,
                    },
                    _ = shutdown_rx.recv() => break,
                }
            }
            tracing::info!("WebSocket reader task ending");
        })
    };

    let writer = WebSocketWriter { sender: tx_to_ws };
    let handle = WebSocketTaskHandle {
        shutdown_tx,
        joins: vec![reader_join, writer_join, ping_join],
    };
    (rx_to_app, writer, handle)
}
