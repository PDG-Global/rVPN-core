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
use tokio::time::Duration;
use tokio_tungstenite::WebSocketStream;
use tungstenite::handshake::client::generate_key;
use tracing::trace;

pub use tungstenite::Message;

use crate::tls_boring::{ChromeTlsStream, TlsFingerprint, connect_chrome_like};

/// WebSocket reader type (receives messages)
pub type WebSocketReader = tokio::sync::mpsc::UnboundedReceiver<Message>;

/// WebSocket writer type (sends messages)
#[derive(Clone)]
pub struct WebSocketWriter {
    sender: tokio::sync::mpsc::UnboundedSender<Message>,
}

impl WebSocketWriter {
    pub fn send(&self, msg: Message) -> Result<()> {
        self.sender
            .send(msg)
            .map_err(|_| anyhow::anyhow!("WebSocket sender closed"))?;
        Ok(())
    }

    /// Check if the underlying channel has been closed (writer task exited)
    pub fn is_closed(&self) -> bool {
        self.sender.is_closed()
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
pub fn split_websocket<S>(ws_stream: WebSocketStream<S>) -> (WebSocketReader, WebSocketWriter)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    use futures::stream::StreamExt;

    let (mut write, mut read) = ws_stream.split();

    let (tx_to_ws, mut rx_from_app) = tokio::sync::mpsc::unbounded_channel::<Message>();
    let (tx_to_app, rx_to_app) = tokio::sync::mpsc::unbounded_channel::<Message>();

    // Writer task
    tokio::spawn(async move {
        while let Some(msg) = rx_from_app.recv().await {
            if let Err(e) = write.send(msg).await {
                tracing::error!("WebSocket send error: {}", e);
                break;
            }
        }
        tracing::info!("WebSocket writer task ending");
    });

    // Ping task - sends WebSocket-level pings to keep connection alive.
    // Uses jittered intervals to avoid perfectly periodic traffic patterns
    // that statistical classifiers can detect.
    let ping_sender = tx_to_ws.clone();
    tokio::spawn(async move {
        let mut rng = rand::rngs::StdRng::from_entropy();
        // Random initial delay to avoid burst at connection start
        tokio::time::sleep(Duration::from_millis(rng.gen_range(5000..=8000))).await;
        loop {
            if ping_sender.send(Message::Ping(vec![])).is_err() {
                tracing::debug!("Ping sender closed, stopping ping task");
                break;
            }
            trace!("WebSocket ping sent");
            // Jittered interval: 8-14s (nominal ~11s, matching Chrome behavior)
            let jitter_ms = rng.gen_range(8000..=14000);
            tokio::time::sleep(Duration::from_millis(jitter_ms)).await;
        }
        tracing::info!("WebSocket ping task ending");
    });

    // Reader task - note: mpsc channel drops tx_to_app when task exits
    tokio::spawn(async move {
        while let Some(result) = read.next().await {
            match result {
                Ok(msg) => {
                    if let Message::Pong(_) = &msg {
                        trace!("WebSocket pong received");
                    }
                    if tx_to_app.send(msg).is_err() {
                        tracing::debug!("WebSocket reader: channel receiver dropped, exiting");
                        break;
                    }
                }
                Err(e) => {
                    tracing::error!("WebSocket receive error: {:?}, closing connection", e);
                    // Don't send anything - just let the task exit which drops the sender
                    break;
                }
            }
        }
        tracing::info!("WebSocket reader task ending");
    });

    let writer = WebSocketWriter { sender: tx_to_ws };
    (rx_to_app, writer)
}
