// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Minimal WebSocket frame parser with pre-allocated buffers.
//!
//! Replaces tungstenite's per-frame `Vec<u8>` allocations with a persistent
//! 16 KB read buffer. Under sustained 5G traffic (~60 frames/sec, ~14 KB each)
//! this eliminates ~840 KB/sec of allocation churn that causes RSS growth to
//! iOS's 50 MB jetsam limit.
//!
//! Only binary frames (0x02) are used for data. Ping (0x09) and Close (0x08)
//! control frames are handled inline. No text frames, no extensions, no
//! compression.

use anyhow::Result;
use base64::Engine;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use tokio::io::{ReadHalf, WriteHalf};

/// Pre-allocated read buffer size. 16 KB is enough for the largest data frame
/// (~14 KB payload + ~10 byte header) with room to spare.
const READ_BUF_SIZE: usize = 16 * 1024;

/// Minimal WebSocket client over an existing TLS stream.
///
/// Uses `tokio::io::split()` internally so the read and write halves can be
/// used independently (required for the concurrent relay loop).
pub struct MinimalWebSocket<S> {
    reader: ReadHalf<S>,
    writer: WriteHalf<S>,
    read_buf: Vec<u8>,
}

/// Type of WebSocket frame received.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FrameType {
    Binary,
    Ping,
    Close,
}

impl<S: AsyncRead + AsyncWrite + Unpin + 'static> MinimalWebSocket<S> {
    /// Perform the client-side WebSocket handshake over an existing TLS stream,
    /// then split into independent read/write halves.
    pub async fn connect(mut stream: S, url: &str) -> Result<Self> {
        // Parse URL: wss://host:port/path
        tracing::debug!("[WS] connect called with url: {}", url);
        let rest = url
            .strip_prefix("wss://")
            .or_else(|| url.strip_prefix("ws://"))
            .unwrap_or(url);
        let (authority, path_part) = rest.split_once('/').unwrap_or((rest, ""));
        let path_owned = if path_part.is_empty() { "/".to_string() } else { format!("/{}", path_part) };
        let path = path_owned.as_str();

        let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
        tracing::debug!("[WS] parsed: host={}, path={}", host, path);

        // Generate random 16-byte key for Sec-WebSocket-Key
        let mut key_bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut key_bytes);
        let ws_key = base64::engine::general_purpose::STANDARD.encode(key_bytes);

        // Send HTTP upgrade request.
        //
        // Header set mirrors Chrome's WebSocket upgrade (parity with
        // android_tun.rs). iOS loses TLS-ClientHello mimicry when using the
        // rustls backend, so carrying Chrome's HTTP headers here is the main
        // remaining stealth signal at the upgrade layer. All header values are
        // static literals baked into the format! write — no per-connect alloc
        // beyond the single request String.
        let request = format!(
            "GET {path} HTTP/1.1\r\n\
             Host: {host}\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: {ws_key}\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n\
             Accept: */*\r\n\
             Accept-Encoding: gzip, deflate, br\r\n\
             Accept-Language: en-US,en;q=0.9\r\n\
             Cache-Control: no-cache\r\n\
             Pragma: no-cache\r\n\
             Sec-Fetch-Dest: websocket\r\n\
             Sec-Fetch-Mode: websocket\r\n\
             Sec-Fetch-Site: same-origin\r\n\
             \r\n"
        );
        tracing::debug!("[WS] sending request: {}", request.replace("\r\n", "\\r\\n"));
        stream.write_all(request.as_bytes()).await?;

        // Read and parse HTTP response
        let mut resp_buf = vec![0u8; 2048];
        let mut resp_len = 0usize;
        loop {
            if resp_len >= resp_buf.len() {
                anyhow::bail!("WebSocket handshake response too large");
            }
            let n = stream.read(&mut resp_buf[resp_len..]).await?;
            if n == 0 {
                anyhow::bail!("Connection closed during WebSocket handshake");
            }
            resp_len += n;
            if resp_buf[..resp_len].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }

        let resp_str = std::str::from_utf8(&resp_buf[..resp_len])?;
        tracing::debug!("[WS] response: {}", resp_str.replace("\r\n", "\\r\\n"));
        let status_line = resp_str.lines().next().unwrap_or("");

        if !status_line.contains(" 101 ") {
            anyhow::bail!("WebSocket upgrade failed: {}", status_line);
        }

        // Validate Sec-WebSocket-Accept
        let expected_accept = ws_accept_hash(&ws_key);
        let got_accept = resp_str
            .lines()
            .find(|l| l.to_lowercase().starts_with("sec-websocket-accept:"))
            .map(|l| l.split_once(':').unwrap().1.trim());

        if got_accept != Some(expected_accept.as_str()) {
            anyhow::bail!("WebSocket Sec-WebSocket-Accept mismatch");
        }

        // Split into independent read/write halves for concurrent access
        let (reader, writer) = tokio::io::split(stream);

        Ok(Self {
            reader,
            writer,
            read_buf: Vec::with_capacity(READ_BUF_SIZE),
        })
    }

    /// Split into independent reader and writer halves.
    ///
    /// The reader retains the pre-allocated frame buffer. Any unconsumed bytes
    /// from the handshake or previous reads are preserved.
    pub fn split(self) -> (MinimalWsReader<S>, MinimalWsWriter<S>) {
        (
            MinimalWsReader {
                reader: self.reader,
                read_buf: self.read_buf,
            },
            MinimalWsWriter {
                writer: self.writer,
                // Pre-allocated scratch buffer for masking client frames. Sized
                // to the largest expected payload so it never reallocates after
                // the first large frame.
                mask_buf: Vec::with_capacity(READ_BUF_SIZE),
            },
        )
    }

    // After `connect`, all I/O is driven via the `split()` halves:
    // `MinimalWsReader::next_frame` (read path) and `MinimalWsWriter::send_*`
    // (write path). There are no un-split read/write methods here by design.
}

/// Reader half — reads WebSocket frames with a pre-allocated buffer.
pub struct MinimalWsReader<S> {
    reader: ReadHalf<S>,
    read_buf: Vec<u8>,
}

impl<S: AsyncRead + Unpin> MinimalWsReader<S> {
    /// Read the next WebSocket frame into the caller-provided buffer.
    ///
    /// Returns the frame type and the number of payload bytes written to `out`.
    /// For Ping frames, call `send_pong` on the writer with `&out[..len]`.
    pub async fn next_frame(&mut self, out: &mut [u8]) -> Result<(FrameType, usize)> {
        loop {
            // Append new bytes from the TLS stream into the read buffer.
            // `read_buf` (bytes::BufMut) extends the Vec's length as it writes,
            // which is what we need. The previous code used `AsyncReadExt::read`
            // on `&mut self.read_buf`, which when the Vec was non-empty handed
            // the source an empty `[len..len]` slice, so it always returned
            // n == 0 and was misinterpreted as EOF. That made the tunnel never
            // establish a connection.
            let before = self.read_buf.len();
            self.reader.read_buf(&mut self.read_buf).await?;
            if self.read_buf.len() == before {
                // No new bytes: true EOF.
                anyhow::bail!("Connection closed (EOF)");
            }

            if self.read_buf.len() < 2 {
                continue;
            }

            let opcode = self.read_buf[0] & 0x0F;
            if self.read_buf[1] & 0x80 != 0 {
                anyhow::bail!("Server sent masked frame (protocol violation)");
            }

            let (payload_len, hdr_len) = match self.read_buf[1] & 0x7F {
                len @ 0..=125 => (len as usize, 2),
                126 => {
                    if self.read_buf.len() < 4 {
                        continue;
                    }
                    let len = u16::from_be_bytes([self.read_buf[2], self.read_buf[3]]) as usize;
                    (len, 4)
                }
                127 => {
                    if self.read_buf.len() < 10 {
                        continue;
                    }
                    let len = u64::from_be_bytes([
                        self.read_buf[2], self.read_buf[3], self.read_buf[4], self.read_buf[5],
                        self.read_buf[6], self.read_buf[7], self.read_buf[8], self.read_buf[9],
                    ]) as usize;
                    (len, 10)
                }
                _ => unreachable!("masked by 0x7F"),
            };

            let frame_end = hdr_len + payload_len;
            if self.read_buf.len() < frame_end {
                self.read_buf.reserve(frame_end - self.read_buf.len());
                continue;
            }

            if payload_len > out.len() {
                anyhow::bail!(
                    "Frame payload ({} bytes) exceeds output buffer ({} bytes)",
                    payload_len,
                    out.len()
                );
            }

            match opcode {
                0x02 => {
                    out[..payload_len]
                        .copy_from_slice(&self.read_buf[hdr_len..hdr_len + payload_len]);
                    self.read_buf.drain(..frame_end);
                    return Ok((FrameType::Binary, payload_len));
                }
                0x09 => {
                    out[..payload_len]
                        .copy_from_slice(&self.read_buf[hdr_len..hdr_len + payload_len]);
                    self.read_buf.drain(..frame_end);
                    return Ok((FrameType::Ping, payload_len));
                }
                0x08 => {
                    self.read_buf.drain(..frame_end);
                    return Ok((FrameType::Close, 0));
                }
                0x0A => {
                    self.read_buf.drain(..frame_end);
                    continue;
                }
                other => {
                    anyhow::bail!("Unsupported WebSocket opcode: 0x{:02X}", other);
                }
            }
        }
    }
}

/// Writer half — writes WebSocket frames to the TLS stream.
///
/// Per RFC 6455 §5.3, a client MUST mask every frame it sends. The masking key
/// is a fresh random 4 bytes per frame; the server unmasks by XORing the same
/// key. We reuse a single pre-allocated `mask_buf` (sized to `READ_BUF_SIZE`)
/// across frames so masking adds no per-frame heap allocation.
pub struct MinimalWsWriter<S> {
    writer: WriteHalf<S>,
    mask_buf: Vec<u8>,
}

impl<S: AsyncWrite + Unpin> MinimalWsWriter<S> {
    /// Send a binary WebSocket frame (client-masked, as required by RFC 6455).
    pub async fn send_binary(&mut self, data: &[u8]) -> Result<()> {
        self.write_frame(0x02, data).await
    }

    /// Send a WS Ping frame (client-masked). The server (tungstenite) will
    /// auto-respond with a pong. Used for WebSocket-level keepalive.
    pub async fn send_ping(&mut self, payload: &[u8]) -> Result<()> {
        self.write_frame(0x09, payload).await
    }

    /// Send a WS Pong frame echoing a ping payload (client-masked).
    pub async fn send_pong(&mut self, payload: &[u8]) -> Result<()> {
        self.write_frame(0x0A, payload).await
    }

    async fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<()> {
        // Fresh random masking key for this frame (RFC 6455 §5.3).
        let mut mask_key = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut mask_key);

        self.write_frame_header(opcode, payload.len()).await?;
        self.writer.write_all(&mask_key).await?;

        if payload.is_empty() {
            return Ok(());
        }

        // Mask the payload into the reusable scratch buffer, then send it in one
        // write. `resize` only sets length here (capacity was pre-allocated up to
        // READ_BUF_SIZE; the largest data batch is ~14 KB which fits), so this
        // does not allocate after the buffer reaches steady state.
        if self.mask_buf.len() < payload.len() {
            self.mask_buf.resize(payload.len(), 0);
        }
        let buf = &mut self.mask_buf[..payload.len()];
        buf.copy_from_slice(payload);
        apply_mask_inplace(buf, &mask_key, 0);
        self.writer.write_all(buf).await?;
        Ok(())
    }

    async fn write_frame_header(&mut self, opcode: u8, payload_len: usize) -> Result<()> {
        let byte0 = 0x80 | opcode; // FIN=1, opcode
        // Mask bit (byte1 bit 7) is ALWAYS set for client frames.
        if payload_len <= 125 {
            self.writer
                .write_all(&[byte0, 0x80 | payload_len as u8])
                .await?;
        } else if payload_len <= 65535 {
            let len_bytes = (payload_len as u16).to_be_bytes();
            self.writer
                .write_all(&[byte0, 0x80 | 126, len_bytes[0], len_bytes[1]])
                .await?;
        } else {
            let len_bytes = (payload_len as u64).to_be_bytes();
            let mut hdr = [0u8; 10];
            hdr[0] = byte0;
            hdr[1] = 0x80 | 127;
            hdr[2..10].copy_from_slice(&len_bytes);
            self.writer.write_all(&hdr).await?;
        }
        Ok(())
    }
}

// --- SHA-1 for WebSocket Accept validation ---

/// XOR `buf` in place with the repeating 4-byte masking key, starting at the
/// given absolute payload offset so chunked masking stays key-aligned.
/// Masking is its own inverse: applying it twice recovers the original.
/// (RFC 6455 §5.3)
fn apply_mask_inplace(buf: &mut [u8], mask_key: &[u8; 4], offset: usize) {
    let key_off = offset & 3;
    for (i, b) in buf.iter_mut().enumerate() {
        *b ^= mask_key[(key_off + i) & 3];
    }
}

#[allow(clippy::needless_range_loop)]
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let ml = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&ml.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for i in 0..20 {
            let temp = a
                .rotate_left(5)
                .wrapping_add((b & c) | (!b & d))
                .wrapping_add(e)
                .wrapping_add(0x5A827999)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for i in 20..40 {
            let temp = a
                .rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(0x6ED9EBA1)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for i in 40..60 {
            let temp = a
                .rotate_left(5)
                .wrapping_add((b & c) | (b & d) | (c & d))
                .wrapping_add(e)
                .wrapping_add(0x8F1BBCDC)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for i in 60..80 {
            let temp = a
                .rotate_left(5)
                .wrapping_add(b ^ c ^ d)
                .wrapping_add(e)
                .wrapping_add(0xCA62C1D6)
                .wrapping_add(w[i]);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

fn ws_accept_hash(key: &str) -> String {
    const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut data = key.to_string();
    data.push_str(WS_GUID);
    let hash = sha1(data.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha1_known() {
        let hash = sha1(b"");
        assert_eq!(
            hex(&hash),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn test_ws_accept() {
        // RFC 6455 example
        let accept = ws_accept_hash("dGhlIHNhbXBsZSBub25jZQ==");
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn test_mask_roundtrip() {
        let key = [0x37, 0xfa, 0x21, 0x8d];
        let original = b"Hello, WebSocket server!";
        let mut buf = original.to_vec();
        apply_mask_inplace(&mut buf, &key, 0);
        assert_ne!(buf.as_slice(), original.as_ref(), "masking must change data");
        apply_mask_inplace(&mut buf, &key, 0);
        assert_eq!(buf.as_slice(), original.as_ref(), "twice recovers original");
    }

    #[test]
    fn test_mask_key_alignment_across_chunks() {
        // Masking in two chunks must equal masking the whole in one pass.
        let key = [0xaa, 0xbb, 0xcc, 0xdd];
        let original: Vec<u8> = (0..100u32).map(|x| x as u8).collect();
        let mut whole = original.clone();
        apply_mask_inplace(&mut whole, &key, 0);

        let mut chunked = original.clone();
        apply_mask_inplace(&mut chunked[..7], &key, 0);
        apply_mask_inplace(&mut chunked[7..], &key, 7);
        assert_eq!(whole, chunked);
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
