// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of R-VPN.
//
// R-VPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Decoy static-file HTTP server.
//!
//! When `decoy_root` is configured, HTTPS requests that are not WebSocket
//! upgrades to a VPN path are answered with static files from the decoy
//! site, so an external prober sees a plausible website instead of a
//! connection that dies right after the TLS handshake (an active-probing
//! tell).
//!
//! The HTTP layer is deliberately minimal — hand-rolled request-head
//! parsing in the same style as `handle_http_port` in `main.rs`, no hyper.
//! Responses mimic an nginx static server (`Server: nginx/1.24.0`, IMF
//! dates, keep-alive).

use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::SystemTime;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::trace;

/// Maximum accepted HTTP request-head size. WebSocket handshakes and
/// browser requests are far below this; anything larger is a prober or a
/// broken client.
pub const MAX_HEADER_SIZE: usize = 16 * 1024;

/// Idle timeout for keep-alive connections waiting on the next request.
/// nginx defaults to 75s; matching it keeps the decoy believable.
const KEEPALIVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(75);

/// Decoy static site rooted at a configured directory.
pub struct DecoyServer {
    /// Canonicalized site root. Every served file must canonicalize to a
    /// path under this — the guard against symlink escapes.
    root: PathBuf,
}

/// Parsed HTTP request head (request line + the headers we care about).
pub struct RequestHead {
    /// HTTP method, e.g. `GET`.
    pub method: String,
    /// Raw request target, e.g. `/style.css?v=1`.
    pub target: String,
    /// Whether the connection should stay open after this request.
    pub keep_alive: bool,
    /// True when this is a well-formed WebSocket upgrade request.
    pub is_websocket_upgrade: bool,
    /// Bytes consumed by the head, including the terminating `\r\n\r\n`.
    pub header_len: usize,
}

/// Parse a complete-or-incomplete request head out of `buf`.
///
/// Returns `None` when the head is incomplete (no `\r\n\r\n` yet) or
/// malformed — callers distinguish the two by buffer length vs.
/// [`MAX_HEADER_SIZE`].
pub fn parse_request_head(buf: &[u8]) -> Option<RequestHead> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header_len = end + 4;
    let text = std::str::from_utf8(&buf[..end]).ok()?;
    let mut lines = text.split("\r\n");

    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();
    let version = parts.next()?;
    if parts.next().is_some() {
        return None; // junk after the version
    }
    let http11 = version.eq_ignore_ascii_case("HTTP/1.1");
    let http10 = version.eq_ignore_ascii_case("HTTP/1.0");
    if !http11 && !http10 {
        return None;
    }

    let mut connection_tokens = String::new();
    let mut upgrade_websocket = false;
    let mut has_ws_key = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue; // tolerate header lines without a colon
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("connection") {
            connection_tokens.push_str(value);
            connection_tokens.push(',');
        } else if name.eq_ignore_ascii_case("upgrade") {
            if value.eq_ignore_ascii_case("websocket") {
                upgrade_websocket = true;
            }
        } else if name.eq_ignore_ascii_case("sec-websocket-key") {
            has_ws_key = true;
        }
    }

    let has_token = |token: &str| {
        connection_tokens
            .split(',')
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    };
    let keep_alive = if http11 {
        !has_token("close")
    } else {
        has_token("keep-alive")
    };

    Some(RequestHead {
        method,
        target,
        keep_alive,
        is_websocket_upgrade: upgrade_websocket && has_token("upgrade") && has_ws_key,
        header_len,
    })
}

/// Map a request target to a safe relative filesystem path.
///
/// Defenses, in order:
/// - query string (`?...`) stripped;
/// - absolute-form targets (`http://host/path`) reduced to their path;
/// - percent-decoding applied exactly once (so `%2e%2e` becomes `..` and is
///   rejected, while `%252e` decodes to the literal filename `%2e`);
/// - any `..` segment, NUL byte, or backslash rejects the whole path;
/// - empty and `.` segments are dropped, so `//etc/passwd` and `/a/./b`
///   normalize inside the root.
///
/// Returns `None` for anything suspicious; the caller answers 404.
pub fn sanitize_url_path(target: &str) -> Option<PathBuf> {
    let path = target.split('?').next().unwrap_or("");
    let path = match path
        .strip_prefix("http://")
        .or_else(|| path.strip_prefix("https://"))
    {
        Some(rest) => match rest.find('/') {
            Some(i) => &rest[i..],
            None => "/",
        },
        None => path,
    };

    let decoded = percent_decode(path.as_bytes())?;
    let decoded = std::str::from_utf8(&decoded).ok()?;

    let mut rel = PathBuf::new();
    for segment in decoded.split('/') {
        match segment {
            "" | "." => continue,
            ".." => return None,
            s if s.contains('\0') || s.contains('\\') => return None,
            s => rel.push(s),
        }
    }
    Some(rel)
}

/// Decode `%XX` sequences. Returns `None` on a malformed escape (lone `%`
/// or non-hex digits) — treated as a bad request upstream.
fn percent_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            let hi = *input.get(i + 1)?;
            let lo = *input.get(i + 2)?;
            let hi = (hi as char).to_digit(16)?;
            let lo = (lo as char).to_digit(16)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    Some(out)
}

/// Content-Type for the extensions a static site realistically serves.
/// Hand-rolled — the workspace has no `mime_guess` dependency and this
/// map is intentionally exhaustive for decoy purposes.
fn content_type(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase());
    match ext.as_deref() {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") | Some("mjs") => "application/javascript",
        Some("json") => "application/json",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("webp") => "image/webp",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("otf") => "font/otf",
        Some("pdf") => "application/pdf",
        Some("wasm") => "application/wasm",
        Some("mp3") => "audio/mpeg",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        _ => "application/octet-stream",
    }
}

/// Format a timestamp as an IMF-fixdate (`Wed, 21 Oct 2015 07:28:00 GMT`).
fn http_date(t: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = t.into();
    dt.format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    }
}

/// A fully-resolved response ready to serialize.
struct FileResponse {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    last_modified: Option<SystemTime>,
}

impl DecoyServer {
    /// Create a decoy server rooted at `root`. The directory must exist.
    pub fn new(root: &Path) -> Result<Self> {
        let canonical = std::fs::canonicalize(root)?;
        if !canonical.is_dir() {
            anyhow::bail!("decoy_root {:?} is not a directory", root);
        }
        Ok(Self { root: canonical })
    }

    /// Serve HTTP requests on an established stream until the client
    /// closes, asks for `Connection: close`, errors, or the keep-alive
    /// idle timeout fires. `initial` carries bytes already read from the
    /// stream (the first request head, possibly with pipelined bytes).
    pub async fn serve<S>(&self, stream: &mut S, initial: Vec<u8>) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut buf = initial;
        let mut scratch = [0u8; 8192];

        loop {
            // Fill `buf` until a complete request head is available.
            let head = loop {
                if let Some(head) = parse_request_head(&buf) {
                    break head;
                }
                if buf.len() >= MAX_HEADER_SIZE {
                    let resp = self.error_response(431).await;
                    self.write_response(stream, &resp, false, true).await?;
                    return Ok(());
                }
                let read = tokio::time::timeout(KEEPALIVE_TIMEOUT, stream.read(&mut scratch)).await;
                match read {
                    Ok(Ok(0)) => return Ok(()), // client closed
                    Ok(Ok(n)) => buf.extend_from_slice(&scratch[..n]),
                    Ok(Err(e)) => return Err(e.into()),
                    Err(_) => return Ok(()), // keep-alive idle timeout
                }
            };

            let keep_alive = head.keep_alive;
            let method = head.method.clone();
            let header_len = head.header_len;

            let resp = if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
            {
                self.build_response(&head.target).await
            } else {
                // Methods other than GET/HEAD may carry a body we never
                // consumed, so keep-alive would desynchronize — answer 405
                // and close (handled by the early return below).
                self.error_response(405).await
            };

            let head_only = method.eq_ignore_ascii_case("HEAD");
            let force_close = resp.status == 405 || resp.status == 431;
            self.write_response(stream, &resp, head_only, force_close || !keep_alive)
                .await?;

            if force_close || !keep_alive {
                return Ok(());
            }
            buf.drain(..header_len);
        }
    }

    /// Resolve a request target to a response: the file under the root, or
    /// an error page. Never panics and never reveals whether a path exists
    /// outside the root — every failure is a plain 404 (or 403 for a
    /// directory without `index.html`).
    async fn build_response(&self, target: &str) -> FileResponse {
        let Some(rel) = sanitize_url_path(target) else {
            trace!("decoy: rejected target {:?}", target);
            return self.error_response(404).await;
        };

        let mut candidate = self.root.join(&rel);
        let mut meta = match tokio::fs::metadata(&candidate).await {
            Ok(m) => m,
            Err(_) => return self.error_response(404).await,
        };
        if meta.is_dir() {
            candidate = candidate.join("index.html");
            meta = match tokio::fs::metadata(&candidate).await {
                Ok(m) if m.is_file() => m,
                _ => return self.error_response(403).await,
            };
        } else if !meta.is_file() {
            return self.error_response(404).await;
        }

        // Symlink-escape guard: the resolved path must stay under the root.
        match tokio::fs::canonicalize(&candidate).await {
            Ok(canon) if canon.starts_with(&self.root) => {}
            _ => return self.error_response(404).await,
        }

        match tokio::fs::read(&candidate).await {
            Ok(body) => FileResponse {
                status: 200,
                content_type: content_type(&candidate),
                body,
                last_modified: meta.modified().ok(),
            },
            Err(_) => self.error_response(404).await,
        }
    }

    /// Build an error page. For 404, a `404.html` at the site root is used
    /// when present; otherwise an nginx-style default page is generated.
    async fn error_response(&self, status: u16) -> FileResponse {
        if status == 404 {
            let custom = self.root.join("404.html");
            let under_root = tokio::fs::canonicalize(&custom)
                .await
                .map(|c| c.starts_with(&self.root))
                .unwrap_or(false);
            if under_root {
                if let Ok(body) = tokio::fs::read(&custom).await {
                    return FileResponse {
                        status,
                        content_type: "text/html; charset=utf-8",
                        body,
                        last_modified: None,
                    };
                }
            }
        }

        let reason = reason_phrase(status);
        let body = format!(
            "<html>\r\n<head><title>{status} {reason}</title></head>\r\n<body>\r\n<center><h1>{status} {reason}</h1></center>\r\n<hr><center>nginx/1.24.0</center>\r\n</body>\r\n</html>\r\n"
        );
        FileResponse {
            status,
            content_type: "text/html; charset=utf-8",
            body: body.into_bytes(),
            last_modified: None,
        }
    }

    /// Serialize and write a response. `head_only` suppresses the body
    /// (HEAD requests); `close` selects the `Connection` header.
    async fn write_response<S>(
        &self,
        stream: &mut S,
        resp: &FileResponse,
        head_only: bool,
        close: bool,
    ) -> Result<()>
    where
        S: AsyncWrite + Unpin,
    {
        let mut head = format!(
            "HTTP/1.1 {} {}\r\nServer: nginx/1.24.0\r\nDate: {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
            resp.status,
            reason_phrase(resp.status),
            http_date(SystemTime::now()),
            resp.content_type,
            resp.body.len(),
        );
        if let Some(lm) = resp.last_modified {
            head.push_str(&format!("Last-Modified: {}\r\n", http_date(lm)));
        }
        if resp.status == 405 {
            head.push_str("Allow: GET, HEAD\r\n");
        }
        head.push_str(if close {
            "Connection: close\r\n\r\n"
        } else {
            "Connection: keep-alive\r\n\r\n"
        });

        stream.write_all(head.as_bytes()).await?;
        if !head_only {
            stream.write_all(&resp.body).await?;
        }
        stream.flush().await?;
        Ok(())
    }
}

/// Stream wrapper that replays `prefix` before delegating to the inner
/// stream. Used to hand a pre-read WebSocket handshake to tungstenite
/// without losing the bytes already consumed for path detection.
pub struct RewindStream<S> {
    prefix: std::io::Cursor<Vec<u8>>,
    inner: S,
}

impl<S> RewindStream<S> {
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: std::io::Cursor::new(prefix),
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for RewindStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let pos = self.prefix.position() as usize;
        if pos < self.prefix.get_ref().len() {
            let data = &self.prefix.get_ref()[pos..];
            let n = data.len().min(buf.remaining());
            buf.put_slice(&data[..n]);
            self.prefix.set_position((pos + n) as u64);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RewindStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn sanitize_str(target: &str) -> Option<String> {
        sanitize_url_path(target).map(|p| p.to_string_lossy().into_owned())
    }

    #[test]
    fn sanitize_basic_paths() {
        assert_eq!(sanitize_str("/"), Some("".to_string()));
        assert_eq!(sanitize_str("/index.html"), Some("index.html".to_string()));
        assert_eq!(sanitize_str("/a/b/c.png"), Some("a/b/c.png".to_string()));
        assert_eq!(
            sanitize_str("/style.css?v=123"),
            Some("style.css".to_string())
        );
        assert_eq!(sanitize_str("//etc/passwd"), Some("etc/passwd".to_string()));
        assert_eq!(sanitize_str("/a/./b"), Some("a/b".to_string()));
        assert_eq!(sanitize_str("/etc/passwd"), Some("etc/passwd".to_string()));
        // Absolute-form request target (proxied requests)
        assert_eq!(
            sanitize_str("http://example.com/x.html"),
            Some("x.html".to_string())
        );
        assert_eq!(sanitize_str("https://example.com"), Some("".to_string()));
    }

    #[test]
    fn sanitize_rejects_traversal() {
        assert!(sanitize_url_path("/../etc/passwd").is_none());
        assert!(sanitize_url_path("/foo/../../../bar").is_none());
        assert!(sanitize_url_path("..").is_none());
        assert!(sanitize_url_path("/..").is_none());
        // Percent-encoded traversal (decoded once, then rejected)
        assert!(sanitize_url_path("/%2e%2e/etc/passwd").is_none());
        assert!(sanitize_url_path("/%2E%2E/").is_none());
        assert!(sanitize_url_path("..%2f..%2fetc").is_none());
        assert!(sanitize_url_path("/%2e%2e%2f%2e%2e%2fetc/passwd").is_none());
    }

    #[test]
    fn sanitize_rejects_nul_and_backslash() {
        assert!(sanitize_url_path("/%00").is_none());
        assert!(sanitize_url_path("/a%00b").is_none());
        assert!(sanitize_url_path("/a%5cb").is_none());
        assert!(sanitize_url_path("/..\\..\\winnt").is_none());
    }

    #[test]
    fn sanitize_handles_encoding_edge_cases() {
        // Malformed percent escapes → rejected
        assert!(sanitize_url_path("/%zz").is_none());
        assert!(sanitize_url_path("/%2").is_none());
        // Double-encoding decodes once into a harmless literal filename
        assert_eq!(sanitize_str("/%252e%252e/x"), Some("%2e%2e/x".to_string()));
        // Encoded slash becomes a real separator, still inside the root
        assert_eq!(sanitize_str("/a%2fb"), Some("a/b".to_string()));
    }

    #[test]
    fn parse_head_detects_websocket_upgrade() {
        let req = b"GET /api/v1/ws HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let head = parse_request_head(req).expect("should parse");
        assert!(head.is_websocket_upgrade);
        assert_eq!(head.target, "/api/v1/ws");
        assert_eq!(head.header_len, req.len());
    }

    #[test]
    fn parse_head_plain_http() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let head = parse_request_head(req).expect("should parse");
        assert!(!head.is_websocket_upgrade);
        assert!(head.keep_alive); // HTTP/1.1 default

        let req = b"GET / HTTP/1.0\r\n\r\n";
        let head = parse_request_head(req).expect("should parse");
        assert!(!head.keep_alive); // HTTP/1.0 default

        let req = b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
        let head = parse_request_head(req).expect("should parse");
        assert!(!head.keep_alive);

        // Incomplete head → None
        assert!(parse_request_head(b"GET / HTTP/1.1\r\nHost: x\r\n").is_none());
        // Garbage → None
        assert!(parse_request_head(b"garbage\r\n\r\n").is_none());
    }

    /// Spin up a DecoyServer on a loopback listener, return its address.
    async fn spawn_decoy(root: &Path) -> std::net::SocketAddr {
        let server = DecoyServer::new(root).expect("decoy root");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let server = std::sync::Arc::new(server);
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, _)) => {
                        let server = server.clone();
                        tokio::spawn(async move {
                            let _ = server.serve(&mut stream, Vec::new()).await;
                        });
                    }
                    Err(_) => break,
                }
            }
        });
        addr
    }

    /// Send one raw request, read the full response (server must close).
    async fn raw_http(addr: std::net::SocketAddr, request: &str) -> String {
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
            .await
            .expect("read timeout")
            .expect("read response");
        String::from_utf8_lossy(&out).into_owned()
    }

    fn fixture_root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("index.html"), "<h1>hello decoy</h1>").expect("index");
        std::fs::write(dir.path().join("style.css"), "body{}").expect("css");
        std::fs::write(dir.path().join("404.html"), "<h1>custom not found</h1>").expect("404");
        std::fs::create_dir(dir.path().join("emptydir")).expect("emptydir");
        std::fs::create_dir(dir.path().join("subdir")).expect("subdir");
        std::fs::write(dir.path().join("subdir").join("index.html"), "sub").expect("sub index");
        dir
    }

    #[tokio::test]
    async fn serves_index_on_root() {
        let dir = fixture_root();
        let addr = spawn_decoy(dir.path()).await;
        let resp = raw_http(
            addr,
            "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "got: {resp:?}");
        assert!(resp.contains("Content-Type: text/html; charset=utf-8\r\n"));
        assert!(resp.contains("Content-Length: 20\r\n"));
        assert!(resp.contains("Last-Modified: "));
        assert!(resp.ends_with("<h1>hello decoy</h1>"));
    }

    #[tokio::test]
    async fn serves_files_with_correct_content_type() {
        let dir = fixture_root();
        let addr = spawn_decoy(dir.path()).await;
        let resp = raw_http(
            addr,
            "GET /style.css HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "got: {resp:?}");
        assert!(resp.contains("Content-Type: text/css; charset=utf-8\r\n"));
        assert!(resp.ends_with("body{}"));
    }

    #[tokio::test]
    async fn head_request_has_headers_but_no_body() {
        let dir = fixture_root();
        let addr = spawn_decoy(dir.path()).await;
        let resp = raw_http(
            addr,
            "HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "got: {resp:?}");
        assert!(resp.contains("Content-Length: 20\r\n"));
        assert!(!resp.contains("<h1>hello decoy</h1>"));
        assert!(resp.ends_with("\r\n\r\n"));
    }

    #[tokio::test]
    async fn missing_file_serves_custom_404() {
        let dir = fixture_root();
        let addr = spawn_decoy(dir.path()).await;
        let resp = raw_http(
            addr,
            "GET /nope.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            resp.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "got: {resp:?}"
        );
        assert!(resp.ends_with("<h1>custom not found</h1>"));
    }

    #[tokio::test]
    async fn directory_without_index_is_403() {
        let dir = fixture_root();
        let addr = spawn_decoy(dir.path()).await;
        let resp = raw_http(
            addr,
            "GET /emptydir/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            resp.starts_with("HTTP/1.1 403 Forbidden\r\n"),
            "got: {resp:?}"
        );
    }

    #[tokio::test]
    async fn directory_with_index_is_served() {
        let dir = fixture_root();
        let addr = spawn_decoy(dir.path()).await;
        let resp = raw_http(
            addr,
            "GET /subdir HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "got: {resp:?}");
        assert!(resp.ends_with("sub"));
    }

    #[tokio::test]
    async fn non_get_methods_are_405() {
        let dir = fixture_root();
        let addr = spawn_decoy(dir.path()).await;
        let resp = raw_http(
            addr,
            "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        assert!(
            resp.starts_with("HTTP/1.1 405 Method Not Allowed\r\n"),
            "got: {resp:?}"
        );
        assert!(resp.contains("Allow: GET, HEAD\r\n"));
    }

    #[tokio::test]
    async fn traversal_attempts_get_404_and_no_leak() {
        let dir = fixture_root();
        let addr = spawn_decoy(dir.path()).await;
        for target in [
            "/../../etc/passwd",
            "/%2e%2e/%2e%2e/etc/passwd",
            "/..%2f..%2fetc/passwd",
            "/....//....//etc/passwd",
        ] {
            let req = format!("GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
            let resp = raw_http(addr, &req).await;
            assert!(
                resp.starts_with("HTTP/1.1 404 Not Found\r\n"),
                "target {target:?} got: {resp:?}"
            );
            assert!(
                !resp.contains("root:"),
                "target {target:?} leaked /etc/passwd"
            );
        }
    }

    #[tokio::test]
    async fn keep_alive_serves_multiple_requests() {
        let dir = fixture_root();
        let addr = spawn_decoy(dir.path()).await;
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(
                b"GET /style.css HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
            )
            .await
            .expect("write");
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
            .await
            .expect("read timeout")
            .expect("read");
        let resp = String::from_utf8_lossy(&out);
        assert_eq!(resp.matches("HTTP/1.1 200 OK").count(), 2, "got: {resp:?}");
        assert!(resp.contains("body{}"));
        assert!(resp.contains("<h1>hello decoy</h1>"));
        assert!(resp.contains("Connection: keep-alive\r\n"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn symlink_escaping_root_is_404() {
        let dir = fixture_root();
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("link")).expect("symlink");
        let addr = spawn_decoy(dir.path()).await;
        let resp = raw_http(
            addr,
            "GET /link HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        )
        .await;
        assert!(
            resp.starts_with("HTTP/1.1 404 Not Found\r\n"),
            "got: {resp:?}"
        );
        assert!(!resp.contains("root:"));
    }

    #[tokio::test]
    async fn rewind_stream_replays_prefix_then_inner() {
        let (a, mut b) = tokio::io::duplex(64);
        let mut stream = RewindStream::new(b"hello ".to_vec(), a);
        tokio::spawn(async move {
            b.write_all(b"world").await.expect("write");
        });
        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.expect("read");
        assert_eq!(out, b"hello world");
    }
}
