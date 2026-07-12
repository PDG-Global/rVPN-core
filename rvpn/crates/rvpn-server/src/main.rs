// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// R-VPN Server - HTTP/WebSocket server with optional TLS
//
// This server handles HTTP/WebSocket connections:
// - Direct TLS mode: Uses rustls with provided certificates
// - Behind proxy mode: Plain WebSocket (TLS terminated by Caddy/nginx)
// - HTTP decoy on port 80 (optional)

extern crate rvpn_server;

// Use config from the library crate
use rvpn_server::config::{ServerConfig, TunNetworkConfig};

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context as _, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use rvpn_server::handler::{DnsHandler, MultiplexerHandler, TunHandler, VpnHandler};

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args();

    // Setup logging
    let log_level = match args.verbose {
        0 => Level::INFO,
        1 => Level::DEBUG,
        _ => Level::TRACE,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("R-VPN Server v{}", env!("CARGO_PKG_VERSION"));

    if args.help {
        print_help();
        return Ok(());
    }

    // Load configuration
    let config = load_config(&args.config).await;
    let mut config = config;
    if let Some(bind) = args.bind {
        config.bind_address = bind;
    }

    // Handle commands
    if let Some(cmd) = args.command {
        match cmd.as_str() {
            "keygen" => return keygen(&config, args.output),
            "prekey-bundle" => {
                return prekey_bundle(
                    &config,
                    args.identity,
                    args.output,
                    args.rotate_from,
                    args.from_version,
                )
            }
            _ => {}
        }
    }

    run_server(config).await
}

/// Run the VPN server
async fn run_server(config: ServerConfig) -> Result<()> {
    info!("Starting R-VPN Server on {}", config.bind_address);
    verify_tun_network_prerequisites(&config);

    // Initialize TUN server if configured (must be done before creating handlers)
    let tun_server = rvpn_server::tun_server::TunServer::new(&config.tun)?;
    // Always wrap in Arc for uniform handling
    let tun_server = Arc::new(RwLock::new(tun_server));
    let tun_server_for_loop = tun_server.clone();

    if config.tun.enabled {
        {
            let mut ts = tun_server_for_loop.write().await;
            ts.start().await?;
        }
        setup_tun_routing(&config.tun)?;
        info!("TUN server started on {}", config.tun.tun_ip);
    }

    let handler = Arc::new(RwLock::new(VpnHandler::new(config.clone())?));
    let tun_handler = Arc::new(RwLock::new(TunHandler::new(config.clone(), Some(tun_server.clone()))?));
    let dns_handler = Arc::new(RwLock::new(DnsHandler::new(config.clone())?));
    let mux_handler = Arc::new(RwLock::new(MultiplexerHandler::new(config.clone())?));

    // Path for TUN-mode mobile connections
    let tun_path = format!("{}/tun", config.websocket_path.trim_end_matches('/'));
    // Path for DNS-over-WebSocket connections
    let dns_path = format!("{}/dns", config.websocket_path.trim_end_matches('/'));
    // Path for SOCKS5 multiplexed connections (single WebSocket, multiple flows)
    let mux_path = format!("{}/mux", config.websocket_path.trim_end_matches('/'));

    let addr: SocketAddr = config.bind_address.parse()
        .context("Invalid bind address")?;

    // Check if TLS is configured — either static cert files or automatic
    // ACME (mutually exclusive, checked in configure_tls).
    let tls_acceptor = configure_tls(&config).await
        .context("Failed to configure TLS")?;

    let listener = TcpListener::bind(addr).await
        .context("Failed to bind")?;

    let protocol = if tls_acceptor.is_some() { "wss" } else { "ws" };
    info!("Server listening on {}://{}", protocol, addr);
    info!("WebSocket endpoint: {}", config.websocket_path);
    info!("WebSocket endpoint (desktop SOCKS): /api/v1/ws");
    info!("WebSocket endpoint (mobile TUN): {}", tun_path);
    info!("WebSocket endpoint (DNS proxy): {}", dns_path);
    info!("WebSocket endpoint (SOCKS5 mux): {}", mux_path);

    // Spawn HTTP server on port 80 if configured
    if let Some(http_port) = config.http_port {
        let http_addr: SocketAddr = format!("0.0.0.0:{}", http_port)
            .parse()
            .context("Invalid HTTP bind address")?;
        
        match TcpListener::bind(http_addr).await {
            Ok(http_listener) => {
                info!("HTTP server listening on http://{}", http_listener.local_addr()?);
                
                let redirect_https = config.redirect_http_to_https;
                tokio::spawn(async move {
                    loop {
                        match http_listener.accept().await {
                            Ok((stream, peer_addr)) => {
                                tokio::spawn(async move {
                                    if let Err(e) = handle_http_port(stream, peer_addr, redirect_https).await {
                                        debug!("HTTP error from {}: {}", peer_addr, e);
                                    }
                                });
                            }
                            Err(e) => {
                                warn!("HTTP accept error: {}", e);
                            }
                        }
                    }
                });
            }
            Err(e) => {
                warn!("Failed to bind HTTP port {}: {}", http_port, e);
            }
        }
    }

    info!("WebSocket endpoint (desktop SOCKS): {}", config.websocket_path);
    info!("WebSocket endpoint (mobile TUN): {}", tun_path);
    info!("WebSocket endpoint (DNS proxy): {}", dns_path);

    // Accept connections
    loop {
        let (stream, peer_addr) = listener.accept().await
            .context("Failed to accept connection")?;

        let handler = handler.clone();
        let tun_handler = tun_handler.clone();
        let dns_handler = dns_handler.clone();
        let mux_handler = mux_handler.clone();
        let tun_server = tun_server.clone();
        let ws_path = config.websocket_path.clone();
        let tun_path = tun_path.clone();
        let dns_path = dns_path.clone();
        let mux_path = mux_path.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, peer_addr, handler, tun_handler, dns_handler, mux_handler, tun_server, ws_path, tun_path, dns_path, mux_path, tls_acceptor).await {
                debug!("Connection error from {}: {}", peer_addr, e);
            }
        });
    }
}

/// Setup kernel routing for TUN interface
fn setup_tun_routing(config: &TunNetworkConfig) -> Result<()> {
    use std::process::Command;

    // Parse CIDR and calculate actual network address (e.g., "10.200.0.1/24" -> "10.200.0.0/24")
    let parts: Vec<&str> = config.tun_ip.split('/').collect();
    let ip_str = parts.first().unwrap();
    let prefix: u8 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(24);

    let ip: std::net::Ipv4Addr = ip_str.parse()
        .with_context(|| format!("Invalid IP: {}", ip_str))?;

    let ip_u32 = u32::from(ip);
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    let network_u32 = ip_u32 & mask;

    let network = format!(
        "{}/{}",
        std::net::Ipv4Addr::from(network_u32),
        prefix
    );

    // Add route to TUN network via TUN interface
    let output = Command::new("ip")
        .args(["route", "add", &network, "dev", &config.interface_name])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Don't fail if route already exists
        if !stderr.contains("File exists") {
            anyhow::bail!("Failed to add route: {}", stderr);
        }
    }

    info!("Added route for {} via {}", network, config.interface_name);
    Ok(())
}

fn verify_tun_network_prerequisites(config: &ServerConfig) {
    if !config.network.nat_enabled {
        warn!("server.network.nat_enabled is false; full-tunnel Internet egress will require external routing");
        return;
    }

    if cfg!(target_os = "linux") {
        match std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
            Ok(v) => {
                if v.trim() != "1" {
                    warn!("net.ipv4.ip_forward is disabled; enable it for full-tunnel packet forwarding");
                } else {
                    info!("Kernel IPv4 forwarding is enabled");
                }
            }
            Err(e) => warn!("Unable to read /proc/sys/net/ipv4/ip_forward: {}", e),
        }
    }

    match detect_default_interface() {
        Some(iface) => {
            if !has_nat_masquerade_rule(&iface, &config.network.dhcp_range) {
                warn!(
                    "NAT MASQUERADE rule appears missing for subnet {} via interface {}; full-tunnel Internet access may fail",
                    config.network.dhcp_range, iface
                );
            } else {
                info!(
                    "Detected NAT MASQUERADE rule for subnet {} via interface {}",
                    config.network.dhcp_range, iface
                );
            }
        }
        None => warn!("Could not detect default egress interface; verify NAT MASQUERADE setup manually"),
    }
}

fn detect_default_interface() -> Option<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i==\"dev\"){print $(i+1); exit}}'")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let iface = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if iface.is_empty() {
        None
    } else {
        Some(iface)
    }
}

fn has_nat_masquerade_rule(interface: &str, subnet: &str) -> bool {
    let cmd = format!(
        "iptables -t nat -C POSTROUTING -s {} -o {} -j MASQUERADE >/dev/null 2>&1",
        subnet, interface
    );
    if let Ok(status) = Command::new("sh").arg("-c").arg(&cmd).status() {
        if status.success() {
            return true;
        }
    }

    let legacy_cmd = format!(
        "iptables -t nat -S POSTROUTING 2>/dev/null | grep -q -- '-s {} -o {} -j MASQUERADE'",
        subnet, interface
    );
    Command::new("sh")
        .arg("-c")
        .arg(&legacy_cmd)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Server TLS front-end. Either a static rustls acceptor, or the pair of
/// ACME configs (challenge vs default) that `LazyConfigAcceptor` picks
/// between per-handshake by inspecting the ClientHello ALPN list.
#[derive(Clone)]
enum RvpnTlsAcceptor {
    Static(tokio_rustls::TlsAcceptor),
    Acme {
        challenge: Arc<rustls::ServerConfig>,
        default: Arc<rustls::ServerConfig>,
    },
}

impl RvpnTlsAcceptor {
    /// Complete a TLS handshake. Returns `Ok(Some(stream))` for a normal
    /// TLS session the caller should hand off to WebSocket upgrade;
    /// returns `Ok(None)` if the ClientHello was an ACME TLS-ALPN-01
    /// challenge (already completed and shut down here) — caller should
    /// just drop the connection.
    async fn accept(
        &self,
        stream: tokio::net::TcpStream,
    ) -> Result<Option<Box<dyn AsyncReadWrite + Send + Unpin>>> {
        match self {
            RvpnTlsAcceptor::Static(acceptor) => {
                let tls = acceptor.accept(stream).await?;
                Ok(Some(Box::new(tls)))
            }
            RvpnTlsAcceptor::Acme { challenge, default } => {
                use rustls_acme::is_tls_alpn_challenge;
                use tokio_rustls::LazyConfigAcceptor;
                let start = LazyConfigAcceptor::new(Default::default(), stream).await?;
                if is_tls_alpn_challenge(&start.client_hello()) {
                    debug!("ACME TLS-ALPN-01 challenge handshake");
                    let mut tls = start.into_stream(Arc::clone(challenge)).await?;
                    tokio::io::AsyncWriteExt::shutdown(&mut tls).await.ok();
                    Ok(None)
                } else {
                    let tls = start.into_stream(Arc::clone(default)).await?;
                    Ok(Some(Box::new(tls)))
                }
            }
        }
    }
}

/// Configure TLS for the server. Three exclusive branches:
///
/// - `[acme].enabled = true` → obtain and auto-renew a Let's Encrypt cert
///   via TLS-ALPN-01 on the existing `:443` listener. No `:80` needed.
/// - `tls_cert_file` + `tls_key_file` present on disk → static cert path.
/// - Neither → run in plain-WebSocket mode (reverse proxy expected).
///
/// Refuses at startup if both ACME and a static cert are configured, so
/// there's exactly one authority for the served certificate.
async fn configure_tls(config: &ServerConfig) -> Result<Option<RvpnTlsAcceptor>> {
    let static_cert_present = config.tls_cert_file.exists() && config.tls_key_file.exists();

    if config.acme.enabled {
        if static_cert_present {
            anyhow::bail!(
                "[acme].enabled=true but static TLS cert files also exist at {:?} / {:?}. \
                 Move or remove them, or disable [acme] — the server won't guess which to serve.",
                config.tls_cert_file, config.tls_key_file
            );
        }
        return Ok(Some(build_acme_acceptor(&config.acme).await?));
    }

    if static_cert_present {
        info!("Loading TLS certificates...");
        match load_tls_config(&config.tls_cert_file, &config.tls_key_file) {
            Ok(tls_config) => {
                info!("TLS enabled on {}", config.bind_address);
                Ok(Some(RvpnTlsAcceptor::Static(
                    tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)),
                )))
            }
            Err(e) => {
                warn!("Failed to load TLS certificates: {}. Running without TLS.", e);
                Ok(None)
            }
        }
    } else {
        info!("No TLS certificates configured. Running in plain WebSocket mode (suitable for behind reverse proxy)");
        Ok(None)
    }
}

/// Build a `tokio_rustls::TlsAcceptor` backed by `rustls-acme`.
///
/// The same `:443` listener handles both live traffic and the TLS-ALPN-01
/// challenge: rustls sees the `acme-tls/1` ALPN, calls the ACME resolver,
/// which returns the challenge cert. A background task drives renewals.
async fn build_acme_acceptor(
    acme: &rvpn_server::config::AcmeConfig,
) -> Result<RvpnTlsAcceptor> {
    use futures_util::StreamExt as _;
    use rustls_acme::{caches::DirCache, AcmeConfig as RustlsAcmeConfig};

    if acme.domains.is_empty() {
        anyhow::bail!(
            "[acme].enabled=true but no [acme].domains listed — set at least one FQDN"
        );
    }

    tokio::fs::create_dir_all(&acme.cache_dir).await.with_context(|| {
        format!(
            "Failed to create ACME cache directory {:?} — the account key and certs must persist across restarts",
            acme.cache_dir
        )
    })?;

    // Fresh install into production is the one situation where a config
    // mistake burns through Let's Encrypt's 5-failed-authorizations-per-hour
    // budget in minutes. Warn loudly at exactly that moment.
    let cache_is_empty = acme_cache_is_empty(&acme.cache_dir).await;
    info!(
        "ACME: requesting Let's Encrypt {} cert for {:?}; cache at {:?}",
        if acme.staging { "STAGING" } else { "production" },
        acme.domains,
        acme.cache_dir
    );
    if acme.staging {
        warn!("ACME staging directory in use — certificates will not be trusted by browsers");
    } else if cache_is_empty {
        warn!(
            "ACME: first-time production issuance for {:?}. If the TLS-ALPN-01 challenge fails 5 times \
             in an hour, Let's Encrypt locks this hostname out for 60 minutes. If you're setting this up \
             for the first time, consider `[server.acme].staging = true` first — staging has no rate limits.",
            acme.domains
        );
    }

    let mut state = RustlsAcmeConfig::new(acme.domains.clone())
        .contact(acme.contacts.iter().cloned())
        .cache(DirCache::new(acme.cache_dir.clone()))
        .directory_lets_encrypt(!acme.staging)
        .state();

    // rustls-acme needs TWO ServerConfigs:
    // - `challenge_rustls_config` advertises `acme-tls/1` in ALPN and is
    //   used only when the incoming ClientHello has that ALPN listed.
    //   The dispatch happens in `RvpnTlsAcceptor::accept`.
    // - `default_rustls_config` is the normal-traffic path and shares the
    //   same resolver, so once ACME finishes issuance the real cert is
    //   served here without a restart.
    let challenge = state.challenge_rustls_config();
    let default = state.default_rustls_config();

    // Drive the ACME state machine forever: handles the initial issuance,
    // TLS-ALPN-01 challenges, and periodic renewal. Errors are logged and
    // the loop keeps going — a transient LE failure shouldn't kill TLS.
    tokio::spawn(async move {
        loop {
            match state.next().await {
                Some(Ok(ok)) => info!("ACME event: {:?}", ok),
                Some(Err(err)) => {
                    // Downgrade Let's Encrypt rate-limit responses from
                    // ERROR to a single WARN. rustls-acme retries with its
                    // own backoff; the raw Debug prints of the whole error
                    // chain add noise without changing behavior.
                    let msg = format!("{:?}", err);
                    if let Some(retry) = parse_acme_rate_limit(&msg) {
                        warn!(
                            "ACME rate-limited by Let's Encrypt; next retry allowed after {} \
                             (see https://letsencrypt.org/docs/rate-limits/)",
                            retry
                        );
                    } else {
                        error!("ACME error: {}", msg);
                    }
                }
                None => {
                    warn!("ACME state stream ended; no further renewals will run");
                    break;
                }
            }
        }
    });

    Ok(RvpnTlsAcceptor::Acme { challenge, default })
}

/// Return true if the ACME cache directory holds no files. Used to detect
/// first-time issuance so the operator gets a rate-limit heads-up before
/// their first production attempt.
async fn acme_cache_is_empty(dir: &PathBuf) -> bool {
    match tokio::fs::read_dir(dir).await {
        Ok(mut entries) => matches!(entries.next_entry().await, Ok(None)),
        // Nonexistent or unreadable → treat as empty so we still warn.
        Err(_) => true,
    }
}

/// If `msg` contains a Let's Encrypt rate-limit response (HTTP 429 with a
/// `retry after <timestamp>` phrase), return the parsed timestamp string.
/// Very deliberately a substring scan rather than a JSON parse — the
/// exact error shape is a private rustls-acme detail and we only need
/// the retry-after hint to make the log line useful.
fn parse_acme_rate_limit(msg: &str) -> Option<String> {
    if !msg.contains("rateLimited") && !msg.contains("status_code: 429") {
        return None;
    }
    let idx = msg.find("retry after ")?;
    let rest = &msg[idx + "retry after ".len()..];
    // Timestamp shape: `2026-07-11 06:01:16 UTC` — terminated by `: see`
    // (LE's message continues with a link) or `\\n` in the JSON-escaped
    // body. Split on either boundary and take the first ~40 chars.
    let end = rest
        .find(": see")
        .or_else(|| rest.find("\\n"))
        .unwrap_or_else(|| rest.len().min(40));
    Some(rest[..end].trim().trim_end_matches(['"', '\\', ',']).to_string())
}

#[cfg(test)]
mod acme_tests {
    use super::parse_acme_rate_limit;

    #[test]
    fn parses_le_rate_limit_retry_after() {
        let msg = "Order(Acme(HttpRequest(Non2xxStatus { status_code: 429, body: \"{ \\\"type\\\": \\\"urn:ietf:params:acme:error:rateLimited\\\", \\\"detail\\\": \\\"too many failed authorizations (5) for \\\\\\\"003.hk.97688.io\\\\\\\" in the last 1h0m0s, retry after 2026-07-11 06:01:16 UTC: see https://letsencrypt.org/docs/rate-limits/\\\" }\" }))";
        assert_eq!(
            parse_acme_rate_limit(msg).as_deref(),
            Some("2026-07-11 06:01:16 UTC")
        );
    }

    #[test]
    fn returns_none_on_normal_error() {
        assert_eq!(parse_acme_rate_limit("some other error"), None);
    }
}

/// Load TLS configuration from certificate files
fn load_tls_config(cert_path: &PathBuf, key_path: &PathBuf) -> Result<rustls::ServerConfig> {
    use rustls_pemfile::{certs, private_key};
    
    // Load certificates
    let cert_file = std::fs::read(cert_path)
        .with_context(|| format!("Failed to read certificate file: {:?}", cert_path))?;
    let cert_reader = &mut std::io::Cursor::new(cert_file);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> = certs(cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificates")?;
    
    if certs.is_empty() {
        anyhow::bail!("No certificates found in {:?}", cert_path);
    }
    
    // Load private key
    let key_file = std::fs::read(key_path)
        .with_context(|| format!("Failed to read key file: {:?}", key_path))?;
    let key_reader = &mut std::io::Cursor::new(key_file);
    let key = private_key(key_reader)
        .context("Failed to parse private key")?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {:?}", key_path))?;
    
    // Build TLS config
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to create TLS config")?;
    
    Ok(config)
}

/// Handle HTTP requests on port 80
async fn handle_http_port(
    mut stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    redirect_https: bool,
) -> Result<()> {
    debug!("Handling HTTP request from {}", peer_addr);
    
    // Read the HTTP request
    let mut buffer = vec![0u8; 8192];
    let mut total_read = 0;
    
    loop {
        let n = stream.read(&mut buffer[total_read..]).await?;
        if n == 0 {
            return Ok(());
        }
        total_read += n;
        
        if buffer[..total_read].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        
        if total_read >= buffer.len() {
            return Ok(());
        }
    }
    
    let request = String::from_utf8_lossy(&buffer[..total_read]);
    
    // Check for ACME challenge
    if request.contains("/.well-known/acme-challenge/") {
        let lines: Vec<&str> = request.lines().collect();
        if let Some(first_line) = lines.first() {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 {
                let path = parts[1];
                if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
                    let body = format!("rvpn-acme-challenge-{}", token);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(response.as_bytes()).await?;
                    return Ok(());
                }
            }
        }
    }
    
    // Extract Host header from request
    let host = request.lines()
        .find(|line| line.to_lowercase().starts_with("host:"))
        .and_then(|line| line.split_once(':').map(|x| x.1))
        .map(|h| h.trim())
        .unwrap_or("localhost");
    
    // Redirect to HTTPS or serve decoy
    if redirect_https {
        let response = format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: https://{}\r\nContent-Length: 0\r\n\r\n",
            host
        );
        stream.write_all(response.as_bytes()).await?;
    } else {
        // Serve decoy
        let body = "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.24.0</center></body></html>";
        let response = format!(
            "HTTP/1.1 404 Not Found\r\nServer: nginx/1.24.0\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await?;
    }
    
    Ok(())
}

/// Handle a single TCP connection
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    handler: Arc<RwLock<VpnHandler>>,
    tun_handler: Arc<RwLock<TunHandler>>,
    dns_handler: Arc<RwLock<DnsHandler>>,
    mux_handler: Arc<RwLock<MultiplexerHandler>>,
    _tun_server: Arc<tokio::sync::RwLock<rvpn_server::tun_server::TunServer>>,
    ws_path: String,
    tun_path: String,
    dns_path: String,
    mux_path: String,
    tls_acceptor: Option<RvpnTlsAcceptor>,
) -> Result<()> {
    // If TLS is configured, do TLS handshake first. In ACME mode the
    // acceptor may consume the ClientHello as a TLS-ALPN-01 challenge —
    // that's `Ok(None)`, and we're done with this connection.
    let stream: Box<dyn AsyncReadWrite + Send + Unpin> = if let Some(acceptor) = tls_acceptor {
        match acceptor.accept(stream).await {
            Ok(Some(tls_stream)) => {
                info!("TLS handshake successful from {}", peer_addr);
                tls_stream
            }
            Ok(None) => {
                // ACME challenge already completed inside accept().
                return Ok(());
            }
            Err(e) => {
                debug!("TLS handshake failed from {}: {}", peer_addr, e);
                return Ok(());
            }
        }
    } else {
        Box::new(stream)
    };
    
    // Try WebSocket upgrade with path detection
    debug!("Attempting WebSocket upgrade for {}", peer_addr);

    // Track the request path using std::sync::Mutex since the callback is synchronous
    let request_path = Arc::new(std::sync::Mutex::new(String::new()));
    let request_path_clone = request_path.clone();

    let callback = move |req: &tokio_tungstenite::tungstenite::handshake::server::Request, response: tokio_tungstenite::tungstenite::handshake::server::Response| {
        // Extract the path from the request URI
        let path = req.uri().path().to_string();
        if let Ok(mut guard) = request_path_clone.lock() {
            *guard = path;
        }
        Ok(response)
    };
    
    let ws_result = tokio_tungstenite::accept_hdr_async(stream, callback).await;
    
    match ws_result {
        Ok(ws) => {
            // WebSocket upgrade successful
            let path = request_path.lock().unwrap().clone();
            info!("WebSocket upgrade accepted from {} on path: {}", peer_addr, path);
            
            // Route based on path
            if path == tun_path || path.starts_with(&format!("{}/", tun_path)) {
                if let Err(e) = tun_handler.read().await.handle_connection(ws, peer_addr).await {
                    debug!("TUN handler error for {}: {}", peer_addr, e);
                }
            } else if path == dns_path || path.starts_with(&format!("{}/", dns_path)) {
                if let Err(e) = dns_handler.read().await.handle_connection(ws, peer_addr).await {
                    debug!("DNS handler error for {}: {}", peer_addr, e);
                }
            } else if path == mux_path || path.starts_with(&format!("{}/", mux_path)) {
                // SOCKS5 multiplexed connection: single WebSocket, multiple TCP flows
                if let Err(e) = mux_handler.read().await.handle_connection(ws, peer_addr, None, rvpn_server::config::TunNetworkConfig::default()).await {
                    debug!("MUX handler error for {}: {}", peer_addr, e);
                }
            } else if path == ws_path || path == format!("{}/", ws_path.trim_end_matches('/')) {
                if let Err(e) = handler.read().await.handle_ws_connection(ws, peer_addr).await {
                    debug!("Handler error for {}: {}", peer_addr, e);
                }
            } else {
                // Unknown path - close connection
                warn!("WebSocket connection on unknown path '{}' from {}", path, peer_addr);
            }
            
            info!("Connection from {} closed", peer_addr);
        }
        Err(e) => {
            // Not a WebSocket - handle as HTTP
            debug!("Not a WebSocket from {}: {}", peer_addr, e);
        }
    }
    
    Ok(())
}

// Helper trait for type erasure
trait AsyncReadWrite: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T> AsyncReadWrite for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}

#[derive(Debug)]
struct Args {
    config: PathBuf,
    bind: Option<String>,
    command: Option<String>,
    identity: Option<PathBuf>,
    output: Option<PathBuf>,
    /// `prekey-bundle --rotate-from <path>`: path to the *previous* identity
    /// key file. When present, the new bundle carries a rotation signature
    /// authored by that previous identity, letting already-pinned clients
    /// silently accept the new identity.
    rotate_from: Option<PathBuf>,
    /// `prekey-bundle --from-version N`: the version number the previous
    /// bundle published. The new bundle will carry `N + 1`. Required when
    /// `--rotate-from` is set. See dev_docs/specs/TOFU_FINGERPRINT.md §6.
    from_version: Option<u32>,
    verbose: u8,
    help: bool,
}

fn parse_args() -> Args {
    let mut args = Args {
        config: PathBuf::from("server.toml"),
        bind: None,
        command: None,
        identity: None,
        output: None,
        rotate_from: None,
        from_version: None,
        verbose: 0,
        help: false,
    };

    let argv: Vec<String> = std::env::args().collect();
    let mut i = 1;

    while i < argv.len() {
        match argv[i].as_str() {
            "-c" | "--config" => {
                i += 1;
                if i < argv.len() {
                    args.config = PathBuf::from(&argv[i]);
                }
            }
            "-b" | "--bind" => {
                i += 1;
                if i < argv.len() {
                    args.bind = Some(argv[i].clone());
                }
            }
            "-v" | "--verbose" => args.verbose += 1,
            "-h" | "--help" => args.help = true,
            "keygen" => args.command = Some("keygen".to_string()),
            "prekey-bundle" => args.command = Some("prekey-bundle".to_string()),
            "--identity" => {
                i += 1;
                if i < argv.len() {
                    args.identity = Some(PathBuf::from(&argv[i]));
                }
            }
            "-o" | "--output" => {
                i += 1;
                if i < argv.len() {
                    args.output = Some(PathBuf::from(&argv[i]));
                }
            }
            "--rotate-from" => {
                i += 1;
                if i < argv.len() {
                    args.rotate_from = Some(PathBuf::from(&argv[i]));
                }
            }
            "--from-version" => {
                i += 1;
                if i < argv.len() {
                    match argv[i].parse::<u32>() {
                        Ok(v) => args.from_version = Some(v),
                        Err(_) => {
                            eprintln!("--from-version expects a non-negative integer");
                            std::process::exit(2);
                        }
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    args
}

fn print_help() {
    println!("R-VPN Server");
    println!();
    println!("Usage: rvpn-server [OPTIONS] [COMMAND]");
    println!();
    println!("Options:");
    println!("  -c, --config FILE    Configuration file (default: server.toml)");
    println!("  -b, --bind ADDR      Bind address (overrides config)");
    println!("  -v, --verbose        Verbose output (use multiple times for more)");
    println!("  -h, --help           Print this help");
    println!();
    println!("Commands:");
    println!("  keygen               Generate server identity key");
    println!("  prekey-bundle        Generate prekey bundle");
    println!();
    println!("Prekey bundle options:");
    println!("  --identity FILE      Identity key file to sign the bundle with");
    println!("  -o, --output FILE    Where to write the bundle JSON");
    println!("  --rotate-from FILE   Path to the PREVIOUS identity key. When set,");
    println!("                       the new bundle carries a rotation signature");
    println!("                       authored by that identity — already-pinned");
    println!("                       clients accept the rotation silently.");
    println!("  --from-version N     Version number the previous bundle published.");
    println!("                       The new bundle will carry N+1. Required with");
    println!("                       --rotate-from.");
    println!();
    println!("Examples:");
    println!("  rvpn-server                          # Run with default config");
    println!("  rvpn-server -c /etc/rvpn/server.toml # Use specific config");
    println!("  rvpn-server keygen                   # Generate identity key");
    println!("  rvpn-server prekey-bundle --identity server.key --output bundle.json");
    println!("  rvpn-server prekey-bundle \\           # Rotate to a new identity");
    println!("      --identity new_identity.key \\");
    println!("      --output bundle.json \\");
    println!("      --rotate-from old_identity.key \\");
    println!("      --from-version 1");
}

async fn load_config(path: &PathBuf) -> ServerConfig {
    if path.exists() {
        match ServerConfig::load(path) {
            Ok(config) => {
                info!("Loaded configuration from {:?}", path);
                config
            }
            Err(e) => {
                error!("Failed to load config from {:?}: {}", path, e);
                std::process::exit(1);
            }
        }
    } else {
        info!("No config file found at {:?}. Using defaults.", path);
        ServerConfig::default()
    }
}

fn keygen(config: &ServerConfig, output_path: Option<PathBuf>) -> Result<()> {
    use rvpn_core::crypto::IdentityKey;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    let path = output_path.unwrap_or_else(|| PathBuf::from(&config.identity_key_file));

    let identity = IdentityKey::generate();
    let key_data = format!(
        "R-VPN-IDENTITY-v1\n{}\n{}\n",
        BASE64.encode(identity.verifying_key.as_bytes()),
        BASE64.encode(identity.signing_key.to_bytes())
    );
    std::fs::write(&path, key_data)?;
    info!("Generated identity key: {:?}", path);
    Ok(())
}

fn prekey_bundle(
    config: &ServerConfig,
    identity_path: Option<PathBuf>,
    output_path: Option<PathBuf>,
    rotate_from: Option<PathBuf>,
    from_version: Option<u32>,
) -> Result<()> {
    use rvpn_core::crypto::{IdentityKey, Signer, X3DHResponder};
    use rvpn_core::identity_pin::rotation_signature_message;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use serde::Serialize;

    let identity_path = identity_path.unwrap_or_else(|| PathBuf::from(&config.identity_key_file));
    let output_path = output_path.unwrap_or_else(|| {
        config.prekey_bundle_file.clone()
            .unwrap_or_else(|| PathBuf::from("prekey-bundle.json"))
    });

    let identity = IdentityKey::load(&identity_path)?;
    let responder = X3DHResponder::from_identity(identity);
    let mut bundle = responder.get_public_bundle();

    // Rotation ceremony (see dev_docs/specs/TOFU_FINGERPRINT.md §6).
    //
    // Two paths:
    //   - Neither flag set: this is a first-ever bundle. Publish
    //     identity_key_version = 1 and rotation_signature = None. Clients
    //     doing TOFU capture pin whatever identity key is in this bundle.
    //   - Both flags set: this is a rotation. Load the *previous*
    //     identity's SigningKey, bump the version, sign
    //     `new_identity_pub || new_version_le` with the previous key. A
    //     client that already pinned the previous identity_key_version
    //     can silently update its pin via
    //     `rvpn_core::identity_pin::verify_rotation_signature`.
    //
    // We refuse mixed states (one flag but not the other) — the operator
    // has to be explicit about which version they're rotating from.
    match (rotate_from, from_version) {
        (None, None) => {
            info!("Bundle publishes identity_key_version=1 with no rotation signature (initial deployment)");
        }
        (Some(prev_path), Some(prev_ver)) => {
            let prev_identity = IdentityKey::load(&prev_path)?;
            let new_version = prev_ver
                .checked_add(1)
                .context("Version rollover past u32::MAX not supported")?;
            let msg = rotation_signature_message(
                bundle.identity_key.as_slice(),
                new_version,
            );
            let sig = prev_identity.signing_key.sign(&msg);
            bundle.identity_key_version = new_version;
            bundle.rotation_signature = Some(sig.to_bytes());
            info!(
                "Bundle publishes identity_key_version={} with rotation signature by previous identity {:?}",
                new_version, prev_path
            );
        }
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!(
                "--rotate-from and --from-version must be supplied together \
                 (see dev_docs/specs/TOFU_FINGERPRINT.md §6)"
            );
        }
    }

    // BundleJson mirrors the on-disk shape of X3DHPublicBundle field-for-field
    // rather than serializing the struct itself; we use plain base64 strings
    // per the historical bundle format, not the strongly-typed serde codec
    // that X3DHPublicBundle uses at rest.
    #[derive(Serialize)]
    struct BundleJson {
        identity_key: String,
        identity_x25519_key: String,
        signed_prekey: String,
        prekey_signature: String,
        one_time_prekey: Option<String>,
        identity_key_version: u32,
        rotation_signature: Option<String>,
    }

    let json = serde_json::to_string_pretty(&BundleJson {
        identity_key: BASE64.encode(bundle.identity_key),
        identity_x25519_key: BASE64.encode(bundle.identity_x25519_key),
        signed_prekey: BASE64.encode(bundle.signed_prekey),
        prekey_signature: BASE64.encode(bundle.prekey_signature),
        one_time_prekey: bundle.one_time_prekey.map(|k| BASE64.encode(k)),
        identity_key_version: bundle.identity_key_version,
        rotation_signature: bundle.rotation_signature.map(|sig| BASE64.encode(sig)),
    })?;

    std::fs::write(&output_path, json)?;
    info!("Generated prekey bundle: {:?}", output_path);

    // Also save the private key
    let private_key = responder.get_signed_prekey_private();
    let private_output_path = output_path.with_extension("private.json");

    #[derive(Serialize)]
    struct PrivateKeyJson {
        signed_prekey_private: String,
    }

    let private_json = serde_json::to_string_pretty(&PrivateKeyJson {
        signed_prekey_private: BASE64.encode(private_key),
    })?;

    std::fs::write(&private_output_path, private_json)?;
    info!("Generated private key: {:?}", private_output_path);

    Ok(())
}
