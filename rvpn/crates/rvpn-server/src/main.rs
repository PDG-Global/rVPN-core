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
use std::sync::Arc;

use anyhow::{Context as _, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use rvpn_server::decoy::{parse_request_head, DecoyServer, RequestHead, RewindStream};
use rvpn_server::handler::{DnsHandler, MultiplexerHandler, TunHandler, VpnHandler};

/// TCP_NOTSENT_LOWAT applied to every accepted tunnel socket (Linux only).
///
/// The WebSocket writer keeps writing as long as the kernel reports the
/// socket writable; with default send-buffer autotuning the buffer grows
/// toward `net.ipv4.tcp_wmem` max (commonly 4 MB), which becomes a standing
/// bufferbloat queue whenever the downstream hop drains slower than the TUN
/// reader feeds packets — e.g. the loopback hop to a reverse proxy
/// (caddy :443 → rvpn-server :8443), where loopback BDP is huge. Measured
/// on a congested HK exit as 4 MB queued in the server's own Send-Q and
/// >1 s added RTT for traffic sharing the tunnel during a bulk download.
/// Limiting *unsent* data to 64 KiB pushes backpressure up to the TUN
/// response channel (which drops rather than queues), while throughput on
/// fast paths is unaffected — in-flight data is not limited by this option.
#[cfg(target_os = "linux")]
const TCP_NOTSENT_LOWAT_BYTES: u32 = 64 * 1024;

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

    // Load configuration
    let config = load_config(&args.config, args.config_explicit).await;
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
            "clients" => return clients_command(&config, args.clients_args, args.label),
            _ => {}
        }
    }

    run_server(config).await
}

/// Run the VPN server
async fn run_server(config: ServerConfig) -> Result<()> {
    info!("Starting R-VPN Server on {}", config.bind_address);

    // Deny relays and raw TUN egress to the host's own interface addresses —
    // SSH and other local services must not be reachable through the VPN.
    // Operator-configured public_addresses (1:1 NAT) are denied too. Fail
    // closed: refuse to accept clients if the address set cannot be
    // enumerated, and keep it refreshed as interfaces change.
    // The opt-in client-egress exemptions (C24: allow_client_to_client,
    // allowed_internal_ranges) are parsed and validated here; dangerous
    // allow-list entries refuse startup. Host-address denial always wins
    // over the exemptions, at init and on every refresh.
    let client_policy = rvpn_server::egress::ClientEgressPolicy::from_config(
        config.network.allow_client_to_client,
        &config.tun.tun_ip,
        &config.network.allowed_internal_ranges,
    )
    .context("Invalid client egress policy configuration")?;
    if client_policy.allow_client_to_client || !client_policy.allowed_ranges.is_empty() {
        info!(
            "Client egress exemptions enabled (C24): allow_client_to_client={}, allowed_internal_ranges={:?}",
            client_policy.allow_client_to_client,
            config.network.allowed_internal_ranges
        );
    }
    rvpn_server::egress::initialize_host_egress_policy(
        &config.network.public_addresses,
        client_policy,
    )
    .context("Host egress policy initialization failed; refusing to accept clients")?;
    rvpn_server::egress::spawn_host_egress_refresh();

    // Initialize TUN server if configured (must be done before creating handlers)
    let tun_server = rvpn_server::tun_server::TunServer::new(&config.tun)?;
    // Always wrap in Arc for uniform handling
    let tun_server = Arc::new(RwLock::new(tun_server));
    let tun_server_for_loop = tun_server.clone();

    if config.tun.enabled {
        rvpn_server::firewall::setup_tun_egress(&config).context(
            "TUN egress containment failed; refusing to accept clients. \
             Firewall management needs root, or CAP_NET_ADMIN when using the \
             documented systemd unit; on FreeBSD the rc.d service runs as root",
        )?;
        {
            let mut ts = tun_server_for_loop.write().await;
            ts.start().await?;
        }
        setup_tun_routing(&config.tun)?;
        info!("TUN server started on {}", config.tun.tun_ip);
    }

    let handler = Arc::new(RwLock::new(VpnHandler::new(config.clone())?));
    let tun_handler = Arc::new(RwLock::new(TunHandler::new(
        config.clone(),
        Some(tun_server.clone()),
    )?));
    let dns_handler = Arc::new(RwLock::new(DnsHandler::new(config.clone())?));
    let mux_handler = Arc::new(RwLock::new(MultiplexerHandler::new(config.clone())?));

    // Decoy static site for non-VPN HTTPS requests (active-probing mask).
    // When absent or unusable, non-WebSocket requests keep the historical
    // behavior: connection closed right after the TLS handshake.
    let decoy = match config.decoy_root.as_ref() {
        Some(root) => match DecoyServer::new(root) {
            Ok(server) => {
                info!("Decoy site enabled, serving {:?}", root);
                Some(Arc::new(server))
            }
            Err(e) => {
                warn!(
                    "decoy_root {:?} is unusable: {}. Non-WebSocket requests will be dropped.",
                    root, e
                );
                None
            }
        },
        None => None,
    };

    // Path for TUN-mode mobile connections
    let tun_path = format!("{}/tun", config.websocket_path.trim_end_matches('/'));
    // Path for DNS-over-WebSocket connections
    let dns_path = format!("{}/dns", config.websocket_path.trim_end_matches('/'));
    // Path for SOCKS5 multiplexed connections (single WebSocket, multiple flows)
    let mux_path = format!("{}/mux", config.websocket_path.trim_end_matches('/'));

    let addr: SocketAddr = config
        .bind_address
        .parse()
        .context("Invalid bind address")?;

    // Check if TLS is configured — either static cert files or automatic
    // ACME (mutually exclusive, checked in configure_tls).
    let tls_acceptor = configure_tls(&config)
        .await
        .context("Failed to configure TLS")?;

    let listener = TcpListener::bind(addr).await.context("Failed to bind")?;

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
                info!(
                    "HTTP server listening on http://{}",
                    http_listener.local_addr()?
                );

                let redirect_https = config.redirect_http_to_https;
                tokio::spawn(async move {
                    loop {
                        match http_listener.accept().await {
                            Ok((stream, peer_addr)) => {
                                tokio::spawn(async move {
                                    if let Err(e) =
                                        handle_http_port(stream, peer_addr, redirect_https).await
                                    {
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

    info!(
        "WebSocket endpoint (desktop SOCKS): {}",
        config.websocket_path
    );
    info!("WebSocket endpoint (mobile TUN): {}", tun_path);
    info!("WebSocket endpoint (DNS proxy): {}", dns_path);

    // Accept connections
    loop {
        let (stream, peer_addr) = listener
            .accept()
            .await
            .context("Failed to accept connection")?;

        // Bound the kernel-level send queue (see TCP_NOTSENT_LOWAT_BYTES).
        // Without this, a slow downstream hop turns the socket buffer into
        // a multi-MB standing queue instead of dropping at the TUN reader.
        #[cfg(target_os = "linux")]
        {
            let sock_ref = socket2::SockRef::from(&stream);
            if let Err(e) = sock_ref.set_tcp_notsent_lowat(TCP_NOTSENT_LOWAT_BYTES) {
                debug!("Failed to set TCP_NOTSENT_LOWAT for {}: {}", peer_addr, e);
            }
        }

        let handler = handler.clone();
        let tun_handler = tun_handler.clone();
        let dns_handler = dns_handler.clone();
        let mux_handler = mux_handler.clone();
        let tun_server = tun_server.clone();
        let decoy = decoy.clone();
        let ws_path = config.websocket_path.clone();
        let tun_path = tun_path.clone();
        let dns_path = dns_path.clone();
        let mux_path = mux_path.clone();
        let tls_acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(
                stream,
                peer_addr,
                handler,
                tun_handler,
                dns_handler,
                mux_handler,
                tun_server,
                decoy,
                ws_path,
                tun_path,
                dns_path,
                mux_path,
                tls_acceptor,
            )
            .await
            {
                debug!("Connection error from {}: {}", peer_addr, e);
            }
        });
    }
}

/// Setup kernel routing for TUN interface
fn setup_tun_routing(config: &TunNetworkConfig) -> Result<()> {
    use std::process::Command;

    let network = rvpn_server::egress::normalized_tun_subnet(&config.tun_ip)?;

    // Add route to TUN network via TUN interface
    #[cfg(target_os = "freebsd")]
    let output = Command::new("route")
        .args([
            "add",
            "-net",
            &network,
            "-interface",
            &config.interface_name,
        ])
        .output()?;
    #[cfg(not(target_os = "freebsd"))]
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

    // Optional CAKE shaper on the TUN interface. When the path to clients
    // has a known rate-limited bottleneck (e.g. a capped transit product),
    // shaping just below it moves the standing queue from the bottleneck's
    // policer — where it adds seconds of bufferbloat with no fairness —
    // into our own qdisc, where cake fair-shares between inner flows.
    if let Some(kbit) = config.shaper_bandwidth_kbit {
        if cfg!(target_os = "linux") {
            let bw = format!("{}kbit", kbit);
            let tc = Command::new("tc")
                .args([
                    "qdisc",
                    "replace",
                    "dev",
                    &config.interface_name,
                    "root",
                    "cake",
                    "bandwidth",
                    &bw,
                ])
                .output();
            match tc {
                Ok(out) if out.status.success() => {
                    info!("CAKE shaper enabled on {} at {}", config.interface_name, bw);
                }
                Ok(out) => warn!(
                    "Failed to set CAKE shaper on {}: {}",
                    config.interface_name,
                    String::from_utf8_lossy(&out.stderr)
                ),
                Err(e) => warn!("tc not available, skipping CAKE shaper: {}", e),
            }
        } else {
            warn!("shaper_bandwidth_kbit is only supported on Linux; ignoring");
        }
    }
    Ok(())
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
/// - Neither → plain WebSocket only with `allow_plaintext = true` for a
///   trusted reverse proxy.
///
/// Missing or invalid certificates and conflicting ACME/static settings are
/// fatal instead of silently exposing plaintext.
async fn configure_tls(config: &ServerConfig) -> Result<Option<RvpnTlsAcceptor>> {
    let cert_exists = config.tls_cert_file.exists();
    let key_exists = config.tls_key_file.exists();
    if cert_exists != key_exists {
        anyhow::bail!(
            "TLS certificate and key must both exist. Missing {:?}; provide both files or remove both and explicitly set allow_plaintext=true only behind a trusted proxy",
            if cert_exists { &config.tls_key_file } else { &config.tls_cert_file }
        );
    }

    if config.acme.enabled {
        if cert_exists {
            anyhow::bail!(
                "[acme].enabled=true but static TLS cert files also exist at {:?} / {:?}. \
                 Move or remove them, or disable [acme] — the server won't guess which to serve.",
                config.tls_cert_file,
                config.tls_key_file
            );
        }
        return Ok(Some(build_acme_acceptor(&config.acme).await?));
    }

    if cert_exists {
        info!("Loading TLS certificates...");
        rvpn_server::private_files::require_private_file(&config.tls_key_file)?;
        let tls_config = load_tls_config(&config.tls_cert_file, &config.tls_key_file)
            .with_context(|| {
                format!(
                    "Cannot start with invalid TLS files {:?} / {:?}; replace or repair them (plaintext opt-in does not permit invalid files)",
                    config.tls_cert_file, config.tls_key_file
                )
            })?;
        info!("TLS enabled on {}", config.bind_address);
        return Ok(Some(RvpnTlsAcceptor::Static(
            tokio_rustls::TlsAcceptor::from(Arc::new(tls_config)),
        )));
    }

    if config.allow_plaintext {
        let exposed = config
            .bind_address
            .parse::<SocketAddr>()
            .map(|address| !address.ip().is_loopback())
            .unwrap_or(true);
        if exposed {
            warn!(
                "Plain WebSocket is exposed on {} without TLS",
                config.bind_address
            );
        } else {
            warn!(
                "Plain WebSocket enabled on {}; use only behind a trusted TLS-terminating proxy",
                config.bind_address
            );
        }
        return Ok(None);
    }

    anyhow::bail!(
        "TLS certificates are missing at {:?} / {:?}; provide both files, enable [acme], or set allow_plaintext=true only behind a trusted TLS-terminating proxy",
        config.tls_cert_file,
        config.tls_key_file
    )
}

/// Build a `tokio_rustls::TlsAcceptor` backed by `rustls-acme`.
///
/// The same `:443` listener handles both live traffic and the TLS-ALPN-01
/// challenge: rustls sees the `acme-tls/1` ALPN, calls the ACME resolver,
/// which returns the challenge cert. A background task drives renewals.
async fn build_acme_acceptor(acme: &rvpn_server::config::AcmeConfig) -> Result<RvpnTlsAcceptor> {
    use futures_util::StreamExt as _;
    use rustls_acme::{caches::DirCache, AcmeConfig as RustlsAcmeConfig};

    if acme.domains.is_empty() {
        anyhow::bail!("[acme].enabled=true but no [acme].domains listed — set at least one FQDN");
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
        if acme.staging {
            "STAGING"
        } else {
            "production"
        },
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

    // rustls-acme 0.15 needs an explicit client config for its ACME API
    // calls (0.9 built one internally). Build it from the crate's own
    // rustls re-export so the types always match its futures-rustls.
    let acme_client_config = Arc::new(
        rustls_acme::rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls_acme::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_root_certificates(rustls_acme::rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ))
        .with_no_client_auth(),
    );

    let mut state =
        RustlsAcmeConfig::new_with_client_config(acme.domains.clone(), acme_client_config)
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
    Some(
        rest[..end]
            .trim()
            .trim_end_matches(['"', '\\', ','])
            .to_string(),
    )
}

#[cfg(test)]
mod acme_tests {
    use super::parse_acme_rate_limit;

    #[test]
    fn parses_le_rate_limit_retry_after() {
        let msg = "Order(Acme(HttpRequest(Non2xxStatus { status_code: 429, body: \"{ \\\"type\\\": \\\"urn:ietf:params:acme:error:rateLimited\\\", \\\"detail\\\": \\\"too many failed authorizations (5) for \\\\\\\"003.hk.example.com\\\\\\\" in the last 1h0m0s, retry after 2026-07-11 06:01:16 UTC: see https://letsencrypt.org/docs/rate-limits/\\\" }\" }))";
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

    // Build TLS config — explicit ring provider: with tokio-rustls's aws-lc-rs
    // feature also in the graph, rustls 0.23's builder() panics on the ambiguity.
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("rustls ServerConfig protocol versions")?
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
    let host = request
        .lines()
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
    decoy: Option<Arc<DecoyServer>>,
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
                debug!("TLS handshake successful from {}", peer_addr);
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

    // When a decoy site is configured, pre-read the HTTP request head so
    // non-WebSocket requests are answered with static files instead of a
    // dropped connection (which is an active-probing tell). WebSocket
    // upgrades — to VPN paths or otherwise — still go through tungstenite
    // unchanged, replaying the buffered head via RewindStream so no bytes
    // are lost. Without a decoy, hand the stream straight to tungstenite
    // exactly as before.
    if let Some(decoy) = decoy {
        let mut stream = stream;
        match pre_read_head(&mut stream).await {
            HeadVerdict::WebSocket(buffered) => {
                debug!("WebSocket upgrade from {} (decoy pre-read)", peer_addr);
                let stream = RewindStream::new(buffered, stream);
                accept_and_dispatch_ws(
                    stream,
                    peer_addr,
                    handler,
                    tun_handler,
                    dns_handler,
                    mux_handler,
                    ws_path,
                    tun_path,
                    dns_path,
                    mux_path,
                )
                .await
            }
            HeadVerdict::Http(buffered) => {
                if let Err(e) = decoy.serve(&mut stream, buffered).await {
                    debug!("Decoy HTTP error from {}: {}", peer_addr, e);
                }
                Ok(())
            }
            HeadVerdict::Drop => Ok(()),
        }
    } else {
        debug!("Attempting WebSocket upgrade for {}", peer_addr);
        accept_and_dispatch_ws(
            stream,
            peer_addr,
            handler,
            tun_handler,
            dns_handler,
            mux_handler,
            ws_path,
            tun_path,
            dns_path,
            mux_path,
        )
        .await
    }
}

/// Timeout for reading the initial HTTP request head when a decoy site is
/// configured. VPN clients send the WebSocket handshake immediately after
/// TLS, so this only bites probers that connect and stay silent.
const HEAD_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Outcome of pre-reading the HTTP request head on a decoy-enabled port.
enum HeadVerdict {
    /// Well-formed WebSocket upgrade; replay these bytes into tungstenite.
    WebSocket(Vec<u8>),
    /// Plain HTTP request; serve from the decoy site.
    Http(Vec<u8>),
    /// EOF, timeout, oversized, or malformed head — close silently.
    Drop,
}

/// Read from the stream until a complete HTTP request head has been
/// buffered, then classify it.
async fn pre_read_head<S>(stream: &mut S) -> HeadVerdict
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut scratch = [0u8; 8192];

    let read_head = async {
        loop {
            if let Some(head) = parse_request_head(&buf) {
                return Some(head);
            }
            if buf.len() >= rvpn_server::decoy::MAX_HEADER_SIZE {
                return None;
            }
            match stream.read(&mut scratch).await {
                Ok(0) => return None,
                Ok(n) => buf.extend_from_slice(&scratch[..n]),
                Err(_) => return None,
            }
        }
    };

    let head: Option<RequestHead> = tokio::time::timeout(HEAD_READ_TIMEOUT, read_head)
        .await
        .ok()
        .flatten();

    match head {
        Some(h) if h.is_websocket_upgrade => HeadVerdict::WebSocket(buf),
        Some(_) => HeadVerdict::Http(buf),
        None => HeadVerdict::Drop,
    }
}

/// Perform the WebSocket handshake and route the connection to the VPN
/// handler for its path. Unknown paths are accepted then dropped, exactly
/// as before.
#[allow(clippy::too_many_arguments)]
async fn accept_and_dispatch_ws<S>(
    stream: S,
    peer_addr: SocketAddr,
    handler: Arc<RwLock<VpnHandler>>,
    tun_handler: Arc<RwLock<TunHandler>>,
    dns_handler: Arc<RwLock<DnsHandler>>,
    mux_handler: Arc<RwLock<MultiplexerHandler>>,
    ws_path: String,
    tun_path: String,
    dns_path: String,
    mux_path: String,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    // Track the request path using std::sync::Mutex since the callback is synchronous
    let request_path = Arc::new(std::sync::Mutex::new(String::new()));
    let request_path_clone = request_path.clone();

    let callback =
        move |req: &tokio_tungstenite::tungstenite::handshake::server::Request,
              response: tokio_tungstenite::tungstenite::handshake::server::Response| {
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
            debug!(
                "WebSocket upgrade accepted from {} on path: {}",
                peer_addr, path
            );

            // Route based on path
            if path == tun_path || path.starts_with(&format!("{}/", tun_path)) {
                if let Err(e) = tun_handler
                    .read()
                    .await
                    .handle_connection(ws, peer_addr)
                    .await
                {
                    debug!("TUN handler error for {}: {}", peer_addr, e);
                }
            } else if path == dns_path || path.starts_with(&format!("{}/", dns_path)) {
                if let Err(e) = dns_handler
                    .read()
                    .await
                    .handle_connection(ws, peer_addr)
                    .await
                {
                    debug!("DNS handler error for {}: {}", peer_addr, e);
                }
            } else if path == mux_path || path.starts_with(&format!("{}/", mux_path)) {
                // SOCKS5 multiplexed connection: single WebSocket, multiple TCP flows
                if let Err(e) = mux_handler
                    .read()
                    .await
                    .handle_connection(
                        ws,
                        peer_addr,
                        None,
                        rvpn_server::config::TunNetworkConfig::default(),
                    )
                    .await
                {
                    debug!("MUX handler error for {}: {}", peer_addr, e);
                }
            } else if path == ws_path || path == format!("{}/", ws_path.trim_end_matches('/')) {
                if let Err(e) = handler
                    .read()
                    .await
                    .handle_ws_connection(ws, peer_addr)
                    .await
                {
                    debug!("Handler error for {}: {}", peer_addr, e);
                }
            } else {
                // Unknown path - close connection
                debug!(
                    "WebSocket connection on unknown path '{}' from {}",
                    path, peer_addr
                );
            }

            debug!("Connection from {} closed", peer_addr);
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
    /// `-c/--config` was given: a missing file is then an error, not defaults.
    config_explicit: bool,
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
    /// `clients ...` subcommand tail: action + positional value.
    clients_args: Vec<String>,
    /// `clients approve --label "..."`: operator label for the key.
    label: Option<String>,
}

/// Parse the process arguments. `--help` and `--version` print and exit
/// here, before any startup work; an unknown argument or a missing value
/// exits non-zero. A mistyped flag must never fall through to starting a
/// second server (found on a production box, 18 Nov 2026).
/// `rvpn-server clients ...` — local-only admission admin (#32). Operates
/// directly on the allow-list / pending-list files; the running server
/// picks changes up on its next handshake's reload. No network admin API.
fn clients_command(config: &ServerConfig, tail: Vec<String>, label: Option<String>) -> Result<()> {
    use rvpn_server::admission::{
        cmd_approve, cmd_list, cmd_pending, cmd_revoke, cmd_set_mode, parse_admission_mode,
    };

    let allow = &config.admission.allow_file;
    let pending = &config.admission.pending_file;
    let audit = &config.admission.audit_file;

    let code = match tail.first().map(String::as_str) {
        Some("pending") if tail.len() == 1 => cmd_pending(pending),
        Some("list") if tail.len() == 1 => cmd_list(allow),
        Some("approve") if tail.len() == 2 => {
            cmd_approve(allow, pending, audit, &tail[1], label.as_deref())
        }
        Some("revoke") if tail.len() == 2 => cmd_revoke(allow, pending, audit, &tail[1]),
        Some("mode") if tail.len() == 2 && (tail[1] == "learn" || tail[1] == "enforce") => {
            cmd_set_mode(allow, audit, parse_admission_mode(&tail[1]))
        }
        _ => {
            eprintln!("rvpn-server: usage:");
            eprintln!(
                "  clients pending              list refused keys (fingerprint + times only)"
            );
            eprintln!("  clients list                 list approved keys with labels");
            eprintln!("  clients approve <fingerprint> [--label \"name\"]");
            eprintln!("  clients revoke <fingerprint> drop live sessions on the next reload");
            eprintln!("  clients mode learn|enforce   flip rollout mode (no restart)");
            2
        }
    };
    std::process::exit(code);
}

fn parse_args() -> Args {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    match parse_argv(&argv) {
        Ok(ParseOutcome::Run(args)) => args,
        Ok(ParseOutcome::Help) => {
            print_help();
            std::process::exit(0);
        }
        Ok(ParseOutcome::Version) => {
            println!("rvpn-server {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("rvpn-server: {e}");
            eprintln!("Run 'rvpn-server --help' for usage.");
            std::process::exit(2);
        }
    }
}

#[derive(Debug)]
enum ParseOutcome {
    Run(Args),
    Help,
    Version,
}

/// Arguments without the program name. Pure, so it can be tested.
fn parse_argv(argv: &[String]) -> Result<ParseOutcome, String> {
    // Help and version win wherever they appear, so `rvpn-server -c x --version`
    // never starts anything either.
    if argv.iter().any(|a| a == "-h" || a == "--help") {
        return Ok(ParseOutcome::Help);
    }
    if argv.iter().any(|a| a == "-V" || a == "--version") {
        return Ok(ParseOutcome::Version);
    }

    let mut args = Args {
        config: PathBuf::from("server.toml"),
        config_explicit: false,
        bind: None,
        command: None,
        identity: None,
        output: None,
        rotate_from: None,
        from_version: None,
        verbose: 0,
        clients_args: Vec::new(),
        label: None,
    };

    let mut it = argv.iter();
    while let Some(arg) = it.next() {
        let mut value = |flag: &str| -> Result<String, String> {
            match it.next() {
                Some(v) if !v.starts_with('-') || v == "-" => Ok(v.clone()),
                _ => Err(format!("{flag} needs a value")),
            }
        };
        match arg.as_str() {
            "-c" | "--config" => {
                args.config = PathBuf::from(value("--config")?);
                args.config_explicit = true;
            }
            "-b" | "--bind" => args.bind = Some(value("--bind")?),
            "-v" | "--verbose" => args.verbose = args.verbose.saturating_add(1),
            "--identity" => args.identity = Some(PathBuf::from(value("--identity")?)),
            "-o" | "--output" => args.output = Some(PathBuf::from(value("--output")?)),
            "--rotate-from" => args.rotate_from = Some(PathBuf::from(value("--rotate-from")?)),
            "--from-version" => {
                let v = value("--from-version")?;
                args.from_version =
                    Some(v.parse::<u32>().map_err(|_| {
                        "--from-version expects a non-negative integer".to_string()
                    })?);
            }
            "keygen" | "prekey-bundle" | "clients" => {
                if let Some(prev) = &args.command {
                    return Err(format!(
                        "only one command allowed (got '{prev}' and '{arg}')"
                    ));
                }
                args.command = Some(arg.clone());
            }
            "--label" => {
                args.label = Some(value("--label")?);
            }
            other => {
                // Positional tail for `clients` (action, fingerprint/mode).
                if args.command.as_deref() == Some("clients") && !other.starts_with('-') {
                    args.clients_args.push(other.to_string());
                } else {
                    return Err(format!("unrecognised argument '{other}'"));
                }
            }
        }
    }

    Ok(ParseOutcome::Run(args))
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
    println!("  -V, --version        Print the version");
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

async fn load_config(path: &PathBuf, explicit: bool) -> ServerConfig {
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
    } else if explicit {
        error!("Config file {:?} not found", path);
        std::process::exit(1);
    } else {
        info!("No config file found at {:?}. Using defaults.", path);
        ServerConfig::default()
    }
}

#[cfg(test)]
mod tls_tests {
    use super::*;

    #[tokio::test]
    async fn missing_certificates_are_fatal_by_default() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.tls_cert_file = directory.path().join("missing-cert.pem");
        config.tls_key_file = directory.path().join("missing-key.pem");
        let error = match configure_tls(&config).await {
            Err(error) => error.to_string(),
            Ok(_) => panic!("TLS configuration unexpectedly succeeded"),
        };
        assert!(error.contains("allow_plaintext=true"));
    }

    #[tokio::test]
    async fn plaintext_requires_explicit_opt_in() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.tls_cert_file = directory.path().join("missing-cert.pem");
        config.tls_key_file = directory.path().join("missing-key.pem");
        config.allow_plaintext = true;
        assert!(configure_tls(&config).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn partial_and_invalid_certificates_are_fatal_even_with_plaintext_enabled() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.tls_cert_file = directory.path().join("cert.pem");
        config.tls_key_file = directory.path().join("key.pem");
        config.allow_plaintext = true;
        std::fs::write(&config.tls_cert_file, "invalid").unwrap();
        assert!(configure_tls(&config).await.is_err());
        std::fs::write(&config.tls_key_file, "invalid").unwrap();
        assert!(configure_tls(&config).await.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tls_key_permissions_are_enforced() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let mut config = ServerConfig::default();
        config.tls_cert_file = directory.path().join("cert.pem");
        config.tls_key_file = directory.path().join("key.pem");
        std::fs::write(&config.tls_cert_file, "invalid").unwrap();
        std::fs::write(&config.tls_key_file, "invalid").unwrap();
        std::fs::set_permissions(&config.tls_key_file, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        let error = match configure_tls(&config).await {
            Err(error) => error.to_string(),
            Ok(_) => panic!("TLS configuration unexpectedly succeeded"),
        };
        assert!(error.contains("chmod 600"));
    }
}

fn keygen(config: &ServerConfig, output_path: Option<PathBuf>) -> Result<()> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use rvpn_core::crypto::IdentityKey;

    let path = output_path.unwrap_or_else(|| PathBuf::from(&config.identity_key_file));

    let identity = IdentityKey::generate();
    let key_data = format!(
        "R-VPN-IDENTITY-v1\n{}\n{}\n",
        BASE64.encode(identity.verifying_key.as_bytes()),
        BASE64.encode(identity.signing_key.to_bytes())
    );
    rvpn_server::private_files::atomic_write_private(&path, key_data.as_bytes())?;
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
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
    use rvpn_core::crypto::{Signer, X3DHResponder};
    use rvpn_core::identity_pin::rotation_signature_message;
    use serde::Serialize;

    let identity_path = identity_path.unwrap_or_else(|| PathBuf::from(&config.identity_key_file));
    let output_path = output_path.unwrap_or_else(|| {
        config
            .prekey_bundle_file
            .clone()
            .unwrap_or_else(|| PathBuf::from("prekey-bundle.json"))
    });

    let identity = rvpn_server::private_files::load_identity(&identity_path)?;
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
            let prev_identity = rvpn_server::private_files::load_identity(&prev_path)?;
            let new_version = prev_ver
                .checked_add(1)
                .context("Version rollover past u32::MAX not supported")?;
            let msg = rotation_signature_message(bundle.identity_key.as_slice(), new_version);
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
        identity_x25519_signature: Option<String>,
        signed_prekey: String,
        prekey_signature: String,
        one_time_prekey: Option<String>,
        identity_key_version: u32,
        rotation_signature: Option<String>,
    }

    let json = serde_json::to_string_pretty(&BundleJson {
        identity_key: BASE64.encode(bundle.identity_key),
        identity_x25519_key: BASE64.encode(bundle.identity_x25519_key),
        identity_x25519_signature: bundle
            .identity_x25519_signature
            .map(|sig| BASE64.encode(sig)),
        signed_prekey: BASE64.encode(bundle.signed_prekey),
        prekey_signature: BASE64.encode(bundle.prekey_signature),
        one_time_prekey: bundle.one_time_prekey.map(|k| BASE64.encode(k)),
        identity_key_version: bundle.identity_key_version,
        rotation_signature: bundle.rotation_signature.map(|sig| BASE64.encode(sig)),
    })?;

    rvpn_server::private_files::atomic_write_private(&output_path, json.as_bytes())?;
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

    rvpn_server::private_files::atomic_write_private(
        &private_output_path,
        private_json.as_bytes(),
    )?;
    info!("Generated private key: {:?}", private_output_path);

    Ok(())
}

#[cfg(test)]
mod arg_tests {
    use super::*;

    fn parse(a: &[&str]) -> Result<ParseOutcome, String> {
        parse_argv(&a.iter().map(|s| s.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn version_and_help_never_run() {
        for a in [
            &["--version"][..],
            &["-V"],
            &["-c", "/etc/rvpn/server.toml", "--version"],
            &["keygen", "-V"],
        ] {
            assert!(matches!(parse(a), Ok(ParseOutcome::Version)), "{a:?}");
        }
        for a in [&["--help"][..], &["-h"], &["--bogus", "-h"]] {
            assert!(matches!(parse(a), Ok(ParseOutcome::Help)), "{a:?}");
        }
    }

    #[test]
    fn unknown_argument_is_rejected() {
        for a in [&["--confg", "x"][..], &["--versoin"], &["serve"], &["-x"]] {
            assert!(parse(a).is_err(), "{a:?} must not start a server");
        }
    }

    #[test]
    fn missing_value_is_rejected() {
        for a in [
            &["-c"][..],
            &["--bind"],
            &["-c", "--verbose"],
            &["--from-version"],
            &["--from-version", "abc"],
        ] {
            assert!(parse(a).is_err(), "{a:?}");
        }
    }

    #[test]
    fn one_command_only() {
        assert!(parse(&["keygen", "prekey-bundle"]).is_err());
    }

    #[test]
    fn valid_invocations_still_parse() {
        let Ok(ParseOutcome::Run(a)) = parse(&["--config", "/etc/rvpn/server.toml", "-v", "-v"])
        else {
            panic!()
        };
        assert_eq!(a.config, PathBuf::from("/etc/rvpn/server.toml"));
        assert!(a.config_explicit);
        assert_eq!(a.verbose, 2);
        assert!(a.command.is_none());

        let Ok(ParseOutcome::Run(a)) = parse(&[]) else {
            panic!()
        };
        assert!(!a.config_explicit);

        let Ok(ParseOutcome::Run(a)) = parse(&[
            "prekey-bundle",
            "--identity",
            "new.key",
            "-o",
            "b.json",
            "--rotate-from",
            "old.key",
            "--from-version",
            "1",
        ]) else {
            panic!()
        };
        assert_eq!(a.command.as_deref(), Some("prekey-bundle"));
        assert_eq!(a.from_version, Some(1));
        assert_eq!(a.rotate_from, Some(PathBuf::from("old.key")));
    }
}
