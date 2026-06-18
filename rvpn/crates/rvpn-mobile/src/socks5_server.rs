//! SOCKS5 Server for rvpn-mobile
//!
//! This module implements a minimal SOCKS5 server that runs in-process
//! and forwards connections through the VPN tunnel.
//! 
//! ## Split DNS Support
//! 
//! When split tunneling is enabled, DNS queries (port 53) are intercepted
//! and routed to different DNS servers based on the domain being queried:
//! - Bypass domains (e.g., *.cn) → Local DNS (223.5.5.5)
//! - Tunnel domains (e.g., google.com) → Tunnel DNS (1.1.1.1)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context as _, Result};
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, RwLock};
use tokio::time::Instant;
use tracing::{debug, error, info, warn};

// Split tunnel imports
use crate::split_tunnel::{SplitTunnel, RoutingDecision};

/// UDP idle timeout duration (5 minutes)
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Create a TCP listener with SO_REUSEADDR enabled
/// 
/// This is critical for iOS where the VPN extension may be restarted
/// rapidly and we need to reuse the port immediately.
fn create_reuse_listener(bind_addr: SocketAddr) -> Result<TcpListener> {
    use std::net::TcpListener as StdTcpListener;
    use socket2::{Domain, Socket, Type};

    // Create socket with SO_REUSEADDR
    let socket = Socket::new(
        if bind_addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 },
        Type::STREAM,
        None,
    ).with_context(|| "Failed to create socket")?;

    // Enable SO_REUSEADDR to allow rapid restarts
    socket.set_reuse_address(true)
        .with_context(|| "Failed to set SO_REUSEADDR")?;

    // Bind to address
    socket.bind(&bind_addr.into())
        .with_context(|| format!("Failed to bind to {}", bind_addr))?;

    // Listen for connections
    socket.listen(128)
        .with_context(|| "Failed to listen on socket")?;

    // Set non-blocking for tokio
    socket.set_nonblocking(true)
        .with_context(|| "Failed to set non-blocking")?;

    // Convert to std listener then tokio listener
    let std_listener: StdTcpListener = socket.into();
    TcpListener::from_std(std_listener)
        .with_context(|| "Failed to create tokio listener")
}

/// DNS server configuration for split tunnel routing
#[derive(Debug, Clone)]
pub struct DnsConfig {
    /// DNS servers for tunnel traffic (e.g., 1.1.1.1, 8.8.8.8)
    pub tunnel_dns: Vec<String>,
    /// DNS servers for bypass traffic (e.g., 223.5.5.5 for AliDNS)
    pub bypass_dns: Vec<String>,
}

/// DNS query tracking for response relay
#[derive(Debug, Clone)]
struct DnsQueryRecord {
    /// Client address to send response back to
    client_addr: SocketAddr,
    /// Original transaction ID from client query (used as HashMap key)
    #[allow(dead_code)]
    transaction_id: u16,
    /// Timestamp for timeout tracking
    timestamp: Instant,
    /// Domain being queried (for logging)
    domain: String,
}

/// Result of DNS query forwarding decision
enum DnsForwardResult {
    /// Query was forwarded to external DNS server
    Forwarded,
    /// Query should be sent through tunnel
    Tunnel,
    /// Query was dropped (blocked)
    Dropped,
}

/// DNS forwarder for split tunnel DNS routing
struct DnsForwarder {
    /// UDP socket for communicating with external DNS servers
    socket: UdpSocket,
    /// Pending queries waiting for response
    pending_queries: Arc<RwLock<HashMap<u16, DnsQueryRecord>>>,
    /// Channel to send DNS responses back to clients
    response_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    /// DNS configuration
    dns_config: DnsConfig,
    /// Split tunnel for routing decisions
    split_tunnel: Option<Arc<SplitTunnel>>,
}

impl DnsForwarder {
    /// Create a new DNS forwarder
    async fn new(
        dns_config: DnsConfig,
        split_tunnel: Option<Arc<SplitTunnel>>,
        response_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    ) -> Result<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await
            .context("Failed to bind DNS forwarder socket")?;
        
        Ok(Self {
            socket,
            pending_queries: Arc::new(RwLock::new(HashMap::new())),
            response_tx,
            dns_config,
            split_tunnel,
        })
    }

    /// Run the DNS forwarder - receives responses and relays them to clients
    async fn run(self: Arc<Self>) {
        let mut buf = vec![0u8; 512];
        
        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, dns_server_addr)) => {
                    if len < 12 {
                        warn!("[DNS] Received too short DNS response");
                        continue;
                    }

                    // Extract transaction ID from response
                    let transaction_id = u16::from_be_bytes([buf[0], buf[1]]);
                    
                    // Look up the original query
                    let mut pending = self.pending_queries.write().await;
                    if let Some(record) = pending.remove(&transaction_id) {
                        info!("[DNS] Received response for {} from {}, relaying to client", 
                            record.domain, dns_server_addr);
                        
                        // Format DNS response for SOCKS5 UDP relay
                        // Format: [ATYP:1][ADDR:var][PORT:2][DATA:var]
                        // For DNS responses, we use ATYP=0x01 (IPv4) with 0.0.0.0:0
                        let mut formatted_response = vec![
                            0x01,       // ATYP (IPv4)
                            0x00, 0x00, 0x00, 0x00, // ADDR (0.0.0.0)
                            0x00, 0x00, // PORT (0)
                        ];
                        formatted_response.extend_from_slice(&buf[..len]);
                        
                        // Send response back to original client
                        if let Err(e) = self.response_tx.send((formatted_response, record.client_addr)).await {
                            error!("[DNS] Failed to relay DNS response: {}", e);
                        }
                    } else {
                        warn!("[DNS] Received DNS response with unknown transaction ID {}", transaction_id);
                    }
                }
                Err(e) => {
                    error!("[DNS] DNS forwarder receive error: {}", e);
                    break;
                }
            }
        }
    }

    /// Forward a DNS query to the appropriate DNS server based on split tunnel routing
    /// Returns DnsForwardResult indicating what to do with the query
    async fn forward_query(
        &self,
        query_data: &[u8],
        client_addr: SocketAddr,
        domain: &str,
    ) -> Result<DnsForwardResult> {
        if query_data.len() < 2 {
            return Err(anyhow::anyhow!("DNS query too short"));
        }

        // Extract transaction ID
        let transaction_id = u16::from_be_bytes([query_data[0], query_data[1]]);

        // Determine which DNS server to use
        let dns_server = if let Some(ref split_tunnel) = self.split_tunnel {
            let routing = split_tunnel.decide_by_host(domain).await;
            
            match routing {
                RoutingDecision::Bypass => {
                    let bypass_dns = self.dns_config.bypass_dns.first()
                        .cloned()
                        .unwrap_or_else(|| "223.5.5.5".to_string());
                    info!("🌏 [DNS] Domain '{}' routing to LOCAL DNS {} (bypass VPN)", domain, bypass_dns);
                    bypass_dns
                }
                RoutingDecision::Tunnel => {
                    info!("🔒 [DNS] Domain '{}' routing to TUNNEL DNS (through VPN)", domain);
                    return Ok(DnsForwardResult::Tunnel);
                }
                RoutingDecision::Block => {
                    info!("🚫 [DNS] Domain '{}' BLOCKED - dropping query", domain);
                    return Ok(DnsForwardResult::Dropped);
                }
            }
        } else {
            // No split tunnel, send to tunnel
            info!("⚠️  [DNS] Split tunnel disabled, domain '{}' going to tunnel", domain);
            return Ok(DnsForwardResult::Tunnel);
        };

        // Parse DNS server address
        let dns_addr: SocketAddr = format!("{}:53", dns_server)
            .parse()
            .context("Invalid DNS server address")?;

        // Record the query for response tracking
        let record = DnsQueryRecord {
            client_addr,
            transaction_id,
            timestamp: Instant::now(),
            domain: domain.to_string(),
        };
        
        {
            let mut pending = self.pending_queries.write().await;
            
            // Clean up old entries (older than 30 seconds)
            let now = Instant::now();
            pending.retain(|_, r| now.duration_since(r.timestamp) < Duration::from_secs(30));
            
            pending.insert(transaction_id, record);
        }

        // Send query to DNS server
        self.socket.send_to(query_data, dns_addr).await
            .context("Failed to send DNS query")?;

        debug!("[DNS] Forwarded query for {} to {}", domain, dns_addr);
        Ok(DnsForwardResult::Forwarded)
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            tunnel_dns: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            bypass_dns: vec!["223.5.5.5".to_string()], // AliDNS
        }
    }
}

/// SOCKS5 proxy server configuration
#[derive(Debug, Clone)]
pub struct Socks5ServerConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Split tunnel configuration
    pub split_tunnel: Option<crate::split_tunnel::SplitTunnelConfig>,
    /// DNS server configuration for split tunnel routing
    pub dns_config: Option<DnsConfig>,
}

/// SOCKS5 server that handles connections and forwards to tunnel
pub struct Socks5Server {
    listen_addr: SocketAddr,
    /// Split tunnel for DNS and routing decisions
    split_tunnel: Option<Arc<SplitTunnel>>,
    /// DNS configuration
    dns_config: DnsConfig,
}

impl Clone for Socks5Server {
    fn clone(&self) -> Self {
        Self {
            listen_addr: self.listen_addr,
            split_tunnel: self.split_tunnel.clone(),
            dns_config: self.dns_config.clone(),
        }
    }
}

/// Handle to control a running SOCKS5 server
#[derive(Clone)]
pub struct Socks5ServerHandle {
    /// Signal to stop the server
    shutdown_tx: mpsc::Sender<()>,
    /// Local address the server is bound to
    pub local_addr: SocketAddr,
}

impl Socks5ServerHandle {
    /// Stop the SOCKS5 server
    pub async fn stop(&self) {
        let _ = self.shutdown_tx.send(()).await;
    }
}

impl Socks5Server {
    /// Create a new SOCKS5 server with split tunnel support
    pub async fn new(config: Socks5ServerConfig) -> Result<Self> {
        // Initialize split tunnel if configured
        let split_tunnel = if let Some(ref st_config) = config.split_tunnel {
            if st_config.enabled {
                info!("🔧 Split tunnel configuration:");
                info!("  - Enabled: {}", st_config.enabled);
                info!("  - Builtin bypass countries: {:?}", st_config.builtin_bypass_countries);
                info!("  - Bypass domains from file: {}", st_config.bypass_domains_file.is_some());
                info!("  - Tunnel domains from file: {}", st_config.tunnel_domains_file.is_some());
                info!("  - Block ads: {}", st_config.block_ads);
                info!("  - Inline bypass networks: {:?}", st_config.bypass_networks);
                
                let dns_resolver = std::sync::Arc::new(rvpn_client::dns_cache::DnsResolver::new(true, 14400, 1000, false, true, vec![]));
                dns_resolver.start_cleanup_task();
                match SplitTunnel::new(st_config.clone(), dns_resolver).await {
                    Ok(st) => {
                        let stats = st.get_stats().await;
                        info!("✅ Split tunnel initialized successfully:");
                        info!("  - Bypass networks: {}", stats.bypass_networks_count);
                        info!("  - Bypass domains: {}", stats.bypass_domains_count);
                        info!("  - Tunnel networks: {}", stats.tunnel_networks_count);
                        info!("  - Tunnel domains: {}", stats.tunnel_domains_count);
                        Some(Arc::new(st))
                    }
                    Err(e) => {
                        warn!("❌ Failed to initialize split tunnel: {}", e);
                        None
                    }
                }
            } else {
                info!("⚠️  Split tunnel is disabled in configuration");
                None
            }
        } else {
            warn!("⚠️  No split tunnel configuration provided");
            None
        };
        
        let dns_config = config.dns_config.unwrap_or_default();
        info!("🌐 DNS configuration:");
        info!("  - Tunnel DNS: {:?}", dns_config.tunnel_dns);
        info!("  - Bypass DNS: {:?}", dns_config.bypass_dns);
        
        Ok(Self {
            listen_addr: config.listen_addr,
            split_tunnel,
            dns_config,
        })
    }
    
    /// Create a new SOCKS5 server without split tunnel support (legacy)
    pub fn new_simple(config: Socks5ServerConfig) -> Self {
        Self {
            listen_addr: config.listen_addr,
            split_tunnel: None,
            dns_config: config.dns_config.unwrap_or_default(),
        }
    }

    /// Run the SOCKS5 server with graceful shutdown support
    /// 
    /// This spawns a task that listens for SOCKS5 connections and forwards
    /// them to the tunnel via the provided channel. Returns a handle that
    /// can be used to stop the server.
    pub async fn run_with_shutdown(
        &self,
        tunnel_sender: mpsc::Sender<TunnelRequest>,
        udp_tunnel_sender: mpsc::Sender<UdpAssociationRequest>,
    ) -> Result<Socks5ServerHandle> {
        // Use SO_REUSEADDR socket to allow rapid restarts (critical for iOS)
        let listener = create_reuse_listener(self.listen_addr)
            .with_context(|| format!("Failed to bind SOCKS5 proxy to {}", self.listen_addr))?;

        let local_addr = listener.local_addr()?;
        info!("SOCKS5 proxy listening on {}", local_addr);

        // Create shutdown channel
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
        
        // Track active connections for graceful shutdown
        let active_connections: Arc<RwLock<Vec<tokio::task::AbortHandle>>> = 
            Arc::new(RwLock::new(Vec::new()));
        let active_connections_clone = active_connections.clone();
        
        // Clone server state for the accept loop
        let split_tunnel = self.split_tunnel.clone();
        let dns_config = self.dns_config.clone();

        // Spawn the accept loop
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Accept new connections
                    result = listener.accept() => {
                        match result {
                            Ok((socket, addr)) => {
                                // Enable TCP_NODELAY for low-latency SOCKS5 responses
                                if let Err(e) = socket.set_nodelay(true) {
                                    error!("Failed to set TCP_NODELAY: {}", e);
                                }
                                
                                let tcp_sender = tunnel_sender.clone();
                                let udp_sender = udp_tunnel_sender.clone();
                                let st = split_tunnel.clone();
                                let dns = dns_config.clone();
                                let handle = tokio::spawn(async move {
                                    if let Err(e) = handle_socks5_connection(
                                        socket, 
                                        addr, 
                                        tcp_sender, 
                                        udp_sender,
                                        st,
                                        dns,
                                    ).await {
                                        error!("SOCKS5 connection error from {}: {}", addr, e);
                                    }
                                });
                                
                                // Track the connection
                                let mut connections = active_connections_clone.write().await;
                                connections.push(handle.abort_handle());
                                
                                // Clean up completed tasks periodically
                                connections.retain(|h| !h.is_finished());
                            }
                            Err(e) => {
                                error!("Failed to accept SOCKS5 connection: {}", e);
                            }
                        }
                    }
                    // Wait for shutdown signal
                    _ = shutdown_rx.recv() => {
                        info!("SOCKS5 server received shutdown signal");
                        
                        // Abort all active connections
                        let mut connections = active_connections_clone.write().await;
                        for handle in connections.drain(..) {
                            handle.abort();
                        }
                        
                        info!("SOCKS5 server stopped");
                        break;
                    }
                }
            }
        });

        Ok(Socks5ServerHandle {
            shutdown_tx,
            local_addr,
        })
    }
}

/// Handle a single SOCKS5 connection
///
/// This function performs the SOCKS5 handshake, then hands off the socket to the tunnel
/// for WebSocket-based relay. The tunnel will signal completion when the relay is done.
/// 
/// For DNS queries (port 53), this function intercepts the request and routes it to
/// the appropriate DNS server based on split tunnel configuration.
async fn handle_socks5_connection(
    mut socket: TcpStream,
    addr: SocketAddr,
    tunnel_sender: mpsc::Sender<TunnelRequest>,
    udp_tunnel_sender: mpsc::Sender<UdpAssociationRequest>,
    split_tunnel: Option<Arc<SplitTunnel>>,
    dns_config: DnsConfig,
) -> Result<()> {
    info!("[SOCKS5] New connection from {}", addr);

    // 1. SOCKS5 handshake - get target address
    let (mut target_addr, target_host) = match socks5_handshake(&mut socket, udp_tunnel_sender, split_tunnel.clone(), dns_config.clone()).await {
        Ok(Some(addr)) => {
            info!("[SOCKS5] Handshake successful, target: {}", addr);
            // Extract host from target for DNS routing
            let host = addr.split(':').next().unwrap_or("").to_string();
            (addr, host)
        }
        Ok(None) => {
            // UDP ASSOCIATE - already handled, no TCP relay needed
            info!("[SOCKS5] UDP ASSOCIATE completed, closing TCP connection");
            return Ok(());
        }
        Err(e) => {
            error!("[SOCKS5] Handshake failed for {}: {}", addr, e);
            return Err(e);
        }
    };

    // 2. Parse target host and port
    let target_port = target_addr.split(':').last().and_then(|p| p.parse::<u16>().ok()).unwrap_or(0);
    
    // 3. Check IP-based bypass routing for non-DNS connections
    // For DNS queries (port 53), we handle DNS-specific routing below
    if target_port != 53 {
        if let Some(ref split_tunnel) = split_tunnel {
            // Try to parse target as IP address
            // For domain names, we can't do IP-based bypass without resolving first
            if let Ok(target_ip) = target_host.parse::<std::net::IpAddr>() {
                let routing = split_tunnel.decide_by_ip(target_ip).await;
                
                match routing {
                    RoutingDecision::Bypass => {
                        info!(
                            "[SOCKS5] Connection to {}:{} bypassing VPN (IP in bypass networks)", 
                            target_host, target_port
                        );
                        // Send SOCKS5 error: Connection not allowed by ruleset (0x02)
                        // This signals to iOS that it should retry with direct connection
                        send_socks5_error(&mut socket, 0x02).await?;
                        return Ok(());
                    }
                    RoutingDecision::Block => {
                        warn!(
                            "[SOCKS5] Connection to {}:{} blocked", 
                            target_host, target_port
                        );
                        send_socks5_error(&mut socket, 0x02).await?;
                        return Ok(());
                    }
                    RoutingDecision::Tunnel => {
                        debug!(
                            "[SOCKS5] Connection to {}:{} going through tunnel", 
                            target_host, target_port
                        );
                    }
                }
            }
        }
    }
    
    // 4. Check if this is a DNS query (port 53) and apply split tunnel routing
    if target_port == 53 {
        if let Some(ref split_tunnel) = split_tunnel {
            // Try to extract domain from DNS query packet
            let domain = peek_dns_domain(&mut socket).await;
            
            let domain_to_check = domain.as_deref().unwrap_or(&target_host);
            
            if !domain_to_check.is_empty() {
                let routing = split_tunnel.decide_by_host(domain_to_check).await;
                
                match routing {
                    RoutingDecision::Bypass => {
                        // Use local DNS server (China)
                        if let Some(local_dns) = get_next_dns_server(&dns_config.bypass_dns, 0) {
                            info!("DNS for {} bypassing tunnel (using local DNS: {})", domain_to_check, local_dns);
                            target_addr = format!("{}:53", local_dns);
                        }
                    }
                    RoutingDecision::Tunnel => {
                        // Use tunnel DNS server
                        if let Some(tunnel_dns) = get_next_dns_server(&dns_config.tunnel_dns, 0) {
                            info!("DNS for {} going through tunnel (using {})", domain_to_check, tunnel_dns);
                            // Keep original target or use configured tunnel DNS
                            if dns_config.tunnel_dns.iter().any(|d| target_host == *d) {
                                // Target is already a tunnel DNS, keep it
                            } else {
                                target_addr = format!("{}:53", tunnel_dns);
                            }
                        }
                    }
                    RoutingDecision::Block => {
                        info!("DNS for {} blocked", domain_to_check);
                        // Return connection refused
                        send_socks5_refused(&mut socket).await?;
                        return Ok(());
                    }
                }
            }
        }
    }

    // 3. Send success response to SOCKS5 client
    // Note: We send this BEFORE tunnel is ready because SOCKS5 protocol requires it
    send_socks5_success(&mut socket).await?;
    debug!("Sent SOCKS5 success response to {}", addr);

    // 4. Create completion channel
    let (completion_tx, mut completion_rx) = mpsc::channel::<Result<()>>(1);

    // 5. Create tunnel request with the socket
    let request = TunnelRequest {
        target_address: target_addr.clone(),
        socket,
        completion_sender: completion_tx,
    };

    // 6. Send request to tunnel
    tunnel_sender.send(request).await
        .map_err(|_| anyhow::anyhow!("Tunnel channel closed"))?;

    // 7. Wait for tunnel to signal completion
    match completion_rx.recv().await {
        Some(result) => {
            match result {
                Ok(()) => debug!("Tunnel relay completed successfully for {}", addr),
                Err(e) => error!("Tunnel relay failed for {}: {}", addr, e),
            }
        }
        None => {
            error!("Completion channel closed unexpectedly for {}", addr);
        }
    }

    debug!("SOCKS5 connection closed: {}", addr);
    Ok(())
}

/// Peek at the first packet to extract DNS domain without consuming it
/// 
/// This reads the first packet from the socket, extracts the domain name,
/// and returns it. The packet data is NOT consumed - it will be read again
/// by the tunnel relay.
async fn peek_dns_domain(socket: &mut TcpStream) -> Option<String> {
    // Try to peek at the first few bytes to get DNS query
    // We use a small buffer since DNS queries are typically short
    let mut buf = [0u8; 512];
    
    // Set a short timeout for peeking
    match tokio::time::timeout(Duration::from_millis(100), socket.peek(&mut buf)).await {
        Ok(Ok(len)) if len >= 12 => {
            // Successfully peeked at data, try to parse DNS domain
            parse_dns_query_domain(&buf[..len])
        }
        _ => {
            // Timeout or error - continue without domain extraction
            None
        }
    }
}

/// SOCKS5 handshake - parse target address
async fn socks5_handshake(
    socket: &mut TcpStream,
    udp_tunnel_sender: mpsc::Sender<UdpAssociationRequest>,
    split_tunnel: Option<Arc<SplitTunnel>>,
    dns_config: DnsConfig,
) -> Result<Option<String>> {
    // Read client greeting: [VER][NMETHODS]
    let mut greeting = [0u8; 2];
    socket.read_exact(&mut greeting).await
        .map_err(|e| anyhow::anyhow!("Failed to read greeting: {}", e))?;
    
    if greeting[0] != 0x05 {
        return Err(anyhow::anyhow!("Unsupported SOCKS version: {}", greeting[0]));
    }
    
    let nmethods = greeting[1] as usize;
    if nmethods == 0 {
        return Err(anyhow::anyhow!("No methods provided"));
    }
    
    // Read methods
    let mut methods = vec![0u8; nmethods];
    socket.read_exact(&mut methods).await
        .map_err(|e| anyhow::anyhow!("Failed to read methods: {}", e))?;
    
    // We only support no-auth (0x00)
    if !methods.contains(&0x00) {
        return Err(anyhow::anyhow!("No supported auth methods: {:?}", methods));
    }
    
    // Send method selection response: [VER=0x05][METHOD=0x00]
    socket.write_all(&[0x05, 0x00]).await
        .map_err(|e| anyhow::anyhow!("Failed to send auth response: {}", e))?;
    
    socket.flush().await
        .map_err(|e| anyhow::anyhow!("Failed to flush auth response: {}", e))?;
    
    info!("[SOCKS5] Sent auth response [0x05, 0x00] and flushed");
    
    // Read request
    let mut header = [0u8; 4];
    socket.read_exact(&mut header).await
        .map_err(|e| anyhow::anyhow!("Failed to read request header: {}", e))?;
    let cmd = header[1];
    let atyp = header[3];
    info!("[SOCKS5] Request: cmd={}, atyp={}", cmd, atyp);
    
    match cmd {
        0x01 => {
            // CONNECT command - handle below
            info!("[SOCKS5] CONNECT command");
        }
        0x03 => {
            // UDP ASSOCIATE command
            info!("[SOCKS5] UDP ASSOCIATE command - handling UDP relay");
            handle_udp_associate(socket, atyp, udp_tunnel_sender, split_tunnel, dns_config).await?;
            return Ok(None); // UDP ASSOCIATE handled, no target string needed
        }
        _ => {
            // Command not supported
            socket.write_all(&[0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
            return Err(anyhow::anyhow!("Command not supported: {}", cmd));
        }
    }
    
    // Parse address
    let target = match atyp {
        0x01 => {  // IPv4
            let mut addr = [0u8; 4];
            socket.read_exact(&mut addr).await
                .map_err(|e| anyhow::anyhow!("Failed to read IPv4 addr: {}", e))?;
            let port = read_port(socket).await
                .map_err(|e| anyhow::anyhow!("Failed to read port: {}", e))?;
            let target = format!("{}.{}.{}.{}:{}", addr[0], addr[1], addr[2], addr[3], port);
            info!("[SOCKS5] IPv4 target: {}", target);
            target
        }
        0x03 => {  // Domain
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await
                .map_err(|e| anyhow::anyhow!("Failed to read domain len: {}", e))?;
            let mut domain = vec![0u8; len[0] as usize];
            socket.read_exact(&mut domain).await
                .map_err(|e| anyhow::anyhow!("Failed to read domain: {}", e))?;
            let port = read_port(socket).await
                .map_err(|e| anyhow::anyhow!("Failed to read port: {}", e))?;
            let target = format!("{}:{}", String::from_utf8_lossy(&domain), port);
            info!("[SOCKS5] Domain target: {}", target);
            target
        }
        0x04 => {  // IPv6
            let mut addr = [0u8; 16];
            socket.read_exact(&mut addr).await
                .map_err(|e| anyhow::anyhow!("Failed to read IPv6 addr: {}", e))?;
            let port = read_port(socket).await
                .map_err(|e| anyhow::anyhow!("Failed to read port: {}", e))?;
            let ip = std::net::Ipv6Addr::from(addr);
            let target = format!("[{}]:{}", ip, port);
            info!("[SOCKS5] IPv6 target: {}", target);
            target
        }
        _ => {
            socket.write_all(&[0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
            return Err(anyhow::anyhow!("Invalid address type: {}", atyp));
        }
    };
    
    Ok(Some(target))
}

/// Handle UDP ASSOCIATE command
///
/// This creates a UDP relay socket that forwards packets through the VPN tunnel.
/// The client sends UDP packets to the relay address, which are then encapsulated
/// and sent through the tunnel.
/// 
/// For DNS queries (port 53), split tunnel routing is applied to route queries
/// to either local DNS (bypass) or tunnel DNS based on the domain being queried.
async fn handle_udp_associate(
    socket: &mut TcpStream,
    atyp: u8,
    udp_tunnel_sender: mpsc::Sender<UdpAssociationRequest>,
    split_tunnel: Option<Arc<SplitTunnel>>,
    dns_config: DnsConfig,
) -> Result<()> {
    // Parse address from already-read request ATYP (we don't use it, but consume it)
    match atyp {
        0x01 => {  // IPv4
            let mut addr = [0u8; 4];
            socket.read_exact(&mut addr).await?;
            let _port = read_port(socket).await?;
        }
        0x03 => {  // Domain
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut domain = vec![0u8; len[0] as usize];
            socket.read_exact(&mut domain).await?;
            let _port = read_port(socket).await?;
        }
        0x04 => {  // IPv6
            let mut addr = [0u8; 16];
            socket.read_exact(&mut addr).await?;
            let _port = read_port(socket).await?;
        }
        _ => {
            socket.write_all(&[0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
            return Err(anyhow::anyhow!("Invalid address type in UDP ASSOCIATE: {}", atyp));
        }
    }

    // Create UDP socket bound to localhost with ephemeral port
    let udp_bind_addr = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
    let udp_socket = UdpSocket::bind(udp_bind_addr).await
        .map_err(|e| anyhow::anyhow!("Failed to bind UDP socket: {}", e))?;

    let relay_addr = udp_socket.local_addr()
        .map_err(|e| anyhow::anyhow!("Failed to get UDP socket address: {}", e))?;

    info!("[SOCKS5] UDP ASSOCIATE: Created relay at {}", relay_addr);

    // Send success response with relay address
    let mut response = vec![
        0x05, 0x00,  // Version 5, no error
        0x00,        // Reserved
        0x01,        // IPv4
    ];

    // Add relay IP
    if let SocketAddr::V4(addr) = relay_addr {
        response.extend_from_slice(&addr.ip().octets());
        response.extend_from_slice(&addr.port().to_be_bytes());
    } else {
        // Shouldn't happen since we bound to IPv4
        response.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    }

    socket.write_all(&response).await?;
    socket.flush().await?;

    info!("[SOCKS5] UDP ASSOCIATE: Sent relay address {} to client", relay_addr);

    // Create channels for UDP packet exchange with the tunnel
    let (tunnel_to_socks_tx, mut tunnel_to_socks_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100);
    let (socks_to_tunnel_tx, socks_to_tunnel_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(100);
    let (completion_tx, mut completion_rx) = mpsc::channel::<Result<()>>(1);

    // Send UDP association request to tunnel
    let udp_request = UdpAssociationRequest {
        packet_tx: tunnel_to_socks_tx.clone(), // Clone for DNS forwarder
        packet_rx: socks_to_tunnel_rx,
        completion_sender: completion_tx,
        relay_addr,
    };

    if let Err(e) = udp_tunnel_sender.send(udp_request).await {
        error!("[SOCKS5] Failed to send UDP association request to tunnel: {}", e);
        return Err(anyhow::anyhow!("Tunnel channel closed"));
    }

    info!("[SOCKS5] UDP ASSOCIATE: Sent association request to tunnel");

    // Arc for sharing the socket between tasks
    let udp_socket = Arc::new(udp_socket);
    let udp_socket_clone = udp_socket.clone();

    // Track last activity for idle timeout
    let last_activity = Arc::new(RwLock::new(Instant::now()));
    let last_activity_clone = last_activity.clone();

    // Create DNS forwarder for split tunnel DNS routing (if split tunnel enabled)
    let dns_forwarder = if split_tunnel.is_some() {
        let forwarder = DnsForwarder::new(dns_config.clone(), split_tunnel.clone(), tunnel_to_socks_tx.clone()).await;
        match forwarder {
            Ok(f) => {
                info!("[DNS] DNS forwarder initialized for split tunnel routing");
                Some(Arc::new(f))
            }
            Err(e) => {
                warn!("[DNS] Failed to create DNS forwarder: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Start DNS forwarder response listener if created
    if let Some(ref forwarder) = dns_forwarder {
        let forwarder_clone = forwarder.clone();
        tokio::spawn(async move {
            forwarder_clone.run().await;
        });
    }

    // Spawn UDP relay task: receive from tunnel, send to client
    let relay_to_client = tokio::spawn(async move {
        while let Some((data, client_addr)) = tunnel_to_socks_rx.recv().await {
            // Update last activity timestamp
            *last_activity_clone.write().await = Instant::now();

            // Parse server response format: [ATYP:1][ADDR:var][PORT:2][DATA:var]
            // Extract the actual data portion before sending to client
            let payload = if data.is_empty() {
                warn!("[SOCKS5] UDP ASSOCIATE: Received empty data from tunnel");
                continue;
            } else {
                let atyp = data[0];
                let header_len = match atyp {
                    0x01 => { // IPv4: ATYP(1) + ADDR(4) + PORT(2) = 7 bytes
                        if data.len() < 7 {
                            warn!("[SOCKS5] UDP ASSOCIATE: IPv4 response too short: {} bytes", data.len());
                            continue;
                        }
                        7
                    }
                    0x03 => { // Domain: ATYP(1) + LEN(1) + DOMAIN(var) + PORT(2)
                        if data.len() < 2 {
                            warn!("[SOCKS5] UDP ASSOCIATE: Domain response too short: {} bytes", data.len());
                            continue;
                        }
                        let domain_len = data[1] as usize;
                        let total_header = 1 + 1 + domain_len + 2;
                        if data.len() < total_header {
                            warn!("[SOCKS5] UDP ASSOCIATE: Domain response too short for header: {} bytes", data.len());
                            continue;
                        }
                        total_header
                    }
                    0x04 => { // IPv6: ATYP(1) + ADDR(16) + PORT(2) = 19 bytes
                        if data.len() < 19 {
                            warn!("[SOCKS5] UDP ASSOCIATE: IPv6 response too short: {} bytes", data.len());
                            continue;
                        }
                        19
                    }
                    _ => {
                        warn!("[SOCKS5] UDP ASSOCIATE: Unknown ATYP in server response: {}", atyp);
                        continue;
                    }
                };
                // Extract just the data portion (after the address header)
                &data[header_len..]
            };

            // Wrap the payload in SOCKS5 UDP header
            // Format: [RSV:2][FRAG:1][ATYP:1][DST.ADDR:variable][DST.PORT:2][DATA:variable]
            // For responses from tunnel, we use ATYP=0x01 (IPv4) with 0.0.0.0:0
            let mut udp_packet = vec![
                0x00, 0x00, // RSV (reserved)
                0x00,       // FRAG (fragment number, 0 = no fragmentation)
                0x01,       // ATYP (IPv4)
                0x00, 0x00, 0x00, 0x00, // DST.ADDR (0.0.0.0)
                0x00, 0x00, // DST.PORT (0)
            ];
            udp_packet.extend_from_slice(payload);

            if let Err(e) = udp_socket.send_to(&udp_packet, client_addr).await {
                error!("[SOCKS5] UDP ASSOCIATE: Failed to send packet to client {}: {}", client_addr, e);
                break;
            }
            debug!("[SOCKS5] UDP ASSOCIATE: Sent {} bytes to client {}", payload.len(), client_addr);
        }
        info!("[SOCKS5] UDP ASSOCIATE: Tunnel-to-client relay task ended");
    });

    // Spawn UDP relay task: receive from client, send to tunnel (or local DNS for split tunnel)
    let relay_to_tunnel = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        
        loop {
            // Check for idle timeout
            let idle_duration = {
                let last = last_activity.read().await;
                Instant::now().duration_since(*last)
            };
            if idle_duration >= UDP_IDLE_TIMEOUT {
                info!("[SOCKS5] UDP ASSOCIATE: Idle timeout after {:?}, closing association", idle_duration);
                break;
            }

            // Use timeout for recv_from to periodically check idle timeout
            match tokio::time::timeout(Duration::from_secs(1), udp_socket_clone.recv_from(&mut buf)).await {
                Ok(Ok((len, client_addr))) => {
                    // Update last activity timestamp on receiving data from client
                    *last_activity.write().await = Instant::now();

                    if len < 10 {
                        warn!("[SOCKS5] UDP ASSOCIATE: Received too short packet ({} bytes) from {}", len, client_addr);
                        continue;
                    }

                    // Parse SOCKS5 UDP request header
                    // Format: [RSV:2][FRAG:1][ATYP:1][DST.ADDR:variable][DST.PORT:2][DATA:variable]
                    let rsv = u16::from_be_bytes([buf[0], buf[1]]);
                    let frag = buf[2];
                    let atyp = buf[3];

                    if rsv != 0 {
                        warn!("[SOCKS5] UDP ASSOCIATE: Non-zero RSV: {}", rsv);
                    }

                    if frag != 0 {
                        // Fragmentation not supported
                        warn!("[SOCKS5] UDP ASSOCIATE: Fragmentation not supported (FRAG={})", frag);
                        continue;
                    }

                    // Parse destination address
                    let (header_len, _dst_addr, dst_port, dst_domain) = match atyp {
                        0x01 => {  // IPv4
                            if len < 10 {
                                warn!("[SOCKS5] UDP ASSOCIATE: IPv4 packet too short");
                                continue;
                            }
                            let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                            let port = u16::from_be_bytes([buf[8], buf[9]]);
                            let dst = SocketAddr::new(std::net::IpAddr::V4(ip), port);
                            (10, dst, port, None)
                        }
                        0x03 => {  // Domain
                            if len < 5 {
                                warn!("[SOCKS5] UDP ASSOCIATE: Domain packet too short");
                                continue;
                            }
                            let domain_len = buf[4] as usize;
                            if len < 5 + domain_len + 2 {
                                warn!("[SOCKS5] UDP ASSOCIATE: Domain packet too short for domain+port");
                                continue;
                            }
                            let domain = String::from_utf8_lossy(&buf[5..5 + domain_len]).to_string();
                            let port = u16::from_be_bytes([buf[5 + domain_len], buf[5 + domain_len + 1]]);
                            let dst = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), port);
                            (5 + domain_len + 2, dst, port, Some(domain))
                        }
                        0x04 => {  // IPv6
                            if len < 22 {
                                warn!("[SOCKS5] UDP ASSOCIATE: IPv6 packet too short");
                                continue;
                            }
                            let ip = std::net::Ipv6Addr::from([
                                buf[4], buf[5], buf[6], buf[7],
                                buf[8], buf[9], buf[10], buf[11],
                                buf[12], buf[13], buf[14], buf[15],
                                buf[16], buf[17], buf[18], buf[19],
                            ]);
                            let port = u16::from_be_bytes([buf[20], buf[21]]);
                            let dst = SocketAddr::new(std::net::IpAddr::V6(ip), port);
                            (22, dst, port, None)
                        }
                        _ => {
                            warn!("[SOCKS5] UDP ASSOCIATE: Unknown ATYP: {}", atyp);
                            continue;
                        }
                    };

                    // Extract payload (SOCKS5 header is not forwarded, just the payload)
                    let payload = &buf[header_len..len];

                    // Check if this is a DNS query (port 53) and apply split tunnel routing
                    if dst_port == 53 {
                        // Try to extract domain from DNS query payload
                        let query_domain = if let Some(ref domain) = dst_domain {
                            info!("📦 [DNS] UDP DNS query received for domain: {}", domain);
                            Some(domain.clone())
                        } else {
                            parse_dns_query_domain(payload)
                        };

                        // Use DNS forwarder if available and domain extracted
                        if let (Some(forwarder), Some(ref domain)) = (&dns_forwarder, &query_domain) {
                            info!("🔍 [DNS] Processing DNS query for '{}' via DNS forwarder", domain);
                            match forwarder.forward_query(payload, client_addr, domain).await {
                                Ok(DnsForwardResult::Forwarded) => {
                                    // Query forwarded to local DNS server
                                    // Response will be relayed by DNS forwarder
                                    info!("✅ [DNS] Query for '{}' forwarded to local DNS, waiting for response", domain);
                                    continue;
                                }
                                Ok(DnsForwardResult::Dropped) => {
                                    // Query was blocked, drop it
                                    info!("🚫 [DNS] Query for '{}' blocked and dropped", domain);
                                    continue;
                                }
                                Ok(DnsForwardResult::Tunnel) => {
                                    // Tunnel routing - fall through to normal tunnel forwarding
                                    info!("🔒 [DNS] Query for '{}' going through VPN tunnel", domain);
                                }
                                Err(e) => {
                                    warn!("⚠️  [DNS] DNS forwarder error for '{}': {}, falling back to tunnel", domain, e);
                                    // Fall through to tunnel forwarding
                                }
                            }
                        } else {
                            if dns_forwarder.is_none() {
                                warn!("⚠️  [DNS] DNS forwarder not initialized - query for '{}' will go through tunnel", 
                                    query_domain.as_deref().unwrap_or("unknown"));
                            } else if query_domain.is_none() {
                                warn!("⚠️  [DNS] Could not extract domain from DNS query - sending through tunnel");
                            }
                        }
                    }

                    // Send to tunnel (normal forwarding for non-DNS or tunnel DNS)
                    if let Err(e) = socks_to_tunnel_tx.send((payload.to_vec(), client_addr)).await {
                        error!("[SOCKS5] UDP ASSOCIATE: Failed to send packet to tunnel: {}", e);
                        break;
                    }
                    debug!("[SOCKS5] UDP ASSOCIATE: Forwarded {} bytes from client {} to tunnel", payload.len(), client_addr);
                }
                Ok(Err(e)) => {
                    error!("[SOCKS5] UDP ASSOCIATE: UDP socket receive error: {}", e);
                    break;
                }
                Err(_) => {
                    // Timeout - continue loop to check idle timeout
                    continue;
                }
            }
        }
        info!("[SOCKS5] UDP ASSOCIATE: Client-to-tunnel relay task ended");
    });

    // Keep the TCP connection open while UDP is active
    // Wait for either: control connection closes, or tunnel signals completion
    let mut buf = [0u8; 1];
    loop {
        tokio::select! {
            result = socket.read(&mut buf) => {
                match result {
                    Ok(0) => {
                        // Client closed connection
                        info!("[SOCKS5] UDP ASSOCIATE: Client closed control connection");
                        break;
                    }
                    Ok(_) => {
                        // Ignore any data on control connection
                        continue;
                    }
                    Err(e) => {
                        warn!("[SOCKS5] UDP ASSOCIATE: Control connection error: {}", e);
                        break;
                    }
                }
            }
            result = completion_rx.recv() => {
                match result {
                    Some(Ok(())) => {
                        info!("[SOCKS5] UDP ASSOCIATE: Tunnel signaled completion");
                    }
                    Some(Err(e)) => {
                        error!("[SOCKS5] UDP ASSOCIATE: Tunnel error: {}", e);
                    }
                    None => {
                        info!("[SOCKS5] UDP ASSOCIATE: Completion channel closed");
                    }
                }
                break;
            }
        }
    }

    // Abort relay tasks
    relay_to_client.abort();
    relay_to_tunnel.abort();

    info!("[SOCKS5] UDP ASSOCIATE: Closing relay at {}", relay_addr);
    Ok(())
}

/// Parse domain name from DNS query packet
/// 
/// DNS packet structure:
/// - 2 bytes: Transaction ID
/// - 2 bytes: Flags
/// - 2 bytes: Questions
/// - 2 bytes: Answer RRs
/// - 2 bytes: Authority RRs
/// - 2 bytes: Additional RRs
/// - Variable: Queries
/// 
/// Returns the domain name being queried, or None if parsing fails
fn parse_dns_query_domain(data: &[u8]) -> Option<String> {
    // DNS packet must be at least 12 bytes (header)
    if data.len() < 12 {
        return None;
    }
    
    // Check if this is a query (QR bit = 0)
    let flags = u16::from_be_bytes([data[2], data[3]]);
    if (flags & 0x8000) != 0 {
        // This is a response, not a query
        return None;
    }
    
    // Get number of questions
    let questions = u16::from_be_bytes([data[4], data[5]]);
    if questions == 0 {
        return None;
    }
    
    // Parse first query starting at byte 12
    let mut pos = 12;
    let mut domain_parts = Vec::new();
    
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            // End of domain name
            break;
        }
        // Check for compression pointer (shouldn't happen in queries, but be safe)
        if (len & 0xC0) == 0xC0 {
            // Compression pointer - skip it
            break;
        }
        if pos + len + 1 > data.len() {
            return None;
        }
        let label = String::from_utf8_lossy(&data[pos + 1..pos + 1 + len]);
        domain_parts.push(label.to_string());
        pos += len + 1;
    }
    
    if domain_parts.is_empty() {
        return None;
    }
    
    Some(domain_parts.join("."))
}

/// Get the next DNS server from a list, cycling through them
fn get_next_dns_server(servers: &[String], attempt: usize) -> Option<String> {
    if servers.is_empty() {
        return None;
    }
    Some(servers[attempt % servers.len()].clone())
}

async fn read_port(socket: &mut TcpStream) -> Result<u16> {
    let mut port = [0u8; 2];
    socket.read_exact(&mut port).await?;
    Ok(u16::from_be_bytes(port))
}

async fn send_socks5_success(socket: &mut TcpStream) -> Result<()> {
    // Send success response (bind address = 0.0.0.0:0)
    socket.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
    // Ensure the response is sent immediately
    socket.flush().await?;
    Ok(())
}

/// Send connection refused response to SOCKS5 client
async fn send_socks5_refused(socket: &mut TcpStream) -> Result<()> {
    // Send connection refused response (error code 0x05)
    socket.write_all(&[0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
    socket.flush().await?;
    Ok(())
}

/// Send a SOCKS5 error response to the client
/// 
/// Error codes:
/// - 0x01: General SOCKS server failure
/// - 0x02: Connection not allowed by ruleset (used for bypass detection)
/// - 0x03: Network unreachable
/// - 0x04: Host unreachable
/// - 0x05: Connection refused
/// - 0x06: TTL expired
/// - 0x07: Command not supported
/// - 0x08: Address type not supported
async fn send_socks5_error(socket: &mut TcpStream, error_code: u8) -> Result<()> {
    // Send error response with the specified error code
    // Format: [VER=0x05][REP=error][RSV=0x00][ATYP=IPv4][BND.ADDR=0.0.0.0][BND.PORT=0]
    socket.write_all(&[0x05, error_code, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).await?;
    socket.flush().await?;
    Ok(())
}

/// Request to connect to a target through the tunnel
#[derive(Debug)]
pub struct TunnelRequest {
    /// Target address (host:port)
    pub target_address: String,
    /// The SOCKS5 client socket
    pub socket: TcpStream,
    /// Channel to signal when relay is complete
    pub completion_sender: mpsc::Sender<Result<()>>,
}

/// Request for UDP association through the tunnel
#[derive(Debug)]
pub struct UdpAssociationRequest {
    /// Channel to send UDP packets from tunnel to SOCKS5 client
    pub packet_tx: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    /// Channel to receive UDP packets from SOCKS5 client to tunnel
    pub packet_rx: mpsc::Receiver<(Vec<u8>, SocketAddr)>,
    /// Channel to signal when UDP association is complete/cancelled
    pub completion_sender: mpsc::Sender<Result<()>>,
    /// Relay address for this UDP association (target for CreateFlow)
    pub relay_addr: SocketAddr,
}

/// UDP packet data received from the tunnel
#[derive(Debug)]
pub struct UdpPacket {
    /// Packet payload
    pub data: Vec<u8>,
    /// Source/destination address
    pub addr: SocketAddr,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_query_domain_simple() {
        // Create a simple DNS query for "example.com"
        // DNS header (12 bytes) + query
        let packet = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            // Query: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of domain
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];
        
        let domain = parse_dns_query_domain(&packet);
        assert_eq!(domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_parse_dns_query_domain_subdomain() {
        // DNS query for "www.google.com"
        let packet = vec![
            0xAB, 0xCD, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            // Query: www.google.com
            0x03, b'w', b'w', b'w',
            0x06, b'g', b'o', b'o', b'g', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of domain
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];
        
        let domain = parse_dns_query_domain(&packet);
        assert_eq!(domain, Some("www.google.com".to_string()));
    }

    #[test]
    fn test_parse_dns_query_domain_too_short() {
        // Packet too short
        let packet = vec![0x12, 0x34, 0x01, 0x00];
        let domain = parse_dns_query_domain(&packet);
        assert_eq!(domain, None);
    }

    #[test]
    fn test_parse_dns_query_response() {
        // DNS response (QR bit set) should return None
        let packet = vec![
            0x12, 0x34, // Transaction ID
            0x81, 0x80, // Flags: response (QR=1)
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            // Query: example.com
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of domain
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];
        
        let domain = parse_dns_query_domain(&packet);
        assert_eq!(domain, None);
    }

    #[test]
    fn test_parse_dns_query_no_questions() {
        // DNS query with no questions
        let packet = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x00, // Questions: 0
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
        ];
        
        let domain = parse_dns_query_domain(&packet);
        assert_eq!(domain, None);
    }

    #[test]
    fn test_parse_dns_query_china_domain() {
        // DNS query for "www.baidu.com"
        let packet = vec![
            0x11, 0x11, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            // Query: www.baidu.com
            0x03, b'w', b'w', b'w',
            0x05, b'b', b'a', b'i', b'd', b'u',
            0x03, b'c', b'o', b'm',
            0x00, // End of domain
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];
        
        let domain = parse_dns_query_domain(&packet);
        assert_eq!(domain, Some("www.baidu.com".to_string()));
    }

    #[tokio::test]
    async fn test_dns_config_default() {
        let config = DnsConfig::default();
        assert_eq!(config.tunnel_dns, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(config.bypass_dns, vec!["223.5.5.5"]);
    }

    #[test]
    fn test_get_next_dns_server() {
        let servers = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        
        assert_eq!(get_next_dns_server(&servers, 0), Some("1.1.1.1".to_string()));
        assert_eq!(get_next_dns_server(&servers, 1), Some("8.8.8.8".to_string()));
        assert_eq!(get_next_dns_server(&servers, 2), Some("1.1.1.1".to_string())); // Wrap around
        assert_eq!(get_next_dns_server(&servers, 3), Some("8.8.8.8".to_string()));
        
        let empty: Vec<String> = vec![];
        assert_eq!(get_next_dns_server(&empty, 0), None);
    }

    /// Integration test for split tunnel DNS routing
    #[tokio::test]
    async fn test_split_tunnel_dns_routing() {
        use crate::split_tunnel::SplitTunnelConfig;
        
        // Create a split tunnel config with CN bypass
        let config = SplitTunnelConfig {
            enabled: true,
            builtin_bypass_countries: vec!["CN".to_string()],
            block_ads: false,
            ..Default::default()
        };
        
        let split_tunnel = SplitTunnel::new(config, std::sync::Arc::new(rvpn_client::dns_cache::DnsResolver::new(true, 14400, 1000, false, true, vec![]))).await.unwrap();

        // Test China domain should bypass
        let routing = split_tunnel.decide_by_host("www.baidu.com").await;
        assert_eq!(routing, RoutingDecision::Bypass, "Baidu should bypass tunnel");
        
        // Test Google should tunnel
        let routing = split_tunnel.decide_by_host("www.google.com").await;
        assert_eq!(routing, RoutingDecision::Tunnel, "Google should go through tunnel");
        
        // Test Facebook should tunnel
        let routing = split_tunnel.decide_by_host("www.facebook.com").await;
        assert_eq!(routing, RoutingDecision::Tunnel, "Facebook should go through tunnel");
        
        // Test Alibaba should bypass
        let routing = split_tunnel.decide_by_host("www.alibaba.com").await;
        assert_eq!(routing, RoutingDecision::Bypass, "Alibaba should bypass tunnel");
        
        // Test YouTube should tunnel
        let routing = split_tunnel.decide_by_host("www.youtube.com").await;
        assert_eq!(routing, RoutingDecision::Tunnel, "YouTube should go through tunnel");
    }

    /// Test DNS forwarder creation
    #[tokio::test]
    async fn test_dns_forwarder_creation() {
        use crate::split_tunnel::SplitTunnelConfig;
        
        let dns_config = DnsConfig::default();
        let (response_tx, _response_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(10);
        
        // Test without split tunnel
        let forwarder = DnsForwarder::new(dns_config.clone(), None, response_tx.clone()).await;
        assert!(forwarder.is_ok(), "DNS forwarder should be created without split tunnel");
        
        // Test with split tunnel
        let config = SplitTunnelConfig {
            enabled: true,
            builtin_bypass_countries: vec!["CN".to_string()],
            block_ads: false,
            ..Default::default()
        };
        let split_tunnel = SplitTunnel::new(config, std::sync::Arc::new(rvpn_client::dns_cache::DnsResolver::new(true, 14400, 1000, false, true, vec![]))).await.unwrap();

        let forwarder = DnsForwarder::new(dns_config, Some(Arc::new(split_tunnel)), response_tx).await;
        assert!(forwarder.is_ok(), "DNS forwarder should be created with split tunnel");
    }

    /// Test DNS forwarder routing decision
    #[tokio::test]
    async fn test_dns_forwarder_routing() {
        use crate::split_tunnel::SplitTunnelConfig;
        
        let dns_config = DnsConfig {
            tunnel_dns: vec!["1.1.1.1".to_string()],
            bypass_dns: vec!["223.5.5.5".to_string()],
        };
        
        let config = SplitTunnelConfig {
            enabled: true,
            builtin_bypass_countries: vec!["CN".to_string()],
            block_ads: false,
            ..Default::default()
        };
        let split_tunnel = SplitTunnel::new(config, std::sync::Arc::new(rvpn_client::dns_cache::DnsResolver::new(true, 14400, 1000, false, true, vec![]))).await.unwrap();

        let (response_tx, _response_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(10);
        let forwarder = DnsForwarder::new(dns_config, Some(Arc::new(split_tunnel)), response_tx).await.unwrap();
        
        // Create a DNS query for baidu.com (should bypass)
        let baidu_query = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            0x05, b'b', b'a', b'i', b'd', b'u',
            0x03, b'c', b'o', b'm',
            0x00, // End of domain
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];
        
        let client_addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        let result = forwarder.forward_query(&baidu_query, client_addr, "baidu.com").await;
        assert!(result.is_ok(), "Forward query should succeed");
        assert!(matches!(result.unwrap(), DnsForwardResult::Forwarded), "Baidu should be forwarded to local DNS");
        
        // Create a DNS query for google.com (should tunnel)
        let google_query = vec![
            0x56, 0x78, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            0x06, b'g', b'o', b'o', b'g', b'l', b'e',
            0x03, b'c', b'o', b'm',
            0x00, // End of domain
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];
        
        let result = forwarder.forward_query(&google_query, client_addr, "google.com").await;
        assert!(result.is_ok(), "Forward query should succeed");
        assert!(matches!(result.unwrap(), DnsForwardResult::Tunnel), "Google should go through tunnel");
    }

    /// Test DNS packet parsing with various domain types
    #[test]
    fn test_dns_parsing_various_domains() {
        // Test short domain
        let packet = vec![
            0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        assert_eq!(parse_dns_query_domain(&packet), Some("com".to_string()));
        
        // Test longer domain
        let packet = vec![
            0x00, 0x02, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x06, b'g', b'o', b'o', b'g', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        assert_eq!(parse_dns_query_domain(&packet), Some("google.com".to_string()));
        
        // Test multi-level subdomain
        let packet = vec![
            0x00, 0x03, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, b'w', b'w', b'w',
            0x04, b't', b'e', b's', b't',
            0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
        ];
        assert_eq!(parse_dns_query_domain(&packet), Some("www.test.example.com".to_string()));
    }
}
