//! TUN Server - True TUN interface for TUN-to-TUN tunneling
//!
//! This module provides a TUN interface that operates at Layer 3 (IP packets).
//! When enabled, packets from clients are written to the TUN interface where
//! the kernel handles routing. Response packets from the TUN interface are
//! sent back to the appropriate client.
//!
//! Architecture:
//! - One TUN interface per server (shared across all clients)
//! - Client sessions are identified by their tunnel IP (10.200.0.x)
//! - Outbound packets from TUN are routed based on kernel routing table
//! - Packets are sent through mpsc channels to the session for encryption

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context as _, Result};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, trace, warn};

use crate::config::TunNetworkConfig;

/// TUN server that manages the server-side TUN interface
pub struct TunServer {
    /// Configuration
    config: TunNetworkConfig,
    /// Async TUN device handle (Arc-wrapped for sharing with spawned tasks)
    device: Option<Arc<tun_rs::AsyncDevice>>,
    /// Channels for routing response packets from TUN to correct client
    /// Maps client IP -> sender that routes through session encryption
    client_senders: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<Vec<u8>>>>>,
    /// IP address pool with DHCP-style lease management
    ip_pool: IpPool,
    /// Shutdown signal
    shutdown_tx: Option<tokio::sync::broadcast::Sender<()>>,
}

/// IP lease entry with expiration
struct LeaseEntry {
    /// Client identifier (e.g., client ID string)
    client_id: String,
    /// When the lease was granted
    #[allow(dead_code)]
    granted_at: Instant,
    /// When the lease expires
    expires_at: Instant,
}

/// IP address pool with DHCP-style allocation and lease management
struct IpPool {
    /// Lease duration
    lease_duration: Duration,
    /// Available IP addresses (excludes gateway and reserved)
    available: std::sync::Mutex<Vec<IpAddr>>,
    /// Currently allocated leases (IP -> LeaseEntry)
    allocated: std::sync::Mutex<HashMap<IpAddr, LeaseEntry>>,
}

impl IpPool {
    /// Create a new IP pool from CIDR notation
    fn new(network: &str, lease_duration: Duration) -> Result<Self> {
        let (gateway_ip, prefix) = parse_cidr(network)?;

        if prefix < 24 {
            anyhow::bail!("IP pool requires /24 or smaller prefix");
        }

        // Calculate the number of usable IPs
        // For /24, we have 256 IPs total: .0 (network), .1 (gateway), .2-.254 (usable), .255 (broadcast)
        let host_bits = 32 - prefix as u32;
        let total_hosts = (1u32 << host_bits) as usize;

        // Start from .2 (after gateway) to leave room for static routes
        // Gateway is .1, first usable is .2
        let start_offset = 2;

        let mut available = Vec::with_capacity(total_hosts.saturating_sub(start_offset + 2));

        for i in start_offset..(total_hosts - 2) {
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                gateway_ip.octets()[0],
                gateway_ip.octets()[1],
                gateway_ip.octets()[2],
                gateway_ip.octets()[3] + i as u8,
            ));
            available.push(ip);
        }

        // Reverse available IPs so allocation uses ascending order (pop takes from end)
        // Pool is built [3, 4, 5...254]; after reverse becomes [254, 253, 252...3]
        // Now pop() gives 3 first (ascending), then 4, etc.
        available.reverse();

        Ok(Self {
            lease_duration,
            available: std::sync::Mutex::new(available),
            allocated: std::sync::Mutex::new(HashMap::new()),
        })
    }

    /// Allocate an IP address for a client
    fn allocate(&self, client_id: &str) -> Option<IpAddr> {
        let mut available = self.available.lock().unwrap();
        let mut allocated = self.allocated.lock().unwrap();

        // Check if client already has a lease
        if let Some((ip, entry)) = allocated.iter_mut().find(|(_, e)| e.client_id == client_id) {
            // Extend existing lease
            entry.expires_at = Instant::now() + self.lease_duration;
            return Some(*ip);
        }

        // Allocate new IP from available pool
        let ip = available.pop()?;
        let now = Instant::now();
        allocated.insert(
            ip,
            LeaseEntry {
                client_id: client_id.to_string(),
                granted_at: now,
                expires_at: now + self.lease_duration,
            },
        );
        Some(ip)
    }

    /// Release an IP address back to the pool
    /// Returns true if the IP was successfully released, false if it wasn't allocated
    fn release(&self, ip: IpAddr) -> bool {
        let mut allocated = self.allocated.lock().unwrap();
        if let Some(entry) = allocated.remove(&ip) {
            debug!("Released IP {} (was leased to {})", ip, entry.client_id);
            drop(allocated);
            let mut available = self.available.lock().unwrap();
            available.push(ip);
            return true;
        }
        // If not in allocated, it was never ours to release - this indicates a bug elsewhere
        warn!("Attempted to release IP {} that was not allocated!", ip);
        false
    }

    /// Extend leases that still have an active session; reclaim expired
    /// leases that don't. `is_active` reports whether an IP currently has a
    /// live connection (registered downlink sender). Active sessions can
    /// live 24h+, so their leases are never reclaimed. A lease with no
    /// active session is a reconnect gap: the IP is kept for the whole
    /// lease duration (so a reconnecting client reclaims its previous
    /// tunnel IP) and returned to the pool only once the lease expires.
    /// Returns the number of reclaimed IPs.
    fn reclaim_expired(&self, is_active: impl Fn(&IpAddr) -> bool) -> usize {
        let mut allocated = self.allocated.lock().unwrap();
        let now = Instant::now();
        let mut reclaimed = Vec::new();

        for (ip, entry) in allocated.iter_mut() {
            if is_active(ip) {
                if entry.expires_at <= now {
                    entry.expires_at = now + self.lease_duration;
                }
            } else if entry.expires_at <= now {
                reclaimed.push(*ip);
            }
        }

        if reclaimed.is_empty() {
            return 0;
        }

        let mut available = self.available.lock().unwrap();
        for ip in &reclaimed {
            if let Some(entry) = allocated.remove(ip) {
                debug!("Reclaimed expired lease {} (was leased to {})", ip, entry.client_id);
                available.push(*ip);
            }
        }
        reclaimed.len()
    }

    /// Get the number of available IPs
    #[allow(dead_code)]
    fn available_count(&self) -> usize {
        self.available.lock().unwrap().len()
    }

    /// Get the number of currently leased IPs
    #[allow(dead_code)]
    fn leased_count(&self) -> usize {
        self.allocated.lock().unwrap().len()
    }
}

/// Parse CIDR notation (e.g., "10.200.0.1/24") into IP address and prefix length
fn parse_cidr(cidr: &str) -> Result<(std::net::Ipv4Addr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid CIDR format: expected 'ip/prefix'");
    }

    let ip: std::net::Ipv4Addr = parts[0]
        .parse()
        .with_context(|| format!("Invalid IP address: {}", parts[0]))?;

    let prefix: u8 = parts[1]
        .parse()
        .with_context(|| format!("Invalid prefix length: {}", parts[1]))?;

    if prefix > 32 {
        anyhow::bail!("Invalid prefix length for IPv4: {}", prefix);
    }

    Ok((ip, prefix))
}

impl TunServer {
    /// Create a new TUN server
    pub fn new(config: &TunNetworkConfig) -> Result<Self> {
        // Initialize IP pool with /24 network (256 IPs total, gateway at .1, pool starts at .2)
        let ip_pool = IpPool::new(&config.tun_ip, Duration::from_secs(3600))?;

        Ok(Self {
            config: config.clone(),
            device: None,
            client_senders: Arc::new(RwLock::new(HashMap::new())),
            ip_pool,
            shutdown_tx: None,
        })
    }

    /// Start the TUN interface and background tasks
    pub async fn start(&mut self) -> Result<()> {
        use tun_rs::DeviceBuilder;

        if !self.config.enabled {
            info!("TUN server is disabled in configuration");
            return Ok(());
        }

        info!("Starting TUN server...");

        // Parse CIDR notation to get IP and prefix
        let (ip_addr, prefix_len) = parse_cidr(&self.config.tun_ip)
            .with_context(|| format!("Invalid TUN IP: {}", self.config.tun_ip))?;

        // Create TUN device
        let device = DeviceBuilder::new()
            .name(&self.config.interface_name)
            .mtu(self.config.mtu)
            .layer(tun_rs::Layer::L3) // TUN is L3 (IP packets)
            .ipv4(ip_addr, prefix_len, None)
            .packet_information(false)
            .build_sync()
            .with_context(|| {
                format!(
                    "Failed to create TUN device: {}",
                    self.config.interface_name
                )
            })?;

        // Wrap in AsyncDevice
        let async_device = tun_rs::AsyncDevice::new(device)
            .with_context(|| "Failed to create async TUN device")?;

        self.device = Some(Arc::new(async_device));

        // Create shutdown channel
        let (shutdown_tx, _) = tokio::sync::broadcast::channel(1);
        self.shutdown_tx = Some(shutdown_tx.clone());

        info!(
            "TUN interface {} created with IP {}/{}, MTU {}",
            self.config.interface_name, ip_addr, prefix_len, self.config.mtu
        );

        // Spawn the read loop as a background task
        let device = self
            .device
            .clone()
            .ok_or_else(|| anyhow::anyhow!("TUN device not set"))?;
        let client_senders = self.client_senders.clone();
        let shutdown_tx = self
            .shutdown_tx
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Shutdown channel not initialized"))?;
        let shutdown_rx = shutdown_tx.subscribe();

        tokio::spawn(async move {
            if let Err(e) = Self::run_read_loop(device, client_senders, shutdown_rx).await {
                error!("TUN read loop ended with error: {}", e);
            } else {
                debug!("TUN read loop ended normally");
            }
        });

        Ok(())
    }

    /// Register a client session (called when client connects)
    /// Stores the mpsc sender that will be used to send encrypted packets back to the client
    pub async fn register_client(
        &self,
        client_ip: IpAddr,
        sender: mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
        let mut senders = self.client_senders.write().await;
        senders.insert(client_ip, sender);
        info!("Registered client {} for TUN response routing", client_ip);
        Ok(())
    }

    /// Unregister a client session (called when client disconnects)
    /// Takes the session's own downlink sender to validate ownership: after a
    /// fast reconnect, the map holds the NEW connection's sender for the same
    /// tunnel IP, and a stale connection's cleanup must not evict it.
    ///
    /// The IP lease is deliberately NOT released here. Leases are sticky per
    /// client identity so a reconnecting client reclaims its previous tunnel
    /// IP (the client's utun interface keeps that address across a lightweight
    /// reconnect; handing out a different one silently blackholes downlink).
    /// Idle leases are returned to the pool by reclaim_expired_leases once
    /// they expire with no active session.
    pub async fn unregister_client(
        &self,
        client_ip: IpAddr,
        client_id: &str,
        sender: &mpsc::Sender<Vec<u8>>,
    ) -> Result<()> {
        // Pool ownership check (defense in depth — the sender check below is
        // the real guard against the reconnect race).
        let pool_client_id = {
            let allocated = self.ip_pool.allocated.lock().unwrap();
            allocated.get(&client_ip).map(|e| e.client_id.clone())
        };

        if let Some(owner) = pool_client_id {
            if owner != client_id {
                // Another client now owns this IP — skip cleanup to avoid
                // corrupting the new connection's state
                warn!("Skipping unregister for IP {} — owned by {}, not {}",
                      client_ip, owner, client_id);
                return Ok(());
            }
        } else {
            debug!("Unregister for IP {} ({}): no pool lease (already reclaimed)",
                   client_ip, client_id);
        }

        // Remove the sender only if the registered sender still belongs to
        // THIS connection. After a fast reconnect the map holds the new
        // connection's sender for the same IP; removing it would kill the
        // live session's downlink.
        let mut senders = self.client_senders.write().await;
        match senders.get(&client_ip) {
            Some(existing) if existing.same_channel(sender) => {
                senders.remove(&client_ip);
                info!("Unregistered client {} (IP {}) from TUN server", client_id, client_ip);
            }
            Some(_) => {
                debug!("Skipping unregister for IP {} ({}): sender belongs to a newer connection",
                       client_ip, client_id);
            }
            None => {
                debug!("Unregister for IP {} ({}): no sender registered",
                       client_ip, client_id);
            }
        }
        Ok(())
    }

    /// Allocate an IP address for a client
    #[allow(dead_code)]
    pub async fn allocate_ip(&self, client_id: &str) -> Result<IpAddr> {
        // First reclaim expired leases that have no active session
        self.reclaim_expired_leases().await;

        match self.ip_pool.allocate(client_id) {
            Some(ip) => {
                info!("Allocated IP {} to client {}", ip, client_id);
                Ok(ip)
            }
            None => Err(anyhow::anyhow!("No available IPs in pool")),
        }
    }

    /// Release an IP address back to the pool
    #[allow(dead_code)]
    pub async fn release_ip(&self, ip: IpAddr) -> bool {
        let released = self.ip_pool.release(ip);
        if released {
            info!("Released IP {} back to pool", ip);
        } else {
            warn!("Failed to release IP {} - was not allocated", ip);
        }
        released
    }

    /// Extend leases with an active session; reclaim expired ones without
    /// one. A lease with a registered downlink sender belongs to a live
    /// connection and is renewed indefinitely (sessions can live 24h+).
    /// A lease with no sender is a reconnect gap — kept for the full lease
    /// duration for stickiness, then returned to the pool.
    #[allow(dead_code)]
    pub async fn reclaim_expired_leases(&self) -> usize {
        let senders = self.client_senders.read().await;
        let count = self.ip_pool.reclaim_expired(|ip| senders.contains_key(ip));
        if count > 0 {
            info!("Reclaimed {} expired IP leases", count);
        }
        count
    }

    /// Write packet to TUN interface (for sending to kernel/network)
    pub async fn write_to_tun(&self, packet: &[u8]) -> Result<()> {
        let device = self
            .device
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TUN device not initialized"))?
            .clone();

        trace!("Writing {} bytes to TUN device", packet.len());

        device
            .send(packet)
            .await
            .with_context(|| "Failed to write to TUN device")?;

        debug!("Wrote {} bytes to TUN interface", packet.len());
        Ok(())
    }

    /// Shutdown the TUN server
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down TUN server...");

        // Signal shutdown to background tasks
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }

        // Drop the device to close it
        self.device = None;

        info!("TUN server shutdown complete");
        Ok(())
    }

    /// Run the packet read loop - receives packets from TUN and routes to clients via channels
    /// The channels lead to the MultiplexerSession which encrypts and sends via WebSocket
    async fn run_read_loop(
        device: Arc<tun_rs::AsyncDevice>,
        client_senders: Arc<RwLock<HashMap<IpAddr, mpsc::Sender<Vec<u8>>>>>,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        let mtu = 1420; // Default MTU, could be passed as parameter if needed
        let mut buf = vec![0u8; mtu as usize + 100];

        info!("Starting TUN read loop");

        loop {
            tokio::select! {
                result = device.recv(&mut buf) => {
                    match result {
                        Ok(n) if n > 0 => {
                            let packet = buf[..n].to_vec();
                            debug!("Read {} bytes from TUN interface", n);

                            // Parse destination IP from packet to route to correct client
                            if let Some(dst_ip) = Self::parse_destination_ip(&packet) {
                                trace!("Routing {} bytes from TUN to {}", n, dst_ip);
                                let senders = client_senders.read().await;

                                if let Some(sender) = senders.get(&dst_ip) {
                                    // Clone sender to drop the read lock before sending
                                    let sender = sender.clone();
                                    drop(senders);

                                    // Send without blocking: this loop is shared
                                    // by ALL clients, so blocking on a stalled
                                    // client's full queue would head-of-line
                                    // block everyone's downlink. Overflow means
                                    // that client is stalled; TCP retransmits
                                    // recover the dropped packet.
                                    match sender.try_send(packet) {
                                        Ok(()) => {}
                                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                                            debug!(
                                                "TUN READ: response queue full for {} - packet dropped",
                                                dst_ip
                                            );
                                        }
                                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                                            error!(
                                                "Packet channel for {} closed - removing stale sender",
                                                dst_ip
                                            );
                                            let mut senders = client_senders.write().await;
                                            senders.remove(&dst_ip);
                                        }
                                    }
                                } else {
                                    warn!("TUN READ: No channel registered for destination IP {} - packet dropped!", dst_ip);
                                }
                            } else {
                                debug!("TUN READ: Could not parse destination IP from packet");
                            }
                        }
                        Ok(_) => continue,  // Zero bytes, keep reading
                        Err(e) => {
                            error!("TUN read error: {}", e);
                            break;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    info!("TUN read loop received shutdown signal");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Parse destination IP from an IP packet
    fn parse_destination_ip(packet: &[u8]) -> Option<IpAddr> {
        if packet.len() < 20 {
            return None;
        }

        let version = packet[0] >> 4;
        if version == 4 {
            // IPv4: destination IP is at bytes 16-19
            let ip = IpAddr::V4(std::net::Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            ));
            Some(ip)
        } else {
            None // IPv6 not supported yet
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> TunNetworkConfig {
        TunNetworkConfig {
            enabled: true,
            tun_ip: "10.200.0.1/24".to_string(),
            mtu: 1420,
            interface_name: "tun-test".to_string(),
            dns_servers: vec![],
        }
    }

    #[tokio::test]
    async fn allocate_is_sticky_per_client_id() {
        let ts = TunServer::new(&test_config()).unwrap();
        let ip1 = ts.allocate_ip("ik:alice").await.unwrap();
        let ip2 = ts.allocate_ip("ik:alice").await.unwrap();
        assert_eq!(ip1, ip2, "same client_id must reclaim the same IP");

        let ip3 = ts.allocate_ip("ik:bob").await.unwrap();
        assert_ne!(ip1, ip3, "different client_id must get a different IP");
    }

    #[tokio::test]
    async fn stale_unregister_does_not_evict_new_connection() {
        let ts = TunServer::new(&test_config()).unwrap();
        let ip = ts.allocate_ip("ik:alice").await.unwrap();

        let (tx_old, _rx_old) = mpsc::channel::<Vec<u8>>(1);
        ts.register_client(ip, tx_old.clone()).await.unwrap();

        // Fast reconnect: same identity reclaims the same IP and registers
        // a new sender, overwriting the old registration.
        let ip2 = ts.allocate_ip("ik:alice").await.unwrap();
        assert_eq!(ip, ip2);
        let (tx_new, _rx_new) = mpsc::channel::<Vec<u8>>(1);
        ts.register_client(ip, tx_new.clone()).await.unwrap();

        // The OLD connection's teardown must not evict the new sender.
        ts.unregister_client(ip, "ik:alice", &tx_old).await.unwrap();
        {
            let senders = ts.client_senders.read().await;
            let current = senders
                .get(&ip)
                .expect("new sender must survive stale unregister");
            assert!(current.same_channel(&tx_new));
        }

        // The lease must survive too: a third connect still gets the same IP.
        let ip3 = ts.allocate_ip("ik:alice").await.unwrap();
        assert_eq!(ip, ip3);

        // The NEW connection's own teardown removes its registration.
        ts.unregister_client(ip, "ik:alice", &tx_new).await.unwrap();
        let senders = ts.client_senders.read().await;
        assert!(!senders.contains_key(&ip));
    }

    #[tokio::test]
    async fn reclaim_expires_idle_leases_but_extends_active() {
        // Zero-duration lease: everything is immediately expired.
        let pool = IpPool::new("10.200.0.1/24", Duration::from_secs(0)).unwrap();
        let active_ip = pool.allocate("ik:active").unwrap();
        let idle_ip = pool.allocate("ik:idle").unwrap();

        let reclaimed = pool.reclaim_expired(|ip| ip == &active_ip);
        assert_eq!(reclaimed, 1, "only the idle lease should be reclaimed");

        // The active lease is still sticky for its owner.
        let again = pool.allocate("ik:active").unwrap();
        assert_eq!(again, active_ip);

        // The reclaimed IP went back to the available pool.
        let recycled = pool.allocate("ik:other").unwrap();
        assert_eq!(
            recycled, idle_ip,
            "reclaimed IP returns to the available pool"
        );
    }
}
