//! TUN Device Interface

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, trace};

use crate::config::TunConfig;
use crate::tunnel::VpnTunnel;
use rvpn_core::protocol::packet::parse_packet;
use rvpn_core::protocol::PayloadType;

/// TUN device for full VPN functionality
pub struct TunDevice {
    /// Configuration
    config: TunConfig,

    /// Async TUN device handle
    device: Option<tun_rs::AsyncDevice>,
}

impl TunDevice {
    /// Create a new TUN device with server-assigned IP
    pub fn create_with_ip(config: &TunConfig, ip_cidr: &str) -> Result<Self> {
        // Parse CIDR notation (e.g., "10.200.0.2/24") to get IP and netmask
        let (ip_addr, prefix_len) = parse_cidr(ip_cidr)
            .with_context(|| format!("Invalid IP address format: {}", ip_cidr))?;

        // Create the TUN device using tun-rs DeviceBuilder
        let device = if let Some(ref name) = config.interface_name {
            // Use specified interface name
            info!("Creating TUN device '{}' with IP {}", name, ip_cidr);
            {
                let builder = tun_rs::DeviceBuilder::new()
                    .name(name)
                    .mtu(config.mtu)
                    .layer(tun_rs::Layer::L3)
                    .ipv4(ip_addr, prefix_len, None);
                #[cfg(not(windows))]
                let builder = builder.packet_information(false);
                builder.build_sync()
                    .with_context(|| format!("Failed to create TUN device '{}'", name))?
            }
        } else {
            // Auto-assign interface name
            info!("Creating TUN device with auto-assigned name");
            {
                let builder = tun_rs::DeviceBuilder::new()
                    .mtu(config.mtu)
                    .layer(tun_rs::Layer::L3)
                    .ipv4(ip_addr, prefix_len, None);
                #[cfg(not(windows))]
                let builder = builder.packet_information(false);
                builder.build_sync()
                    .with_context(|| "Failed to create TUN device (auto-name)")?
            }
        };

        // Get actual device name (may differ from requested if auto-assigned)
        let device_name = device.name().unwrap_or_else(|_| "unknown".to_string());
        info!(
            "TUN device '{}' created with IP {}/{}, MTU {}",
            device_name, ip_addr, prefix_len, config.mtu
        );

        // Wrap in AsyncDevice for async operations
        let async_device = tun_rs::AsyncDevice::new(device)
            .with_context(|| "Failed to create async TUN device")?;

        Ok(Self {
            config: config.clone(),
            device: Some(async_device),
        })
    }

    /// Create a new TUN device (legacy - requires ip_address in config)
    /// DEPRECATED: Use create_with_ip() with server-assigned IP instead
    #[allow(dead_code)]
    pub fn create(config: &TunConfig) -> Result<Self> {
        let ip_cidr: &String = config
            .ip_address
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No IP address configured and no server-assigned IP provided. Use create_with_ip() with server-assigned IP."))?;
        Self::create_with_ip(config, ip_cidr)
    }

    /// Run the TUN device with graceful shutdown support
    /// Reads packets from TUN and sends them through the tunnel
    pub async fn run(
        &self,
        tunnel: Arc<RwLock<VpnTunnel>>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let if_name = self.config.interface_name.as_deref().unwrap_or("(auto)");
        info!("Starting TUN device {}", if_name);

        let device = self
            .device
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TUN device not initialized"))?;

        // Check tunnel is connected
        {
            let tunnel_guard = tunnel.read().await;
            if !tunnel_guard.is_connected() {
                return Err(anyhow::anyhow!("Tunnel not connected"));
            }
        }

        info!("TUN device running, processing packets...");

        // Buffer for reading packets from TUN
        let mut tun_buffer = vec![0u8; self.config.mtu as usize + 100]; // Extra space for headers

        // Keepalive timer - send keepalive every 15 seconds to prevent connection timeout and DPI detection
        let mut keepalive_interval = interval(Duration::from_secs(15));
        // Skip the first tick which fires immediately
        keepalive_interval.tick().await;

        loop {
            tokio::select! {
                // Check for shutdown signal
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("TUN device received shutdown signal, stopping...");
                        break;
                    }
                }

                // Keepalive: send ping every 15 seconds to prevent connection timeout and DPI detection
                _ = keepalive_interval.tick() => {
                    // Check if the WebSocket writer has died (half-open connection)
                    let writer_dead = {
                        let tunnel_guard = tunnel.read().await;
                        tunnel_guard.is_writer_closed()
                    };
                    if writer_dead {
                        error!("WebSocket writer closed, tunnel is dead");
                        return Err(anyhow::anyhow!("Tunnel writer closed"));
                    }

                    // Send keepalive packet through tunnel
                    if let Err(e) = self.send_keepalive(&tunnel).await {
                        debug!("Keepalive failed: {}", e);
                    } else {
                        trace!("Keepalive sent");
                    }
                }

                // Read from TUN device and send to tunnel
                result = device.recv(&mut tun_buffer) => {
                    match result {
                        Ok(n) if n > 0 => {
                            let packet = &tun_buffer[..n];
                            trace!("Read {} bytes from TUN", n);

                            // Parse packet for logging/debugging
                            if let Some(packet_info) = parse_packet(packet) {
                                trace!(
                                    "TUN -> Tunnel: {:?} {}:{} -> {}:{}",
                                    packet_info.protocol,
                                    packet_info.src_ip,
                                    packet_info.src_port.unwrap_or(0),
                                    packet_info.dst_ip,
                                    packet_info.dst_port.unwrap_or(0)
                                );
                            }

                            // Send through tunnel
                            if let Err(e) = self.send_to_tunnel(&tunnel, packet).await {
                                error!("Failed to send packet to tunnel: {}", e);
                                // If the WebSocket writer is closed, the tunnel is dead (half-open connection)
                                let writer_dead = {
                                    let tunnel_guard = tunnel.read().await;
                                    tunnel_guard.is_writer_closed()
                                };
                                if writer_dead {
                                    return Err(anyhow::anyhow!("Tunnel writer closed"));
                                }
                            }
                        }
                        Ok(_) => {
                            // Zero bytes read, continue
                            continue;
                        }
                        Err(e) => {
                            error!("Failed to read from TUN device: {}", e);
                            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                        }
                    }
                }

                // Receive from tunnel and write to TUN
                result = self.recv_from_tunnel(&tunnel) => {
                    match result {
                        Ok(data) => {
                            if data.is_empty() {
                                // Keepalive or empty message, continue
                                trace!("recv_from_tunnel returned empty data");
                                continue;
                            }

                            trace!("TUN RX: Received {} bytes from tunnel", data.len());

                            // Parse packet for logging
                            if let Some(packet_info) = parse_packet(&data) {
                                trace!(
                                    "TUN RX: {:?} {} -> {} ({} bytes)",
                                    packet_info.protocol,
                                    packet_info.src_ip,
                                    packet_info.dst_ip,
                                    data.len()
                                );
                            }

                            // Write to TUN device
                            if let Err(e) = device.send(&data).await {
                                error!("Failed to write to TUN device: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("Failed to receive from tunnel: {}", e);
                            // Check if tunnel is still connected or writer has died
                            let tunnel_guard = tunnel.read().await;
                            if !tunnel_guard.is_connected() || tunnel_guard.is_writer_closed() {
                                return Err(anyhow::anyhow!("Tunnel disconnected"));
                            }
                            tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                        }
                    }
                }
            }
        }

        info!("TUN device stopped gracefully");
        Ok(())
    }

    /// Send packet data through the VPN tunnel
    async fn send_to_tunnel(&self, tunnel: &Arc<RwLock<VpnTunnel>>, data: &[u8]) -> Result<()> {
        let mut tunnel_guard = tunnel.write().await;

        // In TUN mode, send raw IP packets directly without JSON wrapping
        // The multiplexed frame protocol already provides the framing we need
        tunnel_guard
            .send_with_payload_type(data, PayloadType::Data)
            .await
            .with_context(|| "Failed to send data through tunnel")?;

        Ok(())
    }

    /// Send keepalive packet to maintain connection
    async fn send_keepalive(&self, tunnel: &Arc<RwLock<VpnTunnel>>) -> Result<()> {
        let mut tunnel_guard = tunnel.write().await;

        // Keepalive is just an empty payload with KeepAlive type
        // This proves the tunnel is still alive end-to-end
        tunnel_guard
            .send_with_payload_type(&[], PayloadType::KeepAlive)
            .await
            .with_context(|| "Failed to send keepalive")?;

        Ok(())
    }

    /// Receive packet data from the VPN tunnel
    /// In multiplexed mode, expects MultiplexedFrame with flow_id=1 for TUN data.
    /// Control frames (flow_id=0, e.g. Pong keepalive responses) are consumed
    /// silently and never returned to the caller.
    async fn recv_from_tunnel(&self, tunnel: &Arc<RwLock<VpnTunnel>>) -> Result<Bytes> {
        const DATA_FLOW_ID: u32 = 1;

        loop {
            let mut tunnel_guard = tunnel.write().await;

            let frame = tunnel_guard
                .recv_multiplexed_frame()
                .await
                .with_context(|| "Failed to receive multiplexed frame from tunnel")?;

            trace!("recv_from_tunnel: received frame flow_id={}, payload_len={}", frame.flow_id, frame.payload.len());

            if frame.flow_id == DATA_FLOW_ID {
                return Ok(frame.payload);
            }

            // Control frame (flow_id=0) - Pong keepalive responses, etc.
            // Discard and keep reading for the next data frame.
            trace!("recv_from_tunnel: discarded control frame (flow_id={})", frame.flow_id);
        }
    }

    /// Read a packet from the TUN device
    #[allow(dead_code)]
    async fn read_packet(&self) -> Result<Vec<u8>> {
        let device = self
            .device
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TUN device not initialized"))?;

        let mut buffer = vec![0u8; self.config.mtu as usize + 100];
        let n = device
            .recv(&mut buffer)
            .await
            .with_context(|| "Failed to read from TUN device")?;

        buffer.truncate(n);
        Ok(buffer)
    }

    /// Write a packet to the TUN device
    #[allow(dead_code)]
    async fn write_packet(&self, packet: &[u8]) -> Result<()> {
        let device = self
            .device
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TUN device not initialized"))?;

        device
            .send(packet)
            .await
            .with_context(|| "Failed to write to TUN device")?;

        Ok(())
    }
}

/// Parse CIDR notation (e.g., "10.200.0.2/24") into IP address and prefix length
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_cidr_ipv4() {
        let (ip, prefix) = parse_cidr("10.200.0.2/24").unwrap();
        assert_eq!(ip.to_string(), "10.200.0.2");
        assert_eq!(prefix, 24);
    }

    #[test]
    fn test_parse_cidr_ipv4_16() {
        let (ip, prefix) = parse_cidr("192.168.1.1/16").unwrap();
        assert_eq!(ip.to_string(), "192.168.1.1");
        assert_eq!(prefix, 16);
    }

    #[test]
    fn test_parse_cidr_invalid() {
        assert!(parse_cidr("invalid").is_err());
        assert!(parse_cidr("10.200.0.2").is_err()); // Missing prefix
        assert!(parse_cidr("10.200.0.2/33").is_err()); // Invalid prefix
    }
}
