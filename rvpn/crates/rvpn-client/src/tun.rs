//! TUN Device Interface

use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use futures::FutureExt;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{interval, Duration};
use tracing::{error, info, trace};

use crate::config::TunConfig;
use crate::tunnel::VpnTunnel;
use crate::websocket::{Message, WebSocketWriter};
use rvpn_core::crypto::DoubleRatchet;
use rvpn_core::protocol::packet::parse_packet;
use rvpn_core::protocol::{ControlMessage, MultiplexedFrame};

/// Flow ID for TUN data frames (flow_id 0 is reserved for control messages)
const DATA_FLOW_ID: u32 = 1;

/// Uplink batching limits (mirror the mobile client's proven values).
///
/// Multiple TUN packets are coalesced into one padded + encrypted WebSocket
/// frame, so small packets (TCP ACKs, DNS queries) no longer each cost a
/// full 1KB-padded frame on the wire. The byte cap stays well below the 16KB
/// maximum padded size to leave room for frame headers and padding length.
const UPLINK_BATCH_MAX_FRAMES: usize = 16;
const UPLINK_BATCH_MAX_BYTES: usize = 14 * 1024;
const UPLINK_BATCH_WINDOW: Duration = Duration::from_millis(5);

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

    /// Run the TUN device with graceful shutdown support.
    ///
    /// Splits into independent uplink (TUN → tunnel) and downlink
    /// (tunnel → TUN) tasks so uplink backpressure (a full WebSocket send
    /// channel on a congested link) can never stall downlink delivery —
    /// previously both directions serialized through a single task and one
    /// tunnel write lock, so a slow uplink froze downloads entirely.
    /// Whichever direction ends first ends the tunnel.
    pub async fn run(
        &self,
        tunnel: Arc<RwLock<VpnTunnel>>,
        shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let if_name = self.config.interface_name.as_deref().unwrap_or("(auto)");
        info!("Starting TUN device {}", if_name);

        let device = self
            .device
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("TUN device not initialized"))?;

        // Split the tunnel into its parts: the downlink task owns the frame
        // receiver outright (no tunnel lock on the RX path at all), the
        // uplink task shares the writer and ratchet.
        let (writer, ratchet, frame_rx) = {
            let mut tunnel_guard = tunnel.write().await;
            if !tunnel_guard.is_connected() {
                return Err(anyhow::anyhow!("Tunnel not connected"));
            }
            let frame_rx = tunnel_guard
                .take_frame_rx()
                .ok_or_else(|| anyhow::anyhow!("Tunnel frame receiver already taken"))?;
            (tunnel_guard.writer(), tunnel_guard.ratchet(), frame_rx)
        };

        info!("TUN device running, processing packets...");

        let uplink = self.run_uplink(device, writer, ratchet, shutdown.clone());
        let downlink = self.run_downlink(device, frame_rx, shutdown);

        tokio::select! {
            r = uplink => r,
            r = downlink => r,
        }
    }

    /// Uplink task: read packets from the TUN device, coalesce them into
    /// batches, encrypt once per batch, and send through the tunnel.
    ///
    /// This task is the tunnel's only encryptor, so wire order matches
    /// ratchet message-number order trivially. The ratchet lock is held only
    /// around `encrypt` and released before the writer await, so a
    /// backpressured writer never blocks the receive loop's decrypts.
    async fn run_uplink(
        &self,
        device: &tun_rs::AsyncDevice,
        writer: WebSocketWriter,
        ratchet: Arc<Mutex<DoubleRatchet>>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let mut tun_buffer = vec![0u8; self.config.mtu as usize + 100]; // Extra space for headers

        // Keepalive timer - send keepalive every 15 seconds to prevent connection timeout and DPI detection
        let mut keepalive_interval = interval(Duration::from_secs(15));
        // Skip the first tick which fires immediately
        keepalive_interval.tick().await;

        // Reused batch buffer: encoded MultiplexedFrames concatenated, then
        // padded/encrypted/sent as one WebSocket message.
        let mut batch = BytesMut::with_capacity(UPLINK_BATCH_MAX_BYTES + 256);

        loop {
            // Wait for the first packet of the next batch, a keepalive tick,
            // or shutdown.
            let first_len = tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("TUN uplink received shutdown signal, stopping");
                        return Ok(());
                    }
                    continue;
                }

                // Keepalive: send ping every 15 seconds to prevent connection timeout and DPI detection
                _ = keepalive_interval.tick() => {
                    // A send failure means the WebSocket writer task is dead
                    // (half-open connection) — the tunnel is gone.
                    if let Err(e) = Self::send_keepalive(&writer, &ratchet).await {
                        error!("Keepalive failed, tunnel is dead: {}", e);
                        return Err(anyhow::anyhow!("Tunnel writer closed"));
                    }
                    trace!("Keepalive sent");
                    continue;
                }

                result = device.recv(&mut tun_buffer) => {
                    match result {
                        Ok(n) if n > 0 => n,
                        Ok(_) => continue,
                        Err(e) => {
                            error!("Failed to read from TUN device: {}", e);
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            continue;
                        }
                    }
                }
            };

            batch.clear();
            crate::dashboard::record_bytes_up(first_len as u64);
            if let Some(packet_info) = parse_packet(&tun_buffer[..first_len]) {
                trace!(
                    "TUN -> Tunnel: {:?} {}:{} -> {}:{}",
                    packet_info.protocol,
                    packet_info.src_ip,
                    packet_info.src_port.unwrap_or(0),
                    packet_info.dst_ip,
                    packet_info.dst_port.unwrap_or(0)
                );
            }
            Self::encode_data_frame(&mut batch, &tun_buffer[..first_len])?;
            let mut batch_frames = 1usize;

            // Drain any packets already queued in the kernel without
            // waiting. Only if at least one more packet was ready do we open
            // a short collection window so a burst coalesces — interactive
            // single-packet traffic (SYN, DNS) pays zero added latency.
            // The MTU headroom check guarantees any packet we read fits, so
            // no carry-over to the next batch is ever needed.
            let mut window: Option<tokio::time::Instant> = None;
            while batch_frames < UPLINK_BATCH_MAX_FRAMES
                && batch.len() + 6 + self.config.mtu as usize <= UPLINK_BATCH_MAX_BYTES
            {
                let next = match window {
                    None => device.recv(&mut tun_buffer).now_or_never(),
                    Some(deadline) => {
                        let remaining =
                            deadline.saturating_duration_since(tokio::time::Instant::now());
                        if remaining.is_zero() {
                            break;
                        }
                        match tokio::time::timeout(remaining, device.recv(&mut tun_buffer)).await {
                            Ok(r) => Some(r),
                            Err(_) => None, // window expired
                        }
                    }
                };

                match next {
                    Some(Ok(n)) if n > 0 => {
                        crate::dashboard::record_bytes_up(n as u64);
                        Self::encode_data_frame(&mut batch, &tun_buffer[..n])?;
                        batch_frames += 1;
                        if window.is_none() {
                            window = Some(tokio::time::Instant::now() + UPLINK_BATCH_WINDOW);
                        }
                    }
                    Some(Ok(_)) | None => break, // empty read or nothing queued
                    Some(Err(e)) => {
                        error!("Failed to read from TUN device: {}", e);
                        break;
                    }
                }
            }

            if batch_frames > 1 {
                trace!("TUN uplink: sending batch of {} packets", batch_frames);
            }
            Self::encrypt_and_send(&ratchet, &writer, &batch).await?;
        }
    }

    /// Downlink task: drain decrypted frames from the tunnel and write them
    /// to the TUN device. Needs no lock on the tunnel — it owns the frame
    /// receiver — so it keeps delivering packets even while the uplink is
    /// backpressured.
    async fn run_downlink(
        &self,
        device: &tun_rs::AsyncDevice,
        mut frame_rx: mpsc::UnboundedReceiver<MultiplexedFrame>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        loop {
            tokio::select! {
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        info!("TUN downlink received shutdown signal, stopping");
                        return Ok(());
                    }
                }

                frame = frame_rx.recv() => {
                    match frame {
                        Some(frame) => {
                            if frame.flow_id != DATA_FLOW_ID {
                                // Control frame (e.g. Pong keepalive
                                // responses) — consume silently.
                                trace!(
                                    "TUN downlink: discarded control frame (flow_id={})",
                                    frame.flow_id
                                );
                                continue;
                            }

                            let data = &frame.payload;
                            if data.is_empty() {
                                continue;
                            }

                            trace!("TUN RX: Received {} bytes from tunnel", data.len());
                            crate::dashboard::record_bytes_down(data.len() as u64);

                            if let Some(packet_info) = parse_packet(data) {
                                trace!(
                                    "TUN RX: {:?} {} -> {} ({} bytes)",
                                    packet_info.protocol,
                                    packet_info.src_ip,
                                    packet_info.dst_ip,
                                    data.len()
                                );
                            }

                            // Write to TUN device
                            if let Err(e) = device.send(data).await {
                                error!("Failed to write to TUN device: {}", e);
                            }
                        }
                        None => {
                            // Frame channel closed — the tunnel receive loop
                            // ended, so the connection is dead.
                            return Err(anyhow::anyhow!(
                                "Tunnel frame channel closed (receive loop ended)"
                            ));
                        }
                    }
                }
            }
        }
    }

    /// Encode one raw IP packet as a data MultiplexedFrame onto the batch.
    fn encode_data_frame(batch: &mut BytesMut, packet: &[u8]) -> Result<()> {
        MultiplexedFrame::new_data(DATA_FLOW_ID, Bytes::copy_from_slice(packet))
            .encode_to(batch)
            .map_err(|e| anyhow::anyhow!("Failed to encode data frame: {}", e))?;
        Ok(())
    }

    /// Pad, encrypt, and send one batch of encoded frames as a single
    /// WebSocket message.
    async fn encrypt_and_send(
        ratchet: &Arc<Mutex<DoubleRatchet>>,
        writer: &WebSocketWriter,
        encoded_frames: &[u8],
    ) -> Result<()> {
        // Pad to 1KB boundary (must match server's unpad_packet). Padding
        // amortises over the whole batch instead of inflating every packet.
        let padded = rvpn_core::protocol::padding::pad_packet(encoded_frames)
            .map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;

        let message = {
            let mut ratchet_guard = ratchet.lock().await;
            ratchet_guard
                .encrypt(padded.as_ref(), &[0x01])
                .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?
        };

        let encrypted = message
            .to_bytes()
            .context("Failed to serialize RatchetMessage")?;

        writer
            .send(Message::Binary(encrypted))
            .await
            .context("Failed to send through WebSocket")?;

        Ok(())
    }

    /// Send keepalive packet to maintain connection (ControlMessage::Ping on
    /// the control flow). Goes through the same encrypt+send path as data so
    /// ratchet message-number order matches wire order.
    async fn send_keepalive(
        writer: &WebSocketWriter,
        ratchet: &Arc<Mutex<DoubleRatchet>>,
    ) -> Result<()> {
        let ping = ControlMessage::Ping {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };
        let payload = bincode::serialize(&ping).context("Failed to serialize Ping")?;
        let mut buf = BytesMut::with_capacity(6 + payload.len());
        MultiplexedFrame::new_data(0, payload)
            .encode_to(&mut buf)
            .map_err(|e| anyhow::anyhow!("Failed to encode keepalive frame: {}", e))?;
        Self::encrypt_and_send(ratchet, writer, &buf).await
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
