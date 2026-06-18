//! IP packet handling

use bytes::Bytes;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP packet info extracted from raw packet
#[derive(Debug, Clone)]
pub struct PacketInfo {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Source port (if applicable)
    pub src_port: Option<u16>,
    /// Destination port (if applicable)
    pub dst_port: Option<u16>,
    /// Protocol number
    pub protocol: Protocol,
    /// Total packet length
    pub total_len: usize,
}

/// Transport protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Protocol {
    /// ICMP
    Icmp = 1,
    /// TCP
    Tcp = 6,
    /// UDP
    Udp = 17,
    /// ICMPv6
    Icmpv6 = 58,
    /// Other/unknown
    Other = 0,
}

impl From<u8> for Protocol {
    fn from(p: u8) -> Self {
        match p {
            1 => Self::Icmp,
            6 => Self::Tcp,
            17 => Self::Udp,
            58 => Self::Icmpv6,
            _ => Self::Other,
        }
    }
}

/// Parse IP packet and extract info
pub fn parse_packet(packet: &[u8]) -> Option<PacketInfo> {
    if packet.is_empty() {
        return None;
    }

    // Check IP version
    let version = (packet[0] >> 4) & 0x0f;

    match version {
        4 => parse_ipv4(packet),
        6 => parse_ipv6(packet),
        _ => None,
    }
}

fn parse_ipv4(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() < 20 {
        return None;
    }

    let header_len = ((packet[0] & 0x0f) * 4) as usize;
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let protocol = Protocol::from(packet[9]);

    let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

    let (src_port, dst_port) = match protocol {
        Protocol::Tcp | Protocol::Udp => {
            if packet.len() >= header_len + 4 {
                let src = u16::from_be_bytes([packet[header_len], packet[header_len + 1]]);
                let dst = u16::from_be_bytes([packet[header_len + 2], packet[header_len + 3]]);
                (Some(src), Some(dst))
            } else {
                (None, None)
            }
        }
        _ => (None, None),
    };

    Some(PacketInfo {
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
        src_port,
        dst_port,
        protocol,
        total_len,
    })
}

fn parse_ipv6(packet: &[u8]) -> Option<PacketInfo> {
    if packet.len() < 40 {
        return None;
    }

    let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let next_header = packet[6];
    let protocol = Protocol::from(next_header);

    let src_ip = parse_ipv6_addr(&packet[8..24]);
    let dst_ip = parse_ipv6_addr(&packet[24..40]);

    // Handle extension headers (simplified)
    let (src_port, dst_port) = match protocol {
        Protocol::Tcp | Protocol::Udp => {
            if packet.len() >= 44 {
                let src = u16::from_be_bytes([packet[40], packet[41]]);
                let dst = u16::from_be_bytes([packet[42], packet[43]]);
                (Some(src), Some(dst))
            } else {
                (None, None)
            }
        }
        _ => (None, None),
    };

    Some(PacketInfo {
        src_ip: IpAddr::V6(src_ip),
        dst_ip: IpAddr::V6(dst_ip),
        src_port,
        dst_port,
        protocol,
        total_len: 40 + payload_len,
    })
}

fn parse_ipv6_addr(bytes: &[u8]) -> Ipv6Addr {
    let mut segments = [0u16; 8];
    for i in 0..8 {
        segments[i] = u16::from_be_bytes([bytes[i * 2], bytes[i * 2 + 1]]);
    }
    Ipv6Addr::new(
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7],
    )
}

/// Create IPv4 packet bytes
pub fn create_ipv4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: Protocol,
    payload: &[u8],
) -> Bytes {
    let header_len = 20;
    let total_len = header_len + payload.len();

    let mut packet = vec![0u8; total_len];

    // Version and IHL
    packet[0] = 0x45; // IPv4, 5 words (20 bytes)

    // DSCP and ECN
    packet[1] = 0;

    // Total length
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());

    // Identification
    packet[4..6].copy_from_slice(&[0, 0]);

    // Flags and fragment offset
    packet[6..8].copy_from_slice(&[0, 0]);

    // TTL
    packet[8] = 64;

    // Protocol
    packet[9] = match protocol {
        Protocol::Icmp => 1,
        Protocol::Tcp => 6,
        Protocol::Udp => 17,
        Protocol::Icmpv6 => 58,
        Protocol::Other => 0,
    };

    // Source IP
    packet[12..16].copy_from_slice(&src.octets());

    // Destination IP
    packet[16..20].copy_from_slice(&dst.octets());

    // Payload
    packet[header_len..].copy_from_slice(payload);

    // Calculate checksum
    let checksum = calculate_ip_checksum(&packet[..header_len]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());

    Bytes::from(packet)
}

fn calculate_ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let len = header.len();

    // Add all 16-bit words
    for i in (0..len).step_by(2) {
        if i + 1 < len {
            sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        }
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}
