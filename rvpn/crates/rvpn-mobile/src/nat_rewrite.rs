// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Per-session IP address rewriting for multi-server Direct TUN.

//! Multi-server Direct TUN holds one `/tun` session per exit server, and each
//! session is allocated its own virtual IP by that server. The OS utun
//! interface carries only the primary session's address, so packets routed
//! via a secondary exit must be rewritten:
//!
//! - **Uplink** (client → session X): source IP primary → session X's IP.
//!   The server writes uplink packets verbatim to its TUN device; without
//!   this, replies would come back addressed to an IP that belongs to a
//!   *different* session (or, on a shared IP pool, a different client).
//! - **Downlink** (session X → client): destination IP session X's IP →
//!   primary, so the OS network stack accepts the packet as local.
//!
//! Checksums are updated incrementally (RFC 1624) rather than recomputed:
//! one 32-bit word changes per rewrite, so the IP header checksum and the
//! TCP/UDP pseudo-header checksum each get a single-word adjustment.

use std::net::Ipv4Addr;

/// Rewrite the source address of an IPv4 packet in place.
/// Returns false (packet untouched) if it is not a usable IPv4 packet.
pub fn rewrite_src_ip(packet: &mut [u8], new_src: Ipv4Addr) -> bool {
    rewrite_addr(packet, new_src, AddrSlot::Source)
}

/// Rewrite the destination address of an IPv4 packet in place.
/// Returns false (packet untouched) if it is not a usable IPv4 packet.
pub fn rewrite_dst_ip(packet: &mut [u8], new_dst: Ipv4Addr) -> bool {
    rewrite_addr(packet, new_dst, AddrSlot::Destination)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddrSlot {
    Source,
    Destination,
}

impl AddrSlot {
    /// Byte offset of the address within the IPv4 header.
    fn offset(self) -> usize {
        match self {
            AddrSlot::Source => 12,
            AddrSlot::Destination => 16,
        }
    }
}

fn rewrite_addr(packet: &mut [u8], new_addr: Ipv4Addr, slot: AddrSlot) -> bool {
    // Version + IHL byte; need at least the 20-byte base header.
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return false;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if ihl < 20 || packet.len() < ihl {
        return false;
    }

    let off = slot.offset();
    let old = u32::from_be_bytes([packet[off], packet[off + 1], packet[off + 2], packet[off + 3]]);
    let new = u32::from(new_addr);
    if old == new {
        return true; // nothing to do
    }

    // 1. Write the new address.
    packet[off..off + 4].copy_from_slice(&new.to_be_bytes());

    // 2. IP header checksum (bytes 10-11): one word changed.
    let ip_csum = u16::from_be_bytes([packet[10], packet[11]]);
    let ip_csum = rfc1624_update(ip_csum, old, new);
    packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // 3. Transport checksum (TCP/UDP pseudo-header covers the addresses).
    //    Only the first fragment carries the transport header: skip when the
    //    fragment offset is non-zero (flags+offset field, bytes 6-7).
    let frag_field = u16::from_be_bytes([packet[6], packet[7]]);
    if frag_field & 0x1fff != 0 {
        return true;
    }
    let proto = packet[9];
    let csum_off = match proto {
        6 => ihl + 16,  // TCP checksum
        17 => ihl + 6,  // UDP checksum
        _ => return true,
    };
    if packet.len() < csum_off + 2 {
        return true; // truncated transport header — leave it alone
    }
    let t_csum = u16::from_be_bytes([packet[csum_off], packet[csum_off + 1]]);
    if proto == 17 && t_csum == 0 {
        return true; // UDP checksum disabled (0x0000) — stays disabled
    }
    let t_csum = rfc1624_update(t_csum, old, new);
    // UDP: a computed zero is transmitted as all-ones (RFC 768).
    let t_csum = if proto == 17 && t_csum == 0 { 0xffff } else { t_csum };
    packet[csum_off..csum_off + 2].copy_from_slice(&t_csum.to_be_bytes());

    true
}

/// RFC 1624 incremental checksum update for a 32-bit field change:
/// `HC' = ~(~HC + ~m + m')` computed with one's-complement arithmetic.
fn rfc1624_update(old_csum: u16, old_word: u32, new_word: u32) -> u16 {
    // Work in 32-bit space with carry fold-back.
    let mut sum = !old_csum as u32;
    sum += !(old_word >> 16) as u16 as u32;
    sum += !(old_word & 0xffff) as u16 as u32;
    sum += (new_word >> 16) as u16 as u32;
    sum += (new_word & 0xffff) as u16 as u32;
    // Fold carries (at most a few iterations needed).
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One's-complement checksum over a byte slice (used to verify results).
    fn checksum(data: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        let mut chunks = data.chunks_exact(2);
        for c in &mut chunks {
            sum += u16::from_be_bytes([c[0], c[1]]) as u32;
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            sum += (rem[0] as u32) << 8;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !sum as u16
    }

    /// Build an IPv4+TCP packet with correct header and transport checksums.
    fn build_tcp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut pkt = vec![0u8; 40]; // 20 IP + 20 TCP, no payload
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(40u16).to_be_bytes()); // total length
        pkt[8] = 64; // TTL
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        // TCP: sport=12345, dport=443, data offset 5
        pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&443u16.to_be_bytes());
        pkt[32] = 0x50;
        // IP header checksum
        let c = checksum(&pkt[0..20]);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());
        // TCP checksum over pseudo-header + segment
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(20u16).to_be_bytes()); // TCP length
        pseudo.extend_from_slice(&pkt[20..40]);
        let tc = checksum(&pseudo);
        pkt[36..38].copy_from_slice(&tc.to_be_bytes());
        pkt
    }

    fn tcp_checksum_valid(pkt: &[u8]) -> bool {
        let src = &pkt[12..16];
        let dst = &pkt[16..20];
        let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        let tcp_len = total - 20;
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(src);
        pseudo.extend_from_slice(dst);
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(tcp_len as u16).to_be_bytes());
        pseudo.extend_from_slice(&pkt[20..total]);
        checksum(&pseudo) == 0
    }

    #[test]
    fn tcp_rewrite_preserves_checksums() {
        let src: Ipv4Addr = "10.200.0.2".parse().unwrap();
        let dst: Ipv4Addr = "142.250.72.14".parse().unwrap();
        let session_ip: Ipv4Addr = "10.200.0.7".parse().unwrap();

        let mut pkt = build_tcp_packet(src, dst);
        assert_eq!(checksum(&pkt[0..20]), 0, "initial IP checksum valid");
        assert!(tcp_checksum_valid(&pkt), "initial TCP checksum valid");

        // Uplink: src primary -> session IP
        assert!(rewrite_src_ip(&mut pkt, session_ip));
        assert_eq!(&pkt[12..16], &session_ip.octets());
        assert_eq!(checksum(&pkt[0..20]), 0, "IP checksum valid after rewrite");
        assert!(tcp_checksum_valid(&pkt), "TCP checksum valid after rewrite");

        // Downlink on the other session: dst session IP -> primary
        let mut reply = build_tcp_packet(dst, session_ip);
        assert!(rewrite_dst_ip(&mut reply, src));
        assert_eq!(&reply[16..20], &src.octets());
        assert_eq!(checksum(&reply[0..20]), 0);
        assert!(tcp_checksum_valid(&reply));
    }

    #[test]
    fn rewrite_round_trip_restores_bytes() {
        let src: Ipv4Addr = "10.200.0.2".parse().unwrap();
        let dst: Ipv4Addr = "8.8.8.8".parse().unwrap();
        let session_ip: Ipv4Addr = "10.200.0.9".parse().unwrap();
        let original = build_tcp_packet(src, dst);
        let mut pkt = original.clone();
        assert!(rewrite_src_ip(&mut pkt, session_ip));
        assert_ne!(pkt, original);
        assert!(rewrite_src_ip(&mut pkt, src));
        assert_eq!(pkt, original, "A->B->A must restore the original packet");
    }

    #[test]
    fn udp_rewrite_updates_checksum() {
        let src: Ipv4Addr = "10.200.0.2".parse().unwrap();
        let dst: Ipv4Addr = "1.1.1.1".parse().unwrap();
        let session_ip: Ipv4Addr = "10.200.0.5".parse().unwrap();

        // IPv4 + UDP header + 4 bytes payload
        let mut pkt = vec![0u8; 32];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(32u16).to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        pkt[20..22].copy_from_slice(&53000u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&(12u16).to_be_bytes()); // UDP length
        pkt[28..32].copy_from_slice(&[1, 2, 3, 4]);
        let c = checksum(&pkt[0..20]);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());
        // UDP checksum
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.push(0);
        pseudo.push(17);
        pseudo.extend_from_slice(&(12u16).to_be_bytes());
        pseudo.extend_from_slice(&pkt[20..32]);
        let uc = checksum(&pseudo);
        let uc = if uc == 0 { 0xffff } else { uc };
        pkt[26..28].copy_from_slice(&uc.to_be_bytes());

        assert!(rewrite_dst_ip(&mut pkt, session_ip));
        // Validate UDP checksum after rewrite
        let mut pseudo2 = Vec::new();
        pseudo2.extend_from_slice(&src.octets());
        pseudo2.extend_from_slice(&session_ip.octets());
        pseudo2.push(0);
        pseudo2.push(17);
        pseudo2.extend_from_slice(&(12u16).to_be_bytes());
        pseudo2.extend_from_slice(&pkt[20..32]);
        assert_eq!(checksum(&pseudo2), 0, "UDP checksum valid after rewrite");
        assert_eq!(checksum(&pkt[0..20]), 0, "IP checksum valid after rewrite");
    }

    #[test]
    fn udp_zero_checksum_stays_zero() {
        let src: Ipv4Addr = "10.200.0.2".parse().unwrap();
        let session_ip: Ipv4Addr = "10.200.0.5".parse().unwrap();
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(28u16).to_be_bytes());
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&"1.1.1.1".parse::<Ipv4Addr>().unwrap().octets());
        // UDP checksum left at 0 (disabled)
        let c = checksum(&pkt[0..20]);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());

        assert!(rewrite_src_ip(&mut pkt, session_ip));
        assert_eq!(&pkt[26..28], &[0, 0], "disabled UDP checksum untouched");
        assert_eq!(checksum(&pkt[0..20]), 0);
    }

    #[test]
    fn rejects_non_ipv4_and_short() {
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        assert!(!rewrite_src_ip(&mut v6, Ipv4Addr::new(10, 0, 0, 1)));

        let mut short = vec![0x45u8; 10];
        assert!(!rewrite_dst_ip(&mut short, Ipv4Addr::new(10, 0, 0, 1)));

        let mut bad_ihl = vec![0u8; 60];
        bad_ihl[0] = 0x43; // IHL=3 < 5, invalid
        assert!(!rewrite_src_ip(&mut bad_ihl, Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn same_address_is_noop() {
        let src: Ipv4Addr = "10.200.0.2".parse().unwrap();
        let original = build_tcp_packet(src, "8.8.8.8".parse().unwrap());
        let mut pkt = original.clone();
        assert!(rewrite_src_ip(&mut pkt, src));
        assert_eq!(pkt, original);
    }

    #[test]
    fn non_first_fragment_skips_transport_checksum() {
        let src: Ipv4Addr = "10.200.0.2".parse().unwrap();
        let session_ip: Ipv4Addr = "10.200.0.5".parse().unwrap();
        let mut pkt = vec![0u8; 24];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&(24u16).to_be_bytes());
        // Fragment offset = 1 (non-first fragment)
        pkt[6..8].copy_from_slice(&(1u16).to_be_bytes());
        pkt[9] = 6; // TCP, but no transport header in this fragment
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&"8.8.8.8".parse::<Ipv4Addr>().unwrap().octets());
        let c = checksum(&pkt[0..20]);
        pkt[10..12].copy_from_slice(&c.to_be_bytes());

        assert!(rewrite_src_ip(&mut pkt, session_ip));
        assert_eq!(checksum(&pkt[0..20]), 0, "IP checksum still valid");
    }
}
