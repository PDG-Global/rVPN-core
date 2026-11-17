// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of R-VPN.
//
// R-VPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Shared destination policy for every server-side egress path.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::{OnceLock, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use tracing::warn;

#[derive(Default)]
struct HostAddressState {
    initialized: bool,
    addresses: HashSet<IpAddr>,
    /// Operator-configured public addresses (1:1 NAT) that must survive
    /// interface re-enumeration.
    configured: HashSet<IpAddr>,
}

static HOST_ADDRESSES: OnceLock<RwLock<HostAddressState>> = OnceLock::new();

fn host_address_state() -> &'static RwLock<HostAddressState> {
    HOST_ADDRESSES.get_or_init(|| RwLock::new(HostAddressState::default()))
}

/// Special-use IPv4 destinations that must never be reached through client egress.
pub const BLOCKED_IPV4_CIDRS: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.31.196.0/24",
    "192.52.193.0/24",
    "192.88.99.0/24",
    "192.168.0.0/16",
    "192.175.48.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
];

/// Special-use IPv6 destinations that must never be reached through client egress.
pub const BLOCKED_IPV6_CIDRS: &[&str] = &[
    "::/128",
    "::1/128",
    "64:ff9b::/96",
    "64:ff9b:1::/48",
    "100::/64",
    "2001::/23",
    "2001:db8::/32",
    "2002::/16",
    "3fff::/20",
    "5f00::/16",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

/// Return whether a destination is outside the public-Internet egress boundary.
///
/// Before initialization and after a failed refresh, all destinations are
/// denied so an unknown host-address set can never fail open.
pub fn is_blocked_egress(addr: IpAddr) -> bool {
    match host_address_state().read() {
        Ok(state) => !state.initialized || is_blocked_by_host_addresses(addr, &state.addresses),
        Err(_) => true,
    }
}

fn is_blocked_special_address(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(addr) => is_blocked_ipv4(addr),
        IpAddr::V6(addr) => {
            if let Some(mapped) = addr.to_ipv4_mapped() {
                is_blocked_ipv4(mapped)
            } else {
                is_blocked_ipv6(addr)
            }
        }
    }
}

fn is_blocked_by_host_addresses(addr: IpAddr, host_addresses: &HashSet<IpAddr>) -> bool {
    is_blocked_special_address(addr) || host_addresses.contains(&addr)
}

/// Initialize the host-address deny set before accepting client connections.
///
/// `configured_public` lists operator-known public addresses that are not on
/// any local interface (1:1 NAT cloud deployments); they are denied in
/// addition to every enumerated interface address and survive refreshes.
pub fn initialize_host_egress_policy(configured_public: &[IpAddr]) -> Result<()> {
    if let Ok(mut state) = host_address_state().write() {
        state.configured = configured_public.iter().copied().collect();
    }
    refresh_host_egress_policy()
}

/// Refresh host addresses every minute; failed refreshes deny all client egress.
pub fn spawn_host_egress_refresh() {
    tokio::spawn(async {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            let result = tokio::task::spawn_blocking(refresh_host_egress_policy).await;
            if !matches!(result, Ok(Ok(()))) {
                if let Ok(mut state) = host_address_state().write() {
                    state.initialized = false;
                    state.addresses.clear();
                }
                warn!("Host-address refresh failed; denying client egress until recovery");
            }
        }
    });
}

fn refresh_host_egress_policy() -> Result<()> {
    let mut addresses = collect_host_addresses()?;
    let mut state = host_address_state()
        .write()
        .map_err(|_| anyhow::anyhow!("Host-address policy lock is poisoned"))?;
    if addresses.is_empty() && state.configured.is_empty() {
        anyhow::bail!("No host interface addresses found; refusing to fail open");
    }
    addresses.extend(state.configured.iter().copied());
    state.addresses = addresses;
    state.initialized = true;
    Ok(())
}

fn collect_host_addresses() -> Result<HashSet<IpAddr>> {
    #[cfg(target_os = "linux")]
    let output = Command::new("ip")
        .args(["-o", "addr", "show"])
        .output()
        .context("Failed to execute ip for host-address containment")?;
    #[cfg(not(target_os = "linux"))]
    let output = Command::new("ifconfig")
        .arg("-a")
        .output()
        .context("Failed to execute ifconfig for host-address containment")?;
    if !output.status.success() {
        anyhow::bail!(
            "Host-address enumeration failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(parse_host_addresses(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn parse_host_addresses(output: &str) -> HashSet<IpAddr> {
    let mut addresses = HashSet::new();
    for line in output.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        for pair in fields.windows(2) {
            if !matches!(pair[0], "inet" | "inet6") {
                continue;
            }
            let address = pair[1]
                .split('/')
                .next()
                .unwrap_or(pair[1])
                .split('%')
                .next()
                .unwrap_or(pair[1]);
            if let Ok(address) = address.parse() {
                addresses.insert(address);
            }
        }
    }
    addresses
}

/// Serializes tests that mutate or depend on the shared host-address policy
/// state. Tests touching `is_blocked_egress` must hold this lock for their
/// whole body and configure the policy via `set_host_policy_for_test`.
#[cfg(test)]
pub(crate) fn host_policy_test_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    &LOCK
}

#[cfg(test)]
pub(crate) fn set_host_policy_for_test(addrs: &[IpAddr]) {
    if let Ok(mut state) = host_address_state().write() {
        state.initialized = true;
        state.addresses = addrs.iter().copied().collect();
        state.configured.clear();
    }
}

fn is_blocked_ipv4(addr: Ipv4Addr) -> bool {
    let value = u32::from(addr);
    const PREFIXES: &[(u32, u8)] = &[
        (0x0000_0000, 8),
        (0x0a00_0000, 8),
        (0x6440_0000, 10),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc000_0200, 24),
        (0xc01f_c400, 24),
        (0xc034_c100, 24),
        (0xc058_6300, 24),
        (0xc0a8_0000, 16),
        (0xc0af_3000, 24),
        (0xc612_0000, 15),
        (0xc633_6400, 24),
        (0xcb00_7100, 24),
        (0xe000_0000, 4),
        (0xf000_0000, 4),
    ];
    PREFIXES
        .iter()
        .any(|&(network, prefix)| ipv4_prefix_contains(value, network, prefix))
}

fn is_blocked_ipv6(addr: Ipv6Addr) -> bool {
    let value = u128::from(addr);
    const PREFIXES: &[(u128, u8)] = &[
        (0, 128),
        (1, 128),
        (
            u128::from_be_bytes([0, 100, 255, 155, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            96,
        ),
        (
            u128::from_be_bytes([0, 100, 255, 155, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            48,
        ),
        (
            u128::from_be_bytes([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            64,
        ),
        (
            u128::from_be_bytes([32, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            23,
        ),
        (
            u128::from_be_bytes([32, 1, 13, 184, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            32,
        ),
        (
            u128::from_be_bytes([32, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            16,
        ),
        (
            u128::from_be_bytes([63, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            20,
        ),
        (
            u128::from_be_bytes([95, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            16,
        ),
        (
            u128::from_be_bytes([252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            7,
        ),
        (
            u128::from_be_bytes([254, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            10,
        ),
        (
            u128::from_be_bytes([255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            8,
        ),
    ];
    PREFIXES
        .iter()
        .any(|&(network, prefix)| ipv6_prefix_contains(value, network, prefix))
}

fn ipv4_prefix_contains(value: u32, network: u32, prefix: u8) -> bool {
    value & prefix_mask_v4(prefix) == network
}

fn ipv6_prefix_contains(value: u128, network: u128, prefix: u8) -> bool {
    value & prefix_mask_v6(prefix) == network
}

fn prefix_mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn prefix_mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

/// Normalize a configured IPv4 TUN address to its actual network CIDR.
pub fn normalized_tun_subnet(tun_ip: &str) -> anyhow::Result<String> {
    let (address, prefix) = tun_ip
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("TUN address must use ip/prefix notation: {tun_ip}"))?;
    let address: Ipv4Addr = address
        .parse()
        .map_err(|_| anyhow::anyhow!("TUN address must be IPv4: {tun_ip}"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid TUN prefix in {tun_ip}"))?;
    if prefix > 32 {
        anyhow::bail!("Invalid TUN prefix in {tun_ip}");
    }
    let network = u32::from(address) & prefix_mask_v4(prefix);
    Ok(format!("{}/{}", Ipv4Addr::from(network), prefix))
}

/// Parse and validate an uplink IP packet, returning its permitted destination.
///
/// Any malformed, truncated, IPv6, unsupported, or special-use packet returns `None`.
/// Raw IPv6 remains disabled until an IPv6 client pool and source binding exist.
pub fn permitted_tun_destination(packet: &[u8]) -> Option<IpAddr> {
    let destination = match packet.first().map(|byte| byte >> 4) {
        Some(4) => parse_ipv4_destination(packet)?,
        Some(6) => {
            parse_ipv6_destination(packet)?;
            return None;
        }
        _ => return None,
    };
    (!is_blocked_egress(destination)).then_some(destination)
}

fn parse_ipv4_destination(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 20 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len || packet.len() != total_len {
        return None;
    }
    Some(IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    )))
}

fn parse_ipv6_destination(packet: &[u8]) -> Option<IpAddr> {
    if packet.len() < 40 {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if packet.len() != 40 + payload_len {
        return None;
    }
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&packet[24..40]);
    Some(IpAddr::V6(Ipv6Addr::from(octets)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value
            .parse()
            .unwrap_or_else(|error| panic!("invalid test address {value}: {error}"))
    }

    #[test]
    fn host_addresses_include_linux_and_freebsd_interface_addresses() {
        let linux = "1: lo inet 127.0.0.1/8 scope host lo\n2: eth0 inet 198.51.100.10/24 scope global eth0\n2: eth0 inet6 2001:4860:4860::8888/64 scope global\n";
        let freebsd = "vtnet0: flags=...\n\tinet 203.0.113.20 netmask 0xffffff00\n\tinet6 2606:4700:4700::1111%vtnet0 prefixlen 64\n";
        let addresses = parse_host_addresses(&format!("{linux}{freebsd}"));
        for address in [
            "127.0.0.1",
            "198.51.100.10",
            "203.0.113.20",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
        ] {
            assert!(addresses.contains(&ip(address)), "{address}");
        }

        for address in ["198.51.100.10", "2001:4860:4860::8888"] {
            assert!(is_blocked_by_host_addresses(ip(address), &addresses));
        }
        assert!(!is_blocked_by_host_addresses(ip("1.1.1.1"), &addresses));
        assert!(is_blocked_by_host_addresses(ip("100.64.0.1"), &addresses));
    }

    #[test]
    fn configured_host_addresses_are_denied_for_raw_tun_and_relays() {
        let _guard = host_policy_test_lock().lock().unwrap();
        set_host_policy_for_test(&[ip("8.8.8.8"), ip("2606:4700:4700::1111")]);

        // Raw TUN: a packet to the server's own public address is dropped.
        let mut packet = ipv4_packet("8.8.8.8".parse().unwrap(), 6, 20);
        assert_eq!(permitted_tun_destination(&packet), None);
        // Same packet shape to a non-host public address is still permitted.
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        assert_eq!(permitted_tun_destination(&packet), Some(ip("1.1.1.1")));

        // Relays consult the same policy (handler::connect_fastest,
        // select_udp_target and permitted_dns_addresses all deny these).
        assert!(is_blocked_egress(ip("8.8.8.8")));
        assert!(is_blocked_egress(ip("2606:4700:4700::1111")));
        assert!(!is_blocked_egress(ip("1.1.1.1")));
    }

    #[test]
    fn configured_public_addresses_are_denied_alongside_interface_addresses() {
        let _guard = host_policy_test_lock().lock().unwrap();
        // 8.8.8.8 / 2606:4700:4700::1111 are not special-use ranges, so their
        // denial can only come from the configured list. This also exercises
        // real interface enumeration on the host (ip/ifconfig).
        initialize_host_egress_policy(&[ip("8.8.8.8"), ip("2606:4700:4700::1111")]).unwrap();
        assert!(is_blocked_egress(ip("8.8.8.8")));
        assert!(is_blocked_egress(ip("2606:4700:4700::1111")));

        // Raw TUN and relays share the policy.
        let mut packet = ipv4_packet("8.8.8.8".parse().unwrap(), 6, 20);
        assert_eq!(permitted_tun_destination(&packet), None);
        packet[16..20].copy_from_slice(&[1, 1, 1, 1]);
        assert_eq!(permitted_tun_destination(&packet), Some(ip("1.1.1.1")));
        set_host_policy_for_test(&[]);
    }

    #[test]
    fn uninitialized_host_policy_denies_all_client_egress() {
        // Outside the lock the policy is whatever a previous test left
        // behind, so assert the contract on a fresh state instead: simulate
        // a failed refresh by clearing the initialized flag.
        let _guard = host_policy_test_lock().lock().unwrap();
        if let Ok(mut state) = host_address_state().write() {
            state.initialized = false;
            state.addresses.clear();
        }
        assert!(is_blocked_egress(ip("8.8.8.8")));
        assert!(is_blocked_egress(ip("1.1.1.1")));
        set_host_policy_for_test(&[]);
    }

    #[test]
    fn denies_every_ipv4_range_boundary_and_allows_neighbors() {
        let cases = [
            ("0.0.0.0", "0.255.255.255", "1.0.0.0"),
            ("10.0.0.0", "10.255.255.255", "11.0.0.0"),
            ("100.64.0.0", "100.127.255.255", "100.128.0.0"),
            ("127.0.0.0", "127.255.255.255", "128.0.0.0"),
            ("169.254.0.0", "169.254.255.255", "169.255.0.0"),
            ("172.16.0.0", "172.31.255.255", "172.32.0.0"),
            ("192.0.0.0", "192.0.0.255", "192.0.1.0"),
            ("192.0.2.0", "192.0.2.255", "192.0.3.0"),
            ("192.31.196.0", "192.31.196.255", "192.31.197.0"),
            ("192.52.193.0", "192.52.193.255", "192.52.194.0"),
            ("192.88.99.0", "192.88.99.255", "192.88.100.0"),
            ("192.168.0.0", "192.168.255.255", "192.169.0.0"),
            ("192.175.48.0", "192.175.48.255", "192.175.49.0"),
            ("198.18.0.0", "198.19.255.255", "198.20.0.0"),
            ("198.51.100.0", "198.51.100.255", "198.51.101.0"),
            ("203.0.113.0", "203.0.113.255", "203.0.114.0"),
            ("224.0.0.0", "239.255.255.255", "223.255.255.255"),
            ("240.0.0.0", "255.255.255.255", "223.255.255.255"),
        ];
        for (first, last, public_neighbor) in cases {
            assert!(
                is_blocked_special_address(ip(first)),
                "{first} must be denied"
            );
            assert!(
                is_blocked_special_address(ip(last)),
                "{last} must be denied"
            );
            assert!(
                !is_blocked_special_address(ip(public_neighbor)),
                "{public_neighbor} must be allowed"
            );
        }
    }

    #[test]
    fn denies_ipv6_special_use_and_mapped_ipv4() {
        let denied = [
            "::",
            "::1",
            "64:ff9b::",
            "64:ff9b::7f00:1",
            "64:ff9b::a00:1",
            "64:ff9b::6440:1",
            "64:ff9b:1::",
            "100::",
            "100::ffff:ffff:ffff:ffff",
            "2001::",
            "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff",
            "2001:db8::",
            "2001:2::1",
            "2002::",
            "3fff::",
            "5f00::",
            "fc00::",
            "fe80::",
            "ff00::",
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:100.64.0.1",
            "::ffff:0.0.0.0",
        ];
        for addr in denied {
            assert!(
                is_blocked_special_address(ip(addr)),
                "{addr} must be denied"
            );
        }
        for addr in [
            Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0xffff, 0xffff),
            Ipv6Addr::new(0x64, 0xff9b, 1, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff),
            Ipv6Addr::new(
                0x2001, 0xdb8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
            Ipv6Addr::new(
                0x2002, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
            Ipv6Addr::new(
                0x3fff, 0x0fff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
            Ipv6Addr::new(
                0x5f00, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
            Ipv6Addr::new(
                0xfdff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
            Ipv6Addr::new(
                0xfebf, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            ),
        ] {
            assert!(
                is_blocked_special_address(IpAddr::V6(addr)),
                "{addr} must be denied"
            );
        }

        for addr in [
            "8.8.8.8",
            "1.1.1.1",
            "2001:200::1",
            "2001:4860:4860::8888",
            "2606:4700:4700::1111",
            "::ffff:8.8.8.8",
        ] {
            assert!(
                !is_blocked_special_address(ip(addr)),
                "{addr} must be allowed"
            );
        }
    }

    #[test]
    fn tun_subnet_is_normalized_and_config_defaults_stay_closed() {
        let config = crate::config::ServerConfig::default();
        assert!(!config.tun.enabled);
        assert!(config.network.nat_enabled);
        assert_eq!(
            normalized_tun_subnet(&config.tun.tun_ip).unwrap(),
            "10.200.0.0/24"
        );
        assert_eq!(
            normalized_tun_subnet("10.8.9.129/24").unwrap(),
            "10.8.9.0/24"
        );
        assert_eq!(normalized_tun_subnet("10.8.9.1/32").unwrap(), "10.8.9.1/32");
        assert_eq!(normalized_tun_subnet("10.8.9.1/0").unwrap(), "0.0.0.0/0");
        for invalid in ["10.0.0.1", "10.0.0.1/33", "fd00::1/64", "10.0.0.1/24/1"] {
            assert!(normalized_tun_subnet(invalid).is_err(), "{invalid}");
        }
    }

    fn ipv4_packet(destination: Ipv4Addr, protocol: u8, payload_len: usize) -> Vec<u8> {
        let total_len = 20 + payload_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[16..20].copy_from_slice(&destination.octets());
        packet
    }

    fn ipv6_packet(destination: Ipv6Addr, next_header: u8, payload_len: usize) -> Vec<u8> {
        let mut packet = vec![0u8; 40 + payload_len];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[6] = next_header;
        packet[24..40].copy_from_slice(&destination.octets());
        packet
    }

    #[test]
    fn raw_tun_accepts_public_protocols_and_denies_special_destinations() {
        let _guard = host_policy_test_lock().lock().unwrap();
        set_host_policy_for_test(&[]);
        for (protocol, payload_len) in [(6, 20), (17, 8), (1, 8)] {
            let mut public = ipv4_packet("8.8.8.8".parse().unwrap(), protocol, payload_len);
            if protocol == 17 {
                public[22..24].copy_from_slice(&53u16.to_be_bytes());
            }
            assert_eq!(permitted_tun_destination(&public), Some(ip("8.8.8.8")));
            let private = ipv4_packet("10.0.0.1".parse().unwrap(), protocol, payload_len);
            assert_eq!(permitted_tun_destination(&private), None);

            // Raw IPv6 is dropped entirely until an IPv6 client pool and
            // source binding exist (matches the pf/ip6tables posture).
            let mut public_v6 = ipv6_packet(
                "2606:4700:4700::1111".parse().unwrap(),
                protocol,
                payload_len,
            );
            if protocol == 17 {
                public_v6[42..44].copy_from_slice(&53u16.to_be_bytes());
            }
            assert_eq!(permitted_tun_destination(&public_v6), None);
            let private_v6 = ipv6_packet("fd00::1".parse().unwrap(), protocol, payload_len);
            assert_eq!(permitted_tun_destination(&private_v6), None);
        }
    }

    #[test]
    fn raw_tun_malformed_and_truncated_packets_fail_closed() {
        let valid = ipv4_packet("8.8.8.8".parse().unwrap(), 6, 20);
        for len in 0..20 {
            assert_eq!(permitted_tun_destination(&valid[..len]), None);
        }
        let mut bad_ihl = valid.clone();
        bad_ihl[0] = 0x44;
        assert_eq!(permitted_tun_destination(&bad_ihl), None);
        let mut truncated_header = valid[..20].to_vec();
        truncated_header[0] = 0x46;
        assert_eq!(permitted_tun_destination(&truncated_header), None);
        let mut bad_total = valid.clone();
        bad_total[3] += 1;
        assert_eq!(permitted_tun_destination(&bad_total), None);
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(permitted_tun_destination(&trailing), None);
        let mut unsupported = valid;
        unsupported[0] = 0x50;
        assert_eq!(permitted_tun_destination(&unsupported), None);

        let valid_v6 = ipv6_packet("2606:4700:4700::1111".parse().unwrap(), 6, 20);
        assert_eq!(permitted_tun_destination(&valid_v6[..39]), None);
        let mut bad_v6_len = valid_v6;
        bad_v6_len[5] += 1;
        assert_eq!(permitted_tun_destination(&bad_v6_len), None);
    }
}
