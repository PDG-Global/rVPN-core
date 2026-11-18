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

/// A parsed CIDR: network address normalized to the prefix, plus the prefix.
pub type Cidr = (IpAddr, u8);

/// Parse `address/prefix` (IPv4 or IPv6) into a normalized [`Cidr`].
/// IPv4-mapped IPv6 CIDRs with prefix >= 96 are canonicalized to IPv4.
pub fn parse_cidr(text: &str) -> Result<Cidr> {
    let (address, prefix) = text
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("CIDR must use address/prefix notation: {text}"))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid address in CIDR: {text}"))?;
    let prefix: u8 = prefix
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid prefix in CIDR: {text}"))?;
    let (address, prefix) = match address {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) if prefix >= 96 => (IpAddr::V4(v4), prefix - 96),
            Some(_) => anyhow::bail!("IPv4-mapped CIDR needs prefix >= 96: {text}"),
            None => (IpAddr::V6(v6), prefix),
        },
        v4 => (v4, prefix),
    };
    let max = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        anyhow::bail!("Prefix out of range in CIDR: {text}");
    }
    let network = match address {
        IpAddr::V4(v4) => IpAddr::V4(Ipv4Addr::from(u32::from(v4) & prefix_mask_v4(prefix))),
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & prefix_mask_v6(prefix))),
    };
    Ok((network, prefix))
}

/// Whether `cidr` contains `addr` (IPv4-mapped addresses canonicalized to v4).
pub fn cidr_contains(cidr: &Cidr, addr: IpAddr) -> bool {
    let addr = canonical_ip(addr);
    match (cidr.0, addr) {
        (IpAddr::V4(net), IpAddr::V4(addr)) => {
            ipv4_prefix_contains(u32::from(addr), u32::from(net), cidr.1)
        }
        (IpAddr::V6(net), IpAddr::V6(addr)) => {
            ipv6_prefix_contains(u128::from(addr), u128::from(net), cidr.1)
        }
        _ => false,
    }
}

fn canonical_ip(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(addr),
        v4 => v4,
    }
}

fn cidrs_overlap(a: &Cidr, b: &Cidr) -> bool {
    cidr_contains(a, b.0) || cidr_contains(b, a.0)
}

fn fmt_cidr(cidr: &Cidr) -> String {
    format!("{}/{}", cidr.0, cidr.1)
}

/// Opt-in exemptions to the client uplink egress boundary (register C24,
/// task #rVPN:#18). Defaults are the strict v1.3.7+ containment: no
/// client-to-client, no internal ranges. Both settings apply to the raw TUN
/// uplink filter, the iptables RVPN_FORWARD chain and the pf anchor; the
/// server's own relay paths ([`is_blocked_egress`]) never consult them.
#[derive(Debug, Clone, Default)]
pub struct ClientEgressPolicy {
    /// Permit client-to-client traffic within the server's own TUN pool.
    pub allow_client_to_client: bool,
    /// Normalized pool network (from `tun.tun_ip`).
    pub tun_subnet: Option<(Ipv4Addr, u8)>,
    /// The TUN gateway address itself: always denied, even with the flag on
    /// (it is a host address; the interface may not exist yet at init time).
    pub tun_gateway: Option<IpAddr>,
    /// Operator-listed internal ranges clients may reach (validated).
    pub allowed_ranges: Vec<Cidr>,
}

impl ClientEgressPolicy {
    /// Parse and validate the policy from configuration. Refuses dangerous
    /// allow-list entries (default routes, loopback, link-local/metadata,
    /// IPv6 ULA); host-address containment is checked at initialization,
    /// once the host's addresses have been enumerated.
    pub fn from_config(
        allow_client_to_client: bool,
        tun_ip: &str,
        allowed_internal_ranges: &[String],
    ) -> Result<Self> {
        let mut policy = Self {
            allow_client_to_client,
            ..Default::default()
        };
        let normalized = normalized_tun_subnet(tun_ip)?;
        if let (IpAddr::V4(network), prefix) = parse_cidr(&normalized)? {
            policy.tun_subnet = Some((network, prefix));
        }
        let gateway: IpAddr = tun_ip
            .split('/')
            .next()
            .unwrap_or(tun_ip)
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid TUN address: {tun_ip}"))?;
        policy.tun_gateway = Some(gateway);
        for text in allowed_internal_ranges {
            let cidr = parse_cidr(text)
                .with_context(|| format!("Invalid allowed_internal_ranges entry: {text}"))?;
            validate_allowed_range(&cidr, text)?;
            // No IPv6 pool exists and the uplink drops every IPv6 packet, so
            // a v6 entry could never be used — but it would still install an
            // ip6tables exemption, breaking the no-v6-forward invariant.
            // Refuse until an IPv6 pool exists.
            if cidr.0.is_ipv6() {
                anyhow::bail!(
                    "allowed_internal_ranges entry {text} is IPv6 — refused until an IPv6 pool exists (the IPv6 uplink is disabled)"
                );
            }
            // An entry overlapping the pool would re-open client-to-client
            // through the allow-list with the flag off. The pool is governed
            // by allow_client_to_client only.
            if let Some((network, prefix)) = policy.tun_subnet {
                let pool = (IpAddr::V4(network), prefix);
                if cidrs_overlap(&cidr, &pool) {
                    anyhow::bail!(
                        "allowed_internal_ranges entry {text} overlaps the TUN pool {} — client-to-client is governed by allow_client_to_client only; refusing to start",
                        fmt_cidr(&pool)
                    );
                }
            }
            policy.allowed_ranges.push(cidr);
        }
        Ok(policy)
    }
}

/// Ranges that must never appear in `allowed_internal_ranges`: loopback,
/// link-local (cloud metadata at 169.254.169.254), IPv6 loopback, link-local
/// and ULA (fc00::/7 covers fd00::/8 and the fd00:ec2::254 metadata endpoint).
fn forbidden_policy_ranges() -> Vec<Cidr> {
    vec![
        (IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)), 8),
        (IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)), 16),
        (IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
        (IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0)), 10),
        (IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0)), 7),
    ]
}

fn validate_allowed_range(cidr: &Cidr, text: &str) -> Result<()> {
    if cidr.1 == 0 {
        anyhow::bail!(
            "allowed_internal_ranges entry {text} is a default route — refusing to start"
        );
    }
    for forbidden in forbidden_policy_ranges() {
        if cidrs_overlap(cidr, &forbidden) {
            anyhow::bail!(
                "allowed_internal_ranges entry {text} overlaps {} (loopback/link-local/metadata/ULA) — refusing to start",
                fmt_cidr(&forbidden)
            );
        }
    }
    Ok(())
}

static CLIENT_EGRESS_POLICY: OnceLock<RwLock<ClientEgressPolicy>> = OnceLock::new();

fn client_egress_policy() -> &'static RwLock<ClientEgressPolicy> {
    CLIENT_EGRESS_POLICY.get_or_init(|| RwLock::new(ClientEgressPolicy::default()))
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
///
/// `policy` carries the opt-in client-egress exemptions (C24). Allow-list
/// entries containing any of the server's own addresses are refused here,
/// after enumeration; the runtime filter also denies host addresses ahead of
/// every exemption, so addresses that appear later (60s refresh) stay denied.
pub fn initialize_host_egress_policy(
    configured_public: &[IpAddr],
    policy: ClientEgressPolicy,
) -> Result<()> {
    if let Ok(mut state) = host_address_state().write() {
        state.configured = configured_public.iter().copied().collect();
    }
    refresh_host_egress_policy()?;
    {
        let state = host_address_state()
            .read()
            .map_err(|_| anyhow::anyhow!("Host-address policy lock is poisoned"))?;
        for cidr in &policy.allowed_ranges {
            for host in state.addresses.iter().chain(state.configured.iter()) {
                if cidr_contains(cidr, *host) {
                    anyhow::bail!(
                        "allowed_internal_ranges entry {} contains the server's own address {host} — refusing to start",
                        fmt_cidr(cidr)
                    );
                }
            }
        }
    }
    match client_egress_policy().write() {
        Ok(mut stored) => *stored = policy,
        Err(_) => anyhow::bail!("Client egress policy lock is poisoned"),
    }
    Ok(())
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
    // Reset the C24 exemptions too, so tests never inherit a policy.
    if let Ok(mut stored) = client_egress_policy().write() {
        *stored = ClientEgressPolicy::default();
    }
}

#[cfg(test)]
pub(crate) fn set_client_policy_for_test(policy: ClientEgressPolicy) {
    if let Ok(mut stored) = client_egress_policy().write() {
        *stored = policy;
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
    client_destination_permitted(destination).then_some(destination)
}

/// Client uplink destination policy (C24). Order is load-bearing:
/// fail-closed uninitialized state, then host-address denial (wins over every
/// exemption — the pool contains the gateway, a listed range could contain a
/// host address), then the opt-in pool/list exemptions, then the special-use
/// boundary. The server's own relay paths use [`is_blocked_egress`] instead
/// and never consult the exemptions.
fn client_destination_permitted(dest: IpAddr) -> bool {
    let state = match host_address_state().read() {
        Ok(state) => state,
        Err(_) => return false,
    };
    if !state.initialized {
        return false;
    }
    let canonical = canonical_ip(dest);
    if state.addresses.contains(&dest) || state.addresses.contains(&canonical) {
        return false;
    }
    let policy = match client_egress_policy().read() {
        Ok(policy) => policy,
        Err(_) => return false,
    };
    if Some(canonical) == policy.tun_gateway {
        return false;
    }
    if policy.allow_client_to_client {
        if let (IpAddr::V4(addr), Some((network, prefix))) = (canonical, policy.tun_subnet) {
            if ipv4_prefix_contains(u32::from(addr), u32::from(network), prefix) {
                return true;
            }
        }
    }
    if policy
        .allowed_ranges
        .iter()
        .any(|cidr| cidr_contains(cidr, canonical))
    {
        return true;
    }
    !is_blocked_special_address(dest)
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
        initialize_host_egress_policy(
            &[ip("8.8.8.8"), ip("2606:4700:4700::1111")],
            ClientEgressPolicy::default(),
        )
        .unwrap();
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

    // ---- C24: opt-in client egress exemptions (task #rVPN:#18) ----

    fn c2c_policy(allow: bool, ranges: &[&str]) -> ClientEgressPolicy {
        let ranges: Vec<String> = ranges.iter().map(|text| text.to_string()).collect();
        ClientEgressPolicy::from_config(allow, "10.200.0.1/24", &ranges).unwrap()
    }

    fn v4_dest(address: &str) -> Option<IpAddr> {
        permitted_tun_destination(&ipv4_packet(address.parse().unwrap(), 6, 20))
    }

    #[test]
    fn flag_off_preserves_strict_containment_byte_for_byte() {
        let _guard = host_policy_test_lock().lock().unwrap();
        set_host_policy_for_test(&[]);
        // Default policy: pool peers stay blocked exactly as in v1.3.7/v1.3.8.
        assert_eq!(v4_dest("10.200.0.5"), None);
        assert_eq!(v4_dest("10.200.0.1"), None);
        assert_eq!(v4_dest("1.1.1.1"), Some(ip("1.1.1.1")));
    }

    #[test]
    fn flag_on_permits_pool_peers_only() {
        let _guard = host_policy_test_lock().lock().unwrap();
        set_host_policy_for_test(&[]);
        set_client_policy_for_test(c2c_policy(true, &[]));

        assert_eq!(v4_dest("10.200.0.5"), Some(ip("10.200.0.5")));
        assert_eq!(v4_dest("10.200.0.254"), Some(ip("10.200.0.254")));
        // The exemption is pool-specific: the rest of 10/8 and every other
        // special-use range stays blocked, public internet stays open.
        for blocked in [
            "10.0.0.1",
            "10.200.1.5",
            "172.16.0.1",
            "192.168.1.5",
            "169.254.169.254",
            "100.64.0.1",
        ] {
            assert_eq!(v4_dest(blocked), None, "{blocked}");
        }
        assert_eq!(v4_dest("1.1.1.1"), Some(ip("1.1.1.1")));
        // The gateway is denied even though it sits inside the pool and was
        // not enumerated (the TUN device may not exist yet at init time).
        assert_eq!(v4_dest("10.200.0.1"), None);
        // Relay paths never consult the exemption.
        assert!(is_blocked_egress(ip("10.200.0.5")));
        set_host_policy_for_test(&[]);
    }

    #[test]
    fn host_addresses_win_over_the_pool_exemption() {
        let _guard = host_policy_test_lock().lock().unwrap();
        // A host address inside the pool (e.g. picked up by the 60s refresh)
        // stays denied even with the flag on.
        set_host_policy_for_test(&[ip("10.200.0.9")]);
        set_client_policy_for_test(c2c_policy(true, &[]));
        assert_eq!(v4_dest("10.200.0.9"), None);
        assert_eq!(v4_dest("10.200.0.5"), Some(ip("10.200.0.5")));
        set_host_policy_for_test(&[]);
    }

    #[test]
    fn allowed_ranges_permit_listed_destinations_only() {
        let _guard = host_policy_test_lock().lock().unwrap();
        set_host_policy_for_test(&[]);
        set_client_policy_for_test(c2c_policy(false, &["192.168.1.0/24"]));

        assert_eq!(v4_dest("192.168.1.5"), Some(ip("192.168.1.5")));
        assert_eq!(v4_dest("192.168.2.5"), None);
        assert_eq!(v4_dest("10.0.0.1"), None);
        assert_eq!(v4_dest("10.200.0.5"), None); // flag still off
                                                 // A host address inside a listed range stays denied (refresh case).
        set_host_policy_for_test(&[ip("192.168.1.10")]);
        set_client_policy_for_test(c2c_policy(false, &["192.168.1.0/24"]));
        assert_eq!(v4_dest("192.168.1.10"), None);
        assert_eq!(v4_dest("192.168.1.5"), Some(ip("192.168.1.5")));
        // Relays stay exemption-free.
        assert!(is_blocked_egress(ip("192.168.1.5")));
        set_host_policy_for_test(&[]);
    }

    #[test]
    fn uninitialized_policy_denies_even_with_exemptions() {
        let _guard = host_policy_test_lock().lock().unwrap();
        set_host_policy_for_test(&[]);
        set_client_policy_for_test(c2c_policy(true, &["192.168.1.0/24"]));
        if let Ok(mut state) = host_address_state().write() {
            state.initialized = false;
        }
        assert_eq!(v4_dest("10.200.0.5"), None);
        assert_eq!(v4_dest("192.168.1.5"), None);
        assert_eq!(v4_dest("1.1.1.1"), None);
        set_host_policy_for_test(&[]);
    }

    #[test]
    fn dangerous_allow_list_entries_refuse_startup() {
        for bad in [
            "0.0.0.0/0",
            "::/0",
            "127.0.0.0/8",
            "127.5.0.0/16",
            "169.254.0.0/16",
            "169.254.5.0/24",
            "::1/128",
            "fe80::/10",
            "fe80::1/128",
            "fc00::/7",
            "fd00::/8",
            "fd00:ec2::254/128",
            "not-a-cidr",
            "192.168.1.0/33",
            // Pool overlap: the allow-list must not re-open client-to-client
            // with the flag off (exact, subset and superset all refused).
            "10.200.0.0/24",
            "10.200.0.128/25",
            "10.0.0.0/8",
            // IPv6 entries are refused until an IPv6 pool exists.
            "2001:db8::/32",
            "2606:4700::/32",
        ] {
            assert!(
                ClientEgressPolicy::from_config(false, "10.200.0.1/24", &[bad.to_string()])
                    .is_err(),
                "accepted dangerous entry {bad}"
            );
        }
        // Valid entries parse and normalize.
        let policy = c2c_policy(false, &["192.168.1.5/24", "10.50.0.0/16"]);
        assert_eq!(policy.allowed_ranges[0], (ip("192.168.1.0"), 24));
        assert_eq!(policy.tun_subnet, Some(("10.200.0.0".parse().unwrap(), 24)));
        assert_eq!(policy.tun_gateway, Some(ip("10.200.0.1")));
    }

    #[test]
    fn allow_list_containing_a_server_address_refuses_initialization() {
        let _guard = host_policy_test_lock().lock().unwrap();
        // 192.0.2.0/24 is TEST-NET-1: never a real interface address, so the
        // refusal can only come from the configured-public check.
        let error = initialize_host_egress_policy(
            &[ip("192.0.2.10")],
            c2c_policy(false, &["192.0.2.0/24"]),
        );
        assert!(error.is_err());
        set_host_policy_for_test(&[]);
    }

    #[test]
    fn parse_cidr_normalizes_and_canonicalizes_mapped_addresses() {
        assert_eq!(
            parse_cidr("192.168.1.77/24").unwrap(),
            (ip("192.168.1.0"), 24)
        );
        assert_eq!(
            parse_cidr("::ffff:192.168.0.0/112").unwrap(),
            (ip("192.168.0.0"), 16)
        );
        assert!(parse_cidr("::ffff:192.168.0.0/64").is_err());
        assert!(cidr_contains(&(ip("10.200.0.0"), 24), ip("10.200.0.5")));
        assert!(!cidr_contains(&(ip("10.200.0.0"), 24), ip("10.200.1.5")));
        assert!(cidr_contains(
            &(ip("10.200.0.0"), 24),
            ip("::ffff:10.200.0.5")
        ));
        assert!(!cidr_contains(&(ip("10.200.0.0"), 24), ip("2606:4700::1")));
    }
}
