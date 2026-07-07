// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// R-VPN split tunnel routing engine.

pub mod split_tunnel;
pub mod config;
pub mod dns_cache;

#[cfg(feature = "builtin-domains")]
pub mod builtin_domains;

#[cfg(feature = "builtin-ips")]
pub mod builtin_ips;

pub use split_tunnel::{SplitTunnel, RoutingDecision};
pub use config::SplitTunnelConfig;
pub use dns_cache::DnsResolver;

// Always export these — stubs return None/false when features disabled
#[cfg(feature = "builtin-ips")]
pub use builtin_ips::get_country_ips;
#[cfg(not(feature = "builtin-ips"))]
pub fn get_country_ips(_country_code: &str) -> Option<&'static [&'static str]> { None }

#[cfg(feature = "builtin-ips")]
pub use builtin_ips::supported_countries;

#[cfg(feature = "builtin-domains")]
pub use builtin_domains::get_country_domains;
#[cfg(not(feature = "builtin-domains"))]
pub fn get_country_domains(_country_code: &str) -> Option<&'static [&'static str]> { None }

#[cfg(feature = "builtin-domains")]
pub use builtin_domains::{matches_china_domain, matches_ad_domain, is_china_domain, is_ad_domain, matches_force_tunnel_domain};
