//! Re-export from rvpn-split-tunnel for backwards compatibility.
#![allow(unused_imports)]
pub use rvpn_split_tunnel::{
    SplitTunnel, RoutingDecision, SplitTunnelConfig,
    get_country_ips, get_country_domains,
    matches_china_domain, matches_ad_domain,
    is_china_domain, is_ad_domain,
    matches_force_tunnel_domain,
};
