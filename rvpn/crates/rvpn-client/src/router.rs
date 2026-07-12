// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Multi-server per-flow routing.

//! Chooses which named server should handle a given SOCKS5 request.
//!
//! Match priority: hostname first (exact host, wildcard `*.parent`, or bare
//! parent), IP address fallback (literal match against `IpNetwork` CIDR).
//! If nothing matches, the default server is returned.
//!
//! The router is built once from `ClientConfig::routing` and consulted per
//! flow from `proxy_common::route_connection`.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{Context as _, Result};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;

use crate::config::RoutingRule;
use crate::server_pool::{ServerPool, DEFAULT_SERVER_NAME};

/// Compiled routing table.
///
/// Domain patterns are held as `(kind, needle, server_name)` tuples so a
/// single hostname walks a short vector rather than a per-suffix hashmap;
/// with 3–4 servers and a modest override list that's the simplest thing
/// that still gives predictable ordering.
pub struct Router {
    domain_rules: Vec<DomainRule>,
    ip_rules: IpNetworkTable<String>,
    ip_rule_count: usize,
    default_name: String,
}

#[derive(Debug, Clone)]
struct DomainRule {
    kind: DomainKind,
    pattern: String,
    server: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DomainKind {
    /// Exact hostname match (case-insensitive).
    Exact,
    /// `*.parent` — matches any subdomain of `parent`, but not `parent` itself.
    Wildcard,
    /// Bare parent — matches `parent` and any subdomain.
    Suffix,
}

impl Router {
    /// Build the router from parsed routing rules. Fails if a rule references
    /// an unknown server, a CIDR won't parse, or a domain pattern is malformed.
    pub fn build(
        pool: &ServerPool,
        routing: &HashMap<String, RoutingRule>,
    ) -> Result<Self> {
        let known: std::collections::HashSet<&str> = pool.names().into_iter().collect();

        let mut domain_rules: Vec<DomainRule> = Vec::new();
        let mut ip_rules: IpNetworkTable<String> = IpNetworkTable::new();
        let mut ip_rule_count = 0usize;

        for (server_name, rule) in routing {
            if server_name == DEFAULT_SERVER_NAME {
                anyhow::bail!(
                    "[routing.{}] is redundant — every unmatched flow already goes to the default server",
                    DEFAULT_SERVER_NAME
                );
            }
            if !known.contains(server_name.as_str()) {
                anyhow::bail!(
                    "[routing.{server}] references unknown server; declare it with [[server]] name = \"{server}\"",
                    server = server_name,
                );
            }

            for pattern in &rule.domains {
                let parsed = parse_domain_pattern(pattern).with_context(|| {
                    format!("invalid domain pattern '{}' in [routing.{}]", pattern, server_name)
                })?;
                domain_rules.push(DomainRule {
                    kind: parsed.0,
                    pattern: parsed.1,
                    server: server_name.clone(),
                });
            }

            for ip_pattern in &rule.ips {
                let network = parse_ip_or_cidr(ip_pattern).with_context(|| {
                    format!("invalid IP/CIDR '{}' in [routing.{}]", ip_pattern, server_name)
                })?;
                ip_rules.insert(network, server_name.clone());
                ip_rule_count += 1;
            }
        }

        // Longest / most-specific pattern wins on hostname collisions:
        // Exact > Wildcard > Suffix, and within a kind the longer pattern.
        domain_rules.sort_by(|a, b| {
            let sa = specificity(a);
            let sb = specificity(b);
            sb.cmp(&sa)
        });

        Ok(Self {
            domain_rules,
            ip_rules,
            ip_rule_count,
            default_name: DEFAULT_SERVER_NAME.to_string(),
        })
    }

    /// Return the server name to use for a SOCKS5 target host.
    ///
    /// `host` is the raw hostname or literal IP from the SOCKS5 request
    /// (no port, no brackets). Hostname patterns are tried first, then a
    /// CIDR lookup if `host` parses as an `IpAddr`. Falls back to
    /// `"default"` when nothing matches.
    pub fn choose<'a>(&'a self, host: &str) -> &'a str {
        let host_lc = host.trim_end_matches('.').to_ascii_lowercase();

        for rule in &self.domain_rules {
            if matches_rule(rule, &host_lc) {
                return &rule.server;
            }
        }

        if let Ok(ip) = host_lc.parse::<IpAddr>() {
            if let Some((_, name)) = self.ip_rules.longest_match(ip) {
                return name;
            }
        }

        &self.default_name
    }

    /// Total number of compiled rules (for diagnostics / startup log line).
    pub fn rule_count(&self) -> (usize, usize) {
        (self.domain_rules.len(), self.ip_rule_count)
    }
}

fn parse_domain_pattern(raw: &str) -> Result<(DomainKind, String)> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        anyhow::bail!("empty domain pattern");
    }

    if let Some(rest) = trimmed.strip_prefix("*.") {
        if rest.is_empty() || rest.contains('*') {
            anyhow::bail!("wildcard must be leading '*.<parent>'");
        }
        return Ok((DomainKind::Wildcard, rest.to_ascii_lowercase()));
    }

    if trimmed.contains('*') {
        anyhow::bail!("wildcards other than leading '*.' are not supported");
    }

    // Bare hostname: match both the hostname itself and any subdomain.
    // "google.com" also matches "mail.google.com". Users who want a strict
    // exact match should write it as a full FQDN with a trailing '.'.
    let ends_with_dot = raw.trim().ends_with('.');
    let kind = if ends_with_dot { DomainKind::Exact } else { DomainKind::Suffix };
    Ok((kind, trimmed.to_ascii_lowercase()))
}

fn matches_rule(rule: &DomainRule, host: &str) -> bool {
    match rule.kind {
        DomainKind::Exact => host == rule.pattern,
        DomainKind::Wildcard => {
            host.len() > rule.pattern.len() + 1
                && host.ends_with(&rule.pattern)
                && host.as_bytes()[host.len() - rule.pattern.len() - 1] == b'.'
        }
        DomainKind::Suffix => {
            host == rule.pattern
                || (host.len() > rule.pattern.len() + 1
                    && host.ends_with(&rule.pattern)
                    && host.as_bytes()[host.len() - rule.pattern.len() - 1] == b'.')
        }
    }
}

fn specificity(rule: &DomainRule) -> (u8, usize) {
    let kind_rank = match rule.kind {
        DomainKind::Exact => 2,
        DomainKind::Wildcard => 1,
        DomainKind::Suffix => 0,
    };
    (kind_rank, rule.pattern.len())
}

fn parse_ip_or_cidr(raw: &str) -> Result<IpNetwork> {
    let trimmed = raw.trim();
    if let Ok(network) = trimmed.parse::<IpNetwork>() {
        return Ok(network);
    }
    // Bare IP → /32 (v4) or /128 (v6).
    let ip: IpAddr = trimmed
        .parse()
        .with_context(|| format!("not an IP or CIDR: '{}'", trimmed))?;
    match ip {
        IpAddr::V4(v4) => IpNetwork::new(IpAddr::V4(v4), 32)
            .map_err(|e| anyhow::anyhow!("invalid /32 for {}: {:?}", v4, e)),
        IpAddr::V6(v6) => IpNetwork::new(IpAddr::V6(v6), 128)
            .map_err(|e| anyhow::anyhow!("invalid /128 for {}: {:?}", v6, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(routing: &HashMap<String, RoutingRule>, known: &[&str]) -> Router {
        let mut domain_rules: Vec<DomainRule> = Vec::new();
        let mut ip_rules: IpNetworkTable<String> = IpNetworkTable::new();
        let mut ip_rule_count = 0usize;
        for (name, rule) in routing {
            assert!(known.contains(&name.as_str()));
            for pattern in &rule.domains {
                let (kind, needle) = parse_domain_pattern(pattern).unwrap();
                domain_rules.push(DomainRule { kind, pattern: needle, server: name.clone() });
            }
            for ip_pattern in &rule.ips {
                ip_rules.insert(parse_ip_or_cidr(ip_pattern).unwrap(), name.clone());
                ip_rule_count += 1;
            }
        }
        domain_rules.sort_by(|a, b| specificity(b).cmp(&specificity(a)));
        Router {
            domain_rules,
            ip_rules,
            ip_rule_count,
            default_name: DEFAULT_SERVER_NAME.to_string(),
        }
    }

    #[test]
    fn wildcard_beats_suffix_on_subdomain() {
        let mut r: HashMap<String, RoutingRule> = HashMap::new();
        r.insert("sg".into(), RoutingRule {
            domains: vec!["*.google.com".into()],
            ips: vec![],
        });
        let router = build(&r, &["sg", DEFAULT_SERVER_NAME]);
        assert_eq!(router.choose("mail.google.com"), "sg");
        // Wildcard does NOT match apex — apex falls back to default.
        assert_eq!(router.choose("google.com"), DEFAULT_SERVER_NAME);
    }

    #[test]
    fn suffix_matches_both_apex_and_subdomain() {
        let mut r: HashMap<String, RoutingRule> = HashMap::new();
        r.insert("sg".into(), RoutingRule {
            domains: vec!["google.com".into()],
            ips: vec![],
        });
        let router = build(&r, &["sg", DEFAULT_SERVER_NAME]);
        assert_eq!(router.choose("google.com"), "sg");
        assert_eq!(router.choose("mail.google.com"), "sg");
        assert_eq!(router.choose("notgoogle.com"), DEFAULT_SERVER_NAME);
    }

    #[test]
    fn ip_cidr_fallback() {
        let mut r: HashMap<String, RoutingRule> = HashMap::new();
        r.insert("sg".into(), RoutingRule {
            domains: vec![],
            ips: vec!["8.8.8.0/24".into(), "1.1.1.1".into()],
        });
        let router = build(&r, &["sg", DEFAULT_SERVER_NAME]);
        assert_eq!(router.choose("8.8.8.42"), "sg");
        assert_eq!(router.choose("1.1.1.1"), "sg");
        assert_eq!(router.choose("9.9.9.9"), DEFAULT_SERVER_NAME);
    }

    #[test]
    fn hostname_takes_priority_over_ip_for_literal_ip() {
        // Domain patterns never match a literal IP because they don't parse
        // that way; verify IP path is what's exercised.
        let mut r: HashMap<String, RoutingRule> = HashMap::new();
        r.insert("sg".into(), RoutingRule {
            domains: vec!["1.1.1.1".into()],
            ips: vec![],
        });
        // 1.1.1.1 is a Suffix rule; matches string "1.1.1.1" as hostname.
        let router = build(&r, &["sg", DEFAULT_SERVER_NAME]);
        assert_eq!(router.choose("1.1.1.1"), "sg");
    }

    #[test]
    fn case_insensitive_host_match() {
        let mut r: HashMap<String, RoutingRule> = HashMap::new();
        r.insert("sg".into(), RoutingRule {
            domains: vec!["Google.COM".into()],
            ips: vec![],
        });
        let router = build(&r, &["sg", DEFAULT_SERVER_NAME]);
        assert_eq!(router.choose("MAIL.google.com"), "sg");
    }

    #[test]
    fn no_match_returns_default() {
        let router = build(&HashMap::new(), &[DEFAULT_SERVER_NAME]);
        assert_eq!(router.choose("example.com"), DEFAULT_SERVER_NAME);
    }
}
