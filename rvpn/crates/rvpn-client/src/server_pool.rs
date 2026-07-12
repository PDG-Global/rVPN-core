// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Multi-server routing pool.

//! Registry of named servers referenced by the multi-server router.
//!
//! Each entry holds the pre-parsed URL, TLS knobs, and the pre-loaded X3DH
//! prekey bundle so that per-flow dispatch is a cheap `HashMap` lookup —
//! no disk I/O or JSON parsing on the hot path. The client's identity key
//! is shared across all servers (SSH-model: one key, many hosts).

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context as _, Result};

use rvpn_core::crypto::X3DHPublicBundle;

use crate::config::{ClientConfig, ServerEntry, ServerIdentityConfig};

/// The reserved name for the top-level (implicit) server.
pub const DEFAULT_SERVER_NAME: &str = "default";

/// A resolved server, ready to be handed to `StreamRelay::connect`.
///
/// The `identity_config` is per-server so a pinned `[[server]].fingerprint`
/// can override the top-level TOFU/strict settings.
#[derive(Debug, Clone)]
pub struct ResolvedServer {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub sni_hostname: Option<String>,
    pub bundle: Arc<X3DHPublicBundle>,
    pub identity_config: ServerIdentityConfig,
}

/// Registry of all servers keyed by name; `"default"` is always present.
#[derive(Debug, Clone)]
pub struct ServerPool {
    servers: HashMap<String, Arc<ResolvedServer>>,
    default_name: String,
}

impl ServerPool {
    /// Load and resolve every server declared in the config.
    ///
    /// The top-level `server_address` + `prekey_bundle` become the `"default"`
    /// entry; each `[[server]]` block adds another. Fails if any bundle can't
    /// be read, if names collide, or if a `[[server]]` uses the reserved
    /// name `"default"`.
    pub async fn from_config(config: &ClientConfig) -> Result<Self> {
        let mut servers: HashMap<String, Arc<ResolvedServer>> = HashMap::new();

        let default_bundle_path = config.prekey_bundle.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Prekey bundle file is required for the default server (set `prekey_bundle` in config)"
            )
        })?;
        let default_bundle = load_bundle(default_bundle_path).await?;
        let (host, port, path) = parse_server_url(&config.server_address);
        servers.insert(
            DEFAULT_SERVER_NAME.to_string(),
            Arc::new(ResolvedServer {
                name: DEFAULT_SERVER_NAME.to_string(),
                host,
                port,
                path,
                sni_hostname: config.sni_hostname.clone(),
                bundle: Arc::new(default_bundle),
                identity_config: config.server_identity.clone(),
            }),
        );

        for entry in &config.extra_servers {
            let name = entry.name.trim().to_string();
            if name.is_empty() {
                anyhow::bail!("[[server]] entry has empty name");
            }
            if name == DEFAULT_SERVER_NAME {
                anyhow::bail!(
                    "[[server]] name '{}' is reserved; use a different symbolic name",
                    DEFAULT_SERVER_NAME
                );
            }
            if servers.contains_key(&name) {
                anyhow::bail!("Duplicate server name '{}'", name);
            }

            let (host, port, path) = parse_server_url(&entry.address);
            let bundle = load_bundle(&entry.prekey_bundle).await?;
            let identity_config = resolve_identity(&config.server_identity, entry);

            servers.insert(
                name.clone(),
                Arc::new(ResolvedServer {
                    name,
                    host,
                    port,
                    path,
                    sni_hostname: entry.sni_hostname.clone(),
                    bundle: Arc::new(bundle),
                    identity_config,
                }),
            );
        }

        Ok(Self {
            servers,
            default_name: DEFAULT_SERVER_NAME.to_string(),
        })
    }

    /// Return the resolved server for `name`, falling back to the default
    /// entry if the name is unknown. In practice the router only ever emits
    /// names present in the pool, but the fallback keeps the caller total.
    pub fn get_or_default(&self, name: &str) -> Arc<ResolvedServer> {
        self.servers
            .get(name)
            .or_else(|| self.servers.get(&self.default_name))
            .cloned()
            .expect("ServerPool always contains the default entry")
    }

    /// Names of every configured server, including `"default"`.
    pub fn names(&self) -> Vec<&str> {
        self.servers.keys().map(|s| s.as_str()).collect()
    }

    /// Number of extra (non-default) servers.
    pub fn extra_count(&self) -> usize {
        self.servers.len().saturating_sub(1)
    }
}

async fn load_bundle(path: &std::path::Path) -> Result<X3DHPublicBundle> {
    let json = tokio::fs::read_to_string(path)
        .await
        .with_context(|| format!("Failed to read prekey bundle: {:?}", path))?;
    serde_json::from_str(&json)
        .with_context(|| format!("Failed to parse prekey bundle: {:?}", path))
}

fn resolve_identity(
    base: &ServerIdentityConfig,
    entry: &ServerEntry,
) -> ServerIdentityConfig {
    let mut cfg = base.clone();
    if let Some(fp) = entry.fingerprint.clone() {
        cfg.fingerprint = Some(fp);
    }
    cfg
}

/// Parse a server URL into `(host, port, path)`. Mirrors the helper in
/// `main.rs` / `socks5.rs`; duplicated here to avoid pulling the caller
/// into this module's dependency graph.
fn parse_server_url(url: &str) -> (String, u16, String) {
    let url = url
        .strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url);

    let (host_port, path) = url
        .split_once('/')
        .map(|(hp, p)| (hp, format!("/{}", p)))
        .unwrap_or((url, "/".to_string()));

    if host_port.starts_with('[') {
        if let Some(bracket_end) = host_port.find(']') {
            let host = host_port[1..bracket_end].to_string();
            let port = if bracket_end + 1 < host_port.len()
                && host_port.as_bytes()[bracket_end + 1] == b':'
            {
                host_port[bracket_end + 2..].parse().unwrap_or(443)
            } else {
                443
            };
            return (host, port, path);
        }
    }

    let (host, port) = host_port
        .split_once(':')
        .map(|(h, p)| (h.to_string(), p.parse().unwrap_or(443)))
        .unwrap_or_else(|| (host_port.to_string(), 443));

    (host, port, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_server_url_wss_with_path() {
        let (host, port, path) = parse_server_url("wss://example.com/api/v1/ws");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api/v1/ws");
    }

    #[test]
    fn parse_server_url_ipv6() {
        let (host, port, path) = parse_server_url("wss://[2001:db8::1]:8443/ws");
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, 8443);
        assert_eq!(path, "/ws");
    }
}
