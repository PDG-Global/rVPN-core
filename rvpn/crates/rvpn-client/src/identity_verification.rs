//! Server identity verification with Trust on First Use (TOFU)
//!
//! This module provides protection against compromised servers by verifying
//! the server's X3DH identity key fingerprint, similar to SSH's known_hosts.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{error, info, warn};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use rvpn_core::crypto::X3DHPublicBundle;

/// Known hosts storage
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KnownHosts {
    /// Map of server address to fingerprint
    pub servers: HashMap<String, ServerIdentity>,
}

/// Server identity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerIdentity {
    /// Server's Ed25519 identity key fingerprint (hex encoded, first 32 chars)
    pub fingerprint: String,
    /// When this identity was first seen
    pub first_seen: String,
    /// When this identity was last verified
    pub last_verified: String,
}

/// Verification result
#[derive(Debug, Clone, PartialEq)]
pub enum VerificationResult {
    /// Identity matches known fingerprint
    Verified,
    /// New server identity (TOFU - first connection)
    New,
    /// Identity mismatch - possible compromised server
    Mismatch { expected: String, got: String },
}

impl KnownHosts {
    /// Load known hosts from file
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        if !path.as_ref().exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read known hosts file: {:?}", path.as_ref()))?;

        let hosts: KnownHosts = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse known hosts file: {:?}", path.as_ref()))?;

        Ok(hosts)
    }

    /// Save known hosts to file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content =
            serde_json::to_string_pretty(self).context("Failed to serialize known hosts")?;

        // Use OpenOptions for more control over file creation
        use std::fs::OpenOptions;
        use std::io::Write;

        let path = path.as_ref();
        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);

        #[cfg(unix)]
        opts.mode(0o644);

        let mut file = opts
            .open(path)
            .with_context(|| format!("Failed to open known hosts file for writing: {:?}", path))?;

        file.write_all(content.as_bytes())
            .with_context(|| format!("Failed to write known hosts file content: {:?}", path))?;

        file.sync_all()
            .with_context(|| format!("Failed to sync known hosts file: {:?}", path))?;

        Ok(())
    }

    /// Check if a server is known
    pub fn is_known(&self, server_address: &str) -> bool {
        self.servers.contains_key(server_address)
    }

    /// Get fingerprint for a server
    pub fn get_fingerprint(&self, server_address: &str) -> Option<&str> {
        self.servers
            .get(server_address)
            .map(|s| s.fingerprint.as_str())
    }

    /// Add or update a server identity
    pub fn add_server(&mut self, server_address: String, fingerprint: String) {
        let now = chrono::Local::now().to_rfc3339();

        let identity = ServerIdentity {
            fingerprint,
            first_seen: now.clone(),
            last_verified: now,
        };

        self.servers.insert(server_address, identity);
    }

    /// Update last verified timestamp
    #[allow(dead_code)]
    pub fn update_verified(&mut self, server_address: &str) {
        if let Some(identity) = self.servers.get_mut(server_address) {
            identity.last_verified = chrono::Local::now().to_rfc3339();
        }
    }
}

/// Compute fingerprint from X3DH public bundle
///
/// The fingerprint is the first 32 characters of the hex-encoded Ed25519 identity key
pub fn compute_fingerprint(bundle: &X3DHPublicBundle) -> String {
    // Use the Ed25519 identity key (not the X25519 derived key)
    let full_hex = hex::encode(bundle.identity_key);
    // Take first 32 characters (16 bytes) for the fingerprint
    full_hex[..32].to_string()
}

/// Verify server identity against known hosts
///
/// Returns the verification result and whether the connection should proceed
pub fn verify_server_identity(
    server_address: &str,
    bundle: &X3DHPublicBundle,
    known_hosts: &KnownHosts,
    config_fingerprint: Option<&str>,
    trust_on_first_use: bool,
    strict_mode: bool,
) -> (VerificationResult, bool) {
    let actual_fingerprint = compute_fingerprint(bundle);

    // First check: explicit fingerprint in config (highest priority)
    if let Some(expected) = config_fingerprint {
        let expected_normalized = expected.to_lowercase().replace(" ", "").replace(":", "");
        let actual_normalized = actual_fingerprint.to_lowercase();

        if expected_normalized != actual_normalized {
            error!("Server identity mismatch!");
            error!("  Expected: {}", format_fingerprint(&expected_normalized));
            error!("  Got:      {}", format_fingerprint(&actual_fingerprint));
            error!("  This could indicate a compromised server or MITM attack!");

            return (
                VerificationResult::Mismatch {
                    expected: expected.to_string(),
                    got: actual_fingerprint,
                },
                false,
            );
        }

        info!(
            "Server identity verified against configured fingerprint: {}",
            format_fingerprint(&actual_fingerprint)
        );
        return (VerificationResult::Verified, true);
    }

    // Second check: known hosts file
    if let Some(known_fingerprint) = known_hosts.get_fingerprint(server_address) {
        if known_fingerprint != actual_fingerprint {
            error!("Server identity mismatch for {}!", server_address);
            error!(
                "  Known fingerprint: {}",
                format_fingerprint(known_fingerprint)
            );
            error!(
                "  Got fingerprint:   {}",
                format_fingerprint(&actual_fingerprint)
            );
            error!("  This could indicate:");
            error!("    - Compromised server");
            error!("    - MITM attack");
            error!("    - Server identity key rotation (legitimate but rare)");
            error!("");
            error!("  To accept the new identity, remove the entry from known_hosts.json");

            return (
                VerificationResult::Mismatch {
                    expected: known_fingerprint.to_string(),
                    got: actual_fingerprint,
                },
                false,
            );
        }

        info!(
            "Server identity verified: {}",
            format_fingerprint(&actual_fingerprint)
        );
        return (VerificationResult::Verified, true);
    }

    // Third: new server (TOFU)
    if trust_on_first_use {
        if known_hosts.is_known(server_address) {
            // Server is known but fingerprint didn't match - this shouldn't happen
            // because we already checked get_fingerprint above
            error!(
                "Server {} is in known hosts but fingerprint lookup failed",
                server_address
            );
        }

        let formatted_fp = format_fingerprint(&actual_fingerprint);

        if strict_mode {
            // In strict mode, reject unknown servers
            warn!("New server identity detected for {} (strict mode enabled, rejecting)", server_address);
            return (VerificationResult::New, false);
        }

        warn!("New server identity detected for {}", server_address);
        warn!("  Fingerprint: {}", formatted_fp);
        warn!("  Raw: {}", actual_fingerprint);
        warn!("  This server will be trusted for future connections.");
        warn!("  If this is unexpected, verify the fingerprint with your server administrator.");

        return (VerificationResult::New, true);
    }

    // TOFU disabled and no known fingerprint
    error!("Unknown server identity for {}", server_address);
    error!("  Fingerprint: {}", actual_fingerprint);
    error!("  trust_on_first_use is disabled and no fingerprint is configured.");
    error!("  Add the fingerprint to your config or enable trust_on_first_use.");

    (VerificationResult::New, false)
}

/// Format fingerprint for display (adds colons for readability)
pub fn format_fingerprint(fingerprint: &str) -> String {
    fingerprint
        .as_bytes()
        .chunks(2)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or("??"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_fingerprint() {
        let bundle = X3DHPublicBundle {
            identity_key: [0xab; 32],
            identity_x25519_key: [0xcd; 32],
            signed_prekey: [0xef; 32],
            prekey_signature: [0x12; 64],
            one_time_prekey: None,
        };

        let fingerprint = compute_fingerprint(&bundle);
        assert_eq!(fingerprint.len(), 32);
        assert!(fingerprint.starts_with("abababab"));
    }

    #[test]
    fn test_format_fingerprint() {
        let fingerprint = "aabbccdd1122";
        let formatted = format_fingerprint(fingerprint);
        assert_eq!(formatted, "aa:bb:cc:dd:11:22");
    }
}
