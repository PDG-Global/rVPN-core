//! Server identity verification with Trust on First Use (TOFU)
//!
//! Protects against compromised servers by pinning the server's X3DH
//! Ed25519 identity key fingerprint, SSH-style. All pins are stored in
//! the canonical `ik:1:<base32>` form defined by
//! [`rvpn_core::identity_pin`]. Legacy truncated-hex pins written by
//! desktop builds prior to the format bump are still accepted on read
//! and quietly rewritten to canonical on the next successful verify —
//! see the "Migration" section below.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tracing::{error, info, warn};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use rvpn_core::crypto::X3DHPublicBundle;
use rvpn_core::identity_pin::{encode_identity_pin, pins_match, ParsedPin};

/// Resolve the server's identity-X25519 key for X3DH from a ServerHello,
/// mirroring the mobile client's rules (`rvpn-mobile/src/server_hello.rs`):
///
/// - wire key + wire signature: verify the signature against the wire
///   identity key, then use the **wire** key. A verified wire key wins
///   over the pre-loaded copy, so a server-side regeneration under the
///   same identity cannot strand the client on a stale on-disk value.
/// - neither: the pre-loaded bundle's key and signature — the legacy
///   unsigned migration path, accepted until clients require the proof.
/// - only one of the pair: refuse. A partial proof is malformed, never
///   a reason to fall back to the unsigned path.
///
/// A signed proof only ever speaks for the identity the client already
/// holds: the wire Ed25519 identity must equal the pre-loaded bundle's.
/// Verifying a wire X25519 key against a *wire-supplied* identity would
/// accept a proof the attacker signed themselves — the pre-loaded
/// bundle is the binding, and a different identity is refused outright
/// (rotation goes through the pin layer, not this path).
///
/// Returns the key to use for X3DH and the signature to carry in the
/// constructed bundle.
pub fn resolve_identity_x25519(
    wire_identity_key: &[u8; 32],
    hello_x25519_key: Option<&[u8]>,
    hello_x25519_signature: Option<&[u8]>,
    disk_bundle: &X3DHPublicBundle,
) -> Result<([u8; 32], Option<[u8; 64]>)> {
    if wire_identity_key != &disk_bundle.identity_key {
        anyhow::bail!(
            "wire identity does not match the pre-loaded bundle's identity; refusing the proof instead of binding X3DH to a new identity"
        );
    }
    match (hello_x25519_key, hello_x25519_signature) {
        (Some(key), Some(signature)) => {
            let key: [u8; 32] = key
                .try_into()
                .map_err(|_| anyhow::anyhow!("Server identity X25519 key has invalid length"))?;
            let signature: [u8; 64] = signature
                .try_into()
                .map_err(|_| anyhow::anyhow!("Identity X25519 signature has invalid length"))?;
            rvpn_core::crypto::verify_identity_x25519_signature(
                wire_identity_key,
                &key,
                &signature,
            )
            .map_err(|e| anyhow::anyhow!("Invalid identity X25519 signature: {}", e))?;
            Ok((key, Some(signature)))
        }
        (None, None) => Ok((
            disk_bundle.identity_x25519_key,
            disk_bundle.identity_x25519_signature,
        )),
        _ => anyhow::bail!("Server supplied only part of the signed identity X25519 proof"),
    }
}

/// Known hosts storage
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct KnownHosts {
    /// Map of server address to fingerprint
    pub servers: HashMap<String, ServerIdentity>,
}

/// Server identity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerIdentity {
    /// Server's Ed25519 identity key pin, canonical `ik:1:<base32>`.
    ///
    /// Historical desktop builds wrote the first-32-chars-of-hex form
    /// (`compute_fingerprint` in v1.2.6 and earlier). Those values are
    /// still accepted on read via [`rvpn_core::identity_pin::parse_pin`]
    /// and rewritten to canonical form on the next successful verify.
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
    Mismatch {
        /// The pin the client had stored (canonical form).
        expected: String,
        /// The pin derived from this connection (canonical form).
        got: String,
        /// True when `expected` came from the client's config file rather
        /// than the known_hosts store. A config pin is the operator's
        /// explicit choice and is ALWAYS enforced: `reject_mismatch = false`
        /// only relaxes mismatches against known_hosts-stored pins — see
        /// [`mismatch_is_fatal`].
        against_config_pin: bool,
    },
}

impl KnownHosts {
    /// Load known hosts from file.
    ///
    /// A missing file is an empty store (first run). A file that EXISTS
    /// but cannot be read or parsed is an ERROR, not an empty store:
    /// callers that proceeded anyway would TOFU-capture whatever answers
    /// and overwrite every stored pin on the next save — an identity-swap
    /// window that also destroys the pins. The distinction is made on the
    /// read error kind, not a prior `exists()` probe, so a permission
    /// error is never mistaken for "no file".
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let content = match std::fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => {
                return Err(e).context(format!("Failed to read known hosts file: {:?}", path))
            }
        };

        let hosts: KnownHosts = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse known hosts file: {:?}", path))?;

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

    /// Check if a server is known. Currently unused inside this crate —
    /// kept because it's part of the public surface of `KnownHosts` and a
    /// natural building block for CLI tooling that inspects the store.
    #[allow(dead_code)]
    pub fn is_known(&self, server_address: &str) -> bool {
        self.servers.contains_key(server_address)
    }

    /// Get fingerprint for a server (as stored on disk — may be legacy hex).
    pub fn get_fingerprint(&self, server_address: &str) -> Option<&str> {
        self.servers
            .get(server_address)
            .map(|s| s.fingerprint.as_str())
    }

    /// Add or update a server identity.
    ///
    /// The `fingerprint` should be a canonical `ik:1:<base32>` string —
    /// use [`encode_identity_pin`] to produce it. Legacy values coming
    /// from an old on-disk file are still stored as-is (see [`KnownHosts::load`])
    /// but every code path that calls `add_server` in this module now
    /// hands over a canonical pin.
    pub fn add_server(&mut self, server_address: String, fingerprint: String) {
        let now = chrono::Local::now().to_rfc3339();

        // Preserve `first_seen` across rewrites so we can tell "pin
        // migrated from legacy form" apart from "new server pinned for
        // the first time" in logs and audits. Only the fingerprint +
        // last_verified fields change on a migration rewrite.
        let first_seen = self
            .servers
            .get(&server_address)
            .map(|prev| prev.first_seen.clone())
            .unwrap_or_else(|| now.clone());

        let identity = ServerIdentity {
            fingerprint,
            first_seen,
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

/// Compute the canonical `ik:1:<base32>` pin for a server's public bundle.
///
/// Delegates to [`rvpn_core::identity_pin::encode_identity_pin`] on the
/// bundle's raw Ed25519 identity key. This replaces the legacy
/// "first 32 chars of hex" fingerprint that shipped in v1.2.6 and
/// earlier — the old format only carried 64 bits of collision
/// resistance, and mixing hex and base32 across desktop / mobile was a
/// footgun waiting to bite.
pub fn compute_fingerprint(bundle: &X3DHPublicBundle) -> String {
    encode_identity_pin(&bundle.identity_key)
        .expect("Ed25519 identity_key is 32 bytes by construction")
}

/// Verify server identity against the config-supplied pin and the
/// known-hosts store, mutating `known_hosts` where a legacy pin needs
/// to be rewritten to canonical form or a new server needs to be
/// added under TOFU.
///
/// Returns `(result, should_proceed)`. Any mutation of `known_hosts`
/// is confined to the paths that return `should_proceed = true`.
pub fn verify_server_identity(
    server_address: &str,
    bundle: &X3DHPublicBundle,
    known_hosts: &mut KnownHosts,
    config_fingerprint: Option<&str>,
    trust_on_first_use: bool,
    reject_new_identity: bool,
) -> (VerificationResult, bool) {
    let canonical_actual = compute_fingerprint(bundle);

    // 1. Config-supplied pin wins over everything else. If the operator
    //    pasted a fingerprint into their client config, they want that
    //    exact server no matter what known_hosts says — and a mismatch
    //    against it is ALWAYS fatal (against_config_pin = true): the
    //    reject_mismatch dev opt-in only relaxes known_hosts-stored pins
    //    (see mismatch_is_fatal).
    if let Some(expected) = config_fingerprint {
        let matched = match pins_match(expected, &bundle.identity_key) {
            Ok(v) => v,
            Err(e) => {
                error!("Configured server fingerprint is not a valid pin: {}", e);
                return (
                    VerificationResult::Mismatch {
                        expected: expected.to_string(),
                        got: canonical_actual,
                        against_config_pin: true,
                    },
                    false,
                );
            }
        };
        if !matched {
            error!("Server identity mismatch!");
            error!("  Expected: {}", format_fingerprint(expected));
            error!("  Got:      {}", format_fingerprint(&canonical_actual));
            error!("  This could indicate a compromised server or MITM attack!");
            return (
                VerificationResult::Mismatch {
                    expected: canonicalise_for_display(expected),
                    got: canonical_actual,
                    against_config_pin: true,
                },
                false,
            );
        }

        info!(
            "Server identity verified against configured fingerprint: {}",
            format_fingerprint(&canonical_actual)
        );
        return (VerificationResult::Verified, true);
    }

    // 2. Known-hosts lookup. The stored pin may be legacy hex written
    //    by an older desktop build — pins_match handles both. On a
    //    successful legacy match we quietly upgrade the entry to
    //    canonical form so subsequent runs never re-do the migration.
    if let Some(known_fingerprint) = known_hosts.get_fingerprint(server_address) {
        let stored = known_fingerprint.to_string();
        let stored_is_legacy = matches!(
            rvpn_core::identity_pin::parse_pin(&stored),
            Ok(ParsedPin { version: 0, .. })
        );
        let matched = pins_match(&stored, &bundle.identity_key).unwrap_or_else(|e| {
            error!(
                "Stored fingerprint for {} could not be parsed: {}",
                server_address, e
            );
            false
        });
        if !matched {
            error!("Server identity mismatch for {}!", server_address);
            error!("  Known fingerprint: {}", format_fingerprint(&stored));
            error!(
                "  Got fingerprint:   {}",
                format_fingerprint(&canonical_actual)
            );
            error!("  This could indicate:");
            error!("    - Compromised server");
            error!("    - MITM attack");
            error!("    - Server identity key rotation (legitimate but rare)");
            error!("");
            error!("  To accept the new identity, remove the entry from known_hosts.json");
            return (
                VerificationResult::Mismatch {
                    expected: canonicalise_for_display(&stored),
                    got: canonical_actual,
                    against_config_pin: false,
                },
                false,
            );
        }

        if stored_is_legacy {
            info!(
                "Migrating legacy fingerprint for {} to canonical ik:1: form",
                server_address
            );
            known_hosts.add_server(server_address.to_string(), canonical_actual.clone());
        } else {
            known_hosts.update_verified(server_address);
        }

        info!(
            "Server identity verified: {}",
            format_fingerprint(&canonical_actual)
        );
        return (VerificationResult::Verified, true);
    }

    // 3. New server → TOFU capture.
    if trust_on_first_use {
        if reject_new_identity {
            warn!(
                "New server identity detected for {} (reject_new_identity enabled, rejecting)",
                server_address
            );
            return (VerificationResult::New, false);
        }

        warn!("New server identity detected for {}", server_address);
        warn!("  Fingerprint: {}", format_fingerprint(&canonical_actual));
        warn!("  Raw:         {}", canonical_actual);
        warn!("  This server will be trusted for future connections.");
        warn!("  If this is unexpected, verify the fingerprint with your server administrator.");

        known_hosts.add_server(server_address.to_string(), canonical_actual);
        return (VerificationResult::New, true);
    }

    // TOFU disabled and no known fingerprint
    error!("Unknown server identity for {}", server_address);
    error!("  Fingerprint: {}", canonical_actual);
    error!("  trust_on_first_use is disabled and no fingerprint is configured.");
    error!("  Add the fingerprint to your config or enable trust_on_first_use.");

    (VerificationResult::New, false)
}

/// Persist `known_hosts` after a verification, failing hard when a fresh
/// TOFU pin can't be saved.
///
/// A TOFU capture (`VerificationResult::New` with `should_proceed`) that
/// never reaches disk means the next session re-captures blindly — a fresh
/// identity-swap window — so a save failure there must fail the connection.
/// For `Verified` and `Mismatch` no new pin was at stake; a save failure
/// stays warn-only.
pub fn persist_known_hosts<P: AsRef<Path>>(
    known_hosts: &KnownHosts,
    path: P,
    result: &VerificationResult,
    should_proceed: bool,
) -> Result<()> {
    match known_hosts.save(path) {
        Ok(()) => Ok(()),
        Err(e) if matches!(result, VerificationResult::New) && should_proceed => {
            Err(e.context("Failed to persist new server identity pin"))
        }
        Err(e) => {
            warn!("Failed to persist known_hosts.json: {}", e);
            Ok(())
        }
    }
}

/// Whether a [`VerificationResult::Mismatch`] must reject the connection.
///
/// A mismatch against a config-pinned fingerprint is ALWAYS fatal — the
/// operator pinned that exact identity, so the `reject_mismatch = false`
/// dev opt-in must not relax it. The opt-in only relaxes mismatches
/// against known_hosts-stored pins. Centralized here so every caller of
/// [`verify_server_identity`] inherits the rule; call this instead of
/// reading `reject_mismatch` directly at the mismatch site.
pub fn mismatch_is_fatal(result: &VerificationResult, reject_mismatch: bool) -> bool {
    matches!(
        result,
        VerificationResult::Mismatch {
            against_config_pin: true,
            ..
        }
    ) || reject_mismatch
}

/// Format a pin for display.
///
/// - Canonical `ik:1:<52>` → `ik:1:abcdefgh…qrstuvwx` (first 8 + last 8 of
///   the base32 body). Fits comfortably in a log line and keeps enough
///   information for out-of-band eyeball comparison.
/// - Legacy hex → colon-grouped bytes (`aa:bb:cc:...`), the historical
///   desktop presentation, so audit logs from older versions still read
///   the same.
pub fn format_fingerprint(fingerprint: &str) -> String {
    if let Some(body) = fingerprint.strip_prefix("ik:1:") {
        if body.len() >= 20 {
            return format!("ik:1:{}…{}", &body[..8], &body[body.len() - 8..]);
        }
        return fingerprint.to_string();
    }
    fingerprint
        .as_bytes()
        .chunks(2)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or("??"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Best-effort convert an on-disk / config pin to canonical form for
/// display in error messages, so the "expected" and "got" strings both
/// use the same encoding. Legacy inputs that can't be losslessly
/// rewritten (16-byte truncated hex) come back unchanged.
fn canonicalise_for_display(pin: &str) -> String {
    match rvpn_core::identity_pin::parse_pin(pin) {
        Ok(parsed) if parsed.version != 0 => parsed.to_canonical(),
        _ => pin.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_bundle(seed: u8) -> X3DHPublicBundle {
        X3DHPublicBundle {
            identity_key: [seed; 32],
            identity_x25519_key: [0xcd; 32],
            signed_prekey: [0xef; 32],
            prekey_signature: [0x12; 64],
            one_time_prekey: None,
            identity_key_version: 1,
            rotation_signature: None,
            identity_x25519_signature: None,
           capabilities: 0,
}
    }

    fn signed_disk_bundle() -> X3DHPublicBundle {
        // A real responder bundle: the identity X25519 key carries a
        // valid signature from the bundle's own Ed25519 identity key.
        rvpn_core::crypto::X3DHResponder::new().get_public_bundle()
    }

    #[test]
    fn resolve_prefers_a_verified_wire_key() {
        // Same identity on both sides, but the on-disk copy carries a
        // stale X25519 value: a valid wire proof from that identity
        // replaces it.
        let wire = signed_disk_bundle();
        let mut disk = wire.clone();
        disk.identity_x25519_key = [0xab; 32];
        disk.identity_x25519_signature = None;
        let sig = wire.identity_x25519_signature.unwrap();
        let (key, carried) = resolve_identity_x25519(
            &wire.identity_key,
            Some(&wire.identity_x25519_key),
            Some(&sig),
            &disk,
        )
        .expect("a valid wire proof from the held identity resolves");
        assert_eq!(key, wire.identity_x25519_key);
        assert_eq!(carried, Some(sig));
        assert_ne!(key, disk.identity_x25519_key);
    }

    #[test]
    fn resolve_rejects_a_tampered_wire_signature() {
        let disk = signed_disk_bundle();
        let wire = signed_disk_bundle();
        let mut sig = wire.identity_x25519_signature.unwrap();
        sig[0] ^= 0x01;
        let err = resolve_identity_x25519(
            &wire.identity_key,
            Some(&wire.identity_x25519_key),
            Some(&sig),
            &disk,
        );
        assert!(err.is_err(), "a tampered signature must not resolve");
    }

    #[test]
    fn resolve_rejects_a_signature_over_another_key() {
        let disk = signed_disk_bundle();
        let wire = signed_disk_bundle();
        let other = signed_disk_bundle();
        let sig = other.identity_x25519_signature.unwrap();
        let err = resolve_identity_x25519(
            &wire.identity_key,
            Some(&wire.identity_x25519_key),
            Some(&sig),
            &disk,
        );
        assert!(err.is_err(), "a signature over a different key must fail");
    }

    #[test]
    fn resolve_refuses_a_partial_proof() {
        let disk = signed_disk_bundle();
        let sig = disk.identity_x25519_signature.unwrap();
        assert!(
            resolve_identity_x25519(
                &disk.identity_key,
                Some(&disk.identity_x25519_key),
                None,
                &disk
            )
            .is_err(),
            "a key with no signature is a partial proof"
        );
        assert!(
            resolve_identity_x25519(&disk.identity_key, None, Some(&sig), &disk).is_err(),
            "a signature with no key is a partial proof"
        );
    }

    #[test]
    fn resolve_falls_back_to_the_disk_bundle_when_unsigned() {
        let disk = signed_disk_bundle();
        let (key, carried) = resolve_identity_x25519(&disk.identity_key, None, None, &disk)
            .expect("the unsigned path resolves from the disk bundle");
        assert_eq!(key, disk.identity_x25519_key);
        assert_eq!(carried, disk.identity_x25519_signature);
    }

    #[test]
    fn resolve_refuses_a_proof_from_a_different_identity() {
        // The attack the equality guard exists for: a MITM presents their
        // own Ed25519 identity plus an X25519 key they validly signed
        // with it. The signature is good — and must still be refused,
        // because the proof does not speak for the identity the client
        // holds. The disk bundle's X25519 key is the binding.
        let disk = signed_disk_bundle();
        let attacker = signed_disk_bundle();
        let sig = attacker.identity_x25519_signature.unwrap();
        let signed = resolve_identity_x25519(
            &attacker.identity_key,
            Some(&attacker.identity_x25519_key),
            Some(&sig),
            &disk,
        );
        assert!(signed.is_err(), "a foreign identity's proof must fail");
        let unsigned = resolve_identity_x25519(&attacker.identity_key, None, None, &disk);
        assert!(
            unsigned.is_err(),
            "a foreign identity is refused even without a proof"
        );
    }

    #[test]
    fn compute_fingerprint_is_canonical() {
        let bundle = make_bundle(0xab);
        let fp = compute_fingerprint(&bundle);
        assert!(fp.starts_with("ik:1:"));
        assert_eq!(fp.trim_start_matches("ik:1:").len(), 52);
    }

    #[test]
    fn format_canonical_pin_truncates_middle() {
        let bundle = make_bundle(0x33);
        let fp = compute_fingerprint(&bundle);
        let formatted = format_fingerprint(&fp);
        assert!(formatted.starts_with("ik:1:"));
        assert!(formatted.contains('…'));
        assert!(formatted.len() < fp.len());
    }

    #[test]
    fn format_legacy_hex_uses_colons() {
        let formatted = format_fingerprint("aabbccdd1122");
        assert_eq!(formatted, "aa:bb:cc:dd:11:22");
    }

    #[test]
    fn verify_config_fingerprint_canonical() {
        let bundle = make_bundle(0x77);
        let expected = compute_fingerprint(&bundle);
        let mut hosts = KnownHosts::default();

        let (result, ok) = verify_server_identity(
            "example.com",
            &bundle,
            &mut hosts,
            Some(&expected),
            false,
            false,
        );
        assert_eq!(result, VerificationResult::Verified);
        assert!(ok);
    }

    #[test]
    fn verify_config_fingerprint_legacy_hex_still_accepted() {
        // A user with an old config: their pin is the 32-char legacy
        // hex (first 16 bytes of the raw identity key). It must still
        // verify against the same server.
        let bundle = make_bundle(0x99);
        let legacy = hex::encode(bundle.identity_key)[..32].to_string();
        let mut hosts = KnownHosts::default();

        let (result, ok) = verify_server_identity(
            "example.com",
            &bundle,
            &mut hosts,
            Some(&legacy),
            false,
            false,
        );
        assert_eq!(result, VerificationResult::Verified);
        assert!(ok);
    }

    #[test]
    fn verify_config_fingerprint_mismatch_returns_canonical_in_error() {
        let bundle = make_bundle(0x11);
        let other = make_bundle(0x22);
        let expected = compute_fingerprint(&other);
        let mut hosts = KnownHosts::default();

        let (result, ok) = verify_server_identity(
            "example.com",
            &bundle,
            &mut hosts,
            Some(&expected),
            false,
            false,
        );
        assert!(!ok);
        match result {
            VerificationResult::Mismatch {
                expected: e,
                got: g,
                against_config_pin,
            } => {
                assert!(e.starts_with("ik:1:"));
                assert!(g.starts_with("ik:1:"));
                assert!(against_config_pin, "mismatch is against the config pin");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn known_hosts_tofu_captures_canonical_pin() {
        let bundle = make_bundle(0x55);
        let mut hosts = KnownHosts::default();

        let (result, ok) =
            verify_server_identity("host.example", &bundle, &mut hosts, None, true, false);
        assert_eq!(result, VerificationResult::New);
        assert!(ok);
        let stored = hosts.get_fingerprint("host.example").unwrap();
        assert!(stored.starts_with("ik:1:"));
        assert_eq!(stored, compute_fingerprint(&bundle));
    }

    #[test]
    fn known_hosts_legacy_entry_migrates_on_read() {
        // Simulate a desktop upgraded from v1.2.6: known_hosts.json
        // holds a legacy hex fingerprint. The next successful verify
        // rewrites it to canonical form and preserves first_seen.
        let bundle = make_bundle(0x66);
        let legacy = hex::encode(bundle.identity_key)[..32].to_string();
        let mut hosts = KnownHosts::default();
        hosts.servers.insert(
            "host.example".into(),
            ServerIdentity {
                fingerprint: legacy.clone(),
                first_seen: "old".into(),
                last_verified: "old".into(),
            },
        );

        let (result, ok) =
            verify_server_identity("host.example", &bundle, &mut hosts, None, true, false);
        assert_eq!(result, VerificationResult::Verified);
        assert!(ok);

        let entry = hosts.servers.get("host.example").unwrap();
        assert_eq!(entry.fingerprint, compute_fingerprint(&bundle));
        assert_eq!(entry.first_seen, "old", "first_seen must be preserved");
        assert_ne!(entry.last_verified, "old", "last_verified must be updated");
    }

    #[test]
    fn known_hosts_mismatch_flags_dialog_data() {
        let bundle = make_bundle(0x77);
        let stored_pin = compute_fingerprint(&make_bundle(0x88));
        let mut hosts = KnownHosts::default();
        hosts.servers.insert(
            "host.example".into(),
            ServerIdentity {
                fingerprint: stored_pin.clone(),
                first_seen: "old".into(),
                last_verified: "old".into(),
            },
        );

        let (result, ok) =
            verify_server_identity("host.example", &bundle, &mut hosts, None, true, false);
        assert!(!ok);
        match result {
            VerificationResult::Mismatch {
                expected,
                got,
                against_config_pin,
            } => {
                assert_eq!(expected, stored_pin);
                assert_eq!(got, compute_fingerprint(&bundle));
                assert!(!against_config_pin, "mismatch is against a known_hosts pin");
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[test]
    fn tofu_disabled_rejects_unknown() {
        let bundle = make_bundle(0xEE);
        let mut hosts = KnownHosts::default();

        let (result, ok) =
            verify_server_identity("new.example", &bundle, &mut hosts, None, false, false);
        assert_eq!(result, VerificationResult::New);
        assert!(!ok);
        assert!(hosts.get_fingerprint("new.example").is_none());
    }

    #[test]
    fn reject_new_identity_rejects_new_server_without_saving() {
        let bundle = make_bundle(0xEF);
        let mut hosts = KnownHosts::default();

        let (result, ok) =
            verify_server_identity("strict.example", &bundle, &mut hosts, None, true, true);
        assert_eq!(result, VerificationResult::New);
        assert!(!ok);
        assert!(hosts.get_fingerprint("strict.example").is_none());
    }

    #[test]
    fn tofu_capture_with_failed_save_is_fatal() {
        // A TOFU capture whose pin can't be persisted reopens the
        // identity-swap window on the next session — the connection must
        // fail, not warn-and-continue.
        let bundle = make_bundle(0xF0);
        let mut hosts = KnownHosts::default();

        let (result, ok) =
            verify_server_identity("new.example", &bundle, &mut hosts, None, true, false);
        assert_eq!(result, VerificationResult::New);
        assert!(ok, "capture happened");
        assert!(hosts.get_fingerprint("new.example").is_some());

        // A path inside a nonexistent directory makes save() fail (ENOENT).
        let bad_path = Path::new("/nonexistent-rvpn-test-dir")
            .join(format!("{}/known_hosts.json", std::process::id()));
        let err = persist_known_hosts(&hosts, &bad_path, &result, ok)
            .expect_err("save failure after a TOFU capture must be fatal");
        assert!(
            err.to_string()
                .contains("Failed to persist new server identity pin"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn save_failure_is_warn_only_when_no_new_pin_at_stake() {
        let bundle = make_bundle(0xF1);
        let mut hosts = KnownHosts::default();
        hosts.add_server("known.example".to_string(), compute_fingerprint(&bundle));

        let (result, ok) =
            verify_server_identity("known.example", &bundle, &mut hosts, None, true, false);
        assert_eq!(result, VerificationResult::Verified);
        assert!(ok);

        let bad_path = Path::new("/nonexistent-rvpn-test-dir")
            .join(format!("{}/known_hosts.json", std::process::id()));
        persist_known_hosts(&hosts, &bad_path, &result, ok)
            .expect("Verified result: save failure stays warn-only");

        // A rejected TOFU capture (reject_new_identity) never reaches the
        // persist call in a caller that honors should_proceed, but even if
        // it did, no new pin was at stake.
        let (result, ok) =
            verify_server_identity("strict.example", &bundle, &mut hosts, None, true, true);
        assert_eq!(result, VerificationResult::New);
        assert!(!ok);
        persist_known_hosts(&hosts, &bad_path, &result, ok)
            .expect("rejected capture: save failure stays warn-only");
    }

    #[test]
    fn missing_known_hosts_file_loads_as_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let missing = dir.path().join("known_hosts.json");
        let hosts = KnownHosts::load(&missing).expect("a missing file loads as an empty store");
        assert!(hosts.servers.is_empty());
    }

    #[test]
    fn corrupt_known_hosts_file_fails_closed_and_stays_byte_identical() {
        // A19 review: a present-but-unparseable known_hosts must NOT be
        // treated as pin-less — the old `unwrap_or_default()` callers would
        // TOFU-capture whatever answered and overwrite every stored pin on
        // save. Tested at the load level: the full connect path needs a
        // live server handshake and is not unit-harnessable, but every
        // caller now propagates this Err with `?` BEFORE verify/save, so
        // the file must survive untouched.
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("known_hosts.json");
        let garbage = b"{\"servers\": {\"host.example\": {\"fingerprint\": \"ik:1:AAAA";
        std::fs::write(&path, garbage).unwrap();

        let err = KnownHosts::load(&path).expect_err("a corrupt file must not load as empty");
        assert!(
            err.to_string().contains("Failed to parse known hosts file"),
            "unexpected error: {}",
            err
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            garbage,
            "the corrupt file must be left byte-identical (no clobbering save)"
        );
    }

    #[test]
    fn config_pin_mismatch_is_fatal_even_with_reject_mismatch_relaxed() {
        // A19 review: reject_mismatch = false is a dev opt-in that relaxes
        // known_hosts mismatches ONLY. A mismatch against the fingerprint
        // the operator pasted into the config is refused regardless.
        let bundle = make_bundle(0x12);
        let other = make_bundle(0x34);
        let config_pin = compute_fingerprint(&other);
        let mut hosts = KnownHosts::default();

        let (result, should_proceed) = verify_server_identity(
            "example.com",
            &bundle,
            &mut hosts,
            Some(&config_pin),
            false,
            false,
        );
        assert!(!should_proceed);
        match &result {
            VerificationResult::Mismatch {
                against_config_pin, ..
            } => assert!(against_config_pin),
            other => panic!("unexpected result: {other:?}"),
        }
        // The caller-side decision rule every connect path inherits:
        assert!(
            mismatch_is_fatal(&result, false),
            "config pin is always enforced"
        );
        assert!(mismatch_is_fatal(&result, true));
    }

    #[test]
    fn known_hosts_mismatch_remains_relaxed_only_by_explicit_opt_in() {
        // The opt-in still works where it is meant to: a mismatch against
        // a known_hosts-stored pin with reject_mismatch = false warns and
        // continues; with the default true it rejects.
        let bundle = make_bundle(0x56);
        let stored_pin = compute_fingerprint(&make_bundle(0x78));
        let mut hosts = KnownHosts::default();
        hosts.add_server("host.example".to_string(), stored_pin);

        let (result, should_proceed) =
            verify_server_identity("host.example", &bundle, &mut hosts, None, true, false);
        assert!(!should_proceed);
        match &result {
            VerificationResult::Mismatch {
                against_config_pin, ..
            } => assert!(!against_config_pin),
            other => panic!("unexpected result: {other:?}"),
        }
        assert!(
            !mismatch_is_fatal(&result, false),
            "the dev opt-in relaxes known_hosts mismatches"
        );
        assert!(mismatch_is_fatal(&result, true));
    }
}
