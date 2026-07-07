//! Two-server TOFU flow, run entirely in-process.
//!
//! Stands in for the "two `rvpn-server` instances" acceptance test in
//! `dev_docs/specs/TOFU_FINGERPRINT.md §8`. Instead of spawning two
//! server binaries (they'd need TLS certs and free ports and a client
//! that speaks WebSocket), we mint two `X3DHResponder`s in-process to
//! stand in for servers A and B, and thread them through the shipping
//! `identity_verification::verify_server_identity` — the same function
//! called by the desktop tunnel handshake path. If a real
//! two-binary run ever diverges from this test, either the client or
//! the CLI-generated bundles have quietly changed their shape and we
//! want the regression to fire.

use rvpn_client::identity_verification::{
    compute_fingerprint, verify_server_identity, KnownHosts, VerificationResult,
};
use rvpn_core::crypto::X3DHResponder;
use rvpn_core::identity_pin::encode_identity_pin;
use tempfile::TempDir;

fn known_hosts_path(dir: &TempDir) -> std::path::PathBuf {
    dir.path().join("known_hosts.json")
}

#[test]
fn tofu_captures_pin_on_first_connect_and_rejects_redirect() {
    // Server A + Server B, each with their own identity (same shape as
    // the server prekey_bundle CLI produces on disk).
    let server_a = X3DHResponder::new();
    let server_b = X3DHResponder::new();
    let bundle_a = server_a.get_public_bundle();
    let bundle_b = server_b.get_public_bundle();
    assert_ne!(bundle_a.identity_key, bundle_b.identity_key);

    let pin_a = encode_identity_pin(&bundle_a.identity_key).unwrap();
    assert_eq!(pin_a, compute_fingerprint(&bundle_a));

    let dir = TempDir::new().unwrap();
    let hosts_path = known_hosts_path(&dir);
    let mut hosts = KnownHosts::load(&hosts_path).unwrap();

    // (1) TOFU capture: no known hosts, no config pin, trust_on_first_use.
    let (result, ok) = verify_server_identity(
        "hk3.example.com:443",
        &bundle_a,
        &mut hosts,
        None,
        true,
        false,
    );
    assert!(ok);
    assert_eq!(result, VerificationResult::New);
    assert_eq!(hosts.get_fingerprint("hk3.example.com:443"), Some(pin_a.as_str()));

    // Persist so a "next connect" simulation reloads from the same file
    // — the CLI writes on every save, so this exercises the real path.
    hosts.save(&hosts_path).unwrap();

    // (2) Redirect to server B under the same profile → mismatch.
    let mut hosts_reloaded = KnownHosts::load(&hosts_path).unwrap();
    let (result, ok) = verify_server_identity(
        "hk3.example.com:443",
        &bundle_b,
        &mut hosts_reloaded,
        None,
        true,
        false,
    );
    assert!(!ok);
    match result {
        VerificationResult::Mismatch { expected, got } => {
            assert_eq!(expected, pin_a);
            assert_eq!(got, encode_identity_pin(&bundle_b.identity_key).unwrap());
        }
        other => panic!("expected mismatch, got {other:?}"),
    }
    // The stored pin must NOT have been overwritten by the failed verify.
    assert_eq!(
        hosts_reloaded.get_fingerprint("hk3.example.com:443"),
        Some(pin_a.as_str()),
        "mismatch must not clobber the pinned entry"
    );
}

#[test]
fn config_supplied_pin_still_verifies_after_a_reboot() {
    // Simulates a user who pasted the canonical ik:1: pin from the
    // operator into their client.toml. No known_hosts entry, just the
    // config value. Verify twice — the second time from a freshly-
    // loaded KnownHosts — to catch any state that leaks between calls.
    let server_a = X3DHResponder::new();
    let bundle_a = server_a.get_public_bundle();
    let pin_a = compute_fingerprint(&bundle_a);

    let dir = TempDir::new().unwrap();
    let hosts_path = known_hosts_path(&dir);

    for _ in 0..2 {
        let mut hosts = KnownHosts::load(&hosts_path).unwrap();
        let (result, ok) = verify_server_identity(
            "hk3.example.com:443",
            &bundle_a,
            &mut hosts,
            Some(&pin_a),
            false,
            false,
        );
        assert!(ok);
        assert_eq!(result, VerificationResult::Verified);
        hosts.save(&hosts_path).unwrap();
    }
}

#[test]
fn strict_mode_refuses_new_server_without_state_change() {
    // A profile with trust_on_first_use = true AND strict_mode = true
    // means "I want to pin only what I set in config; refuse unknowns".
    // The verify call must fail and NOT stamp a new entry.
    let server_a = X3DHResponder::new();
    let bundle_a = server_a.get_public_bundle();

    let dir = TempDir::new().unwrap();
    let mut hosts = KnownHosts::load(&known_hosts_path(&dir)).unwrap();

    let (result, ok) = verify_server_identity(
        "hk3.example.com:443",
        &bundle_a,
        &mut hosts,
        None,
        true, // trust_on_first_use
        true, // strict_mode
    );
    assert!(!ok);
    assert_eq!(result, VerificationResult::New);
    assert!(hosts.get_fingerprint("hk3.example.com:443").is_none());
}
