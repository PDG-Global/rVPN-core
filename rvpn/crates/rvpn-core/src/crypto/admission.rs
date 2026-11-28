// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Admission key-confirmation MAC (S1, #rVPN:#32).
//!
//! The server's admission check must only ever answer a client that has
//! PROVED it holds the identity key it claims. DH maths alone proves
//! nothing about possession: anyone can send a victim's public identity key
//! in a Hello. This module binds the Hello to the X3DH shared secret:
//! the client derives a key-confirmation key `kc` from the shared secret
//! and sends `HMAC-SHA256(kc, transcript)` in the Hello; the server derives
//! the same `kc` after `agree()` and verifies the MAC in constant time
//! BEFORE any admission decision. A wrong MAC is a generic handshake
//! failure — never the `pending_approval` refusal, so the refusal can
//! never be used as an oracle for which keys exist.
//!
//! The transcript is identity-anchored: the client identity key, the
//! client ephemeral, and the server identity key. Signed/one-time prekeys
//! are deliberately NOT included: they rotate on the server (default every
//! 168h), and a client that fetched its pinned bundle before a rotation
//! would compute a transcript the server cannot reproduce. Identity keys
//! are stable (rotations carry a rotation signature), so the binding holds
//! across prekey rotations.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use super::hkdf_derive;

/// HKDF label separating the admission key-confirmation key from every
/// other use of the X3DH shared secret.
pub const ADMISSION_CONFIRM_LABEL: &[u8] = b"rvpn admission confirm v1";

/// The handshake error code the server sends for a refused client key
/// (unknown OR revoked — identical either way). Clients map this to their
/// "waiting for approval" state. A wrong or missing proof NEVER gets this
/// code — it is a generic handshake failure instead.
pub const REFUSAL_CODE: u16 = 20;

/// The refusal message body. Fixed and detail-free by design.
pub const REFUSAL_MESSAGE: &str = "pending_approval";

type HmacSha256 = Hmac<Sha256>;

/// Derive the key-confirmation key from the X3DH shared secret.
pub fn derive_confirm_key(shared_secret: &[u8; 32]) -> [u8; 32] {
    let out = hkdf_derive(&[], shared_secret, ADMISSION_CONFIRM_LABEL, 32);
    let mut kc = [0u8; 32];
    kc.copy_from_slice(&out);
    kc
}

/// The handshake transcript the MAC covers: Hello plus ServerHello, so
/// neither flight can be swapped or replayed into another session (Thomas's
/// condition 2). Includes both identity keys, both ephemerals, the signed
/// prekey and its signature, the client connection nonce, and both
/// capability sets. One-time-prekey use is internal to each side's
/// agreement and deliberately excluded; identity keys are stable across the
/// server's signed-prekey rotation, so the binding survives it.
#[allow(clippy::too_many_arguments)]
pub fn transcript(
    client_identity_x25519: &[u8; 32],
    client_ephemeral: &[u8; 32],
    connection_nonce: &Option<Vec<u8>>,
    client_caps: u32,
    server_identity_x25519: &[u8; 32],
    server_ephemeral: &[u8],
    server_signed_prekey: &[u8; 32],
    prekey_signature: &[u8],
    server_caps: u32,
) -> Vec<u8> {
    let mut t = Vec::with_capacity(32 + 32 * 6 + 64 + 8 + 32);
    t.extend_from_slice(b"rvpn-admission-transcript-v2");
    t.extend_from_slice(client_identity_x25519);
    t.extend_from_slice(client_ephemeral);
    if let Some(n) = connection_nonce {
        t.extend_from_slice(n);
    }
    t.extend_from_slice(&client_caps.to_le_bytes());
    t.extend_from_slice(server_identity_x25519);
    t.extend_from_slice(server_ephemeral);
    t.extend_from_slice(server_signed_prekey);
    t.extend_from_slice(prekey_signature);
    t.extend_from_slice(&server_caps.to_le_bytes());
    t
}

/// Compute the admission MAC (client side, and server-side reference).
pub fn compute_mac(kc: &[u8; 32], transcript: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(kc).expect("HMAC accepts any key length");
    mac.update(transcript);
    let out = mac.finalize().into_bytes();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Constant-time verify (server side). Any mismatch, length error, or
/// malformed input returns false; the caller maps that to the GENERIC
/// handshake failure, never the admission refusal.
pub fn verify_mac(kc: &[u8; 32], transcript: &[u8], presented: &[u8]) -> bool {
    if presented.len() != 32 {
        return false;
    }
    let expected = compute_mac(kc, transcript);
    bool::from(expected.ct_eq(presented))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> ([u8; 32], Vec<u8>, [u8; 32]) {
        let kc = derive_confirm_key(&[7u8; 32]);
        let t = transcript(
            &[1u8; 32],
            &[2u8; 32],
            &Some(vec![9u8; 16]),
            1,
            &[3u8; 32],
            &[],
            &[4u8; 32],
            &[5u8; 64],
            1,
        );
        let mac = compute_mac(&kc, &t);
        (kc, t, mac)
    }

    #[test]
    fn roundtrip_verifies() {
        let (kc, t, mac) = fixture();
        assert!(verify_mac(&kc, &t, &mac));
    }

    #[test]
    fn wrong_mac_fails() {
        let (kc, t, mut mac) = fixture();
        mac[0] ^= 1;
        assert!(!verify_mac(&kc, &t, &mac));
    }

    #[test]
    fn wrong_key_fails() {
        let (_kc, t, mac) = fixture();
        let other = derive_confirm_key(&[8u8; 32]);
        assert!(!verify_mac(&other, &t, &mac));
    }

    #[test]
    fn wrong_transcript_fails() {
        let (kc, _t, mac) = fixture();
        // Another session's transcript (different ephemeral) fails.
        let other_t = transcript(
            &[1u8; 32],
            &[9u8; 32],
            &Some(vec![9u8; 16]),
            1,
            &[3u8; 32],
            &[],
            &[4u8; 32],
            &[5u8; 64],
            1,
        );
        assert!(!verify_mac(&kc, &other_t, &mac));
        // And so does a tampered one (flipped capability bit).
        let tampered = transcript(
            &[1u8; 32],
            &[2u8; 32],
            &Some(vec![9u8; 16]),
            0,
            &[3u8; 32],
            &[],
            &[4u8; 32],
            &[5u8; 64],
            1,
        );
        assert!(!verify_mac(&kc, &tampered, &mac));
    }

    #[test]
    fn malformed_length_fails() {
        let (kc, t, _) = fixture();
        assert!(!verify_mac(&kc, &t, &[0u8; 31]));
        assert!(!verify_mac(&kc, &t, &[]));
    }

    #[test]
    fn label_separation_changes_key() {
        // kc must differ from any direct use of the shared secret.
        let kc = derive_confirm_key(&[7u8; 32]);
        assert_ne!(kc, [7u8; 32]);
    }
}
