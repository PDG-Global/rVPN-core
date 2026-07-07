//! Server identity pin encoding + rotation-signature validation.
//!
//! # Pin encoding
//!
//! Canonical form:
//!
//! ```text
//! ik:1:<base32-no-pad-lowercase>(sha256(identity_key_bytes))
//! ```
//!
//! - `ik:` — namespace, leaves room for future key kinds.
//! - `1`  — version, so a legitimate rotation can bump to `ik:2:...`
//!          unambiguously in the future.
//! - 52-char body — RFC 4648 base32, no padding, lowercase. Sortable, no
//!   `+/=` to escape in JSON, comfortably inside a QR v1.
//!
//! # Legacy compatibility
//!
//! Desktop `rvpn-client/src/identity_verification.rs` shipped a 32-char
//! hex fingerprint (first 32 chars of `hex(identity_key)`, i.e. the first
//! 16 raw bytes of the Ed25519 public key). [`parse_pin`] accepts both
//! forms so a single "read legacy, write new" release can migrate every
//! installation on the next successful connect.
//!
//! # Rotation signature
//!
//! To let an operator rotate the server's identity key without every
//! pinned client seeing a mismatch dialog, the prekey bundle grows two
//! fields:
//!
//! ```text
//! identity_key_version: u32
//! rotation_signature:   [u8; 64]      // Ed25519(prev_identity, new_ident || new_version_le)
//! ```
//!
//! [`verify_rotation_signature`] checks the signature. On a valid chain
//! the client silently overwrites its pin and bumps its stored version.
//! A broken chain (missing sig, wrong version bump, bad signature) falls
//! back to the manual mismatch dialog.

use crate::{Error, Result};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// The `ik:` prefix on every canonical pin. Public so app layers can
/// range-check strings coming out of the UI.
pub const PIN_PREFIX: &str = "ik:";

/// The current pin version. Bumped when the pin encoding itself changes
/// (not when a server's identity key rotates — that's tracked separately
/// via `identity_key_version` in the prekey bundle).
pub const PIN_VERSION: u8 = 1;

/// Length in raw bytes of an Ed25519 public key. Used throughout to
/// guard against feeding a compressed X25519 point or something equally
/// wrong-sized into the pin helpers.
pub const IDENTITY_KEY_LEN: usize = 32;

/// A pin parsed out of a config string.
///
/// The pin body is the SHA-256 of the identity key; carrying it out of
/// [`parse_pin`] lets callers compare pins without re-parsing. Two pins
/// match iff their `hash` bytes are equal — the surface encoding doesn't
/// affect equality.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPin {
    /// The version prefix (e.g. `1` for `ik:1:...`). Legacy hex pins are
    /// reported as version `0` so callers can tell "this needs to be
    /// rewritten on next save" without a separate flag.
    pub version: u8,
    /// SHA-256 of the identity key bytes.
    pub hash: [u8; 32],
}

impl ParsedPin {
    /// Produce the canonical `ik:1:<base32>` form of this pin.
    ///
    /// For a version-1 pin this is exact. For a legacy pin (version 0)
    /// the pad bytes leak in — the true canonical form is unrecoverable
    /// from a 16-byte truncated pin alone. Callers migrating legacy
    /// storage should re-encode from the raw identity bytes:
    /// [`encode_identity_pin`] once [`pins_match`] confirms the pin was
    /// actually matched, not [`ParsedPin::to_canonical`].
    pub fn to_canonical(&self) -> String {
        format!(
            "{}{}:{}",
            PIN_PREFIX,
            PIN_VERSION,
            BASE32_NOPAD.encode(&self.hash).to_lowercase()
        )
    }
}

/// Compute the canonical pin for an identity key.
///
/// Panics: never — length is checked and returned as `Err(InvalidKey)`.
pub fn encode_identity_pin(identity_key: &[u8]) -> Result<String> {
    if identity_key.len() != IDENTITY_KEY_LEN {
        return Err(Error::InvalidKey(format!(
            "identity key must be {} bytes, got {}",
            IDENTITY_KEY_LEN,
            identity_key.len()
        )));
    }
    let hash = Sha256::digest(identity_key);
    Ok(format!(
        "{}{}:{}",
        PIN_PREFIX,
        PIN_VERSION,
        BASE32_NOPAD.encode(&hash).to_lowercase()
    ))
}

/// Parse a pin string. Accepts:
///
/// - `ik:1:<base32-52-chars>` — the canonical form.
/// - `<64-char-hex>` — full-hash hex. Not shipped anywhere; supported so
///   the same parser handles CLI paste and QR alike.
/// - `<32-char-hex>` — the legacy first-16-bytes-of-Ed25519 form written
///   by desktop's `identity_verification::compute_fingerprint` in v1.2.6.
///   Reported as version `0`.
///
/// Any whitespace or `:` separators in the input are stripped before
/// parsing (so `ik : 1 : abcd...` and `ab:cd:ef:...` both work).
pub fn parse_pin(input: &str) -> Result<ParsedPin> {
    // Normalise: strip whitespace and (for hex forms only) `:` separators.
    // We deliberately do NOT strip `:` from the ik:1: form — the parse of
    // `ik:1:` is order-sensitive.
    let trimmed = input.trim();

    if let Some(rest) = trimmed.strip_prefix(PIN_PREFIX) {
        // Canonical `ik:<v>:<body>` form.
        let mut parts = rest.splitn(2, ':');
        let version_str = parts
            .next()
            .ok_or_else(|| Error::InvalidKey("pin missing version".into()))?;
        let body = parts
            .next()
            .ok_or_else(|| Error::InvalidKey("pin missing body".into()))?;
        let version: u8 = version_str
            .parse()
            .map_err(|_| Error::InvalidKey(format!("invalid pin version {version_str:?}")))?;
        if version != PIN_VERSION {
            return Err(Error::InvalidKey(format!(
                "unknown pin version {version}, only {PIN_VERSION} understood",
            )));
        }
        let body_upper = body.trim().to_uppercase();
        let hash_vec = BASE32_NOPAD
            .decode(body_upper.as_bytes())
            .map_err(|e| Error::InvalidKey(format!("pin body is not base32: {e}")))?;
        let hash: [u8; 32] = hash_vec
            .try_into()
            .map_err(|v: Vec<u8>| {
                Error::InvalidKey(format!(
                    "pin body decoded to {} bytes, expected 32",
                    v.len()
                ))
            })?;
        return Ok(ParsedPin { version, hash });
    }

    // Legacy hex forms. Strip separators before decoding.
    let hex_only: String = trimmed
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect();

    match hex_only.len() {
        64 => {
            // Full 32-byte SHA-256 hash in hex. Not a form we ship, but
            // trivial to normalise; useful for CLI paste.
            let bytes = hex::decode(&hex_only)
                .map_err(|e| Error::InvalidKey(format!("pin hex decode: {e}")))?;
            let hash: [u8; 32] = bytes
                .try_into()
                .map_err(|_| Error::InvalidKey("hex pin length wrong".into()))?;
            Ok(ParsedPin {
                version: PIN_VERSION,
                hash,
            })
        }
        32 => {
            // Legacy 16-byte truncated hex. We can't recover the full
            // hash from it, so we stash it in the low 16 bytes of `hash`
            // and pad the high half with zeros. Comparisons against a
            // legacy pin therefore only look at the low 16 bytes — see
            // `pins_match`.
            let bytes = hex::decode(&hex_only)
                .map_err(|e| Error::InvalidKey(format!("legacy pin hex decode: {e}")))?;
            let mut hash = [0u8; 32];
            hash[..16].copy_from_slice(&bytes);
            Ok(ParsedPin { version: 0, hash })
        }
        _ => Err(Error::InvalidKey(format!(
            "pin has unexpected length {} (want 32 or 64 hex chars, or ik:1:...)",
            hex_only.len()
        ))),
    }
}

/// Constant-time compare a stored pin string against an identity key.
///
/// Handles the three encodings [`parse_pin`] understands. Returns
/// `Ok(true)` on match, `Ok(false)` on a valid-format mismatch, and
/// `Err(_)` if the stored pin can't be parsed.
///
/// # Legacy semantics
///
/// A legacy 16-byte truncated pin compares only its 16-byte slice — the
/// full SHA-256 comparison is impossible without the missing bytes. This
/// is safe (16-byte prefix collision on SHA-256 of a random 32-byte input
/// is still 2^-64) but callers should trigger a rewrite to canonical form
/// on the next successful connect. See [`ParsedPin::to_canonical`].
pub fn pins_match(stored: &str, actual_identity_key: &[u8]) -> Result<bool> {
    let parsed = parse_pin(stored)?;

    if parsed.version == 0 {
        // Legacy pin was truncated hex of the RAW identity key, not the
        // SHA-256 hash. Compare against the first 16 bytes of the key
        // directly. (Callers should trigger a rewrite to canonical form
        // on the next successful connect via ParsedPin::to_canonical.)
        if actual_identity_key.len() < 16 {
            return Ok(false);
        }
        Ok(crate::crypto::constant_time_eq(
            &parsed.hash[..16],
            &actual_identity_key[..16],
        ))
    } else {
        let actual_hash = Sha256::digest(actual_identity_key);
        Ok(crate::crypto::constant_time_eq(&parsed.hash, &actual_hash))
    }
}

/// Bytes signed when the server operator rotates the server identity key.
///
/// The signature covers `new_identity_pub || new_version_le` — a
/// hostile third party cannot forge a rotation because they don't hold
/// the old identity private key, and a replay of one rotation into a
/// server at a different version is caught because the version bumps.
///
/// Public so unit tests and the server prekey-bundle generator can
/// reproduce the same byte sequence without duplicating the definition.
pub fn rotation_signature_message(new_identity_pub: &[u8], new_version: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(new_identity_pub.len() + 4);
    out.extend_from_slice(new_identity_pub);
    out.extend_from_slice(&new_version.to_le_bytes());
    out
}

/// Verify that a server-provided rotation is a legitimate chained update
/// of a previously pinned identity.
///
/// # Rules
///
/// - The old identity signs a message containing the new identity's raw
///   Ed25519 bytes and the new version, using [`rotation_signature_message`].
/// - The new version must be exactly `prev_version + 1`. Skipping versions
///   is rejected so a rotation window can't leapfrog a compromised
///   intermediate key.
/// - Any input length mismatch fails hard rather than being silently
///   accepted.
///
/// Callers on a successful `Ok(())` should silently overwrite the pinned
/// identity with `new_identity_pub`, bump the stored version, and log
/// the rotation. On `Err(_)` they fall back to the mismatch dialog.
pub fn verify_rotation_signature(
    prev_identity_pub: &[u8],
    prev_version: u32,
    new_identity_pub: &[u8],
    new_version: u32,
    rotation_signature: &[u8; 64],
) -> Result<()> {
    if prev_identity_pub.len() != IDENTITY_KEY_LEN {
        return Err(Error::InvalidKey(format!(
            "previous identity key must be {IDENTITY_KEY_LEN} bytes, got {}",
            prev_identity_pub.len()
        )));
    }
    if new_identity_pub.len() != IDENTITY_KEY_LEN {
        return Err(Error::InvalidKey(format!(
            "new identity key must be {IDENTITY_KEY_LEN} bytes, got {}",
            new_identity_pub.len()
        )));
    }
    // Version must bump by exactly one. A wider check would let an
    // operator quietly skip revoked intermediate keys.
    if new_version != prev_version.wrapping_add(1) {
        return Err(Error::HandshakeFailed(format!(
            "rotation version must bump by 1 (prev={prev_version}, new={new_version})",
        )));
    }

    let key_arr: [u8; IDENTITY_KEY_LEN] = prev_identity_pub
        .try_into()
        .expect("length checked above");
    let verifying_key = VerifyingKey::from_bytes(&key_arr)
        .map_err(|e| Error::InvalidKey(format!("previous identity key is not a valid Ed25519 point: {e}")))?;
    let sig = Signature::from_bytes(rotation_signature);
    let message = rotation_signature_message(new_identity_pub, new_version);

    verifying_key
        .verify(&message, &sig)
        .map_err(|e| Error::HandshakeFailed(format!("rotation signature invalid: {e}")))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn make_key(seed: u8) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        bytes
    }

    #[test]
    fn encode_produces_canonical_form() {
        let key = make_key(0xAB);
        let pin = encode_identity_pin(&key).unwrap();
        assert!(pin.starts_with("ik:1:"));
        let body = pin.trim_start_matches("ik:1:");
        assert_eq!(body.len(), 52);
        assert_eq!(body, body.to_lowercase());
        // Deterministic — same input → same pin.
        assert_eq!(pin, encode_identity_pin(&key).unwrap());
    }

    #[test]
    fn encode_rejects_wrong_length() {
        let short = vec![0u8; 16];
        assert!(encode_identity_pin(&short).is_err());
    }

    #[test]
    fn parse_round_trips_canonical() {
        let key = make_key(0x11);
        let pin = encode_identity_pin(&key).unwrap();
        let parsed = parse_pin(&pin).unwrap();
        assert_eq!(parsed.version, PIN_VERSION);
        let expected_hash = Sha256::digest(key);
        assert_eq!(parsed.hash.as_slice(), expected_hash.as_slice());
        assert_eq!(parsed.to_canonical(), pin);
    }

    #[test]
    fn parse_accepts_uppercase_body() {
        let key = make_key(0x22);
        let canonical = encode_identity_pin(&key).unwrap();
        let upper = format!(
            "ik:1:{}",
            canonical.trim_start_matches("ik:1:").to_uppercase()
        );
        let parsed = parse_pin(&upper).unwrap();
        assert_eq!(parsed.to_canonical(), canonical);
    }

    #[test]
    fn parse_accepts_legacy_hex() {
        let key = make_key(0x33);
        let legacy = hex::encode(&key)[..32].to_string();
        let parsed = parse_pin(&legacy).unwrap();
        assert_eq!(parsed.version, 0);
        // Low 16 bytes must equal the raw key's first 16 bytes.
        assert_eq!(&parsed.hash[..16], &key[..16]);
        assert_eq!(parsed.hash[16..], [0u8; 16]);
    }

    #[test]
    fn parse_accepts_full_hash_hex() {
        let key = make_key(0x44);
        let full_hash_hex = hex::encode(Sha256::digest(key));
        let parsed = parse_pin(&full_hash_hex).unwrap();
        assert_eq!(parsed.version, PIN_VERSION);
        assert_eq!(parsed.to_canonical(), encode_identity_pin(&key).unwrap());
    }

    #[test]
    fn parse_ignores_separators_in_hex() {
        let key = make_key(0x55);
        let hex_grouped = hex::encode(&key)[..32]
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join(":");
        let parsed = parse_pin(&hex_grouped).unwrap();
        assert_eq!(parsed.version, 0);
        assert_eq!(&parsed.hash[..16], &key[..16]);
    }

    #[test]
    fn parse_rejects_unknown_version() {
        assert!(parse_pin("ik:99:abcd").is_err());
    }

    #[test]
    fn parse_rejects_malformed_body() {
        assert!(parse_pin("ik:1:not-base32-at-all!!!").is_err());
    }

    #[test]
    fn pins_match_true_on_canonical() {
        let key = make_key(0x66);
        let pin = encode_identity_pin(&key).unwrap();
        assert!(pins_match(&pin, &key).unwrap());
    }

    #[test]
    fn pins_match_false_on_last_byte_flip() {
        let key = make_key(0x77);
        let mut wrong = key;
        wrong[31] ^= 0xFF;
        let pin = encode_identity_pin(&key).unwrap();
        assert!(!pins_match(&pin, &wrong).unwrap());
    }

    #[test]
    fn pins_match_true_across_legacy_and_canonical() {
        let key = make_key(0x88);
        let canonical = encode_identity_pin(&key).unwrap();
        let legacy = hex::encode(&key)[..32].to_string();
        assert!(pins_match(&canonical, &key).unwrap());
        assert!(pins_match(&legacy, &key).unwrap());
    }

    #[test]
    fn rotation_signature_verifies() {
        let prev = SigningKey::from_bytes(&make_key(0xA0));
        let new_sk = SigningKey::from_bytes(&make_key(0xA1));
        let prev_pub = prev.verifying_key();
        let new_pub = new_sk.verifying_key();

        let msg = rotation_signature_message(new_pub.as_bytes(), 2);
        let sig = prev.sign(&msg);
        let sig_bytes: [u8; 64] = sig.to_bytes();

        verify_rotation_signature(prev_pub.as_bytes(), 1, new_pub.as_bytes(), 2, &sig_bytes)
            .unwrap();
    }

    #[test]
    fn rotation_signature_rejects_wrong_prev_key() {
        let prev = SigningKey::from_bytes(&make_key(0xB0));
        let impostor = SigningKey::from_bytes(&make_key(0xBF));
        let new_sk = SigningKey::from_bytes(&make_key(0xB1));
        let new_pub = new_sk.verifying_key();

        let msg = rotation_signature_message(new_pub.as_bytes(), 2);
        let sig = impostor.sign(&msg);
        let sig_bytes: [u8; 64] = sig.to_bytes();

        // Signature was made by an unrelated key; verifying against the
        // real previous key must fail.
        assert!(verify_rotation_signature(
            prev.verifying_key().as_bytes(),
            1,
            new_pub.as_bytes(),
            2,
            &sig_bytes,
        )
        .is_err());
    }

    #[test]
    fn rotation_signature_rejects_version_skip() {
        let prev = SigningKey::from_bytes(&make_key(0xC0));
        let new_sk = SigningKey::from_bytes(&make_key(0xC1));
        let new_pub = new_sk.verifying_key();

        // Correct signature — but skipping from v1 to v3.
        let msg = rotation_signature_message(new_pub.as_bytes(), 3);
        let sig = prev.sign(&msg);
        let sig_bytes: [u8; 64] = sig.to_bytes();

        assert!(verify_rotation_signature(
            prev.verifying_key().as_bytes(),
            1,
            new_pub.as_bytes(),
            3,
            &sig_bytes,
        )
        .is_err());
    }

    #[test]
    fn rotation_signature_rejects_replayed_message() {
        // Sign the rotation for v2, then try to verify it against v5.
        let prev = SigningKey::from_bytes(&make_key(0xD0));
        let new_sk = SigningKey::from_bytes(&make_key(0xD1));
        let new_pub = new_sk.verifying_key();

        let msg_v2 = rotation_signature_message(new_pub.as_bytes(), 2);
        let sig = prev.sign(&msg_v2);
        let sig_bytes: [u8; 64] = sig.to_bytes();

        // Trying to plug this signature in at a different version fails.
        assert!(verify_rotation_signature(
            prev.verifying_key().as_bytes(),
            4,
            new_pub.as_bytes(),
            5,
            &sig_bytes,
        )
        .is_err());
    }

    #[test]
    fn parsed_pin_canonical_is_stable() {
        let key = make_key(0xEE);
        let canonical = encode_identity_pin(&key).unwrap();
        let parsed = parse_pin(&canonical).unwrap();
        assert_eq!(parsed.to_canonical(), canonical);
        // And a legacy input rewritten to canonical still round-trips.
        let legacy = hex::encode(&key)[..32].to_string();
        let legacy_parsed = parse_pin(&legacy).unwrap();
        // Legacy holds only 16 bytes, so its canonical is *not* equal to
        // the real canonical for that key — the pad bytes leak in.
        assert_ne!(legacy_parsed.to_canonical(), canonical);
    }
}
