// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of R-VPN.
//
// R-VPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Shared validation and migration state for a server's handshake identity.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use anyhow::{bail, Context, Result};
use rvpn_core::{
    crypto::{verify_identity_x25519_signature, X3DHPublicBundle},
    identity_pin::{encode_identity_pin, pins_match},
    protocol::HandshakeMessage,
};

/// Identity and migration state that must survive session reconnects.
#[derive(Clone, Debug)]
pub(crate) struct ServerSecurity {
    expected_pin: Option<String>,
    actual_pin: Arc<Mutex<Option<String>>>,
    signed_x25519_seen: Arc<AtomicBool>,
}

/// A validated ServerHello and the identity information to persist.
pub(crate) struct ValidatedServerHello {
    pub bundle: X3DHPublicBundle,
    used_signed_x25519: bool,
    actual_pin: String,
}

impl ValidatedServerHello {
    pub fn commit(self, security: &ServerSecurity) {
        if self.used_signed_x25519 {
            security.signed_x25519_seen.store(true, Ordering::Release);
        }
        *security
            .actual_pin
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(self.actual_pin);
    }
}

#[derive(Debug)]
struct SignedX25519Downgrade;

impl std::fmt::Display for SignedX25519Downgrade {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("server downgraded from signed to unsigned identity X25519")
    }
}

impl std::error::Error for SignedX25519Downgrade {}

impl ServerSecurity {
    #[cfg(any(
        feature = "ios-direct-tun",
        feature = "macos-direct-tun",
        feature = "android-direct-tun",
        test
    ))]
    pub fn new(
        expected_pin: Option<String>,
        signed_x25519_seen: bool,
        disk_bundle: &X3DHPublicBundle,
    ) -> Result<Self> {
        let bundle_is_signed = if let Some(signature) = disk_bundle.identity_x25519_signature {
            verify_identity_x25519_signature(
                &disk_bundle.identity_key,
                &disk_bundle.identity_x25519_key,
                &signature,
            )?;
            true
        } else {
            false
        };
        Ok(Self {
            expected_pin,
            actual_pin: Arc::new(Mutex::new(None)),
            signed_x25519_seen: Arc::new(AtomicBool::new(signed_x25519_seen || bundle_is_signed)),
        })
    }

    #[cfg(any(
        feature = "ios-direct-tun",
        feature = "macos-direct-tun",
        feature = "android-direct-tun",
        test
    ))]
    pub fn actual_pin(&self) -> Option<String> {
        self.actual_pin
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn signed_x25519_seen(&self) -> bool {
        self.signed_x25519_seen.load(Ordering::Acquire)
    }

    pub fn security_failure_message(error: &anyhow::Error) -> Option<String> {
        error.chain().find_map(|cause| {
            if cause.downcast_ref::<SignedX25519Downgrade>().is_some() {
                return Some(
                    "SIGNED_X25519_DOWNGRADE: server removed its signed identity proof".to_string(),
                );
            }
            match cause.downcast_ref::<rvpn_core::Error>() {
                Some(rvpn_core::Error::ServerIdentityMismatch { expected, actual }) => Some(
                    format!("IDENTITY_MISMATCH expected={expected} actual={actual}"),
                ),
                _ => None,
            }
        })
    }

    /// Validate identity and key material before attempting X3DH.
    pub fn validate(
        &self,
        message: HandshakeMessage,
        disk_bundle: &X3DHPublicBundle,
    ) -> Result<ValidatedServerHello> {
        let (
            identity_key,
            signed_prekey,
            prekey_signature,
            identity_x25519_key,
            identity_x25519_signature,
            capabilities,
        ) = match message {
            HandshakeMessage::ServerHello {
                identity_key,
                signed_prekey,
                prekey_signature,
                identity_x25519_key,
                identity_x25519_signature,
                capabilities,
                ..
            } => (
                identity_key,
                signed_prekey,
                prekey_signature,
                identity_x25519_key,
                identity_x25519_signature,
                capabilities,
            ),
            _ => bail!("Unexpected handshake message type from server"),
        };

        let identity_key: [u8; 32] = identity_key
            .as_slice()
            .try_into()
            .context("Server identity key has invalid length")?;
        let signed_prekey: [u8; 32] = signed_prekey
            .as_slice()
            .try_into()
            .context("Server signed prekey has invalid length")?;
        let prekey_signature: [u8; 64] = prekey_signature
            .as_slice()
            .try_into()
            .context("Prekey signature has invalid length")?;

        ed25519_dalek::Verifier::verify(
            &ed25519_dalek::VerifyingKey::from_bytes(&identity_key)
                .context("Invalid server identity key")?,
            &signed_prekey,
            &ed25519_dalek::Signature::from_bytes(&prekey_signature),
        )
        .context("Invalid prekey signature")?;

        let actual_pin = encode_identity_pin(&identity_key).context("Cannot encode server pin")?;
        let expected = match self.expected_pin.as_deref() {
            Some(expected) => expected.to_string(),
            None => encode_identity_pin(&disk_bundle.identity_key)
                .context("Cannot encode the profile's server pin")?,
        };
        if !pins_match(&expected, &identity_key).context("Invalid configured server pin")? {
            return Err(rvpn_core::Error::ServerIdentityMismatch {
                expected,
                actual: actual_pin.clone(),
            }
            .into());
        }

        let (identity_x25519_key, used_signed_x25519) =
            match (identity_x25519_key, identity_x25519_signature) {
                (Some(key), Some(signature)) => {
                    let key: [u8; 32] = key
                        .as_slice()
                        .try_into()
                        .context("Server identity X25519 key has invalid length")?;
                    let signature: [u8; 64] = signature
                        .as_slice()
                        .try_into()
                        .context("Identity X25519 signature has invalid length")?;
                    verify_identity_x25519_signature(&identity_key, &key, &signature)?;
                    (key, true)
                }
                (None, None) if disk_bundle.identity_x25519_signature.is_some() => {
                    (disk_bundle.identity_x25519_key, true)
                }
                (None, None) => {
                    if self.signed_x25519_seen() {
                        return Err(SignedX25519Downgrade.into());
                    }
                    (disk_bundle.identity_x25519_key, false)
                }
                _ => bail!("Server supplied only part of the signed identity X25519 proof"),
            };

        Ok(ValidatedServerHello {
            bundle: X3DHPublicBundle {
                identity_key,
                identity_x25519_key,
                identity_x25519_signature: disk_bundle.identity_x25519_signature,
                signed_prekey,
                prekey_signature,
                one_time_prekey: None,
                identity_key_version: disk_bundle.identity_key_version,
                rotation_signature: disk_bundle.rotation_signature,
                capabilities: capabilities.unwrap_or(0),
            },
            used_signed_x25519,
            actual_pin,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvpn_core::crypto::X3DHResponder;

    fn hello(bundle: &X3DHPublicBundle, signed: bool) -> HandshakeMessage {
        HandshakeMessage::ServerHello {
            ephemeral_key: Vec::new(),
            signed_prekey: bundle.signed_prekey.to_vec(),
            prekey_signature: bundle.prekey_signature.to_vec(),
            identity_key: bundle.identity_key.to_vec(),
            identity_x25519_key: signed.then(|| bundle.identity_x25519_key.to_vec()),
            identity_x25519_signature: signed
                .then(|| bundle.identity_x25519_signature.unwrap().to_vec()),
            capabilities: None,
        }
    }

    #[test]
    fn wire_pin_mismatch_is_rejected_even_when_disk_bundle_matches() {
        let responder = X3DHResponder::new();
        let bundle = responder.get_public_bundle();
        let wrong = X3DHResponder::new().get_public_bundle();
        let security = ServerSecurity::new(
            Some(encode_identity_pin(&wrong.identity_key).unwrap()),
            false,
            &bundle,
        )
        .unwrap();
        let error = security
            .validate(hello(&bundle, true), &bundle)
            .err()
            .unwrap()
            .context("handshake failed");
        let expected = format!(
            "IDENTITY_MISMATCH expected={} actual={}",
            encode_identity_pin(&wrong.identity_key).unwrap(),
            encode_identity_pin(&bundle.identity_key).unwrap()
        );
        assert_eq!(
            ServerSecurity::security_failure_message(&error).as_deref(),
            Some(expected.as_str())
        );
        assert!(security.actual_pin().is_none());
    }

    #[test]
    fn unpinned_profile_rejects_identity_not_present_in_its_bundle() {
        let bundle = X3DHResponder::new().get_public_bundle();
        let attacker = X3DHResponder::new().get_public_bundle();
        let security = ServerSecurity::new(None, false, &bundle).unwrap();
        assert!(security.validate(hello(&attacker, true), &bundle).is_err());
        assert!(security.actual_pin().is_none());
    }

    #[test]
    fn valid_signed_wire_x25519_replaces_tampered_disk_key_and_latches() {
        let responder = X3DHResponder::new();
        let bundle = responder.get_public_bundle();
        let mut disk = bundle.clone();
        disk.identity_x25519_signature = None;
        let security = ServerSecurity::new(None, false, &disk).unwrap();
        disk.identity_x25519_key = [7; 32];
        let validated = security.validate(hello(&bundle, true), &disk).unwrap();
        assert_eq!(
            validated.bundle.identity_x25519_key,
            bundle.identity_x25519_key
        );
        assert!(!security.signed_x25519_seen());
        assert!(security.actual_pin().is_none());
        validated.commit(&security);
        assert!(security.signed_x25519_seen());
        assert_eq!(
            security.actual_pin().unwrap(),
            encode_identity_pin(&bundle.identity_key).unwrap()
        );
    }

    #[test]
    fn signed_disk_bundle_is_verified_and_counts_as_signed_support() {
        let bundle = X3DHResponder::new().get_public_bundle();
        let security = ServerSecurity::new(None, false, &bundle).unwrap();
        assert!(security.signed_x25519_seen());
        let validated = security.validate(hello(&bundle, false), &bundle).unwrap();
        validated.commit(&security);
        assert_eq!(
            security.actual_pin().unwrap(),
            encode_identity_pin(&bundle.identity_key).unwrap()
        );

        let mut swapped = bundle.clone();
        swapped.identity_x25519_key = [7; 32];
        assert!(ServerSecurity::new(None, false, &swapped).is_err());
    }

    #[test]
    fn unsigned_server_is_rejected_after_signed_migration() {
        let responder = X3DHResponder::new();
        let mut bundle = responder.get_public_bundle();
        bundle.identity_x25519_signature = None;
        assert!(ServerSecurity::new(None, false, &bundle)
            .unwrap()
            .validate(hello(&bundle, false), &bundle)
            .is_ok());
        let error = ServerSecurity::new(None, true, &bundle)
            .unwrap()
            .validate(hello(&bundle, false), &bundle)
            .err()
            .unwrap()
            .context("handshake failed");
        assert_eq!(
            ServerSecurity::security_failure_message(&error).as_deref(),
            Some("SIGNED_X25519_DOWNGRADE: server removed its signed identity proof")
        );
    }

    #[test]
    fn partial_signed_proof_is_rejected() {
        let responder = X3DHResponder::new();
        let bundle = responder.get_public_bundle();
        let mut message = hello(&bundle, true);
        if let HandshakeMessage::ServerHello {
            identity_x25519_signature,
            ..
        } = &mut message
        {
            *identity_x25519_signature = None;
        }
        assert!(ServerSecurity::new(None, false, &bundle)
            .unwrap()
            .validate(message, &bundle)
            .is_err());
    }
}
