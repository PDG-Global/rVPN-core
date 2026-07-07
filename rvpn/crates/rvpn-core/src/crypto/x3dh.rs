//! X3DH (Extended Triple Diffie-Hellman) key agreement
//!
//! Implementation based on Signal Protocol specification:
//! https://signal.org/docs/specifications/x3dh/

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use super::{hkdf_derive, EphemeralKey, IdentityKey, SharedSecret};

/// Serialize a fixed-size byte array as base64
fn serialize_base64<S: Serializer, const N: usize>(
    bytes: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let encoded = BASE64.encode(bytes);
    serializer.serialize_str(&encoded)
}

/// Deserialize a fixed-size byte array from base64
fn deserialize_base64<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error> {
    let encoded: String = Deserialize::deserialize(deserializer)?;
    let decoded = BASE64.decode(&encoded).map_err(serde::de::Error::custom)?;
    decoded
        .try_into()
        .map_err(|_| serde::de::Error::custom("Invalid byte array length"))
}

/// Serialize optional fixed-size byte array as base64
fn serialize_base64_opt<S: Serializer, const N: usize>(
    bytes: &Option<[u8; N]>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match bytes {
        Some(b) => serialize_base64(b, serializer),
        None => serializer.serialize_none(),
    }
}

/// Deserialize optional fixed-size byte array from base64
fn deserialize_base64_opt<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<Option<[u8; N]>, D::Error> {
    let encoded: Option<String> = Deserialize::deserialize(deserializer)?;
    match encoded {
        Some(s) => {
            let decoded = BASE64.decode(&s).map_err(serde::de::Error::custom)?;
            Ok(Some(decoded.try_into().map_err(|_| {
                serde::de::Error::custom("Invalid byte array length")
            })?))
        }
        None => Ok(None),
    }
}

/// Derive an X25519 private key from an Ed25519 signing key.
///
/// This uses the Ed25519 private key seed (the first 32 bytes of the expanded secret)
/// and applies X25519 clamping to produce a valid X25519 private key.
fn ed25519_signing_key_to_x25519_private_key(signing_key: &SigningKey) -> [u8; 32] {
    // The Ed25519 signing key's to_bytes() returns the seed (32 bytes)
    let seed = signing_key.to_bytes();

    // Apply X25519 clamping to the seed to get a valid X25519 private key
    // This follows the same clamping rules as X25519:
    // - Clear bit 0, 1, 2 of byte 0
    // - Clear bit 7 of byte 31
    // - Set bit 6 of byte 31
    let mut x25519_private = seed;
    x25519_private[0] &= 0b1111_1000;
    x25519_private[31] &= 0b0111_1111;
    x25519_private[31] |= 0b0100_0000;

    x25519_private
}

/// Convert an Ed25519 public key to an X25519 public key.
///
/// This performs proper point conversion from the Edwards curve (Ed25519)
/// to the Montgomery curve (X25519) using the birational map:
/// u = (1 + y) / (1 - y)
///
/// The Ed25519 public key is interpreted as a compressed Edwards point,
/// decompressed, and then converted to Montgomery form.
#[allow(dead_code)]
fn ed25519_public_key_to_x25519(ed25519_public: &[u8; 32]) -> crate::Result<[u8; 32]> {
    // Interpret the Ed25519 public key as a compressed Edwards point
    let compressed = CompressedEdwardsY(*ed25519_public);

    // Decompress to get the Edwards point
    let edwards_point = compressed
        .decompress()
        .ok_or_else(|| crate::Error::Crypto("Invalid Ed25519 public key: not a valid Edwards point".to_string()))?;

    // Convert to Montgomery form (u-coordinate)
    let montgomery_point = edwards_point.to_montgomery();

    Ok(montgomery_point.to_bytes())
}

/// X3DH key bundle (published by server)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct X3DHPublicBundle {
    /// Identity public key (Ed25519, for signing)
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub identity_key: [u8; 32],
    /// Identity key for X3DH (X25519, derived from Ed25519 identity key)
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub identity_x25519_key: [u8; 32],
    /// Signed prekey (X25519)
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub signed_prekey: [u8; 32],
    /// Prekey signature
    #[serde(
        serialize_with = "serialize_base64",
        deserialize_with = "deserialize_base64"
    )]
    pub prekey_signature: [u8; 64],
    /// One-time prekey (X25519, optional)
    #[serde(
        serialize_with = "serialize_base64_opt",
        deserialize_with = "deserialize_base64_opt"
    )]
    pub one_time_prekey: Option<[u8; 32]>,
    /// Monotonic version of the identity key. Bumped by 1 every time the
    /// operator rotates the server identity via the chained-signature
    /// ceremony (see `rvpn_core::identity_pin::rotation_signature_message`).
    /// Bundles from pre-TOFU servers default to `1` so a fresh install of
    /// the new client can still deserialize them.
    #[serde(default = "default_identity_key_version")]
    pub identity_key_version: u32,
    /// Ed25519 signature over `new_identity_pub || new_version_le`, signed
    /// by the *previous* identity's private key. When present and valid,
    /// a client that already pinned the old identity can silently rotate
    /// its pin to the new one; when absent (or version = 1), no rotation
    /// is on offer.
    #[serde(
        default,
        serialize_with = "serialize_base64_opt",
        deserialize_with = "deserialize_base64_opt"
    )]
    pub rotation_signature: Option<[u8; 64]>,
}

fn default_identity_key_version() -> u32 {
    1
}

/// X3DH private keys (held by server)
#[derive(Clone)]
pub struct X3DHPrivateBundle {
    /// Identity signing key (Ed25519)
    pub identity_key: SigningKey,
    /// Identity key for X3DH (X25519, derived from Ed25519 identity key)
    pub identity_x25519_key: X25519StaticSecret,
    /// Signed prekey
    pub signed_prekey: X25519StaticSecret,
    /// One-time prekey
    pub one_time_prekey: Option<X25519StaticSecret>,
}

impl zeroize::Zeroize for X3DHPrivateBundle {
    fn zeroize(&mut self) {
        // SigningKey from ed25519-dalek does not implement Zeroize.
        // Replace with a random key to overwrite the old one.
        let mut rng = rand::rngs::StdRng::from_entropy();
        self.identity_key = SigningKey::generate(&mut rng);
        self.identity_x25519_key.zeroize();
        self.signed_prekey.zeroize();
        if let Some(ref mut otpk) = self.one_time_prekey {
            otpk.zeroize();
        }
    }
}

impl zeroize::ZeroizeOnDrop for X3DHPrivateBundle {}

/// X3DH initiator (client side)
pub struct X3DHInitiator {
    /// Client's identity key
    pub identity_key: IdentityKey,
    /// Client's ephemeral key
    pub ephemeral_key: EphemeralKey,
}

impl X3DHInitiator {
    /// Create a new X3DH initiator with a freshly generated identity key
    pub fn new() -> Self {
        Self {
            identity_key: IdentityKey::generate(),
            ephemeral_key: EphemeralKey::generate(),
        }
    }

    /// Create a new X3DH initiator from an existing identity key
    pub fn from_identity_key(identity_key: std::sync::Arc<IdentityKey>) -> Self {
        Self {
            identity_key: std::sync::Arc::try_unwrap(identity_key)
                .unwrap_or_else(|arc| (*arc).clone()),
            ephemeral_key: EphemeralKey::generate(),
        }
    }

    /// Perform X3DH key agreement (initiator side)
    ///
    /// Computes 4 DH secrets:
    /// - DH1 = IK_client * SPK_server
    /// - DH2 = EK_client * IK_server
    /// - DH3 = EK_client * SPK_server
    /// - DH4 = EK_client * OPK_server (if available)
    pub fn agree(
        &self,
        server_bundle: &X3DHPublicBundle,
    ) -> crate::Result<(SharedSecret, X3DHMaterial)> {
        // Derive X25519 private key from Ed25519 signing key for the client
        let ik_client_x25519_private =
            ed25519_signing_key_to_x25519_private_key(&self.identity_key.signing_key);

        // Derive the X25519 public key from the client's Ed25519 identity key
        let ik_client_x25519_public =
            X25519PublicKey::from(&X25519StaticSecret::from(ik_client_x25519_private));

        // DH1: IK_client * SPK_server
        let dh1 = x25519_diffie_hellman(&ik_client_x25519_private, &server_bundle.signed_prekey);

        // DH2: EK_client * IK_server (using the X25519 identity key from server)
        let dh2 = x25519_diffie_hellman(
            &self.ephemeral_key.private_key.to_bytes(),
            &server_bundle.identity_x25519_key,
        );

        // DH3: EK_client * SPK_server
        let dh3 = x25519_diffie_hellman(
            &self.ephemeral_key.private_key.to_bytes(),
            &server_bundle.signed_prekey,
        );

        // DH4: EK_client * OPK_server (if available)
        let dh4 = server_bundle.one_time_prekey.map(|opk| {
            x25519_diffie_hellman(&self.ephemeral_key.private_key.to_bytes(), &opk)
        });

        // Concatenate DH results
        let mut dh_concat = Vec::with_capacity(32 * if dh4.is_some() { 4 } else { 3 });
        dh_concat.extend_from_slice(&dh1);
        dh_concat.extend_from_slice(&dh2);
        dh_concat.extend_from_slice(&dh3);
        if let Some(dh4) = &dh4 {
            dh_concat.extend_from_slice(dh4);
        }

        // Derive shared secret using HKDF
        let shared_secret = derive_shared_secret(&dh_concat);

        let material = X3DHMaterial {
            ephemeral_public: self.ephemeral_key.public_key.to_bytes(),
            identity_public: self.identity_key.verifying_key.to_bytes(),
            identity_x25519_public: ik_client_x25519_public.to_bytes(),
            one_time_prekey: server_bundle.one_time_prekey,
        };

        Ok((shared_secret, material))
    }
}

impl Default for X3DHInitiator {
    fn default() -> Self {
        Self::new()
    }
}

/// X3DH responder (server side)
pub struct X3DHResponder {
    /// Server's private bundle
    pub private_bundle: X3DHPrivateBundle,
}

impl X3DHResponder {
    /// Create a new X3DH responder with a new identity
    pub fn new() -> Self {
        let identity_key = SigningKey::generate(&mut rand::rngs::StdRng::from_entropy());
        // Derive X25519 identity key from Ed25519 signing key
        let identity_x25519_key =
            X25519StaticSecret::from(ed25519_signing_key_to_x25519_private_key(&identity_key));
        let signed_prekey = X25519StaticSecret::random_from_rng(rand::rngs::StdRng::from_entropy());

        Self {
            private_bundle: X3DHPrivateBundle {
                identity_key,
                identity_x25519_key,
                signed_prekey,
                one_time_prekey: None,
            },
        }
    }

    /// Create a X3DH responder from an existing identity key
    pub fn from_identity(identity: crate::crypto::IdentityKey) -> Self {
        let identity_x25519_key = X25519StaticSecret::from(
            ed25519_signing_key_to_x25519_private_key(&identity.signing_key),
        );
        let signed_prekey = X25519StaticSecret::random_from_rng(rand::rngs::StdRng::from_entropy());

        // Clone signing_key via bytes since ed25519-dalek doesn't implement Clone
        let signing_key_bytes = identity.signing_key.to_bytes();
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);

        Self {
            private_bundle: X3DHPrivateBundle {
                identity_key: signing_key,
                identity_x25519_key,
                signed_prekey,
                one_time_prekey: None,
            },
        }
    }

    /// Create a X3DH responder from an identity key and specific prekey bundle values
    /// This ensures the server uses the same keys that were published in the prekey bundle
    pub fn from_identity_with_bundle(
        identity: crate::crypto::IdentityKey,
        signed_prekey_bytes: [u8; 32],
    ) -> Self {
        let identity_x25519_key = X25519StaticSecret::from(
            ed25519_signing_key_to_x25519_private_key(&identity.signing_key),
        );
        let signed_prekey = X25519StaticSecret::from(signed_prekey_bytes);

        // Clone signing_key via bytes since ed25519-dalek doesn't implement Clone
        let signing_key_bytes = identity.signing_key.to_bytes();
        let signing_key = SigningKey::from_bytes(&signing_key_bytes);

        Self {
            private_bundle: X3DHPrivateBundle {
                identity_key: signing_key,
                identity_x25519_key,
                signed_prekey,
                one_time_prekey: None,
            },
        }
    }

    /// Generate a new one-time prekey
    pub fn generate_one_time_prekey(&mut self) -> [u8; 32] {
        let key = X25519StaticSecret::random_from_rng(rand::rngs::StdRng::from_entropy());
        let public = X25519PublicKey::from(&key);
        self.private_bundle.one_time_prekey = Some(key);
        public.to_bytes()
    }

    /// Perform X3DH key agreement (responder side)
    ///
    /// # Arguments
    ///
    /// * `client_identity_x25519` - The client's X25519 identity public key
    /// * `client_ephemeral` - The client's ephemeral public key
    /// * `used_one_time_prekey` - Whether the client used a one-time prekey (if so, server's OTPK is used)
    pub fn agree(
        &self,
        client_identity_x25519: &[u8; 32],
        client_ephemeral: &[u8; 32],
        used_one_time_prekey: bool,
    ) -> crate::Result<SharedSecret> {
        // DH1: SPK_server * IK_client
        let dh1 = x25519_diffie_hellman(
            &self.private_bundle.signed_prekey.to_bytes(),
            client_identity_x25519,
        );

        // DH2: IK_server * EK_client
        let dh2 = x25519_diffie_hellman(
            &self.private_bundle.identity_x25519_key.to_bytes(),
            client_ephemeral,
        );

        // DH3: SPK_server * EK_client
        let dh3 = x25519_diffie_hellman(
            &self.private_bundle.signed_prekey.to_bytes(),
            client_ephemeral,
        );

        // DH4: OPK_server * EK_client (if client used an OTPK)
        let dh4 = if used_one_time_prekey {
            self.private_bundle.one_time_prekey.as_ref().map(|opk| {
                x25519_diffie_hellman(&opk.to_bytes(), client_ephemeral)
            })
        } else {
            None
        };

        // Concatenate DH results
        let mut dh_concat = Vec::with_capacity(32 * if dh4.is_some() { 4 } else { 3 });
        dh_concat.extend_from_slice(&dh1);
        dh_concat.extend_from_slice(&dh2);
        dh_concat.extend_from_slice(&dh3);
        if let Some(dh4) = &dh4 {
            dh_concat.extend_from_slice(dh4);
        }

        let shared_secret = derive_shared_secret(&dh_concat);

        Ok(shared_secret)
    }

    /// Get public bundle for publishing
    pub fn get_public_bundle(&self) -> X3DHPublicBundle {
        let signed_prekey_public = X25519PublicKey::from(&self.private_bundle.signed_prekey);
        let identity_x25519_public =
            X25519PublicKey::from(&self.private_bundle.identity_x25519_key);

        // Sign the prekey
        use ed25519_dalek::Signer;
        let signature = self
            .private_bundle
            .identity_key
            .sign(&signed_prekey_public.to_bytes());

        // Include one-time prekey public key if available
        let one_time_prekey = self
            .private_bundle
            .one_time_prekey
            .as_ref()
            .map(|opk| X25519PublicKey::from(opk).to_bytes());

        X3DHPublicBundle {
            identity_key: self.private_bundle.identity_key.verifying_key().to_bytes(),
            identity_x25519_key: identity_x25519_public.to_bytes(),
            signed_prekey: signed_prekey_public.to_bytes(),
            prekey_signature: signature.to_bytes(),
            one_time_prekey,
            // First-ever bundle: version 1, no rotation signature. The
            // server CLI's `prekey-bundle --rotate-from ...` flow patches
            // both fields post-construction; see
            // `rvpn_server::main::prekey_bundle`.
            identity_key_version: 1,
            rotation_signature: None,
        }
    }

    /// Get the private signed_prekey for deterministic prekey (server needs this)
    pub fn get_signed_prekey_private(&self) -> [u8; 32] {
        self.private_bundle.signed_prekey.to_bytes()
    }
}

impl Default for X3DHResponder {
    fn default() -> Self {
        Self::new()
    }
}

/// Material exchanged during X3DH handshake
#[derive(Clone, Debug)]
pub struct X3DHMaterial {
    /// Ephemeral public key
    pub ephemeral_public: [u8; 32],
    /// Identity public key (Ed25519)
    pub identity_public: [u8; 32],
    /// Identity public key (X25519, for DH)
    pub identity_x25519_public: [u8; 32],
    /// One-time prekey used (if any)
    pub one_time_prekey: Option<[u8; 32]>,
}

/// Perform X25519 Diffie-Hellman
fn x25519_diffie_hellman(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    let private = X25519StaticSecret::from(*private_key);
    let public = X25519PublicKey::from(*public_key);
    *private.diffie_hellman(&public).as_bytes()
}

/// Derive shared secret from DH results
fn derive_shared_secret(dh_results: &[u8]) -> SharedSecret {
    let mut result = [0u8; 32];
    let derived = hkdf_derive(&[], dh_results, b"R-VPN-v1 X3DH", 32);
    result.copy_from_slice(&derived);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    /// New bundles serialize both TOFU fields (version + optional rotation
    /// signature); a legacy bundle JSON that predates the format bump
    /// deserializes with version=1 and rotation_signature=None via
    /// `#[serde(default)]`. Guards against breaking old on-disk / on-wire
    /// bundles when we ship the format bump.
    #[test]
    fn bundle_serde_backwards_compatible() {
        // Take a real bundle, serialize it, strip out the two new fields
        // and confirm it still deserializes — this is the "old client's
        // bundle file loaded by the new client" migration case.
        let responder = X3DHResponder::new();
        let bundle = responder.get_public_bundle();
        let full_json = serde_json::to_value(&bundle).unwrap();
        let full_obj = full_json.as_object().unwrap();

        let legacy_obj: serde_json::Map<_, _> = full_obj
            .iter()
            .filter(|(k, _)| {
                k.as_str() != "identity_key_version"
                    && k.as_str() != "rotation_signature"
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let legacy = serde_json::Value::Object(legacy_obj).to_string();

        let restored: X3DHPublicBundle =
            serde_json::from_str(&legacy).expect("legacy bundle decodes with defaults");
        assert_eq!(restored.identity_key_version, 1, "missing version defaults to 1");
        assert!(restored.rotation_signature.is_none());

        // A new bundle with both TOFU fields set round-trips exactly.
        let mut rotated = bundle.clone();
        rotated.identity_key_version = 3;
        rotated.rotation_signature = Some([0x55; 64]);
        let json = serde_json::to_string(&rotated).expect("rotated bundle serializes");
        let back: X3DHPublicBundle = serde_json::from_str(&json).expect("rotated bundle round-trips");
        assert_eq!(back.identity_key_version, 3);
        assert_eq!(back.rotation_signature, Some([0x55; 64]));
    }

    #[test]
    fn responder_publishes_version_1_by_default() {
        // A fresh server always publishes version=1 with no rotation
        // signature. Rotation ceremony via the CLI patches the bundle
        // after construction (see rvpn-server prekey_bundle()).
        let responder = X3DHResponder::new();
        let bundle = responder.get_public_bundle();
        assert_eq!(bundle.identity_key_version, 1);
        assert!(bundle.rotation_signature.is_none());
    }

    #[test]
    fn test_x3dh_handshake() {
        // Create responder (server)
        let mut responder = X3DHResponder::new();
        let _otpk = responder.generate_one_time_prekey();
        let server_bundle = responder.get_public_bundle();

        // Create initiator (client)
        let initiator = X3DHInitiator::new();

        // Client performs X3DH - with OTPK available
        let (client_secret, material) = initiator.agree(&server_bundle).unwrap();

        // Server performs X3DH with the OTPK
        let used_otpk = material.one_time_prekey.is_some();
        let server_secret = responder
            .agree(
                &material.identity_x25519_public,
                &material.ephemeral_public,
                used_otpk,
            )
            .unwrap();

        // Secrets should match
        assert_eq!(client_secret, server_secret);
    }

    /// Test that simulates the bug where server's bundle is missing identity_x25519_key
    /// This happens when the prekey bundle JSON doesn't include the identity_x25519_key field
    #[test]
    fn test_x3dh_handshake_missing_identity_x25519_key() {
        // Create responder (server)
        let responder = X3DHResponder::new();
        let server_bundle_full = responder.get_public_bundle();

        // Simulate what happens when the bundle is loaded from JSON without identity_x25519_key
        // The client falls back to [0u8; 32] for this field
        let server_bundle_broken = X3DHPublicBundle {
            identity_key: server_bundle_full.identity_key,
            identity_x25519_key: [0u8; 32], // BUG: This is what the client uses when field is missing
            signed_prekey: server_bundle_full.signed_prekey,
            prekey_signature: server_bundle_full.prekey_signature,
            one_time_prekey: server_bundle_full.one_time_prekey,
            identity_key_version: server_bundle_full.identity_key_version,
            rotation_signature: server_bundle_full.rotation_signature,
        };

        // Create initiator (client)
        let initiator = X3DHInitiator::new();

        // Client performs X3DH with the broken bundle (missing identity_x25519_key)
        let (client_secret, material) = initiator.agree(&server_bundle_broken).unwrap();

        // Server performs X3DH with its actual keys
        let server_secret = responder
            .agree(
                &material.identity_x25519_public,
                &material.ephemeral_public,
                false, // no OTPK used
            )
            .unwrap();

        // This will FAIL because the client used [0u8; 32] for IK_server
        // but the server used its actual identity_x25519_key
        println!("Client secret: {:?}", hex::encode(&client_secret[..8]));
        println!("Server secret: {:?}", hex::encode(&server_secret[..8]));

        // This assertion should fail, demonstrating the bug
        if client_secret != server_secret {
            println!("BUG REPRODUCED: Client and server secrets don't match!");
            println!("This happens when identity_x25519_key is missing from the prekey bundle");
        }

        // For the test, we expect them to be different (demonstrating the bug)
        assert_ne!(client_secret, server_secret, "This demonstrates the bug - secrets should NOT match when identity_x25519_key is missing");
    }

    /// Test that shows the fix - when identity_x25519_key is properly included
    #[test]
    fn test_x3dh_handshake_with_identity_x25519_key() {
        // Create responder (server)
        let responder = X3DHResponder::new();
        let server_bundle = responder.get_public_bundle();

        // Create initiator (client)
        let initiator = X3DHInitiator::new();

        // Client performs X3DH with the complete bundle
        let (client_secret, material) = initiator.agree(&server_bundle).unwrap();

        // Server performs X3DH with its actual keys
        let server_secret = responder
            .agree(
                &material.identity_x25519_public,
                &material.ephemeral_public,
                false, // no OTPK used
            )
            .unwrap();

        // Secrets should match when identity_x25519_key is properly included
        assert_eq!(client_secret, server_secret);
    }
}
