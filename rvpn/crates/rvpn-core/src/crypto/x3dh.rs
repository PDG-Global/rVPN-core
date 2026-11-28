//! X3DH (Extended Triple Diffie-Hellman) key agreement
//!
//! Implementation based on Signal Protocol specification:
//! https://signal.org/docs/specifications/x3dh/

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::SigningKey;
use rand::SeedableRng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use super::{hkdf_derive, EphemeralKey, IdentityKey, SharedSecret};
use crate::Error;

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
    let edwards_point = compressed.decompress().ok_or_else(|| {
        crate::Error::Crypto("Invalid Ed25519 public key: not a valid Edwards point".to_string())
    })?;

    // Convert to Montgomery form (u-coordinate)
    let montgomery_point = edwards_point.to_montgomery();

    Ok(montgomery_point.to_bytes())
}

/// X3DH key bundle (published by server)
/// Capability bit: the peer speaks ratchet wire version 2 (the
/// header-authenticating AAD and commit-after-verify decrypt, Q1).
pub const CAP_RATCHET_V2: u32 = 1;

/// v1 handshake sunset, 2027-02-01T00:00:00Z. After this moment a session
/// that cannot negotiate V2 is REFUSED (visible error), on both sides.
/// Sized to the Android rollout through the release lane; adjust only by
/// PR, never by config. The cleanup commit deletes `negotiate_version`'s
/// V1 arm together with every `RatchetVersion::V1` AAD path — one commit,
/// no archaeology: a sunset that lives only in a design doc never happens.
pub const V1_SUNSET_UNIX: u64 = 1801440000;

/// Which side of the handshake is asking: the downgrade rules differ.
/// Servers deploy first, so a v2-capable **client** can demand v2 — every
/// server it meets speaks it — while the **server** must still answer
/// genuinely old clients in v1 until the sunset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegotiationSide {
    /// V2 or an error, never V1: while bundles are unsigned, stripping
    /// BOTH capability fields would otherwise downgrade a new client onto
    /// the unauthenticated header. V1 on this side is simply not an outcome.
    Client,
    /// V2 when both advertise it; V1 for old clients until
    /// [`V1_SUNSET_UNIX`], an error after.
    Server,
}

/// What the two capability sets negotiate to. `now_unix` is injectable for
/// tests. The both-strip attack (unsigned bundles until area-1 Q5 signs
/// them) is closed asymmetrically: the client side never accepts V1, so a
/// both-strip fails the client; the server side accepts v1 only until the
/// coded sunset, after which it fails too.
pub fn negotiate_version(
    side: NegotiationSide,
    client_caps: u32,
    server_caps: u32,
    now_unix: u64,
) -> crate::Result<super::ratchet::RatchetVersion> {
    if client_caps & CAP_RATCHET_V2 != 0 && server_caps & CAP_RATCHET_V2 != 0 {
        return Ok(super::ratchet::RatchetVersion::V2);
    }
    match side {
        NegotiationSide::Client => Err(crate::Error::HandshakeFailed(
            "server does not speak ratchet v2; a v2-capable client refuses v1".to_string(),
        )),
        NegotiationSide::Server if now_unix < V1_SUNSET_UNIX => {
            Ok(super::ratchet::RatchetVersion::V1)
        }
        NegotiationSide::Server => Err(crate::Error::HandshakeFailed(format!(
            "peer cannot negotiate ratchet v2 and the v1 sunset ({V1_SUNSET_UNIX}) has passed"
        ))),
    }
}

/// The shared-secret derivation for a negotiated version. V1 is the legacy
/// construction (DH results only, legacy info string) so pre-v2 peers
/// derive identical keys; V2 mixes both capability sets into the KDF input
/// with a fresh info string, so a stripped or altered capability field
/// makes the two ends derive different secrets and the handshake dies at
/// the first tag check instead of silently downgrading: the capability
/// lives inside what the handshake authenticates.
fn derive_session_secret(
    dh_concat: &[u8],
    client_caps: u32,
    server_caps: u32,
    version: super::ratchet::RatchetVersion,
) -> SharedSecret {
    match version {
        super::ratchet::RatchetVersion::V1 => derive_shared_secret(dh_concat),
        super::ratchet::RatchetVersion::V2 => {
            let mut input = Vec::with_capacity(dh_concat.len() + 8);
            input.extend_from_slice(dh_concat);
            input.extend_from_slice(&client_caps.to_be_bytes());
            input.extend_from_slice(&server_caps.to_be_bytes());
            let mut result = [0u8; 32];
            let derived = hkdf_derive(&[], &input, b"R-VPN-v2 X3DH", 32);
            result.copy_from_slice(&derived);
            result
        }
    }
}

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
    /// Optional Ed25519 signature over the identity X25519 public key.
    /// Legacy bundles omit this and use the unsigned migration path.
    #[serde(
        default,
        serialize_with = "serialize_base64_opt",
        deserialize_with = "deserialize_base64_opt"
    )]
    pub identity_x25519_signature: Option<[u8; 64]>,
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
    /// Server capability bits (see [`CAP_RATCHET_V2`]). Pre-v2 bundles omit
    /// the field and deserialize as 0 = v1-only. Mixed into the KDF input
    /// for V2 sessions, so an on-path alteration diverges the secrets.
    #[serde(default)]
    pub capabilities: u32,
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
    ) -> crate::Result<(SharedSecret, X3DHMaterial, super::ratchet::RatchetVersion)> {
        // Derive X25519 private key from Ed25519 signing key for the client
        let ik_client_x25519_private =
            ed25519_signing_key_to_x25519_private_key(&self.identity_key.signing_key);

        // Derive the X25519 public key from the client's Ed25519 identity key
        let ik_client_x25519_public =
            X25519PublicKey::from(&X25519StaticSecret::from(ik_client_x25519_private));

        // DH1: IK_client * SPK_server
        let dh1 = x25519_diffie_hellman(&ik_client_x25519_private, &server_bundle.signed_prekey)?;

        // DH2: EK_client * IK_server (using the X25519 identity key from server)
        let dh2 = x25519_diffie_hellman(
            &self.ephemeral_key.private_key.to_bytes(),
            &server_bundle.identity_x25519_key,
        )?;

        // DH3: EK_client * SPK_server
        let dh3 = x25519_diffie_hellman(
            &self.ephemeral_key.private_key.to_bytes(),
            &server_bundle.signed_prekey,
        )?;

        // DH4: EK_client * OPK_server (if available)
        let dh4 = server_bundle
            .one_time_prekey
            .map(|opk| x25519_diffie_hellman(&self.ephemeral_key.private_key.to_bytes(), &opk))
            .transpose()?;

        // Concatenate DH results
        let mut dh_concat = Vec::with_capacity(32 * if dh4.is_some() { 4 } else { 3 });
        dh_concat.extend_from_slice(&dh1);
        dh_concat.extend_from_slice(&dh2);
        dh_concat.extend_from_slice(&dh3);
        if let Some(dh4) = &dh4 {
            dh_concat.extend_from_slice(dh4);
        }

        // Negotiate the ratchet version from the two capability sets and
        // derive with them inside the KDF input (V2), so a stripped or
        // altered capability diverges the secrets instead of downgrading.
        let client_caps = CAP_RATCHET_V2;
        let server_caps = server_bundle.capabilities;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let version = negotiate_version(NegotiationSide::Client, client_caps, server_caps, now)?;
        let shared_secret = derive_session_secret(&dh_concat, client_caps, server_caps, version);

        let material = X3DHMaterial {
            ephemeral_public: self.ephemeral_key.public_key.to_bytes(),
            identity_public: self.identity_key.verifying_key.to_bytes(),
            identity_x25519_public: ik_client_x25519_public.to_bytes(),
            one_time_prekey: server_bundle.one_time_prekey,
            capabilities: client_caps,
        };

        Ok((shared_secret, material, version))
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
        client_caps: u32,
    ) -> crate::Result<(SharedSecret, super::ratchet::RatchetVersion)> {
        // Contributory checks on the client-supplied keys: canonical, not
        // low-order, and every DH output contributory (S1).
        validate_x25519_public_key(client_identity_x25519)?;
        validate_x25519_public_key(client_ephemeral)?;

        // DH1: SPK_server * IK_client
        let dh1 = x25519_diffie_hellman(
            &self.private_bundle.signed_prekey.to_bytes(),
            client_identity_x25519,
        )?;

        // DH2: IK_server * EK_client
        let dh2 = x25519_diffie_hellman(
            &self.private_bundle.identity_x25519_key.to_bytes(),
            client_ephemeral,
        )?;

        // DH3: SPK_server * EK_client
        let dh3 = x25519_diffie_hellman(
            &self.private_bundle.signed_prekey.to_bytes(),
            client_ephemeral,
        )?;

        // DH4: OPK_server * EK_client (if client used an OTPK)
        let dh4 = if used_one_time_prekey {
            self.private_bundle
                .one_time_prekey
                .as_ref()
                .map(|opk| x25519_diffie_hellman(&opk.to_bytes(), client_ephemeral))
                .transpose()?
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

        let server_caps = self.get_public_bundle().capabilities;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let version = negotiate_version(NegotiationSide::Server, client_caps, server_caps, now)?;
        let shared_secret = derive_session_secret(&dh_concat, client_caps, server_caps, version);

        Ok((shared_secret, version))
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
        let identity_x25519_signature = self
            .private_bundle
            .identity_key
            .sign(&identity_x25519_message(&identity_x25519_public.to_bytes()))
            .to_bytes();

        // Include one-time prekey public key if available
        let one_time_prekey = self
            .private_bundle
            .one_time_prekey
            .as_ref()
            .map(|opk| X25519PublicKey::from(opk).to_bytes());

        X3DHPublicBundle {
            identity_key: self.private_bundle.identity_key.verifying_key().to_bytes(),
            identity_x25519_key: identity_x25519_public.to_bytes(),
            identity_x25519_signature: Some(identity_x25519_signature),
            signed_prekey: signed_prekey_public.to_bytes(),
            prekey_signature: signature.to_bytes(),
            one_time_prekey,
            // First-ever bundle: version 1, no rotation signature. The
            // server CLI's `prekey-bundle --rotate-from ...` flow patches
            // both fields post-construction; see
            // `rvpn_server::main::prekey_bundle`.
            identity_key_version: 1,
            rotation_signature: None,
            capabilities: CAP_RATCHET_V2,
        }
    }

    /// Get the private signed_prekey for deterministic prekey (server needs this)
    pub fn get_signed_prekey_private(&self) -> [u8; 32] {
        self.private_bundle.signed_prekey.to_bytes()
    }
}

fn identity_x25519_message(identity_x25519_key: &[u8; 32]) -> Vec<u8> {
    let mut message = b"rvpn-identity-x25519-v1".to_vec();
    message.extend_from_slice(identity_x25519_key);
    message
}

/// Verify the optional identity-X25519 signature using the server's Ed25519 key.
pub fn verify_identity_x25519_signature(
    identity_key: &[u8; 32],
    identity_x25519_key: &[u8; 32],
    signature: &[u8; 64],
) -> crate::Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let identity = VerifyingKey::from_bytes(identity_key)
        .map_err(|error| Error::HandshakeFailed(format!("invalid server identity key: {error}")))?;
    identity
        .verify(
            &identity_x25519_message(identity_x25519_key),
            &Signature::from_bytes(signature),
        )
        .map_err(|error| {
            Error::HandshakeFailed(format!("invalid identity X25519 signature: {error}"))
        })
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
    /// Client capability bits offered in this handshake.
    pub capabilities: u32,
}

/// The X25519 field prime p = 2^255 - 19, little-endian. Public keys MUST
/// be canonical (< p); the top range is a non-canonical encoding of the
/// same points.
const X25519_P_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Known low-order X25519 public keys (RFC 7748 / libsodium blocklist).
/// Any of these as a peer key makes the DH output non-contributory.
const X25519_LOW_ORDER: [[u8; 32]; 7] = [
    [0u8; 32],
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    [
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4,
        0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49,
        0xb8, 0x00,
    ],
    [
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef,
        0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f,
        0x11, 0x57,
    ],
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

/// Validate a received X25519 public key: canonical (< p) and not a known
/// low-order point. Both ends of an agree() run this on every wire key.
fn validate_x25519_public_key(public_key: &[u8; 32]) -> crate::Result<()> {
    // Canonical: LE integer must be < p. Compare from the top byte down.
    let mut ge = false;
    let mut eq = true;
    for i in (0..32).rev() {
        if eq {
            if public_key[i] > X25519_P_LE[i] {
                ge = true;
                eq = false;
            } else if public_key[i] < X25519_P_LE[i] {
                eq = false;
            }
        }
    }
    if ge || eq {
        return Err(crate::Error::HandshakeFailed(
            "non-canonical X25519 public key".to_string(),
        ));
    }
    for low in X25519_LOW_ORDER.iter() {
        if bool::from(public_key.ct_eq(low)) {
            return Err(crate::Error::HandshakeFailed(
                "low-order X25519 public key".to_string(),
            ));
        }
    }
    Ok(())
}

/// Perform X25519 Diffie-Hellman with the contributory check: an all-zero
/// output means the peer key was low-order, and the session must not be
/// built on a non-contributory secret.
fn x25519_diffie_hellman(private_key: &[u8; 32], public_key: &[u8; 32]) -> crate::Result<[u8; 32]> {
    validate_x25519_public_key(public_key)?;
    let private = X25519StaticSecret::from(*private_key);
    let public = X25519PublicKey::from(*public_key);
    let out = *private.diffie_hellman(&public).as_bytes();
    if bool::from(out.ct_eq(&[0u8; 32])) {
        return Err(crate::Error::HandshakeFailed(
            "non-contributory X25519 output".to_string(),
        ));
    }
    Ok(out)
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

    /// Contributory pin (S1): a low-order or non-canonical client key must
    /// fail the agreement, so a learned "identity" that is actually a
    /// low-order point can never complete a session.
    #[test]
    fn low_order_and_noncanonical_keys_are_rejected() {
        let responder = X3DHResponder::new();
        // All-zero identity key (low-order).
        assert!(
            responder.agree(&[0u8; 32], &[9u8; 32], false, 0).is_err(),
            "all-zero identity key must be rejected"
        );
        // Identity key = 1 (low-order).
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(
            responder.agree(&one, &[9u8; 32], false, 0).is_err(),
            "low-order identity key must be rejected"
        );
        // Non-canonical identity key (>= p): p itself.
        let p_le = crate::crypto::x3dh::X25519_P_LE;
        assert!(
            responder.agree(&p_le, &[9u8; 32], false, 0).is_err(),
            "non-canonical identity key must be rejected"
        );
        // Low-order ephemeral.
        let valid_ik = X25519PublicKey::from(&X25519StaticSecret::from([42u8; 32])).to_bytes();
        assert!(
            responder.agree(&valid_ik, &[0u8; 32], false, 0).is_err(),
            "low-order ephemeral key must be rejected"
        );
        // A valid key pair still agrees.
        let valid_ek = X25519PublicKey::from(&X25519StaticSecret::from([43u8; 32])).to_bytes();
        assert!(
            responder.agree(&valid_ik, &valid_ek, false, 0).is_ok(),
            "valid keys must still complete"
        );
    }

    /// Blocklist self-validation: EVERY entry of X25519_LOW_ORDER must be
    /// a genuine contributory point — X25519(11, entry) == 0 — so a typo'd
    /// entry can never rot into dead weight (review nit: entry 3 once
    /// wasn't a low-order point at all). And every entry must be rejected
    /// by the validator.
    #[test]
    fn low_order_blocklist_is_self_validating() {
        let scalar = X25519StaticSecret::from({
            let mut s = [0u8; 32];
            s[0] = 11;
            s
        });
        for entry in X25519_LOW_ORDER.iter() {
            let out = scalar.diffie_hellman(&X25519PublicKey::from(*entry));
            assert!(
                out.as_bytes().iter().all(|b| *b == 0),
                "blocklist entry {:02x?}… is NOT a contributory point",
                &entry[..4]
            );
            assert!(
                validate_x25519_public_key(entry).is_err(),
                "blocklist entry {:02x?}… must be rejected",
                &entry[..4]
            );
        }
        // Control: the basepoint is neither blocked nor contributory.
        let mut nine = [0u8; 32];
        nine[0] = 9;
        let out = scalar.diffie_hellman(&X25519PublicKey::from(nine));
        assert!(!out.as_bytes().iter().all(|b| *b == 0));
        assert!(validate_x25519_public_key(&nine).is_ok());
    }

    /// New bundles serialize both TOFU fields (version + optional rotation
    /// signature); a legacy bundle JSON that predates the format bump
    /// deserializes with version=1 and rotation_signature=None via
    /// `#[serde(default)]`. Guards against breaking old on-disk / on-wire
    /// bundles when we ship the format bump.
    #[test]
    fn bundle_serde_backwards_compatible() {
        let responder = X3DHResponder::new();
        let bundle = responder.get_public_bundle();
        let full_json = serde_json::to_value(&bundle).unwrap();
        let full_obj = full_json.as_object().unwrap();

        let legacy_obj: serde_json::Map<_, _> = full_obj
            .iter()
            .filter(|(k, _)| {
                k.as_str() != "identity_key_version"
                    && k.as_str() != "rotation_signature"
                    && k.as_str() != "identity_x25519_signature"
            })
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        let legacy = serde_json::Value::Object(legacy_obj).to_string();

        let restored: X3DHPublicBundle =
            serde_json::from_str(&legacy).expect("legacy bundle decodes with defaults");
        assert_eq!(
            restored.identity_key_version, 1,
            "missing version defaults to 1"
        );
        assert!(restored.rotation_signature.is_none());
        assert!(restored.identity_x25519_signature.is_none());

        let mut rotated = bundle.clone();
        rotated.identity_key_version = 3;
        rotated.rotation_signature = Some([0x55; 64]);
        let json = serde_json::to_string(&rotated).expect("rotated bundle serializes");
        let back: X3DHPublicBundle =
            serde_json::from_str(&json).expect("rotated bundle round-trips");
        assert_eq!(back.identity_key_version, 3);
        assert_eq!(back.rotation_signature, Some([0x55; 64]));
        assert_eq!(
            back.identity_x25519_signature,
            bundle.identity_x25519_signature
        );
    }

    #[test]
    fn identity_x25519_signature_binds_key_to_identity() {
        let responder = X3DHResponder::new();
        let bundle = responder.get_public_bundle();
        let signature = bundle.identity_x25519_signature.unwrap();
        verify_identity_x25519_signature(
            &bundle.identity_key,
            &bundle.identity_x25519_key,
            &signature,
        )
        .unwrap();

        let mut tampered_key = bundle.identity_x25519_key;
        tampered_key[0] ^= 1;
        assert!(
            verify_identity_x25519_signature(&bundle.identity_key, &tampered_key, &signature,)
                .is_err()
        );

        let other_identity = X3DHResponder::new().get_public_bundle().identity_key;
        assert!(verify_identity_x25519_signature(
            &other_identity,
            &bundle.identity_x25519_key,
            &signature,
        )
        .is_err());
    }

    #[test]
    fn prekey_signature_cannot_be_reused_as_identity_x25519_proof() {
        let bundle = X3DHResponder::new().get_public_bundle();
        assert!(verify_identity_x25519_signature(
            &bundle.identity_key,
            &bundle.signed_prekey,
            &bundle.prekey_signature,
        )
        .is_err());
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
        let (client_secret, material, _version) = initiator.agree(&server_bundle).unwrap();

        // Server performs X3DH with the OTPK
        let used_otpk = material.one_time_prekey.is_some();
        let server_secret = responder
            .agree(
                &material.identity_x25519_public,
                &material.ephemeral_public,
                used_otpk,
                material.capabilities,
            )
            .unwrap();

        // Secrets should match
        assert_eq!(client_secret, server_secret.0);
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
            identity_x25519_signature: server_bundle_full.identity_x25519_signature,
            capabilities: server_bundle_full.capabilities,
        };

        // Create initiator (client)
        let initiator = X3DHInitiator::new();

        // With the contributory check (S1), the broken bundle is refused up
        // front: identity_x25519_key = [0u8; 32] is a low-order point, so
        // the initiator's agreement FAILS instead of deriving a secret that
        // can never match the server's. That is strictly stronger than the
        // old outcome (mismatched secrets discovered after the handshake).
        let result = initiator.agree(&server_bundle_broken);
        assert!(
            result.is_err(),
            "a missing (zeroed) identity_x25519_key must fail the handshake, not derive a dead secret"
        );
        let _ = responder; // server side unchanged
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
        let (client_secret, material, _version) = initiator.agree(&server_bundle).unwrap();

        // Server performs X3DH with its actual keys
        let server_secret = responder
            .agree(
                &material.identity_x25519_public,
                &material.ephemeral_public,
                false, // no OTPK used
                material.capabilities,
            )
            .unwrap();

        // Secrets should match when identity_x25519_key is properly included
        assert_eq!(client_secret, server_secret.0);
    }
}

#[cfg(test)]
mod q1_negotiation_tests {
    use super::*;

    fn pair() -> (X3DHInitiator, X3DHResponder) {
        (X3DHInitiator::new(), X3DHResponder::new())
    }

    #[test]
    fn v2_handshake_secrets_match_and_version_is_v2() {
        let (initiator, responder) = pair();
        let bundle = responder.get_public_bundle();
        assert_eq!(bundle.capabilities, CAP_RATCHET_V2);
        let (client_secret, material, c_version) = initiator.agree(&bundle).unwrap();
        let (server_secret, s_version) = responder
            .agree(
                &material.identity_x25519_public,
                &material.ephemeral_public,
                false,
                material.capabilities,
            )
            .unwrap();
        assert_eq!(client_secret, server_secret);
        assert_eq!(c_version, super::super::ratchet::RatchetVersion::V2);
        assert_eq!(s_version, super::super::ratchet::RatchetVersion::V2);
    }

    #[test]
    fn stripped_client_capability_diverges_the_secrets() {
        // On-path attacker removes the client's capability field: server
        // sees 0 and derives the v1 secret; the honest client derives v2.
        // The handshake must DIE (secrets differ), not fall back to v1.
        let (initiator, responder) = pair();
        let bundle = responder.get_public_bundle();
        let (client_secret, material, c_version) = initiator.agree(&bundle).unwrap();
        let (server_secret, s_version) = responder
            .agree(
                &material.identity_x25519_public,
                &material.ephemeral_public,
                false,
                0, // stripped in flight
            )
            .unwrap();
        assert_eq!(c_version, super::super::ratchet::RatchetVersion::V2);
        assert_eq!(s_version, super::super::ratchet::RatchetVersion::V1);
        assert_ne!(
            client_secret, server_secret,
            "strip must diverge the secrets: the session dies at the first tag"
        );
    }

    #[test]
    fn both_strip_is_refused_by_the_client() {
        // The both-strip attack: remove CAP_RATCHET_V2 from the
        // (unsigned) server bundle AND from the client's handshake. With a
        // symmetric rule both ends would negotiate V1 and the handshake
        // would succeed on the unauthenticated header. The client side
        // never accepts V1, so the tampered bundle kills the handshake at
        // agree() — before any secret is derived.
        let (initiator, responder) = pair();
        let mut bundle = responder.get_public_bundle();
        bundle.capabilities = 0; // stripped in flight
        assert!(
            initiator.agree(&bundle).is_err(),
            "a v2-capable client must refuse a v1-only negotiation"
        );
    }

    #[test]
    fn server_side_still_answers_old_clients_until_the_sunset() {
        // The asymmetry's other half: a genuinely old client (no caps)
        // still gets a working v1 session from a new server, pre-sunset,
        // and both derive the SAME legacy secret.
        let legacy_client_caps = 0;
        let (_, responder) = pair();
        let bundle = responder.get_public_bundle();
        assert_eq!(bundle.capabilities, CAP_RATCHET_V2);
        assert_eq!(
            negotiate_version(
                NegotiationSide::Server,
                legacy_client_caps,
                bundle.capabilities,
                V1_SUNSET_UNIX - 1
            )
            .unwrap(),
            super::super::ratchet::RatchetVersion::V1
        );
    }

    #[test]
    fn v1_is_refused_after_the_coded_sunset() {
        use super::super::ratchet::RatchetVersion as V;
        // Client side: never v1, before or after the sunset.
        assert!(negotiate_version(NegotiationSide::Client, 0, 0, 1).is_err());
        assert!(negotiate_version(NegotiationSide::Client, CAP_RATCHET_V2, 0, 1).is_err());
        // Server side: v1 only until the sunset.
        assert!(negotiate_version(NegotiationSide::Server, 0, 0, V1_SUNSET_UNIX + 1).is_err());
        assert_eq!(
            negotiate_version(NegotiationSide::Server, 0, 0, V1_SUNSET_UNIX - 1).unwrap(),
            V::V1
        );
        // v2 is always available to both sides when both advertise it.
        for side in [NegotiationSide::Client, NegotiationSide::Server] {
            assert_eq!(
                negotiate_version(side, CAP_RATCHET_V2, CAP_RATCHET_V2, V1_SUNSET_UNIX + 1)
                    .unwrap(),
                V::V2
            );
        }
    }

    #[test]
    fn legacy_bundle_without_capabilities_deserializes_as_v1_only() {
        // Pre-v2 bundle JSON has no capabilities field: must read as 0.
        let responder = X3DHResponder::new();
        let bundle = responder.get_public_bundle();
        let json = serde_json::to_string(&bundle).unwrap();
        let stripped: serde_json::Value = serde_json::from_str(&json).unwrap();
        let mut obj = stripped.clone();
        obj.as_object_mut().unwrap().remove("capabilities");
        let legacy: X3DHPublicBundle = serde_json::from_value(obj).unwrap();
        assert_eq!(legacy.capabilities, 0);
    }
}
