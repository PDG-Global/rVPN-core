//! Cryptographic primitives for R-VPN

pub use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::SeedableRng;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod cipher;
pub mod ratchet;
pub mod x3dh;

pub use x3dh::{X3DHResponder, X3DHPublicBundle};
pub use ratchet::{DoubleRatchet, RatchetMessage, RatchetMessageRef, MessageHeader};

/// Ed25519 identity key pair
///
/// # Security
/// This type implements `ZeroizeOnDrop` to ensure private key material is cleared
/// from memory when the key is dropped. The `Clone` implementation temporarily
/// duplicates key material in memory — avoid cloning in hot paths.
#[derive(Clone)]
pub struct IdentityKey {
    /// Private signing key
    pub signing_key: SigningKey,
    /// Public verifying key
    pub verifying_key: VerifyingKey,
}

impl zeroize::Zeroize for IdentityKey {
    fn zeroize(&mut self) {
        // ed25519-dalek's SigningKey does not implement Zeroize.
        // Replace with a freshly generated random key to overwrite memory.
        let mut rng = rand::rngs::OsRng;
        self.signing_key = SigningKey::generate(&mut rng);
        self.verifying_key = self.signing_key.verifying_key();
    }
}

impl zeroize::ZeroizeOnDrop for IdentityKey {}

impl IdentityKey {
    /// Generate a new random identity key
    pub fn generate() -> Self {
        // Use from_entropy instead of thread_rng for better compatibility
        // thread_rng uses OsRng which may have initialization issues on some platforms
        let mut rng = rand::rngs::StdRng::from_entropy();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Load identity key from file
    ///
    /// Supports two formats:
    /// - New (4 lines): R-VPN-IDENTITY-v1\ned25519: <b64>\nx25519: <b64>\n<b64_signing>\n
    /// - Old (3 lines): R-VPN-IDENTITY-v1\n<b64_public>\n<b64_private>\n
    pub fn load(path: &std::path::Path) -> crate::Result<Self> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

        let content = std::fs::read_to_string(path)?;
        let lines: Vec<&str> = content.lines().collect();

        if lines.is_empty() || lines[0] != "R-VPN-IDENTITY-v1" {
            return Err(crate::Error::InvalidKey("Invalid identity key file format".to_string()));
        }

        // New format: 4 lines with prefixed key types
        // R-VPN-IDENTITY-v1\ned25519: <b64>\nx25519: <b64>\n<b64_signing>\n
        let signing_key_bytes = if lines.len() >= 4 && lines[1].starts_with("ed25519:") {
            let key_b64 = &lines[1]["ed25519:".len()..].trim();
            let _ = BASE64.decode(key_b64)?; // validate ed25519 key
            BASE64.decode(lines[3].trim())?
        } else if lines.len() >= 3 {
            // Old format: 3 lines, signing key is on line 2
            BASE64.decode(lines[2].trim())?
        } else {
            return Err(crate::Error::InvalidKey(
                "Invalid identity key file: too few lines".to_string(),
            ));
        };

        let signing_key_array: [u8; 32] = signing_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| crate::Error::InvalidKey("Invalid signing key length".to_string()))?;

        // Create signing key and derive verifying key from it
        let signing_key = SigningKey::from_bytes(&signing_key_array);
        let verifying_key = signing_key.verifying_key();

        Ok(Self { signing_key, verifying_key })
    }
    
    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer;
        self.signing_key.sign(message).to_bytes()
    }
    
    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &[u8; 64]) -> crate::Result<()> {
        use ed25519_dalek::Verifier;
        let sig = ed25519_dalek::Signature::from_bytes(signature);
        self.verifying_key
            .verify(message, &sig)
            .map_err(|e| crate::Error::Crypto(e.to_string()))
    }

    /// Get the X25519 public key derived from this Ed25519 identity
    /// This is used for X3DH key exchange
    pub fn x25519_public_key(&self) -> [u8; 32] {
        use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
        let x25519_secret = X25519StaticSecret::from(self.signing_key.to_bytes());
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        x25519_public.to_bytes()
    }

    /// Save identity key to file
    pub fn save(&self, path: &std::path::Path) -> crate::Result<()> {
        use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

        let content = zeroize::Zeroizing::new(format!(
            "R-VPN-IDENTITY-v1\n{}\n{}\n",
            BASE64.encode(self.verifying_key.to_bytes()),
            BASE64.encode(self.signing_key.to_bytes())
        ));

        std::fs::write(path, content.as_str())?;
        Ok(())
    }
}

/// X25519 key pair for key exchange
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralKey {
    /// Private key
    pub private_key: X25519StaticSecret,
    /// Public key
    #[zeroize(skip)]
    pub public_key: X25519PublicKey,
}

impl EphemeralKey {
    /// Generate a new ephemeral key pair
    pub fn generate() -> Self {
        let private_key = X25519StaticSecret::random_from_rng(rand::rngs::StdRng::from_entropy());
        let public_key = X25519PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }
    
    /// Perform Diffie-Hellman key exchange
    pub fn diffie_hellman(&self, other_public: &X25519PublicKey) -> [u8; 32] {
        *self.private_key.diffie_hellman(other_public).as_bytes()
    }
}

impl Clone for EphemeralKey {
    fn clone(&self) -> Self {
        // Clone by re-deriving from bytes
        let private_bytes = self.private_key.to_bytes();
        let private_key = X25519StaticSecret::from(private_bytes);
        let public_key = X25519PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
        }
    }
}

/// Prekey bundle for X3DH
#[derive(Clone, Debug)]
pub struct PreKeyBundle {
    /// Identity public key (Ed25519)
    pub identity_key: VerifyingKey,
    /// Signed prekey (X25519)
    pub signed_prekey: X25519PublicKey,
    /// Signature of signed_prekey
    pub prekey_signature: [u8; 64],
    /// One-time prekeys (X25519)
    pub one_time_prekeys: Vec<X25519PublicKey>,
}

/// Shared secret derived from key exchange
pub type SharedSecret = [u8; 32];

/// Derive keys using HKDF-SHA256
pub fn hkdf_derive(salt: &[u8], ikm: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hkdf.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}

/// Constant-time comparison of two byte slices
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Use subtle crate for constant-time comparison
    a.ct_eq(b).into()
}
