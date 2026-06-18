//! AEAD cipher implementations

use aead::{Aead, AeadInPlace, KeyInit, Payload};
use chacha20poly1305::ChaCha20Poly1305;
use chacha20poly1305::Nonce as ChaChaNonce;
use rand::Rng;

/// Nonce size for ChaCha20-Poly1305
pub const NONCE_SIZE: usize = 12;
/// Tag size for ChaCha20-Poly1305
pub const TAG_SIZE: usize = 16;
/// Key size for ChaCha20-Poly1305
pub const KEY_SIZE: usize = 32;

/// AEAD cipher wrapper
#[derive(Clone)]
pub struct Cipher {
    inner: ChaCha20Poly1305,
}

impl Cipher {
    /// Create a new cipher from a 32-byte key
    pub fn new(key: &[u8; 32]) -> Self {
        let inner = ChaCha20Poly1305::new_from_slice(key).expect("Key size is valid");
        Self { inner }
    }

    /// Encrypt plaintext in place
    ///
    /// # Arguments
    /// * `nonce` - 12-byte nonce
    /// * `associated_data` - Additional authenticated data
    /// * `plaintext` - Data to encrypt (will be extended with tag)
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8; NONCE_SIZE],
        associated_data: &[u8],
        plaintext: &mut Vec<u8>,
    ) -> crate::Result<()> {
        let nonce = ChaChaNonce::from_slice(nonce);
        let tag = self
            .inner
            .encrypt_in_place_detached(nonce, associated_data, plaintext)
            .map_err(|e| crate::Error::EncryptionFailed(e.to_string()))?;

        // Append tag to ciphertext
        plaintext.extend_from_slice(&tag);
        Ok(())
    }

    /// Decrypt ciphertext
    ///
    /// # Arguments
    /// * `nonce` - 12-byte nonce
    /// * `associated_data` - Additional authenticated data
    /// * `ciphertext` - Data to decrypt (includes tag at end)
    ///
    /// # Returns
    /// Decrypted plaintext or error
    pub fn decrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> crate::Result<Vec<u8>> {
        if ciphertext.len() < TAG_SIZE {
            return Err(crate::Error::DecryptionFailed(
                "ciphertext too short".to_string(),
            ));
        }

        let nonce = ChaChaNonce::from_slice(nonce);

        // Pass entire ciphertext including tag to decrypt
        self.inner
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|e| crate::Error::DecryptionFailed(e.to_string()))
    }

    /// Encrypt plaintext
    pub fn encrypt(
        &self,
        nonce: &[u8; NONCE_SIZE],
        associated_data: &[u8],
        plaintext: &[u8],
    ) -> crate::Result<Vec<u8>> {
        let nonce = ChaChaNonce::from_slice(nonce);

        self.inner
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|e| crate::Error::EncryptionFailed(e.to_string()))
    }
}

/// Generate a random nonce using cryptographically secure RNG
pub fn generate_nonce() -> [u8; NONCE_SIZE] {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill(&mut nonce);
    nonce
}

/// Generate a random key using cryptographically secure RNG
pub fn generate_key() -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    rand::thread_rng().fill(&mut key);
    key
}
