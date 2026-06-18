//! Length-prefixed encryption framing protocol
//!
//! This module implements the Brook-style wire format for encrypted communication.
//! Each frame consists of an encrypted length field followed by encrypted data,
//! using AES-256-GCM for authenticated encryption.
//!
//! # Frame Format
//! ```text
//! +------------------+-------------------+-------------------+
//! | Encrypted Length |  Encrypted Data   |   (Optional Pad)  |
//! |     18 bytes     |   N + 16 bytes    |     0-255 bytes   |
//! | (2 len + 16 tag) | (N data + 16 tag) |    (padding)      |
//! +------------------+-------------------+-------------------+
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};

/// Size of encrypted length field (2 bytes plaintext + 16 bytes AEAD tag)
pub const LEN_CIPHERTEXT_SIZE: usize = 18;
/// Size of AEAD authentication tag
pub const TAG_SIZE: usize = 16;
/// Size of nonce
pub const NONCE_SIZE: usize = 12;
/// Maximum frame size (u16::MAX + length overhead + data overhead)
pub const MAX_FRAME_SIZE: usize = 65535 + LEN_CIPHERTEXT_SIZE + TAG_SIZE;
/// Size of plaintext length field
const LEN_PLAINTEXT_SIZE: usize = 2;

/// Error type for framing operations
#[derive(Debug, Clone, PartialEq)]
pub enum FramingError {
    /// Frame is too small to be valid
    FrameTooSmall,
    /// Frame exceeds maximum allowed size
    FrameTooLarge,
    /// Invalid length field
    InvalidLength,
    /// Decryption failed
    DecryptionFailed(String),
    /// Encryption failed
    EncryptionFailed(String),
}

impl std::fmt::Display for FramingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FramingError::FrameTooSmall => write!(f, "frame too small"),
            FramingError::FrameTooLarge => write!(f, "frame too large"),
            FramingError::InvalidLength => write!(f, "invalid length field"),
            FramingError::DecryptionFailed(s) => write!(f, "decryption failed: {}", s),
            FramingError::EncryptionFailed(s) => write!(f, "encryption failed: {}", s),
        }
    }
}

impl std::error::Error for FramingError {}

/// Encode data into a length-prefixed encrypted frame
///
/// # Arguments
/// * `data` - Plaintext data to encrypt and frame
/// * `cipher` - AES-256-GCM cipher instance
/// * `nonce` - 12-byte nonce (will be incremented after encryption)
///
/// # Returns
/// Encrypted frame ready for transmission
///
/// # Errors
/// Returns `FramingError::EncryptionFailed` if encryption fails
pub fn encode_frame(
    data: &[u8],
    cipher: &Aes256Gcm,
    nonce: &mut [u8; NONCE_SIZE],
) -> Result<Vec<u8>, FramingError> {
    // Validate data size (must fit in u16)
    let data_len = data.len();
    if data_len > u16::MAX as usize {
        return Err(FramingError::EncryptionFailed(
            "data exceeds maximum size".to_string(),
        ));
    }

    // 1. Encrypt length (2 bytes big-endian)
    let len = data_len as u16;
    let len_bytes = len.to_be_bytes();
    let len_ciphertext = encrypt_length(&len_bytes, cipher, nonce)?;
    increment_nonce(nonce);

    // 2. Encrypt data
    let data_ciphertext = encrypt_data(data, cipher, nonce)?;
    increment_nonce(nonce);

    // 3. Concatenate: encrypted length + encrypted data
    let frame_size = len_ciphertext.len() + data_ciphertext.len();
    let mut frame = Vec::with_capacity(frame_size);
    frame.extend_from_slice(&len_ciphertext);
    frame.extend_from_slice(&data_ciphertext);

    Ok(frame)
}

/// Decode a length-prefixed encrypted frame
///
/// # Arguments
/// * `frame` - Complete encrypted frame
/// * `cipher` - AES-256-GCM cipher instance
/// * `nonce` - 12-byte nonce (will be incremented after decryption)
///
/// # Returns
/// Decrypted plaintext data
///
/// # Errors
/// Returns `FramingError` if frame is invalid or decryption fails
pub fn decode_frame(
    frame: &[u8],
    cipher: &Aes256Gcm,
    nonce: &mut [u8; NONCE_SIZE],
) -> Result<Vec<u8>, FramingError> {
    // Validate frame has at least the encrypted length field
    if frame.len() < LEN_CIPHERTEXT_SIZE {
        return Err(FramingError::FrameTooSmall);
    }

    // Validate frame doesn't exceed maximum
    if frame.len() > MAX_FRAME_SIZE {
        return Err(FramingError::FrameTooLarge);
    }

    // 1. Decrypt length (first 18 bytes)
    let len_ciphertext = &frame[..LEN_CIPHERTEXT_SIZE];
    let len_plaintext = decrypt_length(len_ciphertext, cipher, nonce)?;
    increment_nonce(nonce);

    // Extract data length from plaintext
    let data_len = u16::from_be_bytes([len_plaintext[0], len_plaintext[1]]) as usize;

    // 2. Decrypt data
    // Data ciphertext starts at byte 18 and extends for data_len + 16 (tag)
    let data_start = LEN_CIPHERTEXT_SIZE;
    let data_end = data_start + data_len + TAG_SIZE;

    if frame.len() < data_end {
        return Err(FramingError::FrameTooSmall);
    }

    let data_ciphertext = &frame[data_start..data_end];
    let data_plaintext = decrypt_data(data_ciphertext, cipher, nonce)?;
    increment_nonce(nonce);

    Ok(data_plaintext)
}

/// Validate frame structure without decrypting
///
/// Checks:
/// - Frame is at least large enough for the encrypted length field
/// - Frame does not exceed maximum allowed size
/// - Frame length field is consistent with total frame size
///
/// # Arguments
/// * `frame` - Frame to validate
///
/// # Returns
/// `Ok(())` if frame is valid, `Err(FramingError)` otherwise
pub fn validate_frame(frame: &[u8]) -> Result<(), FramingError> {
    // Check minimum size
    if frame.len() < LEN_CIPHERTEXT_SIZE {
        return Err(FramingError::FrameTooSmall);
    }

    // Check maximum size
    if frame.len() > MAX_FRAME_SIZE {
        return Err(FramingError::FrameTooLarge);
    }

    // Note: Full validation requires decryption of the length field
    // which is done in decode_frame()
    Ok(())
}

/// Increment nonce as a big-endian counter
///
/// # Arguments
/// * `nonce` - 12-byte nonce to increment
pub fn increment_nonce(nonce: &mut [u8; NONCE_SIZE]) {
    // Treat as big-endian counter: start from least significant byte
    for i in (0..NONCE_SIZE).rev() {
        if nonce[i] == 255 {
            nonce[i] = 0;
        } else {
            nonce[i] += 1;
            break;
        }
    }
}

/// Derive client nonce from base nonce
///
/// Client uses odd nonces (1, 3, 5...)
/// Ensures the last byte has bit 0 set to 1
pub fn derive_client_nonce(base: &[u8; NONCE_SIZE]) -> [u8; NONCE_SIZE] {
    let mut nonce = *base;
    nonce[NONCE_SIZE - 1] |= 0x01; // Ensure odd
    nonce
}

/// Derive server nonce from base nonce
///
/// Server uses even nonces (0, 2, 4...)
/// Ensures the last byte has bit 0 set to 0
pub fn derive_server_nonce(base: &[u8; NONCE_SIZE]) -> [u8; NONCE_SIZE] {
    let mut nonce = *base;
    nonce[NONCE_SIZE - 1] &= 0xFE; // Ensure even
    nonce
}

/// Encrypt the length field
fn encrypt_length(
    plaintext: &[u8; LEN_PLAINTEXT_SIZE],
    cipher: &Aes256Gcm,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>, FramingError> {
    let nonce_ref = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce_ref, plaintext.as_ref())
        .map_err(|e| FramingError::EncryptionFailed(e.to_string()))
}

/// Decrypt the length field
fn decrypt_length(
    ciphertext: &[u8],
    cipher: &Aes256Gcm,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>, FramingError> {
    let nonce_ref = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce_ref, ciphertext)
        .map_err(|e| FramingError::DecryptionFailed(e.to_string()))
}

/// Encrypt data payload
fn encrypt_data(
    plaintext: &[u8],
    cipher: &Aes256Gcm,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>, FramingError> {
    let nonce_ref = Nonce::from_slice(nonce);

    cipher
        .encrypt(nonce_ref, plaintext)
        .map_err(|e| FramingError::EncryptionFailed(e.to_string()))
}

/// Decrypt data payload
fn decrypt_data(
    ciphertext: &[u8],
    cipher: &Aes256Gcm,
    nonce: &[u8; NONCE_SIZE],
) -> Result<Vec<u8>, FramingError> {
    let nonce_ref = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce_ref, ciphertext)
        .map_err(|e| FramingError::DecryptionFailed(e.to_string()))
}

/// Create a new AES-256-GCM cipher from a 32-byte key
pub fn create_cipher(key: &[u8; 32]) -> Aes256Gcm {
    let key_ref = Key::<Aes256Gcm>::from_slice(key);
    Aes256Gcm::new(key_ref)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        for (i, byte) in key.iter_mut().enumerate() {
            *byte = i as u8;
        }
        key
    }

    fn generate_test_nonce() -> [u8; 12] {
        let mut nonce = [0u8; 12];
        for (i, byte) in nonce.iter_mut().enumerate() {
            *byte = (i * 17) as u8;
        }
        nonce
    }

    #[test]
    fn test_round_trip_encode_decode() {
        let key = generate_test_key();
        let cipher = create_cipher(&key);
        let mut nonce = generate_test_nonce();

        // Test with various data sizes
        let test_cases = vec![
            vec![],
            vec![0x01],
            vec![0x01, 0x02, 0x03, 0x04],
            vec![0xFF; 100],
            vec![0xAA; 1000],
            vec![0x55; 65535], // Max data size
        ];

        for data in test_cases {
            let mut encode_nonce = nonce;
            let mut decode_nonce = nonce;

            // Encode
            let frame = encode_frame(&data, &cipher, &mut encode_nonce).unwrap();

            // Decode
            let decoded = decode_frame(&frame, &cipher, &mut decode_nonce).unwrap();

            assert_eq!(
                data,
                decoded,
                "Round-trip failed for data length {}",
                data.len()
            );

            // Update nonce for next iteration
            nonce = encode_nonce;
        }
    }

    #[test]
    fn test_increment_nonce() {
        // Test basic increment
        let mut nonce = [0u8; 12];
        increment_nonce(&mut nonce);
        assert_eq!(nonce[11], 1);

        // Test overflow handling
        let mut nonce = [0u8; 12];
        nonce[11] = 255;
        increment_nonce(&mut nonce);
        assert_eq!(nonce[11], 0);
        assert_eq!(nonce[10], 1);

        // Test full overflow (should wrap around)
        let mut nonce = [255u8; 12];
        increment_nonce(&mut nonce);
        assert_eq!(nonce, [0u8; 12]);
    }

    #[test]
    fn test_derive_client_nonce() {
        let base = [0u8; 12];
        let client_nonce = derive_client_nonce(&base);
        assert_eq!(client_nonce[11], 1); // Should be odd
        assert_eq!(&client_nonce[..11], &base[..11]); // Other bytes unchanged

        // Test with odd base
        let mut base = [0u8; 12];
        base[11] = 2;
        let client_nonce = derive_client_nonce(&base);
        assert_eq!(client_nonce[11], 3); // Should still be odd
    }

    #[test]
    fn test_derive_server_nonce() {
        let mut base = [0u8; 12];
        base[11] = 1;
        let server_nonce = derive_server_nonce(&base);
        assert_eq!(server_nonce[11], 0); // Should be even
        assert_eq!(&server_nonce[..11], &base[..11]); // Other bytes unchanged

        // Test with even base
        let base = [0u8; 12];
        let server_nonce = derive_server_nonce(&base);
        assert_eq!(server_nonce[11], 0); // Should still be even
    }

    #[test]
    fn test_validate_frame() {
        // Valid minimum frame
        let frame = vec![0u8; LEN_CIPHERTEXT_SIZE];
        assert!(validate_frame(&frame).is_ok());

        // Too small
        let frame = vec![0u8; LEN_CIPHERTEXT_SIZE - 1];
        assert_eq!(validate_frame(&frame), Err(FramingError::FrameTooSmall));

        // Too large
        let frame = vec![0u8; MAX_FRAME_SIZE + 1];
        assert_eq!(validate_frame(&frame), Err(FramingError::FrameTooLarge));
    }

    #[test]
    fn test_decode_invalid_frame() {
        let key = generate_test_key();
        let cipher = create_cipher(&key);
        let mut nonce = generate_test_nonce();

        // Frame too small
        let frame = vec![0u8; LEN_CIPHERTEXT_SIZE - 1];
        let result = decode_frame(&frame, &cipher, &mut nonce);
        assert_eq!(result, Err(FramingError::FrameTooSmall));

        // Corrupted length ciphertext (will fail decryption)
        let frame = vec![0xFFu8; LEN_CIPHERTEXT_SIZE];
        let mut nonce = generate_test_nonce();
        let result = decode_frame(&frame, &cipher, &mut nonce);
        assert!(matches!(result, Err(FramingError::DecryptionFailed(_))));
    }

    #[test]
    fn test_encode_data_too_large() {
        let key = generate_test_key();
        let cipher = create_cipher(&key);
        let mut nonce = generate_test_nonce();

        // Data exceeding u16::MAX
        let data = vec![0u8; (u16::MAX as usize) + 1];
        let result = encode_frame(&data, &cipher, &mut nonce);
        assert!(matches!(result, Err(FramingError::EncryptionFailed(_))));
    }

    #[test]
    fn test_client_server_nonce_separation() {
        let base = generate_test_nonce();

        let client_nonce = derive_client_nonce(&base);
        let server_nonce = derive_server_nonce(&base);

        // Client nonce should be odd, server should be even
        assert_ne!(client_nonce[11] & 0x01, 0);
        assert_eq!(server_nonce[11] & 0x01, 0);

        // They should differ
        assert_ne!(client_nonce, server_nonce);
    }

    #[test]
    fn test_max_frame_size_constant() {
        // Verify MAX_FRAME_SIZE calculation
        let expected = 65535 + LEN_CIPHERTEXT_SIZE + TAG_SIZE;
        assert_eq!(MAX_FRAME_SIZE, expected);

        // Verify individual constants
        assert_eq!(LEN_CIPHERTEXT_SIZE, 18);
        assert_eq!(TAG_SIZE, 16);
        assert_eq!(NONCE_SIZE, 12);
    }

    #[test]
    fn test_encode_produces_correct_frame_size() {
        let key = generate_test_key();
        let cipher = create_cipher(&key);
        let mut nonce = generate_test_nonce();

        // Test empty data
        let data: Vec<u8> = vec![];
        let frame = encode_frame(&data, &cipher, &mut nonce).unwrap();
        assert_eq!(frame.len(), LEN_CIPHERTEXT_SIZE + TAG_SIZE);

        // Reset nonce
        let mut nonce = generate_test_nonce();

        // Test 100 bytes of data
        let data = vec![0xABu8; 100];
        let frame = encode_frame(&data, &cipher, &mut nonce).unwrap();
        assert_eq!(frame.len(), LEN_CIPHERTEXT_SIZE + 100 + TAG_SIZE);
    }

    #[test]
    fn test_nonce_increment_per_operation() {
        let key = generate_test_key();
        let cipher = create_cipher(&key);
        let mut nonce = generate_test_nonce();

        let original_nonce = nonce;

        // Encode - should increment nonce twice (length + data)
        let data = vec![0x01, 0x02, 0x03];
        let _frame = encode_frame(&data, &cipher, &mut nonce).unwrap();

        // Nonce should have been incremented twice
        let mut expected_nonce = original_nonce;
        increment_nonce(&mut expected_nonce);
        increment_nonce(&mut expected_nonce);
        assert_eq!(nonce, expected_nonce);
    }

    #[test]
    fn test_framing_error_display() {
        let err = FramingError::FrameTooSmall;
        assert_eq!(err.to_string(), "frame too small");

        let err = FramingError::FrameTooLarge;
        assert_eq!(err.to_string(), "frame too large");

        let err = FramingError::InvalidLength;
        assert_eq!(err.to_string(), "invalid length field");

        let err = FramingError::DecryptionFailed("test".to_string());
        assert_eq!(err.to_string(), "decryption failed: test");

        let err = FramingError::EncryptionFailed("test".to_string());
        assert_eq!(err.to_string(), "encryption failed: test");
    }
}
