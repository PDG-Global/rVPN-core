//! Traffic padding for traffic analysis resistance
//!
//! Implements packet padding to 1KB boundaries and constant-rate mode
//! to obfuscate traffic patterns and resist traffic analysis attacks.

use rand::{Rng, RngCore, SeedableRng};
use serde::{Deserialize, Serialize};

/// Padding mode for traffic shaping
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum PaddingMode {
    /// No padding
    #[default]
    None,
    /// Pad packets to 1KB boundaries
    Packet,
    /// Maintain constant rate with dummy packets
    ConstantRate,
}

/// Traffic shaper configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficShaper {
    /// Target rate in bytes per second (None = no constant rate)
    pub target_rate: Option<u64>,
    /// Padding mode
    pub padding_mode: PaddingMode,
}

impl TrafficShaper {
    /// Create a new traffic shaper with no padding
    pub fn none() -> Self {
        Self {
            target_rate: None,
            padding_mode: PaddingMode::None,
        }
    }

    /// Create a new traffic shaper with packet padding only
    pub fn packet_padding() -> Self {
        Self {
            target_rate: None,
            padding_mode: PaddingMode::Packet,
        }
    }

    /// Create a new traffic shaper with constant rate mode
    pub fn constant_rate(target_rate: u64) -> Self {
        Self {
            target_rate: Some(target_rate),
            padding_mode: PaddingMode::ConstantRate,
        }
    }

    /// Check if padding is enabled
    pub fn is_padding_enabled(&self) -> bool {
        self.padding_mode != PaddingMode::None
    }

    /// Get the target rate if in constant rate mode
    pub fn target_rate(&self) -> Option<u64> {
        if self.padding_mode == PaddingMode::ConstantRate {
            self.target_rate
        } else {
            None
        }
    }
}

impl Default for TrafficShaper {
    fn default() -> Self {
        Self::none()
    }
}

/// Minimum padding block size (1KB)
pub const PADDING_BLOCK_SIZE: usize = 1024;

/// Maximum padded packet size (16KB)
pub const MAX_PADDED_SIZE: usize = 16 * 1024;

/// Minimum dummy packet size
pub const MIN_DUMMY_SIZE: usize = 64;

/// Maximum dummy packet size
pub const MAX_DUMMY_SIZE: usize = 1024;

/// Pad data to the next 1KB boundary
///
/// The padding length is encoded in the last 2 bytes of the padding
/// so the receiver knows how much to strip.
///
/// # Arguments
/// * `data` - The data to pad
///
/// # Returns
/// Padded data with padding length encoded in the last 2 bytes
///
/// # Errors
/// Returns `PaddingError::DataTooLarge` if data exceeds the maximum padded size
pub fn pad_packet(data: &[u8]) -> Result<Vec<u8>, PaddingError> {
    if data.is_empty() {
        // Create a minimal padded packet with just the padding length
        let mut result = vec![0u8; PADDING_BLOCK_SIZE];
        // Encode padding length (full block minus 2 bytes for the length itself)
        let padding_len = (PADDING_BLOCK_SIZE - 2) as u16;
        result[PADDING_BLOCK_SIZE - 2..].copy_from_slice(&padding_len.to_be_bytes());
        return Ok(result);
    }

    let data_len = data.len();

    // Calculate target size (next 1KB boundary, max 16KB).
    // We must account for the 2-byte padding-length field that is appended
    // after the data, so data_len + 2 determines the block count.
    let blocks = (data_len + 2).div_ceil(PADDING_BLOCK_SIZE);
    let target_size = (blocks * PADDING_BLOCK_SIZE).min(MAX_PADDED_SIZE);

    // Calculate how much data we can actually fit
    // Reserve 2 bytes for padding length encoding
    let max_data_len = target_size.saturating_sub(2);

    if data_len > max_data_len {
        return Err(PaddingError::DataTooLarge { data_len, max_len: max_data_len });
    }

    // Calculate padding length
    let padding_len = max_data_len.saturating_sub(data_len);

    let mut result = Vec::with_capacity(target_size);

    // Copy original data
    result.extend_from_slice(data);

    // Add random padding
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        rand::rngs::StdRng::from_entropy().fill_bytes(&mut padding);
        result.extend_from_slice(&padding);
    }

    // Encode padding length in last 2 bytes
    result.extend_from_slice(&(padding_len as u16).to_be_bytes());

    Ok(result)
}

/// Remove padding from a packet
///
/// Reads the padding length from the last 2 bytes and strips that many
/// bytes from the end (plus the 2 bytes for the length encoding).
///
/// # Arguments
/// * `data` - The padded data
///
/// # Returns
/// The original data without padding
///
/// # Errors
/// Returns an error if the data is too short or padding length is invalid
pub fn unpad_packet(data: &[u8]) -> Result<Vec<u8>, PaddingError> {
    if data.len() < 2 {
        return Err(PaddingError::DataTooShort);
    }

    // Read padding length from last 2 bytes
    let padding_len = u16::from_be_bytes([data[data.len() - 2], data[data.len() - 1]]) as usize;

    // Validate padding length
    if padding_len > data.len() - 2 {
        return Err(PaddingError::InvalidPaddingLength);
    }

    // Return data without padding and length encoding
    Ok(data[..data.len() - 2 - padding_len].to_vec())
}

/// Generate a dummy padding packet
///
/// Creates a packet with random data that can be sent as padding.
/// The size is random between MIN_DUMMY_SIZE and MAX_DUMMY_SIZE.
///
/// # Returns
/// A dummy packet with padding length encoded
pub fn generate_dummy_packet() -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::from_entropy();

    // Random size between min and max
    let size = rng.gen_range(MIN_DUMMY_SIZE..=MAX_DUMMY_SIZE);

    // Generate random data
    let mut data = vec![0u8; size];
    rng.fill_bytes(&mut data);

    // Pad to 1KB boundary (always succeeds since size <= MAX_DUMMY_SIZE <= MAX_PADDED_SIZE)
    pad_packet(&data).expect("dummy packet size always within limits")
}

/// Calculate the padded size for a given data length
///
/// # Arguments
/// * `data_len` - Length of the original data
///
/// # Returns
/// The size after padding to 1KB boundary (capped at 16KB)
pub fn padded_size(data_len: usize) -> usize {
    if data_len == 0 {
        return PADDING_BLOCK_SIZE;
    }

    // Add 2 bytes for padding length encoding
    let total_len = data_len + 2;
    let blocks = total_len.div_ceil(PADDING_BLOCK_SIZE);
    (blocks * PADDING_BLOCK_SIZE).min(MAX_PADDED_SIZE)
}

/// Errors that can occur during padding operations
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PaddingError {
    /// Data is too short to contain padding length
    #[error("data too short to contain padding")]
    DataTooShort,
    /// Invalid padding length
    #[error("invalid padding length")]
    InvalidPaddingLength,
    /// Data too large for padding
    #[error("data too large for padding: {data_len} bytes exceeds max {max_len}")]
    DataTooLarge {
        /// Length of the data that was too large
        data_len: usize,
        /// Maximum allowed data length
        max_len: usize,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_empty_data() {
        let padded = pad_packet(&[]).unwrap();
        assert_eq!(padded.len(), PADDING_BLOCK_SIZE);

        // Verify we can unpad
        let unpadded = unpad_packet(&padded).unwrap();
        assert!(unpadded.is_empty());
    }

    #[test]
    fn test_pad_small_data() {
        let data = vec![1, 2, 3, 4, 5];
        let padded = pad_packet(&data).unwrap();

        // Should pad to 1KB
        assert_eq!(padded.len(), PADDING_BLOCK_SIZE);

        // Verify we can unpad and get original data
        let unpadded = unpad_packet(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pad_exact_boundary() {
        // Data that fits exactly in 1KB minus 2 bytes for length
        let data = vec![0u8; PADDING_BLOCK_SIZE - 2];
        let padded = pad_packet(&data).unwrap();

        // Should still be 1KB (just the length encoding added)
        assert_eq!(padded.len(), PADDING_BLOCK_SIZE);

        let unpadded = unpad_packet(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pad_cross_boundary() {
        // Data that crosses 1KB boundary
        let data = vec![0u8; PADDING_BLOCK_SIZE + 100];
        let padded = pad_packet(&data).unwrap();

        // Should pad to 2KB
        assert_eq!(padded.len(), 2 * PADDING_BLOCK_SIZE);

        let unpadded = unpad_packet(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pad_max_size() {
        // Data at max size
        let data = vec![0u8; MAX_PADDED_SIZE - 2];
        let padded = pad_packet(&data).unwrap();

        // Should be capped at 16KB
        assert_eq!(padded.len(), MAX_PADDED_SIZE);

        let unpadded = unpad_packet(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_pad_exceeds_max() {
        // Data that exceeds max padded size
        let data = vec![0u8; MAX_PADDED_SIZE + 1000];
        let result = pad_packet(&data);

        // Should return an error instead of silently truncating
        assert!(matches!(result, Err(PaddingError::DataTooLarge { .. })));
    }

    #[test]
    fn test_unpad_too_short() {
        let result = unpad_packet(&[1]);
        assert_eq!(result, Err(PaddingError::DataTooShort));
    }

    #[test]
    fn test_unpad_invalid_length() {
        // Create data with invalid padding length
        let mut data = vec![0u8; 10];
        data.extend_from_slice(&0xFFFFu16.to_be_bytes()); // Invalid large length

        let result = unpad_packet(&data);
        assert_eq!(result, Err(PaddingError::InvalidPaddingLength));
    }

    #[test]
    fn test_generate_dummy_packet() {
        let dummy = generate_dummy_packet();

        // Should be padded to at least 1KB
        assert!(dummy.len() >= PADDING_BLOCK_SIZE);
        assert!(dummy.len() <= MAX_PADDED_SIZE);

        // Should be unpadable
        let unpadded = unpad_packet(&dummy).unwrap();
        // Original dummy data should be between MIN_DUMMY_SIZE and MAX_DUMMY_SIZE
        assert!(unpadded.len() >= MIN_DUMMY_SIZE);
        assert!(unpadded.len() <= MAX_DUMMY_SIZE);
    }

    #[test]
    fn test_padded_size() {
        assert_eq!(padded_size(0), PADDING_BLOCK_SIZE);
        assert_eq!(padded_size(100), PADDING_BLOCK_SIZE);
        assert_eq!(padded_size(PADDING_BLOCK_SIZE - 2), PADDING_BLOCK_SIZE);
        assert_eq!(padded_size(PADDING_BLOCK_SIZE), 2 * PADDING_BLOCK_SIZE);
        assert_eq!(padded_size(MAX_PADDED_SIZE - 2), MAX_PADDED_SIZE);
        assert_eq!(padded_size(MAX_PADDED_SIZE), MAX_PADDED_SIZE);
    }

    #[test]
    fn test_traffic_shaper() {
        let shaper = TrafficShaper::none();
        assert!(!shaper.is_padding_enabled());
        assert_eq!(shaper.target_rate(), None);

        let shaper = TrafficShaper::packet_padding();
        assert!(shaper.is_padding_enabled());
        assert_eq!(shaper.target_rate(), None);

        let shaper = TrafficShaper::constant_rate(1024);
        assert!(shaper.is_padding_enabled());
        assert_eq!(shaper.target_rate(), Some(1024));
    }
}
