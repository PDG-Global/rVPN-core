// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Frame padding to eliminate fixed-size WebSocket frame fingerprinting.
//!
//! Format: [real_len: u16 BE][real_data][random padding 0..=MAX_PAD bytes]
//! Padding is applied before encryption and stripped after decryption.

use rand::{Rng, SeedableRng};

/// Maximum padding bytes appended after the real data.
/// 64 bytes is sufficient to eliminate uniform frame-size fingerprinting
/// while adding negligible bandwidth overhead (<1% on typical 8KB frames).
pub const MAX_PAD: usize = 64;

/// Pad a frame: prepend 2-byte real length, append random padding.
pub fn pad_frame(data: &[u8]) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::from_entropy();
    let pad_len = rng.gen_range(0..=MAX_PAD);
    let mut out = Vec::with_capacity(2 + data.len() + pad_len);
    let real_len = data.len() as u16;
    out.extend_from_slice(&real_len.to_be_bytes());
    out.extend_from_slice(data);
    for _ in 0..pad_len {
        out.push(rng.gen());
    }
    out
}

/// Strip padding from a frame using its length prefix.
pub fn unpad_frame(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if data.len() < 2 {
        return Err(anyhow::anyhow!("Frame too short for length prefix: {} bytes", data.len()));
    }
    let real_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + real_len {
        return Err(anyhow::anyhow!(
            "Frame truncated: real_len={}, available={}",
            real_len,
            data.len() - 2
        ));
    }
    Ok(data[2..2 + real_len].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let data = b"hello world this is test data";
        let padded = pad_frame(data);
        assert!(padded.len() >= 2 + data.len());
        let unpadded = unpad_frame(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_empty() {
        let data = b"";
        let padded = pad_frame(data);
        let unpadded = unpad_frame(&padded).unwrap();
        assert_eq!(unpadded, data as &[u8]);
    }

    #[test]
    fn test_too_short() {
        assert!(unpad_frame(&[0x00]).is_err());
        assert!(unpad_frame(&[]).is_err());
    }
}
