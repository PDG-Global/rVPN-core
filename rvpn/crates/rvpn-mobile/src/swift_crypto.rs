// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Pure crypto FFI for the Swift tunnel implementation.
// No networking, no async, no Tokio. Synchronous, caller-owned state.

#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, CStr};
use std::ptr;

use ed25519_dalek::Verifier;
use rvpn_core::crypto::{DoubleRatchet, IdentityKey, X3DHPublicBundle};
use rvpn_core::protocol::padding::{pad_packet, unpad_packet};

// --- Handle types ---

/// Opaque handle to a DoubleRatchet instance.
/// Swift passes this pointer back to Rust for encrypt/decrypt.
pub struct RatchetHandle {
    pub ratchet: DoubleRatchet,
}

/// Opaque handle to an IdentityKey.
pub struct IdentityHandle {
    pub key: IdentityKey,
}

// --- Double Ratchet ---

/// Encrypt plaintext using the ratchet state.
///
/// # Arguments
/// * `handle` - Opaque ratchet handle
/// * `plaintext` - Data to encrypt
/// * `plaintext_len` - Length of plaintext
/// * `payload_type` - PayloadType byte (used as AAD, e.g. 0x01 for Data)
/// * `out_buf` - Caller-allocated output buffer for serialized RatchetMessage
/// * `out_buf_len` - Size of output buffer (recommend 16384+)
/// * `out_len` - Actual bytes written to out_buf
///
/// # Returns
/// 0 on success, -1 on error. Call `rvpn_last_error()` for details.
#[no_mangle]
pub unsafe extern "C" fn rvpn_ratchet_encrypt(
    handle: *mut RatchetHandle,
    plaintext: *const u8,
    plaintext_len: usize,
    payload_type: u8,
    out_buf: *mut u8,
    out_buf_len: usize,
    out_len: *mut usize,
) -> c_int {
    if handle.is_null() || plaintext.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let handle = &mut *handle;
    let data = std::slice::from_raw_parts(plaintext, plaintext_len);

    let mut ciphertext = Vec::new();
    let (nonce, header) = match handle.ratchet.encrypt_to(data, &[payload_type], &mut ciphertext) {
        Ok(v) => v,
        Err(e) => {
            super::ios_tun_ffi::set_last_error(&format!("encrypt: {}", e));
            return -1;
        }
    };

    let msg = rvpn_core::crypto::RatchetMessage {
        header,
        nonce,
        ciphertext,
    };
    let serialized = match msg.to_bytes() {
        Ok(v) => v,
        Err(e) => {
            super::ios_tun_ffi::set_last_error(&format!("serialize: {}", e));
            return -1;
        }
    };

    if serialized.len() > out_buf_len {
        super::ios_tun_ffi::set_last_error(&format!(
            "output buffer too small: need {} bytes, have {}",
            serialized.len(),
            out_buf_len
        ));
        return -1;
    }

    let out = std::slice::from_raw_parts_mut(out_buf, serialized.len());
    out.copy_from_slice(&serialized);
    *out_len = serialized.len();
    0
}

/// Decrypt a serialized RatchetMessage.
///
/// # Arguments
/// * `handle` - Opaque ratchet handle
/// * `data` - Serialized RatchetMessage bytes (from bincode)
/// * `data_len` - Length of data
/// * `out_buf` - Caller-allocated output buffer for plaintext
/// * `out_buf_len` - Size of output buffer
/// * `out_len` - Actual plaintext bytes written
/// * `out_payload_type` - PayloadType byte from the message header
///
/// # Returns
/// 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn rvpn_ratchet_decrypt(
    handle: *mut RatchetHandle,
    data: *const u8,
    data_len: usize,
    out_buf: *mut u8,
    out_buf_len: usize,
    out_len: *mut usize,
    out_payload_type: *mut u8,
) -> c_int {
    if handle.is_null() || data.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let handle = &mut *handle;
    let bytes = std::slice::from_raw_parts(data, data_len);

    let msg = match rvpn_core::crypto::RatchetMessage::from_bytes(bytes) {
        Ok(v) => v,
        Err(e) => {
            super::ios_tun_ffi::set_last_error(&format!("deserialize: {}", e));
            return -1;
        }
    };

    let payload_type = msg.header.payload_type;
    let mut plaintext = Vec::new();
    let pt_len = match handle.ratchet.decrypt_to(&msg, &[payload_type], &mut plaintext) {
        Ok(v) => v,
        Err(e) => {
            super::ios_tun_ffi::set_last_error(&format!("decrypt: {}", e));
            return -1;
        }
    };

    if pt_len > out_buf_len {
        super::ios_tun_ffi::set_last_error(&format!(
            "output buffer too small: need {} bytes, have {}",
            pt_len, out_buf_len
        ));
        return -1;
    }

    let out = std::slice::from_raw_parts_mut(out_buf, pt_len);
    out.copy_from_slice(&plaintext[..pt_len]);
    *out_len = pt_len;
    if !out_payload_type.is_null() {
        *out_payload_type = payload_type;
    }
    0
}

/// Create a DoubleRatchet as Alice (initiator) from a 32-byte shared secret.
///
/// # Returns
/// Opaque ratchet handle, or null on error.
#[no_mangle]
pub unsafe extern "C" fn rvpn_ratchet_init_alice(
    shared_secret: *const u8,
) -> *mut RatchetHandle {
    if shared_secret.is_null() {
        return ptr::null_mut();
    }
    let secret = std::slice::from_raw_parts(shared_secret, 32);
    let mut ss = [0u8; 32];
    ss.copy_from_slice(secret);
    let ratchet = DoubleRatchet::init_alice(ss, [0u8; 32]);
    Box::into_raw(Box::new(RatchetHandle { ratchet }))
}

/// Free a ratchet handle.
#[no_mangle]
pub unsafe extern "C" fn rvpn_ratchet_free(handle: *mut RatchetHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

// --- Identity Keys ---

/// Load an identity key from a file path.
///
/// # Returns
/// Opaque identity handle, or null on error.
#[no_mangle]
pub unsafe extern "C" fn rvpn_identity_load(
    path: *const c_char,
) -> *mut IdentityHandle {
    if path.is_null() {
        return ptr::null_mut();
    }
    let path = match CStr::from_ptr(path).to_str() {
        Ok(s) => s,
        Err(_) => return ptr::null_mut(),
    };
    let key = match IdentityKey::load(&std::path::PathBuf::from(path)) {
        Ok(k) => k,
        Err(_) => return ptr::null_mut(),
    };
    Box::into_raw(Box::new(IdentityHandle { key }))
}

/// Get the X25519 public key bytes (32 bytes) from an identity key.
/// Copies into `out` which must be at least 32 bytes.
///
/// # Returns
/// 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn rvpn_identity_x25519_pubkey(
    handle: *const IdentityHandle,
    out: *mut u8,
) -> c_int {
    if handle.is_null() || out.is_null() {
        return -1;
    }
    let handle = &*handle;
    let pubkey = handle.key.x25519_public_key();
    let out = std::slice::from_raw_parts_mut(out, 32);
    out.copy_from_slice(&pubkey);
    0
}

/// Get the Ed25519 verifying key bytes (32 bytes) from an identity key.
///
/// # Returns
/// 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn rvpn_identity_ed25519_pubkey(
    handle: *const IdentityHandle,
    out: *mut u8,
) -> c_int {
    if handle.is_null() || out.is_null() {
        return -1;
    }
    let handle = &*handle;
    let pubkey = handle.key.verifying_key.to_bytes();
    let out = std::slice::from_raw_parts_mut(out, 32);
    out.copy_from_slice(&pubkey);
    0
}

/// Verify an Ed25519 signature.
///
/// # Arguments
/// * `pubkey` - 32-byte Ed25519 verifying key
/// * `data` - Data that was signed
/// * `data_len` - Length of data
/// * `signature` - 64-byte Ed25519 signature
///
/// # Returns
/// 1 if valid, 0 if invalid, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn rvpn_ed25519_verify(
    pubkey: *const u8,
    data: *const u8,
    data_len: usize,
    signature: *const u8,
) -> c_int {
    if pubkey.is_null() || data.is_null() || signature.is_null() {
        return -1;
    }
    let pk_bytes: [u8; 32] = match std::slice::from_raw_parts(pubkey, 32).try_into() {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let sig_bytes: [u8; 64] = match std::slice::from_raw_parts(signature, 64).try_into() {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let msg = std::slice::from_raw_parts(data, data_len);

    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    match verifying_key.verify(msg, &sig) {
        Ok(()) => 1,
        Err(_) => 0,
    }
}

/// Free an identity handle.
#[no_mangle]
pub unsafe extern "C" fn rvpn_identity_free(handle: *mut IdentityHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}

// --- Padding ---

/// Pad data to 1KB boundary. Caller-allocated output buffer.
///
/// # Returns
/// 0 on success, -1 on error. `out_len` set to actual padded size.
#[no_mangle]
pub unsafe extern "C" fn rvpn_pad(
    data: *const u8,
    data_len: usize,
    out_buf: *mut u8,
    out_buf_len: usize,
    out_len: *mut usize,
) -> c_int {
    if data.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let input = std::slice::from_raw_parts(data, data_len);
    let padded = match pad_packet(input) {
        Ok(v) => v,
        Err(e) => {
            super::ios_tun_ffi::set_last_error(&format!("pad: {}", e));
            return -1;
        }
    };
    if padded.len() > out_buf_len {
        super::ios_tun_ffi::set_last_error(&format!(
            "pad output buffer too small: need {} bytes, have {}",
            padded.len(),
            out_buf_len
        ));
        return -1;
    }
    let out = std::slice::from_raw_parts_mut(out_buf, padded.len());
    out.copy_from_slice(&padded);
    *out_len = padded.len();
    0
}

/// Unpad data. Returns the unpadded length.
/// The unpadded data is written to `out_buf` (caller-allocated).
///
/// # Returns
/// 0 on success, -1 on error. `out_len` set to unpadded size.
#[no_mangle]
pub unsafe extern "C" fn rvpn_unpad(
    data: *const u8,
    data_len: usize,
    out_buf: *mut u8,
    out_buf_len: usize,
    out_len: *mut usize,
) -> c_int {
    if data.is_null() || out_buf.is_null() || out_len.is_null() {
        return -1;
    }
    let input = std::slice::from_raw_parts(data, data_len);
    let unpadded = match unpad_packet(input) {
        Ok(v) => v,
        Err(e) => {
            super::ios_tun_ffi::set_last_error(&format!("unpad: {}", e));
            return -1;
        }
    };
    if unpadded.len() > out_buf_len {
        super::ios_tun_ffi::set_last_error(&format!(
            "unpad output buffer too small: need {} bytes, have {}",
            unpadded.len(),
            out_buf_len
        ));
        return -1;
    }
    let out = std::slice::from_raw_parts_mut(out_buf, unpadded.len());
    out.copy_from_slice(&unpadded);
    *out_len = unpadded.len();
    0
}

// --- X3DH Helpers ---

/// Compute X3DH key agreement (initiator side).
///
/// Verifies the server's Ed25519 signature on the signed prekey, then
/// performs the 4-way DH to derive the shared secret.
///
/// # Arguments
/// * `identity` - Identity handle (client's key)
/// * `server_identity_key` - Server's Ed25519 verifying key (32 bytes)
/// * `server_identity_x25519` - Server's X25519 identity key (32 bytes, from prekey bundle JSON)
/// * `server_signed_prekey` - Server's signed prekey (32 bytes, from ServerHello)
/// * `server_prekey_signature` - Server's prekey signature (64 bytes, from ServerHello)
/// * `ephemeral_pubkey_out` - Output: 32-byte ephemeral public key (for Hello message)
/// * `shared_secret_out` - Output: 32-byte shared secret
///
/// # Returns
/// 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn rvpn_x3dh_agree(
    identity: *const IdentityHandle,
    server_identity_key: *const u8,
    server_identity_x25519: *const u8,
    server_signed_prekey: *const u8,
    server_prekey_signature: *const u8,
    ephemeral_pubkey_out: *mut u8,
    shared_secret_out: *mut u8,
) -> c_int {
    if identity.is_null()
        || server_identity_key.is_null()
        || server_identity_x25519.is_null()
        || server_signed_prekey.is_null()
        || server_prekey_signature.is_null()
        || ephemeral_pubkey_out.is_null()
        || shared_secret_out.is_null()
    {
        return -1;
    }

    let identity = &*identity;

    let sid_key: [u8; 32] =
        match std::slice::from_raw_parts(server_identity_key, 32).try_into() {
            Ok(v) => v,
            Err(_) => return -1,
        };
    let sid_x25519: [u8; 32] =
        match std::slice::from_raw_parts(server_identity_x25519, 32).try_into() {
            Ok(v) => v,
            Err(_) => return -1,
        };
    let spk: [u8; 32] =
        match std::slice::from_raw_parts(server_signed_prekey, 32).try_into() {
            Ok(v) => v,
            Err(_) => return -1,
        };
    let sig: [u8; 64] =
        match std::slice::from_raw_parts(server_prekey_signature, 64).try_into() {
            Ok(v) => v,
            Err(_) => return -1,
        };

    // Verify Ed25519 signature on signed prekey
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&sid_key) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig);
    if verifying_key.verify(&spk, &signature).is_err() {
        super::ios_tun_ffi::set_last_error("prekey signature verification failed");
        return -1;
    }

    // Build server bundle from verified keys
    let server_bundle = X3DHPublicBundle {
        identity_key: sid_key,
        identity_x25519_key: sid_x25519,
        signed_prekey: spk,
        prekey_signature: sig,
        one_time_prekey: None,
        // Swift crypto path doesn't handle rotation directly — pin
        // enforcement lives in IosTunClient::new. Neutral defaults keep
        // the bundle valid for X3DH agreement without asserting a version.
        identity_key_version: 1,
        rotation_signature: None,
    };

    // Create X3DH initiator
    let initiator = rvpn_core::crypto::x3dh::X3DHInitiator::from_identity_key(
        std::sync::Arc::new(identity.key.clone()),
    );

    // Copy ephemeral public key to output
    let epk = initiator.ephemeral_key.public_key.to_bytes();
    let epk_out = std::slice::from_raw_parts_mut(ephemeral_pubkey_out, 32);
    epk_out.copy_from_slice(&epk);

    // Perform X3DH agreement
    let (shared_secret, _material) = match initiator.agree(&server_bundle) {
        Ok(v) => v,
        Err(e) => {
            super::ios_tun_ffi::set_last_error(&format!("x3dh agree: {}", e));
            return -1;
        }
    };

    let ss_out = std::slice::from_raw_parts_mut(shared_secret_out, 32);
    ss_out.copy_from_slice(&shared_secret);
    0
}

// --- Ephemeral Key Split API ---
// For the Swift handshake, we need to generate the ephemeral key BEFORE
// sending Hello (so we can include the pubkey), then use it for X3DH
// AFTER receiving ServerHello.

/// Opaque handle to an ephemeral X25519 private key.
pub struct EphemeralKeyHandle {
    pub private_key: [u8; 32],
    pub public_key: [u8; 32],
}

/// Generate a new X25519 ephemeral keypair.
///
/// # Arguments
/// * `pubkey_out` - Output: 32-byte public key (for Hello message)
///
/// # Returns
/// Opaque ephemeral key handle, or null on error. Caller must free with rvpn_ephemeral_key_free.
#[no_mangle]
pub unsafe extern "C" fn rvpn_generate_ephemeral_key(
    pubkey_out: *mut u8,
) -> *mut EphemeralKeyHandle {
    if pubkey_out.is_null() {
        return ptr::null_mut();
    }
    let ephemeral = rvpn_core::crypto::EphemeralKey::generate();
    let private_key = ephemeral.private_key.to_bytes();
    let public_key = ephemeral.public_key.to_bytes();

    let out = std::slice::from_raw_parts_mut(pubkey_out, 32);
    out.copy_from_slice(&public_key);

    Box::into_raw(Box::new(EphemeralKeyHandle {
        private_key,
        public_key,
    }))
}

/// Perform X3DH key agreement with a pre-generated ephemeral key.
///
/// Same as rvpn_x3dh_agree but uses the provided ephemeral key instead of generating a new one.
///
/// # Arguments
/// * `identity` - Identity handle (client's key)
/// * `ephemeral` - Ephemeral key handle (from rvpn_generate_ephemeral_key)
/// * `server_identity_key` - Server's Ed25519 verifying key (32 bytes)
/// * `server_identity_x25519` - Server's X25519 identity key (32 bytes, from prekey bundle)
/// * `server_signed_prekey` - Server's signed prekey (32 bytes, from ServerHello)
/// * `server_prekey_signature` - Server's prekey signature (64 bytes, from ServerHello)
/// * `shared_secret_out` - Output: 32-byte shared secret
///
/// # Returns
/// 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn rvpn_x3dh_agree_with_ephemeral(
    identity: *const IdentityHandle,
    ephemeral: *const EphemeralKeyHandle,
    server_identity_key: *const u8,
    server_identity_x25519: *const u8,
    server_signed_prekey: *const u8,
    server_prekey_signature: *const u8,
    shared_secret_out: *mut u8,
) -> c_int {
    if identity.is_null()
        || ephemeral.is_null()
        || server_identity_key.is_null()
        || server_identity_x25519.is_null()
        || server_signed_prekey.is_null()
        || server_prekey_signature.is_null()
        || shared_secret_out.is_null()
    {
        return -1;
    }

    let identity = &*identity;
    let ephemeral = &*ephemeral;

    let sid_key: [u8; 32] =
        match std::slice::from_raw_parts(server_identity_key, 32).try_into() {
            Ok(v) => v,
            Err(_) => return -1,
        };
    let sid_x25519: [u8; 32] =
        match std::slice::from_raw_parts(server_identity_x25519, 32).try_into() {
            Ok(v) => v,
            Err(_) => return -1,
        };
    let spk: [u8; 32] =
        match std::slice::from_raw_parts(server_signed_prekey, 32).try_into() {
            Ok(v) => v,
            Err(_) => return -1,
        };
    let sig: [u8; 64] =
        match std::slice::from_raw_parts(server_prekey_signature, 64).try_into() {
            Ok(v) => v,
            Err(_) => return -1,
        };

    // Verify Ed25519 signature on signed prekey
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&sid_key) {
        Ok(v) => v,
        Err(_) => return -1,
    };
    let signature = ed25519_dalek::Signature::from_bytes(&sig);
    if verifying_key.verify(&spk, &signature).is_err() {
        super::ios_tun_ffi::set_last_error("prekey signature verification failed");
        return -1;
    }

    // Build server bundle
    let server_bundle = X3DHPublicBundle {
        identity_key: sid_key,
        identity_x25519_key: sid_x25519,
        signed_prekey: spk,
        prekey_signature: sig,
        one_time_prekey: None,
        // Swift crypto path doesn't handle rotation directly — pin
        // enforcement lives in IosTunClient::new. Neutral defaults keep
        // the bundle valid for X3DH agreement without asserting a version.
        identity_key_version: 1,
        rotation_signature: None,
    };

    // Create X3DH initiator with the pre-generated ephemeral key
    let private_key = x25519_dalek::StaticSecret::from(ephemeral.private_key);
    let public_key = x25519_dalek::PublicKey::from(&private_key);
    let ephemeral_key = rvpn_core::crypto::EphemeralKey {
        private_key,
        public_key,
    };
    let initiator = rvpn_core::crypto::x3dh::X3DHInitiator {
        identity_key: identity.key.clone(),
        ephemeral_key,
    };

    // Perform X3DH agreement
    let (shared_secret, _material) = match initiator.agree(&server_bundle) {
        Ok(v) => v,
        Err(e) => {
            super::ios_tun_ffi::set_last_error(&format!("x3dh agree: {}", e));
            return -1;
        }
    };

    let ss_out = std::slice::from_raw_parts_mut(shared_secret_out, 32);
    ss_out.copy_from_slice(&shared_secret);
    0
}

/// Free an ephemeral key handle.
#[no_mangle]
pub unsafe extern "C" fn rvpn_ephemeral_key_free(handle: *mut EphemeralKeyHandle) {
    if !handle.is_null() {
        drop(Box::from_raw(handle));
    }
}
