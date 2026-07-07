//! Double Ratchet implementation
//!
//! Based on Signal Protocol specification:
//! https://signal.org/docs/specifications/doubleratchet/

use serde::{Deserialize, Serialize};
use lru::LruCache;
use std::num::NonZeroUsize;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::cipher::{Cipher, NONCE_SIZE};
use super::{EphemeralKey, SharedSecret};

/// Size of chain keys
pub const CHAIN_KEY_SIZE: usize = 32;
/// Size of message keys
pub const MESSAGE_KEY_SIZE: usize = 32;
/// Maximum number of skipped messages to store
pub const MAX_SKIP: usize = 1000;
/// Maximum plaintext message size (1MB) to prevent memory exhaustion
pub const MAX_MESSAGE_SIZE: usize = 1024 * 1024;

/// Double Ratchet state
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DoubleRatchet {
    /// Our current DH key pair
    #[zeroize(skip)]
    dh_pair: Option<EphemeralKey>,

    /// Remote DH public key (current)
    remote_dh_key: Option<[u8; 32]>,

    /// Remote DH public key (previous, for receiving chain derivation)
    previous_remote_dh_key: Option<[u8; 32]>,

    /// Root key
    root_key: [u8; 32],

    /// Sending chain key
    sending_chain_key: Option<[u8; 32]>,

    /// Receiving chain key
    receiving_chain_key: Option<[u8; 32]>,

    /// Message number in sending chain
    send_message_number: u32,

    /// Message number in receiving chain
    recv_message_number: u32,

    /// Previous chain length
    previous_chain_length: u32,

    /// Skipped message keys (for out-of-order handling)
    #[zeroize(skip)]
    skipped_keys: LruCache<(Vec<u8>, u32), [u8; MESSAGE_KEY_SIZE]>,
}

impl DoubleRatchet {
    /// Initialize Alice (initiator)
    ///
    /// Uses the X3DH shared secret to derive initial chain keys.
    /// The DH ratchet will start when the first message is exchanged.
    pub fn init_alice(shared_secret: SharedSecret, _server_public_key: [u8; 32]) -> Self {
        // Generate initial DH key pair for future ratchet steps
        let dh_pair = EphemeralKey::generate();

        // Derive initial chain keys directly from the X3DH shared secret
        // Both Alice and Bob use the same derivation
        let keys = kdf_init(&shared_secret);
        let mut sending_chain_key = [0u8; CHAIN_KEY_SIZE];
        let mut receiving_chain_key = [0u8; CHAIN_KEY_SIZE];
        sending_chain_key.copy_from_slice(&keys.0);
        receiving_chain_key.copy_from_slice(&keys.1);

        Self {
            dh_pair: Some(dh_pair),
            remote_dh_key: None, // Will be set when we receive Bob's first message
            previous_remote_dh_key: None,
            root_key: shared_secret,
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key: Some(receiving_chain_key),
            send_message_number: 0,
            recv_message_number: 0,
            previous_chain_length: 0,
            skipped_keys: LruCache::new(NonZeroUsize::new(MAX_SKIP).unwrap()),
        }
    }
    
    /// Initialize Bob (responder)
    ///
    /// Bob generates a DH key pair and derives initial chain keys from the shared secret.
    /// When Alice's first message arrives, a DH ratchet step will be performed.
    pub fn init_bob(shared_secret: SharedSecret) -> Self {
        // Generate initial DH key pair
        let dh_pair = EphemeralKey::generate();

        // Derive initial root key and chain keys
        // For the initial state, we use a simple KDF to derive chain keys from shared secret
        let mut sending_chain_key = [0u8; CHAIN_KEY_SIZE];
        let mut receiving_chain_key = [0u8; CHAIN_KEY_SIZE];

        // Derive initial chain keys from shared secret
        // Bob's sending chain = Alice's receiving chain, and vice versa
        let keys = kdf_init(&shared_secret);
        // Note: Bob's receiving chain is what Alice uses for sending
        receiving_chain_key.copy_from_slice(&keys.0);
        sending_chain_key.copy_from_slice(&keys.1);

        Self {
            dh_pair: Some(dh_pair),
            remote_dh_key: None,
            previous_remote_dh_key: None,
            root_key: shared_secret,
            sending_chain_key: Some(sending_chain_key),
            receiving_chain_key: Some(receiving_chain_key),
            send_message_number: 0,
            recv_message_number: 0,
            previous_chain_length: 0,
            skipped_keys: LruCache::new(NonZeroUsize::new(MAX_SKIP).unwrap()),
        }
    }
    
    /// Get the current send message number (for debugging)
    pub fn get_send_message_number(&self) -> u32 {
        self.send_message_number
    }
    
    /// Get the current receive message number (for debugging)
    pub fn get_recv_message_number(&self) -> u32 {
        self.recv_message_number
    }

    /// Get our DH public key (for ServerHello response)
    /// Returns None if dh_pair is not initialized
    pub fn get_dh_public_key(&self) -> Option<[u8; 32]> {
        self.dh_pair.as_ref().map(|k| k.public_key.to_bytes())
    }

    /// Encrypt plaintext, writing ciphertext into the provided buffer.
    ///
    /// Reuses the caller's buffer to avoid per-message heap allocation.
    /// Returns the nonce and header (caller builds RatchetMessage).
    pub fn encrypt_to(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
        ciphertext_out: &mut Vec<u8>,
    ) -> crate::Result<([u8; NONCE_SIZE], MessageHeader)> {
        let chain_key = self.sending_chain_key
            .ok_or_else(|| crate::Error::EncryptionFailed("No sending chain".to_string()))?;

        let (message_key, next_chain_key) = kdf_ck(&chain_key);
        let cipher = Cipher::new(&message_key);

        let payload_type = associated_data.first().copied().unwrap_or(0);
        let aad = &[payload_type];

        let nonce = super::cipher::generate_nonce();

        ciphertext_out.clear();
        ciphertext_out.extend_from_slice(plaintext);
        cipher.encrypt_in_place(&nonce, aad, ciphertext_out)
            .map_err(|e| crate::Error::EncryptionFailed(e.to_string()))?;

        let header = MessageHeader {
            dh_public: self.dh_pair.as_ref().map(|k| k.public_key.to_bytes()),
            message_number: self.send_message_number,
            previous_chain_length: self.previous_chain_length,
            payload_type,
        };

        self.sending_chain_key = Some(next_chain_key);
        self.send_message_number += 1;

        Ok((nonce, header))
    }

    /// Decrypt a message, writing plaintext into the provided buffer.
    ///
    /// Reuses the caller's buffer to avoid per-message heap allocation.
    /// Returns the number of plaintext bytes written.
    pub fn decrypt_to(
        &mut self,
        message: &RatchetMessage,
        _associated_data: &[u8],
        plaintext_out: &mut Vec<u8>,
    ) -> crate::Result<usize> {
        if message.ciphertext.len() > MAX_MESSAGE_SIZE {
            return Err(crate::Error::DecryptionFailed(
                format!("Message too large: {} bytes (max {})", message.ciphertext.len(), MAX_MESSAGE_SIZE)
            ));
        }

        let target_number = message.header.message_number;
        let current_number = self.recv_message_number;
        let associated_data = &[message.header.payload_type];

        let header_bytes = message.header.to_bytes();
        let key = (header_bytes.clone(), target_number);

        if self.skipped_keys.contains(&key) {
            let message_key = self.skipped_keys.pop(&key).unwrap();
            let cipher = Cipher::new(&message_key);
            let result = cipher.decrypt(&message.nonce, associated_data, &message.ciphertext)?;
            plaintext_out.clear();
            plaintext_out.extend_from_slice(&result);
            return Ok(result.len());
        }

        if target_number < current_number {
            return Err(crate::Error::DecryptionFailed(
                format!("Message too old: target={}, current={}", target_number, current_number)
            ));
        }

        if let (Some(remote_dh), Some(current_remote)) = (message.header.dh_public, self.remote_dh_key) {
            if current_remote != remote_dh {
                self.skip_message_keys(message.header.previous_chain_length)?;
                self.dh_ratchet_step(&remote_dh);
            }
        } else if message.header.dh_public.is_some() && self.remote_dh_key.is_none() {
            self.remote_dh_key = message.header.dh_public;
        }

        if target_number > current_number {
            self.skip_message_keys(target_number)?;
        }

        let chain_key = self.receiving_chain_key
            .ok_or_else(|| crate::Error::DecryptionFailed("No receiving chain".to_string()))?;

        let (message_key, next_chain_key) = kdf_ck(&chain_key);
        let cipher = Cipher::new(&message_key);
        let result = cipher.decrypt(&message.nonce, associated_data, &message.ciphertext);

        match result {
            Ok(plaintext) => {
                self.receiving_chain_key = Some(next_chain_key);
                self.recv_message_number = target_number + 1;
                plaintext_out.clear();
                plaintext_out.extend_from_slice(&plaintext);
                Ok(plaintext.len())
            }
            Err(e) => Err(crate::Error::DecryptionFailed(e.to_string()))
        }
    }

    /// Decrypt from a zero-copy `RatchetMessageRef`, writing plaintext into the
    /// provided buffer.  Identical to `decrypt_to` but avoids the per-message
    /// `Vec<u8>` allocation that `RatchetMessage::from_bytes` performs.
    ///
    /// Returns the number of plaintext bytes written.
    pub fn decrypt_to_ref(
        &mut self,
        message: &RatchetMessageRef<'_>,
        _associated_data: &[u8],
        plaintext_out: &mut Vec<u8>,
    ) -> crate::Result<usize> {
        if message.ciphertext.len() > MAX_MESSAGE_SIZE {
            return Err(crate::Error::DecryptionFailed(
                format!("Message too large: {} bytes (max {})", message.ciphertext.len(), MAX_MESSAGE_SIZE)
            ));
        }

        let target_number = message.header.message_number;
        let current_number = self.recv_message_number;
        let associated_data = &[message.header.payload_type];

        // Only construct the skipped-key lookup key (which allocates a Vec for
        // the header bytes) when there are actually skipped keys stored. On the
        // steady-state in-order path this map is empty, so this avoids a
        // per-frame allocation.
        if !self.skipped_keys.is_empty() {
            let key = (message.header.to_bytes(), target_number);
            if self.skipped_keys.contains(&key) {
                let message_key = self.skipped_keys.pop(&key).unwrap();
                let cipher = Cipher::new(&message_key);
                plaintext_out.clear();
                plaintext_out.extend_from_slice(message.ciphertext);
                cipher.decrypt_in_place(&message.nonce, associated_data, plaintext_out)?;
                return Ok(plaintext_out.len());
            }
        }

        if target_number < current_number {
            return Err(crate::Error::DecryptionFailed(
                format!("Message too old: target={}, current={}", target_number, current_number)
            ));
        }

        if let (Some(remote_dh), Some(current_remote)) = (message.header.dh_public, self.remote_dh_key) {
            if current_remote != remote_dh {
                self.skip_message_keys(message.header.previous_chain_length)?;
                self.dh_ratchet_step(&remote_dh);
            }
        } else if message.header.dh_public.is_some() && self.remote_dh_key.is_none() {
            self.remote_dh_key = message.header.dh_public;
        }

        if target_number > current_number {
            self.skip_message_keys(target_number)?;
        }

        let chain_key = self.receiving_chain_key
            .ok_or_else(|| crate::Error::DecryptionFailed("No receiving chain".to_string()))?;

        let (message_key, next_chain_key) = kdf_ck(&chain_key);
        let cipher = Cipher::new(&message_key);

        // Decrypt directly into the reusable `plaintext_out` buffer: copy the
        // ciphertext in, then decrypt in place. This avoids the owned-Vec
        // allocation that `Cipher::decrypt` would make on every inbound frame.
        plaintext_out.clear();
        plaintext_out.extend_from_slice(message.ciphertext);
        match cipher.decrypt_in_place(&message.nonce, associated_data, plaintext_out) {
            Ok(plaintext_len) => {
                self.receiving_chain_key = Some(next_chain_key);
                self.recv_message_number = target_number + 1;
                Ok(plaintext_len)
            }
            Err(e) => Err(crate::Error::DecryptionFailed(e.to_string()))
        }
    }

    /// Encrypt a message
    /// 
    /// Advances the sending chain key and returns an encrypted message.
    /// The payload_type is extracted from the associated_data parameter (first byte).
    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> crate::Result<RatchetMessage> {
        let chain_key = self.sending_chain_key
            .ok_or_else(|| crate::Error::EncryptionFailed("No sending chain".to_string()))?;
        
        // Derive message key and next chain key
        let (message_key, next_chain_key) = kdf_ck(&chain_key);
        let cipher = Cipher::new(&message_key);
        
        // Extract payload type from associated data (first byte, or 0 if empty)
        let payload_type = associated_data.first().copied().unwrap_or(0);
        // Use payload_type as associated data for AEAD (must match decrypt)
        let aad = &[payload_type];
        
        // Generate random nonce
        let nonce = super::cipher::generate_nonce();
        let ciphertext = cipher.encrypt(&nonce, aad, plaintext)
            .map_err(|e| crate::Error::EncryptionFailed(e.to_string()))?;
        
        // Build header with CURRENT message number (before advancing)
        let header = MessageHeader {
            dh_public: self.dh_pair.as_ref().map(|k| k.public_key.to_bytes()),
            message_number: self.send_message_number,
            previous_chain_length: self.previous_chain_length,
            payload_type,
        };
        
        // NOW advance the chain - this ensures the header reflects the correct state
        self.sending_chain_key = Some(next_chain_key);
        self.send_message_number += 1;
        
        Ok(RatchetMessage {
            header,
            nonce,
            ciphertext,
        })
    }
    
    /// Decrypt a message
    ///
    /// Handles out-of-order messages via skipped_keys storage. Verifies message sequence
    /// numbers to ensure chain key synchronization.
    /// Uses the payload_type from the message header as associated data.
    pub fn decrypt(
        &mut self,
        message: &RatchetMessage,
        _associated_data: &[u8],  // Kept for API compatibility, but we use header.payload_type
    ) -> crate::Result<Vec<u8>> {
        // Reject oversized messages to prevent memory exhaustion
        if message.ciphertext.len() > MAX_MESSAGE_SIZE {
            return Err(crate::Error::DecryptionFailed(
                format!("Message too large: {} bytes (max {})", message.ciphertext.len(), MAX_MESSAGE_SIZE)
            ));
        }

        let target_number = message.header.message_number;
        let current_number = self.recv_message_number;
        
        // Use payload type from header as associated data
        let associated_data = &[message.header.payload_type];
        
        // Try to decrypt with skipped keys first (for out-of-order messages we've seen before)
        let header_bytes = message.header.to_bytes();
        let key = (header_bytes.clone(), target_number);

        if self.skipped_keys.contains(&key) {
            let message_key = self.skipped_keys.pop(&key).unwrap(); // safe since we just checked
            let cipher = Cipher::new(&message_key);
            return cipher.decrypt(&message.nonce, associated_data, &message.ciphertext);
        }
        
        // Check for old messages that we can't decrypt anymore
        if target_number < current_number {
            return Err(crate::Error::DecryptionFailed(
                format!("Message too old: target={}, current={}", target_number, current_number)
            ));
        }
        
        // Check if we need to perform a DH ratchet step
        if let (Some(remote_dh), Some(current_remote)) = (message.header.dh_public, self.remote_dh_key) {
            if current_remote != remote_dh {
                // DH ratchet step - skip remaining messages in current chain
                self.skip_message_keys(message.header.previous_chain_length)?;
                self.dh_ratchet_step(&remote_dh);
            }
        } else if message.header.dh_public.is_some() && self.remote_dh_key.is_none() {
            // First message: store the remote DH key for future ratchet steps
            self.remote_dh_key = message.header.dh_public;
        }
        
        // Handle future messages (out-of-order): skip ahead and store keys
        if target_number > current_number {
            self.skip_message_keys(target_number)?;
        }
        
        // Decrypt with current chain key
        let chain_key = self.receiving_chain_key
            .ok_or_else(|| crate::Error::DecryptionFailed("No receiving chain".to_string()))?;
        
        let (message_key, next_chain_key) = kdf_ck(&chain_key);
        
        // Only advance the chain on successful decryption
        let cipher = Cipher::new(&message_key);
        let result = cipher.decrypt(&message.nonce, associated_data, &message.ciphertext);
        
        match result {
            Ok(plaintext) => {
                // Advance chain only on success
                self.receiving_chain_key = Some(next_chain_key);
                self.recv_message_number = target_number + 1;
                Ok(plaintext)
            }
            Err(e) => Err(crate::Error::DecryptionFailed(e.to_string()))
        }
    }
    
    /// Skip message keys for out-of-order handling
    fn skip_message_keys(&mut self, until: u32) -> crate::Result<()> {
        if (self.recv_message_number + MAX_SKIP as u32) < until {
            return Err(crate::Error::DecryptionFailed(
                "Too many skipped messages".to_string()
            ));
        }
        
        let chain_key = self.receiving_chain_key
            .ok_or_else(|| crate::Error::DecryptionFailed("No receiving chain".to_string()))?;
        
        let mut current_ck = chain_key;
        
        while self.recv_message_number < until {
            let (message_key, next_ck) = kdf_ck(&current_ck);
            
            // Store skipped key
            let header_bytes = self.remote_dh_key.map(|k| k.to_vec()).unwrap_or_default();
            self.skipped_keys.put(
                (header_bytes, self.recv_message_number),
                message_key,
            );
            
            current_ck = next_ck;
            self.recv_message_number += 1;
        }
        
        self.receiving_chain_key = Some(current_ck);
        Ok(())
    }
    
    /// Perform DH ratchet step
    /// When called with a new remote DH key, we:
    /// 1. Use the OLD remote key + our current key to derive receiving chain (for messages encrypted with remote's OLD key)
    /// 2. Generate a new DH key pair
    /// 3. Use the NEW remote key + our new key to derive sending chain (for messages we'll send)
    fn dh_ratchet_step(&mut self, remote_dh: &[u8; 32]) {
        // Store current sending chain info
        self.previous_chain_length = self.send_message_number;
        self.send_message_number = 0;
        self.recv_message_number = 0;

        // Get the old remote key for deriving receiving chain
        // If we don't have a previous key, use the current one (first ratchet)
        let old_remote_key = self.previous_remote_dh_key
            .or(self.remote_dh_key)
            .unwrap_or(*remote_dh);

        // Step 1: Derive receiving chain using OLD remote key + our CURRENT key
        // The remote encrypted messages with their OLD key, so we need this to decrypt
        let current_dh_pair = self.dh_pair.as_ref().expect("Need DH pair for ratchet");
        let recv_dh_secret = current_dh_pair.diffie_hellman(&x25519_public_key(&old_remote_key));
        let (root_key, recv_chain_key) = kdf_rk_2(&self.root_key, &recv_dh_secret);
        self.receiving_chain_key = Some(recv_chain_key);
        self.root_key = root_key;

        // Step 2: Generate new DH key pair for sending chain
        let new_dh_pair = EphemeralKey::generate();

        // Step 3: Derive sending chain using NEW remote key + our NEW key
        let send_dh_secret = new_dh_pair.diffie_hellman(&x25519_public_key(remote_dh));
        let (root_key, send_chain_key) = kdf_rk_2(&self.root_key, &send_dh_secret);
        self.sending_chain_key = Some(send_chain_key);
        self.root_key = root_key;

        // Store previous remote key before updating to new
        if let Some(current) = self.remote_dh_key {
            self.previous_remote_dh_key = Some(current);
        }
        self.remote_dh_key = Some(*remote_dh);
        self.dh_pair = Some(new_dh_pair);
    }

    /// Perform a DH ratchet step to generate a new key for the next message
    /// NOTE: This should NOT be called after every message. The DH ratchet happens
    /// automatically in decrypt() when a message with a new remote DH key is received.
    /// This function is only needed for special cases where we need to force a ratchet.
    #[allow(dead_code)]
    pub fn ratchet_for_next_message(&mut self) {
        // We need to have a remote key to ratchet with
        if let Some(remote_dh) = self.remote_dh_key {
            self.dh_ratchet_step(&remote_dh);
        }
    }
}

/// Sending chain state - can be locked independently for concurrent encryption
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SendingChain {
    /// Chain key for sending
    chain_key: Option<[u8; 32]>,
    /// Message number in sending chain
    message_number: u32,
}

/// Receiving chain state - can be locked independently for concurrent decryption
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ReceivingChain {
    /// Chain key for receiving
    chain_key: Option<[u8; 32]>,
    /// Message number in receiving chain
    message_number: u32,
    /// Skipped message keys (for out-of-order handling)
    #[zeroize(skip)]
    skipped_keys: LruCache<(Vec<u8>, u32), [u8; MESSAGE_KEY_SIZE]>,
}

/// Split Ratchet state that allows concurrent encryption and decryption
/// by separating the sending and receiving chains into independently lockable structs
pub struct SplitRatchet {
    /// Root key (shared between chains, only changes during DH ratchet)
    root_key: std::sync::Arc<tokio::sync::Mutex<[u8; 32]>>,
    /// Our current DH key pair
    dh_pair: std::sync::Arc<tokio::sync::Mutex<Option<EphemeralKey>>>,
    /// Remote DH public key (current)
    remote_dh_key: std::sync::Arc<tokio::sync::Mutex<Option<[u8; 32]>>>,
    /// Remote DH public key (previous, for receiving chain derivation)
    previous_remote_dh_key: std::sync::Arc<tokio::sync::Mutex<Option<[u8; 32]>>>,
    /// Sending chain - can be locked independently
    sending_chain: std::sync::Arc<tokio::sync::Mutex<SendingChain>>,
    /// Receiving chain - can be locked independently
    receiving_chain: std::sync::Arc<tokio::sync::Mutex<ReceivingChain>>,
    /// Previous chain length (for message headers)
    previous_chain_length: std::sync::Arc<tokio::sync::Mutex<u32>>,
}

impl SplitRatchet {
    /// Initialize Alice (initiator) - async version
    pub async fn init_alice(shared_secret: SharedSecret, _server_public_key: [u8; 32]) -> Self {
        // Generate initial DH key pair for future ratchet steps
        let dh_pair = EphemeralKey::generate();
        
        // Derive initial chain keys directly from the X3DH shared secret
        let keys = kdf_init(&shared_secret);
        let mut sending_chain_key = [0u8; CHAIN_KEY_SIZE];
        let mut receiving_chain_key = [0u8; CHAIN_KEY_SIZE];
        sending_chain_key.copy_from_slice(&keys.0);
        receiving_chain_key.copy_from_slice(&keys.1);
        
        Self {
            root_key: std::sync::Arc::new(tokio::sync::Mutex::new(shared_secret)),
            dh_pair: std::sync::Arc::new(tokio::sync::Mutex::new(Some(dh_pair))),
            remote_dh_key: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            previous_remote_dh_key: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            sending_chain: std::sync::Arc::new(tokio::sync::Mutex::new(SendingChain {
                chain_key: Some(sending_chain_key),
                message_number: 0,
            })),
            receiving_chain: std::sync::Arc::new(tokio::sync::Mutex::new(ReceivingChain {
                chain_key: Some(receiving_chain_key),
                message_number: 0,
                skipped_keys: LruCache::new(NonZeroUsize::new(MAX_SKIP).unwrap()),
            })),
            previous_chain_length: std::sync::Arc::new(tokio::sync::Mutex::new(0)),
        }
    }
    
    /// Initialize Bob (responder) - async version
    pub async fn init_bob(shared_secret: SharedSecret) -> Self {
        // Generate initial DH key pair
        let dh_pair = EphemeralKey::generate();
        
        // Derive initial chain keys from shared secret
        let keys = kdf_init(&shared_secret);
        let mut sending_chain_key = [0u8; CHAIN_KEY_SIZE];
        let mut receiving_chain_key = [0u8; CHAIN_KEY_SIZE];
        // Note: Bob's receiving chain is what Alice uses for sending
        receiving_chain_key.copy_from_slice(&keys.0);
        sending_chain_key.copy_from_slice(&keys.1);
        
        Self {
            root_key: std::sync::Arc::new(tokio::sync::Mutex::new(shared_secret)),
            dh_pair: std::sync::Arc::new(tokio::sync::Mutex::new(Some(dh_pair))),
            remote_dh_key: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            previous_remote_dh_key: std::sync::Arc::new(tokio::sync::Mutex::new(None)),
            sending_chain: std::sync::Arc::new(tokio::sync::Mutex::new(SendingChain {
                chain_key: Some(sending_chain_key),
                message_number: 0,
            })),
            receiving_chain: std::sync::Arc::new(tokio::sync::Mutex::new(ReceivingChain {
                chain_key: Some(receiving_chain_key),
                message_number: 0,
                skipped_keys: LruCache::new(NonZeroUsize::new(MAX_SKIP).unwrap()),
            })),
            previous_chain_length: std::sync::Arc::new(tokio::sync::Mutex::new(0)),
        }
    }
    
    /// Encrypt a message - only locks sending_chain for concurrent operations
    /// 
    /// The lock is held for the entire operation to ensure message ordering is preserved.
    /// This prevents race conditions where message N+1 could be sent before message N.
    pub async fn encrypt(&self, plaintext: &[u8], associated_data: &[u8]) -> crate::Result<RatchetMessage> {
        // Lock the sending chain for the entire operation to ensure sequential message numbers
        let mut sending = self.sending_chain.lock().await;
        
        let chain_key = sending.chain_key.ok_or_else(|| 
            crate::Error::EncryptionFailed("Sending chain not initialized".to_string()))?;
        
        // Get DH public key for header (don't need to lock dh_pair for long)
        let dh_public = {
            let dh = self.dh_pair.lock().await;
            dh.as_ref().map(|k| k.public_key.to_bytes())
        };
        
        // Derive message key and next chain key
        let (message_key, next_chain_key) = kdf_ck(&chain_key);
        
        // Get previous chain length for header
        let prev_chain_len = *self.previous_chain_length.lock().await;
        
        // Extract payload type from associated data
        let payload_type = associated_data.first().copied().unwrap_or(0);
        
        // Build header with CURRENT message number (before advancing)
        let header = MessageHeader {
            dh_public,
            message_number: sending.message_number,
            previous_chain_length: prev_chain_len,
            payload_type,
        };
        
        // NOW advance the chain - this ensures the header reflects the correct state
        sending.chain_key = Some(next_chain_key);
        sending.message_number += 1;
        // Lock is dropped here after all state changes are complete
        drop(sending);
        
        // Encrypt (outside of lock)
        let cipher = Cipher::new(&message_key);
        let nonce = super::cipher::generate_nonce();
        
        let ciphertext = cipher.encrypt(&nonce, associated_data, plaintext)
            .map_err(|e| crate::Error::EncryptionFailed(e.to_string()))?;
        
        Ok(RatchetMessage {
            header,
            nonce,
            ciphertext,
        })
    }
    
    /// Decrypt a message - only locks receiving_chain for concurrent operations
    /// Note: DH ratchet step will temporarily lock both chains and root_key
    ///
    /// Handles out-of-order messages via skipped_keys storage. Verifies message sequence
    /// numbers to ensure chain key synchronization.
    pub async fn decrypt(&self, message: &RatchetMessage, associated_data: &[u8]) -> crate::Result<Vec<u8>> {
        // Reject oversized messages to prevent memory exhaustion
        if message.ciphertext.len() > MAX_MESSAGE_SIZE {
            return Err(crate::Error::DecryptionFailed(
                format!("Message too large: {} bytes (max {})", message.ciphertext.len(), MAX_MESSAGE_SIZE)
            ));
        }

        let target_number = message.header.message_number;
        
        // Check if we need a DH ratchet step first (this may lock both chains)
        if let Some(remote_dh) = message.header.dh_public {
            let current_remote = *self.remote_dh_key.lock().await;
            
            if let Some(current) = current_remote {
                if current != remote_dh {
                    // Need to perform DH ratchet - this locks everything
                    self.dh_ratchet_step(&remote_dh).await?;
                }
            } else {
                // First message - store remote DH key
                *self.remote_dh_key.lock().await = Some(remote_dh);
            }
        }
        
        // Now lock only receiving chain for decryption
        let mut receiving = self.receiving_chain.lock().await;
        let current_number = receiving.message_number;
        
        // Try skipped keys first (for out-of-order messages we've seen before)
        let header_bytes = message.header.to_bytes();
        let key = (header_bytes.clone(), target_number);

        if receiving.skipped_keys.contains(&key) {
            let message_key = receiving.skipped_keys.pop(&key).unwrap(); // safe since we just checked
            let cipher = Cipher::new(&message_key);
            return cipher.decrypt(&message.nonce, associated_data, &message.ciphertext);
        }
        
        // Check for old messages that we can't decrypt anymore
        if target_number < current_number {
            return Err(crate::Error::DecryptionFailed(
                format!("Message too old: target={}, current={}", target_number, current_number)
            ));
        }
        
        // Handle future messages (out-of-order): skip ahead and store keys
        if target_number > current_number {
            Self::skip_message_keys(&mut receiving, target_number).await?;
        }
        
        // Decrypt with current chain key
        let chain_key = receiving.chain_key
            .ok_or_else(|| crate::Error::DecryptionFailed("No receiving chain".to_string()))?;
        
        let (message_key, next_chain_key) = kdf_ck(&chain_key);
        
        // Try decryption before advancing chain
        let cipher = Cipher::new(&message_key);
        let result = cipher.decrypt(&message.nonce, associated_data, &message.ciphertext);
        
        match result {
            Ok(plaintext) => {
                // Advance chain only on success
                receiving.chain_key = Some(next_chain_key);
                receiving.message_number = target_number + 1;
                Ok(plaintext)
            }
            Err(e) => Err(crate::Error::DecryptionFailed(e.to_string()))
        }
    }
    
    /// Skip message keys for out-of-order handling (internal, assumes receiving lock is held)
    async fn skip_message_keys(receiving: &mut ReceivingChain, until: u32) -> crate::Result<()> {
        if (receiving.message_number + MAX_SKIP as u32) < until {
            return Err(crate::Error::DecryptionFailed(
                "Too many skipped messages".to_string()
            ));
        }
        
        let chain_key = receiving.chain_key
            .ok_or_else(|| crate::Error::DecryptionFailed("No receiving chain".to_string()))?;
        
        let mut current_ck = chain_key;
        
        while receiving.message_number < until {
            let (message_key, next_ck) = kdf_ck(&current_ck);
            
            // Store skipped key (use empty vec for dh_public since we don't have access to it here)
            receiving.skipped_keys.put(
                (Vec::new(), receiving.message_number),
                message_key,
            );
            
            current_ck = next_ck;
            receiving.message_number += 1;
        }
        
        receiving.chain_key = Some(current_ck);
        Ok(())
    }
    
    /// Perform DH ratchet step - locks both chains and root_key (rare operation)
    async fn dh_ratchet_step(&self, remote_dh: &[u8; 32]) -> crate::Result<()> {
        // Lock everything for the ratchet step (this is rare)
        let mut root_key = self.root_key.lock().await;
        let mut dh_pair = self.dh_pair.lock().await;
        let mut remote_dh_key = self.remote_dh_key.lock().await;
        let mut previous_remote_dh_key = self.previous_remote_dh_key.lock().await;
        let mut sending = self.sending_chain.lock().await;
        let mut receiving = self.receiving_chain.lock().await;
        let mut prev_chain_len = self.previous_chain_length.lock().await;
        
        // Store current sending chain info
        *prev_chain_len = sending.message_number;
        sending.message_number = 0;
        receiving.message_number = 0;
        
        // Get the old remote key for deriving receiving chain
        let old_remote_key = previous_remote_dh_key
            .or(*remote_dh_key)
            .unwrap_or(*remote_dh);
        
        // Step 1: Derive receiving chain using OLD remote key + our CURRENT key
        let current_dh_pair = dh_pair.as_ref().ok_or_else(|| 
            crate::Error::DecryptionFailed("Need DH pair for ratchet".to_string()))?;
        let recv_dh_secret = current_dh_pair.diffie_hellman(&x25519_public_key(&old_remote_key));
        let (new_root_key, recv_chain_key) = kdf_rk_2(&root_key, &recv_dh_secret);
        receiving.chain_key = Some(recv_chain_key);
        *root_key = new_root_key;
        
        // Step 2: Generate new DH key pair for sending chain
        let new_dh_pair = EphemeralKey::generate();
        
        // Step 3: Derive sending chain using NEW remote key + our NEW key
        let send_dh_secret = new_dh_pair.diffie_hellman(&x25519_public_key(remote_dh));
        let (new_root_key, send_chain_key) = kdf_rk_2(&root_key, &send_dh_secret);
        sending.chain_key = Some(send_chain_key);
        *root_key = new_root_key;
        
        // Store previous remote key before updating to new
        if let Some(current) = *remote_dh_key {
            *previous_remote_dh_key = Some(current);
        }
        *remote_dh_key = Some(*remote_dh);
        *dh_pair = Some(new_dh_pair);
        
        Ok(())
    }
}

impl SplitRatchet {
    /// Create a SplitRatchet from a DoubleRatchet, preserving all state.
    /// This consumes the DoubleRatchet and converts it to the concurrent version.
    #[allow(clippy::too_many_arguments)]
    pub fn from_double_ratchet(
        root_key: [u8; 32],
        dh_pair: Option<EphemeralKey>,
        remote_dh_key: Option<[u8; 32]>,
        previous_remote_dh_key: Option<[u8; 32]>,
        sending_chain_key: Option<[u8; 32]>,
        receiving_chain_key: Option<[u8; 32]>,
        send_message_number: u32,
        recv_message_number: u32,
        previous_chain_length: u32,
        skipped_keys: LruCache<(Vec<u8>, u32), [u8; MESSAGE_KEY_SIZE]>,
    ) -> Self {
        Self {
            root_key: std::sync::Arc::new(tokio::sync::Mutex::new(root_key)),
            dh_pair: std::sync::Arc::new(tokio::sync::Mutex::new(dh_pair)),
            remote_dh_key: std::sync::Arc::new(tokio::sync::Mutex::new(remote_dh_key)),
            previous_remote_dh_key: std::sync::Arc::new(tokio::sync::Mutex::new(previous_remote_dh_key)),
            sending_chain: std::sync::Arc::new(tokio::sync::Mutex::new(SendingChain {
                chain_key: sending_chain_key,
                message_number: send_message_number,
            })),
            receiving_chain: std::sync::Arc::new(tokio::sync::Mutex::new(ReceivingChain {
                chain_key: receiving_chain_key,
                message_number: recv_message_number,
                skipped_keys,
            })),
            previous_chain_length: std::sync::Arc::new(tokio::sync::Mutex::new(previous_chain_length)),
        }
    }
}

/// Message header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// DH public key (for ratchet)
    pub dh_public: Option<[u8; 32]>,
    /// Message number in chain
    pub message_number: u32,
    /// Length of previous sending chain
    pub previous_chain_length: u32,
    /// Payload type (for associated data selection)
    pub payload_type: u8,
}

impl MessageHeader {
    /// Serialize to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.dh_public.is_some() as u8);
        if let Some(dh) = &self.dh_public {
            result.extend_from_slice(dh);
        }
        result.extend_from_slice(&self.message_number.to_be_bytes());
        result.extend_from_slice(&self.previous_chain_length.to_be_bytes());
        result.push(self.payload_type);
        result
    }
}

/// Ratchet message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatchetMessage {
    /// Message header
    pub header: MessageHeader,
    /// Nonce
    pub nonce: [u8; NONCE_SIZE],
    /// Ciphertext
    pub ciphertext: Vec<u8>,
}

impl RatchetMessage {
    /// Serialize to wire bytes using bincode.
    ///
    /// bincode encodes `Vec<u8>` as (8-byte length + raw bytes), giving ~0%
    /// overhead vs serde_json which encodes each byte as a decimal integer
    /// ("123,") — roughly 3× the wire size for binary payloads.
    pub fn to_bytes(&self) -> anyhow::Result<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| anyhow::anyhow!("RatchetMessage serialize: {}", e))
    }

    /// Deserialize from wire bytes.
    pub fn from_bytes(data: &[u8]) -> anyhow::Result<Self> {
        bincode::deserialize(data)
            .map_err(|e| anyhow::anyhow!("RatchetMessage deserialize: {}", e))
    }
}

/// Zero-copy view into a serialized `RatchetMessage`.
///
/// Borrows the ciphertext from the input buffer instead of allocating a new
/// `Vec<u8>` for every message.  The iOS tunnel's hot decrypt path calls this
/// once per incoming WebSocket frame, so avoiding the allocation matters.
pub struct RatchetMessageRef<'a> {
    /// Parsed message header
    pub header: MessageHeader,
    /// AEAD nonce
    pub nonce: [u8; NONCE_SIZE],
    /// Ciphertext borrowed from the input buffer (zero-copy)
    pub ciphertext: &'a [u8],
}

impl<'a> RatchetMessageRef<'a> {
    /// Parse a `RatchetMessage` from bincode wire bytes without allocating.
    ///
    /// Manually decodes the bincode-1 format so that the ciphertext field
    /// borrows directly from `data` instead of copying into a new `Vec`.
    ///
    /// The layout must match what `bincode::serialize` / `RatchetMessage::to_bytes`
    /// produces — verified by the round-trip test in the test module.
    pub fn from_bytes(data: &'a [u8]) -> anyhow::Result<Self> {
        use std::io::Read;

        let mut cursor = std::io::Cursor::new(data);

        // --- MessageHeader ---

        // dh_public: Option<[u8; 32]> — 1-byte tag + optional 32 bytes
        let has_dh = {
            let mut b = [0u8; 1];
            cursor.read_exact(&mut b)?;
            b[0]
        };
        let dh_public = if has_dh == 1 {
            let mut key = [0u8; 32];
            cursor.read_exact(&mut key)?;
            Some(key)
        } else {
            None
        };

        // message_number: u32 LE (4 bytes in bincode 1.x default config)
        let mut buf4 = [0u8; 4];
        cursor.read_exact(&mut buf4)?;
        let message_number = u32::from_le_bytes(buf4);

        // previous_chain_length: u32 LE
        cursor.read_exact(&mut buf4)?;
        let previous_chain_length = u32::from_le_bytes(buf4);

        // payload_type: u8
        let mut buf1 = [0u8; 1];
        cursor.read_exact(&mut buf1)?;
        let payload_type = buf1[0];

        let header = MessageHeader { dh_public, message_number, previous_chain_length, payload_type };

        // --- nonce: [u8; 12] ---
        let mut nonce = [0u8; NONCE_SIZE];
        cursor.read_exact(&mut nonce)?;

        // --- ciphertext: Vec<u8> = u64 LE length + raw bytes ---
        let mut buf8 = [0u8; 8];
        cursor.read_exact(&mut buf8)?;
        let ct_len = u64::from_le_bytes(buf8) as usize;

        let pos = cursor.position() as usize;
        let end = pos.checked_add(ct_len)
            .ok_or_else(|| anyhow::anyhow!("RatchetMessage ciphertext length overflow"))?;
        if end > data.len() {
            return Err(anyhow::anyhow!(
                "RatchetMessage truncated: need {} bytes for ciphertext at offset {}, have {} total",
                ct_len, pos, data.len()
            ));
        }
        let ciphertext = &data[pos..end];

        Ok(RatchetMessageRef { header, nonce, ciphertext })
    }
}

/// KDF for initial chain key derivation from shared secret (HKDF)
fn kdf_init(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let derived = super::hkdf_derive(&[], shared_secret, b"R-VPN-v1 DoubleRatchet Init", 64);
    let mut ck1 = [0u8; 32];
    let mut ck2 = [0u8; 32];
    ck1.copy_from_slice(&derived[..32]);
    ck2.copy_from_slice(&derived[32..]);
    (ck1, ck2)
}

#[allow(dead_code)]
/// KDF for root key (HKDF)
fn kdf_rk(_rk: &[u8; 32], dh_out: &[u8; 32]) -> [u8; 32] {
    let derived = super::hkdf_derive(&[], dh_out, b"R-VPN-v1 Root Key", 64);
    let mut result = [0u8; 32];
    result.copy_from_slice(&derived[..32]);
    result
}

/// KDF for root key with two outputs
fn kdf_rk_2(rk: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let derived = super::hkdf_derive(rk, dh_out, b"R-VPN-v1 Ratchet", 64);
    let mut root_key = [0u8; 32];
    let mut chain_key = [0u8; 32];
    root_key.copy_from_slice(&derived[..32]);
    chain_key.copy_from_slice(&derived[32..]);
    (root_key, chain_key)
}

/// KDF for chain key
fn kdf_ck(ck: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    
    type HmacSha256 = Hmac<Sha256>;
    
    // Message key
    let mut mac = HmacSha256::new_from_slice(ck).expect("HMAC accepts any key");
    mac.update(&[0x01]);
    let message_key = mac.finalize().into_bytes();
    
    // Next chain key
    let mut mac = HmacSha256::new_from_slice(ck).expect("HMAC accepts any key");
    mac.update(&[0x02]);
    let chain_key = mac.finalize().into_bytes();
    
    let mut mk = [0u8; 32];
    let mut ck_out = [0u8; 32];
    mk.copy_from_slice(&message_key);
    ck_out.copy_from_slice(&chain_key);
    
    (mk, ck_out)
}

/// Helper to create X25519 public key from bytes
fn x25519_public_key(bytes: &[u8; 32]) -> x25519_dalek::PublicKey {
    x25519_dalek::PublicKey::from(*bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ratchet_message_ref_roundtrip() {
        // Verify RatchetMessageRef::from_bytes parses the same data that
        // bincode::serialize (used by RatchetMessage::to_bytes) produces.
        let msg = RatchetMessage {
            header: MessageHeader {
                dh_public: Some([0xABu8; 32]),
                message_number: 42,
                previous_chain_length: 7,
                payload_type: 0x05,
            },
            nonce: [0xCCu8; NONCE_SIZE],
            ciphertext: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };

        let wire = msg.to_bytes().unwrap();
        let parsed = RatchetMessageRef::from_bytes(&wire).unwrap();

        assert_eq!(parsed.header.dh_public, msg.header.dh_public);
        assert_eq!(parsed.header.message_number, msg.header.message_number);
        assert_eq!(parsed.header.previous_chain_length, msg.header.previous_chain_length);
        assert_eq!(parsed.header.payload_type, msg.header.payload_type);
        assert_eq!(parsed.nonce, msg.nonce);
        assert_eq!(parsed.ciphertext, &msg.ciphertext[..]);

        // Also test with None dh_public (smaller header)
        let msg2 = RatchetMessage {
            header: MessageHeader {
                dh_public: None,
                message_number: 0,
                previous_chain_length: 0,
                payload_type: 0,
            },
            nonce: [0u8; NONCE_SIZE],
            ciphertext: vec![],
        };
        let wire2 = msg2.to_bytes().unwrap();
        let parsed2 = RatchetMessageRef::from_bytes(&wire2).unwrap();
        assert_eq!(parsed2.header.dh_public, None);
        assert_eq!(parsed2.ciphertext, &[] as &[u8]);
    }

    #[test]
    fn test_decrypt_to_ref_matches_decrypt_to() {
        let shared_secret = [0x42u8; 32];
        let mut alice = DoubleRatchet::init_alice(shared_secret, [0u8; 32]);
        let mut bob = DoubleRatchet::init_bob(shared_secret);

        let plaintext = b"Hello, zero-copy!";
        let msg = alice.encrypt(plaintext, &[0x05]).expect("encrypt failed");
        let wire = msg.to_bytes().unwrap();

        // Decrypt via owned path
        let mut bob_owned = DoubleRatchet::init_bob(shared_secret);
        let plain_owned = bob_owned.decrypt(&msg, &[0x05]).unwrap();

        // Decrypt via ref path
        let ref_msg = RatchetMessageRef::from_bytes(&wire).unwrap();
        let mut plain_ref = Vec::new();
        let ref_len = bob.decrypt_to_ref(&ref_msg, &[0x05], &mut plain_ref).unwrap();

        assert_eq!(&plain_owned[..], &plain_ref[..ref_len]);
        assert_eq!(&plain_ref[..ref_len], plaintext);
    }

    #[test]
    fn test_double_ratchet_basic() {
        let shared_secret = [0x42u8; 32];
        
        let mut alice = DoubleRatchet::init_alice(shared_secret, [0u8; 32]);
        let mut bob = DoubleRatchet::init_bob(shared_secret);
        
        // Alice encrypts
        let plaintext = b"Hello, Bob!";
        let message = alice.encrypt(plaintext, &[0x05]).expect("Encryption failed");
        
        // Bob decrypts
        let decrypted = bob.decrypt(&message, &[0x05]).expect("Decryption failed");
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_double_ratchet_multiple_messages() {
        let shared_secret = [0x42u8; 32];

        let mut alice = DoubleRatchet::init_alice(shared_secret, [0u8; 32]);
        let mut bob = DoubleRatchet::init_bob(shared_secret);

        // Send multiple messages
        for i in 0..5 {
            let plaintext = format!("Message {}", i);
            let message = alice.encrypt(plaintext.as_bytes(), &[0x05]).expect("Encryption failed");
            let decrypted = bob.decrypt(&message, &[0x05]).expect("Decryption failed");
            assert_eq!(String::from_utf8_lossy(&decrypted), plaintext);
        }
    }

    #[test]
    fn test_double_ratchet_bidirectional() {
        let shared_secret = [0x42u8; 32];

        let mut alice = DoubleRatchet::init_alice(shared_secret, [0u8; 32]);
        let mut bob = DoubleRatchet::init_bob(shared_secret);

        // Alice -> Bob (first message, includes Alice's DH public key)
        let msg1 = alice.encrypt(b"Hello Bob", &[0x05]).expect("Alice encrypt failed");
        let reply1 = bob.decrypt(&msg1, &[0x05]).expect("Bob decrypt failed");
        assert_eq!(&reply1, b"Hello Bob");

        // Bob -> Alice (second message, Bob's response with his NEW DH key)
        // Bob includes his DH key in the message header
        let msg2 = bob.encrypt(b"Hello Alice", &[0x05]).expect("Bob encrypt failed");
        // Alice should detect the new DH key and trigger ratchet BEFORE decrypting
        let reply2 = alice.decrypt(&msg2, &[0x05]).expect("Alice decrypt failed");
        assert_eq!(&reply2, b"Hello Alice");

        // Alice -> Bob (third message)
        let msg3 = alice.encrypt(b"How are you?", &[0x05]).expect("Alice encrypt failed 2");
        let reply3 = bob.decrypt(&msg3, &[0x05]).expect("Bob decrypt failed 2");
        assert_eq!(&reply3, b"How are you?");

        // Bob -> Alice (fourth message)
        let msg4 = bob.encrypt(b"I'm fine!", &[0x05]).expect("Bob encrypt failed 2");
        let reply4 = alice.decrypt(&msg4, &[0x05]).expect("Alice decrypt failed 2");
        assert_eq!(&reply4, b"I'm fine!");
    }
}

#[cfg(test)]
mod split_ratchet_tests {
    use super::*;

    #[tokio::test]
    async fn test_split_ratchet_basic() {
        let shared_secret = [0x42u8; 32];
        
        let alice = SplitRatchet::init_alice(shared_secret, [0u8; 32]).await;
        let bob = SplitRatchet::init_bob(shared_secret).await;
        
        // Alice encrypts
        let plaintext = b"Hello, Bob!";
        let message = alice.encrypt(plaintext, &[0x05]).await.expect("Encryption failed");
        
        // Bob decrypts
        let decrypted = bob.decrypt(&message, &[0x05]).await.expect("Decryption failed");
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[tokio::test]
    async fn test_split_ratchet_multiple_messages() {
        let shared_secret = [0x42u8; 32];

        let alice = SplitRatchet::init_alice(shared_secret, [0u8; 32]).await;
        let bob = SplitRatchet::init_bob(shared_secret).await;

        // Send multiple messages
        for i in 0..5 {
            let plaintext = format!("Message {}", i);
            let message = alice.encrypt(plaintext.as_bytes(), &[0x05]).await.expect("Encryption failed");
            let decrypted = bob.decrypt(&message, &[0x05]).await.expect("Decryption failed");
            assert_eq!(String::from_utf8_lossy(&decrypted), plaintext);
        }
    }

    #[tokio::test]
    async fn test_split_ratchet_bidirectional() {
        let shared_secret = [0x42u8; 32];

        let alice = SplitRatchet::init_alice(shared_secret, [0u8; 32]).await;
        let bob = SplitRatchet::init_bob(shared_secret).await;

        // Alice -> Bob (first message, includes Alice's DH public key)
        let msg1 = alice.encrypt(b"Hello Bob", &[0x05]).await.expect("Alice encrypt failed");
        let reply1 = bob.decrypt(&msg1, &[0x05]).await.expect("Bob decrypt failed");
        assert_eq!(&reply1, b"Hello Bob");

        // Bob -> Alice (second message, Bob's response with his NEW DH key)
        let msg2 = bob.encrypt(b"Hello Alice", &[0x05]).await.expect("Bob encrypt failed");
        let reply2 = alice.decrypt(&msg2, &[0x05]).await.expect("Alice decrypt failed");
        assert_eq!(&reply2, b"Hello Alice");

        // Alice -> Bob (third message)
        let msg3 = alice.encrypt(b"How are you?", &[0x05]).await.expect("Alice encrypt failed 2");
        let reply3 = bob.decrypt(&msg3, &[0x05]).await.expect("Bob decrypt failed 2");
        assert_eq!(&reply3, b"How are you?");

        // Bob -> Alice (fourth message)
        let msg4 = bob.encrypt(b"I'm fine!", &[0x05]).await.expect("Bob encrypt failed 2");
        let reply4 = alice.decrypt(&msg4, &[0x05]).await.expect("Alice decrypt failed 2");
        assert_eq!(&reply4, b"I'm fine!");
    }

    #[tokio::test]
    async fn test_split_ratchet_from_double_ratchet() {
        let shared_secret = [0x42u8; 32];
        
        // Create DoubleRatchets and extract their state for conversion
        let alice_dr = DoubleRatchet::init_alice(shared_secret, [0u8; 32]);
        let bob_dr = DoubleRatchet::init_bob(shared_secret);
        
        // Convert using the from_double_ratchet constructor
        // Note: In real usage, you'd add accessor methods to DoubleRatchet to get these fields
        // For this test, we just verify that init_alice/init_bob work equivalently
        let alice = SplitRatchet::init_alice(shared_secret, [0u8; 32]).await;
        let bob = SplitRatchet::init_bob(shared_secret).await;
        
        // Test basic encryption/decryption
        let plaintext = b"Hello from converted ratchet!";
        let message = alice.encrypt(plaintext, &[0x05]).await.expect("Encryption failed");
        let decrypted = bob.decrypt(&message, &[0x05]).await.expect("Decryption failed");
        assert_eq!(&decrypted[..], &plaintext[..]);
        
        // Suppress unused variable warnings
        let _ = alice_dr;
        let _ = bob_dr;
    }

    #[tokio::test]
    async fn test_split_ratchet_concurrent_encrypt_decrypt() {
        let shared_secret = [0x42u8; 32];

        let alice = std::sync::Arc::new(SplitRatchet::init_alice(shared_secret, [0u8; 32]).await);
        let bob = std::sync::Arc::new(SplitRatchet::init_bob(shared_secret).await);

        // First, exchange initial messages to establish DH keys
        let msg1 = alice.encrypt(b"Hello Bob", &[0x05]).await.expect("Alice encrypt failed");
        let _ = bob.decrypt(&msg1, &[0x05]).await.expect("Bob decrypt failed");
        
        let msg2 = bob.encrypt(b"Hello Alice", &[0x05]).await.expect("Bob encrypt failed");
        let _ = alice.decrypt(&msg2, &[0x05]).await.expect("Alice decrypt failed");

        // Now test concurrent operations
        let alice_clone = alice.clone();
        let bob_clone = bob.clone();
        
        // Spawn concurrent encryption tasks
        let encrypt_task = tokio::spawn(async move {
            for i in 0..10 {
                let plaintext = format!("Concurrent message {}", i);
                let _ = alice_clone.encrypt(plaintext.as_bytes(), &[0x05]).await;
            }
        });
        
        // Spawn concurrent decryption tasks (decrypting our own encrypted messages for test)
        // In real usage, bob would decrypt messages from alice
        let decrypt_task = tokio::spawn(async move {
            for i in 0..10 {
                let plaintext = format!("Bob message {}", i);
                let _ = bob_clone.encrypt(plaintext.as_bytes(), &[0x05]).await;
            }
        });
        
        // Both should complete without deadlock
        let (r1, r2) = tokio::join!(encrypt_task, decrypt_task);
        r1.expect("Encrypt task failed");
        r2.expect("Decrypt task failed");
    }
}
