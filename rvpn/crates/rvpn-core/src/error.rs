//! Error types for R-VPN core

use thiserror::Error;

/// Result type alias with R-VPN error
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for R-VPN core
#[derive(Error, Debug)]
pub enum Error {
    /// Cryptographic error
    #[error("crypto error: {0}")]
    Crypto(String),
    
    /// Protocol error
    #[error("protocol error: {0}")]
    Protocol(String),
    
    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    
    /// Invalid key format
    #[error("invalid key format: {0}")]
    InvalidKey(String),
    
    /// Handshake failed
    #[error("handshake failed: {0}")]
    HandshakeFailed(String),
    
    /// Encryption failed
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    
    /// Decryption failed
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    
    /// Invalid message
    #[error("invalid message: {0}")]
    InvalidMessage(String),
    
    /// Ratchet error
    #[error("ratchet error: {0}")]
    Ratchet(String),

    /// Server identity pin mismatch — the pin captured from the handshake
    /// does not match the pin stored in the client's config. Fields are the
    /// canonical `ik:1:<base32>` strings so the app layer can render them
    /// side-by-side in the mismatch dialog without re-encoding.
    #[error("server identity mismatch: expected {expected}, got {actual}")]
    ServerIdentityMismatch {
        /// The pin the client had stored for this server.
        expected: String,
        /// The pin derived from the handshake we just received.
        actual: String,
    },
}

impl From<ed25519_dalek::SignatureError> for Error {
    fn from(e: ed25519_dalek::SignatureError) -> Self {
        Error::InvalidKey(e.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::InvalidKey(e.to_string())
    }
}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::InvalidKey(e.to_string())
    }
}
