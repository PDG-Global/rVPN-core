//! Protocol definitions for R-VPN

use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::fmt;

pub mod codec;
pub mod length_framing;
pub mod message;
pub mod multiplex;
pub mod packet;
pub mod padding;
pub use codec::*;
pub use length_framing::*;

// Re-export multiplex types for convenience
pub use multiplex::{ControlMessage, FrameCodec, MultiplexError, MultiplexedFrame};

// Re-export DNS message types for convenience
pub use message::{DnsQuery, DnsResponse};

/// Unique identifier for a session
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(#[serde(with = "serde_bytes")] pub [u8; 16]);

impl SessionId {
    /// Generate a new random session ID
    pub fn generate() -> Self {
        let mut bytes = [0u8; 16];
        rand::rngs::StdRng::from_entropy().fill(&mut bytes);
        Self(bytes)
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

/// Protocol version for handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    /// Major version
    pub major: u8,
    /// Minor version
    pub minor: u8,
    /// Patch version
    pub patch: u8,
}

impl ProtocolVersion {
    /// Current protocol version
    pub const CURRENT: Self = Self {
        major: 1,
        minor: 0,
        patch: 0,
    };

    /// Check if versions are compatible
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Authentication method for handshake
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AuthMethod {
    /// X3DH key agreement
    X3DH = 0x01,
    /// Noise protocol handshake
    Noise = 0x02,
    /// Session token resumption
    Token = 0x03,
}

/// Handshake message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HandshakeMessage {
    /// Initial hello from client
    Hello {
        /// Protocol version
        version: ProtocolVersion,
        /// Authentication method
        auth_method: AuthMethod,
        /// Client ephemeral public key (for X3DH)
        #[serde(with = "serde_bytes")]
        ephemeral_key: Option<Vec<u8>>,
        /// Client identity public key (X25519, for X3DH)
        #[serde(with = "serde_bytes")]
        identity_key: Option<Vec<u8>>,
        /// Session token for resumption
        #[serde(with = "serde_bytes")]
        session_token: Option<Vec<u8>>,
        /// Connection nonce - random value to ensure fresh session
        /// Prevents session reuse when client reconnects
        #[serde(with = "serde_bytes")]
        connection_nonce: Option<Vec<u8>>,
    },

    /// Server response with key bundle
    ServerHello {
        /// Server ephemeral key
        #[serde(with = "serde_bytes")]
        ephemeral_key: Vec<u8>,
        /// Server signed prekey
        #[serde(with = "serde_bytes")]
        signed_prekey: Vec<u8>,
        /// Prekey signature
        #[serde(with = "serde_bytes")]
        prekey_signature: Vec<u8>,
        /// Server identity key (for verification)
        #[serde(with = "serde_bytes")]
        identity_key: Vec<u8>,
    },

    /// Client authentication proof
    ClientAuth {
        /// Encrypted authentication data
        #[serde(with = "serde_bytes")]
        encrypted_data: Vec<u8>,
        /// Client identity (if not anonymous)
        #[serde(with = "serde_bytes")]
        identity: Option<Vec<u8>>,
    },

    /// Server authentication acceptance
    ServerAccept {
        /// Session ID
        session_id: SessionId,
        /// Session token for resumption
        #[serde(with = "serde_bytes")]
        session_token: Vec<u8>,
        /// Server time for replay protection
        server_time: u64,
    },

    /// Error during handshake
    Error {
        /// Error code
        code: u16,
        /// Error message
        message: String,
    },
}

/// Cipher suite selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum CipherSuite {
    /// ChaCha20-Poly1305
    #[default]
    ChaCha20Poly1305 = 0x01,
    /// AES-256-GCM
    Aes256Gcm = 0x02,
}

/// Payload type for VPN frames
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PayloadType {
    /// IP packet data
    Data = 0x01,
    /// Administrative command
    Admin = 0x02,
    /// Keepalive
    KeepAlive = 0x03,
    /// Padding
    Padding = 0x04,
    /// Proxy connection request (TCP connect through tunnel)
    ProxyConnect = 0x05,
    /// Proxy connection response
    ProxyResponse = 0x06,
    /// Proxy data (TCP relay)
    ProxyData = 0x07,
    /// DNS query request (client -> server)
    DnsQuery = 0x08,
    /// DNS query response (server -> client)
    DnsResponse = 0x09,
    /// Proxy data batch for reduced overhead
    ProxyDataBatch = 0x0A,
    /// UDP association initialization
    UdpInit = 0x0B,
    /// UDP data packet
    UdpData = 0x0C,
    /// Virtual IP assignment (server -> client after X3DH)
    VirtualIp = 0x0D,
}

/// Virtual IP assignment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualIp {
    /// Assigned IPv4 address
    pub ipv4: Option<std::net::Ipv4Addr>,
    /// Assigned IPv6 address
    pub ipv6: Option<std::net::Ipv6Addr>,
    /// Tunnel gateway IP (for routing)
    pub gateway_ip: Option<std::net::Ipv4Addr>,
    /// DNS servers
    pub dns_servers: Vec<std::net::IpAddr>,
    /// MTU for the tunnel
    pub mtu: u16,
}
