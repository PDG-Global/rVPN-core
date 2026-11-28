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
        /// Client capability bits (`rvpn_core::crypto::x3dh::CAP_RATCHET_V2`).
        /// Absent in pre-v2 clients: treated as 0 (v1-only). Mixed into the
        /// X3DH KDF input, so altering it in flight diverges the secrets.
        #[serde(default)]
        capabilities: Option<u32>,
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
        /// Identity X25519 key, when supplied by a server supporting signed bundles.
        #[serde(default, with = "serde_bytes")]
        identity_x25519_key: Option<Vec<u8>>,
        /// Signature over the identity X25519 key, when supplied.
        #[serde(default, with = "serde_bytes")]
        identity_x25519_signature: Option<Vec<u8>>,
        /// Server capability bits, from the signed public bundle.
        #[serde(default)]
        capabilities: Option<u32>,
    },

    /// Client authentication proof. For v2-capable clients this carries the
    /// admission key-confirmation MAC (see
    /// `rvpn_core::crypto::admission`), sent as the third handshake flight
    /// after ServerHello. The server allocates nothing and registers no
    /// session until it verifies, and answers ServerAccept only after
    /// admission passes.
    ClientAuth {
        /// Encrypted authentication data
        #[serde(with = "serde_bytes")]
        encrypted_data: Vec<u8>,
        /// Client identity (if not anonymous)
        #[serde(with = "serde_bytes")]
        identity: Option<Vec<u8>>,
        /// Admission key-confirmation MAC over the full handshake
        /// transcript (Hello + ServerHello). Present in v2-capable clients.
        #[serde(default, with = "serde_bytes")]
        admission_mac: Option<Vec<u8>>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn server_hello() -> HandshakeMessage {
        HandshakeMessage::ServerHello {
            ephemeral_key: vec![],
            signed_prekey: vec![1; 32],
            prekey_signature: vec![2; 64],
            identity_key: vec![3; 32],
            identity_x25519_key: Some(vec![4; 32]),
            identity_x25519_signature: Some(vec![5; 64]),
            capabilities: None,
        }
    }

    #[test]
    fn legacy_server_hello_decodes_without_signed_identity_fields() {
        let mut json = serde_json::to_value(server_hello()).unwrap();
        let fields = json
            .get_mut("ServerHello")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap();
        fields.remove("identity_x25519_key");
        fields.remove("identity_x25519_signature");

        let decoded: HandshakeMessage = serde_json::from_value(json).unwrap();
        match decoded {
            HandshakeMessage::ServerHello {
                identity_x25519_key,
                identity_x25519_signature,
                ..
            } => {
                assert!(identity_x25519_key.is_none());
                assert!(identity_x25519_signature.is_none());
            }
            _ => panic!("wrong handshake variant"),
        }
    }

    #[test]
    fn legacy_client_ignores_signed_identity_fields() {
        #[derive(Deserialize)]
        enum LegacyHandshakeMessage {
            ServerHello {
                #[serde(with = "serde_bytes")]
                ephemeral_key: Vec<u8>,
                #[serde(with = "serde_bytes")]
                signed_prekey: Vec<u8>,
                #[serde(with = "serde_bytes")]
                prekey_signature: Vec<u8>,
                #[serde(with = "serde_bytes")]
                identity_key: Vec<u8>,
            },
        }

        let decoded: LegacyHandshakeMessage =
            serde_json::from_value(serde_json::to_value(server_hello()).unwrap()).unwrap();
        match decoded {
            LegacyHandshakeMessage::ServerHello {
                ephemeral_key,
                signed_prekey,
                prekey_signature,
                identity_key,
            } => {
                assert!(ephemeral_key.is_empty());
                assert_eq!(signed_prekey, vec![1; 32]);
                assert_eq!(prekey_signature, vec![2; 64]);
                assert_eq!(identity_key, vec![3; 32]);
            }
        }
    }
}
