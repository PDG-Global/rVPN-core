//! Message types for R-VPN protocol

use serde::{Deserialize, Serialize};

/// Encrypted message frame
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedFrame {
    /// Message sequence number
    pub sequence: u64,
    /// Ratchet public key (for DH ratchet)
    #[serde(with = "serde_bytes")]
    pub ratchet_key: Option<Vec<u8>>,
    /// Encrypted header
    #[serde(with = "serde_bytes")]
    pub encrypted_header: Vec<u8>,
    /// Ciphertext
    #[serde(with = "serde_bytes")]
    pub ciphertext: Vec<u8>,
    /// Authentication tag
    #[serde(with = "serde_bytes")]
    pub auth_tag: [u8; 16],
}

/// Decrypted message header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageHeader {
    /// Payload type
    pub payload_type: super::PayloadType,
    /// Length of payload
    pub payload_len: u32,
    /// Padding length
    pub padding_len: u16,
    /// Timestamp for replay protection
    pub timestamp: u64,
}

/// VPN data payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataPayload {
    /// IP packet data
    #[serde(with = "serde_bytes")]
    pub packet: Vec<u8>,
}

/// Proxy connection request (TCP connect through tunnel)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConnect {
    /// Connection ID for tracking
    pub connection_id: u64,
    /// Target host
    pub host: String,
    /// Target port
    pub port: u16,
}

/// Proxy connection response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyResponse {
    /// Connection ID matching the request
    pub connection_id: u64,
    /// Success flag
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Proxy data payload (TCP relay)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyData {
    /// Connection ID
    pub connection_id: u64,
    /// Data payload
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    /// True if this is the last data (connection close)
    pub close: bool,
}

/// Proxy data batch item for connection multiplexing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyDataBatchItem {
    /// Connection ID
    pub connection_id: u64,
    /// Data payload
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
    /// True if this is the last data (connection close)
    pub close: bool,
}

/// Proxy data batch for reduced WebSocket overhead
/// Batches multiple small data chunks into a single message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyDataBatch {
    /// Batch items from multiple connections
    pub items: Vec<ProxyDataBatchItem>,
}

/// Administrative command payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminCommand {
    /// Get server status
    GetStatus,
    /// List connected peers
    ListPeers,
    /// Add a new peer
    AddPeer {
        /// Peer public key
        #[serde(with = "serde_bytes")]
        public_key: Vec<u8>,
        /// Assigned IP address
        ip: String,
    },
    /// Remove a peer
    RemovePeer {
        /// Peer public key
        #[serde(with = "serde_bytes")]
        public_key: Vec<u8>,
    },
    /// Request IP assignment
    RequestIp,
    /// Release IP assignment
    ReleaseIp {
        /// IP address to release
        ip: String,
    },
}

/// Administrative response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminResponse {
    /// Server status
    Status {
        /// Server uptime in seconds
        uptime: u64,
        /// Number of connected clients
        connected_clients: u32,
        /// Total bytes transferred
        bytes_transferred: u64,
    },
    /// Peer list
    PeerList {
        /// List of peers
        peers: Vec<PeerInfo>,
    },
    /// Operation success
    Success,
    /// Operation error
    Error {
        /// Error code
        code: u16,
        /// Error message
        message: String,
    },
}

/// Peer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer public key (hashed/anonymized)
    pub public_key_hash: String,
    /// Assigned IP address
    pub ip: String,
    /// Connection time
    pub connected_since: u64,
    /// Bytes sent to peer
    pub bytes_sent: u64,
    /// Bytes received from peer
    pub bytes_received: u64,
}

/// Keepalive message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeepAlive {
    /// Sent timestamp
    pub sent_at: u64,
}

/// DNS query request (client -> server)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuery {
    /// Query ID for matching response
    pub query_id: u64,
    /// Domain name to resolve
    pub domain: String,
    /// Query type (A=1, AAAA=28, etc.)
    pub query_type: u16,
}

/// DNS query response (server -> client)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResponse {
    /// Query ID matching the request
    pub query_id: u64,
    /// Resolution success
    pub success: bool,
    /// Resolved IPv4 addresses
    pub ipv4_addrs: Vec<std::net::Ipv4Addr>,
    /// Resolved IPv6 addresses
    pub ipv6_addrs: Vec<std::net::Ipv6Addr>,
    /// TTL in seconds
    pub ttl: u32,
    /// Error message if failed
    pub error: Option<String>,
}

/// Flow control message for backpressure management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowControl {
    /// Receiver's available buffer space (in messages)
    pub available_window: u32,
    /// Last sequence number received successfully
    pub last_received_seq: u64,
    /// Number of messages dropped due to buffer overflow
    pub dropped_count: u32,
}

/// Padding frame for traffic shaping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaddingFrame {
    /// Random data
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}
