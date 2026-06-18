//! Binary protocol codec for R-VPN
//!
//! This module provides efficient binary encoding/decoding for protocol messages,
//! replacing JSON serialization to eliminate base64 overhead for binary data.
//!
//! All integer encoding uses big-endian (network byte order).

use crate::crypto::cipher::NONCE_SIZE;
use crate::crypto::ratchet::{MessageHeader, RatchetMessage};
use crate::protocol::message::{
    DnsQuery, DnsResponse, ProxyConnect, ProxyData, ProxyDataBatch, ProxyDataBatchItem,
    ProxyResponse,
};

// Message type constants
const TYPE_PROXY_CONNECT: u8 = 0x01;
const TYPE_PROXY_RESPONSE: u8 = 0x02;
const TYPE_PROXY_DATA: u8 = 0x03;
const TYPE_RATCHET_MESSAGE: u8 = 0x04;
const TYPE_DNS_QUERY: u8 = 0x05;
const TYPE_DNS_RESPONSE: u8 = 0x06;
const TYPE_PROXY_DATA_BATCH: u8 = 0x0A;

/// Encode a ProxyConnect message to binary format
///
/// Format: [type: 1][connection_id: 8][host_len: 1][host: N][port: 2]
pub fn encode_proxy_connect(msg: &ProxyConnect) -> Vec<u8> {
    let host_bytes = msg.host.as_bytes();
    let mut result = Vec::with_capacity(1 + 8 + 1 + host_bytes.len() + 2);

    result.push(TYPE_PROXY_CONNECT);
    result.extend_from_slice(&msg.connection_id.to_be_bytes());
    result.push(host_bytes.len() as u8);
    result.extend_from_slice(host_bytes);
    result.extend_from_slice(&msg.port.to_be_bytes());

    result
}

/// Decode a ProxyConnect message from binary format
pub fn decode_proxy_connect(bytes: &[u8]) -> Result<ProxyConnect, &'static str> {
    if bytes.is_empty() || bytes[0] != TYPE_PROXY_CONNECT {
        return Err("Invalid message type");
    }

    let mut pos = 1;

    // connection_id (8 bytes)
    if bytes.len() < pos + 8 {
        return Err("Insufficient data for connection_id");
    }
    let connection_id = u64::from_be_bytes([
        bytes[pos],
        bytes[pos + 1],
        bytes[pos + 2],
        bytes[pos + 3],
        bytes[pos + 4],
        bytes[pos + 5],
        bytes[pos + 6],
        bytes[pos + 7],
    ]);
    pos += 8;

    // host length (1 byte)
    if bytes.len() < pos + 1 {
        return Err("Insufficient data for host length");
    }
    let host_len = bytes[pos] as usize;
    pos += 1;

    // host
    if bytes.len() < pos + host_len {
        return Err("Insufficient data for host");
    }
    let host = String::from_utf8(bytes[pos..pos + host_len].to_vec())
        .map_err(|_| "Invalid UTF-8 in host")?;
    pos += host_len;

    // port (2 bytes)
    if bytes.len() < pos + 2 {
        return Err("Insufficient data for port");
    }
    let port = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);

    Ok(ProxyConnect {
        connection_id,
        host,
        port,
    })
}

/// Encode a ProxyResponse message to binary format
///
/// Format: [type: 1][connection_id: 8][success: 1][error_len: 2][error: N]
pub fn encode_proxy_response(msg: &ProxyResponse) -> Vec<u8> {
    let error_bytes = msg.error.as_ref().map(|e| e.as_bytes()).unwrap_or(&[]);
    let mut result = Vec::with_capacity(1 + 8 + 1 + 2 + error_bytes.len());

    result.push(TYPE_PROXY_RESPONSE);
    result.extend_from_slice(&msg.connection_id.to_be_bytes());
    result.push(msg.success as u8);
    result.extend_from_slice(&(error_bytes.len() as u16).to_be_bytes());
    result.extend_from_slice(error_bytes);

    result
}

/// Decode a ProxyResponse message from binary format
pub fn decode_proxy_response(bytes: &[u8]) -> Result<ProxyResponse, &'static str> {
    if bytes.is_empty() || bytes[0] != TYPE_PROXY_RESPONSE {
        return Err("Invalid message type");
    }

    let mut pos = 1;

    // connection_id (8 bytes)
    if bytes.len() < pos + 8 {
        return Err("Insufficient data for connection_id");
    }
    let connection_id = u64::from_be_bytes([
        bytes[pos],
        bytes[pos + 1],
        bytes[pos + 2],
        bytes[pos + 3],
        bytes[pos + 4],
        bytes[pos + 5],
        bytes[pos + 6],
        bytes[pos + 7],
    ]);
    pos += 8;

    // success (1 byte)
    if bytes.len() < pos + 1 {
        return Err("Insufficient data for success flag");
    }
    let success = bytes[pos] != 0;
    pos += 1;

    // error length (2 bytes)
    if bytes.len() < pos + 2 {
        return Err("Insufficient data for error length");
    }
    let error_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;

    // error message
    if bytes.len() < pos + error_len {
        return Err("Insufficient data for error message");
    }
    let error = if error_len > 0 {
        Some(
            String::from_utf8(bytes[pos..pos + error_len].to_vec())
                .map_err(|_| "Invalid UTF-8 in error message")?,
        )
    } else {
        None
    };

    Ok(ProxyResponse {
        connection_id,
        success,
        error,
    })
}

/// Encode a ProxyData message to binary format
///
/// Format: [type: 1][connection_id: 8][close: 1][data_len: 4][data: N]
pub fn encode_proxy_data(msg: &ProxyData) -> Vec<u8> {
    let mut result = Vec::with_capacity(1 + 8 + 1 + 4 + msg.data.len());

    result.push(TYPE_PROXY_DATA);
    result.extend_from_slice(&msg.connection_id.to_be_bytes());
    result.push(msg.close as u8);
    result.extend_from_slice(&(msg.data.len() as u32).to_be_bytes());
    result.extend_from_slice(&msg.data);

    result
}

/// Decode a ProxyData message from binary format
pub fn decode_proxy_data(bytes: &[u8]) -> Result<ProxyData, &'static str> {
    if bytes.is_empty() || bytes[0] != TYPE_PROXY_DATA {
        return Err("Invalid message type");
    }

    let mut pos = 1;

    // connection_id (8 bytes)
    if bytes.len() < pos + 8 {
        return Err("Insufficient data for connection_id");
    }
    let connection_id = u64::from_be_bytes([
        bytes[pos],
        bytes[pos + 1],
        bytes[pos + 2],
        bytes[pos + 3],
        bytes[pos + 4],
        bytes[pos + 5],
        bytes[pos + 6],
        bytes[pos + 7],
    ]);
    pos += 8;

    // close flag (1 byte)
    if bytes.len() < pos + 1 {
        return Err("Insufficient data for close flag");
    }
    let close = bytes[pos] != 0;
    pos += 1;

    // data length (4 bytes)
    if bytes.len() < pos + 4 {
        return Err("Insufficient data for data length");
    }
    let data_len =
        u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
    pos += 4;

    // data
    if bytes.len() < pos + data_len {
        return Err("Insufficient data for data payload");
    }
    let data = bytes[pos..pos + data_len].to_vec();

    Ok(ProxyData {
        connection_id,
        data,
        close,
    })
}

/// Encode a ProxyDataBatch message to binary format
///
/// Format: [type: 1][item_count: 2][items...]
/// Each item: [connection_id: 8][close: 1][data_len: 4][data: N]
pub fn encode_proxy_data_batch(batch: &ProxyDataBatch) -> Vec<u8> {
    // Calculate total size
    let items_size: usize = batch
        .items
        .iter()
        .map(|item| 8 + 1 + 4 + item.data.len())
        .sum();
    let mut result = Vec::with_capacity(1 + 2 + items_size);

    result.push(TYPE_PROXY_DATA_BATCH);
    result.extend_from_slice(&(batch.items.len() as u16).to_be_bytes());

    for item in &batch.items {
        result.extend_from_slice(&item.connection_id.to_be_bytes());
        result.push(item.close as u8);
        result.extend_from_slice(&(item.data.len() as u32).to_be_bytes());
        result.extend_from_slice(&item.data);
    }

    result
}

/// Decode a ProxyDataBatch message from binary format
pub fn decode_proxy_data_batch(bytes: &[u8]) -> Result<ProxyDataBatch, &'static str> {
    if bytes.is_empty() || bytes[0] != TYPE_PROXY_DATA_BATCH {
        return Err("Invalid message type");
    }

    let mut pos = 1;

    // item count (2 bytes)
    if bytes.len() < pos + 2 {
        return Err("Insufficient data for item count");
    }
    let item_count = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;

    let mut items = Vec::with_capacity(item_count);

    for _ in 0..item_count {
        // connection_id (8 bytes)
        if bytes.len() < pos + 8 {
            return Err("Insufficient data for connection_id");
        }
        let connection_id = u64::from_be_bytes([
            bytes[pos],
            bytes[pos + 1],
            bytes[pos + 2],
            bytes[pos + 3],
            bytes[pos + 4],
            bytes[pos + 5],
            bytes[pos + 6],
            bytes[pos + 7],
        ]);
        pos += 8;

        // close flag (1 byte)
        if bytes.len() < pos + 1 {
            return Err("Insufficient data for close flag");
        }
        let close = bytes[pos] != 0;
        pos += 1;

        // data length (4 bytes)
        if bytes.len() < pos + 4 {
            return Err("Insufficient data for data length");
        }
        let data_len =
            u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]])
                as usize;
        pos += 4;

        // data
        if bytes.len() < pos + data_len {
            return Err("Insufficient data for data payload");
        }
        let data = bytes[pos..pos + data_len].to_vec();
        pos += data_len;

        items.push(ProxyDataBatchItem {
            connection_id,
            data,
            close,
        });
    }

    Ok(ProxyDataBatch { items })
}

/// Encode a RatchetMessage to binary format
///
/// Format: [type: 1][header: variable][nonce: 12][ciphertext_len: 4][ciphertext: N]
/// Header format: [has_dh_public: 1][dh_public: 32 (if present)][message_number: 4][previous_chain_length: 4]
pub fn encode_ratchet_message(msg: &RatchetMessage) -> Vec<u8> {
    let header = &msg.header;
    let dh_public_len = if header.dh_public.is_some() { 32 } else { 0 };
    let header_len = 1 + dh_public_len + 4 + 4 + 1; // has_dh_public + dh_public + message_number + previous_chain_length + payload_type
    let ciphertext_len = msg.ciphertext.len();

    let mut result = Vec::with_capacity(1 + header_len + NONCE_SIZE + 4 + ciphertext_len);

    result.push(TYPE_RATCHET_MESSAGE);

    // Encode header
    result.push(header.dh_public.is_some() as u8);
    if let Some(dh) = &header.dh_public {
        result.extend_from_slice(dh);
    }
    result.extend_from_slice(&header.message_number.to_be_bytes());
    result.extend_from_slice(&header.previous_chain_length.to_be_bytes());
    result.push(header.payload_type);

    // Encode nonce
    result.extend_from_slice(&msg.nonce);

    // Encode ciphertext
    result.extend_from_slice(&(ciphertext_len as u32).to_be_bytes());
    result.extend_from_slice(&msg.ciphertext);

    result
}

/// Decode a RatchetMessage from binary format
pub fn decode_ratchet_message(bytes: &[u8]) -> Result<RatchetMessage, &'static str> {
    if bytes.is_empty() || bytes[0] != TYPE_RATCHET_MESSAGE {
        return Err("Invalid message type");
    }

    let mut pos = 1;

    // Decode header
    if bytes.len() < pos + 1 {
        return Err("Insufficient data for header flags");
    }
    let has_dh_public = bytes[pos] != 0;
    pos += 1;

    let dh_public = if has_dh_public {
        if bytes.len() < pos + 32 {
            return Err("Insufficient data for DH public key");
        }
        let mut dh = [0u8; 32];
        dh.copy_from_slice(&bytes[pos..pos + 32]);
        pos += 32;
        Some(dh)
    } else {
        None
    };

    if bytes.len() < pos + 4 {
        return Err("Insufficient data for message number");
    }
    let message_number =
        u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    pos += 4;

    if bytes.len() < pos + 4 {
        return Err("Insufficient data for previous chain length");
    }
    let previous_chain_length =
        u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    pos += 4;

    // Decode payload type
    if bytes.len() < pos + 1 {
        return Err("Insufficient data for payload type");
    }
    let payload_type = bytes[pos];
    pos += 1;

    let header = MessageHeader {
        dh_public,
        message_number,
        previous_chain_length,
        payload_type,
    };

    // Decode nonce
    if bytes.len() < pos + NONCE_SIZE {
        return Err("Insufficient data for nonce");
    }
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&bytes[pos..pos + NONCE_SIZE]);
    pos += NONCE_SIZE;

    // Decode ciphertext
    if bytes.len() < pos + 4 {
        return Err("Insufficient data for ciphertext length");
    }
    let ciphertext_len =
        u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]) as usize;
    pos += 4;

    // Validate ciphertext length is reasonable (max 10MB to prevent DoS)
    const MAX_CIPHERTEXT_LEN: usize = 10 * 1024 * 1024; // 10MB
    if ciphertext_len > MAX_CIPHERTEXT_LEN {
        return Err("Ciphertext length exceeds maximum allowed size");
    }

    if bytes.len() < pos + ciphertext_len {
        return Err("Insufficient data for ciphertext");
    }
    let ciphertext = bytes[pos..pos + ciphertext_len].to_vec();

    Ok(RatchetMessage {
        header,
        nonce,
        ciphertext,
    })
}

/// Encode with 4-byte length prefix (for framing)
///
/// This is useful for TCP streams where message boundaries need to be preserved.
/// The length prefix is the size of the payload (not including the 4-byte prefix itself).
pub fn encode_with_length_prefix(data: Vec<u8>) -> Vec<u8> {
    let len = data.len() as u32;
    let mut result = Vec::with_capacity(4 + data.len());
    result.extend_from_slice(&len.to_be_bytes());
    result.extend_from_slice(&data);
    result
}

/// Decode from 4-byte length prefix
///
/// Returns the decoded payload and the total number of bytes consumed (including prefix).
/// Returns None if there is insufficient data to decode a complete message.
pub fn decode_from_length_prefix(bytes: &[u8]) -> Option<(Vec<u8>, usize)> {
    if bytes.len() < 4 {
        return None;
    }

    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;

    if bytes.len() < 4 + len {
        return None;
    }

    Some((bytes[4..4 + len].to_vec(), 4 + len))
}

/// Encode a DnsQuery message to binary format
///
/// Format: [type: 1][query_id: 8][query_type: 2][domain_len: 1][domain: N]
pub fn encode_dns_query(msg: &DnsQuery) -> Vec<u8> {
    let domain_bytes = msg.domain.as_bytes();
    let mut result = Vec::with_capacity(1 + 8 + 2 + 1 + domain_bytes.len());

    result.push(TYPE_DNS_QUERY);
    result.extend_from_slice(&msg.query_id.to_be_bytes());
    result.extend_from_slice(&msg.query_type.to_be_bytes());
    result.push(domain_bytes.len() as u8);
    result.extend_from_slice(domain_bytes);

    result
}

/// Decode a DnsQuery message from binary format
pub fn decode_dns_query(bytes: &[u8]) -> Result<DnsQuery, &'static str> {
    if bytes.is_empty() || bytes[0] != TYPE_DNS_QUERY {
        return Err("Invalid message type");
    }

    let mut pos = 1;

    // query_id (8 bytes)
    if bytes.len() < pos + 8 {
        return Err("Insufficient data for query_id");
    }
    let query_id = u64::from_be_bytes([
        bytes[pos],
        bytes[pos + 1],
        bytes[pos + 2],
        bytes[pos + 3],
        bytes[pos + 4],
        bytes[pos + 5],
        bytes[pos + 6],
        bytes[pos + 7],
    ]);
    pos += 8;

    // query_type (2 bytes)
    if bytes.len() < pos + 2 {
        return Err("Insufficient data for query_type");
    }
    let query_type = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
    pos += 2;

    // domain length (1 byte)
    if bytes.len() < pos + 1 {
        return Err("Insufficient data for domain length");
    }
    let domain_len = bytes[pos] as usize;
    pos += 1;

    // domain
    if bytes.len() < pos + domain_len {
        return Err("Insufficient data for domain");
    }
    let domain = String::from_utf8(bytes[pos..pos + domain_len].to_vec())
        .map_err(|_| "Invalid UTF-8 in domain")?;

    Ok(DnsQuery {
        query_id,
        domain,
        query_type,
    })
}

/// Encode a DnsResponse message to binary format
///
/// Format: [type: 1][query_id: 8][success: 1][ttl: 4][ipv4_count: 1][ipv4_addrs: N*4][ipv6_count: 1][ipv6_addrs: N*16][error_len: 2][error: N]
pub fn encode_dns_response(msg: &DnsResponse) -> Vec<u8> {
    let error_bytes = msg.error.as_ref().map(|e| e.as_bytes()).unwrap_or(&[]);
    let mut result = Vec::with_capacity(
        1 + 8
            + 1
            + 4
            + 1
            + msg.ipv4_addrs.len() * 4
            + 1
            + msg.ipv6_addrs.len() * 16
            + 2
            + error_bytes.len(),
    );

    result.push(TYPE_DNS_RESPONSE);
    result.extend_from_slice(&msg.query_id.to_be_bytes());
    result.push(msg.success as u8);
    result.extend_from_slice(&msg.ttl.to_be_bytes());

    // IPv4 addresses
    result.push(msg.ipv4_addrs.len() as u8);
    for addr in &msg.ipv4_addrs {
        result.extend_from_slice(&addr.octets());
    }

    // IPv6 addresses
    result.push(msg.ipv6_addrs.len() as u8);
    for addr in &msg.ipv6_addrs {
        result.extend_from_slice(&addr.octets());
    }

    // Error message
    result.extend_from_slice(&(error_bytes.len() as u16).to_be_bytes());
    result.extend_from_slice(error_bytes);

    result
}

/// Decode a DnsResponse message from binary format
pub fn decode_dns_response(bytes: &[u8]) -> Result<DnsResponse, &'static str> {
    if bytes.is_empty() || bytes[0] != TYPE_DNS_RESPONSE {
        return Err("Invalid message type");
    }

    let mut pos = 1;

    // query_id (8 bytes)
    if bytes.len() < pos + 8 {
        return Err("Insufficient data for query_id");
    }
    let query_id = u64::from_be_bytes([
        bytes[pos],
        bytes[pos + 1],
        bytes[pos + 2],
        bytes[pos + 3],
        bytes[pos + 4],
        bytes[pos + 5],
        bytes[pos + 6],
        bytes[pos + 7],
    ]);
    pos += 8;

    // success (1 byte)
    if bytes.len() < pos + 1 {
        return Err("Insufficient data for success flag");
    }
    let success = bytes[pos] != 0;
    pos += 1;

    // ttl (4 bytes)
    if bytes.len() < pos + 4 {
        return Err("Insufficient data for TTL");
    }
    let ttl = u32::from_be_bytes([bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]]);
    pos += 4;

    // IPv4 count (1 byte)
    if bytes.len() < pos + 1 {
        return Err("Insufficient data for IPv4 count");
    }
    let ipv4_count = bytes[pos] as usize;
    pos += 1;

    // IPv4 addresses
    if bytes.len() < pos + ipv4_count * 4 {
        return Err("Insufficient data for IPv4 addresses");
    }
    let mut ipv4_addrs = Vec::with_capacity(ipv4_count);
    for _ in 0..ipv4_count {
        let addr =
            std::net::Ipv4Addr::new(bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3]);
        ipv4_addrs.push(addr);
        pos += 4;
    }

    // IPv6 count (1 byte)
    if bytes.len() < pos + 1 {
        return Err("Insufficient data for IPv6 count");
    }
    let ipv6_count = bytes[pos] as usize;
    pos += 1;

    // IPv6 addresses
    if bytes.len() < pos + ipv6_count * 16 {
        return Err("Insufficient data for IPv6 addresses");
    }
    let mut ipv6_addrs = Vec::with_capacity(ipv6_count);
    for _ in 0..ipv6_count {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(&bytes[pos..pos + 16]);
        let addr = std::net::Ipv6Addr::from(octets);
        ipv6_addrs.push(addr);
        pos += 16;
    }

    // error length (2 bytes)
    if bytes.len() < pos + 2 {
        return Err("Insufficient data for error length");
    }
    let error_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
    pos += 2;

    // error message
    if bytes.len() < pos + error_len {
        return Err("Insufficient data for error message");
    }
    let error = if error_len > 0 {
        Some(
            String::from_utf8(bytes[pos..pos + error_len].to_vec())
                .map_err(|_| "Invalid UTF-8 in error message")?,
        )
    } else {
        None
    };

    Ok(DnsResponse {
        query_id,
        success,
        ipv4_addrs,
        ipv6_addrs,
        ttl,
        error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_connect_roundtrip() {
        let original = ProxyConnect {
            connection_id: 12345,
            host: "example.com".to_string(),
            port: 8080,
        };

        let encoded = encode_proxy_connect(&original);
        let decoded = decode_proxy_connect(&encoded).expect("decode failed");

        assert_eq!(original.connection_id, decoded.connection_id);
        assert_eq!(original.host, decoded.host);
        assert_eq!(original.port, decoded.port);
    }

    #[test]
    fn test_proxy_connect_long_host() {
        let original = ProxyConnect {
            connection_id: u64::MAX,
            host: "a".repeat(255),
            port: 65535,
        };

        let encoded = encode_proxy_connect(&original);
        let decoded = decode_proxy_connect(&encoded).expect("decode failed");

        assert_eq!(original.connection_id, decoded.connection_id);
        assert_eq!(original.host, decoded.host);
        assert_eq!(original.port, decoded.port);
    }

    #[test]
    fn test_proxy_response_roundtrip_success() {
        let original = ProxyResponse {
            connection_id: 67890,
            success: true,
            error: None,
        };

        let encoded = encode_proxy_response(&original);
        let decoded = decode_proxy_response(&encoded).expect("decode failed");

        assert_eq!(original.connection_id, decoded.connection_id);
        assert_eq!(original.success, decoded.success);
        assert_eq!(original.error, decoded.error);
    }

    #[test]
    fn test_proxy_response_roundtrip_error() {
        let original = ProxyResponse {
            connection_id: 11111,
            success: false,
            error: Some("Connection refused".to_string()),
        };

        let encoded = encode_proxy_response(&original);
        let decoded = decode_proxy_response(&encoded).expect("decode failed");

        assert_eq!(original.connection_id, decoded.connection_id);
        assert_eq!(original.success, decoded.success);
        assert_eq!(original.error, decoded.error);
    }

    #[test]
    fn test_proxy_data_roundtrip() {
        let original = ProxyData {
            connection_id: 22222,
            data: vec![0x01, 0x02, 0x03, 0x04, 0x05],
            close: false,
        };

        let encoded = encode_proxy_data(&original);
        let decoded = decode_proxy_data(&encoded).expect("decode failed");

        assert_eq!(original.connection_id, decoded.connection_id);
        assert_eq!(original.data, decoded.data);
        assert_eq!(original.close, decoded.close);
    }

    #[test]
    fn test_proxy_data_roundtrip_close() {
        let original = ProxyData {
            connection_id: 33333,
            data: vec![],
            close: true,
        };

        let encoded = encode_proxy_data(&original);
        let decoded = decode_proxy_data(&encoded).expect("decode failed");

        assert_eq!(original.connection_id, decoded.connection_id);
        assert_eq!(original.data, decoded.data);
        assert_eq!(original.close, decoded.close);
    }

    #[test]
    fn test_proxy_data_large_payload() {
        let original = ProxyData {
            connection_id: 44444,
            data: vec![0xAB; 10000],
            close: false,
        };

        let encoded = encode_proxy_data(&original);
        let decoded = decode_proxy_data(&encoded).expect("decode failed");

        assert_eq!(original.connection_id, decoded.connection_id);
        assert_eq!(original.data, decoded.data);
        assert_eq!(original.close, decoded.close);
    }

    #[test]
    fn test_ratchet_message_roundtrip_with_dh() {
        let original = RatchetMessage {
            header: MessageHeader {
                dh_public: Some([0x42; 32]),
                message_number: 100,
                previous_chain_length: 50,
                payload_type: 0x07,
            },
            nonce: [0x12; NONCE_SIZE],
            ciphertext: vec![0xAA, 0xBB, 0xCC, 0xDD],
        };

        let encoded = encode_ratchet_message(&original);
        let decoded = decode_ratchet_message(&encoded).expect("decode failed");

        assert_eq!(original.header.dh_public, decoded.header.dh_public);
        assert_eq!(
            original.header.message_number,
            decoded.header.message_number
        );
        assert_eq!(
            original.header.previous_chain_length,
            decoded.header.previous_chain_length
        );
        assert_eq!(original.header.payload_type, decoded.header.payload_type);
        assert_eq!(original.nonce, decoded.nonce);
        assert_eq!(original.ciphertext, decoded.ciphertext);
    }

    #[test]
    fn test_ratchet_message_roundtrip_without_dh() {
        let original = RatchetMessage {
            header: MessageHeader {
                dh_public: None,
                message_number: 0,
                previous_chain_length: 0,
                payload_type: 0x01,
            },
            nonce: [0x00; NONCE_SIZE],
            ciphertext: vec![],
        };

        let encoded = encode_ratchet_message(&original);
        let decoded = decode_ratchet_message(&encoded).expect("decode failed");

        assert_eq!(original.header.dh_public, decoded.header.dh_public);
        assert_eq!(
            original.header.message_number,
            decoded.header.message_number
        );
        assert_eq!(
            original.header.previous_chain_length,
            decoded.header.previous_chain_length
        );
        assert_eq!(original.header.payload_type, decoded.header.payload_type);
        assert_eq!(original.nonce, decoded.nonce);
        assert_eq!(original.ciphertext, decoded.ciphertext);
    }

    #[test]
    fn test_ratchet_message_large_ciphertext() {
        let original = RatchetMessage {
            header: MessageHeader {
                dh_public: Some([0x99; 32]),
                message_number: u32::MAX,
                previous_chain_length: u32::MAX,
                payload_type: 0x05,
            },
            nonce: [0xFF; NONCE_SIZE],
            ciphertext: vec![0x55; 100000],
        };

        let encoded = encode_ratchet_message(&original);
        let decoded = decode_ratchet_message(&encoded).expect("decode failed");

        assert_eq!(original.header.dh_public, decoded.header.dh_public);
        assert_eq!(
            original.header.message_number,
            decoded.header.message_number
        );
        assert_eq!(
            original.header.previous_chain_length,
            decoded.header.previous_chain_length
        );
        assert_eq!(original.nonce, decoded.nonce);
        assert_eq!(original.ciphertext, decoded.ciphertext);
    }

    #[test]
    fn test_length_prefix_roundtrip() {
        let data = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let encoded = encode_with_length_prefix(data.clone());

        let (decoded, consumed) = decode_from_length_prefix(&encoded).expect("decode failed");

        assert_eq!(data, decoded);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_length_prefix_empty() {
        let data = vec![];
        let encoded = encode_with_length_prefix(data.clone());

        let (decoded, consumed) = decode_from_length_prefix(&encoded).expect("decode failed");

        assert_eq!(data, decoded);
        assert_eq!(consumed, 4); // Just the length prefix
    }

    #[test]
    fn test_length_prefix_large_data() {
        let data = vec![0xAB; 100000];
        let encoded = encode_with_length_prefix(data.clone());

        let (decoded, consumed) = decode_from_length_prefix(&encoded).expect("decode failed");

        assert_eq!(data, decoded);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_length_prefix_insufficient_data() {
        // Less than 4 bytes
        assert!(decode_from_length_prefix(&[0x00, 0x00]).is_none());

        // Length says 100 bytes but only 10 provided
        let incomplete = vec![0x00, 0x00, 0x00, 0x64, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(decode_from_length_prefix(&incomplete).is_none());
    }

    #[test]
    fn test_decode_invalid_message_type() {
        let invalid = vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(decode_proxy_connect(&invalid).is_err());
        assert!(decode_proxy_response(&invalid).is_err());
        assert!(decode_proxy_data(&invalid).is_err());
        assert!(decode_ratchet_message(&invalid).is_err());
    }

    #[test]
    fn test_decode_insufficient_data() {
        assert!(decode_proxy_connect(&[]).is_err());
        assert!(decode_proxy_response(&[]).is_err());
        assert!(decode_proxy_data(&[]).is_err());
        assert!(decode_ratchet_message(&[]).is_err());

        assert!(decode_proxy_connect(&[TYPE_PROXY_CONNECT]).is_err());
        assert!(decode_proxy_response(&[TYPE_PROXY_RESPONSE]).is_err());
        assert!(decode_proxy_data(&[TYPE_PROXY_DATA]).is_err());
        assert!(decode_ratchet_message(&[TYPE_RATCHET_MESSAGE]).is_err());
    }

    #[test]
    fn test_invalid_utf8_host() {
        // Create a ProxyConnect with invalid UTF-8 in host
        let mut encoded = vec![TYPE_PROXY_CONNECT];
        encoded.extend_from_slice(&1u64.to_be_bytes()); // connection_id
        encoded.push(4); // host_len = 4
        encoded.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]); // invalid UTF-8
        encoded.extend_from_slice(&80u16.to_be_bytes()); // port

        assert!(decode_proxy_connect(&encoded).is_err());
    }

    #[test]
    fn test_invalid_utf8_error() {
        // Create a ProxyResponse with invalid UTF-8 in error
        let mut encoded = vec![TYPE_PROXY_RESPONSE];
        encoded.extend_from_slice(&1u64.to_be_bytes()); // connection_id
        encoded.push(0); // success = false
        encoded.extend_from_slice(&4u16.to_be_bytes()); // error_len = 4
        encoded.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]); // invalid UTF-8

        assert!(decode_proxy_response(&encoded).is_err());
    }

    #[test]
    fn test_dns_query_roundtrip() {
        let original = DnsQuery {
            query_id: 12345,
            domain: "example.com".to_string(),
            query_type: 1, // A record
        };

        let encoded = encode_dns_query(&original);
        let decoded = decode_dns_query(&encoded).expect("decode failed");

        assert_eq!(original.query_id, decoded.query_id);
        assert_eq!(original.domain, decoded.domain);
        assert_eq!(original.query_type, decoded.query_type);
    }

    #[test]
    fn test_dns_query_long_domain() {
        let original = DnsQuery {
            query_id: u64::MAX,
            domain: "a".repeat(255),
            query_type: 28, // AAAA record
        };

        let encoded = encode_dns_query(&original);
        let decoded = decode_dns_query(&encoded).expect("decode failed");

        assert_eq!(original.query_id, decoded.query_id);
        assert_eq!(original.domain, decoded.domain);
        assert_eq!(original.query_type, decoded.query_type);
    }

    #[test]
    fn test_dns_response_roundtrip_success() {
        let original = DnsResponse {
            query_id: 67890,
            success: true,
            ipv4_addrs: vec![
                std::net::Ipv4Addr::new(1, 2, 3, 4),
                std::net::Ipv4Addr::new(5, 6, 7, 8),
            ],
            ipv6_addrs: vec![],
            ttl: 300,
            error: None,
        };

        let encoded = encode_dns_response(&original);
        let decoded = decode_dns_response(&encoded).expect("decode failed");

        assert_eq!(original.query_id, decoded.query_id);
        assert_eq!(original.success, decoded.success);
        assert_eq!(original.ipv4_addrs, decoded.ipv4_addrs);
        assert_eq!(original.ipv6_addrs, decoded.ipv6_addrs);
        assert_eq!(original.ttl, decoded.ttl);
        assert_eq!(original.error, decoded.error);
    }

    #[test]
    fn test_dns_response_roundtrip_with_ipv6() {
        let original = DnsResponse {
            query_id: 11111,
            success: true,
            ipv4_addrs: vec![std::net::Ipv4Addr::new(8, 8, 8, 8)],
            ipv6_addrs: vec![std::net::Ipv6Addr::new(
                0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
            )],
            ttl: 600,
            error: None,
        };

        let encoded = encode_dns_response(&original);
        let decoded = decode_dns_response(&encoded).expect("decode failed");

        assert_eq!(original.query_id, decoded.query_id);
        assert_eq!(original.success, decoded.success);
        assert_eq!(original.ipv4_addrs, decoded.ipv4_addrs);
        assert_eq!(original.ipv6_addrs, decoded.ipv6_addrs);
        assert_eq!(original.ttl, decoded.ttl);
        assert_eq!(original.error, decoded.error);
    }

    #[test]
    fn test_dns_response_roundtrip_error() {
        let original = DnsResponse {
            query_id: 22222,
            success: false,
            ipv4_addrs: vec![],
            ipv6_addrs: vec![],
            ttl: 0,
            error: Some("NXDOMAIN".to_string()),
        };

        let encoded = encode_dns_response(&original);
        let decoded = decode_dns_response(&encoded).expect("decode failed");

        assert_eq!(original.query_id, decoded.query_id);
        assert_eq!(original.success, decoded.success);
        assert_eq!(original.ipv4_addrs, decoded.ipv4_addrs);
        assert_eq!(original.ipv6_addrs, decoded.ipv6_addrs);
        assert_eq!(original.ttl, decoded.ttl);
        assert_eq!(original.error, decoded.error);
    }

    #[test]
    fn test_dns_response_empty() {
        let original = DnsResponse {
            query_id: 33333,
            success: true,
            ipv4_addrs: vec![],
            ipv6_addrs: vec![],
            ttl: 0,
            error: None,
        };

        let encoded = encode_dns_response(&original);
        let decoded = decode_dns_response(&encoded).expect("decode failed");

        assert_eq!(original.query_id, decoded.query_id);
        assert_eq!(original.success, decoded.success);
        assert!(decoded.ipv4_addrs.is_empty());
        assert!(decoded.ipv6_addrs.is_empty());
        assert_eq!(original.ttl, decoded.ttl);
        assert_eq!(original.error, decoded.error);
    }

    #[test]
    fn test_invalid_utf8_domain() {
        // Create a DnsQuery with invalid UTF-8 in domain
        let mut encoded = vec![TYPE_DNS_QUERY];
        encoded.extend_from_slice(&1u64.to_be_bytes()); // query_id
        encoded.extend_from_slice(&1u16.to_be_bytes()); // query_type = 1
        encoded.push(4); // domain_len = 4
        encoded.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]); // invalid UTF-8

        assert!(decode_dns_query(&encoded).is_err());
    }

    #[test]
    fn test_proxy_data_batch_roundtrip_empty() {
        let original = ProxyDataBatch { items: vec![] };

        let encoded = encode_proxy_data_batch(&original);
        let decoded = decode_proxy_data_batch(&encoded).expect("decode failed");

        assert_eq!(original.items.len(), decoded.items.len());
    }

    #[test]
    fn test_proxy_data_batch_roundtrip_single() {
        let original = ProxyDataBatch {
            items: vec![ProxyDataBatchItem {
                connection_id: 12345,
                data: vec![0x01, 0x02, 0x03, 0x04],
                close: false,
            }],
        };

        let encoded = encode_proxy_data_batch(&original);
        let decoded = decode_proxy_data_batch(&encoded).expect("decode failed");

        assert_eq!(original.items.len(), decoded.items.len());
        assert_eq!(
            original.items[0].connection_id,
            decoded.items[0].connection_id
        );
        assert_eq!(original.items[0].data, decoded.items[0].data);
        assert_eq!(original.items[0].close, decoded.items[0].close);
    }

    #[test]
    fn test_proxy_data_batch_roundtrip_multiple() {
        let original = ProxyDataBatch {
            items: vec![
                ProxyDataBatchItem {
                    connection_id: 1,
                    data: vec![0x01, 0x02],
                    close: false,
                },
                ProxyDataBatchItem {
                    connection_id: 2,
                    data: vec![0x03, 0x04, 0x05],
                    close: false,
                },
                ProxyDataBatchItem {
                    connection_id: 3,
                    data: vec![],
                    close: true,
                },
            ],
        };

        let encoded = encode_proxy_data_batch(&original);
        let decoded = decode_proxy_data_batch(&encoded).expect("decode failed");

        assert_eq!(original.items.len(), decoded.items.len());
        for (i, item) in original.items.iter().enumerate() {
            assert_eq!(item.connection_id, decoded.items[i].connection_id);
            assert_eq!(item.data, decoded.items[i].data);
            assert_eq!(item.close, decoded.items[i].close);
        }
    }

    #[test]
    fn test_proxy_data_batch_large_payload() {
        let original = ProxyDataBatch {
            items: vec![
                ProxyDataBatchItem {
                    connection_id: 1,
                    data: vec![0xAB; 10000],
                    close: false,
                },
                ProxyDataBatchItem {
                    connection_id: 2,
                    data: vec![0xCD; 5000],
                    close: false,
                },
            ],
        };

        let encoded = encode_proxy_data_batch(&original);
        let decoded = decode_proxy_data_batch(&encoded).expect("decode failed");

        assert_eq!(original.items.len(), decoded.items.len());
        assert_eq!(original.items[0].data, decoded.items[0].data);
        assert_eq!(original.items[1].data, decoded.items[1].data);
    }

    #[test]
    fn test_proxy_data_batch_many_items() {
        let mut items = Vec::new();
        for i in 0..100 {
            items.push(ProxyDataBatchItem {
                connection_id: i as u64,
                data: vec![i as u8],
                close: i == 99,
            });
        }

        let original = ProxyDataBatch { items };

        let encoded = encode_proxy_data_batch(&original);
        let decoded = decode_proxy_data_batch(&encoded).expect("decode failed");

        assert_eq!(original.items.len(), decoded.items.len());
        for (i, item) in original.items.iter().enumerate() {
            assert_eq!(item.connection_id, decoded.items[i].connection_id);
            assert_eq!(item.data, decoded.items[i].data);
            assert_eq!(item.close, decoded.items[i].close);
        }
    }
}
