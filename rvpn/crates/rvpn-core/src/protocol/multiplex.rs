//! Multiplexed frame protocol for R-VPN
//!
//! This module provides frame-level multiplexing over a single WebSocket connection.
//! Frames are tagged with a flow_id to distinguish between different data streams.
//!
//! Frame format:
//! ```text
//! [flow_id: 4 bytes (big-endian)]
//! [payload_len: 2 bytes (big-endian)]
//! [payload: N bytes]
//! ```
//!
//! Control messages use flow_id = 0 and contain serialized ControlMessage payloads.

use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::io::Cursor;

/// Maximum payload size for a single frame (65KB)
pub const MAX_PAYLOAD_SIZE: usize = 65535;

/// Flow ID for control messages
pub const CONTROL_FLOW_ID: u32 = 0;

/// Multiplexed frame for transport over WebSocket
///
/// Frames are used to multiplex multiple data streams over a single connection.
/// Each frame carries data for a specific flow identified by `flow_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiplexedFrame {
    /// Flow identifier (0 = control channel, >0 = data flows)
    pub flow_id: u32,
    /// Frame payload
    pub payload: Bytes,
}

/// Control messages sent on flow_id = 0
///
/// Control messages manage the lifecycle of flows and maintain connection health.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ControlMessage {
    /// Create a new flow to the specified target
    CreateFlow {
        /// Unique flow identifier
        flow_id: u32,
        /// Target host (IP or domain)
        target: String,
        /// Target port
        port: u16,
    },
    /// Close an existing flow
    CloseFlow {
        /// Flow identifier to close
        flow_id: u32,
    },
    /// Flow created successfully
    FlowCreated {
        /// Flow identifier
        flow_id: u32,
        /// Local port assigned (if applicable)
        local_port: Option<u16>,
    },
    /// Flow creation failed
    FlowFailed {
        /// Flow identifier
        flow_id: u32,
        /// Error message
        error: String,
    },
    /// Ping for keepalive
    Ping {
        /// Unix timestamp in milliseconds
        timestamp: u64,
    },
    /// Pong response
    Pong {
        /// Unix timestamp in milliseconds (echoed from Ping)
        timestamp: u64,
    },
    /// Flow window update (flow control)
    WindowUpdate {
        /// Flow identifier
        flow_id: u32,
        /// New window size in bytes
        window_size: u32,
    },
}

/// Error type for multiplexing operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiplexError {
    /// Frame too large
    FrameTooLarge {
        /// Actual size of the frame payload
        size: usize,
        /// Maximum allowed payload size
        max: usize,
    },
    /// Invalid frame format
    InvalidFrame(String),
    /// Incomplete data
    IncompleteData {
        /// Expected number of bytes
        expected: usize,
        /// Actual number of bytes received
        actual: usize,
    },
    /// Control message serialization error
    SerializationError(String),
}

impl std::fmt::Display for MultiplexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MultiplexError::FrameTooLarge { size, max } => {
                write!(f, "Frame payload too large: {} bytes (max: {})", size, max)
            }
            MultiplexError::InvalidFrame(msg) => write!(f, "Invalid frame format: {}", msg),
            MultiplexError::IncompleteData { expected, actual } => {
                write!(
                    f,
                    "Incomplete frame data: expected {} bytes, got {}",
                    expected, actual
                )
            }
            MultiplexError::SerializationError(msg) => {
                write!(f, "Serialization error: {}", msg)
            }
        }
    }
}

impl std::error::Error for MultiplexError {}

impl MultiplexedFrame {
    /// Create a new data frame
    pub fn new_data(flow_id: u32, payload: impl Into<Bytes>) -> Self {
        Self {
            flow_id,
            payload: payload.into(),
        }
    }

    /// Create a control frame
    pub fn new_control(message: &ControlMessage) -> Result<Self, MultiplexError> {
        let payload = bincode::serialize(message)
            .map_err(|e| MultiplexError::SerializationError(e.to_string()))?;
        Ok(Self {
            flow_id: CONTROL_FLOW_ID,
            payload: Bytes::from(payload),
        })
    }

    /// Encode frame to bytes
    ///
    /// Format: [flow_id: 4 bytes][payload_len: 2 bytes][payload: N bytes]
    pub fn encode(&self) -> Result<Bytes, MultiplexError> {
        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(MultiplexError::FrameTooLarge {
                size: self.payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }

        let mut buf = BytesMut::with_capacity(6 + self.payload.len());
        buf.put_u32(self.flow_id);
        buf.put_u16(self.payload.len() as u16);
        buf.extend_from_slice(&self.payload);

        Ok(buf.freeze())
    }

    /// Encode frame into an existing buffer (zero-allocation path)
    pub fn encode_to(&self, dst: &mut BytesMut) -> Result<(), MultiplexError> {
        if self.payload.len() > MAX_PAYLOAD_SIZE {
            return Err(MultiplexError::FrameTooLarge {
                size: self.payload.len(),
                max: MAX_PAYLOAD_SIZE,
            });
        }

        dst.reserve(6 + self.payload.len());
        dst.put_u32(self.flow_id);
        dst.put_u16(self.payload.len() as u16);
        dst.extend_from_slice(&self.payload);

        Ok(())
    }

    /// Decode frame from bytes
    pub fn decode(data: &[u8]) -> Result<Self, MultiplexError> {
        if data.len() < 6 {
            return Err(MultiplexError::IncompleteData {
                expected: 6,
                actual: data.len(),
            });
        }

        let mut cursor = Cursor::new(data);
        let flow_id = cursor.get_u32();
        let payload_len = cursor.get_u16() as usize;

        if data.len() < 6 + payload_len {
            return Err(MultiplexError::IncompleteData {
                expected: 6 + payload_len,
                actual: data.len(),
            });
        }

        let payload = Bytes::copy_from_slice(&data[6..6 + payload_len]);

        Ok(Self { flow_id, payload })
    }

    /// Decode frame from buffer without copying (returns remaining data)
    pub fn decode_from_buffer(buf: &mut BytesMut) -> Result<Option<Self>, MultiplexError> {
        if buf.len() < 6 {
            return Ok(None);
        }

        let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
        let total_len = 6 + payload_len;

        if buf.len() < total_len {
            return Ok(None);
        }

        let flow_id = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

        // Split the buffer to get the frame data
        let frame_buf = buf.split_to(total_len);

        // Extract the payload from the frame (skip 6-byte header)
        let payload = Bytes::copy_from_slice(&frame_buf[6..]);

        Ok(Some(Self { flow_id, payload }))
    }

    /// Check if this is a control frame
    pub fn is_control(&self) -> bool {
        self.flow_id == CONTROL_FLOW_ID
    }

    /// Parse control message from payload
    pub fn parse_control(&self) -> Result<ControlMessage, MultiplexError> {
        if !self.is_control() {
            return Err(MultiplexError::InvalidFrame(
                "Not a control frame".to_string(),
            ));
        }

        bincode::deserialize(&self.payload)
            .map_err(|e| MultiplexError::SerializationError(e.to_string()))
    }

    /// Get total frame size including header
    pub fn frame_size(&self) -> usize {
        6 + self.payload.len()
    }
}

/// Parse multiple frames from a buffer
///
/// Returns parsed frames and the number of bytes consumed.
/// Parsing stops on an invalid frame or incomplete data.
pub fn parse_frames(data: &[u8]) -> (Vec<MultiplexedFrame>, usize) {
    let mut frames = Vec::new();
    let mut pos = 0;

    while pos + 6 <= data.len() {
        let payload_len = u16::from_be_bytes([data[pos + 4], data[pos + 5]]) as usize;
        let total_len = 6 + payload_len;

        if pos + total_len > data.len() {
            break;
        }

        if let Ok(frame) = MultiplexedFrame::decode(&data[pos..pos + total_len]) {
            frames.push(frame);
            pos += total_len;
        } else {
            // Invalid frame -- stop parsing and return what we have so far
            break;
        }
    }

    (frames, pos)
}

/// Frame encoder/decoder for streaming
#[derive(Debug, Default)]
pub struct FrameCodec {
    buffer: BytesMut,
}

impl FrameCodec {
    /// Create a new codec
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::with_capacity(8192),
        }
    }

    /// Create a new codec with specified buffer capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
        }
    }

    /// Feed data into the codec buffer
    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Try to decode the next frame
    pub fn decode_next(&mut self) -> Result<Option<MultiplexedFrame>, MultiplexError> {
        if self.buffer.len() < 6 {
            return Ok(None);
        }

        let payload_len = u16::from_be_bytes([self.buffer[4], self.buffer[5]]) as usize;
        let total_len = 6 + payload_len;

        if self.buffer.len() < total_len {
            return Ok(None);
        }

        let frame_data = self.buffer.split_to(total_len);
        let flow_id =
            u32::from_be_bytes([frame_data[0], frame_data[1], frame_data[2], frame_data[3]]);
        let payload = Bytes::copy_from_slice(&frame_data[6..]);

        Ok(Some(MultiplexedFrame { flow_id, payload }))
    }

    /// Encode a frame
    pub fn encode(&mut self, frame: &MultiplexedFrame) -> Result<Bytes, MultiplexError> {
        frame.encode()
    }

    /// Get current buffer length
    pub fn buffer_len(&self) -> usize {
        self.buffer.len()
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frame_encode_decode() {
        let frame = MultiplexedFrame::new_data(42, Bytes::from_static(b"hello world"));
        let encoded = frame.encode().unwrap();

        assert_eq!(encoded.len(), 6 + 11);
        assert_eq!(&encoded[0..4], &42u32.to_be_bytes());
        assert_eq!(&encoded[4..6], &11u16.to_be_bytes());
        assert_eq!(&encoded[6..], b"hello world");

        let decoded = MultiplexedFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.flow_id, 42);
        assert_eq!(decoded.payload, Bytes::from_static(b"hello world"));
    }

    #[test]
    fn test_control_frame() {
        let msg = ControlMessage::Ping { timestamp: 12345 };
        let frame = MultiplexedFrame::new_control(&msg).unwrap();

        assert!(frame.is_control());
        let decoded_msg = frame.parse_control().unwrap();
        assert_eq!(decoded_msg, msg);
    }

    #[test]
    fn test_create_flow_control() {
        let msg = ControlMessage::CreateFlow {
            flow_id: 123,
            target: "example.com".to_string(),
            port: 443,
        };
        let frame = MultiplexedFrame::new_control(&msg).unwrap();
        let decoded = frame.parse_control().unwrap();

        match decoded {
            ControlMessage::CreateFlow {
                flow_id,
                target,
                port,
            } => {
                assert_eq!(flow_id, 123);
                assert_eq!(target, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("Expected CreateFlow"),
        }
    }

    #[test]
    fn test_frame_too_large() {
        let large_payload = vec![0u8; MAX_PAYLOAD_SIZE + 1];
        let frame = MultiplexedFrame::new_data(1, large_payload);
        assert!(matches!(
            frame.encode(),
            Err(MultiplexError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn test_incomplete_data() {
        let result = MultiplexedFrame::decode(&[0, 0, 0, 1]);
        assert!(matches!(result, Err(MultiplexError::IncompleteData { .. })));
    }

    #[test]
    fn test_parse_multiple_frames() {
        let frame1 = MultiplexedFrame::new_data(1, Bytes::from_static(b"first"));
        let frame2 = MultiplexedFrame::new_data(2, Bytes::from_static(b"second"));
        let frame3 = MultiplexedFrame::new_data(3, Bytes::from_static(b"third"));

        let mut data = BytesMut::new();
        frame1.encode_to(&mut data).unwrap();
        frame2.encode_to(&mut data).unwrap();
        frame3.encode_to(&mut data).unwrap();

        let (frames, consumed) = parse_frames(&data);
        assert_eq!(frames.len(), 3);
        assert_eq!(consumed, data.len());
        assert_eq!(frames[0].flow_id, 1);
        assert_eq!(frames[1].flow_id, 2);
        assert_eq!(frames[2].flow_id, 3);
    }

    #[test]
    fn test_codec_decode_next() {
        let mut codec = FrameCodec::new();
        let frame = MultiplexedFrame::new_data(42, Bytes::from_static(b"test data"));
        let encoded = frame.encode().unwrap();

        codec.feed(&encoded);

        let decoded = codec.decode_next().unwrap().unwrap();
        assert_eq!(decoded.flow_id, 42);
        assert_eq!(decoded.payload, Bytes::from_static(b"test data"));
    }

    #[test]
    fn test_flow_created_control() {
        let msg = ControlMessage::FlowCreated {
            flow_id: 100,
            local_port: Some(8080),
        };
        let frame = MultiplexedFrame::new_control(&msg).unwrap();
        let decoded = frame.parse_control().unwrap();

        match decoded {
            ControlMessage::FlowCreated {
                flow_id,
                local_port,
            } => {
                assert_eq!(flow_id, 100);
                assert_eq!(local_port, Some(8080));
            }
            _ => panic!("Expected FlowCreated"),
        }
    }

    #[test]
    fn test_window_update_control() {
        let msg = ControlMessage::WindowUpdate {
            flow_id: 42,
            window_size: 65536,
        };
        let frame = MultiplexedFrame::new_control(&msg).unwrap();
        let decoded = frame.parse_control().unwrap();

        match decoded {
            ControlMessage::WindowUpdate {
                flow_id,
                window_size,
            } => {
                assert_eq!(flow_id, 42);
                assert_eq!(window_size, 65536);
            }
            _ => panic!("Expected WindowUpdate"),
        }
    }

    #[test]
    fn test_ping_pong_timestamp() {
        let ping = ControlMessage::Ping {
            timestamp: 1234567890,
        };
        let ping_frame = MultiplexedFrame::new_control(&ping).unwrap();
        let decoded_ping = ping_frame.parse_control().unwrap();

        match decoded_ping {
            ControlMessage::Ping { timestamp } => assert_eq!(timestamp, 1234567890),
            _ => panic!("Expected Ping"),
        }

        let pong = ControlMessage::Pong {
            timestamp: 1234567890,
        };
        let pong_frame = MultiplexedFrame::new_control(&pong).unwrap();
        let decoded_pong = pong_frame.parse_control().unwrap();

        match decoded_pong {
            ControlMessage::Pong { timestamp } => assert_eq!(timestamp, 1234567890),
            _ => panic!("Expected Pong"),
        }
    }
}
