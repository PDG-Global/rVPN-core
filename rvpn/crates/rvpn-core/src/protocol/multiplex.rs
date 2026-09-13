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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

/// Maximum payload size for a single frame (65KB)
pub const MAX_PAYLOAD_SIZE: usize = 65535;

/// Flow ID for control messages
pub const CONTROL_FLOW_ID: u32 = 0;

/// Initial per-flow receive window in bytes for credit-based flow control.
///
/// Every flow direction starts with this many credits on the SENDER side.
/// The sender consumes one credit per payload byte sent and is topped up by
/// `ControlMessage::WindowUpdate` grants from the receiver as it drains the
/// flow into the local/target socket. This bounds the in-flight data per
/// flow per direction to `INITIAL_FLOW_WINDOW` bytes, so a bulk flow can
/// never fill the shared session queue ahead of interactive flows.
pub const INITIAL_FLOW_WINDOW: u32 = 256 * 1024;

/// How long a flow's data sender may sit at zero credits before the flow is
/// considered dead and closed with `CloseFlow`.
///
/// Safety valve for protocol skew: peers built before flow control ignore
/// `WindowUpdate` and never grant credits, which would otherwise stall the
/// flow forever after the initial window is exhausted. Client and server are
/// deployed together, so this is purely defensive.
pub const FLOW_CREDIT_STALL_TIMEOUT: Duration = Duration::from_secs(60);

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
    ///
    /// `window_size` is a DELTA, not an absolute window: it grants the
    /// sender this many additional bytes of credit for the flow. Receivers
    /// emit it after writing N consumed bytes to the local/target socket;
    /// senders add it to their remaining credit balance.
    WindowUpdate {
        /// Flow identifier
        flow_id: u32,
        /// Number of credits (bytes) being granted to the sender
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

/// Per-flow, per-direction send credit gate for flow control.
///
/// Outcome of [`FlowSendCredits::wait_for_credit_or_stall`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreditWait {
    /// Credits are available — continue sending.
    Granted,
    /// The flow was closed while the sender was parked (CloseFlow received,
    /// local socket closed, tunnel shutdown). Exit quietly — this is normal
    /// teardown, not a stall.
    Closed,
    /// `stall_timeout` elapsed at zero credits on a live flow. Treat as a
    /// dead flow: log and close it (see [`FLOW_CREDIT_STALL_TIMEOUT`]).
    Stalled,
}

/// The data sender side of a flow direction owns one of these. It starts
/// with [`INITIAL_FLOW_WINDOW`] credits, consumes one credit per payload
/// byte sent, and is topped up via [`FlowSendCredits::grant`] when the peer's
/// `WindowUpdate` control messages arrive. When credits reach zero the
/// sender must stop reading from its source socket — TCP backpressure on
/// that socket then throttles the actual producer.
///
/// Cheap to share: clone an `Arc<FlowSendCredits>` into the send task and
/// keep one in the flow table for the `WindowUpdate` receive path. There is
/// exactly one consumer (the send task) and potentially many granters (the
/// control-message dispatcher), so a simple atomic counter suffices.
#[derive(Debug)]
pub struct FlowSendCredits {
    credits: AtomicU64,
    /// Set by [`FlowSendCredits::close`] when the flow is torn down, so a
    /// sender parked at zero credits wakes immediately instead of waiting
    /// out the stall timeout.
    closed: AtomicBool,
    notify: tokio::sync::Notify,
}

impl Default for FlowSendCredits {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowSendCredits {
    /// Create a gate with the full initial window.
    pub fn new() -> Self {
        Self {
            credits: AtomicU64::new(INITIAL_FLOW_WINDOW as u64),
            closed: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        }
    }

    /// Credits currently available for sending, in bytes.
    pub fn available(&self) -> u64 {
        self.credits.load(Ordering::Acquire)
    }

    /// Consume up to `max` bytes of credit.
    ///
    /// Returns the amount actually consumed: `min(max, available)`, or 0 if
    /// the window is exhausted. The caller must send at most the returned
    /// number of bytes.
    pub fn try_consume(&self, max: u64) -> u64 {
        let mut current = self.credits.load(Ordering::Acquire);
        loop {
            if current == 0 {
                return 0;
            }
            let take = current.min(max);
            match self.credits.compare_exchange_weak(
                current,
                current - take,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return take,
                Err(actual) => current = actual,
            }
        }
    }

    /// Grant `n` bytes of credit (from a peer `WindowUpdate`) and wake the
    /// sender if it is parked in [`FlowSendCredits::wait_for_credit`].
    pub fn grant(&self, n: u64) {
        // Saturating: a misbehaving peer granting unbounded credits must not
        // wrap the counter and corrupt accounting.
        let _ = self
            .credits
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |c| {
                Some(c.saturating_add(n))
            });
        self.notify.notify_one();
    }

    /// Wait until at least one credit is available.
    ///
    /// Only correct with a single waiter (the flow's send task); `grant`
    /// uses `notify_one`, which stores a permit when nobody is waiting, so
    /// the check-then-wait race cannot lose a wakeup.
    pub async fn wait_for_credit(&self) {
        loop {
            if self.available() > 0 {
                return;
            }
            self.notify.notified().await;
        }
    }

    /// Signal that the flow is closed: a sender parked in
    /// [`FlowSendCredits::wait_for_credit_or_stall`] wakes immediately and
    /// gets [`CreditWait::Closed`] instead of waiting out the stall timeout.
    ///
    /// Uses `notify_one` (not `notify_waiters`) deliberately: the gate has a
    /// single waiter by contract, and `notify_one` stores a permit when
    /// nobody is waiting yet, so a `close()` racing a just-parked waiter can
    /// never lose the wakeup.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_one();
    }

    /// Whether [`FlowSendCredits::close`] has been called.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Wait for credits, giving up after `stall_timeout`.
    ///
    /// Returns [`CreditWait::Granted`] when credits are available,
    /// [`CreditWait::Closed`] when the flow was closed while parked (normal
    /// teardown — the caller should exit quietly), or [`CreditWait::Stalled`]
    /// when `stall_timeout` elapsed at zero credits on a live flow.
    pub async fn wait_for_credit_or_stall(&self, stall_timeout: Duration) -> CreditWait {
        let wait = async {
            loop {
                if self.available() > 0 {
                    return CreditWait::Granted;
                }
                if self.is_closed() {
                    return CreditWait::Closed;
                }
                self.notify.notified().await;
            }
        };
        match tokio::time::timeout(stall_timeout, wait).await {
            Ok(state) => state,
            // A close racing the timeout expiry is teardown, not a stall.
            Err(_) => {
                if self.is_closed() {
                    CreditWait::Closed
                } else {
                    CreditWait::Stalled
                }
            }
        }
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

    // ── FlowSendCredits (per-flow flow control) ─────────────────────

    #[test]
    fn test_flow_credits_initial_window() {
        let credits = FlowSendCredits::new();
        assert_eq!(credits.available(), INITIAL_FLOW_WINDOW as u64);
    }

    #[test]
    fn test_flow_credits_consume_stops_at_zero() {
        let credits = FlowSendCredits::new();

        // Partial consume leaves the remainder.
        let taken = credits.try_consume(1024);
        assert_eq!(taken, 1024);
        assert_eq!(credits.available(), INITIAL_FLOW_WINDOW as u64 - 1024);

        // Consuming more than available is clamped to what remains...
        let rest = credits.try_consume(u64::MAX);
        assert_eq!(rest, INITIAL_FLOW_WINDOW as u64 - 1024);
        assert_eq!(credits.available(), 0);

        // ...and at zero the sender must stop.
        assert_eq!(credits.try_consume(1), 0);
    }

    #[test]
    fn test_flow_credits_grant_resumes_sending() {
        let credits = FlowSendCredits::new();
        let window = INITIAL_FLOW_WINDOW as u64;

        // Drain the whole window.
        assert_eq!(credits.try_consume(window), window);
        assert_eq!(credits.try_consume(1), 0);

        // A WindowUpdate grant tops the sender back up.
        credits.grant(4096);
        assert_eq!(credits.available(), 4096);
        assert_eq!(credits.try_consume(8192), 4096);
        assert_eq!(credits.available(), 0);
    }

    #[test]
    fn test_flow_credits_grant_saturates() {
        let credits = FlowSendCredits::new();
        credits.grant(u64::MAX);
        assert_eq!(credits.available(), u64::MAX);
        credits.grant(1);
        assert_eq!(credits.available(), u64::MAX, "grants must not wrap");
    }

    #[tokio::test]
    async fn test_flow_credits_wait_wakes_on_grant() {
        use std::sync::Arc;

        let credits = Arc::new(FlowSendCredits::new());
        assert_eq!(credits.try_consume(INITIAL_FLOW_WINDOW as u64), INITIAL_FLOW_WINDOW as u64);

        let waiter = tokio::spawn({
            let credits = Arc::clone(&credits);
            async move {
                credits.wait_for_credit().await;
                credits.available()
            }
        });

        // Let the waiter park, then grant.
        tokio::task::yield_now().await;
        credits.grant(100);

        let available = tokio::time::timeout(Duration::from_secs(5), waiter)
            .await
            .expect("wait_for_credit never woke after grant")
            .expect("waiter task panicked");
        assert_eq!(available, 100);
    }

    /// Regression: a receiver that never sends WindowUpdate stalls the
    /// sender; the stall valve must report the stall after the timeout so
    /// the caller can close the flow.
    #[tokio::test(start_paused = true)]
    async fn test_flow_credits_stall_valve() {
        let credits = FlowSendCredits::new();
        assert_eq!(credits.try_consume(INITIAL_FLOW_WINDOW as u64), INITIAL_FLOW_WINDOW as u64);

        // No grants at all: the valve must trip after the stall timeout.
        let state = credits
            .wait_for_credit_or_stall(FLOW_CREDIT_STALL_TIMEOUT)
            .await;
        assert_eq!(state, CreditWait::Stalled, "stalled gate must report the stall");

        // A grant before the deadline must prevent the valve from tripping.
        let drained = std::sync::Arc::new(FlowSendCredits::new());
        assert_eq!(
            drained.try_consume(INITIAL_FLOW_WINDOW as u64),
            INITIAL_FLOW_WINDOW as u64
        );
        tokio::spawn({
            let drained = std::sync::Arc::clone(&drained);
            async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                drained.grant(64);
            }
        });
        assert_eq!(
            drained
                .wait_for_credit_or_stall(FLOW_CREDIT_STALL_TIMEOUT)
                .await,
            CreditWait::Granted,
            "grant before the deadline must resume the sender"
        );

        // Credits available immediately (non-zero window) short-circuit.
        let fresh = FlowSendCredits::new();
        assert_eq!(
            fresh
                .wait_for_credit_or_stall(FLOW_CREDIT_STALL_TIMEOUT)
                .await,
            CreditWait::Granted
        );
    }

    /// Regression: closing the flow must wake a sender parked at zero
    /// credits IMMEDIATELY with `CreditWait::Closed` — before this signal,
    /// every flow close (CloseFlow, local socket close, tunnel shutdown)
    /// left parked senders sitting until the 60s stall valve, firing a
    /// misleading stall warning for an already-dead flow.
    #[tokio::test(start_paused = true)]
    async fn test_flow_credits_close_wakes_parked_waiter() {
        use std::sync::Arc;

        let credits = Arc::new(FlowSendCredits::new());
        assert_eq!(
            credits.try_consume(INITIAL_FLOW_WINDOW as u64),
            INITIAL_FLOW_WINDOW as u64
        );

        let waiter = tokio::spawn({
            let credits = Arc::clone(&credits);
            async move { credits.wait_for_credit_or_stall(FLOW_CREDIT_STALL_TIMEOUT).await }
        });

        // Let the waiter park, then close the flow mid-park.
        tokio::task::yield_now().await;
        credits.close();
        assert!(credits.is_closed());

        // Prompt wake: well under the 60s stall timeout.
        let state = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("parked waiter must wake on close")
            .expect("waiter task panicked");
        assert_eq!(state, CreditWait::Closed);

        // A gate closed before any wait also reports Closed, not Stalled.
        let preclosed = FlowSendCredits::new();
        preclosed.try_consume(INITIAL_FLOW_WINDOW as u64);
        preclosed.close();
        assert_eq!(
            preclosed
                .wait_for_credit_or_stall(FLOW_CREDIT_STALL_TIMEOUT)
                .await,
            CreditWait::Closed
        );
    }
}
