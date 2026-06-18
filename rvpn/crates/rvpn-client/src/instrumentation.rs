//! Instrumentation helpers for performance monitoring
//!
//! This module provides convenient traits and macros for instrumenting
//! the R-VPN client code with performance metrics.
//!
//! ## Usage Examples
//!
//! ### Basic function timing:
//! ```rust,ignore
//! use rvpn_client::instrumentation::MetricsInstrumentation;
//! use rvpn_client::metrics::Metrics;
//! use std::sync::Arc;
//!
//! async fn my_function(metrics: Arc<Metrics>) {
//!     let _timer = metrics.time_dns_lookup();
//!     // ... do DNS lookup ...
//! }
//! ```
//!
//! ### Connection tracking:
//! ```rust
//! use rvpn_client::instrumentation::ConnectionTracker;
//!
//! async fn handle_connection(tracker: &ConnectionTracker) {
//!     let _guard = tracker.track_socks5_connection();
//!     // ... handle connection ...
//! }
//! ```

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::metrics::{ErrorType, Metrics};

/// Timer guard for automatic latency recording
///
/// When dropped, this records the elapsed time to the specified histogram.
pub struct MetricsTimer {
    start: Instant,
    metrics: Arc<Metrics>,
    operation: TimerOperation,
}

/// Types of operations that can be timed
#[derive(Debug, Clone, Copy)]
enum TimerOperation {
    DnsLookup,
    Encryption,
    Decryption,
    WebSocketSend,
    WebSocketReceive,
    RoutingDecision,
    Socks5Connect,
    ProxyConnect,
    SplitTunnelLookup,
}

impl MetricsTimer {
    /// Create a new timer for the specified operation
    fn new(metrics: Arc<Metrics>, operation: TimerOperation) -> Self {
        Self {
            start: Instant::now(),
            metrics,
            operation,
        }
    }

    /// Record the elapsed time
    fn record_elapsed(&self) {
        let elapsed_micros = self.start.elapsed().as_micros() as u64;

        match self.operation {
            TimerOperation::DnsLookup => {
                self.metrics.latency.dns_lookup.record(elapsed_micros);
            }
            TimerOperation::Encryption => {
                self.metrics.latency.encryption.record(elapsed_micros);
                self.metrics.crypto.record_encryption(elapsed_micros);
            }
            TimerOperation::Decryption => {
                self.metrics.latency.decryption.record(elapsed_micros);
                self.metrics.crypto.record_decryption(elapsed_micros);
            }
            TimerOperation::WebSocketSend => {
                self.metrics.latency.websocket_send.record(elapsed_micros);
                self.metrics.websocket.record_send_latency(elapsed_micros);
            }
            TimerOperation::WebSocketReceive => {
                self.metrics
                    .latency
                    .websocket_receive
                    .record(elapsed_micros);
            }
            TimerOperation::RoutingDecision => {
                self.metrics.latency.routing_decision.record(elapsed_micros);
            }
            TimerOperation::Socks5Connect => {
                self.metrics.latency.socks5_connect.record(elapsed_micros);
            }
            TimerOperation::ProxyConnect => {
                self.metrics.latency.proxy_connect.record(elapsed_micros);
            }
            TimerOperation::SplitTunnelLookup => {
                self.metrics
                    .latency
                    .split_tunnel_lookup
                    .record(elapsed_micros);
                self.metrics
                    .split_tunnel
                    .decision_latency
                    .record(elapsed_micros);
            }
        }
    }
}

impl Drop for MetricsTimer {
    fn drop(&mut self) {
        self.record_elapsed();
    }
}

/// Trait for adding instrumentation methods to Metrics
pub trait MetricsInstrumentation {
    /// Time a DNS lookup operation
    fn time_dns_lookup(self: &Arc<Self>) -> MetricsTimer;

    /// Time an encryption operation
    fn time_encryption(self: &Arc<Self>) -> MetricsTimer;

    /// Time a decryption operation
    fn time_decryption(self: &Arc<Self>) -> MetricsTimer;

    /// Time a WebSocket send operation
    fn time_websocket_send(self: &Arc<Self>) -> MetricsTimer;

    /// Time a WebSocket receive operation
    fn time_websocket_receive(self: &Arc<Self>) -> MetricsTimer;

    /// Time a routing decision operation
    fn time_routing_decision(self: &Arc<Self>) -> MetricsTimer;

    /// Time a SOCKS5 connection setup
    fn time_socks5_connect(self: &Arc<Self>) -> MetricsTimer;

    /// Time a proxy connection through tunnel
    fn time_proxy_connect(self: &Arc<Self>) -> MetricsTimer;

    /// Time a split tunnel lookup
    fn time_split_tunnel_lookup(self: &Arc<Self>) -> MetricsTimer;

    /// Record bytes sent through tunnel
    fn record_bytes_sent(&self, bytes: u64);

    /// Record bytes received through tunnel
    fn record_bytes_received(&self, bytes: u64);

    /// Record a message sent
    fn record_message_sent(&self);

    /// Record a message received
    fn record_message_received(&self);

    /// Record an error
    fn record_error(&self, error_type: ErrorType);

    /// Record a SOCKS5 connection accepted
    fn record_socks5_connection_accepted(&self);

    /// Record a SOCKS5 connection completed
    fn record_socks5_connection_completed(&self);

    /// Record a SOCKS5 routing decision
    fn record_socks5_routing(
        &self,
        tunneled: bool,
        bypassed: bool,
        blocked: bool,
        latency: Duration,
    );

    /// Record DNS lookup (with cache hit info)
    fn record_dns_lookup(&self, cache_hit: bool, latency: Duration);

    /// Record DNS error
    fn record_dns_error(&self);

    /// Record WebSocket message sent with bytes
    fn record_websocket_sent(&self, bytes: u64);

    /// Record WebSocket message received with bytes
    fn record_websocket_received(&self, bytes: u64);

    /// Record WebSocket connection attempt
    fn record_websocket_connection_attempt(&self);

    /// Record WebSocket connection success
    fn record_websocket_connection_success(&self, latency: Duration);

    /// Record WebSocket connection failure
    fn record_websocket_connection_failure(&self);

    /// Increment active connections gauge
    fn increment_active_connections(&self);

    /// Decrement active connections gauge
    fn decrement_active_connections(&self);

    /// Increment active proxy connections gauge
    fn increment_active_proxy_connections(&self);

    /// Decrement active proxy connections gauge
    fn decrement_active_proxy_connections(&self);

    /// Set crypto queue depth
    fn set_crypto_queue_depth(&self, depth: u64);

    /// Set WebSocket queue depth
    fn set_websocket_queue_depth(&self, depth: u64);

    /// Set DNS cache size
    fn set_dns_cache_size(&self, size: u64);

    /// Set reorder buffer depth
    fn set_reorder_buffer_depth(&self, depth: u64);
}

impl MetricsInstrumentation for Metrics {
    fn time_dns_lookup(self: &Arc<Self>) -> MetricsTimer {
        MetricsTimer::new(Arc::clone(self), TimerOperation::DnsLookup)
    }

    fn time_encryption(self: &Arc<Self>) -> MetricsTimer {
        MetricsTimer::new(Arc::clone(self), TimerOperation::Encryption)
    }

    fn time_decryption(self: &Arc<Self>) -> MetricsTimer {
        MetricsTimer::new(Arc::clone(self), TimerOperation::Decryption)
    }

    fn time_websocket_send(self: &Arc<Self>) -> MetricsTimer {
        MetricsTimer::new(Arc::clone(self), TimerOperation::WebSocketSend)
    }

    fn time_websocket_receive(self: &Arc<Self>) -> MetricsTimer {
        MetricsTimer::new(Arc::clone(self), TimerOperation::WebSocketReceive)
    }

    fn time_routing_decision(self: &Arc<Self>) -> MetricsTimer {
        MetricsTimer::new(Arc::clone(self), TimerOperation::RoutingDecision)
    }

    fn time_socks5_connect(self: &Arc<Self>) -> MetricsTimer {
        MetricsTimer::new(Arc::clone(self), TimerOperation::Socks5Connect)
    }

    fn time_proxy_connect(self: &Arc<Self>) -> MetricsTimer {
        MetricsTimer::new(Arc::clone(self), TimerOperation::ProxyConnect)
    }

    fn time_split_tunnel_lookup(self: &Arc<Self>) -> MetricsTimer {
        MetricsTimer::new(Arc::clone(self), TimerOperation::SplitTunnelLookup)
    }

    fn record_bytes_sent(&self, bytes: u64) {
        self.throughput.record_bytes_sent(bytes);
    }

    fn record_bytes_received(&self, bytes: u64) {
        self.throughput.record_bytes_received(bytes);
    }

    fn record_message_sent(&self) {
        self.throughput.record_message_sent();
    }

    fn record_message_received(&self) {
        self.throughput.record_message_received();
    }

    fn record_error(&self, error_type: ErrorType) {
        self.errors.record_error(error_type);
    }

    fn record_socks5_connection_accepted(&self) {
        self.socks5.connections_accepted.increment();
        self.resources.active_connections.increment();
    }

    fn record_socks5_connection_completed(&self) {
        self.socks5.connections_completed.increment();
        self.resources.active_connections.decrement();
    }

    fn record_socks5_routing(
        &self,
        tunneled: bool,
        bypassed: bool,
        blocked: bool,
        latency: Duration,
    ) {
        self.split_tunnel
            .record_decision(tunneled, bypassed, blocked, latency.as_micros() as u64);

        if blocked {
            self.socks5.connections_blocked.increment();
        } else if bypassed {
            self.socks5.connections_bypassed.increment();
        } else if tunneled {
            self.socks5.connections_tunneled.increment();
        }
    }

    fn record_dns_lookup(&self, cache_hit: bool, latency: Duration) {
        self.dns
            .record_lookup(cache_hit, latency.as_micros() as u64);
    }

    fn record_dns_error(&self) {
        self.dns.record_lookup_error();
        self.errors.record_error(ErrorType::DnsResolution);
    }

    fn record_websocket_sent(&self, bytes: u64) {
        self.websocket.record_message_sent(bytes);
    }

    fn record_websocket_received(&self, bytes: u64) {
        self.websocket.record_message_received(bytes);
    }

    fn record_websocket_connection_attempt(&self) {
        // Note: This would need to be async in real implementation
        // For now, we'll skip the async runtime check
    }

    fn record_websocket_connection_success(&self, latency: Duration) {
        self.websocket.connection_successes.increment();
        self.websocket
            .connection_latency
            .record(latency.as_micros() as u64);
    }

    fn record_websocket_connection_failure(&self) {
        self.websocket.connection_failures.increment();
    }

    fn increment_active_connections(&self) {
        self.resources.active_connections.increment();
    }

    fn decrement_active_connections(&self) {
        self.resources.active_connections.decrement();
    }

    fn increment_active_proxy_connections(&self) {
        self.resources.active_proxy_connections.increment();
    }

    fn decrement_active_proxy_connections(&self) {
        self.resources.active_proxy_connections.decrement();
    }

    fn set_crypto_queue_depth(&self, depth: u64) {
        self.resources.crypto_queue_depth.set(depth);
    }

    fn set_websocket_queue_depth(&self, depth: u64) {
        self.resources.websocket_queue_depth.set(depth);
    }

    fn set_dns_cache_size(&self, size: u64) {
        self.resources.dns_cache_size.set(size);
        self.dns.cache_size.set(size);
    }

    fn set_reorder_buffer_depth(&self, depth: u64) {
        self.resources.reorder_buffer_depth.set(depth);
        crate::metrics::Metrics::set_reorder_buffer_depth(self, depth as usize);
    }
}

/// RAII guard for tracking active connections
pub struct ConnectionGuard {
    metrics: Arc<Metrics>,
    connection_type: ConnectionType,
}

#[derive(Debug, Clone, Copy)]
enum ConnectionType {
    Socks5,
    Proxy,
}

impl ConnectionGuard {
    /// Create a new connection guard for SOCKS5 connections
    pub fn new_socks5(metrics: Arc<Metrics>) -> Self {
        metrics.increment_active_connections();
        metrics.socks5.connections_accepted.increment();

        Self {
            metrics,
            connection_type: ConnectionType::Socks5,
        }
    }

    /// Create a new connection guard for proxy connections
    pub fn new_proxy(metrics: Arc<Metrics>) -> Self {
        metrics.increment_active_proxy_connections();

        Self {
            metrics,
            connection_type: ConnectionType::Proxy,
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        match self.connection_type {
            ConnectionType::Socks5 => {
                self.metrics.decrement_active_connections();
                self.metrics.socks5.connections_completed.increment();
            }
            ConnectionType::Proxy => {
                self.metrics.decrement_active_proxy_connections();
            }
        }
    }
}

/// Connection tracker for high-level tracking
pub struct ConnectionTracker {
    metrics: Arc<Metrics>,
}

impl ConnectionTracker {
    /// Create a new connection tracker
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics }
    }

    /// Track a new SOCKS5 connection
    pub fn track_socks5_connection(&self) -> ConnectionGuard {
        ConnectionGuard::new_socks5(Arc::clone(&self.metrics))
    }

    /// Track a new proxy connection
    pub fn track_proxy_connection(&self) -> ConnectionGuard {
        ConnectionGuard::new_proxy(Arc::clone(&self.metrics))
    }
}

/// Helper function to record operation result
///
/// Records success/failure metrics automatically
pub fn record_operation_result<T, E>(
    metrics: &Metrics,
    error_type: ErrorType,
    result: &Result<T, E>,
) {
    if result.is_err() {
        metrics.record_error(error_type);
    }
}

/// Byte counter for tracking data transfer
pub struct ByteCounter {
    metrics: Arc<Metrics>,
    bytes_sent: u64,
    bytes_received: u64,
    report_threshold: u64,
}

impl ByteCounter {
    /// Create a new byte counter
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self {
            metrics,
            bytes_sent: 0,
            bytes_received: 0,
            report_threshold: 65536, // Report every 64KB
        }
    }

    /// Create a new byte counter with custom threshold
    pub fn with_threshold(metrics: Arc<Metrics>, threshold: u64) -> Self {
        Self {
            metrics,
            bytes_sent: 0,
            bytes_received: 0,
            report_threshold: threshold,
        }
    }

    /// Record bytes sent
    pub fn add_sent(&mut self, bytes: u64) {
        self.bytes_sent += bytes;
        self.check_and_report();
    }

    /// Record bytes received
    pub fn add_received(&mut self, bytes: u64) {
        self.bytes_received += bytes;
        self.check_and_report();
    }

    /// Check if we should report accumulated bytes
    fn check_and_report(&mut self) {
        if self.bytes_sent >= self.report_threshold {
            self.metrics.record_bytes_sent(self.bytes_sent);
            self.bytes_sent = 0;
        }

        if self.bytes_received >= self.report_threshold {
            self.metrics.record_bytes_received(self.bytes_received);
            self.bytes_received = 0;
        }
    }

    /// Flush any remaining bytes to metrics
    pub fn flush(&mut self) {
        if self.bytes_sent > 0 {
            self.metrics.record_bytes_sent(self.bytes_sent);
            self.bytes_sent = 0;
        }

        if self.bytes_received > 0 {
            self.metrics.record_bytes_received(self.bytes_received);
            self.bytes_received = 0;
        }
    }
}

impl Drop for ByteCounter {
    fn drop(&mut self) {
        self.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_guard_socks5() {
        let metrics = Arc::new(Metrics::new());

        {
            let _guard = ConnectionGuard::new_socks5(Arc::clone(&metrics));
            assert_eq!(metrics.resources.active_connections.get(), 1);
            assert_eq!(metrics.socks5.connections_accepted.get(), 1);
        }

        // Guard dropped
        assert_eq!(metrics.resources.active_connections.get(), 0);
        assert_eq!(metrics.socks5.connections_completed.get(), 1);
    }

    #[test]
    fn test_connection_guard_proxy() {
        let metrics = Arc::new(Metrics::new());

        {
            let _guard = ConnectionGuard::new_proxy(Arc::clone(&metrics));
            assert_eq!(metrics.resources.active_proxy_connections.get(), 1);
        }

        // Guard dropped
        assert_eq!(metrics.resources.active_proxy_connections.get(), 0);
    }

    #[test]
    fn test_byte_counter() {
        let metrics = Arc::new(Metrics::new());
        let mut counter = ByteCounter::with_threshold(Arc::clone(&metrics), 100);

        counter.add_sent(50);
        assert_eq!(metrics.throughput.bytes_sent.get(), 0); // Not yet reported

        counter.add_sent(60); // Total 110, exceeds threshold
        assert_eq!(metrics.throughput.bytes_sent.get(), 110);

        counter.add_received(200); // Exceeds threshold
        assert_eq!(metrics.throughput.bytes_received.get(), 200);
    }

    #[test]
    fn test_record_operation_result() {
        let metrics = Arc::new(Metrics::new());

        let ok_result: Result<(), ()> = Ok(());
        record_operation_result(&metrics, ErrorType::DnsResolution, &ok_result);
        assert_eq!(metrics.errors.dns_errors.get(), 0);

        let err_result: Result<(), ()> = Err(());
        record_operation_result(&metrics, ErrorType::DnsResolution, &err_result);
        assert_eq!(metrics.errors.dns_errors.get(), 1);
    }

    #[test]
    fn test_metrics_timer() {
        let metrics = Arc::new(Metrics::new());

        {
            let _timer = metrics.time_dns_lookup();
            // Simulate some work
            std::thread::sleep(Duration::from_millis(1));
        }

        // Timer should have recorded latency
        assert!(metrics.latency.dns_lookup.count() >= 1);
    }
}
