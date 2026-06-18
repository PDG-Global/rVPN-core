//! Prometheus Metrics Exporter
//!
//! This module provides Prometheus-compatible metrics export in text format.
//! The exporter can be served via HTTP endpoint for scraping by Prometheus.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use rvpn_client::metrics::Metrics;
//! use rvpn_client::metrics_exporter::PrometheusExporter;
//! use std::sync::Arc;
//!
//! async fn example() {
//!     let metrics = Arc::new(Metrics::new());
//!     let exporter = PrometheusExporter::new(metrics);
//!
//!     // Start HTTP server on port 9090
//!     let _handle = exporter.start_http_server(9090).await.unwrap();
//! }
//! ```
//!
//! ## Metric Naming Convention
//!
//! All metrics follow Prometheus naming conventions:
//! - `rvpn_` prefix for all R-VPN metrics
//! - `_total` suffix for counters
//! - `_bytes` suffix for byte counters
//! - `_seconds` suffix for latency (converted from microseconds)
//! - Labels for dimensions (e.g., error_type, decision)

use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, error, debug, warn};

use crate::metrics::{Metrics, ConnectionHealth};

/// Prometheus metrics exporter
pub struct PrometheusExporter {
    metrics: Arc<Metrics>,
}

impl PrometheusExporter {
    /// Create a new Prometheus exporter
    pub fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics }
    }

    /// Generate Prometheus-formatted metrics output
    pub async fn render(&self) -> String {
        let mut output = String::with_capacity(8192);

        // Add header
        output.push_str("# R-VPN Client Metrics\n");
        output.push_str("# Generated: ");
        output.push_str(&chrono::Utc::now().to_rfc3339());
        output.push('\n');
        output.push('\n');

        // Throughput metrics
        self.render_throughput(&mut output).await;

        // Latency metrics (histograms)
        self.render_latency(&mut output).await;

        // Resource metrics
        self.render_resources(&mut output).await;

        // Error metrics
        self.render_errors(&mut output).await;

        // Crypto metrics
        self.render_crypto(&mut output).await;

        // SOCKS5 metrics
        self.render_socks5(&mut output).await;

        // DNS metrics
        self.render_dns(&mut output).await;

        // Split tunnel metrics
        self.render_split_tunnel(&mut output).await;

        // WebSocket metrics
        self.render_websocket(&mut output).await;

        // Connection health
        self.render_connection_health(&mut output).await;

        output
    }

    /// Render throughput metrics
    async fn render_throughput(&self, output: &mut String) {
        let throughput = &self.metrics.throughput;

        // Bytes sent
        output.push_str("# HELP rvpn_bytes_sent_total Total bytes sent through the tunnel\n");
        output.push_str("# TYPE rvpn_bytes_sent_total counter\n");
        output.push_str(&format!(
            "rvpn_bytes_sent_total {}\n\n",
            throughput.bytes_sent.get()
        ));

        // Bytes received
        output.push_str("# HELP rvpn_bytes_received_total Total bytes received through the tunnel\n");
        output.push_str("# TYPE rvpn_bytes_received_total counter\n");
        output.push_str(&format!(
            "rvpn_bytes_received_total {}\n\n",
            throughput.bytes_received.get()
        ));

        // Messages sent
        output.push_str("# HELP rvpn_messages_sent_total Total messages sent\n");
        output.push_str("# TYPE rvpn_messages_sent_total counter\n");
        output.push_str(&format!(
            "rvpn_messages_sent_total {}\n\n",
            throughput.messages_sent.get()
        ));

        // Messages received
        output.push_str("# HELP rvpn_messages_received_total Total messages received\n");
        output.push_str("# TYPE rvpn_messages_received_total counter\n");
        output.push_str(&format!(
            "rvpn_messages_received_total {}\n\n",
            throughput.messages_received.get()
        ));

        // Throughput rates (gauges)
        let rates = throughput.rates().await;

        output.push_str("# HELP rvpn_bytes_sent_per_second Current bytes sent per second\n");
        output.push_str("# TYPE rvpn_bytes_sent_per_second gauge\n");
        output.push_str(&format!(
            "rvpn_bytes_sent_per_second {:.2}\n\n",
            rates.bytes_sent_per_sec
        ));

        output.push_str("# HELP rvpn_bytes_received_per_second Current bytes received per second\n");
        output.push_str("# TYPE rvpn_bytes_received_per_second gauge\n");
        output.push_str(&format!(
            "rvpn_bytes_received_per_second {:.2}\n\n",
            rates.bytes_received_per_sec
        ));

        output.push_str("# HELP rvpn_messages_sent_per_second Current messages sent per second\n");
        output.push_str("# TYPE rvpn_messages_sent_per_second gauge\n");
        output.push_str(&format!(
            "rvpn_messages_sent_per_second {:.2}\n\n",
            rates.messages_sent_per_sec
        ));

        output.push_str("# HELP rvpn_messages_received_per_second Current messages received per second\n");
        output.push_str("# TYPE rvpn_messages_received_per_second gauge\n");
        output.push_str(&format!(
            "rvpn_messages_received_per_second {:.2}\n\n",
            rates.messages_received_per_sec
        ));
    }

    /// Render latency histograms
    async fn render_latency(&self, output: &mut String) {
        let latency = &self.metrics.latency;

        // DNS lookup latency
        self.render_histogram(
            output,
            "rvpn_dns_lookup_duration_seconds",
            "DNS lookup latency",
            &latency.dns_lookup,
        );

        // Encryption latency
        self.render_histogram(
            output,
            "rvpn_encryption_duration_seconds",
            "Encryption latency",
            &latency.encryption,
        );

        // Decryption latency
        self.render_histogram(
            output,
            "rvpn_decryption_duration_seconds",
            "Decryption latency",
            &latency.decryption,
        );

        // WebSocket send latency
        self.render_histogram(
            output,
            "rvpn_websocket_send_duration_seconds",
            "WebSocket send latency",
            &latency.websocket_send,
        );

        // Routing decision latency
        self.render_histogram(
            output,
            "rvpn_routing_decision_duration_seconds",
            "Routing decision latency",
            &latency.routing_decision,
        );

        // SOCKS5 connect latency
        self.render_histogram(
            output,
            "rvpn_socks5_connect_duration_seconds",
            "SOCKS5 connection setup latency",
            &latency.socks5_connect,
        );

        // Proxy connect latency
        self.render_histogram(
            output,
            "rvpn_proxy_connect_duration_seconds",
            "Proxy connection through tunnel latency",
            &latency.proxy_connect,
        );

        // Split tunnel lookup latency
        self.render_histogram(
            output,
            "rvpn_split_tunnel_lookup_duration_seconds",
            "Split tunnel lookup latency",
            &latency.split_tunnel_lookup,
        );
    }

    /// Render a histogram in Prometheus format
    fn render_histogram(
        &self,
        output: &mut String,
        name: &str,
        help: &str,
        histogram: &crate::metrics::Histogram,
    ) {
        // Help text
        output.push_str(&format!("# HELP {} {}\n", name, help));
        output.push_str(&format!("# TYPE {} histogram\n", name));

        // Buckets
        let buckets = histogram.bucket_counts();
        let mut cumulative = 0u64;

        for (bucket_bound, count) in buckets {
            cumulative += count;
            // Convert microseconds to seconds for Prometheus
            let bucket_secs = bucket_bound as f64 / 1_000_000.0;
            output.push_str(&format!(
                "{}_bucket{{le=\"{:.6}\"}} {}\n",
                name, bucket_secs, cumulative
            ));
        }

        // +Inf bucket
        output.push_str(&format!(
            "{}_bucket{{le=\"+Inf\"}} {}\n",
            name,
            histogram.count()
        ));

        // Sum (convert to seconds)
        let sum_secs = histogram.sum() as f64 / 1_000_000.0;
        output.push_str(&format!("{}_sum {:.6}\n", name, sum_secs));

        // Count
        output.push_str(&format!("{}_count {}\n\n", name, histogram.count()));
    }

    /// Render resource metrics
    async fn render_resources(&self, output: &mut String) {
        let resources = &self.metrics.resources;

        // Update memory usage
        resources.update_memory_usage();

        output.push_str("# HELP rvpn_active_connections Number of active SOCKS5 connections\n");
        output.push_str("# TYPE rvpn_active_connections gauge\n");
        output.push_str(&format!(
            "rvpn_active_connections {}\n\n",
            resources.active_connections.get()
        ));

        output.push_str("# HELP rvpn_active_proxy_connections Number of active proxy connections through tunnel\n");
        output.push_str("# TYPE rvpn_active_proxy_connections gauge\n");
        output.push_str(&format!(
            "rvpn_active_proxy_connections {}\n\n",
            resources.active_proxy_connections.get()
        ));

        output.push_str("# HELP rvpn_reorder_buffer_depth Current reorder buffer depth\n");
        output.push_str("# TYPE rvpn_reorder_buffer_depth gauge\n");
        output.push_str(&format!(
            "rvpn_reorder_buffer_depth {}\n\n",
            resources.reorder_buffer_depth.get()
        ));

        output.push_str("# HELP rvpn_crypto_queue_depth Crypto worker queue depth\n");
        output.push_str("# TYPE rvpn_crypto_queue_depth gauge\n");
        output.push_str(&format!(
            "rvpn_crypto_queue_depth {}\n\n",
            resources.crypto_queue_depth.get()
        ));

        output.push_str("# HELP rvpn_websocket_queue_depth WebSocket send queue depth\n");
        output.push_str("# TYPE rvpn_websocket_queue_depth gauge\n");
        output.push_str(&format!(
            "rvpn_websocket_queue_depth {}\n\n",
            resources.websocket_queue_depth.get()
        ));

        output.push_str("# HELP rvpn_memory_usage_bytes Current memory usage in bytes\n");
        output.push_str("# TYPE rvpn_memory_usage_bytes gauge\n");
        output.push_str(&format!(
            "rvpn_memory_usage_bytes {}\n\n",
            resources.memory_usage_bytes.get()
        ));

        output.push_str("# HELP rvpn_dns_cache_size DNS cache size\n");
        output.push_str("# TYPE rvpn_dns_cache_size gauge\n");
        output.push_str(&format!(
            "rvpn_dns_cache_size {}\n\n",
            resources.dns_cache_size.get()
        ));
    }

    /// Render error metrics
    async fn render_errors(&self, output: &mut String) {
        let errors = &self.metrics.errors;

        output.push_str("# HELP rvpn_errors_total Total number of errors by type\n");
        output.push_str("# TYPE rvpn_errors_total counter\n");

        // Render each error type with label
        let error_types = vec![
            ("dns_resolution", errors.dns_errors.get()),
            ("crypto_encryption", errors.crypto_encrypt_errors.get()),
            ("crypto_decryption", errors.crypto_decrypt_errors.get()),
            ("websocket_send", errors.websocket_send_errors.get()),
            ("websocket_receive", errors.websocket_receive_errors.get()),
            ("websocket_connection", errors.websocket_connection_errors.get()),
            ("routing_decision", errors.routing_errors.get()),
            ("proxy_connection", errors.proxy_connection_errors.get()),
            ("timeout", errors.timeout_errors.get()),
            ("ratchet_out_of_sync", errors.ratchet_errors.get()),
        ];

        for (error_type, count) in error_types {
            output.push_str(&format!(
                "rvpn_errors_total{{error_type=\"{}\"}} {}\n",
                error_type, count
            ));
        }
        output.push('\n');

        // Total errors
        output.push_str("# HELP rvpn_errors_total_all Total number of all errors\n");
        output.push_str("# TYPE rvpn_errors_total_all counter\n");
        output.push_str(&format!(
            "rvpn_errors_total_all {}\n\n",
            errors.total_errors.get()
        ));
    }

    /// Render crypto metrics
    async fn render_crypto(&self, output: &mut String) {
        let crypto = &self.metrics.crypto;

        output.push_str("# HELP rvpn_crypto_encrypt_operations_total Total encryption operations\n");
        output.push_str("# TYPE rvpn_crypto_encrypt_operations_total counter\n");
        output.push_str(&format!(
            "rvpn_crypto_encrypt_operations_total {}\n\n",
            crypto.encrypt_count.get()
        ));

        output.push_str("# HELP rvpn_crypto_decrypt_operations_total Total decryption operations\n");
        output.push_str("# TYPE rvpn_crypto_decrypt_operations_total counter\n");
        output.push_str(&format!(
            "rvpn_crypto_decrypt_operations_total {}\n\n",
            crypto.decrypt_count.get()
        ));

        output.push_str("# HELP rvpn_crypto_encrypt_errors_total Total encryption errors\n");
        output.push_str("# TYPE rvpn_crypto_encrypt_errors_total counter\n");
        output.push_str(&format!(
            "rvpn_crypto_encrypt_errors_total {}\n\n",
            crypto.encrypt_errors.get()
        ));

        output.push_str("# HELP rvpn_crypto_decrypt_errors_total Total decryption errors\n");
        output.push_str("# TYPE rvpn_crypto_decrypt_errors_total counter\n");
        output.push_str(&format!(
            "rvpn_crypto_decrypt_errors_total {}\n\n",
            crypto.decrypt_errors.get()
        ));

        output.push_str("# HELP rvpn_crypto_avg_encrypt_time_microseconds Average encryption time in microseconds\n");
        output.push_str("# TYPE rvpn_crypto_avg_encrypt_time_microseconds gauge\n");
        output.push_str(&format!(
            "rvpn_crypto_avg_encrypt_time_microseconds {:.2}\n\n",
            crypto.avg_encrypt_time_us()
        ));

        output.push_str("# HELP rvpn_crypto_avg_decrypt_time_microseconds Average decryption time in microseconds\n");
        output.push_str("# TYPE rvpn_crypto_avg_decrypt_time_microseconds gauge\n");
        output.push_str(&format!(
            "rvpn_crypto_avg_decrypt_time_microseconds {:.2}\n\n",
            crypto.avg_decrypt_time_us()
        ));

        output.push_str("# HELP rvpn_crypto_messages_skipped_total Total messages skipped (ratchet gaps)\n");
        output.push_str("# TYPE rvpn_crypto_messages_skipped_total counter\n");
        output.push_str(&format!(
            "rvpn_crypto_messages_skipped_total {}\n\n",
            crypto.messages_skipped.get()
        ));

        output.push_str("# HELP rvpn_crypto_current_send_message_number Current ratchet send message number\n");
        output.push_str("# TYPE rvpn_crypto_current_send_message_number gauge\n");
        output.push_str(&format!(
            "rvpn_crypto_current_send_message_number {}\n\n",
            crypto.current_send_message_num.load(std::sync::atomic::Ordering::Relaxed)
        ));

        output.push_str("# HELP rvpn_crypto_current_recv_message_number Current ratchet receive message number\n");
        output.push_str("# TYPE rvpn_crypto_current_recv_message_number gauge\n");
        output.push_str(&format!(
            "rvpn_crypto_current_recv_message_number {}\n\n",
            crypto.current_recv_message_num.load(std::sync::atomic::Ordering::Relaxed)
        ));
    }

    /// Render SOCKS5 metrics
    async fn render_socks5(&self, output: &mut String) {
        let socks5 = &self.metrics.socks5;

        output.push_str("# HELP rvpn_socks5_connections_accepted_total Total SOCKS5 connections accepted\n");
        output.push_str("# TYPE rvpn_socks5_connections_accepted_total counter\n");
        output.push_str(&format!(
            "rvpn_socks5_connections_accepted_total {}\n\n",
            socks5.connections_accepted.get()
        ));

        output.push_str("# HELP rvpn_socks5_connections_completed_total Total SOCKS5 connections completed\n");
        output.push_str("# TYPE rvpn_socks5_connections_completed_total counter\n");
        output.push_str(&format!(
            "rvpn_socks5_connections_completed_total {}\n\n",
            socks5.connections_completed.get()
        ));

        output.push_str("# HELP rvpn_socks5_connections_tunneled_total Total connections routed through VPN\n");
        output.push_str("# TYPE rvpn_socks5_connections_tunneled_total counter\n");
        output.push_str(&format!(
            "rvpn_socks5_connections_tunneled_total {}\n\n",
            socks5.connections_tunneled.get()
        ));

        output.push_str("# HELP rvpn_socks5_connections_bypassed_total Total connections bypassed (direct)\n");
        output.push_str("# TYPE rvpn_socks5_connections_bypassed_total counter\n");
        output.push_str(&format!(
            "rvpn_socks5_connections_bypassed_total {}\n\n",
            socks5.connections_bypassed.get()
        ));

        output.push_str("# HELP rvpn_socks5_connections_blocked_total Total connections blocked (ads/trackers)\n");
        output.push_str("# TYPE rvpn_socks5_connections_blocked_total counter\n");
        output.push_str(&format!(
            "rvpn_socks5_connections_blocked_total {}\n\n",
            socks5.connections_blocked.get()
        ));

        output.push_str("# HELP rvpn_socks5_bytes_relayed_total Total bytes relayed through SOCKS5\n");
        output.push_str("# TYPE rvpn_socks5_bytes_relayed_total counter\n");
        output.push_str(&format!(
            "rvpn_socks5_bytes_relayed_total {}\n\n",
            socks5.bytes_relayed.get()
        ));
    }

    /// Render DNS metrics
    async fn render_dns(&self, output: &mut String) {
        let dns = &self.metrics.dns;

        output.push_str("# HELP rvpn_dns_lookups_total Total DNS lookups\n");
        output.push_str("# TYPE rvpn_dns_lookups_total counter\n");
        output.push_str(&format!(
            "rvpn_dns_lookups_total {}\n\n",
            dns.lookups_total.get()
        ));

        output.push_str("# HELP rvpn_dns_cache_hits_total Total DNS cache hits\n");
        output.push_str("# TYPE rvpn_dns_cache_hits_total counter\n");
        output.push_str(&format!(
            "rvpn_dns_cache_hits_total {}\n\n",
            dns.cache_hits.get()
        ));

        output.push_str("# HELP rvpn_dns_cache_misses_total Total DNS cache misses\n");
        output.push_str("# TYPE rvpn_dns_cache_misses_total counter\n");
        output.push_str(&format!(
            "rvpn_dns_cache_misses_total {}\n\n",
            dns.cache_misses.get()
        ));

        output.push_str("# HELP rvpn_dns_lookup_errors_total Total DNS lookup errors\n");
        output.push_str("# TYPE rvpn_dns_lookup_errors_total counter\n");
        output.push_str(&format!(
            "rvpn_dns_lookup_errors_total {}\n\n",
            dns.lookup_errors.get()
        ));

        output.push_str("# HELP rvpn_dns_cache_hit_rate DNS cache hit rate (0.0 to 1.0)\n");
        output.push_str("# TYPE rvpn_dns_cache_hit_rate gauge\n");
        output.push_str(&format!(
            "rvpn_dns_cache_hit_rate {:.4}\n\n",
            dns.cache_hit_rate()
        ));

        output.push_str("# HELP rvpn_dns_cache_expired_total Total DNS cache entries expired\n");
        output.push_str("# TYPE rvpn_dns_cache_expired_total counter\n");
        output.push_str(&format!(
            "rvpn_dns_cache_expired_total {}\n\n",
            dns.cache_expired.get()
        ));

        // DNS lookup latency histogram
        self.render_histogram(
            output,
            "rvpn_dns_lookup_duration_seconds",
            "DNS lookup latency",
            &dns.lookup_latency,
        );
    }

    /// Render split tunnel metrics
    async fn render_split_tunnel(&self, output: &mut String) {
        let split_tunnel = &self.metrics.split_tunnel;

        output.push_str("# HELP rvpn_routing_decisions_total Total routing decisions\n");
        output.push_str("# TYPE rvpn_routing_decisions_total counter\n");

        // By decision type
        output.push_str(&format!(
            "rvpn_routing_decisions_total{{decision=\"tunnel\"}} {}\n",
            split_tunnel.decisions_tunnel.get()
        ));
        output.push_str(&format!(
            "rvpn_routing_decisions_total{{decision=\"bypass\"}} {}\n",
            split_tunnel.decisions_bypass.get()
        ));
        output.push_str(&format!(
            "rvpn_routing_decisions_total{{decision=\"block\"}} {}\n",
            split_tunnel.decisions_block.get()
        ));
        output.push('\n');

        output.push_str("# HELP rvpn_routing_domain_lookups_total Total domain list lookups\n");
        output.push_str("# TYPE rvpn_routing_domain_lookups_total counter\n");
        output.push_str(&format!(
            "rvpn_routing_domain_lookups_total {}\n\n",
            split_tunnel.domain_lookups.get()
        ));

        output.push_str("# HELP rvpn_routing_network_lookups_total Total network list lookups\n");
        output.push_str("# TYPE rvpn_routing_network_lookups_total counter\n");
        output.push_str(&format!(
            "rvpn_routing_network_lookups_total {}\n\n",
            split_tunnel.network_lookups.get()
        ));

        // Routing decision latency histogram
        self.render_histogram(
            output,
            "rvpn_routing_decision_duration_seconds",
            "Routing decision latency",
            &split_tunnel.decision_latency,
        );
    }

    /// Render WebSocket metrics
    async fn render_websocket(&self, output: &mut String) {
        let ws = &self.metrics.websocket;

        output.push_str("# HELP rvpn_websocket_connection_attempts_total Total WebSocket connection attempts\n");
        output.push_str("# TYPE rvpn_websocket_connection_attempts_total counter\n");
        output.push_str(&format!(
            "rvpn_websocket_connection_attempts_total {}\n\n",
            ws.connection_attempts.get()
        ));

        output.push_str("# HELP rvpn_websocket_connection_successes_total Total successful WebSocket connections\n");
        output.push_str("# TYPE rvpn_websocket_connection_successes_total counter\n");
        output.push_str(&format!(
            "rvpn_websocket_connection_successes_total {}\n\n",
            ws.connection_successes.get()
        ));

        output.push_str("# HELP rvpn_websocket_connection_failures_total Total failed WebSocket connections\n");
        output.push_str("# TYPE rvpn_websocket_connection_failures_total counter\n");
        output.push_str(&format!(
            "rvpn_websocket_connection_failures_total {}\n\n",
            ws.connection_failures.get()
        ));

        output.push_str("# HELP rvpn_websocket_messages_sent_total Total WebSocket messages sent\n");
        output.push_str("# TYPE rvpn_websocket_messages_sent_total counter\n");
        output.push_str(&format!(
            "rvpn_websocket_messages_sent_total {}\n\n",
            ws.messages_sent.get()
        ));

        output.push_str("# HELP rvpn_websocket_messages_received_total Total WebSocket messages received\n");
        output.push_str("# TYPE rvpn_websocket_messages_received_total counter\n");
        output.push_str(&format!(
            "rvpn_websocket_messages_received_total {}\n\n",
            ws.messages_received.get()
        ));

        output.push_str("# HELP rvpn_websocket_bytes_sent_total Total WebSocket bytes sent\n");
        output.push_str("# TYPE rvpn_websocket_bytes_sent_total counter\n");
        output.push_str(&format!(
            "rvpn_websocket_bytes_sent_total {}\n\n",
            ws.bytes_sent.get()
        ));

        output.push_str("# HELP rvpn_websocket_bytes_received_total Total WebSocket bytes received\n");
        output.push_str("# TYPE rvpn_websocket_bytes_received_total counter\n");
        output.push_str(&format!(
            "rvpn_websocket_bytes_received_total {}\n\n",
            ws.bytes_received.get()
        ));

        output.push_str("# HELP rvpn_websocket_reconnects_total Total WebSocket reconnects\n");
        output.push_str("# TYPE rvpn_websocket_reconnects_total counter\n");
        output.push_str(&format!(
            "rvpn_websocket_reconnects_total {}\n\n",
            ws.reconnect_count.get()
        ));

        output.push_str("# HELP rvpn_websocket_connection_duration_seconds Current connection duration in seconds\n");
        output.push_str("# TYPE rvpn_websocket_connection_duration_seconds gauge\n");
        ws.update_connection_duration().await;
        output.push_str(&format!(
            "rvpn_websocket_connection_duration_seconds {}\n\n",
            ws.connection_duration_secs.get()
        ));

        // WebSocket connection latency histogram
        self.render_histogram(
            output,
            "rvpn_websocket_connection_duration_seconds_histogram",
            "WebSocket connection latency",
            &ws.connection_latency,
        );

        // WebSocket send latency histogram
        self.render_histogram(
            output,
            "rvpn_websocket_send_duration_seconds",
            "WebSocket send latency",
            &ws.send_latency,
        );
    }

    /// Render connection health
    async fn render_connection_health(&self, output: &mut String) {
        let health = self.metrics.get_connection_health().await;
        
        output.push_str("# HELP rvpn_connection_health Current connection health status (0=disconnected, 1=connecting, 2=connected, 3=reconnecting)\n");
        output.push_str("# TYPE rvpn_connection_health gauge\n");
        
        let health_value = match health {
            ConnectionHealth::Disconnected => 0,
            ConnectionHealth::Connecting => 1,
            ConnectionHealth::Connected => 2,
            ConnectionHealth::Reconnecting => 3,
        };
        
        output.push_str(&format!(
            "rvpn_connection_health {{status=\"{}\"}} {}\n\n",
            health, health_value
        ));

        // Connection uptime
        output.push_str("# HELP rvpn_connection_uptime_seconds Connection uptime in seconds\n");
        output.push_str("# TYPE rvpn_connection_uptime_seconds gauge\n");
        
        // Calculate uptime
        let uptime_secs = self.metrics.get_connection_uptime_secs().await;
        
        output.push_str(&format!(
            "rvpn_connection_uptime_seconds {}\n\n",
            uptime_secs
        ));
    }

    /// Start an HTTP server to serve Prometheus metrics
    ///
    /// This starts a simple HTTP server on the specified port that responds to
    /// GET /metrics with Prometheus-formatted metrics.
    pub async fn start_http_server(&self,
        port: u16,
    ) -> anyhow::Result<tokio::task::JoinHandle<()>> {
        let addr = format!("0.0.0.0:{}", port);
        let listener = TcpListener::bind(&addr).await?;
        
        info!("Prometheus metrics HTTP server listening on http://{}/metrics", addr);
        
        let metrics = Arc::clone(&self.metrics);
        
        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((mut stream, peer_addr)) => {
                        debug!("Metrics HTTP request from {}", peer_addr);
                        let metrics = Arc::clone(&metrics);
                        
                        tokio::spawn(async move {
                            // Read request (minimal parsing)
                            let mut buf = [0u8; 1024];
                            match stream.read(&mut buf).await {
                                Ok(n) if n > 0 => {
                                    let request = String::from_utf8_lossy(&buf[..n]);
                                    
                                    // Check if it's a GET request to /metrics
                                    if request.starts_with("GET /metrics") {
                                        // Generate metrics output
                                        let exporter = PrometheusExporter::new(metrics);
                                        let body = exporter.render().await;
                                        
                                        // Send HTTP response
                                        let response = format!(
                                            "HTTP/1.1 200 OK\r\n\
                                             Content-Type: text/plain; charset=utf-8\r\n\
                                             Content-Length: {}\r\n\
                                             Cache-Control: no-cache\r\n\
                                             \r\n\
                                             {}",
                                            body.len(),
                                            body
                                        );
                                        
                                        if let Err(e) = stream.write_all(response.as_bytes()).await {
                                            warn!("Failed to write metrics response: {}", e);
                                        }
                                    } else if request.starts_with("GET /health") {
                                        // Health check endpoint
                                        let body = "OK";
                                        let response = format!(
                                            "HTTP/1.1 200 OK\r\n\
                                             Content-Type: text/plain\r\n\
                                             Content-Length: {}\r\n\
                                             \r\n\
                                             {}",
                                            body.len(),
                                            body
                                        );
                                        
                                        if let Err(e) = stream.write_all(response.as_bytes()).await {
                                            warn!("Failed to write health response: {}", e);
                                        }
                                    } else {
                                        // 404 for other paths
                                        let response = "HTTP/1.1 404 Not Found\r\n\
                                                        Content-Length: 0\r\n\
                                                        \r\n";
                                        if let Err(e) = stream.write_all(response.as_bytes()).await {
                                            warn!("Failed to write 404 response: {}", e);
                                        }
                                    }
                                }
                                Ok(_) => {
                                    // Empty request
                                }
                                Err(e) => {
                                    warn!("Error reading HTTP request: {}", e);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept HTTP connection: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
        
        Ok(handle)
    }
}

/// Start Prometheus HTTP endpoint with the global metrics
pub async fn start_prometheus_endpoint(
    port: u16,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let metrics = global_metrics()
        .ok_or_else(|| anyhow::anyhow!("Global metrics not initialized"))?;
    
    let exporter = PrometheusExporter::new(metrics);
    exporter.start_http_server(port).await
}

use crate::metrics::global_metrics;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_prometheus_exporter_render() {
        let metrics = Arc::new(Metrics::new());
        let exporter = PrometheusExporter::new(metrics);
        
        let output = exporter.render().await;
        
        // Check that output contains expected sections
        assert!(output.contains("# HELP rvpn_bytes_sent_total"));
        assert!(output.contains("# TYPE rvpn_bytes_sent_total counter"));
        assert!(output.contains("# HELP rvpn_connection_health"));
        assert!(output.contains("rvpn_connection_health"));
    }

    #[test]
    fn test_prometheus_naming_conventions() {
        // Verify metric names follow Prometheus conventions
        let metric_names = vec![
            "rvpn_bytes_sent_total",
            "rvpn_messages_received_total",
            "rvpn_errors_total",
            "rvpn_active_connections",
            "rvpn_connection_health",
            "rvpn_dns_lookup_duration_seconds",
        ];

        for name in metric_names {
            // Should start with rvpn_
            assert!(name.starts_with("rvpn_"), "Metric {} should start with rvpn_", name);
            
            // Should use snake_case
            assert!(!name.contains("-"), "Metric {} should use snake_case", name);
            
            // Counters should end with _total
            // Note: "active_connections" is a gauge, not a counter
            if name.contains("bytes") || name.contains("messages") || name.contains("errors") || 
               (name.contains("connections") && !name.contains("active_")) {
                assert!(name.ends_with("_total"), "Counter {} should end with _total", name);
            }
        }
    }
}
