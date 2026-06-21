//! R-VPN Client Library - Brook-style Architecture
//!
//! This library provides the core VPN client functionality for R-VPN.
//! Uses a Brook-style architecture where each SOCKS5 connection manages
//! its own WebSocket connection (no connection pooling or multiplexing).

pub mod config;
pub mod dns;

// These modules are temporarily unused in the Brook-style refactor
// but kept for potential future use (split tunnel, metrics, etc.)
#[allow(dead_code)]
pub mod dns_cache;
#[allow(dead_code)]
pub mod identity_verification;
pub mod metrics;
#[allow(dead_code)]
pub mod split_tunnel;
#[allow(dead_code)]
pub mod stats;

pub mod socks5;
pub mod socks5_tunnel;
pub mod stream_relay;
pub mod tls_boring;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod tun;
pub mod tunnel;
pub mod websocket;
pub mod proxy_common;
pub mod http_proxy;

// Re-export commonly used types
pub use config::{ClientConfig, ServerIdentityConfig};
pub use tls_boring::{TlsFingerprint, fingerprint_from_str};
pub use socks5_tunnel::Socks5Tunnel;
