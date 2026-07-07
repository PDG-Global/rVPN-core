//! R-VPN Client Library - Brook-style Architecture
//!
//! This library provides the core VPN client functionality for R-VPN.
//! Uses a Brook-style architecture where each SOCKS5 connection manages
//! its own WebSocket connection (no connection pooling or multiplexing).

pub mod config;
pub mod dns;

// These modules are temporarily unused in the Brook-style refactor
// but kept for potential future use (metrics, etc.)
#[allow(dead_code)]
pub mod identity_verification;
pub mod metrics;
#[allow(dead_code)]
pub mod stats;

// Desktop-only modules — not compiled on Android (BoringSSL not available).
#[cfg(not(target_os = "android"))]
pub mod socks5;
#[cfg(not(target_os = "android"))]
pub mod socks5_tunnel;
#[cfg(not(target_os = "android"))]
pub mod stream_relay;
// TLS: re-exported from rvpn-tls crate
#[cfg(target_os = "android")]
pub mod tls_fingerprint_stub;
#[cfg(not(any(target_os = "ios", target_os = "android")))]
pub mod tun;
#[cfg(not(target_os = "android"))]
pub mod tunnel;
pub mod websocket;
#[cfg(not(target_os = "android"))]
pub mod proxy_common;
#[cfg(not(target_os = "android"))]
pub mod http_proxy;

// Backwards compatibility re-exports from rvpn-split-tunnel
pub mod split_tunnel;
pub mod dns_cache;

// Re-export commonly used types
pub use config::{ClientConfig, ServerIdentityConfig};
#[cfg(not(target_os = "android"))]
pub use rvpn_tls::{TlsFingerprint, connect_chrome_like, ChromeTlsStream};
pub use rvpn_tls::fingerprint_from_str;
#[cfg(target_os = "android")]
pub use tls_fingerprint_stub::{TlsFingerprint, fingerprint_from_str};
#[cfg(not(target_os = "android"))]
pub use socks5_tunnel::Socks5Tunnel;
