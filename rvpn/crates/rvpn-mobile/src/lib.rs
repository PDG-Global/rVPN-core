//! R-VPN Mobile Library - Direct TUN Architecture
//!
//! This crate provides FFI bindings for the R-VPN client to be used
//! in mobile applications.
//!
//! ## Architecture
//!
//! - iOS/macOS use Direct TUN mode via `ios_tun_ffi.rs` (rvpn_tun_* functions)
//! - Raw IP packets flow bidirectionally through WebSocket tunnel
//! - All network I/O runs in-process within the Tokio runtime
//! - Compatible with iOS Network Extension sandbox

// Use mimalloc as the global allocator on iOS only.
//
// iOS Network Extensions have a strict 50 MB memory limit. Under high
// packet throughput (3000+ allocs/sec for video streaming), the system
// allocator (libmalloc) fragments and never returns freed pages to the OS,
// causing RSS to grow until jetsam kills the process.
//
// Not used on Android — BoringSSL's static linking conflicts with mimalloc,
// and Android VPN services have a higher memory ceiling (128+ MB).
#[cfg(target_os = "ios")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod api;
pub mod ffi;
pub mod flow_connector;

// iOS Direct TUN mode - implementation using IosTunClient
#[cfg(any(feature = "ios-direct-tun", feature = "macos-direct-tun"))]
pub mod ios_tun;
#[cfg(any(feature = "ios-direct-tun", feature = "macos-direct-tun"))]
pub mod ios_tun_ffi;

// Android Direct TUN mode - implementation using AndroidTunClient
#[cfg(feature = "android-direct-tun")]
pub mod android_tun;
#[cfg(feature = "android-direct-tun")]
pub mod android_tun_ffi;

#[cfg(feature = "dns")]
pub mod dns_server;
#[cfg(feature = "dns")]
pub mod doh_client;

// Re-export the API for easier access
pub use api::*;

// Re-export split_tunnel from rvpn-client for use in mobile
pub use rvpn_client::split_tunnel;
pub use rvpn_client::split_tunnel::{SplitTunnel, RoutingDecision};
pub use rvpn_client::config::SplitTunnelConfig;

use std::panic;

/// Initialize panic hook to log panics
pub fn init_panic_hook() {
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        eprintln!("[PANIC] Thread panicked: {}", info);
        original_hook(info);
    }));
}
