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

// Use mimalloc for aggressive page purging on iOS (50MB jetsam limit).
// Gated behind the `mimalloc` feature — disable it to use the system allocator
// for diagnostics (e.g. confirming mimalloc's VM arena reservation is the
// source of the `internal` growth seen in memlog).
#[cfg(feature = "mimalloc")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod api;
pub mod ffi;
// Per-session IPv4 address rewriting for multi-server Direct TUN (pure std,
// used by both the iOS/macOS and Android uplink demux / downlink merge).
pub mod nat_rewrite;
// Dynamic per-IP exit routing learned from DNS answers (pure std, shared by
// the uplink demux in ios_tun.rs and the DNS layer in dns_server.rs).
pub mod route_map;
// flow_connector references rvpn_tls::ChromeTlsStream (boring backend). It is
// only used by android_tun_ffi (android-direct-tun), doh_client (dns), and
// dns_proxy_ffi (dns + ios/macos-direct-tun). On the actual iOS build
// (--no-default-features --features ios-direct-tun) none of those compile, so
// gating this module here keeps ChromeTlsStream/boring out of the iOS
// type-check and link graph.
#[cfg(any(feature = "android-direct-tun", feature = "dns"))]
pub mod flow_connector;
pub mod ws;

// iOS Direct TUN mode - implementation using IosTunClient
#[cfg(any(feature = "ios-direct-tun", feature = "macos-direct-tun"))]
pub mod ios_tun;
// Per-exit-server session state/logic extracted from ios_tun (multi-server prep)
#[cfg(any(feature = "ios-direct-tun", feature = "macos-direct-tun"))]
pub mod ios_tun_ffi;
#[cfg(any(feature = "ios-direct-tun", feature = "macos-direct-tun"))]
pub mod server_session;
#[cfg(any(feature = "ios-direct-tun", feature = "macos-direct-tun"))]
pub mod swift_crypto;

// Android Direct TUN mode - implementation using AndroidTunClient.
// #[macro_use] makes the tun_log!/tun_log_error! logging macros defined in
// android_tun available to android_server_session (declared after it).
#[cfg(feature = "android-direct-tun")]
#[macro_use]
pub mod android_tun;
// Per-exit-server session state/logic for Android (multi-server routing port;
// mirrors server_session.rs on iOS/macOS).
#[cfg(feature = "android-direct-tun")]
pub mod android_server_session;
// JNI exports only exist on Android targets (jni/jni-sys are Android-only
// deps); gating on the target as well keeps host `cargo check/test
// --features android-direct-tun` usable for the session/demux logic and its
// unit tests. The real JNI type-check happens in the cargo-ndk build
// (rvpn-android/build_rust.sh).
#[cfg(all(feature = "android-direct-tun", target_os = "android"))]
pub mod android_tun_ffi;

#[cfg(feature = "harmony-direct-tun")]
pub mod harmony_tun_ffi;

#[cfg(feature = "dns")]
pub mod dns_server;
#[cfg(feature = "dns")]
pub mod doh_client;

// DNS proxy FFI for NEDNSProxyProvider extension
#[cfg(all(
    feature = "dns",
    any(feature = "ios-direct-tun", feature = "macos-direct-tun")
))]
pub mod dns_proxy_ffi;

// Re-export the API for easier access
pub use api::*;

// Re-export split_tunnel from rvpn-split-tunnel for use in mobile
pub use rvpn_split_tunnel;
pub use rvpn_split_tunnel::{RoutingDecision, SplitTunnel, SplitTunnelConfig};

use std::panic;

/// Initialize panic hook to log panics
pub fn init_panic_hook() {
    let original_hook = panic::take_hook();
    panic::set_hook(Box::new(move |info| {
        eprintln!("[PANIC] Thread panicked: {}", info);
        original_hook(info);
    }));
}
