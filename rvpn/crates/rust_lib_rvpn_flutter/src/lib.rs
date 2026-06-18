//! Flutter Rust Bridge for R-VPN
//!
//! This crate provides the FFI interface between Flutter (Dart) and the R-VPN Rust core.
//! It's designed to be used with flutter_rust_bridge for seamless Dart-Rust interop.

use flutter_rust_bridge::frb;
use std::sync::Arc;
use parking_lot::Mutex;
use once_cell::sync::OnceCell;

// Re-export types that Dart needs to know about
pub use rvpn_core::protocol::PayloadType;

/// Global VPN state
static VPN_STATE: OnceCell<Arc<Mutex<VpnState>>> = OnceCell::new();

/// VPN connection state
#[frb]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}

/// VPN configuration
#[frb]
#[derive(Debug, Clone)]
pub struct VpnConfig {
    pub server_address: String,
    pub identity_key_path: String,
    pub prekey_bundle_path: Option<String>,
    pub server_fingerprint: Option<String>,
    pub trust_on_first_use: bool,
    pub known_hosts_path: Option<String>,
    pub socks5_port: Option<u16>,
}

impl Default for VpnConfig {
    fn default() -> Self {
        Self {
            server_address: "wss://localhost:443/connect".to_string(),
            identity_key_path: "identity.key".to_string(),
            prekey_bundle_path: None,
            server_fingerprint: None,
            trust_on_first_use: true,
            known_hosts_path: None,
            socks5_port: Some(1080),
        }
    }
}

/// Connection statistics
#[frb]
#[derive(Debug, Clone, Default)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub reconnect_count: u32,
    pub uptime_secs: u64,
    pub messages_per_second: f64,
    pub decrypt_latency_p50: u64,
    pub decrypt_latency_p99: u64,
    pub reorder_buffer_depth: usize,
    pub reorder_events: u64,
    pub dropped_messages: u64,
}

/// VPN state holder
struct VpnState {
    state: ConnectionState,
    stats: ConnectionStats,
    config: Option<VpnConfig>,
    runtime: Option<tokio::runtime::Runtime>,
}

impl VpnState {
    fn new() -> Self {
        Self {
            state: ConnectionState::Disconnected,
            stats: ConnectionStats::default(),
            config: None,
            runtime: None,
        }
    }
}

fn get_vpn_state() -> Arc<Mutex<VpnState>> {
    VPN_STATE.get_or_init(|| Arc::new(Mutex::new(VpnState::new()))).clone()
}

// ==================== FFI Functions ====================

/// Initialize the R-VPN runtime
#[frb(sync)]
pub fn rvpn_init() -> Result<(), String> {
    let state = get_vpn_state();
    let mut guard = state.lock();
    
    if guard.runtime.is_some() {
        return Ok(()); // Already initialized
    }
    
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to create runtime: {}", e))?;
    
    guard.runtime = Some(runtime);
    log::info!("R-VPN runtime initialized");
    Ok(())
}

/// Get current connection state
#[frb(sync)]
pub fn rvpn_get_state() -> ConnectionState {
    let state = get_vpn_state();
    let guard = state.lock();
    guard.state
}

/// Get connection statistics
#[frb(sync)]
pub fn rvpn_get_stats() -> ConnectionStats {
    let state = get_vpn_state();
    let guard = state.lock();
    guard.stats.clone()
}

/// Connect to VPN server (async)
#[frb]
pub async fn rvpn_connect(config: VpnConfig) -> Result<(), String> {
    let state = get_vpn_state();
    
    // Check if already connected
    {
        let guard = state.lock();
        if guard.state == ConnectionState::Connected {
            return Err("Already connected".to_string());
        }
    }
    
    // Set connecting state
    {
        let mut guard = state.lock();
        guard.state = ConnectionState::Connecting;
        guard.config = Some(config.clone());
    }
    
    // TODO: Implement actual connection logic in Task 2
    // This will integrate with rvpn-client's VpnTunnel
    
    // Simulate connection for now
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    
    {
        let mut guard = state.lock();
        guard.state = ConnectionState::Connected;
    }
    
    log::info!("Connected to {}", config.server_address);
    Ok(())
}

/// Disconnect from VPN server (async)
#[frb]
pub async fn rvpn_disconnect() -> Result<(), String> {
    let state = get_vpn_state();
    
    {
        let mut guard = state.lock();
        if guard.state == ConnectionState::Disconnected {
            return Ok(());
        }
        guard.state = ConnectionState::Disconnecting;
    }
    
    // TODO: Implement actual disconnection logic
    
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    
    {
        let mut guard = state.lock();
        guard.state = ConnectionState::Disconnected;
        guard.stats = ConnectionStats::default();
    }
    
    log::info!("Disconnected");
    Ok(())
}

/// Send a packet through the VPN tunnel (async)
#[frb]
pub async fn rvpn_send_packet(data: Vec<u8>) -> Result<(), String> {
    let state = get_vpn_state();
    
    {
        let guard = state.lock();
        if guard.state != ConnectionState::Connected {
            return Err("Not connected".to_string());
        }
    }
    
    // TODO: Implement actual packet sending
    
    {
        let mut guard = state.lock();
        guard.stats.bytes_sent += data.len() as u64;
        guard.stats.messages_sent += 1;
    }
    
    Ok(())
}

/// Generate a new identity key pair
#[frb]
pub async fn rvpn_generate_identity(output_path: String) -> Result<(), String> {
    // TODO: Implement identity generation using rvpn-client
    log::info!("Generating identity key at: {}", output_path);
    let _ = output_path; // Silence unused warning until implemented
    Ok(())
}

/// Get server prekey bundle
#[frb]
pub async fn rvpn_get_prekey_bundle(
    server_url: String,
    output_path: String,
) -> Result<(), String> {
    // TODO: Implement prekey bundle fetching
    log::info!("Fetching prekey bundle from: {} to {}", server_url, output_path);
    let _ = output_path; // Silence unused warning until implemented
    Ok(())
}

mod generated;
