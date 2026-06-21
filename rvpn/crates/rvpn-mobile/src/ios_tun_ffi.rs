// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// iOS Direct TUN FFI - FFI bridge for IosTunClient
//
// This module provides FFI exports for the IosTunClient, allowing Swift
// to use Direct TUN mode without the legacy TunBridge/packet_processor.

use std::ffi::{c_char, c_int, CStr, CString};
use std::sync::Arc;
use std::sync::Mutex;

use tracing::{error, info, warn};

use crate::dns_server::DnsServer;
use crate::doh_client::DohClient;
use crate::ffi::TunConfig;
use crate::flow_connector::FlowConnectorConfig;
use crate::ios_tun::IosTunClient;
use base64::Engine;
use rvpn_client::split_tunnel::SplitTunnel;
use rvpn_client::dns_cache::DnsResolver;
use rvpn_core::crypto::IdentityKey;

// Global singleton for the TUN client (iOS only runs one VPN at a time)
static TUN_CLIENT: Mutex<Option<Arc<IosTunClient>>> = Mutex::new(None);

// Global runtime handle for spawning tasks
static TUN_RUNTIME: Mutex<Option<Arc<tokio::runtime::Runtime>>> = Mutex::new(None);

// Global last error message
static LAST_ERROR: Mutex<Option<String>> = Mutex::new(None);

// Global DNS proxy abort handle (for cleanup on stop)
static DNS_PROXY_HANDLE: Mutex<Option<tokio::task::JoinHandle<()>>> = Mutex::new(None);

// Atomic flag to prevent duplicate client creation during iOS double-startTunnel race
static TUN_CLIENT_CREATING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// ============================================================================
// Core Runtime Functions
// ============================================================================

/// Initialize the R-VPN runtime
/// - Returns: 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn rvpn_initialize() -> c_int {
    init_tracing();
    info!("[IOS_TUN_FFI] rvpn_initialize() called - R-VPN runtime initialized");
    SUCCESS
}

/// Initialize tracing subscriber (idempotent)
fn init_tracing() {
    use tracing_subscriber::{prelude::*, EnvFilter};

    if TRACING_INITIALIZED
        .compare_exchange(false, true, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst)
        .is_err()
    {
        return; // Already initialized
    }

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(OsLogLayer)
        .with(filter)
        .init();
}

/// Set the last error message
pub fn set_last_error(msg: &str) {
    let mut guard = LAST_ERROR.lock().unwrap();
    *guard = Some(msg.to_string());
}

/// Get the last error message
/// - Returns: Error message C string, or nil if no error
/// Caller must free with rvpn_free_string()
#[no_mangle]
pub extern "C" fn rvpn_last_error() -> *mut c_char {
    let guard = LAST_ERROR.lock().unwrap();
    match guard.as_ref() {
        Some(msg) if !msg.is_empty() => {
            match CString::new(msg.as_str()) {
                Ok(c_str) => c_str.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        _ => std::ptr::null_mut(),
    }
}

/// Free string allocated by Rust
///
/// # Safety
/// `_string` must be a pointer previously returned by this library and must not
/// be used after this call.
#[no_mangle]
pub unsafe extern "C" fn rvpn_free_string(_string: *mut c_char) {
    if _string.is_null() {
        return;
    }
    let _ = CString::from_raw(_string);
}

/// Notify Rust of network connectivity change
/// - Parameter hasInternet: 1 if internet available, 0 otherwise
/// - Returns: 0 on success
#[no_mangle]
pub extern "C" fn rvpn_network_changed(has_internet: c_int) -> c_int {
    info!(
        "[IOS_TUN_FFI] rvpn_network_changed(has_internet={}) called",
        has_internet
    );

    // Trigger a gentle reconnect when internet is available. This breaks the
    // current WebSocket connection immediately (bypassing the 15s read timeout)
    // and lets the reconnect loop establish a fresh connection on the new
    // interface. A 5-second cooldown in request_reconnect() prevents storms.
    //
    // We only reconnect when has_internet == 1 because:
    // - If we lost internet, the connection will naturally timeout or fail;
    //   forcing reconnect while offline just wastes battery.
    // - When we regain internet (or switch interface), we want to use the
    //   new path immediately.
    if has_internet == 1 {
        if let Some(client) = TUN_CLIENT.lock().unwrap().as_ref() {
            client.request_reconnect();
        }
    }

    SUCCESS
}

/// Check if the TUN client has an active WebSocket connection.
///
/// This is a non-destructive check — it does NOT modify state or trigger reconnects.
/// It returns 1 if the client exists and is in Connected state, 0 otherwise.
///
/// # Returns
/// 1 = connected, 0 = not connected or not initialized
#[no_mangle]
pub extern "C" fn rvpn_tun_check_connectivity() -> c_int {
    // Verify runtime exists before checking client state
    let _ = match TUN_RUNTIME.lock().unwrap().as_ref() {
        Some(_) => {},
        None => return 0,
    };

    let client = match TUN_CLIENT.lock().unwrap().as_ref() {
        Some(c) => c.clone(),
        None => return 0,
    };

    match client.get_state() {
        crate::ios_tun::TunClientState::Connected => 1,
        _ => 0,
    }
}

// Static for tracking if tracing is initialized
static TRACING_INITIALIZED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// ============================================================================
// OSLog Bridge - Route Rust tracing logs to iOS unified logging
// ============================================================================

/// Log level enum matching tracing levels
#[repr(C)]
#[derive(Clone, Copy)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

/// C callback type for log forwarding: fn(level, message)
pub type LogCallback = unsafe extern "C" fn(level: LogLevel, msg: *const c_char);

static LOG_CALLBACK: std::sync::Mutex<Option<LogCallback>> = std::sync::Mutex::new(None);

/// Set a callback to receive Rust log messages for forwarding to os_log
///
/// # Safety
/// The callback must be valid and thread-safe. It will be called from multiple threads.
#[no_mangle]
pub unsafe extern "C" fn rvpn_set_log_callback(callback: Option<LogCallback>) {
    let mut guard = LOG_CALLBACK.lock().unwrap();
    *guard = callback;
}

/// Write a log line to the file specified by RVPN_LOG_FILE env var (if set).
/// This bypasses macOS unified logging redaction so we can debug the tunnel.
fn write_log_to_file(level: &str, message: &str) {
    if let Ok(path) = std::env::var("RVPN_LOG_FILE") {
        use std::fs::OpenOptions;
        use std::io::Write;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let ts = format!("{:?}", now);
        let line = format!("[{} {}] {}\n", ts, level, message);
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
            let _ = file.write_all(line.as_bytes());
        }
    }
}

/// Custom tracing layer that forwards log messages to the Swift callback
struct OsLogLayer;

impl<S> tracing_subscriber::Layer<S> for OsLogLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let cb = match LOG_CALLBACK.lock().unwrap() {
            guard => *guard,
        };
        let Some(cb) = cb else { return };

        let level = match *event.metadata().level() {
            tracing::Level::TRACE => LogLevel::Trace,
            tracing::Level::DEBUG => LogLevel::Debug,
            tracing::Level::INFO => LogLevel::Info,
            tracing::Level::WARN => LogLevel::Warn,
            tracing::Level::ERROR => LogLevel::Error,
        };
        let level_str = event.metadata().level().as_str();

        // Format the message
        let mut visitor = LogVisitor(String::new());
        event.record(&mut visitor);

        // Write to file for debugging (bypasses macOS log redaction)
        write_log_to_file(level_str, &visitor.0);

        if let Ok(c_msg) = CString::new(visitor.0) {
            unsafe { cb(level, c_msg.as_ptr()) };
        }
    }
}

struct LogVisitor(String);

impl tracing::field::Visit for LogVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value).trim_matches('"').to_string();
        } else {
            if !self.0.is_empty() {
                self.0.push_str(" ");
            }
            self.0.push_str(&format!("{}={:?}", field.name(), value));
        }
    }
}

// Note: tracing-subscriber's fmt::Visit also records other types; we only need Debug

// ============================================================================
// Legacy VPN Start/Stop (delegates to Direct TUN)
// ============================================================================

/// Mobile config from Swift JSON (legacy format)
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[allow(dead_code)]
struct MobileConfig {
    server_address: String,
    identity_key_path: String,
    prekey_bundle_path: String,
    #[serde(default)]
    server_fingerprint: Option<String>,
    #[serde(default)]
    trust_on_first_use: Option<bool>,
    #[serde(default)]
    dns_servers: Vec<String>,
    #[serde(default)]
    socks5_listen: Option<String>,
    #[serde(default)]
    enable_dns_proxy: Option<bool>,
    #[serde(default = "default_dns_bind_addr")]
    dns_bind_addr: String,
    #[serde(default)]
    bypass_domains: Vec<String>,
    #[serde(default)]
    tunnel_domains: Vec<String>,
    #[serde(default)]
    split_tunnel_enabled: Option<bool>,
    #[serde(default)]
    builtin_bypass_countries: Vec<String>,
    #[serde(default)]
    block_ads: Option<bool>,
}

fn default_dns_bind_addr() -> String {
    "127.0.0.1:53".to_string()
}

/// Start VPN using Direct TUN mode
///
/// This is a legacy entry point that delegates to rvpn_tun_* functions.
/// It accepts the same JSON config format as the original implementation.
///
/// # Arguments
/// * `config_json` - JSON configuration string
///
/// # Returns
/// 0 on success, -1 on error
#[no_mangle]
pub unsafe extern "C" fn rvpn_start(config_json: *const c_char) -> c_int {
    info!("[IOS_TUN_FFI] rvpn_start() called");

    if config_json.is_null() {
        set_last_error("config_json is null");
        return ERROR_NULL_POINTER;
    }

    let json_str = match CStr::from_ptr(config_json).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Invalid config JSON encoding");
            return ERROR_INVALID_CONFIG;
        }
    };

    // Parse mobile config
    let mobile_config: MobileConfig = match serde_json::from_str(json_str) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&format!("Failed to parse config JSON: {}", e));
            return ERROR_INVALID_CONFIG;
        }
    };

    // Validate required fields
    if mobile_config.server_address.is_empty() {
        set_last_error("server_address is required");
        return ERROR_INVALID_CONFIG;
    }
    if mobile_config.identity_key_path.is_empty() {
        set_last_error("identity_key_path is required");
        return ERROR_INVALID_CONFIG;
    }
    if mobile_config.prekey_bundle_path.is_empty() {
        set_last_error("prekey_bundle_path is required");
        return ERROR_INVALID_CONFIG;
    }

    // Build TunConfig for rvpn_tun_create
    let tun_config = TunConfig {
        server_address: mobile_config.server_address,
        identity_key_path: mobile_config.identity_key_path,
        prekey_bundle_path: mobile_config.prekey_bundle_path,
        dns_servers: mobile_config.dns_servers,
        bypass_networks: vec![],
        mtu: 1420,
        split_tunnel_enabled: mobile_config.split_tunnel_enabled.unwrap_or(false),
        builtin_bypass_countries: mobile_config.builtin_bypass_countries,
        bypass_domains: mobile_config.bypass_domains,
        tunnel_domains: mobile_config.tunnel_domains,
        block_ads: mobile_config.block_ads.unwrap_or(false),
        dns_bind_addr: mobile_config.dns_bind_addr,
        enable_dns_proxy: mobile_config.enable_dns_proxy.unwrap_or(false),
        tls_fingerprint: mobile_config.server_fingerprint,
    };

    // Serialize to JSON
    let tun_json = match serde_json::to_string(&tun_config) {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!("Failed to serialize TunConfig: {}", e));
            return ERROR_INVALID_CONFIG;
        }
    };

    // Call rvpn_tun_create
    let tun_cstring = match CString::new(tun_json) {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Failed to create C string from config");
            return ERROR_INVALID_CONFIG;
        }
    };
    let create_result = rvpn_tun_create(tun_cstring.as_ptr());
    if create_result != 0 {
        set_last_error("Failed to create TUN client");
        return ERROR_INVALID_CONFIG;
    }

    // Note: state callback will be set by Swift via rvpn_tun_set_state_callback

    // Call rvpn_tun_start
    let start_result = rvpn_tun_start();
    if start_result != 0 {
        set_last_error("Failed to start TUN client");
        return ERROR_INVALID_CONFIG;
    }

    info!("[IOS_TUN_FFI] rvpn_start() - delegated to Direct TUN successfully");
    SUCCESS
}

/// Stop VPN (delegates to rvpn_tun_stop)
#[no_mangle]
pub extern "C" fn rvpn_stop() -> c_int {
    info!("[IOS_TUN_FFI] rvpn_stop() called");
    rvpn_tun_stop();
    rvpn_tun_destroy();
    info!("[IOS_TUN_FFI] rvpn_stop() - TUN client stopped");
    SUCCESS
}

/// Error codes
const SUCCESS: c_int = 0;
const ERROR_NULL_POINTER: c_int = -1;
const ERROR_NOT_INITIALIZED: c_int = -1;
#[allow(dead_code)]
const ERROR_ALREADY_RUNNING: c_int = -1;
const ERROR_INVALID_CONFIG: c_int = -1;
const ERROR_QUEUE_FULL: c_int = -2;
const ERROR_NO_DATA: c_int = -3;

// ============================================================================
// DNS Proxy for Direct TUN Mode
// ============================================================================

/// Start the local DNS proxy for Direct TUN mode
///
/// This function:
/// 1. Creates a DoH client connected to {server_path}/dns
/// 2. Creates a SplitTunnel with builtin_bypass_countries and block_ads
/// 3. Creates and runs a DnsServer on the configured bind address
///
/// The DNS server will:
/// - Bypass Chinese domains (via local resolver)
/// - Tunnel other domains via DoH/WebSocket to server
/// - Block ads when block_ads is enabled
async fn start_dns_proxy_for_direct_tun(client: &Arc<IosTunClient>) -> anyhow::Result<()> {
    use std::sync::Arc;

    info!(
        "[IOS_TUN_FFI] Starting DNS proxy on {} (enable_dns_proxy={})",
        client.get_dns_bind_addr(),
        client.is_dns_proxy_enabled()
    );

    if !client.is_dns_proxy_enabled() {
        info!("[IOS_TUN_FFI] DNS proxy disabled in config, skipping");
        return Ok(());
    }

    // Get server info from client
    let server_host = client.server_host().to_string();
    let server_port = client.server_port();
    let base_path = client.server_path();

    // Derive DNS WebSocket path from the base path
    // e.g., "/api/v1/ws/tun" → "/api/v1/ws/dns", "/api/v1/ws" → "/api/v1/ws/dns"
    let dns_path = format!("{}/dns", base_path.trim_end_matches("/tun").trim_end_matches('/'));

    // Create FlowConnectorConfig for DoH client
    let flow_config = FlowConnectorConfig {
        server_host: server_host.clone(),
        server_port,
        server_path: dns_path.clone(),
        tls_fingerprint: rvpn_client::tls_boring::TlsFingerprint::Chrome,
        identity_key: Arc::new(client.identity_key().clone()),
        server_bundle: client.server_bundle().clone(),
    };

    // Create and start the DoH client
    let doh_client = Arc::new(DohClient::new(flow_config, dns_path));
    doh_client.clone().start_cleanup_task();
    doh_client.start().await?;

    info!("[IOS_TUN_FFI] DoH client started, connecting to {}/dns", base_path);

    // Create SplitTunnel config from client config
    let split_tunnel_config = rvpn_client::split_tunnel::SplitTunnelConfig {
        enabled: true,
        builtin_bypass_countries: client.get_builtin_bypass_countries().to_vec(),
        bypass_networks: Vec::new(), // Not used for DNS
        block_ads: client.is_block_ads_enabled(),
        ..Default::default()
    };

    // Create SplitTunnel
    let dns_resolver = std::sync::Arc::new(DnsResolver::new(true, 14400, 1000, false, true, vec![]));
    dns_resolver.start_cleanup_task();
    let split_tunnel = SplitTunnel::new(split_tunnel_config, dns_resolver).await?;

    // Create DNS server with SplitTunnel and DoH client
    let dns_server = Arc::new(DnsServer::with_doh(
        split_tunnel,
        doh_client,
        client.get_dns_bind_addr().to_string(),
    ));

    info!("[IOS_TUN_FFI] DNS server created, starting on {}", client.get_dns_bind_addr());

    // Run the DNS server (runs indefinitely)
    dns_server.run().await
}

/// Create a new TUN client from JSON configuration
///
/// # Arguments
/// * `config_json` - JSON configuration string with server_address, identity_key_path, etc.
///
/// # Returns
/// 0 on success, -1 on error
///
/// # Safety
/// The `config_json` pointer must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rvpn_tun_create(config_json: *const c_char) -> c_int {
    // Initialize tracing if not already done (Swift may call rvpn_tun_create directly
    // without calling rvpn_initialize first)
    init_tracing();

    info!("[IOS_TUN_FFI] rvpn_tun_create() called");

    // Validate pointer
    if config_json.is_null() {
        error!("[IOS_TUN_FFI] config_json is null");
        return ERROR_NULL_POINTER;
    }

    // Convert C string to Rust string
    let json_str = match CStr::from_ptr(config_json).to_str() {
        Ok(s) => s,
        Err(_) => {
            error!("[IOS_TUN_FFI] Invalid config JSON encoding");
            return ERROR_INVALID_CONFIG;
        }
    };

    // Parse JSON config
    let config: TunConfig = match serde_json::from_str(json_str) {
        Ok(c) => c,
        Err(e) => {
            error!("[IOS_TUN_FFI] Failed to parse config JSON: {}", e);
            return ERROR_INVALID_CONFIG;
        }
    };

    // Validate required fields
    if config.server_address.is_empty() {
        error!("[IOS_TUN_FFI] server_address is required");
        return ERROR_INVALID_CONFIG;
    }
    if config.identity_key_path.is_empty() {
        error!("[IOS_TUN_FFI] identity_key_path is required");
        return ERROR_INVALID_CONFIG;
    }
    if config.prekey_bundle_path.is_empty() {
        error!("[IOS_TUN_FFI] prekey_bundle_path is required");
        return ERROR_INVALID_CONFIG;
    }

    // Fast path: check if already initialized
    {
        let guard = TUN_CLIENT.lock().unwrap();
        if guard.is_some() {
            warn!("[IOS_TUN_FFI] TUN client already created");
            return SUCCESS; // Already created, not an error
        }
    }

    // Claim creation lock to prevent duplicate clients during iOS double-startTunnel race.
    // iOS can call startTunnel() twice within microseconds. Without this guard,
    // both threads pass the fast-path check, create separate clients, and spawn
    // duplicate reconnect loops that fight each other.
    if TUN_CLIENT_CREATING
        .compare_exchange(false, true, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst)
        .is_err()
    {
        warn!("[IOS_TUN_FFI] TUN client creation already in progress, ignoring duplicate call");
        return SUCCESS;
    }

    // Create Tokio runtime for FFI getter functions.
    // iOS: 256 KB stack to save memory. macOS: default stack.
    let runtime = if cfg!(feature = "ios-direct-tun") {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .thread_stack_size(256 * 1024)
            .enable_all()
            .thread_name("rvpn-ffi")
            .build()
    } else {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("rvpn-ffi")
            .build()
    };
    let runtime = match runtime {
        Ok(rt) => rt,
        Err(e) => {
            error!("[IOS_TUN_FFI] Failed to create Tokio runtime: {}", e);
            TUN_CLIENT_CREATING.store(false, std::sync::atomic::Ordering::SeqCst);
            return ERROR_INVALID_CONFIG;
        }
    };

    // Create the IosTunClient
    let client = match IosTunClient::new(&config) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            error!("[IOS_TUN_FFI] Failed to create IosTunClient: {}", e);
            TUN_CLIENT_CREATING.store(false, std::sync::atomic::Ordering::SeqCst);
            return ERROR_INVALID_CONFIG;
        }
    };

    // Store client and runtime atomically under the TUN_CLIENT lock.
    // The TUN_CLIENT_CREATING flag ensures only one thread reaches this point.
    {
        let mut guard = TUN_CLIENT.lock().unwrap();
        if guard.is_some() {
            warn!("[IOS_TUN_FFI] TUN client already exists (double-check after creation)");
            TUN_CLIENT_CREATING.store(false, std::sync::atomic::Ordering::SeqCst);
            return SUCCESS;
        }
        *guard = Some(client);
    }
    {
        let mut guard = TUN_RUNTIME.lock().unwrap();
        *guard = Some(Arc::new(runtime));
    }

    TUN_CLIENT_CREATING.store(false, std::sync::atomic::Ordering::SeqCst);
    info!("[IOS_TUN_FFI] TUN client created successfully");
    SUCCESS
}

/// Start the TUN client (connects to server in background)
///
/// # Returns
/// 0 on success, -1 on error
#[no_mangle]
pub extern "C" fn rvpn_tun_start() -> c_int {
    info!("[IOS_TUN_FFI] rvpn_tun_start() called");

    // Get the client
    let client = match TUN_CLIENT.lock().unwrap().as_ref() {
        Some(c) => c.clone(),
        None => {
            error!("[IOS_TUN_FFI] TUN client not created, call rvpn_tun_create() first");
            return ERROR_NOT_INITIALIZED;
        }
    };

    // Get the runtime
    let runtime = match TUN_RUNTIME.lock().unwrap().as_ref() {
        Some(rt) => rt.clone(),
        None => {
            error!("[IOS_TUN_FFI] Runtime not initialized");
            return ERROR_NOT_INITIALIZED;
        }
    };

    // Start DNS proxy if enabled
    if client.is_dns_proxy_enabled() {
        // Abort any existing DNS proxy task before starting a new one
        {
            let mut guard = DNS_PROXY_HANDLE.lock().unwrap();
            if let Some(handle) = guard.take() {
                handle.abort();
                info!("[IOS_TUN_FFI] Aborted previous DNS proxy task");
            }
        }

        let dns_client = client.clone();
        let handle = runtime.spawn(async move {
            info!("[IOS_TUN_FFI] Starting DNS proxy task...");
            if let Err(e) = start_dns_proxy_for_direct_tun(&dns_client).await {
                error!("[IOS_TUN_FFI] DNS proxy error: {}", e);
            }
        });
        {
            let mut guard = DNS_PROXY_HANDLE.lock().unwrap();
            *guard = Some(handle);
        }
        info!("[IOS_TUN_FFI] DNS proxy task spawned");
    }

    // Enable reconnection and start the client
    client.set_reconnect_enabled(true);
    client.start();

    info!("[IOS_TUN_FFI] TUN client start initiated (reconnection enabled)");
    SUCCESS
}

/// Get current connection state
///
/// # Returns
/// 0 = Init
/// 1 = Connecting
/// 2 = IpAssigned
/// 3 = Connected
/// 4 = Error
/// -1 = Not initialized
#[no_mangle]
pub extern "C" fn rvpn_tun_get_state() -> c_int {
    match TUN_CLIENT.lock().unwrap().as_ref() {
        Some(client) => client.get_state() as c_int,
        None => ERROR_NOT_INITIALIZED,
    }
}

/// Get assigned tunnel IP address
///
/// # Returns
/// C string with IP address (e.g., "10.200.0.2") or null if not assigned
/// Caller must free with rvpn_free_string()
#[no_mangle]
pub extern "C" fn rvpn_tun_get_ip() -> *mut c_char {
    let runtime = match TUN_RUNTIME.lock().unwrap().as_ref() {
        Some(rt) => rt.clone(),
        None => return std::ptr::null_mut(),
    };

    let client = match TUN_CLIENT.lock().unwrap().as_ref() {
        Some(c) => c.clone(),
        None => return std::ptr::null_mut(),
    };

    // Use block_on to get the async result
    let ip = runtime.block_on(async {
        client.get_tunnel_ip().await
    });

    match ip {
        Some(ip_str) => {
            match CString::new(ip_str) {
                Ok(c_str) => c_str.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        None => std::ptr::null_mut(),
    }
}

/// Get assigned gateway IP address
///
/// # Returns
/// C string with IP address (e.g., "10.200.0.1") or null if not assigned
/// Caller must free with rvpn_free_string()
#[no_mangle]
pub extern "C" fn rvpn_tun_get_gateway_ip() -> *mut c_char {
    let runtime = match TUN_RUNTIME.lock().unwrap().as_ref() {
        Some(rt) => rt.clone(),
        None => return std::ptr::null_mut(),
    };

    let client = match TUN_CLIENT.lock().unwrap().as_ref() {
        Some(c) => c.clone(),
        None => return std::ptr::null_mut(),
    };

    // Use block_on to get the async result
    let ip = runtime.block_on(async {
        client.get_gateway_ip().await
    });

    match ip {
        Some(ip_str) => {
            match CString::new(ip_str) {
                Ok(c_str) => c_str.into_raw(),
                Err(_) => std::ptr::null_mut(),
            }
        }
        None => std::ptr::null_mut(),
    }
}

/// Get assigned MTU
///
/// # Returns
/// MTU value (e.g., 1420) or 0 if not assigned
#[no_mangle]
pub extern "C" fn rvpn_tun_get_mtu() -> c_int {
    let runtime = match TUN_RUNTIME.lock().unwrap().as_ref() {
        Some(rt) => rt.clone(),
        None => return 0,
    };

    let client = match TUN_CLIENT.lock().unwrap().as_ref() {
        Some(c) => c.clone(),
        None => return 0,
    };

    // Use block_on to get the async result
    let mtu = runtime.block_on(async {
        client.get_mtu().await
    });

    mtu as c_int
}

/// Get the pre-resolved VPN server IP address
///
/// This returns the IP that Rust resolved from the server hostname during client creation.
/// Use this in Swift to exclude the server IP from TUN routes, preventing
/// reconnect TCP SYN packets from being routed through the dead TUN interface.
///
/// # Returns
/// C string with IP address (e.g., "113.52.134.101") or null if not initialized
/// Caller must free with rvpn_free_string()
#[no_mangle]
pub extern "C" fn rvpn_tun_get_server_ip() -> *mut c_char {
    let client = match TUN_CLIENT.lock().unwrap().as_ref() {
        Some(c) => c.clone(),
        None => return std::ptr::null_mut(),
    };

    let ip_str = client.server_ip().to_string();
    match CString::new(ip_str) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Write packet to TUN (Swift → Rust → Server)
///
/// # Arguments
/// * `data` - Pointer to packet data (raw IP packet)
/// * `len` - Length of packet data
///
/// # Returns
/// 0 on success, -1 on error (not initialized), -2 if queue full
///
/// # Safety
/// The `data` pointer must be valid for `len` bytes.
///
/// # Thread Safety
/// This function uses try_send() to avoid block_on() deadlocks on the hot path.
/// It is safe to call from any thread (including Swift dispatch queues).
#[no_mangle]
pub unsafe extern "C" fn rvpn_tun_write_packet(
    data: *const u8,
    len: usize,
) -> c_int {
    // Validate pointer
    if data.is_null() {
        return ERROR_NULL_POINTER;
    }

    if len == 0 || len > 65535 {
        return ERROR_INVALID_CONFIG;
    }

    // Copy data to Vec<u8>
    let packet = std::slice::from_raw_parts(data, len).to_vec();

    // Get the client - clone Arc so borrow doesn't outlive the lock
    let client = match TUN_CLIENT.lock().unwrap().as_ref().cloned() {
        Some(c) => c,
        None => return ERROR_NOT_INITIALIZED,
    };

    // Non-blocking send - avoids block_on() deadlock on the hot packet write path
    match client.try_send_packet(packet) {
        Ok(_) => SUCCESS,
        Err(e) => {
            warn!("[IOS_TUN_FFI] Packet queue full, packet dropped ({:?})", e);
            ERROR_QUEUE_FULL
        }
    }
}

/// Read packet from TUN (Server → Rust → Swift)
///
/// # Arguments
/// * `buffer` - Output buffer to store packet
/// * `buffer_len` - Size of output buffer
/// * `out_len` - Pointer to store actual packet length
///
/// # Returns
/// 0 on success, -1 on error, -3 if no data available
///
/// # Safety
/// The `buffer` pointer must be valid for `buffer_len` bytes.
/// The `out_len` pointer must be valid.
#[no_mangle]
pub unsafe extern "C" fn rvpn_tun_read_packet(
    buffer: *mut u8,
    buffer_len: usize,
    out_len: *mut usize,
) -> c_int {
    // Validate pointers
    if buffer.is_null() || out_len.is_null() {
        return ERROR_NULL_POINTER;
    }

    // Get the client
    let client = match TUN_CLIENT.lock().unwrap().as_ref() {
        Some(c) => c.clone(),
        None => return ERROR_NOT_INITIALIZED,
    };

    // Try to receive packet (non-blocking)
    match client.recv_packet_from_server() {
        Some(packet) => {
            let packet_len = packet.len();

            if packet_len > buffer_len {
                error!("[IOS_TUN_FFI] Packet too large for buffer: {} > {}", packet_len, buffer_len);
                return ERROR_INVALID_CONFIG;
            }

            // Copy packet to buffer
            let buf = std::slice::from_raw_parts_mut(buffer, buffer_len);
            buf[..packet_len].copy_from_slice(&packet);
            *out_len = packet_len;

            SUCCESS
        }
        None => ERROR_NO_DATA,
    }
}

/// Wait for a packet to become available from the server.
///
/// # Arguments
/// * `timeout_ms` - Maximum time to wait in milliseconds
///
/// # Returns
/// 1 if a packet may be available, 0 if timed out, -1 if not initialized
#[no_mangle]
pub extern "C" fn rvpn_tun_wait_for_packet(timeout_ms: u64) -> c_int {
    let client = match TUN_CLIENT.lock().unwrap().as_ref() {
        Some(c) => c.clone(),
        None => return ERROR_NOT_INITIALIZED,
    };

    client.wait_for_packet(timeout_ms)
}

/// Get the last time any traffic was received from the server.
///
/// Returns the Unix timestamp (seconds) of the most recently received
/// WebSocket frame, including encrypted data and WS control frames.
/// Swift uses this to detect a suspended/dead connection without
/// mistakenly killing an idle but healthy tunnel.
#[no_mangle]
pub extern "C" fn rvpn_tun_get_last_rx_time() -> u64 {
    let client = match TUN_CLIENT.lock().unwrap().as_ref() {
        Some(c) => c.clone(),
        None => return 0,
    };

    client.last_rx_time()
}

/// Stop the TUN client
///
/// # Returns
/// 0 on success
#[no_mangle]
pub extern "C" fn rvpn_tun_stop() -> c_int {
    info!("[IOS_TUN_FFI] rvpn_tun_stop() called");

    match TUN_CLIENT.lock().unwrap().as_ref() {
        Some(client) => {
            // Disable reconnection first so the start() loop exits cleanly
            client.set_reconnect_enabled(false);
            client.stop();
            info!("[IOS_TUN_FFI] TUN client stopped");
        }
        None => {
            warn!("[IOS_TUN_FFI] TUN client not running");
        }
    }

    // Abort DNS proxy task if running
    {
        let mut guard = DNS_PROXY_HANDLE.lock().unwrap();
        if let Some(handle) = guard.take() {
            handle.abort();
            info!("[IOS_TUN_FFI] DNS proxy task aborted");
        }
    }

    SUCCESS
}

/// Destroy the TUN client and free resources
///
/// This clears both the client and runtime Mutex guards, allowing proper re-initialization.
#[no_mangle]
pub extern "C" fn rvpn_tun_destroy() {
    info!("[IOS_TUN_FFI] rvpn_tun_destroy() called");

    // Stop the client first
    rvpn_tun_stop();

    // Clear the client and runtime
    {
        let mut guard = TUN_CLIENT.lock().unwrap();
        *guard = None;
    }
    {
        let mut guard = TUN_RUNTIME.lock().unwrap();
        *guard = None;
    }

    info!("[IOS_TUN_FFI] TUN client destroyed (resources cleared)");
}

/// Set state change callback
///
/// # Arguments
/// * `callback` - Function pointer: fn(state: i32, ip: *const c_char, msg: *const c_char)
///
/// # Safety
/// The callback must be valid and thread-safe.
#[no_mangle]
pub unsafe extern "C" fn rvpn_tun_set_state_callback(
    callback: Option<extern "C" fn(state: c_int, ip: *const c_char, msg: *const c_char)>,
) {
    let client = match TUN_CLIENT.lock().unwrap().as_ref() {
        Some(c) => c.clone(),
        None => {
            warn!("[IOS_TUN_FFI] Cannot set callback - client not created");
            return;
        }
    };

    // Convert the C callback to our StateCallback type
    let state_callback: crate::ios_tun::StateCallback = callback.map(|cb| {
        std::mem::transmute::<
            extern "C" fn(c_int, *const c_char, *const c_char),
            unsafe extern "C" fn(i32, *const c_char, *const c_char)
        >(cb)
    });

    client.set_state_callback(state_callback);
    info!("[IOS_TUN_FFI] State callback set");
}

/// Get bypass IP CIDR ranges for a list of country codes
///
/// This function looks up built-in IP ranges for the specified countries
/// and returns them as a JSON array of CIDR strings.
///
/// # Arguments
/// * `country_codes_json` - JSON array of country codes, e.g., '["CN", "HK"]'
///
/// # Returns
/// JSON array of CIDR strings, e.g., '["1.0.1.0/24", "1.0.2.0/23", ...]'
/// Returns empty array "[]" on error or if no countries are found.
///
/// # Safety
/// The `country_codes_json` pointer must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rvpn_get_bypass_ips_for_countries(
    country_codes_json: *const c_char,
) -> *mut c_char {
    info!("[IOS_TUN_FFI] rvpn_get_bypass_ips_for_countries() called");

    // Helper to return empty JSON array on error
    fn empty_json() -> *mut c_char {
        CString::new("[]".to_string())
            .expect("Failed to create empty JSON string")
            .into_raw()
    }

    // Validate pointer
    if country_codes_json.is_null() {
        error!("[IOS_TUN_FFI] country_codes_json is null");
        return empty_json();
    }

    // Parse country codes from JSON
    let json_str = match CStr::from_ptr(country_codes_json).to_str() {
        Ok(s) => s,
        Err(_) => {
            error!("[IOS_TUN_FFI] Invalid country_codes_json encoding");
            return empty_json();
        }
    };

    let country_codes: Vec<String> = match serde_json::from_str(json_str) {
        Ok(codes) => codes,
        Err(e) => {
            error!("[IOS_TUN_FFI] Failed to parse country codes JSON: {}", e);
            return empty_json();
        }
    };

    // Collect all CIDRs for the specified countries
    let mut all_cidrs: Vec<String> = Vec::new();

    for country_code in &country_codes {
        if let Some(cidrs) = rvpn_client::split_tunnel::get_country_ips(country_code) {
            for cidr in cidrs {
                all_cidrs.push(cidr.to_string());
            }
        }
    }

    // Serialize to JSON
    let result_json = match serde_json::to_string(&all_cidrs) {
        Ok(json) => json,
        Err(_) => "[]".to_string(),
    };

    info!(
        "[IOS_TUN_FFI] Found {} bypass IPs for {} countries",
        all_cidrs.len(),
        country_codes.len()
    );

    // Convert to C string and return
    match CString::new(result_json) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Get bypass domains for a list of country codes
///
/// This function returns the built-in domain list for specified countries
/// (e.g., for CN: baidu.com, taobao.com, qq.com, etc.)
///
/// # Arguments
/// * `country_codes_json` - JSON array of country codes, e.g. '["CN", "HK"]'
///
/// # Returns
/// JSON array of domain strings, e.g. '["baidu.com", "taobao.com", ...]'
/// Returns empty array "[]" on error or if no countries are found.
///
// # Safety
/// The `country_codes_json` pointer must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rvpn_get_bypass_domains_for_countries(
    country_codes_json: *const c_char,
) -> *mut c_char {
    info!("[IOS_TUN_FFI] rvpn_get_bypass_domains_for_countries() called");

    // Helper to return empty JSON array on error
    fn empty_json() -> *mut c_char {
        CString::new("[]".to_string())
            .expect("Failed to create empty JSON string")
            .into_raw()
    }

    // Validate pointer
    if country_codes_json.is_null() {
        error!("[IOS_TUN_FFI] country_codes_json is null");
        return empty_json();
    }

    // Parse country codes from JSON
    let json_str = match CStr::from_ptr(country_codes_json).to_str() {
        Ok(s) => s,
        Err(_) => {
            error!("[IOS_TUN_FFI] Invalid country_codes_json encoding");
            return empty_json();
        }
    };

    let country_codes: Vec<String> = match serde_json::from_str(json_str) {
        Ok(codes) => codes,
        Err(e) => {
            error!("[IOS_TUN_FFI] Failed to parse country codes JSON: {}", e);
            return empty_json();
        }
    };

    // Collect all domains for the specified countries
    let mut all_domains: Vec<String> = Vec::new();

    for country_code in &country_codes {
        if let Some(domains) = rvpn_client::split_tunnel::get_country_domains(country_code) {
            for domain in domains {
                all_domains.push(domain.to_string());
            }
        }
    }

    // Serialize to JSON
    let result_json = match serde_json::to_string(&all_domains) {
        Ok(json) => json,
        Err(_) => "[]".to_string(),
    };

    info!(
        "[IOS_TUN_FFI] Found {} bypass domains for {} countries",
        all_domains.len(),
        country_codes.len()
    );

    // Convert to C string and return
    match CString::new(result_json) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

// ============================================================================
// Identity Management Functions
// ============================================================================

/// Generate a new Ed25519 identity key pair
///
/// # Returns
/// C string in format:
/// "R-VPN-IDENTITY-v1\ned25519: <base64_verifying_key>\nx25519: <base64_x25519_public_key>\n<base64_signing_key>\n"
/// or null on error. Must be freed with rvpn_free_string().
#[no_mangle]
pub unsafe extern "C" fn rvpn_generate_identity() -> *mut c_char {
    info!("[IOS_TUN_FFI] rvpn_generate_identity() called");

    // Generate new identity key
    let identity = IdentityKey::generate();

    // Derive X25519 public key from Ed25519 verifying key bytes
    let ed25519_pubkey_bytes = identity.verifying_key.to_bytes();
    let x25519_pubkey =
        x25519_dalek::PublicKey::from(ed25519_pubkey_bytes);

    // Format as: R-VPN-IDENTITY-v1\ned25519: <b64>\nx25519: <b64>\n<b64>\n
    let content = format!(
        "R-VPN-IDENTITY-v1\ned25519: {}\nx25519: {}\n{}\n",
        base64::engine::general_purpose::STANDARD.encode(identity.verifying_key.to_bytes()),
        base64::engine::general_purpose::STANDARD.encode(x25519_pubkey.as_bytes()),
        base64::engine::general_purpose::STANDARD.encode(identity.signing_key.to_bytes())
    );

    // Convert to C string
    match CString::new(content) {
        Ok(c_str) => c_str.into_raw(),
        Err(e) => {
            set_last_error(&format!("Failed to create identity string: {}", e));
            std::ptr::null_mut()
        }
    }
}

/// Derive X25519 public key from Ed25519 public key
///
/// # Arguments
/// * `ed25519_pubkey_b64` - Base64-encoded Ed25519 public key (C string)
///
/// # Returns
/// Base64-encoded X25519 public key as C string, or null on error.
/// Must be freed with rvpn_free_string().
///
/// # Safety
/// The `ed25519_pubkey_b64` pointer must be a valid null-terminated C string.
/// The returned pointer must be freed with rvpn_free_string().
#[no_mangle]
pub unsafe extern "C" fn rvpn_derive_x25519_pubkey(
    ed25519_pubkey_b64: *const c_char,
) -> *mut c_char {
    if ed25519_pubkey_b64.is_null() {
        set_last_error("ed25519_pubkey_b64 is null");
        return std::ptr::null_mut();
    }

    let b64_str = match CStr::from_ptr(ed25519_pubkey_b64).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Invalid Ed25519 public key encoding");
            return std::ptr::null_mut();
        }
    };

    // Decode base64 Ed25519 public key
    let ed25519_pubkey_bytes = match base64::engine::general_purpose::STANDARD.decode(b64_str) {
        Ok(bytes) => bytes,
        Err(e) => {
            set_last_error(&format!("Failed to decode base64: {}", e));
            return std::ptr::null_mut();
        }
    };

    // Convert to X25519 public key - need exactly 32 bytes
    let key_bytes: [u8; 32] = if ed25519_pubkey_bytes.len() == 32 {
        ed25519_pubkey_bytes.try_into().unwrap()
    } else {
        set_last_error("Invalid Ed25519 public key length");
        return std::ptr::null_mut();
    };

    let x25519_pubkey = x25519_dalek::PublicKey::from(key_bytes);

    // Encode to base64
    let result = base64::engine::general_purpose::STANDARD.encode(x25519_pubkey.as_bytes());

    match CString::new(result) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => {
            set_last_error("Failed to create result string");
            std::ptr::null_mut()
        }
    }
}

/// Validate an identity content string
///
/// # Arguments
/// * `identity_content` - Identity string from rvpn_generate_identity
///
/// # Returns
/// 0 if valid, -1 if invalid
///
/// # Safety
/// The `identity_content` pointer must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn rvpn_validate_identity(identity_content: *const c_char) -> c_int {
    if identity_content.is_null() {
        set_last_error("identity_content is null");
        return -1;
    }

    let content = match CStr::from_ptr(identity_content).to_str() {
        Ok(s) => s,
        Err(_) => {
            set_last_error("Invalid identity content encoding");
            return -1;
        }
    };

    // Parse the identity format:
    // R-VPN-IDENTITY-v1\ned25519: <base64>\nx25519: <base64>\n<base64_signing_key>\n
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 4 {
        set_last_error("Invalid identity format: expected at least 4 lines");
        return -1;
    }

    if lines[0] != "R-VPN-IDENTITY-v1" {
        set_last_error("Invalid identity format: wrong header");
        return -1;
    }

    // Validate ed25519 line has prefix
    if !lines[1].starts_with("ed25519:") {
        set_last_error("Invalid identity: missing ed25519 prefix");
        return -1;
    }
    let ed25519_key_b64 = &lines[1]["ed25519:".len()..].trim();
    if base64::engine::general_purpose::STANDARD.decode(ed25519_key_b64).is_err() {
        set_last_error("Invalid identity: bad ed25519 key base64");
        return -1;
    }

    // Validate x25519 line has prefix
    if !lines[2].starts_with("x25519:") {
        set_last_error("Invalid identity: missing x25519 prefix");
        return -1;
    }
    let x25519_key_b64 = &lines[2]["x25519:".len()..].trim();
    if base64::engine::general_purpose::STANDARD.decode(x25519_key_b64).is_err() {
        set_last_error("Invalid identity: bad x25519 key base64");
        return -1;
    }

    // Validate signing key
    if base64::engine::general_purpose::STANDARD.decode(lines[3]).is_err() {
        set_last_error("Invalid identity: bad signing key base64");
        return -1;
    }

    info!("[IOS_TUN_FFI] rvpn_validate_identity() - identity is valid");
    0
}
