// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Android Direct TUN FFI - FFI bridge for AndroidTunClient
//
// Uses jni 0.21 crate for JNI string handling

use std::ffi::{c_char, c_int, CString};
use std::sync::Arc;

use parking_lot::Mutex;

// Pending state callback - stored here because it's called before TUN client is created
type StateCallbackType = Option<unsafe extern "C" fn(state: i32, ip: *const c_char, msg: *const c_char)>;
static PENDING_STATE_CALLBACK: Mutex<StateCallbackType> = Mutex::new(None);

// JNI types are only available on Android
#[cfg(target_os = "android")]
use jni::JNIEnv;
#[cfg(target_os = "android")]
use jni::sys::{jclass, jstring, jobject};
#[cfg(target_os = "android")]
use jni_sys::JNIEnv as RawJNIEnv;

/// Helper to create a JNIEnv wrapper from a raw JNI env pointer.
/// The JVM passes raw `*mut jni_sys::JNIEnv` pointers, not `&mut JNIEnv` references.
#[cfg(target_os = "android")]
unsafe fn make_env(env_ptr: *mut RawJNIEnv) -> JNIEnv<'static> {
    // Safety: The JVM guarantees the pointer is valid during the JNI call.
    // We use 'static lifetime because the env pointer is only valid for this call.
    JNIEnv::from_raw(env_ptr as *mut _).expect("JNIEnv::from_raw failed - NULL or invalid env pointer")
}

// Raw Android log functions for debugging (works in release builds)
#[cfg(target_os = "android")]
extern "C" {
    fn __android_log_write(prio: i32, tag: *const c_char, msg: *const c_char) -> i32;
}

#[cfg(target_os = "android")]
fn android_log(tag: &str, msg: &str, prio: i32) {
    if let (Ok(tag_c), Ok(msg_c)) = (CString::new(tag), CString::new(msg)) {
        unsafe { __android_log_write(prio, tag_c.as_ptr(), msg_c.as_ptr()) };
    }
}

#[cfg(target_os = "android")]
macro_rules! logcat_info {
    ($($arg:tt)*) => {
        android_log("rvpn_mobile", &format!($($arg)*), 4); // ANDROID_LOG_INFO
    };
}

#[cfg(target_os = "android")]
macro_rules! logcat_error {
    ($($arg:tt)*) => {
        android_log("rvpn_mobile", &format!("ERROR: {}", format!($($arg)*)), 6); // ANDROID_LOG_ERROR
    };
}

// For non-Android builds, use opaque pointer types for compilation
#[cfg(not(target_os = "android"))]
type JNIEnv = ();
#[cfg(not(target_os = "android"))]
type JClass = *const u8;
#[cfg(not(target_os = "android"))]
type JString = *const u8;

use crate::dns_server::DnsServer;
use crate::doh_client::DohClient;
use crate::ffi::TunConfig;
use crate::flow_connector::FlowConnectorConfig;
use crate::android_tun::AndroidTunClient;
use base64::Engine;
use rvpn_client::split_tunnel::SplitTunnel;
use rvpn_client::dns_cache::DnsResolver;
use rvpn_core::crypto::IdentityKey;

// ============================================================================
// Global State
// ============================================================================

// Use Mutex<Option> instead of OnceCell so we can clear and recreate on reconnect.
static TUN_CLIENT: parking_lot::Mutex<Option<Arc<AndroidTunClient>>> = parking_lot::Mutex::new(None);
static TUN_RUNTIME: parking_lot::Mutex<Option<Arc<tokio::runtime::Runtime>>> = parking_lot::Mutex::new(None);
static LAST_ERROR: Mutex<String> = Mutex::new(String::new());
static TRACING_INITIALIZED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

// ============================================================================
// Core Runtime Functions
// ============================================================================

#[no_mangle]
pub extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnInitialize() -> c_int {
    // Only initialize once. Do NOT call tracing_subscriber::init() here —
    // it calls set_global_default() which panics if a subscriber is already set.
    // On Android, MIUI/Xiaomi system components often initialize logging before
    // our app starts, causing a panic when we try to set our own subscriber.
    //
    // Instead, we use tracing-log to bridge tracing to the log crate,
    // which outputs to stderr → logcat System.err on Android.
    if TRACING_INITIALIZED
        .compare_exchange(false, true, std::sync::atomic::Ordering::SeqCst, std::sync::atomic::Ordering::SeqCst)
        .is_err()
    {
        return SUCCESS;
    }

    // Initialize tracing-log bridge (safe — doesn't call set_global_default)
    // This allows tracing macros to output via the log crate → stderr → logcat
    let _ = tracing_log::LogTracer::init();

    SUCCESS
}

fn set_last_error(msg: &str) {
    let mut guard = LAST_ERROR.lock();
    *guard = msg.to_string();
}

/// Get the last error message as a JNI String.
/// This is the public JNI entry point called from Kotlin's RustVPNCore.rvpnLastError().
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnLastError(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
) -> jobject {
    // Convert raw JNI env pointer to JNIEnv wrapper
    let env = make_env(env_ptr);

    // Clear any pending JNI exception before creating a new string
    let _ = env.exception_clear();

    let msg = LAST_ERROR.lock();
    let text = if msg.is_empty() { "" } else { &*msg };

    match env.new_string(text) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            // If we can't create a JString, clear the exception and return null.
            // Kotlin will receive null and the caller should handle it gracefully.
            let _ = env.exception_clear();
            logcat_error!("rvpnLastError: new_string failed for '{}': {:?}", text, e);
            std::ptr::null_mut()
        }
    }
}

/// Write the last error string into a pre-allocated buffer.
/// This is an alternative buffer-based API.
///
/// # Safety
/// - `buffer` must point to a valid buffer of at least `buffer_len` bytes
/// - `out_len` must point to a valid c_int
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnGetLastErrorString(
    buffer: *mut c_char,
    buffer_len: c_int,
    out_len: *mut c_int,
) -> c_int {
    if buffer.is_null() || out_len.is_null() || buffer_len <= 0 {
        return -1;
    }

    let msg = LAST_ERROR.lock();
    if msg.is_empty() {
        *out_len = 0;
        return 0;
    }

    let bytes = msg.as_bytes();
    let total_len = bytes.len() + 1; // +1 for null terminator

    if total_len > buffer_len as usize {
        *out_len = -1;
        return -1;
    }

    let buf = std::slice::from_raw_parts_mut(buffer as *mut u8, buffer_len as usize);
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0; // null terminator
    *out_len = total_len as c_int;

    0 // success
}

#[no_mangle]
pub extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnNetworkChanged(_has_internet: c_int) -> c_int {
    logcat_info!("[Android_TUN_FFI] rvpnNetworkChanged(has_internet={}) called", _has_internet);
    SUCCESS
}

#[no_mangle]
pub extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnPing() -> c_int {
    logcat_info!("[Android_TUN_FFI] rvpnPing() called - JNI working!");
    42
}

// Error codes
const SUCCESS: c_int = 0;
#[allow(dead_code)]
const ERROR_NULL_POINTER: c_int = -1;
const ERROR_NOT_INITIALIZED: c_int = -1;
#[allow(dead_code)]
const ERROR_ALREADY_RUNNING: c_int = -1;
const ERROR_INVALID_CONFIG: c_int = -1;
const ERROR_QUEUE_FULL: c_int = -2;
const ERROR_NO_DATA: c_int = -3;

// ============================================================================
// Mobile Config (Legacy Format)
// ============================================================================

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
    "127.0.0.1:5353".to_string()
}

// ============================================================================
// JNI String Conversion Helper
// ============================================================================

/// Safely convert a JNI string to a Rust String using raw JNI sys calls.
/// This avoids lifetime issues with JString wrappers.
#[cfg(target_os = "android")]
unsafe fn jstring_to_rust(env_ptr: *mut RawJNIEnv, jstr: jstring) -> Option<String> {
    if env_ptr.is_null() {
        logcat_error!("jstring_to_rust: null env pointer");
        return None;
    }
    if jstr.is_null() {
        logcat_error!("jstring_to_rust: null jstring");
        return None;
    }

    let iface = &**env_ptr;
    let get_string_utf_chars = iface.GetStringUTFChars.unwrap();
    let release_string_utf_chars = iface.ReleaseStringUTFChars.unwrap();

    let ptr = get_string_utf_chars(env_ptr, jstr, std::ptr::null_mut());
    if ptr.is_null() {
        logcat_error!("jstring_to_rust: GetStringUTFChars returned NULL");
        return None;
    }

    let cstr = std::ffi::CStr::from_ptr(ptr);
    let result = cstr.to_string_lossy().into_owned();
    release_string_utf_chars(env_ptr, jstr, ptr);
    Some(result)
}

/// Write a Rust string into a pre-allocated buffer from Kotlin.
/// Returns the number of bytes written (including null terminator), or -1 on error.
///
/// # Safety
/// - `buffer` must point to a valid buffer of at least `buffer_len` bytes
/// - `out_len` must point to a valid c_int
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnWriteStringToBuffer(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
    rust_string: jstring,
    buffer: *mut c_char,
    buffer_len: c_int,
    out_len: *mut c_int,
) -> c_int {
    if buffer.is_null() || out_len.is_null() || buffer_len <= 0 {
        return -1;
    }

    let rust_str = match jstring_to_rust(env_ptr, rust_string) {
        Some(s) => s,
        None => {
            logcat_error!("[Android_TUN_FFI] rvpnWriteStringToBuffer: failed to get string from JNI");
            return -1;
        }
    };

    let bytes = rust_str.as_bytes();
    let total_len = bytes.len() + 1; // +1 for null terminator

    if total_len > buffer_len as usize {
        logcat_error!(
            "[Android_TUN_FFI] rvpnWriteStringToBuffer: string too large ({} > {})",
            total_len, buffer_len
        );
        *out_len = -1;
        return -1;
    }

    let buf = std::slice::from_raw_parts_mut(buffer as *mut u8, buffer_len as usize);
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0; // null terminator
    *out_len = total_len as c_int;

    0 // success
}

// ============================================================================
// VPN Start/Stop Functions
// ============================================================================

#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnStart(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
    config_json: jstring,
) -> c_int {
    logcat_info!("[Android_TUN_FFI] rvpnStart() called");

    let json_str = match jstring_to_rust(env_ptr, config_json) {
        Some(s) => s,
        None => {
            logcat_error!("[Android_TUN_FFI] Failed to get string from JNI");
            set_last_error("Invalid JNI string");
            return ERROR_INVALID_CONFIG;
        }
    };

    let mobile_config: MobileConfig = match serde_json::from_str(&json_str) {
        Ok(c) => c,
        Err(e) => {
            set_last_error(&format!("Failed to parse config JSON: {}", e));
            return ERROR_INVALID_CONFIG;
        }
    };

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

    let tun_json = match serde_json::to_string(&tun_config) {
        Ok(j) => j,
        Err(e) => {
            set_last_error(&format!("Failed to serialize TunConfig: {}", e));
            return ERROR_INVALID_CONFIG;
        }
    };

    let create_result = create_tun_client_impl(&tun_json);
    if create_result != 0 {
        set_last_error("Failed to create TUN client");
        return ERROR_INVALID_CONFIG;
    }

    let start_result = Java_com_rvpn_client_core_RustVPNCore_rvpnTunStart();
    if start_result != 0 {
        set_last_error("Failed to start TUN client");
        return ERROR_INVALID_CONFIG;
    }

    logcat_info!("[Android_TUN_FFI] rvpnStart() - delegated to Direct TUN successfully");
    SUCCESS
}

#[no_mangle]
pub extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnStop() -> c_int {
    logcat_info!("[Android_TUN_FFI] rvpnStop() called");
    Java_com_rvpn_client_core_RustVPNCore_rvpnTunStop();
    Java_com_rvpn_client_core_RustVPNCore_rvpnTunDestroy();
    logcat_info!("[Android_TUN_FFI] rvpnStop() - TUN client stopped");
    SUCCESS
}

// ============================================================================
// DNS Proxy for Direct TUN Mode
// ============================================================================

async fn start_dns_proxy_for_direct_tun(client: &Arc<AndroidTunClient>) -> anyhow::Result<()> {
    use std::sync::Arc;

    logcat_info!(
        "[Android_TUN_FFI] Starting DNS proxy on {} (enable_dns_proxy={})",
        client.get_dns_bind_addr(),
        client.is_dns_proxy_enabled()
    );

    if !client.is_dns_proxy_enabled() {
        logcat_info!("[Android_TUN_FFI] DNS proxy disabled in config, skipping");
        return Ok(());
    }

    let server_host = client.server_host().to_string();
    let server_port = client.server_port();
    let base_path = client.server_path();

    let dns_path = format!("{}/dns", base_path.trim_end_matches("/tun").trim_end_matches('/'));

    let flow_config = FlowConnectorConfig {
        server_host: server_host.clone(),
        server_port,
        server_path: dns_path.clone(),
        tls_fingerprint: client.tls_fingerprint(),
        identity_key: Arc::new(client.identity_key().clone()),
        server_bundle: client.server_bundle().clone(),
    };

    let doh_client = Arc::new(DohClient::new(flow_config, dns_path));
    doh_client.clone().start_cleanup_task();
    doh_client.start().await?;

    logcat_info!("[Android_TUN_FFI] DoH client started, connecting to {}/dns", base_path);

    let split_tunnel_config = rvpn_client::split_tunnel::SplitTunnelConfig {
        enabled: true,
        builtin_bypass_countries: client.get_builtin_bypass_countries().to_vec(),
        bypass_networks: client.get_bypass_networks().to_vec(),
        block_ads: client.is_block_ads_enabled(),
        ..Default::default()
    };

    logcat_info!(
        "[Android_TUN_FFI] Split tunnel config: countries={:?}, bypass_networks={}, block_ads={}",
        split_tunnel_config.builtin_bypass_countries,
        split_tunnel_config.bypass_networks.len(),
        split_tunnel_config.block_ads
    );

    let dns_resolver = std::sync::Arc::new(DnsResolver::new(true, 14400, 1000, false, true, vec![]));
    dns_resolver.start_cleanup_task();
    let split_tunnel = SplitTunnel::new(split_tunnel_config, dns_resolver).await?;

    let dns_server = Arc::new(DnsServer::with_doh(
        split_tunnel,
        doh_client,
        client.get_dns_bind_addr().to_string(),
    ));

    logcat_info!("[Android_TUN_FFI] DNS server created, starting on {}", client.get_dns_bind_addr());

    dns_server.run().await
}

// ============================================================================
// TUN Client Functions
// ============================================================================

#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnTunCreate(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
    config_json: jstring,
) -> c_int {
    logcat_info!("rvpnTunCreate() called");

    let json_str = match jstring_to_rust(env_ptr, config_json) {
        Some(s) => {
            logcat_info!("Config JSON received ({} bytes)", s.len());
            s
        }
        None => {
            logcat_error!("Failed to get config string from JNI");
            set_last_error("Invalid config JSON - JNI string conversion failed");
            return ERROR_INVALID_CONFIG;
        }
    };

    // Use catch_unwind to prevent panics from crossing the FFI boundary
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        create_tun_client_impl(&json_str)
    }));

    match result {
        Ok(code) => {
            logcat_info!("rvpnTunCreate returning: {}", code);
            code
        }
        Err(panic_info) => {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic in rvpnTunCreate".to_string()
            };
            logcat_error!("Panic in rvpnTunCreate: {}", msg);
            set_last_error(&format!("Panic: {}", msg));
            ERROR_INVALID_CONFIG
        }
    }
}

fn create_tun_client_impl(json_str: &str) -> c_int {
    logcat_info!("create_tun_client_impl() called");

    let config: TunConfig = match serde_json::from_str::<TunConfig>(json_str) {
        Ok(c) => {
            logcat_info!("Config parsed: server={}, identity={}, prekey={}",
                c.server_address, c.identity_key_path, c.prekey_bundle_path);
            c
        }
        Err(e) => {
            logcat_error!("Failed to parse config JSON: {}", e);
            set_last_error(&format!("Failed to parse config JSON: {}", e));
            return ERROR_INVALID_CONFIG;
        }
    };

    if config.server_address.is_empty() {
        logcat_error!("server_address is required");
        set_last_error("server_address is required");
        return ERROR_INVALID_CONFIG;
    }
    if config.identity_key_path.is_empty() {
        logcat_error!("identity_key_path is required");
        set_last_error("identity_key_path is required");
        return ERROR_INVALID_CONFIG;
    }
    if config.prekey_bundle_path.is_empty() {
        logcat_error!("prekey_bundle_path is required");
        set_last_error("prekey_bundle_path is required");
        return ERROR_INVALID_CONFIG;
    }

    logcat_info!("Validating file paths...");

    // Check if identity key file exists
    if !std::path::Path::new(&config.identity_key_path).exists() {
        logcat_error!("Identity key file not found: {}", config.identity_key_path);
        set_last_error(&format!("Identity key file not found: {}", config.identity_key_path));
        return ERROR_INVALID_CONFIG;
    }

    // Check if prekey bundle file exists
    if !std::path::Path::new(&config.prekey_bundle_path).exists() {
        logcat_error!("Prekey bundle file not found: {}", config.prekey_bundle_path);
        set_last_error(&format!("Prekey bundle file not found: {}", config.prekey_bundle_path));
        return ERROR_INVALID_CONFIG;
    }

    logcat_info!("Files validated, creating AndroidTunClient...");

    if TUN_CLIENT.lock().clone().is_some() {
        logcat_info!("[WARN]  TUN client already created");
        return SUCCESS;
    }

    // Use catch_unwind to prevent panics from crossing the FFI boundary
    logcat_info!("Calling AndroidTunClient::new...");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        AndroidTunClient::new(&config)
    }));

    let client = match result {
        Ok(Ok(c)) => {
            logcat_info!("AndroidTunClient::new succeeded");
            Arc::new(c)
        }
        Ok(Err(e)) => {
            logcat_error!("AndroidTunClient::new failed: {}", e);
            set_last_error(&format!("Failed to create TUN client: {}", e));
            return ERROR_INVALID_CONFIG;
        }
        Err(panic_info) => {
            let msg = if let Some(s) = panic_info.downcast_ref::<&str>() {
                s.to_string()
            } else if let Some(s) = panic_info.downcast_ref::<String>() {
                s.clone()
            } else {
                "Unknown panic in AndroidTunClient::new".to_string()
            };
            logcat_error!("Panic in AndroidTunClient::new: {}", msg);
            set_last_error(&format!("Panic creating TUN client: {}", msg));
            return ERROR_INVALID_CONFIG;
        }
    };

    let _ = TUN_RUNTIME.lock().insert(client.runtime().clone());
    logcat_info!("[Android_TUN_FFI] AndroidTunClient created");

    if TUN_CLIENT.lock().replace(client).is_some() {
        logcat_info!("[Android_TUN_FFI] TUN client replaced (was previously set)");
    } else {
        logcat_info!("[Android_TUN_FFI] TUN client created successfully");
    }

    // Apply any pending state callback that was set before the client was created
    let pending_cb = PENDING_STATE_CALLBACK.lock().clone();
    if pending_cb.is_some() {
        if let Some(client) = TUN_CLIENT.lock().clone() {
            client.set_state_callback(pending_cb);
            logcat_info!("[Android_TUN_FFI] Pending state callback applied");
        }
    }

    SUCCESS
}

#[no_mangle]
pub extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnTunStart() -> c_int {
    logcat_info!("[Android_TUN_FFI] rvpnTunStart() called");

    let client = match TUN_CLIENT.lock().clone() {
        Some(c) => c.clone(),
        None => {
            logcat_error!("[Android_TUN_FFI] TUN client not created, call rvpnTunCreate() first");
            return ERROR_NOT_INITIALIZED;
        }
    };
    logcat_info!("[Android_TUN_FFI] rvpnTunStart() got client");

    let runtime = match TUN_RUNTIME.lock().clone() {
        Some(rt) => rt.clone(),
        None => {
            logcat_error!("[Android_TUN_FFI] Runtime not initialized");
            return ERROR_NOT_INITIALIZED;
        }
    };
    logcat_info!("[Android_TUN_FFI] rvpnTunStart() got runtime");

    if client.is_dns_proxy_enabled() {
        let dns_client = client.clone();
        runtime.spawn(async move {
            logcat_info!("[Android_TUN_FFI] Starting DNS proxy task...");
            if let Err(e) = start_dns_proxy_for_direct_tun(&dns_client).await {
                logcat_error!("[Android_TUN_FFI] DNS proxy error: {}", e);
            }
        });
        logcat_info!("[Android_TUN_FFI] DNS proxy task spawned");
        // Give DNS proxy a moment to bind before packet relay starts
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    logcat_info!("[Android_TUN_FFI] About to spawn connect task");
    runtime.spawn(async move {
        logcat_info!("[Android_TUN_FFI] Starting TUN client connection...");
        if let Err(e) = client.connect().await {
            logcat_error!("[Android_TUN_FFI] Connection failed: {}", e);
        }
    });
    logcat_info!("[Android_TUN_FFI] TUN client start initiated");
    SUCCESS
}

#[no_mangle]
pub extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnTunGetState() -> c_int {
    match TUN_CLIENT.lock().clone() {
        Some(client) => client.get_state() as c_int,
        None => ERROR_NOT_INITIALIZED,
    }
}

/// Get the tunnel IP address, writing it into a pre-allocated buffer.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// Get the assigned tunnel IP address as a JNI String.
/// This is the public JNI entry point called from Kotlin's RustVPNCore.rvpnTunGetIp().
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnTunGetIp(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
) -> jobject {
    let env = make_env(env_ptr);

    let runtime = match TUN_RUNTIME.lock().clone() {
        Some(rt) => rt.clone(),
        None => return env.new_string("").unwrap_or_default().as_raw(),
    };
    let client = match TUN_CLIENT.lock().clone() {
        Some(c) => c.clone(),
        None => return env.new_string("").unwrap_or_default().as_raw(),
    };

    let ip = runtime.block_on(async { client.get_tunnel_ip().await });

    match ip {
        Some(ip_str) => env.new_string(&ip_str).unwrap_or_default().as_raw(),
        None => env.new_string("").unwrap_or_default().as_raw(),
    }
}

/// Write the tunnel IP into a pre-allocated buffer (alternative buffer-based API).
///
/// # Safety
/// - `buffer` must point to a valid buffer of at least `buffer_len` bytes
/// - `out_len` must point to a valid c_int
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnTunGetIpBuffer(
    buffer: *mut c_char,
    buffer_len: c_int,
    out_len: *mut c_int,
) -> c_int {
    if buffer.is_null() || out_len.is_null() || buffer_len <= 0 {
        return -1;
    }

    let runtime = match TUN_RUNTIME.lock().clone() {
        Some(rt) => rt.clone(),
        None => return -1,
    };

    let client = match TUN_CLIENT.lock().clone() {
        Some(c) => c.clone(),
        None => return -1,
    };

    let ip = runtime.block_on(async {
        client.get_tunnel_ip().await
    });

    match ip {
        Some(ip_str) => {
            let bytes = ip_str.as_bytes();
            let total_len = bytes.len() + 1; // +1 for null terminator

            if total_len > buffer_len as usize {
                *out_len = -1;
                return -1;
            }

            let buf = std::slice::from_raw_parts_mut(buffer as *mut u8, buffer_len as usize);
            buf[..bytes.len()].copy_from_slice(bytes);
            buf[bytes.len()] = 0; // null terminator
            *out_len = total_len as c_int;
            0
        }
        None => {
            *out_len = 0;
            -1
        }
    }
}

#[no_mangle]
pub extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnTunGetMtu() -> c_int {
    let runtime = match TUN_RUNTIME.lock().clone() {
        Some(rt) => rt.clone(),
        None => return 0,
    };

    let client = match TUN_CLIENT.lock().clone() {
        Some(c) => c.clone(),
        None => return 0,
    };

    let mtu = runtime.block_on(async {
        client.get_mtu().await
    });

    mtu as c_int
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnTunWritePacket(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
    data: jni_sys::jbyteArray,
) -> jni_sys::jint {
    let env = jni::JNIEnv::from_raw(env_ptr).unwrap();
    let java_array = jni::objects::JByteArray::from_raw(data);
    let len = env.get_array_length(&java_array).unwrap_or(0) as usize;

    if len == 0 || len > 65535 {
        return ERROR_INVALID_CONFIG;
    }

    let mut packet = vec![0i8; len];
    let _ = env.get_byte_array_region(&java_array, 0, &mut packet);
    let packet: Vec<u8> = packet.iter().map(|b| *b as u8).collect();

    let client = match TUN_CLIENT.lock().clone() {
        Some(c) => c.clone(),
        None => return ERROR_NOT_INITIALIZED,
    };

    // Non-blocking send — avoids block_on() deadlock on the hot packet write path.
    // This mirrors iOS rvpn_tun_write_packet() which uses try_send_packet().
    match client.try_send_packet(packet) {
        Ok(_) => SUCCESS,
        Err(_) => ERROR_QUEUE_FULL,
    }
}

#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnTunReadPacket(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
    buffer: jni_sys::jbyteArray,
) -> jni_sys::jint {
    let client = match TUN_CLIENT.lock().clone() {
        Some(c) => c.clone(),
        None => return ERROR_NOT_INITIALIZED,
    };

    match client.recv_packet_from_server() {
        Some(packet) => {
            let packet_len = packet.len() as i32;

            // Copy packet data into the Java byte array using JNI functions
            let env = jni::JNIEnv::from_raw(env_ptr).unwrap();
            let java_array = jni::objects::JByteArray::from_raw(buffer);
            let len = env.get_array_length(&java_array).unwrap_or(0);
            if packet_len > len {
                logcat_error!("[Android_TUN_FFI] Packet too large for buffer: {} > {}", packet_len, len);
                return ERROR_INVALID_CONFIG;
            }
            let _ = env.set_byte_array_region(&java_array, 0, 
                unsafe { std::slice::from_raw_parts(packet.as_ptr() as *const i8, packet_len as usize) });

            packet_len
        }
        None => ERROR_NO_DATA,
    }
}

#[no_mangle]
pub extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnTunStop() -> c_int {
    logcat_info!("[Android_TUN_FFI] rvpnTunStop() called");

    match TUN_CLIENT.lock().clone() {
        Some(client) => {
            client.stop();
            logcat_info!("[Android_TUN_FFI] TUN client stopped");
        }
        None => {
            logcat_info!("[Android_TUN_FFI] TUN client not running");
        }
    }

    SUCCESS
}

#[no_mangle]
pub extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnTunDestroy() {
    logcat_info!("[Android_TUN_FFI] rvpnTunDestroy() called");
    Java_com_rvpn_client_core_RustVPNCore_rvpnTunStop();
    // Clear the client and runtime so rvpnTunCreate() can create fresh ones
    *TUN_CLIENT.lock() = None;
    *TUN_RUNTIME.lock() = None;
    logcat_info!("[Android_TUN_FFI] TUN client and runtime cleared");
}

#[no_mangle]
pub extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnTunSetStateCallback(
    callback: Option<unsafe extern "C" fn(state: i32, ip: *const c_char, msg: *const c_char)>,
) {
    // Store the callback - it will be applied when the client is created
    let mut pending = PENDING_STATE_CALLBACK.lock();
    *pending = callback;
    logcat_info!("[Android_TUN_FFI] State callback stored (will be applied on client creation)");

    // Also try to set it on existing client if any (race condition protection)
    if let Some(client) = TUN_CLIENT.lock().clone() {
        client.set_state_callback(callback);
    }
}

// ============================================================================
// Bypass IP/Domain Functions
// ============================================================================

/// Get bypass IPs for countries as a JNI String (JSON array).
/// This is the public JNI entry point called from Kotlin's RustVPNCore.rvpnGetBypassIpsForCountries().
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnGetBypassIpsForCountries(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
    country_codes_json: jstring,
) -> jobject {
    let env = make_env(env_ptr);

    let json_str = match jstring_to_rust(env_ptr, country_codes_json) {
        Some(s) => s,
        None => {
            logcat_error!("Failed to get string from JNI");
            return env.new_string("[]").unwrap_or_default().as_raw();
        }
    };

    let country_codes: Vec<String> = match serde_json::from_str(&json_str) {
        Ok(codes) => codes,
        Err(e) => {
            logcat_error!("Failed to parse country codes JSON: {}", e);
            return env.new_string("[]").unwrap_or_default().as_raw();
        }
    };

    let mut all_cidrs: Vec<String> = Vec::new();
    for country_code in &country_codes {
        if let Some(cidrs) = rvpn_client::split_tunnel::get_country_ips(country_code) {
            for cidr in cidrs {
                all_cidrs.push(cidr.to_string());
            }
        }
    }

    let result_json = serde_json::to_string(&all_cidrs).unwrap_or_else(|_| "[]".to_string());
    logcat_info!("Found {} bypass IPs for {} countries", all_cidrs.len(), country_codes.len());

    env.new_string(&result_json).unwrap_or_default().as_raw()
}

/// Buffer-based alternative for bypass IPs (used internally).
///
/// # Safety
/// - `buffer` must point to a valid buffer of at least `buffer_len` bytes
/// - `out_len` must point to a valid c_int
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnGetBypassIpsForCountriesBuffer(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
    country_codes_json: jstring,
    buffer: *mut c_char,
    buffer_len: c_int,
    out_len: *mut c_int,
) -> c_int {
    if buffer.is_null() || out_len.is_null() || buffer_len <= 0 {
        return -1;
    }

    logcat_info!("[Android_TUN_FFI] rvpnGetBypassIpsForCountries() called");

    let json_str = match jstring_to_rust(env_ptr, country_codes_json) {
        Some(s) => s,
        None => {
            logcat_error!("[Android_TUN_FFI] Failed to get string from JNI");
            write_empty_json_to_buffer(buffer, buffer_len, out_len);
            return -1;
        }
    };

    let country_codes: Vec<String> = match serde_json::from_str(&json_str) {
        Ok(codes) => codes,
        Err(e) => {
            logcat_error!("[Android_TUN_FFI] Failed to parse country codes JSON: {}", e);
            write_empty_json_to_buffer(buffer, buffer_len, out_len);
            return -1;
        }
    };

    let mut all_cidrs: Vec<String> = Vec::new();

    for country_code in &country_codes {
        if let Some(cidrs) = rvpn_client::split_tunnel::get_country_ips(country_code) {
            for cidr in cidrs {
                all_cidrs.push(cidr.to_string());
            }
        }
    }

    let result_json = match serde_json::to_string(&all_cidrs) {
        Ok(json) => json,
        Err(_) => "[]".to_string(),
    };

    logcat_info!("[Android_TUN_FFI] Found {} bypass IPs for {} countries", all_cidrs.len(), country_codes.len());

    write_string_to_buffer(buffer, buffer_len, &result_json, out_len)
}

/// Get bypass domains for countries as a JNI String (JSON array).
/// This is the public JNI entry point called from Kotlin's RustVPNCore.rvpnGetBypassDomainsForCountries().
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnGetBypassDomainsForCountries(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
    country_codes_json: jstring,
) -> jobject {
    let env = make_env(env_ptr);

    let json_str = match jstring_to_rust(env_ptr, country_codes_json) {
        Some(s) => s,
        None => {
            logcat_error!("Failed to get string from JNI");
            return env.new_string("[]").unwrap_or_default().as_raw();
        }
    };

    let country_codes: Vec<String> = match serde_json::from_str(&json_str) {
        Ok(codes) => codes,
        Err(e) => {
            logcat_error!("Failed to parse country codes JSON: {}", e);
            return env.new_string("[]").unwrap_or_default().as_raw();
        }
    };

    let mut all_domains: Vec<String> = Vec::new();
    for country_code in &country_codes {
        if let Some(domains) = rvpn_client::split_tunnel::get_country_domains(country_code) {
            for domain in domains {
                all_domains.push(domain.to_string());
            }
        }
    }

    let result_json = serde_json::to_string(&all_domains).unwrap_or_else(|_| "[]".to_string());
    logcat_info!("Found {} bypass domains for {} countries", all_domains.len(), country_codes.len());

    env.new_string(&result_json).unwrap_or_default().as_raw()
}

/// Buffer-based alternative for bypass domains.
///
/// # Safety
/// - `buffer` must point to a valid buffer of at least `buffer_len` bytes
/// - `out_len` must point to a valid c_int
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnGetBypassDomainsForCountriesBuffer(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
    country_codes_json: jstring,
    buffer: *mut c_char,
    buffer_len: c_int,
    out_len: *mut c_int,
) -> c_int {
    if buffer.is_null() || out_len.is_null() || buffer_len <= 0 {
        return -1;
    }

    logcat_info!("[Android_TUN_FFI] rvpnGetBypassDomainsForCountries() called");

    let json_str = match jstring_to_rust(env_ptr, country_codes_json) {
        Some(s) => s,
        None => {
            logcat_error!("[Android_TUN_FFI] Failed to get string from JNI");
            write_empty_json_to_buffer(buffer, buffer_len, out_len);
            return -1;
        }
    };

    let country_codes: Vec<String> = match serde_json::from_str(&json_str) {
        Ok(codes) => codes,
        Err(e) => {
            logcat_error!("[Android_TUN_FFI] Failed to parse country codes JSON: {}", e);
            write_empty_json_to_buffer(buffer, buffer_len, out_len);
            return -1;
        }
    };

    let mut all_domains: Vec<String> = Vec::new();

    for country_code in &country_codes {
        if let Some(domains) = rvpn_client::split_tunnel::get_country_domains(country_code) {
            for domain in domains {
                all_domains.push(domain.to_string());
            }
        }
    }

    let result_json = match serde_json::to_string(&all_domains) {
        Ok(json) => json,
        Err(_) => "[]".to_string(),
    };

    logcat_info!("[Android_TUN_FFI] Found {} bypass domains for {} countries", all_domains.len(), country_codes.len());

    write_string_to_buffer(buffer, buffer_len, &result_json, out_len)
}

/// Helper: write an empty JSON array "[]" to the buffer
unsafe fn write_empty_json_to_buffer(buffer: *mut c_char, buffer_len: c_int, out_len: *mut c_int) {
    const EMPTY_JSON: &[u8] = b"[]";
    let total_len = EMPTY_JSON.len() + 1;

    if total_len <= buffer_len as usize {
        let buf = std::slice::from_raw_parts_mut(buffer as *mut u8, buffer_len as usize);
        buf[..EMPTY_JSON.len()].copy_from_slice(EMPTY_JSON);
        buf[EMPTY_JSON.len()] = 0;
        *out_len = total_len as c_int;
    } else {
        *out_len = -1;
    }
}

/// Helper: write a string to the buffer with null terminator
/// Returns 0 on success, -1 if buffer too small
unsafe fn write_string_to_buffer(
    buffer: *mut c_char,
    buffer_len: c_int,
    s: &str,
    out_len: *mut c_int,
) -> c_int {
    let bytes = s.as_bytes();
    let total_len = bytes.len() + 1;

    if total_len > buffer_len as usize {
        *out_len = -1;
        return -1;
    }

    let buf = std::slice::from_raw_parts_mut(buffer as *mut u8, buffer_len as usize);
    buf[..bytes.len()].copy_from_slice(bytes);
    buf[bytes.len()] = 0;
    *out_len = total_len as c_int;
    0
}

// ============================================================================
// Identity Management Functions
// ============================================================================

/// Generate a new identity key pair and write it into a pre-allocated buffer.
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// - `buffer` must point to a valid buffer of at least `buffer_len` bytes
/// - `out_len` must point to a valid c_int
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnGenerateIdentity(
    buffer: *mut c_char,
    buffer_len: c_int,
    out_len: *mut c_int,
) -> c_int {
    if buffer.is_null() || out_len.is_null() || buffer_len <= 0 {
        return -1;
    }

    logcat_info!("[Android_TUN_FFI] rvpnGenerateIdentity() called");

    let identity = IdentityKey::generate();

    let content = format!(
        "R-VPN-IDENTITY-v1\n{}\n{}\n",
        base64::engine::general_purpose::STANDARD.encode(identity.verifying_key.to_bytes()),
        base64::engine::general_purpose::STANDARD.encode(identity.signing_key.to_bytes())
    );

    let result = write_string_to_buffer(buffer, buffer_len, &content, out_len);
    if result != 0 {
        set_last_error("Buffer too small for identity string");
    }
    result
}

/// Derive an X25519 public key from an Ed25519 public key as a JNI String (base64).
/// This is the public JNI entry point called from Kotlin's RustVPNCore.rvpnDeriveX25519Pubkey().
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnDeriveX25519Pubkey(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
    ed25519_pubkey_b64: jstring,
) -> jobject {
    let env = make_env(env_ptr);

    let b64_str = match jstring_to_rust(env_ptr, ed25519_pubkey_b64) {
        Some(s) => s,
        None => {
            set_last_error("Failed to get string from JNI");
            return env.new_string("").unwrap_or_default().as_raw();
        }
    };

    let ed25519_pubkey_bytes = match base64::engine::general_purpose::STANDARD.decode(&b64_str) {
        Ok(bytes) => bytes,
        Err(e) => {
            set_last_error(&format!("Failed to decode base64: {}", e));
            return env.new_string("").unwrap_or_default().as_raw();
        }
    };

    let key_bytes: [u8; 32] = match ed25519_pubkey_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            set_last_error("Invalid Ed25519 public key length");
            return env.new_string("").unwrap_or_default().as_raw();
        }
    };

    let x25519_pubkey = x25519_dalek::PublicKey::from(key_bytes);
    let result = base64::engine::general_purpose::STANDARD.encode(x25519_pubkey.as_bytes());
    env.new_string(&result).unwrap_or_default().as_raw()
}

/// Buffer-based alternative for X25519 pubkey derivation.
///
/// Returns 0 on success, -1 on error.
///
/// # Safety
/// - `buffer` must point to a valid buffer of at least `buffer_len` bytes
/// - `out_len` must point to a valid c_int
#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnDeriveX25519PubkeyBuffer(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
    ed25519_pubkey_b64: jstring,
    buffer: *mut c_char,
    buffer_len: c_int,
    out_len: *mut c_int,
) -> c_int {
    if buffer.is_null() || out_len.is_null() || buffer_len <= 0 {
        return -1;
    }

    let b64_str = match jstring_to_rust(env_ptr, ed25519_pubkey_b64) {
        Some(s) => s,
        None => {
            set_last_error("Failed to get string from JNI");
            return -1;
        }
    };

    let ed25519_pubkey_bytes = match base64::engine::general_purpose::STANDARD.decode(&b64_str) {
        Ok(bytes) => bytes,
        Err(e) => {
            set_last_error(&format!("Failed to decode base64: {}", e));
            return -1;
        }
    };

    let key_bytes: [u8; 32] = match ed25519_pubkey_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            set_last_error("Invalid Ed25519 public key length");
            return -1;
        }
    };

    let x25519_pubkey = x25519_dalek::PublicKey::from(key_bytes);
    let result = base64::engine::general_purpose::STANDARD.encode(x25519_pubkey.as_bytes());

    write_string_to_buffer(buffer, buffer_len, &result, out_len)
}

#[cfg(target_os = "android")]
#[no_mangle]
pub unsafe extern "C" fn Java_com_rvpn_client_core_RustVPNCore_rvpnValidateIdentity(
    env_ptr: *mut jni_sys::JNIEnv,
    _class: jclass,
    identity_content: jstring,
) -> c_int {
    let content = match jstring_to_rust(env_ptr, identity_content) {
        Some(s) => s,
        None => {
            set_last_error("Failed to get string from JNI");
            return -1;
        }
    };

    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 3 {
        set_last_error("Invalid identity format: expected at least 3 lines");
        return -1;
    }

    if lines[0] != "R-VPN-IDENTITY-v1" {
        set_last_error("Invalid identity format: wrong header");
        return -1;
    }

    if base64::engine::general_purpose::STANDARD.decode(lines[1]).is_err() {
        set_last_error("Invalid identity: bad public key base64");
        return -1;
    }

    if base64::engine::general_purpose::STANDARD.decode(lines[2]).is_err() {
        set_last_error("Invalid identity: bad private key base64");
        return -1;
    }

    logcat_info!("[Android_TUN_FFI] rvpnValidateIdentity() - identity is valid");
    0
}
