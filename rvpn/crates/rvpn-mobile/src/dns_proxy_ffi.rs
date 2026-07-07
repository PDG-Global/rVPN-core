// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// DNS proxy FFI for NEDNSProxyProvider extension.
// Runs on a dedicated OS thread with its own Tokio runtime.
// No block_on — uses channels for synchronous FFI calls.

#![allow(clippy::missing_safety_doc)]

use std::ffi::{c_char, c_int, CStr};
use std::sync::{Mutex, OnceLock};

use rvpn_split_tunnel::DnsResolver;
use rvpn_split_tunnel::{SplitTunnel, SplitTunnelConfig};
use crate::dns_server::DnsServer;
use crate::doh_client::DohClient;
use crate::flow_connector::FlowConnectorConfig;

use rvpn_core::crypto::IdentityKey;

// --- Global state ---

struct DnsProxyState {
    query_tx: tokio::sync::mpsc::Sender<DnsQueryRequest>,
    _runtime_handle: tokio::runtime::Handle,
}

struct DnsQueryRequest {
    query_bytes: Vec<u8>,
    response_tx: tokio::sync::oneshot::Sender<Result<Vec<u8>, String>>,
}

static DNS_PROXY_STATE: OnceLock<Mutex<Option<DnsProxyState>>> = OnceLock::new();

fn get_state() -> &'static Mutex<Option<DnsProxyState>> {
    DNS_PROXY_STATE.get_or_init(|| Mutex::new(None))
}

// --- FFI Functions ---

/// Start the DNS proxy runtime on a dedicated thread.
///
/// # Arguments
/// * `config_json` - JSON config with server_address, identity_key_path,
///   prekey_bundle_path, builtin_bypass_countries, block_ads
///
/// # Returns
/// 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn rvpn_dns_proxy_start(config_json: *const c_char) -> c_int {
    if config_json.is_null() {
        super::ios_tun_ffi::set_last_error("config_json is null");
        return -1;
    }

    let config_str = match CStr::from_ptr(config_json).to_str() {
        Ok(s) => s,
        Err(e) => {
            super::ios_tun_ffi::set_last_error(&format!("invalid config string: {}", e));
            return -1;
        }
    };

    let config: serde_json::Value = match serde_json::from_str(config_str) {
        Ok(v) => v,
        Err(e) => {
            super::ios_tun_ffi::set_last_error(&format!("invalid config JSON: {}", e));
            return -1;
        }
    };

    // Parse config fields
    let server_address = match config["server_address"].as_str() {
        Some(s) => s.to_string(),
        None => {
            super::ios_tun_ffi::set_last_error("missing server_address");
            return -1;
        }
    };

    let identity_key_path = match config["identity_key_path"].as_str() {
        Some(s) => s.to_string(),
        None => {
            super::ios_tun_ffi::set_last_error("missing identity_key_path");
            return -1;
        }
    };

    let prekey_bundle_path = match config["prekey_bundle_path"].as_str() {
        Some(s) => s.to_string(),
        None => {
            super::ios_tun_ffi::set_last_error("missing prekey_bundle_path");
            return -1;
        }
    };

    let builtin_bypass_countries: Vec<String> = config["builtin_bypass_countries"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_else(|| vec!["CN".to_string()]);

    let block_ads = config["block_ads"].as_bool().unwrap_or(true);

    // Create channels
    let (query_tx, mut query_rx) = tokio::sync::mpsc::channel::<DnsQueryRequest>(32);

    // Store state
    {
        let state_guard = get_state().lock().unwrap();
        if state_guard.is_some() {
            super::ios_tun_ffi::set_last_error("DNS proxy already running");
            return -1;
        }
    }

    // Spawn dedicated OS thread
    let bypass_countries = builtin_bypass_countries.clone();
    let result = std::thread::Builder::new()
        .name("dns-proxy-runtime".into())
        .spawn(move || {
            // Build Tokio runtime on this thread
            let runtime = match tokio::runtime::Builder::new_current_thread()
                
                
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!("[DNS_PROXY] Failed to build runtime: {}", e);
                    return;
                }
            };

            let _handle = runtime.handle().clone();

            runtime.block_on(async move {
                // Load identity key
                let identity_key = match IdentityKey::load(std::path::Path::new(&identity_key_path)) {
                    Ok(k) => k,
                    Err(e) => {
                        tracing::error!("[DNS_PROXY] Failed to load identity key: {}", e);
                        return;
                    }
                };

                // Load prekey bundle
                let bundle_json = match std::fs::read_to_string(&prekey_bundle_path) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("[DNS_PROXY] Failed to read prekey bundle: {}", e);
                        return;
                    }
                };
                let server_bundle: rvpn_core::crypto::X3DHPublicBundle =
                    match serde_json::from_str(&bundle_json) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::error!("[DNS_PROXY] Failed to parse prekey bundle: {}", e);
                            return;
                        }
                    };

                // Parse server URL
                let cleaned = server_address
                    .replace("wss://", "")
                    .replace("ws://", "");
                let parts: Vec<&str> = cleaned.split('/').collect();
                let host_port: Vec<&str> = parts[0].split(':').collect();
                let server_host = host_port[0].to_string();
                let server_port: u16 = host_port.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);
                let base_path = if parts.len() > 1 {
                    format!("/{}", parts[1..].join("/"))
                } else {
                    "/connect".to_string()
                };
                let dns_path = format!("{}/dns", base_path.trim_end_matches("/tun").trim_end_matches('/'));

                // Create DohClient
                let flow_config = FlowConnectorConfig {
                    server_host: server_host.clone(),
                    server_port,
                    server_path: dns_path.clone(),
                    tls_fingerprint: rvpn_tls::TlsFingerprint::Chrome,
                    identity_key: std::sync::Arc::new(identity_key),
                    server_bundle,
                };

                let doh_client = std::sync::Arc::new(DohClient::new(flow_config, dns_path));
                doh_client.clone().start_cleanup_task();
                if let Err(e) = doh_client.start().await {
                    tracing::error!("[DNS_PROXY] Failed to start DohClient: {}", e);
                    return;
                }

                tracing::info!("[DNS_PROXY] DohClient started");

                // Create SplitTunnel
                let split_tunnel_config = SplitTunnelConfig {
                    enabled: true,
                    builtin_bypass_countries: bypass_countries,
                    bypass_networks: Vec::new(),
                    block_ads,
                    ..Default::default()
                };

                let dns_resolver = std::sync::Arc::new(DnsResolver::new(true, 14400, 200, false, true, vec![]));
                dns_resolver.start_cleanup_task();
                let split_tunnel = match SplitTunnel::new(split_tunnel_config, dns_resolver).await {
                    Ok(st) => st,
                    Err(e) => {
                        tracing::error!("[DNS_PROXY] Failed to create SplitTunnel: {}", e);
                        return;
                    }
                };

                let dns_server = std::sync::Arc::new(DnsServer::with_doh(
                    split_tunnel,
                    doh_client,
                    "127.0.0.1:0".to_string(), // No UDP listener needed
                ));

                tracing::info!("[DNS_PROXY] DNS server created, entering query loop");

                // Query loop — receives queries from FFI, resolves, returns
                while let Some(req) = query_rx.recv().await {
                    let server = dns_server.clone();
                    let result = server.resolve_raw(&req.query_bytes).await;
                    let _ = req.response_tx.send(result.map_err(|e| e.to_string()));
                }

                tracing::info!("[DNS_PROXY] Query loop exited");
            });
        });

    match result {
        Ok(_) => {
            let mut state = get_state().lock().unwrap();
            *state = Some(DnsProxyState {
                query_tx,
                _runtime_handle: tokio::runtime::Handle::current(),
            });
            tracing::info!("[DNS_PROXY] Started successfully");
            0
        }
        Err(e) => {
            super::ios_tun_ffi::set_last_error(&format!("failed to spawn thread: {}", e));
            -1
        }
    }
}

/// Stop the DNS proxy runtime.
#[no_mangle]
pub unsafe extern "C" fn rvpn_dns_proxy_stop() -> c_int {
    let mut state = get_state().lock().unwrap();
    if let Some(s) = state.take() {
        // Dropping query_tx causes the query loop to exit
        drop(s.query_tx);
        tracing::info!("[DNS_PROXY] Stopped");
        0
    } else {
        super::ios_tun_ffi::set_last_error("DNS proxy not running");
        -1
    }
}

/// Resolve a raw DNS query packet synchronously.
///
/// This runs on a GCD thread (safe to block). Sends the query to the Tokio
/// runtime via channel and blocks on the response.
///
/// # Arguments
/// * `query_data` - Raw DNS query bytes
/// * `query_len` - Length of query
/// * `response_buf` - Output buffer for response
/// * `response_buf_len` - Size of output buffer
/// * `out_len` - Actual response length written
///
/// # Returns
/// 0 on success, -1 on error.
#[no_mangle]
pub unsafe extern "C" fn rvpn_dns_resolve(
    query_data: *const u8,
    query_len: usize,
    response_buf: *mut u8,
    response_buf_len: usize,
    out_len: *mut usize,
) -> c_int {
    if query_data.is_null() || response_buf.is_null() || out_len.is_null() {
        return -1;
    }

    let query_bytes = std::slice::from_raw_parts(query_data, query_len).to_vec();

    // Get the query sender
    let query_tx = {
        let state = get_state().lock().unwrap();
        match state.as_ref() {
            Some(s) => s.query_tx.clone(),
            None => {
                super::ios_tun_ffi::set_last_error("DNS proxy not running");
                *out_len = 0;
                return -1;
            }
        }
    };

    // Create oneshot channel for response
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();

    // Send query
    let request = DnsQueryRequest {
        query_bytes,
        response_tx,
    };

    // Use blocking send (we're on a GCD thread, not a Tokio thread)
    if query_tx.blocking_send(request).is_err() {
        super::ios_tun_ffi::set_last_error("DNS proxy channel closed");
        *out_len = 0;
        return -1;
    }

    // Block on response with timeout
    // Since we can't use tokio::time::timeout outside a Tokio runtime,
    // use a simple thread join with a timeout.
    let thread_handle = std::thread::spawn(move || -> Option<Result<Vec<u8>, String>> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build();
        match rt {
            Ok(rt) => {
                let result = rt.block_on(response_rx);
                result.ok()
            }
            Err(_) => None,
        }
    });

    // Wait up to 5 seconds
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let response = loop {
        if thread_handle.is_finished() {
            break thread_handle.join();
        }
        if std::time::Instant::now() >= deadline {
            super::ios_tun_ffi::set_last_error("DNS resolve timeout (5s)");
            *out_len = 0;
            return -1;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };

    match response {
        Ok(Some(Ok(response_bytes))) => {
            if response_bytes.len() > response_buf_len {
                super::ios_tun_ffi::set_last_error(&format!(
                    "DNS response too large: {} bytes (buf: {})",
                    response_bytes.len(),
                    response_buf_len
                ));
                *out_len = 0;
                return -1;
            }
            let out = std::slice::from_raw_parts_mut(response_buf, response_bytes.len());
            out.copy_from_slice(&response_bytes);
            *out_len = response_bytes.len();
            0
        }
        Ok(Some(Err(e))) => {
            super::ios_tun_ffi::set_last_error(&format!("DNS resolve error: {}", e));
            *out_len = 0;
            -1
        }
        Ok(None) => {
            super::ios_tun_ffi::set_last_error("DNS resolve channel closed");
            *out_len = 0;
            -1
        }
        Err(_) => {
            super::ios_tun_ffi::set_last_error("DNS resolve thread panicked");
            *out_len = 0;
            -1
        }
    }
}
