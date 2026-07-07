// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! iOS Direct TUN Client - True TUN-to-TUN tunneling via WebSocket
//!
//! This module provides a client for iOS Direct TUN mode where:
//! - iOS connects to `/api/v1/ws/tun` endpoint
//! - Server assigns a tunnel IP via `VirtualIp` message after X3DH
//! - Raw IP packets flow bidirectionally through the WebSocket
//!
//! Architecture:
//! - Swift TUN interface captures raw IP packets
//! - This client exchanges packets with Swift via channels
//! - X3DH handshake establishes Double Ratchet
//! - Server sends VirtualIp with assigned IP
//! - Raw IP packets are encrypted and relayed

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use bytes::BytesMut;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use tokio::sync::{broadcast, mpsc, Mutex, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, trace, warn};

use crate::ws::{FrameType, MinimalWebSocket, MinimalWsReader, MinimalWsWriter};

use ed25519_dalek::Verifier;
use rvpn_core::crypto::ratchet::{RatchetMessage, RatchetMessageRef};
use rvpn_core::crypto::x3dh::X3DHInitiator;
use rvpn_core::crypto::{DoubleRatchet, EphemeralKey, IdentityKey, X3DHPublicBundle};
use rvpn_core::protocol::padding::{pad_packet, unpad_packet, unpad_packet_slice};
use rvpn_core::protocol::{
    ControlMessage, HandshakeMessage, MultiplexedFrame, PayloadType, VirtualIp,
};

use crate::ffi::TunConfig;

/// Simple object pool for `Vec<u8>` to reduce per-packet heap allocation churn.
///
/// Under sustained 5G traffic (~100 packets/sec from Swift), allocating and
/// dropping a 1.5 KB `Vec` for every packet fragments mimalloc's pages and
/// pushes RSS toward the 50 MB jetsam limit.  The pool holds a fixed number of
/// reusable buffers; callers `take()` a buffer, fill it, and `put()` it back
/// after the data has been consumed.
///
/// Shared between FFI write functions (producers) and the `swift_to_server`
/// Tokio task (consumer) via `Arc<Mutex<VecPool>>`.
pub(crate) struct VecPool {
    pool: Vec<Vec<u8>>,
    capacity: usize,
}

impl VecPool {
    /// Create a pool that holds up to `capacity` reusable buffers.
    pub fn new(capacity: usize) -> Self {
        Self {
            pool: Vec::with_capacity(capacity),
            capacity,
        }
    }

    /// Take a buffer from the pool, or allocate a new one if empty.
    /// The returned buffer is cleared (len=0) but retains its allocation.
    pub fn take(&mut self) -> Vec<u8> {
        self.pool.pop().unwrap_or_else(|| Vec::with_capacity(1500))
    }

    /// Return a buffer to the pool for reuse.
    /// The buffer is cleared; if the pool is full it is simply dropped.
    pub fn put(&mut self, mut v: Vec<u8>) {
        v.clear();
        if self.pool.len() < self.capacity {
            self.pool.push(v);
        }
    }
}

/// Release freed heap memory back to the OS.
/// mimalloc self-manages — forced collection is counterproductive.
#[allow(dead_code)] // Intentionally retained for future tuning; currently a no-op.
fn trim_memory(_force: bool) {
    // No-op: mimalloc's self-management outperforms forced mi_collect.
}

/// Get the current resident set size (RSS) in bytes using Mach task_info.
/// Always available (not gated behind the diagnostics feature) — the reconnect
/// loop needs it in production builds to log memory across sessions and detect
/// leak-driven jetsam kills. The Mach call is a couple of microseconds.
/// Returns 0 on failure.
#[cfg(target_vendor = "apple")]
fn rss_bytes_now() -> u64 {
    const MACH_TASK_BASIC_INFO: u32 = 20;
    const INFO_COUNT: u32 = 12;
    let mut buf = [0i32; 12];
    let mut count = INFO_COUNT;
    #[allow(deprecated)]
    let task = unsafe { libc::mach_task_self() };
    let kr = unsafe { libc::task_info(task, MACH_TASK_BASIC_INFO, buf.as_mut_ptr(), &mut count) };
    if kr != 0 {
        return 0;
    }
    let lo = buf[2] as u32 as u64;
    let hi = buf[3] as u32 as u64;
    (hi << 32) | lo
}
#[cfg(not(target_vendor = "apple"))]
fn rss_bytes_now() -> u64 { 0 }

/// Bytes of memory the process may still allocate before iOS jetsams it.
/// Always available for the same reason as `rss_bytes_now`.
#[cfg(target_vendor = "apple")]
fn headroom_bytes_now() -> u64 {
    extern "C" {
        fn os_proc_available_memory() -> u64;
    }
    unsafe { os_proc_available_memory() }
}
#[cfg(not(target_vendor = "apple"))]
fn headroom_bytes_now() -> u64 { 0 }

/// Get the current resident set size (RSS) in bytes using Mach task_info.
/// Returns 0 on failure.
#[cfg(feature = "diagnostics")]
pub fn get_rss_bytes() -> u64 {
    // mach_task_basic_info: flavor=20, 48 bytes total
    // Layout: virtual_size(u64) @ 0, resident_size(u64) @ 8, ...
    const MACH_TASK_BASIC_INFO: u32 = 20;
    const INFO_COUNT: u32 = 12; // 48 / sizeof(natural_t)
    let mut buf = [0i32; 12];
    let mut count = INFO_COUNT;
    #[allow(deprecated)]
    let task = unsafe { libc::mach_task_self() };
    let kr = unsafe { libc::task_info(task, MACH_TASK_BASIC_INFO, buf.as_mut_ptr(), &mut count) };
    if kr != 0 {
        return 0;
    }
    // resident_size is at byte offset 8 = natural_t index 2..4
    let lo = buf[2] as u32 as u64;
    let hi = buf[3] as u32 as u64;
    (hi << 32) | lo
}

// iOS: bytes of headroom before the process hits its jetsam memory limit
// (inverse of phys_footprint against the cap). Declining toward 0 == imminent
// jetsam kill. Available iOS 13+; declared manually to avoid a dependency.
#[cfg(feature = "diagnostics")]
extern "C" {
    fn os_proc_available_memory() -> u64;
}

/// Bytes of memory the process may still allocate before iOS jetsams it.
/// Returns 0 if the symbol is unavailable.
#[cfg(feature = "diagnostics")]
fn jetsam_headroom_bytes() -> u64 {
    unsafe { os_proc_available_memory() }
}

// iOS system allocator (libmalloc) zone APIs. The per-frame leak has been
// localized to the C layer (BoringSSL) which allocates via malloc. The default
// zone's live size_in_use is tiny (~90 KB) and pressure_relief on it alone does
// NOT stop the leak — so the growth is in another zone (iOS routes small allocs
// to the nano zone, which `malloc_default_zone()` doesn't cover) or in vm
// regions. These helpers enumerate ALL zones so we can measure/relief the lot.
#[cfg(feature = "diagnostics")]
#[repr(C)]
struct MallocStatistics {
    size_in_use: u32,
    count: u32,
    reserved: [u32; 2],
}

/// Read `task_vm_info` (flavor 22) raw bytes and extract the `internal` and
/// `compressed` fields at their known struct offsets (48 and 112). This splits
/// phys_footprint growth into:
/// - `internal` climbing ⇒ live anonymous (vm_allocate) leak — find the caller.
/// - `compressed` climbing ⇒ iOS compressing freed pages rather than reclaiming.
/// Both are outside the malloc heap (which `all_zones_size_in_use` already
/// proved flat), so this is the decisive next measurement.
#[cfg(feature = "diagnostics")]
fn vm_internal_compressed() -> (u64, u64) {
    const TASK_VM_INFO: u32 = 22;
    let mut buf = [0u8; 1024];
    let mut count = (buf.len() / 4) as u32; // natural_t (u32) units
    #[allow(deprecated)]
    let task = unsafe { libc::mach_task_self() };
    let kr =
        unsafe { libc::task_info(task, TASK_VM_INFO, buf.as_mut_ptr() as *mut i32, &mut count) };
    if kr != 0 {
        return (0, 0);
    }
    let internal = u64::from_le_bytes(buf[48..56].try_into().unwrap_or([0; 8]));
    let compressed = u64::from_le_bytes(buf[112..120].try_into().unwrap_or([0; 8]));
    (internal, compressed)
}

extern "C" {
    fn malloc_get_all_zones(
        task: libc::mach_port_t,
        reader: *mut std::ffi::c_void,
        addresses: *mut *mut usize,
        count: *mut u32,
    ) -> libc::c_int;
    fn malloc_zone_pressure_relief(zone: *mut std::ffi::c_void, goal: usize) -> usize;
    #[cfg(feature = "diagnostics")]
    fn malloc_zone_statistics(zone: *mut std::ffi::c_void, stats: *mut MallocStatistics);
    // VM region enumeration via mach_vm_region + VM_REGION_EXTENDED_INFO.
    // This flavor gives a clean struct: {protection(4), user_tag(4), pages_resident(4), ...}
    // No submap handling needed — mach_vm_region iterates all regions linearly.
    //
    // NOTE: `mach_vm_region` and `vm_region_tags_str` below are retained for
    // reference but are NOT called. Calling mach_vm_region from inside the NE
    // extension triggers a sandbox violation that kills the process instantly
    // (confirmed in prior diagnostic session). Kept dead rather than removed so
    // the struct-offset documentation is not lost; see `append_mem_log` for the
    // active instrumentation path.
    #[allow(dead_code)]
    fn mach_vm_region(
        target_task: u32,
        address: *mut u64,
        size: *mut u64,
        flavor: u32,
        info: *mut i32,
        count: *mut u32,
    ) -> i32;
}

/// Walk all VM regions and return a compact string of tags >1 MB resident,
/// sorted by size: "tag:MB|tag:MB|...". The tag that grows frame-over-frame
/// is the leak source.
/// VM_MEMORY tags: 1=MALLOC, 2=MALLOC_LARGE, 3=MALLOC_HUGE, 5=MALLOC_NANO,
/// 7=VM_ALLOCATE, 10=STACK, 11=IO, 2401=APP_SPECIFIC_1
#[cfg(feature = "diagnostics")]
#[allow(dead_code)] // mach_vm_region crashes the NE sandbox — see note above.
fn vm_region_tags_str() -> String {
    const VM_REGION_EXTENDED_INFO: u32 = 13;
    #[allow(deprecated)]
    let task = unsafe { libc::mach_task_self() };
    let mut address: u64 = 0;
    let mut buckets: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    loop {
        let mut size: u64 = 0;
        let mut info = [0i32; 20];
        let mut count = info.len() as u32;
        let kr = unsafe {
            mach_vm_region(
                task,
                &mut address,
                &mut size,
                VM_REGION_EXTENDED_INFO,
                info.as_mut_ptr(),
                &mut count,
            )
        };
        if kr != 0 {
            break;
        }
        let n = (count as usize) * 4;
        if n >= 12 {
            let bytes = unsafe { std::slice::from_raw_parts(info.as_ptr() as *const u8, n) };
            // vm_region_extended_info: protection@0, user_tag@4, pages_resident@8
            let user_tag = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
            let pages_resident = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
            let resident = (pages_resident as u64).saturating_mul(4096);
            *buckets.entry(user_tag).or_insert(0) += resident;
        }
        if size == 0 {
            break;
        }
        address = address.saturating_add(size);
    }
    let mut sorted: Vec<(u32, u64)> = buckets
        .into_iter()
        .filter(|(_, b)| *b > 1_048_576)
        .collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted
        .into_iter()
        .map(|(t, b)| format!("{}:{}", t, b / (1024 * 1024)))
        .collect::<Vec<_>>()
        .join("|")
}

/// Enumerate every malloc zone in this task. Returns the zone pointer slice
/// (the array is owned by libmalloc; do not free).
fn all_zone_ptrs() -> Vec<*mut std::ffi::c_void> {
    let mut array: *mut usize = std::ptr::null_mut();
    let mut count: u32 = 0;
    #[allow(deprecated)]
    let task = unsafe { libc::mach_task_self() };
    unsafe {
        let kr = malloc_get_all_zones(task, std::ptr::null_mut(), &mut array, &mut count);
        if kr != 0 || array.is_null() || count == 0 {
            return Vec::new();
        }
        let raw = std::slice::from_raw_parts(array, count as usize);
        raw.iter()
            .map(|&addr| addr as *mut std::ffi::c_void)
            .filter(|p| !p.is_null())
            .collect()
    }
}

/// Ask every malloc zone to release as many freed pages as possible. The default
/// zone alone does not cover the nano zone (where small BoringSSL allocations
/// live), so we must relief ALL zones. Non-disruptive (no live allocations,
/// no tunnel drop). Called from the 15 s keepalive.
fn all_zones_pressure_relief() {
    for zone in all_zone_ptrs() {
        unsafe {
            let _ = malloc_zone_pressure_relief(zone, 0);
        }
    }
}

/// Sum of live bytes-in-use across ALL malloc zones. If this stays flat while
/// `headroom_bytes` declines, the growth is NOT in any malloc zone (it's in
/// vm/mmap regions or compressed pages) and malloc-level relief can't help.
#[cfg(feature = "diagnostics")]
fn all_zones_size_in_use() -> u64 {
    let mut total = 0u64;
    let mut stats = MallocStatistics {
        size_in_use: 0,
        count: 0,
        reserved: [0, 0],
    };
    for zone in all_zone_ptrs() {
        unsafe {
            stats.size_in_use = 0;
            stats.count = 0;
            malloc_zone_statistics(zone, &mut stats);
            total += stats.size_in_use as u64;
        }
    }
    total
}

// mimalloc process-wide stats. The crate links the C library, so the symbol is
// available without an extra dependency.  Only available when both `mimalloc`
// and `diagnostics` features are enabled — when disabled, the functions below
// return zero.
#[cfg(all(feature = "mimalloc", feature = "diagnostics"))]
extern "C" {
    fn mi_process_info(
        elapsed_msecs: *mut usize,
        user_msecs: *mut usize,
        system_msecs: *mut usize,
        current_rss: *mut usize,
        peak_rss: *mut usize,
        current_commit: *mut usize,
        peak_commit: *mut usize,
        page_faults: *mut usize,
    );
    // Force mimalloc to return freed pages to the OS.  `true` = force all
    // pages; `false` = only abandoned pages.  Calling this before a snapshot
    // reveals whether mimalloc is hoarding freed-but-unreturned pages: if
    // commit_after_collect < commit_before_collect, the gap is deferred frees.
    fn mi_collect(force: bool);
}

/// Return mimalloc's "current_commit" — the bytes it currently has committed
/// (live allocations, including freed-but-not-yet-returned pages it still owns).
///
/// Compared against `get_rss_bytes()` (OS resident), this is decisive for
/// telling a genuine live leak (commit climbs) apart from mimalloc retaining
/// freed pages (commit flat, RSS climbs).
///
/// Returns 0 when mimalloc is disabled or diagnostics are disabled.
#[cfg(feature = "diagnostics")]
fn mi_committed_bytes() -> u64 {
    #[cfg(all(feature = "mimalloc", feature = "diagnostics"))]
    {
        let mut elapsed = 0usize;
        let mut user = 0usize;
        let mut system = 0usize;
        let mut rss = 0usize;
        let mut peak_rss = 0usize;
        let mut commit = 0usize;
        let mut peak_commit = 0usize;
        let mut faults = 0usize;
        unsafe {
            mi_process_info(
                &mut elapsed,
                &mut user,
                &mut system,
                &mut rss,
                &mut peak_rss,
                &mut commit,
                &mut peak_commit,
                &mut faults,
            );
        }
        commit as u64
    }
    #[cfg(not(all(feature = "mimalloc", feature = "diagnostics")))]
    {
        0
    }
}

/// mimalloc's peak committed bytes (high-water mark). If this is much larger
/// than `current_commit`, mimalloc allocated and then freed a lot of pages.
///
/// Returns 0 when mimalloc is disabled or diagnostics are disabled.
#[cfg(feature = "diagnostics")]
fn mi_peak_commit_bytes() -> u64 {
    #[cfg(all(feature = "mimalloc", feature = "diagnostics"))]
    {
        let mut elapsed = 0usize;
        let mut user = 0usize;
        let mut system = 0usize;
        let mut rss = 0usize;
        let mut peak_rss = 0usize;
        let mut commit = 0usize;
        let mut peak_commit = 0usize;
        let mut faults = 0usize;
        unsafe {
            mi_process_info(
                &mut elapsed,
                &mut user,
                &mut system,
                &mut rss,
                &mut peak_rss,
                &mut commit,
                &mut peak_commit,
                &mut faults,
            );
        }
        peak_commit as u64
    }
    #[cfg(not(all(feature = "mimalloc", feature = "diagnostics")))]
    {
        0
    }
}

/// Force mimalloc to return ALL freed pages to the OS, then return the
/// post-collection commit bytes.  If this is significantly lower than the
/// pre-collection commit, mimalloc was holding onto freed pages (deferred
/// free / thread-local caches).  If it's the same, the committed memory is
/// genuinely live — a real leak or high-water-mark retention.
///
/// Returns 0 when mimalloc is disabled or diagnostics are disabled.
#[cfg(feature = "diagnostics")]
fn mi_commit_after_collect() -> u64 {
    #[cfg(all(feature = "mimalloc", feature = "diagnostics"))]
    {
        unsafe {
            mi_collect(true);
        }
        mi_committed_bytes()
    }
    #[cfg(not(all(feature = "mimalloc", feature = "diagnostics")))]
    {
        0
    }
}

/// WebSocket writer type.
///
/// iOS uses the rustls backend (`rvpn_tls::RustlsTlsStream`) — native-tls
/// (Security.framework) cannot negotiate TLS 1.3 on iOS, and the protocol
/// requires TLS 1.3. macOS (same file, `macos-direct-tun` feature) keeps
/// the boring backend for Chrome ClientHello fingerprint mimicry.
#[cfg(feature = "ios-direct-tun")]
type WsReader = MinimalWsReader<rvpn_tls::RustlsTlsStream>;
#[cfg(feature = "ios-direct-tun")]
type WsWriter = MinimalWsWriter<rvpn_tls::RustlsTlsStream>;
#[cfg(not(feature = "ios-direct-tun"))]
type WsReader = MinimalWsReader<rvpn_tls::ChromeTlsStream>;
#[cfg(not(feature = "ios-direct-tun"))]
type WsWriter = MinimalWsWriter<rvpn_tls::ChromeTlsStream>;

/// DIAGNOSTIC: when true, the inbound (server→client) relay decrypts each
/// frame but discards it instead of forwarding to Swift. This silences the
/// Swift/NE write path so we can tell whether the per-frame memory leak is in
/// BoringSSL (read path) or downstream in Swift/NE. Set false for normal use.
const BISECT_DROP_INBOUND: bool = false;

/// Outgoing packet batching limits.
///
/// Multiple TUN packets are coalesced into a single WebSocket/Ratchet message
/// to reduce per-packet overhead. The batch is capped well below the 16 KB
/// maximum padded size to leave room for frame headers and padding length.
const OUTGOING_BATCH_MAX_FRAMES: usize = 16;
const OUTGOING_BATCH_MAX_BYTES: usize = 14 * 1024;
const OUTGOING_BATCH_TIMEOUT_MS: u64 = 5;

/// Pre-allocated buffers for the encrypt path to avoid per-batch allocations.
/// Under YouTube traffic (~416 batches/sec), allocating and dropping 14KB buffers
/// every 5ms causes massive heap fragmentation and RSS growth.
struct EncryptBuffers {
    plaintext: BytesMut,
    padded: Vec<u8>,
    ciphertext: Vec<u8>,
    serialized: Vec<u8>,
}

impl EncryptBuffers {
    fn new() -> Self {
        Self {
            plaintext: BytesMut::with_capacity(OUTGOING_BATCH_MAX_BYTES),
            padded: Vec::with_capacity(OUTGOING_BATCH_MAX_BYTES + 2),
            ciphertext: Vec::with_capacity(OUTGOING_BATCH_MAX_BYTES + 128),
            serialized: Vec::with_capacity(OUTGOING_BATCH_MAX_BYTES + 256),
        }
    }

    fn clear(&mut self) {
        self.plaintext.clear();
        self.padded.clear();
        self.ciphertext.clear();
        self.serialized.clear();
    }
}

/// Pre-allocated buffers for the decrypt path.
///
/// Mirrors `EncryptBuffers` for the server→swift direction.  The `plaintext`
/// buffer is passed to `DoubleRatchet::decrypt_to_ref` so its allocation is
/// reused across messages instead of creating a new `Vec` per frame.
///
/// The `batch_buf` accumulates multiple decoded packets from a single
/// WebSocket frame into one `Bytes` allocation (u16-LE length-prefixed
/// format), reducing per-packet heap churn from ~1000/s to ~60/s.
struct DecryptBuffers {
    plaintext: Vec<u8>,
    batch_buf: BytesMut,
}

impl DecryptBuffers {
    fn new() -> Self {
        Self {
            plaintext: Vec::with_capacity(2048),
            batch_buf: BytesMut::with_capacity(OUTGOING_BATCH_MAX_BYTES),
        }
    }
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TunClientState {
    Init = 0,
    Connecting = 1,
    IpAssigned = 2,
    Connected = 3,
    Error = 4,
}

impl From<i32> for TunClientState {
    fn from(v: i32) -> Self {
        match v {
            0 => TunClientState::Init,
            1 => TunClientState::Connecting,
            2 => TunClientState::IpAssigned,
            3 => TunClientState::Connected,
            _ => TunClientState::Error,
        }
    }
}

/// State callback type for Swift notifications
/// Called when state changes: (state: i32, ip: *const c_char, message: *const c_char)
pub type StateCallback = Option<
    unsafe extern "C" fn(
        state: i32,
        ip: *const std::os::raw::c_char,
        msg: *const std::os::raw::c_char,
    ),
>;

/// IosTunClient - Direct TUN mode client for iOS
///
/// Connects to the VPN server's `/tun` endpoint, performs X3DH handshake,
/// receives a VirtualIp assignment, and relays raw IP packets bidirectionally.
///
/// # Channel Design
/// - Swift sends packets to server via `from_swift_sender` (mpsc::Sender)
/// - Swift receives packets from server via `to_swift_receiver` (mpsc::Receiver)
///   Both are exposed via getters for Swift to use.
pub struct IosTunClient {
    /// Handle to the tokio runtime that runs this client's tasks.
    ///
    /// The `Runtime` itself is owned by `ios_tun_ffi::TUN_RUNTIME` — NOT by
    /// this struct. This is load-bearing: any `Arc<Self>` captured by a
    /// spawned task must NOT transitively pin the Runtime, because tokio
    /// panics if `Runtime::drop` (which calls `BlockingPool::shutdown`)
    /// runs on a worker thread. Holding only a `Handle` here means the
    /// last-Arc-dropped-on-worker case is harmless: `Handle::drop` is a
    /// no-op wake-source release, not a runtime teardown.
    handle: tokio::runtime::Handle,
    /// Configuration (kept for debugging and future reconnection support)
    /// Note: fields are extracted on construction to avoid per-packet locking
    #[allow(dead_code)]
    config: TunConfig,
    /// Server host (original hostname for TLS SNI)
    server_host: String,
    /// Server IP (pre-resolved to avoid DNS circular dependency during reconnect)
    server_ip: std::net::IpAddr,
    /// Server port
    server_port: u16,
    /// WebSocket path (base path, will append /tun)
    server_path: String,
    /// Connection state
    state: Arc<AtomicI32>,
    /// Assigned tunnel IP (set after VirtualIp received)
    tunnel_ip: Arc<std::sync::Mutex<Option<String>>>,
    /// Assigned gateway IP (set after VirtualIp received)
    gateway_ip: Arc<std::sync::Mutex<Option<String>>>,
    /// Sender for packets to Swift (Swift receives via recv_packet_from_server)
    to_swift_sender: mpsc::Sender<bytes::Bytes>,
    /// Signalled whenever a packet is pushed to to_swift_sender, so the Swift
    /// write loop can wait event-driven instead of polling.
    /// Uses a std channel so the FFI wait function can block without entering
    /// the Tokio runtime.
    packet_notify_tx: std::sync::mpsc::SyncSender<()>,
    packet_notify_rx: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    /// Receiver for packets from Swift (Swift sends via send_packet_to_server)
    from_swift_receiver: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    /// Sender for Swift to use (Swift calls send_packet_to_server with this)
    pub from_swift_sender: mpsc::Sender<Vec<u8>>,
    /// Receiver for packets to Swift
    pub to_swift_receiver: Arc<Mutex<mpsc::Receiver<bytes::Bytes>>>,
    /// Shutdown signal
    shutdown_tx: broadcast::Sender<()>,
    /// Identity key for X3DH
    identity_key: IdentityKey,
    /// Server prekey bundle for X3DH
    server_bundle: X3DHPublicBundle,
    /// Canonical `ik:1:<base32>` pin of the server's identity key, computed
    /// from `server_bundle.identity_key` at construction. The app FFI reads
    /// this via `rvpn_tun_get_server_identity()` after `Connected` to
    /// capture the TOFU pin on first-ever connect.
    server_identity_pin_actual: String,
    /// DNS servers from VirtualIp
    dns_servers: Arc<std::sync::Mutex<Vec<std::net::IpAddr>>>,
    /// MTU from VirtualIp
    mtu: Arc<std::sync::Mutex<u16>>,
    /// State callback for Swift notifications
    state_callback: Arc<RwLock<StateCallback>>,
    /// Last time any traffic was received from the server (Unix seconds).
    /// Updated on every WebSocket frame, including encrypted data and WS
    /// control frames, so Swift can distinguish a healthy idle tunnel from
    /// a suspended/dead one.
    last_rx_time: Arc<AtomicU64>,
    /// Start/reconnect loop running flag (prevents duplicate loops)
    is_started: AtomicBool,
    /// Reconnection enabled flag
    reconnect_enabled: AtomicBool,
    /// Maximum reconnection attempts (0 = unlimited)
    reconnect_max_attempts: AtomicU32,
    /// Initial delay between reconnection attempts (ms)
    reconnect_initial_delay_ms: AtomicU64,
    /// Maximum delay between reconnection attempts (ms)
    reconnect_max_delay_ms: AtomicU64,
    /// Last time a reconnect was requested via network change (debounces rapid calls)
    last_reconnect_request: std::sync::Mutex<std::time::Instant>,
    /// Sliding window of recent reconnect attempt start times, used to detect
    /// network flap on iOS. Under jetsam, a runaway reconnect storm during a
    /// metro-tunnel WiFi/cellular flap can trip the ~50 MB extension memory
    /// limit within seconds; enforcing a minimum backoff after N reconnects in
    /// 30 s throttles the storm and gives the runtime time to reclaim memory.
    reconnect_history: std::sync::Mutex<std::collections::VecDeque<std::time::Instant>>,
    /// Object pool for Vec<u8> packets from Swift to reduce heap churn.
    /// Shared with FFI write functions via `Arc<Mutex>`.
    packet_pool: Arc<Mutex<VecPool>>,
    /// Optional file path for memory-growth diagnostics (RSS snapshots from
    /// the relay loop). Written to the app-group container so it survives the
    /// jetsam kill and can be pulled off afterward. `None` when the container
    /// path can't be derived.
    #[cfg(feature = "diagnostics")]
    mem_log_path: Option<std::path::PathBuf>,
}

impl IosTunClient {
    /// Create a new IosTunClient from configuration.
    ///
    /// `handle` must come from a `Runtime` owned by the FFI layer (see
    /// `ios_tun_ffi::TUN_RUNTIME`). Storing only the Handle here prevents
    /// the Runtime from being transitively dropped inside a tokio worker,
    /// which would panic in `BlockingPool::shutdown`.
    pub fn new(config: &TunConfig, handle: tokio::runtime::Handle) -> Result<Self> {
        // Parse server URL
        let (host, port, path) = Self::parse_server_url(&config.server_address)?;

        // Pre-resolve server hostname to IP to avoid DNS circular dependency during reconnect.
        // When the VPN is active, system DNS is redirected to our DNS proxy (127.0.0.1:53).
        // If the TUN tunnel dies and tries to reconnect, resolving the server hostname would
        // go through our proxy → DoH client → dead connection → resolution fails forever.
        // By resolving here (before DNS is hijacked), we use the IP directly for all reconnects.
        let server_ip = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            ip
        } else {
            let mut addrs = std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", host, port))
                .with_context(|| format!("Failed to resolve server hostname: {}", host))?;
            addrs
                .next()
                .map(|a| a.ip())
                .context("DNS resolution returned no addresses for server")?
        };
        info!("[IosTun] Server {} resolved to {}", host, server_ip);

        // Load identity key (blocking I/O)
        let identity_key_path = std::path::PathBuf::from(&config.identity_key_path);
        let identity_key =
            IdentityKey::load(&identity_key_path).context("Failed to load identity key")?;

        // Load prekey bundle
        let bundle_json = std::fs::read_to_string(&config.prekey_bundle_path)
            .context("Failed to read prekey bundle")?;
        let server_bundle: X3DHPublicBundle =
            serde_json::from_str(&bundle_json).context("Failed to parse prekey bundle JSON")?;

        // Compute the canonical TOFU pin for this server's identity key. If
        // the caller supplied `server_identity_pin`, enforce equality before
        // proceeding — after this point we start opening TCP + WebSocket
        // connections to the server, so failing fast keeps a wrong-identity
        // connection from ever going on the wire. The `Error::
        // ServerIdentityMismatch` variant is what the FFI layer downcasts
        // to produce the `IDENTITY_MISMATCH expected=... actual=...` prefix
        // the app parses.
        let server_identity_pin_actual =
            rvpn_core::identity_pin::encode_identity_pin(&server_bundle.identity_key)
                .context("Failed to encode server identity pin")?;
        if let Some(expected) = config.server_identity_pin.as_deref() {
            let matched = rvpn_core::identity_pin::pins_match(expected, &server_bundle.identity_key)
                .context("Configured server_identity_pin is not a valid pin string")?;
            if !matched {
                return Err(anyhow::Error::from(rvpn_core::Error::ServerIdentityMismatch {
                    expected: expected.to_string(),
                    actual: server_identity_pin_actual,
                }));
            }
        }

        // Create channels for Swift TUN communication.
        // iOS uses smaller channels to stay within the 50 MB NE memory limit.
        // macOS keeps larger channels for throughput (no tight memory limit).
        // Using Bytes instead of Vec<u8> avoids per-packet copy in the server->swift path.
        let chan_cap = if cfg!(feature = "ios-direct-tun") {
            20
        } else {
            1000
        };
        let (to_swift_sender, to_swift_receiver) = mpsc::channel::<bytes::Bytes>(chan_cap);
        // from_swift_receiver is used by Swift to send packets to server (via send_packet_to_server)
        let (from_swift_sender, from_swift_receiver) = mpsc::channel::<Vec<u8>>(chan_cap);

        // Create shutdown channel
        let (shutdown_tx, _) = broadcast::channel::<()>(1);

        // Notification channel used to wake the Swift write loop when packets arrive.
        // std channel allows the FFI wait function to block without entering Tokio.
        let (packet_notify_tx, packet_notify_rx) = std::sync::mpsc::sync_channel(1);

        // Set initial state
        let state = Arc::new(AtomicI32::new(TunClientState::Init as i32));

        // NOTE: Runtime is now created by the FFI layer (see
        // `ios_tun_ffi::rvpn_tun_create`) and passed in as `handle`. Keeping
        // the Runtime out of this struct prevents it from being dropped on a
        // tokio worker thread when the last Arc<Self> ref drops, which would
        // panic in `BlockingPool::shutdown`.

        // Derive a diagnostics path in the app-group container (the same dir
        // that holds the identity key) so RSS snapshots survive a jetsam kill
        // and can be pulled off afterward. Best-effort: stays `None` if the
        // identity key has no parent dir for some reason.
        #[cfg(feature = "diagnostics")]
        let mem_log_path = identity_key_path
            .parent()
            .map(|dir| dir.join("rvpn_memlog.csv"));

        Ok(Self {
            handle,
            config: config.clone(),
            server_host: host,
            server_ip,
            server_port: port,
            server_path: path,
            state,
            tunnel_ip: Arc::new(std::sync::Mutex::new(None)),
            gateway_ip: Arc::new(std::sync::Mutex::new(None)),
            to_swift_sender,
            packet_notify_tx,
            packet_notify_rx: std::sync::Mutex::new(packet_notify_rx),
            from_swift_receiver: Arc::new(Mutex::new(from_swift_receiver)),
            from_swift_sender,
            to_swift_receiver: Arc::new(Mutex::new(to_swift_receiver)),
            shutdown_tx,
            identity_key,
            server_bundle,
            server_identity_pin_actual,
            dns_servers: Arc::new(std::sync::Mutex::new(Vec::new())),
            mtu: Arc::new(std::sync::Mutex::new(1420)),
            state_callback: Arc::new(RwLock::new(None)),
            last_rx_time: Arc::new(AtomicU64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )),
            is_started: AtomicBool::new(false),
            reconnect_enabled: AtomicBool::new(false), // Disabled by default, enable via setter
            reconnect_max_attempts: AtomicU32::new(0),
            last_reconnect_request: std::sync::Mutex::new(
                std::time::Instant::now() - std::time::Duration::from_secs(60),
            ),
            reconnect_history: std::sync::Mutex::new(std::collections::VecDeque::with_capacity(16)),
            reconnect_initial_delay_ms: AtomicU64::new(1000),
            reconnect_max_delay_ms: AtomicU64::new(5000),
            packet_pool: Arc::new(Mutex::new(VecPool::new(32))),
            #[cfg(feature = "diagnostics")]
            mem_log_path,
        })
    }

    /// Canonical `ik:1:<base32>` pin of the server this client was constructed
    /// against. Computed at `new()` from the loaded prekey bundle's identity
    /// key. The app FFI reads this via `rvpn_tun_get_server_identity()`
    /// after the tunnel reaches `Connected` to persist the TOFU pin on the
    /// first connect.
    pub fn server_identity_pin(&self) -> &str {
        &self.server_identity_pin_actual
    }

    /// Parse server URL into (host, port, path) — no url crate dependency
    pub fn parse_server_url(server_address: &str) -> Result<(String, u16, String)> {
        // Strip scheme (wss:// or ws://)
        let rest = server_address
            .strip_prefix("wss://")
            .or_else(|| server_address.strip_prefix("ws://"))
            .unwrap_or(server_address);

        // Split path
        let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
        let path = if path.is_empty() {
            "/".to_string()
        } else {
            format!("/{}", path)
        };

        // Split host:port
        let (host, port) = if let Some((h, p)) = authority.rsplit_once(':') {
            let port: u16 = p.parse().context("Invalid port in server_address")?;
            (h.to_string(), port)
        } else {
            (authority.to_string(), 443)
        };

        if host.is_empty() {
            anyhow::bail!("Missing host in server_address");
        }

        Ok((host, port, path))
    }

    /// Set the state callback for Swift notifications
    pub fn set_state_callback(&self, callback: StateCallback) {
        let state_callback = Arc::clone(&self.state_callback);
        self.handle.spawn(async move {
            let mut guard = state_callback.write().await;
            *guard = callback;
        });
    }

    /// Call the state callback if set
    async fn notify_state(&self, new_state: TunClientState, ip: Option<&str>, message: &str) {
        let callback = { *self.state_callback.read().await };
        if let Some(cb) = callback {
            let ip_cstring = ip.map(|s| std::ffi::CString::new(s).unwrap());
            let msg_cstring = std::ffi::CString::new(message).unwrap();
            let ip_ptr = ip_cstring
                .as_ref()
                .map(|s| s.as_ptr())
                .unwrap_or(std::ptr::null());
            let msg_ptr = msg_cstring.as_ptr();
            unsafe {
                cb(new_state as i32, ip_ptr, msg_ptr);
            }
            // Leaking the CStrings here is safe because:
            // 1. Swift's trampoline copies the strings immediately using String(cString:)
            // 2. Swift never stores the raw pointers
            // 3. The memory will be reclaimed when the process exits
            // Leaking is preferred over from_raw because we don't want Swift to try to free our memory
            std::mem::forget(ip_cstring);
            std::mem::forget(msg_cstring);
        }
        self.state.store(new_state as i32, Ordering::SeqCst);
    }

    /// Connect to the VPN server and perform X3DH handshake
    pub async fn connect(self: &Arc<Self>) -> Result<()> {
        // Early exit if reconnect was disabled (e.g. stopTunnel() called while we were in backoff)
        if !self.reconnect_enabled.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Connection cancelled by stop"));
        }

        // Set state to Connecting
        self.state
            .store(TunClientState::Connecting as i32, Ordering::SeqCst);
        self.notify_state(TunClientState::Connecting, None, "Connecting to server")
            .await;

        // Build WebSocket URL for TUN endpoint
        // Swift may already append /tun, so only add if not present
        let tun_path = if self.server_path.ends_with("/tun") || self.server_path.ends_with("/tun/")
        {
            self.server_path.trim_end_matches('/').to_string()
        } else if self.server_path.ends_with("/") {
            format!("{}tun", self.server_path)
        } else {
            format!("{}/tun", self.server_path)
        };
        let url = format!(
            "wss://{}:{}{}",
            self.server_host, self.server_port, tun_path
        );

        info!("[IosTun] Connecting to {}", url);

        // TLS connect.
        //
        // iOS: rustls backend — pure-Rust TLS with TLS 1.3 support.
        // native-tls (Security.framework) cannot negotiate TLS 1.3 on iOS;
        // boring (BoringSSL) leaks anonymous VM. rustls is the only viable option.
        // Cert verification uses bundled Mozilla roots (webpki-roots) — the NE
        // sandbox blocks /etc/ssl/ and trustd was unreliable from the extension.
        //
        // iOS: rustls backend — BoringSSL's SSL_read leaks anonymous VM in the NE sandbox.
        // macOS: boring backend — retains Chrome ClientHello fingerprint mimicry.
        #[cfg(feature = "ios-direct-tun")]
        let tls_stream =
            rvpn_tls::connect_rustls(&self.server_host, self.server_port, Some(&self.server_host))
                .await
                .context("TLS handshake failed")?;

        #[cfg(not(feature = "ios-direct-tun"))]
        let tls_stream = rvpn_tls::connect_chrome_like(
            &self.server_host,
            self.server_port,
            rvpn_tls::TlsFingerprint::Chrome,
            Some(&self.server_host),
        )
        .await
        .context("TLS handshake failed")?;

        info!(
            "[IosTun] TLS connected ({})",
            if cfg!(feature = "ios-direct-tun") {
                "rustls"
            } else {
                "Chrome fingerprint"
            }
        );

        // Perform WebSocket handshake over the TLS stream using minimal parser
        let ws = timeout(
            std::time::Duration::from_secs(5),
            MinimalWebSocket::connect(tls_stream, &url),
        )
        .await
        .context("WebSocket handshake timeout (5s)")?
        .context("WebSocket handshake failed")?;

        info!("[IosTun] WebSocket connected (TLS verified, minimal parser)");

        // Check again after WS handshake
        if !self.reconnect_enabled.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!(
                "Connection cancelled by stop after WS handshake"
            ));
        }

        // Split into independent reader/writer halves
        let (mut ws_read, mut ws_write) = ws.split();

        // Perform X3DH handshake
        let mut ratchet = self
            .perform_handshake(&mut ws_read, &mut ws_write)
            .await
            .context("X3DH handshake failed")?;

        info!("[IosTun] X3DH handshake complete");

        // Check again after X3DH
        if !self.reconnect_enabled.load(Ordering::Relaxed) {
            return Err(anyhow::anyhow!("Connection cancelled by stop after X3DH"));
        }

        // Receive VirtualIp message
        let virtual_ip = self
            .receive_virtual_ip(&mut ws_read, &mut ratchet)
            .await
            .context("Failed to receive VirtualIp")?;

        // Extract IP address
        let ipv4_str = virtual_ip
            .ipv4
            .map(|v4| v4.to_string())
            .context("No IPv4 address in VirtualIp")?;

        info!("[IosTun] Assigned IP: {}", ipv4_str);

        // Store tunnel IP, gateway IP, DNS servers, and MTU
        {
            let mut tunnel_ip = self.tunnel_ip.lock().unwrap();
            *tunnel_ip = Some(ipv4_str.clone());
        }
        {
            let mut gateway_ip = self.gateway_ip.lock().unwrap();
            *gateway_ip = virtual_ip.gateway_ip.map(|v4| v4.to_string());
        }
        {
            let mut dns = self.dns_servers.lock().unwrap();
            *dns = virtual_ip.dns_servers.clone();
        }
        {
            let mut mtu = self.mtu.lock().unwrap();
            *mtu = virtual_ip.mtu;
        }

        // Set state to IpAssigned and notify Swift
        self.notify_state(TunClientState::IpAssigned, Some(&ipv4_str), "IP assigned")
            .await;

        // Set state to Connected
        self.notify_state(TunClientState::Connected, Some(&ipv4_str), "Connected")
            .await;

        // Start packet relay loop
        info!("[IosTun] connect() entering run_packet_relay()");
        self.run_packet_relay(ws_write, ws_read, ratchet).await;
        info!("[IosTun] connect() run_packet_relay() returned, connection ended");

        Ok(())
    }

    /// Perform X3DH handshake with server
    async fn perform_handshake(
        &self,
        ws_reader: &mut WsReader,
        ws_writer: &mut WsWriter,
    ) -> Result<DoubleRatchet> {
        // Generate ephemeral key
        let ephemeral_key = EphemeralKey::generate();

        // Create X3DH initiator
        let initiator = X3DHInitiator {
            identity_key: self.identity_key.clone(),
            ephemeral_key,
        };

        // Get the X25519 public key derived from the client's Ed25519 identity
        let identity_public = initiator.identity_key.x25519_public_key();

        // Get public key bytes for the handshake
        let ephemeral_public = initiator.ephemeral_key.public_key.to_bytes();

        // Send Hello message with X3DH parameters
        let hello = HandshakeMessage::Hello {
            version: rvpn_core::protocol::ProtocolVersion::CURRENT,
            auth_method: rvpn_core::protocol::AuthMethod::X3DH,
            ephemeral_key: Some(ephemeral_public.to_vec()),
            identity_key: Some(identity_public.to_vec()),
            session_token: None,
            connection_nonce: None,
        };

        let hello_bytes =
            serde_json::to_vec(&hello).context("Failed to serialize Hello message")?;
        ws_writer
            .send_binary(&hello_bytes)
            .await
            .context("Failed to send Hello message")?;

        debug!("[IosTun] Sent X3DH Hello message");

        // Receive ServerHello response
        let mut frame_buf = vec![0u8; 16384];
        let (frame_type, frame_len) = timeout(
            std::time::Duration::from_secs(5),
            ws_reader.next_frame(&mut frame_buf),
        )
        .await
        .context("WebSocket timeout during handshake (5s)")?
        .context("WebSocket error during handshake")?;

        match frame_type {
            FrameType::Binary => {
                // ServerHello received, extract keys
                let server_hello: HandshakeMessage =
                    serde_json::from_slice(&frame_buf[..frame_len])
                        .context("Failed to parse ServerHello message")?;

                match server_hello {
                    HandshakeMessage::ServerHello {
                        ephemeral_key: _server_ephemeral,
                        identity_key: server_identity_key,
                        signed_prekey: server_signed_prekey,
                        prekey_signature: server_prekey_signature,
                    } => {
                        debug!("[IosTun] Received ServerHello with ephemeral key");

                        // Build a bundle from the SERVER'S ACTUAL KEYS (not the pre-loaded bundle)
                        let server_identity_key: [u8; 32] =
                            server_identity_key.as_slice().try_into().map_err(|_| {
                                anyhow::anyhow!("Server identity key has invalid length")
                            })?;
                        let server_signed_prekey: [u8; 32] =
                            server_signed_prekey.as_slice().try_into().map_err(|_| {
                                anyhow::anyhow!("Server signed prekey has invalid length")
                            })?;
                        let prekey_signature: [u8; 64] = server_prekey_signature
                            .as_slice()
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("Prekey signature has invalid length"))?;

                        // Verify the Ed25519 signature on signed_prekey using the server's identity_key
                        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
                            &server_identity_key,
                        )
                        .map_err(|e| anyhow::anyhow!("Invalid server identity key: {}", e))?;
                        let signature = ed25519_dalek::Signature::from_bytes(&prekey_signature);
                        verifying_key
                            .verify(&server_signed_prekey, &signature)
                            .map_err(|e| anyhow::anyhow!("Invalid prekey signature: {}", e))?;
                        debug!("[IosTun] Server prekey signature verified");

                        // For the X3DH key agreement, we need the server's identity_x25519_key which is
                        // derived from the server's Ed25519 *private* key. We can't derive it from the
                        // Ed25519 *public* key sent in ServerHello, so use the pre-loaded bundle's value.
                        let server_identity_x25519_key = self.server_bundle.identity_x25519_key;

                        // Bundle for X3DH key agreement — uses pre-loaded identity_x25519_key
                        // but the actual signed_prekey from the ServerHello (signature-verified above)
                        let server_bundle_from_hello = X3DHPublicBundle {
                            identity_key: server_identity_key,
                            identity_x25519_key: server_identity_x25519_key,
                            signed_prekey: server_signed_prekey,
                            prekey_signature,
                            one_time_prekey: None,
                            // Handshake path doesn't propagate rotation
                            // metadata (yet); the pre-loaded bundle from
                            // disk carries those fields and drives TOFU
                            // enforcement in IosTunClient::new.
                            identity_key_version: self.server_bundle.identity_key_version,
                            rotation_signature: self.server_bundle.rotation_signature,
                        };

                        // Complete X3DH agreement using the SERVER'S ACTUAL bundle
                        let (shared_secret, _x3dh_material) = initiator
                            .agree(&server_bundle_from_hello)
                            .context("X3DH key agreement failed")?;

                        debug!("[IosTun] X3DH shared secret derived successfully");

                        // Initialize Double Ratchet as Alice (initiator)
                        // In X3DH, the server (Bob) doesn't generate an ephemeral key.
                        // The _server_ephemeral field is empty - init_alice doesn't use this parameter.
                        let ratchet = DoubleRatchet::init_alice(shared_secret, [0u8; 32]);

                        info!("[IosTun] Double Ratchet initialized as Alice (initiator)");

                        Ok(ratchet)
                    }
                    _ => Err(anyhow::anyhow!(
                        "Unexpected handshake message type from server"
                    )),
                }
            }
            _ => Err(anyhow::anyhow!("Expected binary message during handshake")),
        }
    }

    /// Receive and process VirtualIp message
    async fn receive_virtual_ip(
        &self,
        ws_reader: &mut WsReader,
        ratchet: &mut DoubleRatchet,
    ) -> Result<VirtualIp> {
        // Wait for first encrypted frame after X3DH
        let mut frame_buf = vec![0u8; 16384];
        let (frame_type, frame_len) = timeout(
            std::time::Duration::from_secs(5),
            ws_reader.next_frame(&mut frame_buf),
        )
        .await
        .context("Timeout waiting for VirtualIp (5s)")?
        .context("WebSocket error during VirtualIp wait")?;

        match frame_type {
            FrameType::Binary => {
                debug!(
                    "[IosTun] Received {} bytes, decrypting VirtualIp",
                    frame_len
                );

                // Deserialize RatchetMessage
                let ratchet_msg = RatchetMessage::from_bytes(&frame_buf[..frame_len])
                    .context("Failed to deserialize RatchetMessage")?;

                // Decrypt with VirtualIp payload type as AAD
                let decrypted = ratchet
                    .decrypt(&ratchet_msg, &[PayloadType::VirtualIp as u8])
                    .context("Failed to decrypt VirtualIp")?;

                // Unpad the frame
                let unpadded = unpad_packet(&decrypted)
                    .map_err(|e| anyhow::anyhow!("Failed to unpad VirtualIp: {}", e))?;

                // Parse VirtualIp from JSON
                let virtual_ip: VirtualIp =
                    serde_json::from_slice(&unpadded).context("Failed to parse VirtualIp JSON")?;

                info!(
                    "[IosTun] VirtualIp received: ipv4={:?}, dns={:?}, mtu={}",
                    virtual_ip.ipv4, virtual_ip.dns_servers, virtual_ip.mtu
                );

                Ok(virtual_ip)
            }
            _ => Err(anyhow::anyhow!("Expected binary message for VirtualIp")),
        }
    }

    /// Truncate the diagnostics CSV at the start of a relay so the file holds
    /// only the current (about-to-run) session's data. The jetsam kill happens
    /// mid-relay, so the file left behind is the killed session's trajectory.
    #[cfg(feature = "diagnostics")]
    fn reset_mem_log(&self) {
        let Some(path) = self.mem_log_path.as_ref() else {
            return;
        };
        use std::io::Write;
        if let Ok(mut f) = std::fs::File::create(path) {
            let _ = f.write_all(b"elapsed_sec,rss_bytes,commit_bytes,peak_commit,commit_after_collect,allzones_in_use,internal,compressed,headroom_bytes,direction,frame_count\n");
            let _ = f.flush();
        }
    }

    /// Append a memory-growth snapshot to the diagnostics CSV (best-effort;
    /// failures are swallowed so this never disrupts the relay). Fires only at
    /// the periodic RSS checkpoints, so the blocking file I/O is infrequent.
    ///
    /// Columns (CSV): `elapsed_sec,rss_bytes,commit_bytes,allzones_in_use,headroom_bytes,direction,frame_count`
    /// - `rss_bytes`: OS resident (overstates jetsam; trust the trend).
    /// - `commit_bytes`: mimalloc live bytes (Rust heap).
    /// - `allzones_in_use`: sum of size_in_use across ALL malloc zones (C heap).
    ///   Flat here while headroom declines ⇒ growth is NOT in any malloc zone
    ///   (it's in vm/mmap regions or compressed pages).
    /// - `headroom_bytes`: `os_proc_available_memory()` — bytes before jetsam.
    #[cfg(feature = "diagnostics")]
    fn append_mem_log(&self, relay_start: std::time::Instant, direction: &str, frame_count: u64) {
        let Some(path) = self.mem_log_path.as_ref() else {
            return;
        };
        let elapsed = relay_start.elapsed().as_secs_f64();
        let rss = get_rss_bytes();
        let commit = mi_committed_bytes();
        let peak_commit = mi_peak_commit_bytes();
        // Force mimalloc to return freed pages BEFORE measuring.  If
        // commit_after_collect < commit, the gap is deferred-free hoarding.
        let commit_after = mi_commit_after_collect();
        let allzones = all_zones_size_in_use();
        let (internal, compressed) = vm_internal_compressed();
        let headroom = jetsam_headroom_bytes();
        let line = format!(
            "{:.1},{},{},{},{},{},{},{},{},{},{}\n",
            elapsed,
            rss,
            commit,
            peak_commit,
            commit_after,
            allzones,
            internal,
            compressed,
            headroom,
            direction,
            frame_count
        );
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = f.write_all(line.as_bytes());
            let _ = f.flush();
        }
    }

    /// Main packet relay loop.
    ///
    /// The three arms (`swift_to_server`, `server_to_swift`, `keepalive`) are
    /// `tokio::spawn`ed as independent tasks. This is important for two reasons:
    ///
    /// 1. **Diagnostic attribution.** The MEMDELTA `vm_internal_compressed()`
    ///    samples inside each arm are only meaningful if that arm's samples are
    ///    adjacent in wall-clock time. When all three arms share a single task
    ///    (as they did under `tokio::select!`), a poll of arm A can be
    ///    arbitrarily separated by polls of arms B and C, so `prev_internal`
    ///    absorbs growth from every arm. Independent tasks are polled
    ///    concurrently by the multi-thread runtime; the samples in a given arm
    ///    are still not perfectly isolated from process-wide anonymous VM, but
    ///    the arm's own operations dominate the observed delta.
    /// 2. **Progress.** A slow ObjC callback into Swift (e.g. writePackets
    ///    stalling behind kernel-IPC backpressure) can no longer starve the
    ///    ws_write / keepalive path — each task has independent poll budget.
    async fn run_packet_relay(
        self: &Arc<Self>,
        ws_write: WsWriter,
        ws_read: WsReader,
        ratchet: DoubleRatchet,
    ) {
        info!("[IosTun] run_packet_relay STARTING");
        #[cfg(feature = "diagnostics")]
        let relay_start = std::time::Instant::now();
        #[cfg(feature = "diagnostics")]
        self.reset_mem_log();

        // Wrap ratchet and WebSocket writer in Arc<Mutex> for safe sharing between
        // the three spawned tasks. All three may need the writer (data path,
        // pong replies, keepalive); TX and keepalive both hold the ratchet.
        let ratchet = Arc::new(Mutex::new(ratchet));
        let ws_write = Arc::new(Mutex::new(ws_write));

        // --- swift_to_server task ---
        let tx_task = {
            let this = Arc::clone(self);
            let ratchet = ratchet.clone();
            let ws_write = ws_write.clone();
            #[cfg(feature = "diagnostics")]
            let relay_start = relay_start;
            tokio::spawn(async move {
                Self::run_tx(
                    this,
                    ratchet,
                    ws_write,
                    #[cfg(feature = "diagnostics")]
                    relay_start,
                )
                .await;
            })
        };

        // --- server_to_swift task ---
        let rx_task = {
            let this = Arc::clone(self);
            let ratchet = ratchet.clone();
            let ws_write = ws_write.clone();
            #[cfg(feature = "diagnostics")]
            let relay_start = relay_start;
            tokio::spawn(async move {
                Self::run_rx(
                    this,
                    ws_read,
                    ratchet,
                    ws_write,
                    #[cfg(feature = "diagnostics")]
                    relay_start,
                )
                .await;
            })
        };

        // --- keepalive task ---
        let ka_task = {
            let this = Arc::clone(self);
            let ratchet = ratchet.clone();
            let ws_write = ws_write.clone();
            tokio::spawn(async move {
                Self::run_keepalive(this, ratchet, ws_write).await;
            })
        };

        // Wait for the first task to finish. That task should have already
        // sent a shutdown signal on its way out (all error paths do); we send
        // one here defensively so the other two arms unblock even if the first
        // exited by clean channel close.
        tokio::select! {
            _ = tx_task => info!("[IosTun] tx task completed first"),
            _ = rx_task => info!("[IosTun] rx task completed first"),
            _ = ka_task => info!("[IosTun] keepalive task completed first"),
        }
        let _ = self.shutdown_tx.send(());

        info!("[IosTun] run_packet_relay ENDING");
        self.notify_state(TunClientState::Error, None, "Connection closed")
            .await;
    }

    /// Swift → Server (TX) task body. Spawned by `run_packet_relay` so its
    /// `prev_internal_tx` samples aren't interleaved with the RX/keepalive
    /// polls on the same task.
    async fn run_tx(
        this: Arc<Self>,
        ratchet: Arc<Mutex<DoubleRatchet>>,
        ws_write: Arc<Mutex<WsWriter>>,
        #[cfg(feature = "diagnostics")] relay_start: std::time::Instant,
    ) {
        let mut encrypt_bufs = EncryptBuffers::new();
        let packet_pool = this.packet_pool();
        let from_swift_receiver = Arc::clone(&this.from_swift_receiver);
        let shutdown_tx = this.shutdown_tx.clone();
        let ws_write_for_swift = ws_write;

        let mut shutdown_rx = shutdown_tx.subscribe();
        let mut packet_count = 0u64;
        let mut batch_count = 0u64;
        let mut pending_packet: Option<Vec<u8>> = None;
        // Reuse the batch Vec across iterations to avoid a heap allocation
        // on every outgoing batch (~416/sec under heavy traffic).
        let mut batch = Vec::with_capacity(OUTGOING_BATCH_MAX_FRAMES);
        #[cfg(feature = "diagnostics")]
        let mut prev_internal_tx: u64 = 0;
        info!("[IosTun] swift_to_server task STARTED");
        'outer: loop {
            // Acquire the first packet for this batch (either a packet that
            // did not fit in the previous batch or a fresh one from Swift).
            batch.clear();
            let mut batch_bytes = 0usize;

            let first = match pending_packet.take() {
                Some(p) => p,
                None => {
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            info!("[IosTun] Swift->Server relay: shutdown received, breaking");
                            break 'outer;
                        }
                        packet = async {
                            let mut r = from_swift_receiver.lock().await;
                            r.recv().await
                        } => {
                            match packet {
                                Some(p) => p,
                                None => {
                                    info!("[IosTun] Swift->Server: from_swift_receiver closed, breaking (sent {} packets)", packet_count);
                                    break 'outer;
                                }
                            }
                        }
                    }
                }
            };

            batch.push(first);
            batch_bytes += batch[0].len();
            packet_count += 1;

            // Collect additional packets until we hit a size/time limit.
            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_millis(OUTGOING_BATCH_TIMEOUT_MS);
            let mut receiver_closed = false;
            while batch.len() < OUTGOING_BATCH_MAX_FRAMES && batch_bytes < OUTGOING_BATCH_MAX_BYTES
            {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }

                let packet = tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("[IosTun] Swift->Server relay: shutdown received while collecting, breaking");
                        break 'outer;
                    }
                    packet = timeout(remaining, async {
                        let mut r = from_swift_receiver.lock().await;
                        r.recv().await
                    }) => packet,
                };

                match packet {
                    Ok(Some(data)) => {
                        // Account for the 6-byte MultiplexedFrame header.
                        if batch_bytes + 6 + data.len() > OUTGOING_BATCH_MAX_BYTES {
                            pending_packet = Some(data);
                            break;
                        }
                        batch_bytes += data.len();
                        batch.push(data);
                        packet_count += 1;
                    }
                    Ok(None) => {
                        receiver_closed = true;
                        break;
                    }
                    Err(_) => break,
                }
            }

            batch_count += 1;

            let encrypted = {
                #[cfg(feature = "diagnostics")]
                {
                    let (internal, _) = vm_internal_compressed();
                    let delta = internal.wrapping_sub(prev_internal_tx);
                    if delta > 0 {
                        info!(
                            "[IosTun] MEMDELTA tx:pre_encrypt +{} B (internal={})",
                            delta, internal
                        );
                    }
                    prev_internal_tx = internal;
                }
                let mut ratchet_guard = ratchet.lock().await;
                match Self::encrypt_data_batch(&mut ratchet_guard, &batch, &mut encrypt_bufs) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        // Return Vecs to pool before breaking
                        let mut pool = packet_pool.lock().await;
                        for v in batch.drain(..) {
                            pool.put(v);
                        }
                        error!("[IosTun] Swift->Server: encrypt_data_batch failed: {}, sending shutdown", e);
                        let _ = shutdown_tx.send(());
                        break 'outer;
                    }
                }
            };

            // Return Vecs to pool for reuse (data is now in `encrypted`)
            {
                let mut pool = packet_pool.lock().await;
                for v in batch.drain(..) {
                    pool.put(v);
                }
            }

            let mut ws_guard = ws_write_for_swift.lock().await;
            if let Err(e) = ws_guard.send_binary(&encrypted).await {
                error!(
                    "[IosTun] Swift->Server: WebSocket send failed: {}, sending shutdown",
                    e
                );
                drop(ws_guard);
                let _ = shutdown_tx.send(());
                break 'outer;
            }
            #[cfg(feature = "diagnostics")]
            {
                let (internal, _) = vm_internal_compressed();
                let delta = internal.wrapping_sub(prev_internal_tx);
                if delta > 0 {
                    info!(
                        "[IosTun] MEMDELTA tx:ws_send +{} B (internal={})",
                        delta, internal
                    );
                }
                prev_internal_tx = internal;
            }

            // Reclaim freed C-heap pages every 100 batches (~4×/sec).
            // The leak is iOS libmalloc retaining BoringSSL's per-record
            // freed allocations. The 15s keepalive call isn't frequent
            // enough; calling here keeps internal growth bounded.
            if batch_count % 100 == 0 {
                all_zones_pressure_relief();
                #[cfg(feature = "diagnostics")]
                {
                    let rss = get_rss_bytes();
                    info!(
                        "[IosTun] RSS: {} bytes ({:.1} MB) after {} batches, {} packets sent",
                        rss,
                        rss as f64 / (1024.0 * 1024.0),
                        batch_count,
                        packet_count
                    );
                    this.append_mem_log(relay_start, "tx", batch_count);
                }
            }

            if receiver_closed {
                info!("[IosTun] Swift->Server: from_swift_receiver closed after batch, breaking (sent {} packets)", packet_count);
                break 'outer;
            }
        }
        info!("[IosTun] swift_to_server task ENDED");
    }

    /// Server → Swift (RX) task body.
    async fn run_rx(
        this: Arc<Self>,
        mut ws_read: WsReader,
        ratchet: Arc<Mutex<DoubleRatchet>>,
        ws_write: Arc<Mutex<WsWriter>>,
        #[cfg(feature = "diagnostics")] relay_start: std::time::Instant,
    ) {
        let mut decrypt_bufs = DecryptBuffers::new();
        let to_swift_sender = this.to_swift_sender.clone();
        let shutdown_tx = this.shutdown_tx.clone();
        let packet_notify_tx = this.packet_notify_tx.clone();
        let ws_write_for_pong = ws_write;

        // SERVER -> SWIFT direction
        let mut shutdown_rx = shutdown_tx.subscribe();
        let mut packet_count = 0u64;
        let mut frame_buf = vec![0u8; 16384];
        #[cfg(feature = "diagnostics")]
        let mut prev_internal_rx: u64 = 0;
        info!("[IosTun] server_to_swift task STARTED");
        loop {
            tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("[IosTun] Server->Swift relay: shutdown received, breaking");
                break;
            }
            result = timeout(std::time::Duration::from_secs(300), ws_read.next_frame(&mut frame_buf)) => {
                #[cfg(feature = "diagnostics")]
                {
                    let (internal, _) = vm_internal_compressed();
                    let delta = internal.wrapping_sub(prev_internal_rx);
                    if delta > 0 {
                        info!("[IosTun] MEMDELTA rx:ws_read +{} B (internal={})", delta, internal);
                    }
                    prev_internal_rx = internal;
                }
                match result {
                    Ok(Ok((FrameType::Binary, len))) => {
                        this.update_last_rx_time();
                        packet_count += 1;

                        // Log RSS every 500 packets to trace memory growth
                        #[cfg(feature = "diagnostics")]
                        if packet_count % 500 == 0 {
                            let rss = get_rss_bytes();
                            info!("[IosTun] RX RSS: {} bytes ({:.1} MB) after {} packets",
                                  rss, rss as f64 / (1024.0 * 1024.0), packet_count);
                            this.append_mem_log(relay_start, "rx", packet_count);
                        }

                            // Deserialize and decrypt — zero-copy: RatchetMessageRef
                            // borrows ciphertext from the WebSocket frame instead of
                            // allocating a new Vec per message.
                            let decrypted_len = match RatchetMessageRef::from_bytes(&frame_buf[..len]) {
                                Ok(ratchet_msg) => {
                                    let mut ratchet_guard = ratchet.lock().await;
                                    match ratchet_guard.decrypt_to_ref(&ratchet_msg, &[PayloadType::Data as u8], &mut decrypt_bufs.plaintext) {
                                        Ok(len) => {
                                            #[cfg(feature = "diagnostics")]
                                            {
                                                let (internal, _) = vm_internal_compressed();
                                                let delta = internal.wrapping_sub(prev_internal_rx);
                                                if delta > 0 {
                                                    info!("[IosTun] MEMDELTA rx:decrypt +{} B (internal={})", delta, internal);
                                                }
                                                prev_internal_rx = internal;
                                            }
                                            Some(len)
                                        }
                                        Err(e) => {
                                            error!("[IosTun] Server->Swift: Failed to decrypt packet: {}", e);
                                            None
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!("[IosTun] Server->Swift: Failed to deserialize RatchetMessage: {}", e);
                                    None
                                }
                            };

                            if let Some(len) = decrypted_len {
                                match unpad_packet_slice(&decrypt_bufs.plaintext[..len]) {
                                    Ok(unpadded) => {
                                        // Parse all MultiplexedFrame packets from the
                                        // decrypted plaintext and batch data packets into a
                                        // single Bytes allocation with u16-LE length prefixes.
                                        // This reduces per-packet heap churn from N to 1.
                                        decrypt_bufs.batch_buf.clear();
                                        let mut offset = 0usize;
                                        let mut has_data = false;
                                        while offset + 6 <= unpadded.len() {
                                            let flow_id = u32::from_be_bytes([unpadded[offset], unpadded[offset + 1], unpadded[offset + 2], unpadded[offset + 3]]);
                                            let payload_len = u16::from_be_bytes([unpadded[offset + 4], unpadded[offset + 5]]) as usize;
                                            if offset + 6 + payload_len > unpadded.len() {
                                                error!("[IosTun] Server->Swift: frame truncated at offset {} (need {} got {})", offset, 6 + payload_len, unpadded.len());
                                                break;
                                            }
                                            if flow_id == 0 {
                                                // Control frame — parse and handle
                                                if let Ok(ctrl) = MultiplexedFrame::decode(&unpadded[offset..]) {
                                                    if let Ok(msg) = ctrl.parse_control() {
                                                        trace!("[IosTun] Server->Swift: control {:?}", msg);
                                                    }
                                                }
                                            } else {
                                                // Data frame — accumulate into batch buffer
                                                let len_bytes = (payload_len as u16).to_le_bytes();
                                                decrypt_bufs.batch_buf.extend_from_slice(&len_bytes);
                                                decrypt_bufs.batch_buf.extend_from_slice(&unpadded[offset + 6..offset + 6 + payload_len]);
                                                has_data = true;
                                            }
                                            offset += 6 + payload_len;
                                        }
                                        if has_data {
                                            if BISECT_DROP_INBOUND {
                                                // BISECTION: discard the decrypted batch so the
                                                // Swift/NE write path stays idle, while BoringSSL
                                                // read + Rust decrypt keep running. If jetsam
                                                // headroom still declines ~per frame → BoringSSL;
                                                // if flat → Swift/NE write path.
                                                decrypt_bufs.batch_buf.clear();
                                            } else {
                                                // Zero-copy: split() takes the filled portion
                                                // of the BytesMut, freeze() converts to Bytes
                                                // without copying. The original batch_buf is
                                                // left empty and reusable on the next frame.
                                                let batch = decrypt_bufs.batch_buf.split().freeze();
                                                if to_swift_sender.send(batch).await.is_err() {
                                                    info!("[IosTun] Server->Swift: to_swift_sender closed, breaking");
                                                    break;
                                                }
                                                let _ = packet_notify_tx.try_send(());
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!("[IosTun] Server->Swift: Failed to unpad packet: {}", e);
                                    }
                                }
                            }
                        }
                        Ok(Ok((FrameType::Close, _))) => {
                            this.update_last_rx_time();
                            info!("[IosTun] Server->Swift: received Close frame, sending shutdown and breaking");
                            let _ = shutdown_tx.send(());
                            break;
                        }
                        Ok(Ok((FrameType::Ping, len))) => {
                            this.update_last_rx_time();
                            debug!("[IosTun] Server->Swift: received Ping");
                            if let Ok(mut ws_guard) = ws_write_for_pong.try_lock() {
                                let _ = ws_guard.send_pong(&frame_buf[..len]).await;
                            }
                        }
                        Ok(Err(e)) => {
                            error!("[IosTun] Server->Swift: WebSocket error: {}, sending shutdown and breaking", e);
                            let _ = shutdown_tx.send(());
                            break;
                        }
                        Err(_) => {
                            error!("[IosTun] Server->Swift: WebSocket read timeout (300s), sending shutdown and breaking");
                            let _ = shutdown_tx.send(());
                            break;
                        }
                    }
                }
            }
        }
        info!(
            "[IosTun] server_to_swift task ENDED (received {} packets)",
            packet_count
        );
    }

    /// Keepalive task body. Sends a WebSocket Ping every 15 seconds to keep the
    /// server-side idle timeout from firing, plus an encrypted keepalive over
    /// the ratchet. Also detects process suspension (>30s wall-clock skip) and
    /// server silence (>30s since last RX) and signals shutdown on either.
    async fn run_keepalive(
        this: Arc<Self>,
        ratchet: Arc<Mutex<DoubleRatchet>>,
        ws_write: Arc<Mutex<WsWriter>>,
    ) {
        let shutdown_tx = this.shutdown_tx.clone();
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate first tick.
        interval.tick().await;
        // Pre-allocate reusable buffers for keepalive packets.
        let mut ka_frame = Vec::with_capacity(128);
        let mut ka_padded = Vec::with_capacity(1024);
        let mut ka_encrypted = Vec::with_capacity(1152);
        let mut ka_serialized = Vec::with_capacity(1280);
        // Track wall-clock time to detect iOS process suspension.
        // Must use SystemTime (CLOCK_REALTIME) — Instant (CLOCK_MONOTONIC)
        // pauses during iOS suspension, making elapsed time unreliable.
        let mut last_wall = std::time::SystemTime::now();
        loop {
            interval.tick().await;

            // Return freed C-heap pages to the OS across ALL malloc zones
            // (default zone alone misses the nano zone where small allocations
            // live). Non-disruptive (no tunnel drop). Vestigial from the
            // BoringSSL era but harmless — a no-op with rustls.
            all_zones_pressure_relief();

            // Detect process suspension: if wall clock advanced >30s
            // since last keepalive, iOS froze us and the server's
            // 60-second timeout already expired. Force reconnect.
            let now = std::time::SystemTime::now();
            let elapsed = now.duration_since(last_wall).unwrap_or_default();
            last_wall = now;
            if elapsed > std::time::Duration::from_secs(30) {
                error!("[IosTun] Keepalive: process was suspended for {:.0}s, connection dead. Reconnecting.", elapsed.as_secs_f64());
                let _ = shutdown_tx.send(());
                break;
            }

            // Check if server is still sending data. If no data received
            // for 60s, the connection is dead (server closed it, network
            // changed, etc.). Force reconnect.
            let rx_elapsed = this.last_rx_time.load(Ordering::Relaxed);
            if rx_elapsed > 0 {
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let since_rx = now_secs.saturating_sub(rx_elapsed);
                if since_rx > 30 {
                    error!("[IosTun] Keepalive: no server data for {}s, connection dead. Reconnecting.", since_rx);
                    let _ = shutdown_tx.send(());
                    break;
                }
            }

            // Send WS ping using try_lock — non-blocking.
            // Under high traffic, the data path holds ws_write continuously.
            // Blocking on lock().await would stall the keepalive for seconds.
            // The data path's own send_binary calls already update
            // last_activity on the server, so a missed ping is fine
            // when data is flowing.
            if let Ok(mut ws_guard) = ws_write.try_lock() {
                let _ = ws_guard.send_ping(b"").await;
            }

            // Try encrypted keepalive (non-blocking on both locks).
            if let Ok(mut ratchet_guard) = ratchet.try_lock() {
                match Self::build_keepalive_to(
                    &mut ratchet_guard,
                    &mut ka_frame,
                    &mut ka_padded,
                    &mut ka_encrypted,
                    &mut ka_serialized,
                ) {
                    Ok(_len) => {
                        drop(ratchet_guard);
                        let payload = std::mem::take(&mut ka_serialized);
                        let mut ws_guard = ws_write.lock().await;
                        if let Err(e) = ws_guard.send_binary(&payload).await {
                            error!("[IosTun] Keepalive: send failed: {}", e);
                            drop(ws_guard);
                            let _ = shutdown_tx.send(());
                            break;
                        }
                    }
                    Err(e) => {
                        error!("[IosTun] Keepalive: build failed: {}", e);
                    }
                }
            }
        }
    }

    /// Encrypt a batch of TUN packets into a single WebSocket/Ratchet message.
    ///
    /// Each packet is wrapped in a `MultiplexedFrame` with `flow_id=1`; the
    /// encoded frames are concatenated, padded once, and encrypted once. The
    /// server parses the decrypted plaintext with `parse_frames`.
    ///
    /// Uses pre-allocated `EncryptBuffers` to avoid per-batch heap allocations.
    /// Frame headers are written directly into the plaintext buffer to avoid
    /// cloning each packet into a `MultiplexedFrame` struct.
    ///
    /// Returns a borrow of `bufs.serialized` rather than an owned `Vec` so the
    /// pre-allocated buffer is genuinely reused across batches. Taking the
    /// buffer out (`mem::take`) would empty its allocation and force a fresh
    /// ~14 KB reallocation on every call (~416/sec under heavy traffic).
    fn encrypt_data_batch<'a>(
        ratchet: &mut DoubleRatchet,
        packets: &[Vec<u8>],
        bufs: &'a mut EncryptBuffers,
    ) -> Result<&'a [u8]> {
        if packets.is_empty() {
            return Err(anyhow::anyhow!("Cannot encrypt empty batch"));
        }

        bufs.clear();

        // Encode frame headers + payload directly into the plaintext buffer.
        // Format: [flow_id: u32 BE] [payload_len: u16 BE] [payload: N bytes]
        // This avoids MultiplexedFrame::new_data() which would clone each packet.
        for packet in packets {
            bufs.plaintext.extend_from_slice(&1u32.to_be_bytes());
            bufs.plaintext
                .extend_from_slice(&(packet.len() as u16).to_be_bytes());
            bufs.plaintext.extend_from_slice(packet);
        }

        // Pad the concatenated frames to a 1KB boundary for traffic analysis mitigation
        // Write padding directly into the pre-allocated buffer
        let data_len = bufs.plaintext.len();
        let target_size = (data_len + 2).div_ceil(1024) * 1024;
        let max_data_len = target_size.saturating_sub(2);
        let padding_len = max_data_len.saturating_sub(data_len);

        bufs.padded.clear();
        bufs.padded.extend_from_slice(&bufs.plaintext);
        if padding_len > 0 {
            let old_len = bufs.padded.len();
            bufs.padded.resize(old_len + padding_len, 0);
            StdRng::from_entropy().fill_bytes(&mut bufs.padded[old_len..]);
        }
        bufs.padded
            .extend_from_slice(&(padding_len as u16).to_be_bytes());

        // Encrypt with Data payload type as AAD — reuse ciphertext buffer
        let (nonce, header) = ratchet
            .encrypt_to(
                &bufs.padded,
                &[PayloadType::Data as u8],
                &mut bufs.ciphertext,
            )
            .context("Failed to encrypt data batch")?;

        // Build RatchetMessage and serialize directly into reuse buffer
        let msg = RatchetMessage {
            header,
            nonce,
            ciphertext: std::mem::take(&mut bufs.ciphertext),
        };
        bufs.serialized.clear();
        bincode::serialize_into(&mut bufs.serialized, &msg)
            .map_err(|e| anyhow::anyhow!("RatchetMessage serialize: {}", e))?;
        // Put the ciphertext buffer back for next batch
        bufs.ciphertext = msg.ciphertext;

        Ok(&bufs.serialized)
    }

    /// Build an encrypted keepalive (Ping) frame into pre-allocated buffers.
    ///
    /// Same as `build_keepalive_packet` but writes the serialized result
    /// into `out` instead of allocating a new `Vec` each time.
    /// Returns the number of bytes written.
    fn build_keepalive_to(
        ratchet: &mut DoubleRatchet,
        frame_buf: &mut Vec<u8>,
        padded_buf: &mut Vec<u8>,
        encrypted_buf: &mut Vec<u8>,
        out: &mut Vec<u8>,
    ) -> Result<usize> {
        let ping = ControlMessage::Ping {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
        };
        let frame =
            MultiplexedFrame::new_control(&ping).context("Failed to create keepalive frame")?;

        // Encode frame directly into buffer (6-byte header + payload)
        frame_buf.clear();
        frame_buf.extend_from_slice(&frame.flow_id.to_be_bytes());
        frame_buf.extend_from_slice(&(frame.payload.len() as u16).to_be_bytes());
        frame_buf.extend_from_slice(&frame.payload);

        let padded = pad_packet(frame_buf).map_err(|e| anyhow::anyhow!("Padding failed: {}", e))?;
        padded_buf.clear();
        padded_buf.extend_from_slice(&padded);

        let (nonce, header) = ratchet
            .encrypt_to(padded_buf, &[PayloadType::Data as u8], encrypted_buf)
            .context("Failed to encrypt keepalive")?;

        let msg = RatchetMessage {
            header,
            nonce,
            ciphertext: std::mem::take(encrypted_buf),
        };
        out.clear();
        bincode::serialize_into(&mut *out, &msg)
            .map_err(|e| anyhow::anyhow!("RatchetMessage serialize: {}", e))?;
        *encrypted_buf = msg.ciphertext;

        Ok(out.len())
    }

    /// Get the assigned tunnel IP
    pub fn get_tunnel_ip(&self) -> Option<String> {
        let guard = self.tunnel_ip.lock().unwrap();
        guard.clone()
    }

    pub fn get_gateway_ip(&self) -> Option<String> {
        let guard = self.gateway_ip.lock().unwrap();
        guard.clone()
    }

    pub fn get_dns_servers(&self) -> Vec<std::net::IpAddr> {
        let guard = self.dns_servers.lock().unwrap();
        guard.clone()
    }

    pub fn get_mtu(&self) -> u16 {
        let guard = self.mtu.lock().unwrap();
        *guard
    }

    /// Get the runtime handle for spawning tasks
    pub fn runtime_handle(&self) -> tokio::runtime::Handle {
        self.handle.clone()
    }

    /// Get current state
    pub fn get_state(&self) -> TunClientState {
        TunClientState::from(self.state.load(Ordering::SeqCst))
    }

    /// Check if DNS proxy is enabled in config
    pub fn is_dns_proxy_enabled(&self) -> bool {
        self.config.enable_dns_proxy
    }

    /// Get DNS bind address from config
    pub fn get_dns_bind_addr(&self) -> &str {
        &self.config.dns_bind_addr
    }

    /// Get builtin bypass countries from config
    pub fn get_builtin_bypass_countries(&self) -> &[String] {
        &self.config.builtin_bypass_countries
    }

    /// Check if block ads is enabled in config
    pub fn is_block_ads_enabled(&self) -> bool {
        self.config.block_ads
    }

    /// Update the last-received timestamp to the current wall-clock time.
    fn update_last_rx_time(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_rx_time.store(now, Ordering::Relaxed);
    }

    /// Get the last time any traffic was received from the server, in Unix seconds.
    pub fn last_rx_time(&self) -> u64 {
        self.last_rx_time.load(Ordering::Relaxed)
    }

    /// Get identity key reference
    #[allow(dead_code)] // Used by android_tun_ffi.rs
    pub(crate) fn identity_key(&self) -> &IdentityKey {
        &self.identity_key
    }

    /// Get server bundle reference
    #[allow(dead_code)] // Used by android_tun_ffi.rs
    pub(crate) fn server_bundle(&self) -> &X3DHPublicBundle {
        &self.server_bundle
    }

    /// Get server host
    pub fn server_host(&self) -> &str {
        &self.server_host
    }

    /// Get server port
    pub fn server_port(&self) -> u16 {
        self.server_port
    }

    /// Get server path
    pub fn server_path(&self) -> &str {
        &self.server_path
    }

    /// Get pre-resolved server IP address
    pub fn server_ip(&self) -> std::net::IpAddr {
        self.server_ip
    }

    /// Get a clone of the packet pool handle for sharing with FFI.
    pub(crate) fn packet_pool(&self) -> Arc<Mutex<VecPool>> {
        Arc::clone(&self.packet_pool)
    }

    /// Send a packet to the server (call this from Swift)
    /// Swift calls this to send packets to be relayed to the server
    pub async fn send_packet_to_server(&self, packet: Vec<u8>) -> Result<()> {
        self.from_swift_sender
            .send(packet)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to send packet: {}", e))
    }

    /// Non-blocking send for FFI hot path (avoids block_on deadlock)
    /// Returns TrySendError if the channel is full or disconnected
    pub fn try_send_packet(
        &self,
        packet: Vec<u8>,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<Vec<u8>>> {
        self.from_swift_sender.try_send(packet)
    }

    /// Receive a packet from the server (call this from Swift)
    /// Swift calls this to receive packets that came from the server
    /// Non-blocking - returns None if no packet is available
    pub fn recv_packet_from_server(&self) -> Option<bytes::Bytes> {
        let mut rx = self.to_swift_receiver.try_lock().ok()?;
        rx.try_recv().ok()
    }

    /// Wait until a packet may be available, or the timeout elapses.
    /// Called from Swift's write loop so it can sleep event-driven instead
    /// of polling every millisecond.
    /// Returns 1 if a packet may be available, 0 on timeout/disconnect.
    pub fn wait_for_packet(&self, timeout_ms: u64) -> i32 {
        // Use a std channel instead of tokio::sync::Notify so we can block
        // synchronously here without entering the Tokio runtime. The Swift
        // write loop runs on its own dispatch queue, not a Tokio worker.
        let rx = self.packet_notify_rx.lock().unwrap();
        match rx.recv_timeout(std::time::Duration::from_millis(timeout_ms)) {
            Ok(()) => 1,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => 0,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => 0,
        }
    }

    /// Start the client (runs connect and relay in background)
    /// Implements reconnection loop when enabled via set_reconnect_enabled()
    ///
    /// This method is idempotent — calling it multiple times has no effect.
    pub fn start(self: &Arc<Self>) {
        // Atomically check and set is_started to prevent duplicate reconnect loops
        if self
            .is_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            warn!("[IosTun] start() called but reconnect loop already running, ignoring");
            return;
        }

        let client = Arc::clone(self);
        self.handle.spawn(async move {
            let mut attempts: u32 = 0;
            let mut had_successful_session = false;
            loop {
                // Check if reconnection is enabled
                if !client.reconnect_enabled.load(Ordering::Relaxed) {
                    info!("[IosTun] Reconnection disabled, exiting reconnect loop");
                    break;
                }

                // Check max attempts (0 = unlimited)
                let max_attempts = client.reconnect_max_attempts.load(Ordering::Relaxed);
                if max_attempts > 0 && attempts >= max_attempts {
                    error!(
                        "[IosTun] Max reconnection attempts ({}) reached",
                        max_attempts
                    );
                    client
                        .notify_state(
                            TunClientState::Error,
                            None,
                            "Max reconnection attempts reached",
                        )
                        .await;
                    break;
                }

                // Track reconnect frequency in a 30 s sliding window. Under a
                // metro-tunnel network flap the previous code path (immediate
                // reconnect after a successful session) could churn 10+
                // reconnects in a minute, each allocating a fresh TLS session
                // + ratchet + tokio tasks. That's how the iOS extension trips
                // the per-process jetsam limit even when no single session is
                // heavy — the cumulative in-flight state from overlapping
                // teardowns pushes us past the cap.
                let recent_reconnects = {
                    let now = std::time::Instant::now();
                    let mut history = client.reconnect_history.lock().unwrap();
                    while let Some(&front) = history.front() {
                        if now.duration_since(front) > std::time::Duration::from_secs(30) {
                            history.pop_front();
                        } else {
                            break;
                        }
                    }
                    let n = history.len();
                    history.push_back(now);
                    n
                };

                // Base delay: none after a successful session (the network
                // path is fresh), exponential backoff after failures.
                let base_delay_ms: u64 = if had_successful_session {
                    had_successful_session = false;
                    0
                } else if attempts > 0 {
                    let initial_delay = client.reconnect_initial_delay_ms.load(Ordering::Relaxed);
                    let max_delay = client.reconnect_max_delay_ms.load(Ordering::Relaxed);
                    std::cmp::min(
                        initial_delay.saturating_mul(2u64.saturating_pow(attempts - 1)),
                        max_delay,
                    )
                } else {
                    0
                };

                // Flap-aware minimum backoff: after N reconnects in 30 s,
                // enforce a growing minimum delay regardless of whether the
                // previous session was "successful". The escalation stays
                // bounded by max_delay so a legitimate transition still
                // recovers quickly, but a signal-drop storm gets throttled
                // hard: 3 → 1s, 4 → 4s, 5 → 9s, 6 → 16s, 7 → 25s, …
                let max_delay = client.reconnect_max_delay_ms.load(Ordering::Relaxed);
                let flap_min_ms: u64 = if recent_reconnects >= 3 {
                    let n = (recent_reconnects - 2) as u64;
                    (1000u64.saturating_mul(n).saturating_mul(n)).min(max_delay.max(1000))
                } else {
                    0
                };
                let delay_ms = base_delay_ms.max(flap_min_ms);

                // Snapshot memory before the connect so we can attribute any
                // leak to a specific reconnect (Rust panics don't fire on
                // jetsam kills — this log is our only signal).
                let rss_before_kb = rss_bytes_now() / 1024;
                let headroom_before_kb = headroom_bytes_now() / 1024;
                info!(
                    "[IosTun] Reconnect: attempt={} recent_reconnects_30s={} delay={}ms (base={} flap_min={}) rss={}KB headroom={}KB",
                    attempts + 1,
                    recent_reconnects,
                    delay_ms,
                    base_delay_ms,
                    flap_min_ms,
                    rss_before_kb,
                    headroom_before_kb,
                );

                if delay_ms > 0 {
                    // Sleep in small chunks so we can check reconnect_enabled mid-sleep
                    let sleep_start = tokio::time::Instant::now();
                    let sleep_duration = tokio::time::Duration::from_millis(delay_ms);
                    while tokio::time::Instant::now().duration_since(sleep_start) < sleep_duration {
                        if !client.reconnect_enabled.load(Ordering::Relaxed) {
                            info!("[IosTun] Reconnection disabled during backoff, stopping");
                            return;
                        }
                        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                    }
                }

                match client.connect().await {
                    Ok(()) => {
                        // Connection completed normally (had a successful session)
                        let rss_after_kb = rss_bytes_now() / 1024;
                        let headroom_after_kb = headroom_bytes_now() / 1024;
                        info!(
                            "[IosTun] Session ended: rss={}KB (Δ{:+}KB) headroom={}KB (Δ{:+}KB)",
                            rss_after_kb,
                            rss_after_kb as i64 - rss_before_kb as i64,
                            headroom_after_kb,
                            headroom_after_kb as i64 - headroom_before_kb as i64,
                        );
                        info!("[IosTun] Connection ended, reconnecting immediately...");
                        attempts = 0;
                        had_successful_session = true;
                    }
                    Err(e) => {
                        let rss_after_kb = rss_bytes_now() / 1024;
                        let headroom_after_kb = headroom_bytes_now() / 1024;
                        error!(
                            "[IosTun] Connection failed (attempt {}): {} — rss={}KB (Δ{:+}KB) headroom={}KB (Δ{:+}KB)",
                            attempts + 1,
                            e,
                            rss_after_kb,
                            rss_after_kb as i64 - rss_before_kb as i64,
                            headroom_after_kb,
                            headroom_after_kb as i64 - headroom_before_kb as i64,
                        );
                        attempts += 1;
                    }
                }

                // Check if reconnection was disabled while we were connected
                if !client.reconnect_enabled.load(Ordering::Relaxed) {
                    info!("[IosTun] Reconnection disabled after connection end, stopping");
                    break;
                }
            }
        });
    }

    /// Set whether reconnection is enabled
    pub fn set_reconnect_enabled(&self, enabled: bool) {
        self.reconnect_enabled.store(enabled, Ordering::Relaxed);
    }

    /// Check if reconnection is enabled
    pub fn is_reconnect_enabled(&self) -> bool {
        self.reconnect_enabled.load(Ordering::Relaxed)
    }

    /// Set maximum reconnection attempts (0 = unlimited)
    pub fn set_reconnect_max_attempts(&self, attempts: u32) {
        self.reconnect_max_attempts
            .store(attempts, Ordering::Relaxed);
    }

    /// Set initial reconnection delay (ms)
    pub fn set_reconnect_initial_delay_ms(&self, delay_ms: u64) {
        self.reconnect_initial_delay_ms
            .store(delay_ms, Ordering::Relaxed);
    }

    /// Set maximum reconnection delay (ms)
    pub fn set_reconnect_max_delay_ms(&self, delay_ms: u64) {
        self.reconnect_max_delay_ms
            .store(delay_ms, Ordering::Relaxed);
    }

    /// Stop the client
    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
        // Reset is_started so the client can be restarted after a full stop
        self.is_started.store(false, Ordering::SeqCst);
    }

    /// Request a gentle reconnect without disabling the reconnect loop.
    ///
    /// This sends a shutdown signal to the current packet relay, causing
    /// `connect()` to return and the reconnect loop to start a new connection.
    /// Unlike `stop()`, this does NOT reset `is_started` or disable reconnect,
    /// so the reconnect loop continues naturally.
    ///
    /// A 5-second cooldown prevents reconnect storms from rapid network
    /// change notifications (especially on macOS where NWPathMonitor fires
    /// frequently).
    pub fn request_reconnect(&self) {
        let now = std::time::Instant::now();
        let mut last = self.last_reconnect_request.lock().unwrap();
        if now.duration_since(*last) < std::time::Duration::from_secs(5) {
            info!("[IosTun] Reconnect requested too soon (cooldown active), ignoring");
            return;
        }
        *last = now;
        drop(last);

        let _ = self.shutdown_tx.send(());
        info!("[IosTun] Reconnect requested via gentle shutdown signal");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tun_client_state_from_i32() {
        assert_eq!(TunClientState::from(0), TunClientState::Init);
        assert_eq!(TunClientState::from(1), TunClientState::Connecting);
        assert_eq!(TunClientState::from(2), TunClientState::IpAssigned);
        assert_eq!(TunClientState::from(3), TunClientState::Connected);
        assert_eq!(TunClientState::from(4), TunClientState::Error);
        assert_eq!(TunClientState::from(99), TunClientState::Error);
    }

    #[test]
    fn test_parse_server_url() {
        let (host, port, path) =
            IosTunClient::parse_server_url("wss://test.example.com:443/api/v1/ws").unwrap();
        assert_eq!(host, "test.example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api/v1/ws");

        let (host, port, path) =
            IosTunClient::parse_server_url("wss://test.example.com:443/api/v1/ws/").unwrap();
        assert_eq!(host, "test.example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/api/v1/ws/");
    }
}
