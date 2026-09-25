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
//!
//! State split: `IosTunClient` holds only the shared plumbing (runtime handle,
//! config, identity key, downlink channels to Swift, buffer pool, state
//! callback) plus one `default_session`. All per-exit-server state and logic
//! (connect, X3DH, packet relay, reconnect loop) lives in
//! [`crate::server_session::ServerSession`] so a later change can run N
//! sessions (one per exit server) for multi-server routing.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use anyhow::{Context as _, Result};
use tokio::sync::{mpsc, Mutex, RwLock};
use tracing::{info, warn};

use rvpn_core::crypto::{IdentityKey, X3DHPublicBundle};
use rvpn_split_tunnel::{Router, DEFAULT_SERVER_NAME};

use crate::ffi::{MobileServerEntry, TunConfig};
use crate::route_map::RouteMap;
use crate::server_session::{ServerSession, SharedContext};

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
pub(crate) fn rss_bytes_now() -> u64 {
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
pub(crate) fn rss_bytes_now() -> u64 { 0 }

/// Bytes of memory the process may still allocate before iOS jetsams it.
/// Always available for the same reason as `rss_bytes_now`.
#[cfg(target_vendor = "apple")]
pub(crate) fn headroom_bytes_now() -> u64 {
    extern "C" {
        fn os_proc_available_memory() -> u64;
    }
    unsafe { os_proc_available_memory() }
}
#[cfg(not(target_vendor = "apple"))]
pub(crate) fn headroom_bytes_now() -> u64 { 0 }

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
pub(crate) fn jetsam_headroom_bytes() -> u64 {
    unsafe { os_proc_available_memory() }
}

// iOS system allocator (libmalloc) zone APIs. The per-frame leak has been
// localized to the C layer (BoringSSL) which allocates via malloc. The default
// zone's live size_in_use is tiny (~90 KB) and pressure_relief on it alone does
// NOT stop the leak — so the growth is in another zone (iOS routes small allocs
// to the nano zone, which `malloc_default_zone()` doesn't cover) or in vm
// regions. These helpers enumerate ALL zones so we can measure/relief the lot.
// MUST match <malloc/malloc.h> malloc_statistics_t exactly (32 bytes on
// 64-bit). An undersized declaration is not a benign truncation:
// malloc_zone_statistics writes ALL four fields, so a smaller struct is a
// stack buffer overflow — on arm64 the trailing max_size_in_use /
// size_allocated writes landed on mem_stats_suffix's saved x28/x27 slots,
// returning with x28 = 0 and segfaulting the caller's next mach_task_self()
// read (the reconnect-loop deaths seen in builds 19–21).
#[cfg(feature = "diagnostics")]
#[repr(C)]
#[allow(dead_code)] // blocks_in_use/max_size_in_use/size_allocated are
// write-only padding for the ABI — the struct must span all 32 bytes even
// though we only read size_in_use.
struct MallocStatistics {
    blocks_in_use: libc::c_uint,
    _pad: u32,
    size_in_use: usize,
    max_size_in_use: usize,
    size_allocated: usize,
}

/// Read `task_vm_info` (flavor 22) raw bytes and extract the `internal` and
/// `compressed` fields at their known struct offsets (48 and 112). This splits
/// phys_footprint growth into:
/// - `internal` climbing ⇒ live anonymous (vm_allocate) leak — find the caller.
/// - `compressed` climbing ⇒ iOS compressing freed pages rather than reclaiming.
/// Both are outside the malloc heap (which `all_zones_size_in_use` already
/// proved flat), so this is the decisive next measurement.
#[cfg(feature = "diagnostics")]
pub(crate) fn vm_internal_compressed() -> (u64, u64) {
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
    #[cfg(feature = "diagnostics")]
    fn malloc_get_zone_name(zone: *mut std::ffi::c_void) -> *const libc::c_char;
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

/// Per-zone live bytes, compact "name=KB" list sorted by size desc, zones
/// >= 64 KB. The aggregate `all_zones_size_in_use` tells us the C heap grows
/// per reconnect; THIS tells us which zone owns the growth (e.g. the nano
/// zone = small ObjC/C allocs, a named helper zone = a specific framework).
#[cfg(feature = "diagnostics")]
pub(crate) fn zone_sizes_str() -> String {
    let mut entries: Vec<(String, u64)> = Vec::new();
    for zone in all_zone_ptrs() {
        unsafe {
            let mut stats = MallocStatistics {
                blocks_in_use: 0,
                _pad: 0,
                size_in_use: 0,
                max_size_in_use: 0,
                size_allocated: 0,
            };
            malloc_zone_statistics(zone, &mut stats);
            let name_ptr = malloc_get_zone_name(zone);
            let name = if name_ptr.is_null() {
                "?".to_string()
            } else {
                std::ffi::CStr::from_ptr(name_ptr)
                    .to_string_lossy()
                    .into_owned()
            };
            entries.push((name, stats.size_in_use as u64));
        }
    }
    entries.sort_by(|a, b| b.1.cmp(&a.1));
    entries
        .iter()
        .filter(|(_, s)| *s >= 64 * 1024)
        .map(|(n, s)| format!("{}={}KB", n, s / 1024))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Ask every malloc zone to release as many freed pages as possible. The default
/// zone alone does not cover the nano zone (where small BoringSSL allocations
/// live), so we must relief ALL zones. Non-disruptive (no live allocations,
/// no tunnel drop). Called from the 15 s keepalive.
pub(crate) fn all_zones_pressure_relief() {
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
pub(crate) fn all_zones_size_in_use() -> u64 {
    let mut total = 0u64;
    for zone in all_zone_ptrs() {
        let mut stats = MallocStatistics {
            blocks_in_use: 0,
            _pad: 0,
            size_in_use: 0,
            max_size_in_use: 0,
            size_allocated: 0,
        };
        unsafe {
            malloc_zone_statistics(zone, &mut stats);
        }
        total += stats.size_in_use as u64;
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
pub(crate) fn mi_committed_bytes() -> u64 {
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
pub(crate) fn mi_peak_commit_bytes() -> u64 {
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
pub(crate) fn mi_commit_after_collect() -> u64 {
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
///
/// # State Split
/// All per-exit-server state lives in [`ServerSession`] (`default_session`);
/// this struct holds only the shared plumbing (runtime handle, config,
/// identity key, downlink channels to Swift, buffer pool, state callback)
/// and delegates every per-session operation to the default session. A later
/// multi-server change adds one `ServerSession` per additional exit server.
pub struct IosTunClient {
    /// Configuration (kept for debugging and future reconnection support)
    /// Note: fields are extracted on construction to avoid per-packet locking
    #[allow(dead_code)]
    config: TunConfig,
    /// Receiver for packets to Swift
    pub to_swift_receiver: Arc<Mutex<mpsc::Receiver<bytes::Bytes>>>,
    /// Receiver half of the packet-arrival notification channel. Signalled
    /// (via `SharedContext::packet_notify_tx`) whenever a packet is pushed to
    /// the to-Swift channel, so the Swift write loop can wait event-driven
    /// instead of polling. Uses a std channel so the FFI wait function can
    /// block without entering the Tokio runtime.
    packet_notify_rx: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    /// Shared context handed to every `ServerSession`: tokio runtime handle
    /// (NEVER the Runtime itself — it is owned by `ios_tun_ffi::TUN_RUNTIME`;
    /// see the runtime-ownership section in AGENTS.md), client identity key,
    /// downlink sender + wakeup notification, buffer pool, state callback.
    shared: Arc<SharedContext>,
    /// The single default exit-server session. All per-server state and
    /// logic (connect, X3DH, packet relay, reconnect loop) lives here.
    default_session: Arc<ServerSession>,
    /// All sessions keyed by exit name: `"default"` (the same Arc as
    /// `default_session`) plus one per `extra_servers` entry. Extra sessions
    /// are created eagerly (cheap — no sockets) but started lazily via
    /// `ensure_session_started`.
    sessions: HashMap<String, Arc<ServerSession>>,
    /// Compiled static routing rules (domain + CIDR). `None` when
    /// `extra_servers` is empty — the single-server fast path, where the
    /// uplink demux short-circuits before parsing anything.
    router: Option<Arc<Router>>,
    /// Dynamic per-IP exit routes learned from routed DNS answers, shared
    /// with the DNS layer (which inserts) and consulted by the uplink demux
    /// before the static table. `None` together with `router`.
    route_map: Option<Arc<std::sync::Mutex<RouteMap>>>,
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
        // By resolving here (before DNS is hijacked), connects dial the IP directly.
        // Failure is NOT fatal: `None` makes connects fall back to dialing the hostname
        // (which works as long as the tunnel's DNS capture isn't live yet).
        let server_ip: Option<std::net::IpAddr> = if let Ok(ip) = host.parse::<std::net::IpAddr>()
        {
            Some(ip)
        } else {
            std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", host, port))
                .ok()
                .and_then(|mut addrs| addrs.next().map(|a| a.ip()))
        };
        match server_ip {
            Some(ip) => info!("[IosTun] Server {} resolved to {}", host, ip),
            None => warn!(
                "[IosTun] Failed to pre-resolve {}; reconnects will dial the hostname",
                host
            ),
        }

        // Load identity key (blocking I/O)
        let identity_key_path = std::path::PathBuf::from(&config.identity_key_path);
        let identity_key =
            IdentityKey::load(&identity_key_path).context("Failed to load identity key")?;

        // Load prekey bundle and enforce the TOFU pin (if configured) for the
        // default server.
        let (server_bundle, server_identity_pin_actual) =
            Self::load_bundle_and_pin(&config.prekey_bundle_path, config.server_identity_pin.as_deref())?;

        // Create channels for Swift TUN communication.
        // iOS keeps channels modest to stay within the 50 MB NE memory limit,
        // but 20 packets was too shallow: `readPackets` delivers bursts of up
        // to 256 packets, and while run_tx is busy encrypting/sending the
        // previous batch the overflow was silently dropped (TCP retransmits
        // and DNS retries manifest as multi-hundred-ms freezes). 256 costs
        // at worst ~0.4 MB. macOS keeps larger channels (no tight limit).
        // Using Bytes instead of Vec<u8> avoids per-packet copy in the server->swift path.
        let chan_cap = if cfg!(feature = "ios-direct-tun") {
            256
        } else {
            1000
        };
        let (to_swift_sender, to_swift_receiver) = mpsc::channel::<bytes::Bytes>(chan_cap);

        // Notification channel used to wake the Swift write loop when packets arrive.
        // std channel allows the FFI wait function to block without entering Tokio.
        let (packet_notify_tx, packet_notify_rx) = std::sync::mpsc::sync_channel(1);

        // NOTE: Runtime is now created by the FFI layer (see
        // `ios_tun_ffi::rvpn_tun_create`) and passed in as `handle`. Keeping
        // the Runtime out of this struct (and out of `SharedContext` /
        // `ServerSession`) prevents it from being dropped on a tokio worker
        // thread when the last Arc<Self> ref drops, which would panic in
        // `BlockingPool::shutdown`.

        // Derive a diagnostics path in the app-group container (the same dir
        // that holds the identity key) so RSS snapshots survive a jetsam kill
        // and can be pulled off afterward. Best-effort: stays `None` if the
        // identity key has no parent dir for some reason.
        #[cfg(feature = "diagnostics")]
        let mem_log_path = identity_key_path
            .parent()
            .map(|dir| dir.join("rvpn_memlog.csv"));

        let shared = Arc::new(SharedContext {
            handle,
            identity_key,
            to_swift_sender,
            packet_notify_tx,
            packet_pool: Arc::new(Mutex::new(VecPool::new(32))),
            state_callback: Arc::new(RwLock::new(None)),
            primary_tunnel_ip: Arc::new(std::sync::Mutex::new(None)),
        });

        let default_session = Arc::new(ServerSession::new(
            Arc::clone(&shared),
            host,
            server_ip,
            port,
            path,
            server_bundle,
            server_identity_pin_actual,
            chan_cap,
            true,  // is_default
            None,  // server_sni — default server uses its URL host for SNI
            #[cfg(feature = "diagnostics")]
            mem_log_path,
        ));

        // --- Multi-server setup (no-op when extra_servers is empty) ---
        let mut sessions: HashMap<String, Arc<ServerSession>> = HashMap::new();
        sessions.insert(DEFAULT_SERVER_NAME.to_string(), Arc::clone(&default_session));

        let mut router: Option<Arc<Router>> = None;
        let mut route_map: Option<Arc<std::sync::Mutex<RouteMap>>> = None;
        if !config.extra_servers.is_empty() {
            Self::validate_extra_server_names(&config.extra_servers)?;

            let mut known: Vec<&str> = vec![DEFAULT_SERVER_NAME];
            for entry in &config.extra_servers {
                let (host, port, path) = Self::parse_server_url(&entry.address)
                    .with_context(|| format!("extraServers[{}]: invalid address", entry.name))?;
                // Pre-resolve to an IP for the same DNS-circularity reason as
                // the default server (see above). Blocking I/O is fine here —
                // this runs before the tunnel hijacks DNS. Non-fatal like the
                // default server: None falls back to dialing the hostname.
                let server_ip: Option<IpAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
                    Some(ip)
                } else {
                    std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:{}", host, port))
                        .ok()
                        .and_then(|mut addrs| addrs.next().map(|a| a.ip()))
                };
                match server_ip {
                    Some(ip) => info!(
                        "[IosTun] Extra exit '{}' ({}): resolved to {}",
                        entry.name, host, ip
                    ),
                    None => warn!(
                        "[IosTun] Extra exit '{}': failed to pre-resolve {}; will dial hostname",
                        entry.name, host
                    ),
                }

                let (bundle, pin) =
                    Self::load_bundle_and_pin(&entry.prekey_bundle_path, entry.server_identity_pin.as_deref())
                        .with_context(|| format!("extraServers[{}]", entry.name))?;

                // Extra sessions do NOT get the diagnostics mem_log_path —
                // they would truncate each other's (and the default
                // session's) CSV on every relay start.
                let session = Arc::new(ServerSession::new(
                    Arc::clone(&shared),
                    host,
                    server_ip,
                    port,
                    path,
                    bundle,
                    pin,
                    chan_cap,
                    false, // is_default
                    entry.sni_hostname.clone(),
                    #[cfg(feature = "diagnostics")]
                    None,
                ));
                sessions.insert(entry.name.clone(), session);
                known.push(entry.name.as_str());
            }

            let built = Router::build(&known, &config.routing)
                .context("invalid multi-server routing rules")?;
            let (domain_rules, ip_rules) = built.rule_count();
            info!(
                "[IosTun] Multi-server routing: {} extra exit(s), {} domain rule(s), {} IP rule(s)",
                config.extra_servers.len(),
                domain_rules,
                ip_rules
            );
            router = Some(Arc::new(built));
            route_map = Some(Arc::new(std::sync::Mutex::new(RouteMap::new())));
        } else if !config.routing.is_empty() {
            anyhow::bail!(
                "routing rules require extraServers entries; with a single server every flow already uses it"
            );
        }

        Ok(Self {
            config: config.clone(),
            to_swift_receiver: Arc::new(Mutex::new(to_swift_receiver)),
            packet_notify_rx: std::sync::Mutex::new(packet_notify_rx),
            shared,
            default_session,
            sessions,
            router,
            route_map,
        })
    }

    /// Load a server prekey bundle from disk and compute its canonical TOFU
    /// pin. If `expected_pin` is set, enforce equality before proceeding —
    /// after this point we start opening TCP + WebSocket connections to the
    /// server, so failing fast keeps a wrong-identity connection from ever
    /// going on the wire. The `Error::ServerIdentityMismatch` variant is what
    /// the FFI layer downcasts to produce the `IDENTITY_MISMATCH
    /// expected=... actual=...` prefix the app parses.
    fn load_bundle_and_pin(
        prekey_bundle_path: &str,
        expected_pin: Option<&str>,
    ) -> Result<(X3DHPublicBundle, String)> {
        let bundle_json = std::fs::read_to_string(prekey_bundle_path)
            .context("Failed to read prekey bundle")?;
        let server_bundle: X3DHPublicBundle =
            serde_json::from_str(&bundle_json).context("Failed to parse prekey bundle JSON")?;

        let pin_actual = rvpn_core::identity_pin::encode_identity_pin(&server_bundle.identity_key)
            .context("Failed to encode server identity pin")?;
        if let Some(expected) = expected_pin {
            let matched = rvpn_core::identity_pin::pins_match(expected, &server_bundle.identity_key)
                .context("Configured server_identity_pin is not a valid pin string")?;
            if !matched {
                return Err(anyhow::Error::from(rvpn_core::Error::ServerIdentityMismatch {
                    expected: expected.to_string(),
                    actual: pin_actual,
                }));
            }
        }
        Ok((server_bundle, pin_actual))
    }

    /// Validate extra-server names: non-empty, unique, and not the reserved
    /// `"default"` (the top-level server_address already occupies that name).
    fn validate_extra_server_names(entries: &[MobileServerEntry]) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for entry in entries {
            if entry.name.is_empty() {
                anyhow::bail!("extraServers entry with empty name");
            }
            if entry.name == DEFAULT_SERVER_NAME {
                anyhow::bail!(
                    "extraServers name '{}' is reserved for the top-level server",
                    DEFAULT_SERVER_NAME
                );
            }
            if !seen.insert(entry.name.as_str()) {
                anyhow::bail!("duplicate extraServers name '{}'", entry.name);
            }
        }
        Ok(())
    }

    /// Canonical `ik:1:<base32>` pin of the server this client was constructed
    /// against. Computed at `new()` from the loaded prekey bundle's identity
    /// key. The app FFI reads this via `rvpn_tun_get_server_identity()`
    /// after the tunnel reaches `Connected` to persist the TOFU pin on the
    /// first connect.
    pub fn server_identity_pin(&self) -> &str {
        self.default_session.server_identity_pin()
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
        let state_callback = Arc::clone(&self.shared.state_callback);
        self.shared.handle.spawn(async move {
            let mut guard = state_callback.write().await;
            *guard = callback;
        });
    }

    /// Get the assigned tunnel IP
    pub fn get_tunnel_ip(&self) -> Option<String> {
        self.default_session.get_tunnel_ip()
    }

    /// Get the assigned gateway IP
    pub fn get_gateway_ip(&self) -> Option<String> {
        self.default_session.get_gateway_ip()
    }

    /// Get the DNS servers from VirtualIp
    pub fn get_dns_servers(&self) -> Vec<std::net::IpAddr> {
        self.default_session.get_dns_servers()
    }

    /// Get the MTU from VirtualIp
    pub fn get_mtu(&self) -> u16 {
        self.default_session.get_mtu()
    }

    /// Get the runtime handle for spawning tasks
    pub fn runtime_handle(&self) -> tokio::runtime::Handle {
        self.shared.handle.clone()
    }

    /// Get current state
    pub fn get_state(&self) -> TunClientState {
        self.default_session.get_state()
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

    /// Get the last time any traffic was received from the server, in Unix seconds.
    pub fn last_rx_time(&self) -> u64 {
        self.default_session.last_rx_time()
    }

    /// Get identity key reference
    #[allow(dead_code)] // Used by the DNS proxy startup in ios_tun_ffi.rs (dns feature)
    pub(crate) fn identity_key(&self) -> &IdentityKey {
        &self.shared.identity_key
    }

    /// Get server bundle reference
    #[allow(dead_code)] // Used by the DNS proxy startup in ios_tun_ffi.rs (dns feature)
    pub(crate) fn server_bundle(&self) -> &X3DHPublicBundle {
        self.default_session.server_bundle()
    }

    /// Get server host
    pub fn server_host(&self) -> &str {
        self.default_session.server_host()
    }

    /// Get server port
    pub fn server_port(&self) -> u16 {
        self.default_session.server_port()
    }

    /// Get server path
    pub fn server_path(&self) -> &str {
        self.default_session.server_path()
    }

    /// Get pre-resolved server IP address (`None` when startup resolution
    /// failed — connects fall back to dialing the hostname)
    pub fn server_ip(&self) -> Option<std::net::IpAddr> {
        self.default_session.server_ip()
    }

    /// Get a clone of the packet pool handle for sharing with FFI.
    pub(crate) fn packet_pool(&self) -> Arc<Mutex<VecPool>> {
        Arc::clone(&self.shared.packet_pool)
    }

    /// Send a packet to the server (call this from Swift)
    /// Swift calls this to send packets to be relayed to the server
    pub async fn send_packet_to_server(&self, packet: Vec<u8>) -> Result<()> {
        match self.choose_exit(&packet) {
            None => self.default_session.send_packet_to_server(packet).await,
            Some(name) => {
                self.ensure_session_started(&name);
                match self.sessions.get(&name) {
                    Some(session) => session
                        .enqueue_uplink(packet)
                        .map_err(|e| anyhow::anyhow!("Failed to send packet: {}", e)),
                    None => self.default_session.send_packet_to_server(packet).await,
                }
            }
        }
    }

    /// Non-blocking send for FFI hot path (avoids block_on deadlock)
    /// Returns TrySendError if the channel is full or disconnected
    pub fn try_send_packet(
        &self,
        packet: Vec<u8>,
    ) -> Result<(), tokio::sync::mpsc::error::TrySendError<Vec<u8>>> {
        match self.choose_exit(&packet) {
            // Single-server fast path (router is None) and default-routed
            // packets take exactly today's path — no rewrite, no stash.
            None => self.default_session.try_send_packet(packet),
            Some(name) => {
                self.ensure_session_started(&name);
                match self.sessions.get(&name) {
                    Some(session) => session.enqueue_uplink(packet),
                    None => self.default_session.try_send_packet(packet),
                }
            }
        }
    }

    /// Decide which exit session a Swift-originated packet should use.
    /// Returns `None` for the default exit (single-server configs, non-IPv4
    /// or unparseable packets, and anything no rule matches).
    fn choose_exit(&self, packet: &[u8]) -> Option<String> {
        choose_exit_name(
            self.router.as_deref(),
            self.route_map.as_deref(),
            packet,
        )
    }

    /// Start the named session's connect/reconnect loop if it isn't running
    /// yet (lazy start for secondary exits). Idempotent — `start()` guards
    /// with a compare-exchange; the early `is_started` check just avoids log
    /// noise. Called from the uplink demux on the first routed packet and
    /// from the DNS layer's pre-warm hook when a routed domain is resolved.
    pub fn ensure_session_started(&self, name: &str) {
        let Some(session) = self.sessions.get(name) else {
            return;
        };
        if session.is_started() {
            return;
        }
        info!("[IosTun] Lazy-starting session for exit '{}'", name);
        session.set_reconnect_enabled(true);
        session.start();
    }

    /// Canonical `ik:1:<base32>` pin of the named exit server, for per-exit
    /// TOFU pin capture. Returns `None` for unknown names.
    pub fn server_identity_pin_for(&self, name: &str) -> Option<String> {
        self.sessions
            .get(name)
            .map(|s| s.server_identity_pin().to_string())
    }

    /// The compiled multi-server router, if any (shared with the DNS layer).
    #[allow(dead_code)] // Used by the DNS proxy startup in ios_tun_ffi.rs (dns feature)
    pub(crate) fn router(&self) -> Option<Arc<Router>> {
        self.router.clone()
    }

    /// The dynamic route map, if any (shared with the DNS layer).
    #[allow(dead_code)] // Used by the DNS proxy startup in ios_tun_ffi.rs (dns feature)
    pub(crate) fn route_map(&self) -> Option<Arc<std::sync::Mutex<RouteMap>>> {
        self.route_map.clone()
    }

    /// Per-extra-exit connection info for the DNS layer's DoH client pool:
    /// (name, host, port, base path, prekey bundle, TLS resumption store).
    /// Empty when single-server. The store is the exit session's own, so the
    /// exit's `/dns` WebSocket reconnects resume from the same TLS tickets.
    #[allow(dead_code)] // Used by the DNS proxy startup in ios_tun_ffi.rs (dns feature)
    pub(crate) fn extra_session_dns_info(
        &self,
    ) -> Vec<(
        String,
        String,
        u16,
        String,
        X3DHPublicBundle,
        rvpn_tls::ResumptionStore,
    )> {
        self.sessions
            .iter()
            .filter(|(name, _)| name.as_str() != DEFAULT_SERVER_NAME)
            .map(|(name, s)| {
                (
                    name.clone(),
                    s.server_host().to_string(),
                    s.server_port(),
                    s.server_path().to_string(),
                    s.server_bundle().clone(),
                    s.resumption_store(),
                )
            })
            .collect()
    }

    /// The default (primary) exit session's TLS session resumption store, for
    /// the DNS layer's primary DoH client.
    #[allow(dead_code)] // Used by the DNS proxy startup in ios_tun_ffi.rs (dns feature)
    pub(crate) fn resumption_store(&self) -> rvpn_tls::ResumptionStore {
        self.default_session.resumption_store()
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
        self.default_session.start();
    }

    /// Set whether reconnection is enabled
    pub fn set_reconnect_enabled(&self, enabled: bool) {
        // Applies to every session: disabling on stop must silence lazy
        // secondary loops too; enabling on start is harmless for sessions
        // that haven't been started yet (the flag is only read by start()).
        for session in self.sessions.values() {
            session.set_reconnect_enabled(enabled);
        }
    }

    /// Check if reconnection is enabled
    pub fn is_reconnect_enabled(&self) -> bool {
        self.default_session.is_reconnect_enabled()
    }

    /// Set maximum reconnection attempts (0 = unlimited)
    pub fn set_reconnect_max_attempts(&self, attempts: u32) {
        self.default_session.set_reconnect_max_attempts(attempts);
    }

    /// Set initial reconnection delay (ms)
    pub fn set_reconnect_initial_delay_ms(&self, delay_ms: u64) {
        self.default_session.set_reconnect_initial_delay_ms(delay_ms);
    }

    /// Set maximum reconnection delay (ms)
    pub fn set_reconnect_max_delay_ms(&self, delay_ms: u64) {
        self.default_session.set_reconnect_max_delay_ms(delay_ms);
    }

    /// Stop the client
    pub fn stop(&self) {
        for session in self.sessions.values() {
            session.stop();
        }
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
        // A network change kills every open connection, so nudge every
        // session that has been started. Each session has its own cooldown.
        for session in self.sessions.values() {
            if session.is_started() {
                session.request_reconnect();
            }
        }
    }
}

/// Decide which named exit a Swift-originated uplink packet should use.
///
/// Lookup order: (a) dynamic route map (unexpired DNS-learned entries),
/// (b) static CIDR rules via `router.choose_ip`, (c) `None` = default exit.
///
/// Returns `None` immediately when `router` is `None` (single-server config)
/// so the App-Store-shipped fast path pays only one Option check — no packet
/// parsing at all. Non-IPv4 or unparseable packets also return `None`.
///
/// Free function (not a method) so the demux policy is unit-testable without
/// constructing an `IosTunClient` (which needs keys, bundles, and DNS).
pub(crate) fn choose_exit_name(
    router: Option<&Router>,
    route_map: Option<&std::sync::Mutex<RouteMap>>,
    packet: &[u8],
) -> Option<String> {
    let router = router?;
    // IPv4 base header: version nibble + enough bytes for the dst address.
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let dst = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));

    // (a) Dynamic DNS-learned routes win over static CIDR rules: the exit
    // that resolved the domain knows the answer's addresses freshest.
    if let Some(route_map) = route_map {
        if let Some(name) = route_map.lock().unwrap().lookup(&dst) {
            return Some(name);
        }
    }

    // (b) Static CIDR rules.
    let chosen = router.choose_ip(dst);
    if chosen == DEFAULT_SERVER_NAME {
        None
    } else {
        Some(chosen.to_string())
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

    fn extra_entry(name: &str) -> MobileServerEntry {
        MobileServerEntry {
            name: name.to_string(),
            address: "wss://127.0.0.1:443/connect".to_string(),
            prekey_bundle_path: "/nonexistent/bundle.json".to_string(),
            server_identity_pin: None,
            sni_hostname: None,
        }
    }

    #[test]
    fn test_validate_extra_server_names() {
        // Valid: distinct, non-reserved names.
        assert!(IosTunClient::validate_extra_server_names(&[
            extra_entry("sg"),
            extra_entry("us")
        ])
        .is_ok());

        // Reserved name rejected.
        let err = IosTunClient::validate_extra_server_names(&[extra_entry("default")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("reserved"), "unexpected error: {}", err);

        // Duplicates rejected.
        let err = IosTunClient::validate_extra_server_names(&[extra_entry("sg"), extra_entry("sg")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("duplicate"), "unexpected error: {}", err);

        // Empty name rejected.
        let err = IosTunClient::validate_extra_server_names(&[extra_entry("")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("empty"), "unexpected error: {}", err);
    }

    /// Minimal IPv4 packet (header only) with the given dst address.
    fn v4_packet(dst: Ipv4Addr) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45;
        p[16..20].copy_from_slice(&dst.octets());
        p
    }

    fn test_router() -> Router {
        let mut routing: HashMap<String, rvpn_split_tunnel::RoutingRule> = HashMap::new();
        routing.insert(
            "sg".to_string(),
            rvpn_split_tunnel::RoutingRule {
                domains: vec!["routed.example.com".to_string()],
                ips: vec!["8.8.8.0/24".to_string()],
            },
        );
        Router::build(&[DEFAULT_SERVER_NAME, "sg"], &routing).unwrap()
    }

    #[test]
    fn test_choose_exit_name_fast_path() {
        // No router (single-server): always default, even for a packet that
        // would match a rule — this is the zero-overhead App Store path.
        let packet = v4_packet(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(choose_exit_name(None, None, &packet), None);

        // Non-IPv4 and truncated packets go to default.
        let router = test_router();
        let route_map = std::sync::Mutex::new(RouteMap::new());
        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        assert_eq!(
            choose_exit_name(Some(&router), Some(&route_map), &v6),
            None
        );
        assert_eq!(
            choose_exit_name(Some(&router), Some(&route_map), &packet[..10]),
            None
        );
    }

    #[test]
    fn test_choose_exit_name_static_rule() {
        let router = test_router();
        let route_map = std::sync::Mutex::new(RouteMap::new());
        // Static CIDR rule match.
        assert_eq!(
            choose_exit_name(
                Some(&router),
                Some(&route_map),
                &v4_packet(Ipv4Addr::new(8, 8, 8, 8))
            )
            .as_deref(),
            Some("sg")
        );
        // No match → default.
        assert_eq!(
            choose_exit_name(
                Some(&router),
                Some(&route_map),
                &v4_packet(Ipv4Addr::new(9, 9, 9, 9))
            ),
            None
        );
    }

    #[test]
    fn test_choose_exit_name_dynamic_overrides_static() {
        let router = test_router();
        let route_map = std::sync::Mutex::new(RouteMap::new());
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        // A DNS-learned route to a different exit beats the static CIDR rule.
        route_map.lock().unwrap().insert(
            IpAddr::V4(dst),
            "hk",
            std::time::Duration::from_secs(300),
        );
        assert_eq!(
            choose_exit_name(Some(&router), Some(&route_map), &v4_packet(dst)).as_deref(),
            Some("hk")
        );
    }

    #[test]
    fn test_choose_exit_name_expired_dynamic_falls_through() {
        let router = test_router();
        let route_map = std::sync::Mutex::new(RouteMap::new());
        let dst = Ipv4Addr::new(8, 8, 8, 8);
        route_map.lock().unwrap().insert(
            IpAddr::V4(dst),
            "hk",
            std::time::Duration::from_secs(0),
        );
        // Expired dynamic entry → static rule decides.
        assert_eq!(
            choose_exit_name(Some(&router), Some(&route_map), &v4_packet(dst)).as_deref(),
            Some("sg")
        );
        // And with no static match, an expired entry falls back to default.
        let other = Ipv4Addr::new(1, 2, 3, 4);
        route_map.lock().unwrap().insert(
            IpAddr::V4(other),
            "hk",
            std::time::Duration::from_secs(0),
        );
        assert_eq!(
            choose_exit_name(Some(&router), Some(&route_map), &v4_packet(other)),
            None
        );
    }
}
