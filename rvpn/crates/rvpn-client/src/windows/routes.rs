//! Windows route and DNS management for TUN mode.
//!
//! On connect we (a) pin a host route for the VPN server through the
//! physical gateway, (b) cover IPv4 with two /1 routes and IPv6 with
//! ::/1 + 8000::/1 through the wintun adapter, and (c) point the adapter's
//! DNS at the resolvers that work through the tunnel with a winning
//! interface metric. Every change is recorded in the state file *before* it
//! is applied, so a crash can never leave the machine with broken routing:
//! the next start restores from that file first, and a clean disconnect
//! tears down the same changes.
//!
//! All route, DNS and metric manipulation goes through the IP Helper API
//! directly (`CreateIpForwardEntry2`, `SetInterfaceDnsSettings`,
//! `SetIpInterfaceEntry`, ...). An earlier version shelled out to route.exe
//! and PowerShell; that was dropped because an elevated child process
//! inherits user-controllable state (PATH, SystemRoot, PSModulePath module
//! auto-load), which made it hijackable by malware running as the user.
//!
//! The state file lives at `%ProgramData%\rvpn\route_state.json` in a
//! directory created with a SYSTEM + Administrators-only ACL (ProgramData is
//! resolved via `SHGetKnownFolderPath`, never the user-controllable
//! environment). Before an existing state file is trusted for restore it is
//! validated: it must be a plain file (no reparse point/junction) owned by
//! SYSTEM or Administrators — anything else is refused, loudly.

use std::ffi::c_void;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND,
    ERROR_OBJECT_ALREADY_EXISTS, ERROR_SUCCESS, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, CreateIpForwardEntry2, DNS_INTERFACE_SETTINGS,
    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER, DeleteIpForwardEntry2, FreeMibTable,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_SKIP_UNICAST, GET_ADAPTERS_ADDRESSES_FLAGS, GetAdaptersAddresses, GetBestRoute2,
    GetIfEntry2, GetIpForwardTable2, GetIpInterfaceEntry, GetUnicastIpAddressEntry,
    IP_ADAPTER_ADDRESSES_LH, IP_ADDRESS_PREFIX, InitializeIpInterfaceEntry, MIB_IF_ROW2,
    MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
    SetInterfaceDnsSettings, SetIpInterfaceEntry, SetUnicastIpAddressEntry,
};
use windows::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0,
    IpDadStateDuplicate, IpDadStatePreferred, MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_INET,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::CreateDirectoryW;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath};
use windows::core::{GUID, HRESULT, PCWSTR, PWSTR, w};

use super::sec;
use super::sec::check;

/// Fail-closed covering routes. Two /1 routes per family cover the whole
/// address space without touching the physical default route. IPv6 is
/// covered even when the server assigns no v6 lease: v6 traffic must be
/// blocked, never sent directly over the physical adapter (the leak is
/// worse than the blackhole). The WFP block in `wfp.rs` makes that
/// blackhole fail fast.
pub(crate) const V4_COVERING: [(Ipv4Addr, Ipv4Addr); 2] = [
    (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(128, 0, 0, 0)),
    (Ipv4Addr::new(128, 0, 0, 0), Ipv4Addr::new(128, 0, 0, 0)),
];
pub(crate) const V6_COVERING: [&str; 2] = ["::/1", "8000::/1"];

/// Gate for the SetIpInterfaceEntry failure probe: when set, a failed Set
/// dumps the Get-filled row and probes which row variants this interface
/// accepts before the error is reported. See diagnose_set_failure.
const IFMETRIC_DEBUG_ENV: &str = "RVPN_IFMETRIC_DEBUG";

/// Gate for the route-leak diagnostics dump: when set, a failed
/// route-resolution check dumps the winning route, the adapter state, and
/// the longest-prefix candidates from the forward table. See
/// diagnose_route_leak. Read-only; never changes the fail-closed behavior.
const ROUTE_DEBUG_ENV: &str = "RVPN_ROUTE_DEBUG";

/// Representative probe addresses for the post-install leak check
/// (verify_routes_resolve_via_adapter). GetBestRoute2 is a pure route-table
/// lookup and sends no traffic, so well-known public resolver addresses are
/// safe targets that never touch the network.
const VERIFY_V4: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);
const VERIFY_V6: Ipv6Addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);

/// How often the connection watchdog re-verifies the adapter and routes
/// while connected. GetIfEntry2/GetBestRoute2 are cheap route-table reads,
/// so two seconds is responsive without churn.
const WATCHDOG_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

/// Everything needed to set up tunnel routing.
pub struct RouteConfig {
    /// IP of the VPN server we connect to (must stay routed via the
    /// physical gateway or the tunnel kills its own transport).
    pub server_ip: IpAddr,
    /// wintun adapter name (e.g. "rVPN").
    pub adapter_name: String,
    /// wintun adapter interface index.
    pub adapter_index: u32,
    /// DNS servers to set on the adapter (queried through the tunnel).
    pub dns_servers: Vec<IpAddr>,
}

/// Record of what we changed. The state file is the rollback plan for the
/// next start after a crash, so every entry is persisted *before* the
/// change it describes is applied.
#[derive(Serialize, Deserialize, Default, Debug, PartialEq)]
struct AppliedState {
    /// LUID (`NET_LUID.Value`) of the wintun adapter every change is scoped
    /// to. LUIDs (unlike interface indexes) are never reused after reboot,
    /// so rollback can never touch the wrong adapter.
    adapter_luid: Option<u64>,
    /// Adapter GUID (the "{...}" string from GetAdaptersAddresses), needed
    /// by SetInterfaceDnsSettings to undo the DNS change.
    adapter_guid: Option<String>,
    /// Host route pinning the VPN server via the physical gateway.
    server_route: Option<ServerRoute>,
    /// Covering routes added via the adapter, one entry per route.
    routes: Vec<CoveringRoute>,
    /// DNS servers set on the adapter; empty means DNS was never touched.
    dns_servers: Vec<IpAddr>,
    /// Previous per-family interface metric settings, restored on rollback.
    interface_metrics: Vec<InterfaceMetricState>,
}

impl AppliedState {
    /// True when nothing recorded remains on the system.
    fn is_empty(&self) -> bool {
        self.server_route.is_none()
            && self.routes.is_empty()
            && self.dns_servers.is_empty()
            && self.interface_metrics.is_empty()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct ServerRoute {
    server_ip: IpAddr,
    gateway: Ipv4Addr,
    /// LUID of the physical interface the gateway is reachable through;
    /// recorded so the delete is scoped to the same interface.
    interface_luid: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct CoveringRoute {
    prefix: IpAddr,
    prefix_len: u8,
    /// On-link routes record no next hop: the interface itself is the next
    /// hop. `Some` only appears in state files written before the on-link
    /// change (IPv4 routes used the adapter address as gateway); the
    /// recorded row is replayed verbatim, so rollback still deletes them.
    next_hop: Option<IpAddr>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct InterfaceMetricState {
    /// Address family (AF_INET / AF_INET6) the recorded row belongs to.
    family: u16,
    use_automatic_metric: bool,
    metric: u32,
}

/// Route-table operations for the covering routes. Production uses the
/// Win32 wrappers; tests substitute stubs so install-failure injection and
/// rollback can be exercised in-process without touching the real route
/// table.
#[derive(Clone, Copy)]
struct CoveringRouteOps {
    add: fn(&CoveringRoute, NET_LUID_LH) -> Result<()>,
    delete: fn(NET_LUID_LH, &CoveringRoute) -> Result<()>,
}

const WIN32_OPS: CoveringRouteOps = CoveringRouteOps {
    add: route_add,
    delete: delete_covering_route,
};

/// Operations the connection watchdog uses to verify the connection while
/// it is up. The Win32 wrappers are used in production; tests substitute
/// stubs to simulate a vanished adapter or a leaked route without touching
/// the system.
#[derive(Clone, Copy)]
pub struct WatchdogOps {
    /// Ok when the adapter exists and is up; Err when it is gone or down.
    adapter_up: fn(NET_LUID_LH) -> Result<()>,
    /// Interface the stack would pick for a destination, as an LUID.
    best_route: fn(IpAddr) -> Result<NET_LUID_LH>,
}

pub const WIN32_WATCHDOG_OPS: WatchdogOps = WatchdogOps {
    adapter_up: adapter_is_up,
    best_route: best_route_luid,
};

/// Handle returned by [`apply`]; dropping it reverses everything, using the
/// state file as the source of truth. A process that dies without dropping
/// leaves the state file behind, so the next start restores from it.
pub struct RouteGuard {
    state_path: PathBuf,
    cfg: RouteConfig,
    state: AppliedState,
    ops: CoveringRouteOps,
}

/// Apply the full routing setup. Every change is persisted to the state
/// file before it is applied; any failure rolls back what was applied and
/// the file is left describing exactly what remains on the system.
pub fn apply(cfg: RouteConfig, state_path: &PathBuf) -> Result<RouteGuard> {
    // Resolve the adapter identity up front: the LUID scopes every route,
    // DNS and metric change (and its rollback) to this adapter.
    let adapter_luid = interface_luid(cfg.adapter_index)?;
    let adapter_guid = adapter_guid_string(cfg.adapter_index)?;
    apply_with_ops(cfg, state_path, adapter_luid, adapter_guid, WIN32_OPS)
}

/// apply() with the covering-route operations injectable, so tests can
/// force install failures without touching the real route table.
fn apply_with_ops(
    cfg: RouteConfig,
    state_path: &PathBuf,
    adapter_luid: NET_LUID_LH,
    adapter_guid: String,
    ops: CoveringRouteOps,
) -> Result<RouteGuard> {
    let mut guard = RouteGuard {
        state_path: state_path.clone(),
        cfg,
        ops,
        state: AppliedState {
            adapter_luid: Some(luid_value(adapter_luid)),
            adapter_guid: Some(adapter_guid),
            ..Default::default()
        },
    };
    guard.persist()?;
    if let Err(e) = guard.apply_all() {
        warn!("route setup failed ({e:#}); rolling back partial changes");
        guard.rollback_and_update_file();
        return Err(e);
    }
    Ok(guard)
}

/// Reverse every change recorded in the state file. Runs on clean
/// disconnect; on a crash the guard never drops and the next start calls
/// [`restore_from_state_file`] instead.
impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.rollback_and_update_file();
    }
}

/// Crash recovery: if a state file exists from a previous run, undo whatever
/// it recorded. Entries that fail to roll back stay in the file so the next
/// start retries them; a fully restored file is deleted. Call this at client
/// start, before applying any new state.
pub fn restore_from_state_file(state_path: &Path) {
    let contents = match std::fs::read_to_string(state_path) {
        Ok(c) => c,
        Err(_) => return, // no crash state: nothing to restore
    };
    // The file drives elevated restore operations, so it must be exactly the
    // file we wrote: no reparse points, and owned by SYSTEM or the
    // Administrators group. Anything else could have been planted by malware
    // running as the user and is refused (loudly) rather than restored.
    if let Err(e) = validate_state_file(state_path) {
        warn!(
            "refusing to restore from untrusted route state {}: {e:#}",
            state_path.display()
        );
        return;
    }
    warn!(
        "found leftover route state at {}; restoring system routing",
        state_path.display()
    );
    let state = match serde_json::from_str::<AppliedState>(&contents) {
        Ok(state) => state,
        Err(e) => {
            // A state file we can't parse must not be silently ignored: it
            // may describe live changes we can no longer reverse.
            warn!("could not parse route state file ({e}); leaving it for manual inspection");
            return;
        }
    };
    finish_restore(state_path, rollback_state(&state, &WIN32_OPS));
}

impl RouteGuard {
    fn persist(&self) -> Result<()> {
        persist_to(&self.state_path, &self.state)
    }

    /// Roll back everything recorded, then make the state file reflect what
    /// is actually left on the system: entries that failed to roll back stay
    /// recorded so the next start can finish the job; a fully rolled-back
    /// state deletes the file.
    fn rollback_and_update_file(&mut self) {
        let ops = self.ops;
        self.state = rollback_state(&self.state, &ops);
        if self.state.is_empty() {
            let _ = std::fs::remove_file(&self.state_path);
        } else {
            warn!(
                "route rollback incomplete; keeping {} so the next start can finish the restore",
                self.state_path.display()
            );
            if let Err(e) = self.persist() {
                warn!("failed to persist remaining route state: {e:#}");
            }
        }
    }

    fn adapter_luid(&self) -> NET_LUID_LH {
        luid_from_value(
            self.state
                .adapter_luid
                .expect("adapter LUID is resolved in apply"),
        )
    }

    fn adapter_guid(&self) -> Result<GUID> {
        let name = self
            .state
            .adapter_guid
            .as_deref()
            .context("adapter GUID missing")?;
        parse_adapter_guid(name)
    }

    /// LUID the connection watchdog monitors: the adapter every route, DNS
    /// and metric change (and its rollback) is scoped to.
    pub fn watchdog_luid(&self) -> NET_LUID_LH {
        self.adapter_luid()
    }

    fn apply_all(&mut self) -> Result<()> {
        let luid = self.adapter_luid();

        // 1. Pin the VPN server through the physical gateway, so the tunnel
        //    transport never loops through the tunnel itself. Skip this when
        //    the server is on this machine: pointing a loopback address at a
        //    physical gateway wedges the Windows loopback stack until reboot
        //    (observed in the smoke test with a localhost test server).
        if !self.cfg.server_ip.is_loopback() {
            let (gateway, physical_luid) = physical_gateway()?;
            let record = ServerRoute {
                server_ip: self.cfg.server_ip,
                gateway,
                interface_luid: luid_value(physical_luid),
            };
            self.state.server_route = Some(record.clone());
            self.persist()?;
            route_add_host(&record)?;
        }

        // 2. IPv4: 0.0.0.0/1 + 128.0.0.0/1 via the adapter (covers the whole
        //    space without touching the physical default route). On-link like
        //    IPv6: a route whose gateway is the adapter's own address passes
        //    CreateIpForwardEntry2 but fails next-hop resolution on the
        //    no-ARP point-to-point wintun interface, so lookups skip it and
        //    fall through to the physical default route.
        for (net, mask) in V4_COVERING {
            let record = CoveringRoute {
                prefix: net.into(),
                prefix_len: u32::from(mask).count_ones() as u8,
                next_hop: None,
            };
            self.state.routes.push(record.clone());
            self.persist()?;
            (self.ops.add)(&record, luid)?;
        }

        // 3. IPv6: ::/1 + 8000::/1 via the adapter (on-link: the tunnel
        //    interface is the next hop, so no gateway address is set). If
        //    the adapter has no IPv6, block nothing here — the leak check in
        //    the smoke test must confirm no ::/0 traffic escapes on the
        //    physical NIC.
        for prefix in V6_COVERING {
            let (addr, len) = parse_prefix6(prefix)?;
            let record = CoveringRoute {
                prefix: addr.into(),
                prefix_len: len,
                next_hop: None,
            };
            self.state.routes.push(record.clone());
            self.persist()?;
            (self.ops.add)(&record, luid)?;
        }

        // 4. DNS on the adapter, then force a winning interface metric so
        //    Windows does not keep asking the physical adapter's DNS.
        if !self.cfg.dns_servers.is_empty() {
            self.state.dns_servers = self.cfg.dns_servers.clone();
            self.persist()?;
            set_adapter_dns(self.adapter_guid()?, &self.cfg.dns_servers)?;
        }
        for family in [AF_INET, AF_INET6] {
            let Some(row) = get_ip_interface(luid, family)? else {
                // e.g. a v4-only adapter has no IPv6 interface row; there is
                // nothing to force or restore for that family.
                continue;
            };
            let record = InterfaceMetricState {
                family: family.0,
                use_automatic_metric: row.UseAutomaticMetric,
                metric: row.Metric,
            };
            self.state.interface_metrics.push(record);
            self.persist()?;
            force_interface_metric(row)?;
        }

        // 6. Leak check (fail closed): the route lookups a host will do must
        //    resolve via this adapter for both families. If they do not,
        //    traffic would escape via the physical interface — tear down
        //    rather than stay up with a silent leak.
        verify_routes_resolve_via_adapter(luid)?;

        info!(
            "tunnel routes active: {} covering routes via adapter '{}' (if {}), server {} {}",
            self.state.routes.len(),
            self.cfg.adapter_name,
            self.cfg.adapter_index,
            self.cfg.server_ip,
            self.state
                .server_route
                .as_ref()
                .map(|r| format!("pinned via {}", r.gateway))
                .unwrap_or_else(|| "(loopback, not pinned)".to_string())
        );
        Ok(())
    }
}

/// Persist after a crash-time restore: delete the file when nothing is left,
/// keep the remaining entries otherwise.
fn finish_restore(state_path: &Path, remaining: AppliedState) {
    if remaining.is_empty() {
        let _ = std::fs::remove_file(state_path);
    } else {
        warn!(
            "route restore incomplete; keeping {} for the next start",
            state_path.display()
        );
        if let Err(e) = persist_to(state_path, &remaining) {
            warn!("failed to persist remaining route state: {e:#}");
        }
    }
}

/// Write the state file atomically: write a temp file in the same directory
/// and rename it over the target (rename replaces atomically on Windows), so
/// a crash mid-persist can never leave a truncated state file behind.
fn persist_to(state_path: &Path, state: &AppliedState) -> Result<()> {
    let json = serde_json::to_string_pretty(state)?;
    let tmp = state_path.with_extension("json.tmp");
    std::fs::write(&tmp, json).with_context(|| format!("Failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, state_path).with_context(|| {
        format!(
            "Failed to rename {} over {}",
            tmp.display(),
            state_path.display()
        )
    })
}

// ---- state file location and trust -----------------------------------------

/// Path of the route state file: `%ProgramData%\rvpn\route_state.json`.
///
/// The state file drives elevated restore operations, so it must live where
/// unprivileged users cannot write: ProgramData is resolved through
/// SHGetKnownFolderPath (never the environment, which is user-controllable)
/// and the rvpn directory is created with a SYSTEM + Administrators-only
/// ACL. Creating that directory needs the elevation TUN mode already
/// requires, so a failure here is a hard error.
pub fn state_path() -> Result<PathBuf> {
    let dir = program_data()?.join("rvpn");
    ensure_state_dir(&dir)?;
    Ok(dir.join("route_state.json"))
}

/// Resolve FOLDERID_ProgramData via SHGetKnownFolderPath. The `ProgramData`
/// environment variable comes from the user environment and must not be
/// trusted by an elevated process.
fn program_data() -> Result<PathBuf> {
    let path = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
        .context("SHGetKnownFolderPath(FOLDERID_ProgramData) failed")?;
    // SAFETY: `path` is a valid NUL-terminated UTF-16 string allocated by
    // the shell call above; it is copied out and freed with CoTaskMemFree
    // immediately after.
    let resolved = unsafe { path.to_string() }.context("ProgramData path is not valid UTF-16")?;
    unsafe { CoTaskMemFree(Some(path.0 as *const c_void)) };
    Ok(PathBuf::from(resolved))
}

/// Create the state directory with a SYSTEM + Administrators-only ACL. The
/// SDDL string builds a protected DACL granting full access to SYSTEM and
/// the Administrators group only, inherited by everything created below
/// (including route_state.json); non-admin users get nothing.
fn ensure_state_dir(dir: &Path) -> Result<()> {
    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            w!("D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)"),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
    }
    .context("failed to build security descriptor for the state directory")?;
    // Frees the descriptor on every exit path below.
    let _guard = sec::LocalFreeGuard(descriptor.0);

    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: false.into(),
    };
    let wide = sec::wide_path(dir);
    match unsafe { CreateDirectoryW(PCWSTR::from_raw(wide.as_ptr()), Some(&attributes)) } {
        Ok(()) => return Ok(()),
        Err(e) if e.code() == HRESULT::from_win32(ERROR_ALREADY_EXISTS.0) => {}
        Err(e) => {
            return Err(e).with_context(|| format!("Failed to create {}", dir.display()));
        }
    }
    // The directory already existed: it must at least be a real directory,
    // not a junction planted to redirect our writes somewhere else.
    if sec::is_reparse_point(dir)? {
        bail!(
            "refusing to use {}: it is a reparse point/junction",
            dir.display()
        );
    }
    Ok(())
}

/// A state file is trusted only if it is a plain file (no reparse point:
/// junctions, symlinks or placeholder files could redirect the elevated
/// process elsewhere) and is owned by SYSTEM or the Administrators group —
/// matching the ACL the directory is created with.
fn validate_state_file(path: &Path) -> Result<()> {
    if sec::is_reparse_point(path)? {
        bail!("file is a reparse point/junction");
    }
    if !sec::owner_is_trusted(path, &sec::trusted_system_sids()?)? {
        bail!("file owner is neither SYSTEM nor Administrators");
    }
    Ok(())
}

/// Best-effort reversal of every recorded change, in reverse order of
/// application. Logs and continues on individual failures so one bad entry
/// cannot block the rest; returns the entries that could NOT be reversed
/// (an empty state means the system is fully restored).
fn rollback_state(state: &AppliedState, ops: &CoveringRouteOps) -> AppliedState {
    let mut remaining = AppliedState::default();
    let luid = state.adapter_luid.map(luid_from_value);

    // Interface metrics first (reverse order of application): restore exactly
    // the recorded rows on exactly the recorded interface. If the adapter is
    // gone its metric died with it and there is nothing to restore.
    if let Some(luid) = luid {
        for record in &state.interface_metrics {
            if let Err(e) = restore_interface_metric(luid, record) {
                warn!("failed to restore interface metric: {e:#}");
                remaining.interface_metrics.push(record.clone());
            }
        }
    } else if !state.interface_metrics.is_empty() {
        warn!("no adapter LUID recorded; cannot restore interface metric");
        remaining.interface_metrics = state.interface_metrics.clone();
    }

    if !state.dns_servers.is_empty() {
        match state
            .adapter_guid
            .as_deref()
            .and_then(|g| parse_adapter_guid(g).ok())
        {
            Some(guid) => {
                if let Err(e) = clear_adapter_dns(guid) {
                    warn!("failed to clear adapter DNS: {e:#}");
                    remaining.dns_servers = state.dns_servers.clone();
                }
            }
            None => {
                warn!("DNS was set but no adapter GUID recorded; cannot reset DNS");
                remaining.dns_servers = state.dns_servers.clone();
            }
        }
    }

    if let Some(luid) = luid {
        for record in state.routes.iter().rev() {
            if let Err(e) = (ops.delete)(luid, record) {
                warn!(
                    "failed to delete route {}/{}: {e:#}",
                    record.prefix, record.prefix_len
                );
                remaining.routes.push(record.clone());
            }
        }
    } else if !state.routes.is_empty() {
        warn!("no adapter LUID recorded; cannot delete covering routes");
        remaining.routes = state.routes.clone();
    }

    if let Some(record) = &state.server_route {
        let row = forward_row(
            luid_from_value(record.interface_luid),
            record.server_ip,
            32,
            Some(record.gateway.into()),
        );
        if let Err(e) = delete_route(&row) {
            warn!(
                "failed to delete server host route {}: {e:#}",
                record.server_ip
            );
            remaining.server_route = Some(record.clone());
        }
    }

    if !remaining.is_empty() {
        remaining.adapter_luid = state.adapter_luid;
        remaining.adapter_guid = state.adapter_guid.clone();
    }
    remaining
}

// ---- IP Helper wrappers ---------------------------------------------------

/// LUID of an interface index. The LUID is stable for the adapter's lifetime
/// and is never reused for a different adapter, unlike the index.
fn interface_luid(if_index: u32) -> Result<NET_LUID_LH> {
    let mut luid = NET_LUID_LH::default();
    let err = unsafe { ConvertInterfaceIndexToLuid(if_index, &mut luid) };
    check(err, "ConvertInterfaceIndexToLuid")?;
    Ok(luid)
}

fn luid_value(luid: NET_LUID_LH) -> u64 {
    // SAFETY: Value is the flat u64 view of the LUID union.
    unsafe { luid.Value }
}

fn luid_from_value(value: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: value }
}

/// Physical default gateway of the machine and the interface it is reached
/// through, found by asking the stack for the best route to a public IPv4
/// address (a lookup only — nothing is sent to that address).
fn physical_gateway() -> Result<(Ipv4Addr, NET_LUID_LH)> {
    let dest = sockaddr_inet(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    let err = unsafe { GetBestRoute2(None, 0, None, &dest, 0, &mut route, &mut source) };
    check(err, "GetBestRoute2")?;
    // SAFETY: the lookup target is IPv4, so the best route's next hop is an
    // IPv4 address and the Ipv4 union member is the initialized one.
    let gateway = unsafe { Ipv4Addr::from(u32::from_be(route.NextHop.Ipv4.sin_addr.S_un.S_addr)) };
    if gateway.is_unspecified() {
        bail!("no physical default gateway found");
    }
    Ok((gateway, route.InterfaceLuid))
}

/// Interface the stack would pick for `dest`, as an LUID. GetBestRoute2 is
/// a pure route-table lookup: nothing is sent to the address.
fn best_route_luid(dest: IpAddr) -> Result<NET_LUID_LH> {
    let dest_sa = sockaddr_inet(dest);
    let mut route = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    let err = unsafe { GetBestRoute2(None, 0, None, &dest_sa, 0, &mut route, &mut source) };
    check(err, "GetBestRoute2")?;
    Ok(route.InterfaceLuid)
}

/// Whether a best-route lookup returned the adapter interface, compared by
/// LUID: GetBestRoute2 output rows carry InterfaceLuid, and unlike the
/// interface index it is never reused for a different adapter.
fn luid_matches(best: NET_LUID_LH, expected: NET_LUID_LH) -> bool {
    luid_value(best) == luid_value(expected)
}

// ---- tunnel address DAD ---------------------------------------------------

/// Read/write access to a unicast-address row, injectable for tests.
#[derive(Clone, Copy)]
struct DadOps {
    get: fn(Ipv4Addr) -> Result<MIB_UNICASTIPADDRESS_ROW>,
    set: fn(&MIB_UNICASTIPADDRESS_ROW) -> Result<()>,
}

const WIN32_DAD_OPS: DadOps = DadOps {
    get: get_unicast_address_row,
    set: set_unicast_address_row,
};

/// Current unicast-address row for `addr`. The row is keyed by address: an
/// IPv4 address exists on exactly one interface, and the returned row names
/// it (InterfaceLuid).
fn get_unicast_address_row(addr: Ipv4Addr) -> Result<MIB_UNICASTIPADDRESS_ROW> {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    row.Address = sockaddr_inet(IpAddr::V4(addr));
    let err = unsafe { GetUnicastIpAddressEntry(&mut row) };
    check(err, "GetUnicastIpAddressEntry")?;
    Ok(row)
}

fn set_unicast_address_row(row: &MIB_UNICASTIPADDRESS_ROW) -> Result<()> {
    let err = unsafe { SetUnicastIpAddressEntry(row) };
    check(err, "SetUnicastIpAddressEntry")
}

/// How long to wait between GetUnicastIpAddressEntry polls while the
/// netsh-assigned address row materializes.
const ADDRESS_WAIT_POLL: Duration = Duration::from_millis(250);

/// Poll access to the unicast row, injectable for tests (sleep is stubbed so
/// the timeout path does not take real time).
#[derive(Clone, Copy)]
struct AddressWaitOps {
    get: fn(Ipv4Addr) -> Result<MIB_UNICASTIPADDRESS_ROW>,
    sleep: fn(Duration),
}

const WIN32_ADDRESS_WAIT_OPS: AddressWaitOps = AddressWaitOps {
    get: get_unicast_address_row,
    sleep: std::thread::sleep,
};

/// Whether an error from GetUnicastIpAddressEntry means "the address row
/// does not exist (yet)": ERROR_FILE_NOT_FOUND (2) while the netsh-assigned
/// row has not materialized in the active store. Anything else is a real
/// failure and must not be retried.
fn is_address_row_absent(e: &anyhow::Error) -> bool {
    e.downcast_ref::<windows::core::Error>()
        .is_some_and(|e| e.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0))
}

/// Wait until the tunnel address exists in the unicast-address table.
///
/// tun-rs assigns the address by shelling out to `netsh interface ipv4 set
/// address` inside build_sync; netsh returns synchronously, but the unicast
/// row materializes in the active store seconds later, so every check right
/// after adapter creation sees ERROR_FILE_NOT_FOUND. Polls every
/// ADDRESS_WAIT_POLL until the row appears or `timeout` elapses. Only the
/// not-found error is retried; any other failure bails immediately.
pub fn wait_for_unicast_address(
    addr: Ipv4Addr,
    timeout: Duration,
) -> Result<MIB_UNICASTIPADDRESS_ROW> {
    let start = Instant::now();
    let row = wait_for_unicast_address_with_ops(addr, timeout, &WIN32_ADDRESS_WAIT_OPS)?;
    info!(
        "tunnel address {addr} present in the unicast table after {:?}",
        start.elapsed()
    );
    Ok(row)
}

fn wait_for_unicast_address_with_ops(
    addr: Ipv4Addr,
    timeout: Duration,
    ops: &AddressWaitOps,
) -> Result<MIB_UNICASTIPADDRESS_ROW> {
    let start = Instant::now();
    loop {
        match (ops.get)(addr) {
            Ok(row) => return Ok(row),
            Err(e) if is_address_row_absent(&e) => {
                if start.elapsed() >= timeout {
                    return Err(e).with_context(|| {
                        format!(
                            "tunnel address {addr} did not appear in the unicast \
                             table within {}s",
                            timeout.as_secs()
                        )
                    });
                }
                (ops.sleep)(ADDRESS_WAIT_POLL);
            }
            Err(e) => return Err(e),
        }
    }
}

/// What force_dad_preferred did with the address's DAD state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DadForce {
    /// Already Preferred: nothing to change.
    AlreadyPreferred,
    /// Was mid-DAD (e.g. Tentative); forced to Preferred.
    Forced,
}

/// Force the tunnel address out of duplicate address detection into
/// Preferred. tun-rs assigns the address via netsh without touching
/// DadState, so once the row exists (see wait_for_unicast_address — the row
/// itself materializes seconds after netsh returns) it is still Tentative,
/// and source-address selection fails: GetBestRoute2 then errors with
/// ERROR_NETWORK_UNREACHABLE even though the covering routes exist. DAD is
/// meaningless on a point-to-point tunnel interface (wireguard-windows sets
/// IpDadStatePreferred when adding the address for the same reason). A
/// Duplicate report is a real address conflict and fails closed instead of
/// being papered over.
///
/// Callers must run wait_for_unicast_address first: this looks the row up
/// and fails with ERROR_FILE_NOT_FOUND while it has not materialized.
///
/// Deliberately NOT part of TunDevice::create_with_ip: the route_diag_probe
/// test calls create_with_ip and must observe the raw tun-rs DAD behavior.
pub fn force_dad_preferred(adapter_index: u32, addr: Ipv4Addr) -> Result<()> {
    let luid = interface_luid(adapter_index)?;
    match force_dad_preferred_with_ops(luid, addr, WIN32_DAD_OPS)? {
        DadForce::AlreadyPreferred => {
            info!("tunnel address {addr} already usable (DAD state Preferred)")
        }
        DadForce::Forced => info!(
            "tunnel address {addr} forced past duplicate address detection \
             (DAD is meaningless on the point-to-point tunnel interface)"
        ),
    }
    Ok(())
}

fn force_dad_preferred_with_ops(
    adapter_luid: NET_LUID_LH,
    addr: Ipv4Addr,
    ops: DadOps,
) -> Result<DadForce> {
    let mut row = (ops.get)(addr)?;
    if !luid_matches(row.InterfaceLuid, adapter_luid) {
        bail!(
            "tunnel address {addr} lives on a different interface (luid {:#x}); \
             refusing to touch it",
            unsafe { row.InterfaceLuid.Value },
        );
    }
    if row.DadState == IpDadStatePreferred {
        return Ok(DadForce::AlreadyPreferred);
    }
    if row.DadState == IpDadStateDuplicate {
        error!("tunnel address {addr} conflicts with another host (DAD duplicate)");
        bail!("tunnel address {addr} is a DAD duplicate; refusing to connect");
    }
    row.DadState = IpDadStatePreferred;
    (ops.set)(&row)?;
    Ok(DadForce::Forced)
}

/// Fail-closed leak check run after the covering routes are installed: the
/// route lookup for one representative address per family must resolve via
/// the wintun adapter. If Windows would actually use any other interface,
/// traffic escapes via the physical NIC — tear down and report not
/// connected instead of staying up with a silent leak.
fn verify_routes_resolve_via_adapter(luid: NET_LUID_LH) -> Result<()> {
    for dest in [IpAddr::V4(VERIFY_V4), IpAddr::V6(VERIFY_V6)] {
        let best = match best_route_luid(dest) {
            Ok(best) => best,
            Err(err) => {
                // A lookup error (e.g. ERROR_NETWORK_UNREACHABLE when
                // next-hop resolution fails on the no-ARP interface) leaks
                // just as surely as a wrong LUID: dump before failing.
                dump_route_leak(dest, luid);
                return Err(err).with_context(|| format!("route lookup for {dest} failed"));
            }
        };
        if !luid_matches(best, luid) {
            dump_route_leak(dest, luid);
            bail!(
                "route lookup for {dest} does not resolve via the tunnel adapter; \
                 refusing to connect with a leaking route table"
            );
        }
    }
    Ok(())
}

/// The adapter exists and is operationally up, checked by LUID
/// (GetIfEntry2), never by name — names can be reused by a replacement
/// adapter. A lookup failure means the adapter is gone.
fn adapter_is_up(luid: NET_LUID_LH) -> Result<()> {
    let mut row = MIB_IF_ROW2 {
        InterfaceLuid: luid,
        ..Default::default()
    };
    let err = unsafe { GetIfEntry2(&mut row) };
    check(err, "GetIfEntry2")?;
    if row.OperStatus != IfOperStatusUp {
        bail!("adapter is not up (OperStatus {})", row.OperStatus.0);
    }
    Ok(())
}

/// One watchdog iteration: the adapter must still be up and both route
/// lookups must still resolve via it. The error names exactly which check
/// failed (adapter gone or down / route leaked), so the caller can report
/// loudly.
fn watchdog_check(luid: NET_LUID_LH, ops: &WatchdogOps) -> Result<()> {
    (ops.adapter_up)(luid).context("wintun adapter check failed")?;
    for dest in [IpAddr::V4(VERIFY_V4), IpAddr::V6(VERIFY_V6)] {
        let best = match (ops.best_route)(dest) {
            Ok(best) => best,
            Err(err) => {
                // Same as the mismatch below: a lookup error means traffic
                // would not take the tunnel — dump before failing.
                dump_route_leak(dest, luid);
                return Err(err).with_context(|| format!("route lookup for {dest} failed"));
            }
        };
        if !luid_matches(best, luid) {
            dump_route_leak(dest, luid);
            bail!("route lookup for {dest} no longer resolves via the tunnel adapter");
        }
    }
    Ok(())
}

/// Connection watchdog: every WATCHDOG_INTERVAL re-verify the adapter and
/// covering routes while connected. Never completes while the checks pass —
/// the caller cancels it during teardown, before the route guard rolls
/// anything back, so it cannot report spuriously. The first failed check is
/// logged and returned, never self-healed: the caller tears the session
/// down.
pub async fn watchdog(luid: NET_LUID_LH, ops: WatchdogOps) -> Result<()> {
    let mut interval = tokio::time::interval(WATCHDOG_INTERVAL);
    loop {
        interval.tick().await;
        if let Err(e) = watchdog_check(luid, &ops) {
            error!("connection watchdog: {e:#}; treating the connection as lost");
            return Err(e.context("connection watchdog"));
        }
    }
}

/// Dump route-leak diagnostics when RVPN_ROUTE_DEBUG=1; a no-op otherwise.
/// Called on the fail-closed verification path and the watchdog's
/// route-leak path, both when the lookup resolves via the wrong interface
/// and when the lookup itself errors (e.g. ERROR_NETWORK_UNREACHABLE); the
/// callers still bail and roll back, so the dump only explains the failure.
fn dump_route_leak(dest: IpAddr, expected_luid: NET_LUID_LH) {
    if std::env::var_os(ROUTE_DEBUG_ENV).is_some() {
        diagnose_route_leak(dest, expected_luid);
    }
}

/// Read-only diagnostics for a route leak: why the lookup for `dest` did
/// not resolve via the tunnel adapter. Dumps the winning route, the
/// adapter's interface state and per-family metrics, and every
/// forward-table row whose prefix contains the destination (the
/// longest-prefix candidates), which shows whether our /1 rows are present
/// and how they differ from what wins. Never mutates state.
fn diagnose_route_leak(dest: IpAddr, expected_luid: NET_LUID_LH) {
    let family = match dest {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    };

    // The route Windows will actually use for the destination.
    let dest_sa = sockaddr_inet(dest);
    let mut best = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    let err = unsafe { GetBestRoute2(None, 0, None, &dest_sa, 0, &mut best, &mut source) };
    if err == ERROR_SUCCESS {
        // The row carries the LUID; resolve the index's LUID too, to catch
        // an index/LUID mismatch on a recycled interface.
        let mut index_luid = NET_LUID_LH::default();
        let luid_err = unsafe { ConvertInterfaceIndexToLuid(best.InterfaceIndex, &mut index_luid) };
        warn!(
            "route debug: best route for {dest}: if_index={} luid={:#x} (index->luid {}{:#x}) \
             next_hop={} metric={} protocol={} valid_lifetime={} age={}",
            best.InterfaceIndex,
            unsafe { best.InterfaceLuid.Value },
            if luid_err == ERROR_SUCCESS {
                ""
            } else {
                "(failed) "
            },
            unsafe { index_luid.Value },
            sockaddr_display(&best.NextHop),
            best.Metric,
            best.Protocol.0,
            best.ValidLifetime,
            best.Age,
        );
    } else {
        warn!(
            "route debug: GetBestRoute2 for {dest} failed: Win32 error {}",
            err.0
        );
    }

    // Adapter state: up/down, type, media connection.
    let mut if_row = MIB_IF_ROW2 {
        InterfaceLuid: expected_luid,
        ..Default::default()
    };
    let err = unsafe { GetIfEntry2(&mut if_row) };
    if err == ERROR_SUCCESS {
        warn!(
            "route debug: adapter state: oper_status={} if_type={} media_connect_state={}",
            if_row.OperStatus.0, if_row.Type, if_row.MediaConnectState.0,
        );
    } else {
        warn!(
            "route debug: GetIfEntry2 for the adapter failed: Win32 error {}",
            err.0
        );
    }
    for fam in [AF_INET, AF_INET6] {
        match get_ip_interface(expected_luid, fam) {
            Ok(Some(row)) => warn!(
                "route debug: adapter ip-interface (family {}): metric={} automatic_metric={}",
                fam.0, row.Metric, row.UseAutomaticMetric
            ),
            Ok(None) => warn!(
                "route debug: adapter has no ip-interface row for family {}",
                fam.0
            ),
            Err(e) => warn!(
                "route debug: GetIpInterfaceEntry for family {} failed: {e:#}",
                fam.0
            ),
        }
    }

    dump_covering_rows(dest, family, expected_luid);
}

/// All forward-table rows whose destination prefix contains `dest` (the
/// longest-prefix candidates for it), longest first. Read-only.
fn dump_covering_rows(dest: IpAddr, family: ADDRESS_FAMILY, expected_luid: NET_LUID_LH) {
    let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    let err = unsafe { GetIpForwardTable2(family, &mut table) };
    if err != ERROR_SUCCESS {
        warn!(
            "route debug: GetIpForwardTable2 failed: Win32 error {}",
            err.0
        );
        return;
    }
    // Frees the table on every exit path.
    let _guard = MibTableGuard(table);
    // SAFETY: GetIpForwardTable2 returned a valid table of NumEntries
    // contiguous rows starting at Table.
    let rows = unsafe {
        let num = (*table).NumEntries as usize;
        std::slice::from_raw_parts((*table).Table.as_ptr(), num)
    };
    let mut candidates: Vec<&MIB_IPFORWARD_ROW2> = rows
        .iter()
        .filter(|row| prefix_contains(&row.DestinationPrefix, dest))
        .collect();
    candidates.sort_by_key(|row| std::cmp::Reverse(row.DestinationPrefix.PrefixLength));
    warn!(
        "route debug: {} forward-table row(s) contain {dest} (expected adapter luid {:#x}):",
        candidates.len(),
        unsafe { expected_luid.Value },
    );
    for row in candidates {
        warn!(
            "route debug:   {}/{} via {} luid={:#x} if_index={} metric={} protocol={} \
             valid_lifetime={} preferred_lifetime={} age={} loopback={} publish={} immortal={}",
            sockaddr_display(&row.DestinationPrefix.Prefix),
            row.DestinationPrefix.PrefixLength,
            sockaddr_display(&row.NextHop),
            unsafe { row.InterfaceLuid.Value },
            row.InterfaceIndex,
            row.Metric,
            row.Protocol.0,
            row.ValidLifetime,
            row.PreferredLifetime,
            row.Age,
            row.Loopback,
            row.Publish,
            row.Immortal,
        );
    }
}

/// Frees a MIB table allocated by GetIpForwardTable2 on every exit path.
struct MibTableGuard(*mut MIB_IPFORWARD_TABLE2);

impl Drop for MibTableGuard {
    fn drop(&mut self) {
        unsafe { FreeMibTable(self.0 as *const std::ffi::c_void) };
    }
}

/// Human-readable rendering of a SOCKADDR_INET for diagnostics.
fn sockaddr_display(sa: &SOCKADDR_INET) -> String {
    // SAFETY: the family field selects the initialized union member.
    let family = unsafe { sa.si_family };
    if family == AF_INET {
        // SAFETY: the family is IPv4, so the Ipv4 member is initialized.
        unsafe { Ipv4Addr::from(u32::from_be(sa.Ipv4.sin_addr.S_un.S_addr)).to_string() }
    } else if family == AF_INET6 {
        // SAFETY: the family is IPv6, so the Ipv6 member is initialized.
        unsafe { Ipv6Addr::from(sa.Ipv6.sin6_addr.u.Byte).to_string() }
    } else {
        format!("(family {})", family.0)
    }
}

/// Whether the forward-row prefix contains `dest` (making the row a
/// longest-prefix candidate for the destination).
fn prefix_contains(prefix: &IP_ADDRESS_PREFIX, dest: IpAddr) -> bool {
    let len = prefix.PrefixLength as u32;
    // SAFETY: the family field selects the initialized union member; the
    // matching union member is read in each branch.
    let family = unsafe { prefix.Prefix.si_family };
    match (family, dest) {
        (AF_INET, IpAddr::V4(dest_v4)) => {
            if len > 32 {
                return false;
            }
            let prefix_bits = u32::from_be(unsafe { prefix.Prefix.Ipv4.sin_addr.S_un.S_addr });
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            (u32::from(dest_v4) & mask) == (prefix_bits & mask)
        }
        (AF_INET6, IpAddr::V6(dest_v6)) => {
            if len > 128 {
                return false;
            }
            let prefix_bytes = unsafe { prefix.Prefix.Ipv6.sin6_addr.u.Byte };
            let dest_bytes = dest_v6.octets();
            let full_bytes = (len / 8) as usize;
            if prefix_bytes[..full_bytes] != dest_bytes[..full_bytes] {
                return false;
            }
            let rem = len % 8;
            rem == 0
                || (prefix_bytes[full_bytes] >> (8 - rem)) == (dest_bytes[full_bytes] >> (8 - rem))
        }
        _ => false,
    }
}

/// Build the forward row identifying one of our routes. The interface LUID
/// is always set: creates AND deletes are scoped to the adapter we own, so a
/// rollback can never remove another VPN's covering routes.
fn forward_row(
    luid: NET_LUID_LH,
    prefix: IpAddr,
    prefix_len: u8,
    next_hop: Option<IpAddr>,
) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2 {
        InterfaceLuid: luid,
        DestinationPrefix: IP_ADDRESS_PREFIX {
            Prefix: sockaddr_inet(prefix),
            PrefixLength: prefix_len,
        },
        Metric: 1,
        Protocol: MIB_IPPROTO_NETMGMT,
        // Default::default() zeroes the lifetimes; a zero ValidLifetime
        // makes the route expire immediately, so lookups skip it and fall
        // through to the physical default route. netsh-created routes use
        // 0xffffffff = infinite.
        ValidLifetime: u32::MAX,
        PreferredLifetime: u32::MAX,
        ..Default::default()
    };
    match next_hop {
        Some(hop) => row.NextHop = sockaddr_inet(hop),
        None => {
            // On-link route: the next hop is the unspecified address of the
            // route's own family, meaning "the interface itself".
            row.NextHop = match prefix {
                IpAddr::V4(_) => sockaddr_inet(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                IpAddr::V6(_) => sockaddr_inet(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            };
        }
    }
    row
}

fn route_add_host(record: &ServerRoute) -> Result<()> {
    let row = forward_row(
        luid_from_value(record.interface_luid),
        record.server_ip,
        32,
        Some(record.gateway.into()),
    );
    create_route(&row)
}

fn route_add(record: &CoveringRoute, luid: NET_LUID_LH) -> Result<()> {
    create_route(&forward_row(
        luid,
        record.prefix,
        record.prefix_len,
        record.next_hop,
    ))
}

/// Delete one recorded covering route. The recorded next hop is replayed
/// verbatim: legacy state files (pre on-link change) recorded the adapter
/// address, and the delete must match the row that was created.
fn delete_covering_route(luid: NET_LUID_LH, record: &CoveringRoute) -> Result<()> {
    delete_route(&forward_row(
        luid,
        record.prefix,
        record.prefix_len,
        record.next_hop,
    ))
}

fn create_route(row: &MIB_IPFORWARD_ROW2) -> Result<()> {
    let err = unsafe { CreateIpForwardEntry2(row) };
    if err == ERROR_OBJECT_ALREADY_EXISTS {
        // Already there (e.g. replayed intent): the desired state holds.
        return Ok(());
    }
    check(err, "CreateIpForwardEntry2")
}

fn delete_route(row: &MIB_IPFORWARD_ROW2) -> Result<()> {
    let err = unsafe { DeleteIpForwardEntry2(row) };
    if err == ERROR_NOT_FOUND {
        // Never added (or already gone): deleting is a no-op, not an error.
        return Ok(());
    }
    check(err, "DeleteIpForwardEntry2")
}

/// Adapter GUID ("{...}" string) for an interface index, resolved through
/// GetAdaptersAddresses: SetInterfaceDnsSettings identifies interfaces by
/// GUID, not by LUID or index.
fn adapter_guid_string(if_index: u32) -> Result<String> {
    // Only IfIndex and AdapterName are needed; skip everything else.
    let flags = GET_ADAPTERS_ADDRESSES_FLAGS(
        GAA_FLAG_SKIP_UNICAST.0
            | GAA_FLAG_SKIP_ANYCAST.0
            | GAA_FLAG_SKIP_MULTICAST.0
            | GAA_FLAG_SKIP_DNS_SERVER.0,
    );
    // First call only sizes the buffer (expected to report BUFFER_OVERFLOW).
    let mut size: u32 = 0;
    let err = unsafe { GetAdaptersAddresses(0, flags, None, None, &mut size) };
    if err != ERROR_SUCCESS.0 && err != ERROR_BUFFER_OVERFLOW.0 {
        check(WIN32_ERROR(err), "GetAdaptersAddresses")?;
    }
    // Backed by u64 elements so the buffer is aligned for the struct cast
    // below; GetAdaptersAddresses fills exactly `size` bytes.
    let mut buf = vec![0u64; size as usize / 8 + 1];
    let err = unsafe {
        GetAdaptersAddresses(
            0,
            flags,
            None,
            Some(buf.as_mut_ptr() as *mut IP_ADAPTER_ADDRESSES_LH),
            &mut size,
        )
    };
    check(WIN32_ERROR(err), "GetAdaptersAddresses")?;

    let mut current = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    // SAFETY: `buf` holds the linked list of IP_ADAPTER_ADDRESSES_LH filled
    // by the call above; each node is valid until `Next` is null.
    while !current.is_null() {
        let adapter = unsafe { &*current };
        // SAFETY: the Length/IfIndex union member is always populated by
        // GetAdaptersAddresses.
        let adapter_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        if adapter_index == if_index {
            let name = unsafe { adapter.AdapterName.to_string() }
                .context("adapter name is not valid UTF-8")?;
            return Ok(name);
        }
        current = adapter.Next;
    }
    bail!("no adapter with interface index {if_index}")
}

/// Parse the "{...}" adapter name from GetAdaptersAddresses into a GUID.
fn parse_adapter_guid(name: &str) -> Result<GUID> {
    let trimmed = name
        .strip_prefix('{')
        .and_then(|n| n.strip_suffix('}'))
        .unwrap_or(name);
    GUID::try_from(trimmed).map_err(|e| anyhow::anyhow!("invalid adapter GUID '{name}': {e}"))
}

/// Point the adapter's DNS at the given resolvers (queried through the
/// tunnel). Takes the whole list in one call, mixed families included.
fn set_adapter_dns(guid: GUID, servers: &[IpAddr]) -> Result<()> {
    let joined = servers
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",");
    set_adapter_dns_raw(guid, &joined, "SetInterfaceDnsSettings")
}

/// Clear DNS on exactly the interface we configured: an empty NameServer
/// list hands the interface back to DHCP.
fn clear_adapter_dns(guid: GUID) -> Result<()> {
    set_adapter_dns_raw(guid, "", "SetInterfaceDnsSettings (clear)")
}

fn set_adapter_dns_raw(guid: GUID, name_server: &str, op: &str) -> Result<()> {
    let name_server = wide(name_server);
    let settings = DNS_INTERFACE_SETTINGS {
        Version: DNS_INTERFACE_SETTINGS_VERSION1,
        Flags: u64::from(DNS_SETTING_NAMESERVER),
        NameServer: PWSTR::from_raw(name_server.as_ptr() as *mut u16),
        ..Default::default()
    };
    let err = unsafe { SetInterfaceDnsSettings(guid, &settings) };
    check(err, op)
}

/// Current interface row for one address family, or None when the adapter
/// has no such family (e.g. no IPv6 row on a v4-only adapter).
fn get_ip_interface(
    luid: NET_LUID_LH,
    family: ADDRESS_FAMILY,
) -> Result<Option<MIB_IPINTERFACE_ROW>> {
    let mut row = MIB_IPINTERFACE_ROW {
        Family: family,
        InterfaceLuid: luid,
        ..Default::default()
    };
    let err = unsafe { GetIpInterfaceEntry(&mut row) };
    if err == ERROR_NOT_FOUND {
        return Ok(None);
    }
    check(err, "GetIpInterfaceEntry")?;
    Ok(Some(row))
}

/// Force metric 1 on the adapter row so wintun wins DNS. The row's previous
/// state must already have been recorded by the caller.
fn force_interface_metric(row: MIB_IPINTERFACE_ROW) -> Result<()> {
    // Only rewrite the row when it actually differs: fewer changes to roll
    // back, and no churn on adapters already configured this way.
    if !row.UseAutomaticMetric && row.Metric == 1 {
        return Ok(());
    }
    let mut set_row = row;
    // Get-filled NlMtu/SitePrefixLength read as change requests to
    // SetIpInterfaceEntry, and the wintun virtual NIC (IfType 53) rejects the
    // implied MTU update with ERROR_INVALID_PARAMETER. Zeroing both asks for
    // no change — wireguard-nt's example.c zeroes/controls the same fields.
    set_row.NlMtu = 0;
    set_row.SitePrefixLength = 0;
    set_row.UseAutomaticMetric = false;
    set_row.Metric = 1;
    set_ip_interface(set_row, &row)
}

/// Restore the recorded per-family metric state on exactly the recorded
/// interface (by LUID). Every other interface is left untouched.
fn restore_interface_metric(luid: NET_LUID_LH, record: &InterfaceMetricState) -> Result<()> {
    let Some(row) = get_ip_interface(luid, ADDRESS_FAMILY(record.family))? else {
        // The adapter (or the family on it) is gone; its metric died with it.
        return Ok(());
    };
    let mut set_row = row;
    // Same treatment as force_interface_metric: leave NlMtu/SitePrefixLength
    // alone or Set fails with ERROR_INVALID_PARAMETER on wintun.
    set_row.NlMtu = 0;
    set_row.SitePrefixLength = 0;
    set_row.UseAutomaticMetric = record.use_automatic_metric;
    set_row.Metric = record.metric;
    set_ip_interface(set_row, &row)
}

/// SetIpInterfaceEntry with failure diagnostics: when RVPN_IFMETRIC_DEBUG
/// is set, a failure dumps the Get-filled row and probes which row variants
/// this interface accepts before the error is reported.
fn set_ip_interface(mut set_row: MIB_IPINTERFACE_ROW, get_row: &MIB_IPINTERFACE_ROW) -> Result<()> {
    let err = unsafe { SetIpInterfaceEntry(&mut set_row) };
    if err != ERROR_SUCCESS && std::env::var_os(IFMETRIC_DEBUG_ENV).is_some() {
        diagnose_set_failure(get_row);
    }
    check(err, "SetIpInterfaceEntry")
}

/// Diagnostic probe for SetIpInterfaceEntry failures (RVPN_IFMETRIC_DEBUG):
/// dump every field of the Get-filled row, then probe which row variants
/// SetIpInterfaceEntry accepts for this interface. Smoke-run evidence: even
/// the unmodified Get row fails with ERROR_INVALID_PARAMETER on wintun.
fn diagnose_set_failure(get_row: &MIB_IPINTERFACE_ROW) {
    warn!(
        "ifmetric debug: Get-filled MIB_IPINTERFACE_ROW fields: \
         Family={} InterfaceLuid={:#x} InterfaceIndex={} MaxReassemblySize={} \
         InterfaceIdentifier={} MinRouterAdvertisementInterval={} \
         MaxRouterAdvertisementInterval={} AdvertisingEnabled={} ForwardingEnabled={} \
         WeakHostSend={} WeakHostReceive={} UseAutomaticMetric={} \
         UseNeighborUnreachabilityDetection={} ManagedAddressConfigurationSupported={} \
         OtherStatefulConfigurationSupported={} AdvertiseDefaultRoute={} \
         RouterDiscoveryBehavior={} DadTransmits={} BaseReachableTime={} RetransmitTime={} \
         PathMtuDiscoveryTimeout={} LinkLocalAddressBehavior={} LinkLocalAddressTimeout={} \
         ZoneIndices={:?} SitePrefixLength={} Metric={} NlMtu={} Connected={} \
         SupportsWakeUpPatterns={} SupportsNeighborDiscovery={} SupportsRouterDiscovery={} \
         ReachableTime={} TransmitOffload={:#x} ReceiveOffload={:#x} DisableDefaultRoutes={}",
        get_row.Family.0,
        unsafe { get_row.InterfaceLuid.Value },
        get_row.InterfaceIndex,
        get_row.MaxReassemblySize,
        get_row.InterfaceIdentifier,
        get_row.MinRouterAdvertisementInterval,
        get_row.MaxRouterAdvertisementInterval,
        get_row.AdvertisingEnabled,
        get_row.ForwardingEnabled,
        get_row.WeakHostSend,
        get_row.WeakHostReceive,
        get_row.UseAutomaticMetric,
        get_row.UseNeighborUnreachabilityDetection,
        get_row.ManagedAddressConfigurationSupported,
        get_row.OtherStatefulConfigurationSupported,
        get_row.AdvertiseDefaultRoute,
        get_row.RouterDiscoveryBehavior.0,
        get_row.DadTransmits,
        get_row.BaseReachableTime,
        get_row.RetransmitTime,
        get_row.PathMtuDiscoveryTimeout,
        get_row.LinkLocalAddressBehavior.0,
        get_row.LinkLocalAddressTimeout,
        get_row.ZoneIndices,
        get_row.SitePrefixLength,
        get_row.Metric,
        get_row.NlMtu,
        get_row.Connected,
        get_row.SupportsWakeUpPatterns,
        get_row.SupportsNeighborDiscovery,
        get_row.SupportsRouterDiscovery,
        get_row.ReachableTime,
        get_row.TransmitOffload._bitfield,
        get_row.ReceiveOffload._bitfield,
        get_row.DisableDefaultRoutes,
    );

    probe_set("a) unmodified Get row", get_row);

    let mut no_mtu = *get_row;
    no_mtu.NlMtu = 0;
    probe_set("b) Get row with NlMtu=0", &no_mtu);

    let mut minimal = MIB_IPINTERFACE_ROW::default();
    unsafe { InitializeIpInterfaceEntry(&mut minimal) };
    minimal.Family = get_row.Family;
    minimal.InterfaceLuid = get_row.InterfaceLuid;
    minimal.UseAutomaticMetric = get_row.UseAutomaticMetric;
    minimal.Metric = get_row.Metric;
    probe_set("c) InitializeIpInterfaceEntry row", &minimal);

    let mut no_index = *get_row;
    no_index.InterfaceIndex = 0;
    probe_set("d) Get row with InterfaceIndex=0", &no_index);
}

/// Run one probe variant and log whether SetIpInterfaceEntry accepts it.
fn probe_set(label: &str, row: &MIB_IPINTERFACE_ROW) {
    let mut row = *row;
    let err = unsafe { SetIpInterfaceEntry(&mut row) };
    if err == ERROR_SUCCESS {
        warn!("ifmetric debug: probe {label}: SUCCESS");
    } else {
        warn!("ifmetric debug: probe {label}: Win32 error {}", err.0);
    }
}

fn sockaddr_inet(addr: IpAddr) -> SOCKADDR_INET {
    let mut sa = SOCKADDR_INET::default();
    match addr {
        IpAddr::V4(v4) => {
            sa.Ipv4 = SOCKADDR_IN {
                sin_family: AF_INET,
                sin_addr: IN_ADDR {
                    // S_addr is stored in network byte order; to_be converts
                    // the host-order bit pattern on little-endian Windows.
                    S_un: IN_ADDR_0 {
                        S_addr: u32::from(v4).to_be(),
                    },
                },
                ..Default::default()
            };
        }
        IpAddr::V6(v6) => {
            sa.Ipv6 = SOCKADDR_IN6 {
                sin6_family: AF_INET6,
                sin6_addr: IN6_ADDR {
                    u: IN6_ADDR_0 { Byte: v6.octets() },
                },
                ..Default::default()
            };
        }
    }
    sa
}

/// Parse a "addr/len" IPv6 prefix string (V6_COVERING entries).
fn parse_prefix6(prefix: &str) -> Result<(Ipv6Addr, u8)> {
    let (addr, len) = prefix
        .split_once('/')
        .with_context(|| format!("invalid prefix '{prefix}'"))?;
    let addr: Ipv6Addr = addr
        .parse()
        .with_context(|| format!("invalid prefix '{prefix}'"))?;
    let len: u8 = len
        .parse()
        .with_context(|| format!("invalid prefix '{prefix}'"))?;
    Ok((addr, len))
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use windows::Win32::Networking::WinSock::{
        IpDadStateTentative, MIB_IPPROTO_NT_STATIC, NL_DAD_STATE,
    };

    /// Pin the fail-closed contract: both families are covered by exactly
    /// the two /1 routes, so no traffic — IPv6 included, lease or not — can
    /// take the physical default route while the tunnel is up.
    #[test]
    fn covering_routes_are_fail_closed() {
        assert_eq!(V4_COVERING.len(), 2);
        assert_eq!(V6_COVERING.len(), 2);
        let mut covered = V4_COVERING
            .iter()
            .map(|(net, mask)| (net, mask))
            .collect::<Vec<_>>();
        covered.sort();
        // The two /1 halves must be complementary and exhaustive.
        assert_eq!(covered[0].0, &Ipv4Addr::new(0, 0, 0, 0));
        assert_eq!(covered[1].0, &Ipv4Addr::new(128, 0, 0, 0));
        assert!(
            covered
                .iter()
                .all(|(_, m)| *m == &Ipv4Addr::new(128, 0, 0, 0))
        );
        assert!(V6_COVERING.contains(&"::/1"));
        assert!(V6_COVERING.contains(&"8000::/1"));
        // The V6_COVERING strings must parse into real prefixes.
        assert_eq!(parse_prefix6("::/1").unwrap(), (Ipv6Addr::UNSPECIFIED, 1));
        assert_eq!(parse_prefix6("8000::/1").unwrap().1, 1);
    }

    /// Covering routes are on-link: the next hop is the unspecified address
    /// of the route's own family, meaning "the interface itself". A gateway
    /// address (even the adapter's own IP) fails next-hop resolution on the
    /// no-ARP point-to-point wintun interface, and lookups fall through to
    /// the physical default route.
    #[test]
    fn forward_row_on_link_has_unspecified_next_hop() {
        let luid = NET_LUID_LH::default();
        let v4 = forward_row(luid, IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1, None);
        assert_eq!(unsafe { v4.NextHop.Ipv4.sin_family }, AF_INET);
        assert_eq!(unsafe { v4.NextHop.Ipv4.sin_addr.S_un.S_addr }, 0);
        let v6 = forward_row(luid, IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1, None);
        assert_eq!(unsafe { v6.NextHop.Ipv6.sin6_family }, AF_INET6);
        assert_eq!(unsafe { v6.NextHop.Ipv6.sin6_addr.u.Byte }, [0u8; 16]);
    }

    /// Routes must carry infinite lifetimes: a zero ValidLifetime makes the
    /// route expire immediately, so lookups skip it and fall through to the
    /// physical default route (netsh uses 0xffffffff).
    #[test]
    fn forward_row_has_infinite_lifetimes() {
        let row = forward_row(
            NET_LUID_LH::default(),
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            1,
            None,
        );
        assert_eq!(row.ValidLifetime, u32::MAX);
        assert_eq!(row.PreferredLifetime, u32::MAX);
    }

    /// prefix_contains selects exactly the forward-table rows whose prefix
    /// covers the destination: both /1 halves, the /0 default, and never the
    /// other half or the other family.
    #[test]
    fn prefix_contains_selects_covering_rows() {
        let prefix = |addr: IpAddr, len: u8| IP_ADDRESS_PREFIX {
            Prefix: sockaddr_inet(addr),
            PrefixLength: len,
        };
        let v4 = |a: u8, b: u8, c: u8, d: u8| IpAddr::V4(Ipv4Addr::new(a, b, c, d));
        let probe_v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        assert!(prefix_contains(&prefix(v4(0, 0, 0, 0), 1), v4(1, 1, 1, 1)));
        assert!(!prefix_contains(
            &prefix(v4(0, 0, 0, 0), 1),
            v4(200, 1, 1, 1)
        ));
        assert!(prefix_contains(
            &prefix(v4(128, 0, 0, 0), 1),
            v4(200, 1, 1, 1)
        ));
        assert!(!prefix_contains(
            &prefix(v4(128, 0, 0, 0), 1),
            v4(1, 1, 1, 1)
        ));
        // The default route covers everything; an unaligned prefix boundary
        // (a /10) is masked per byte.
        assert!(prefix_contains(&prefix(v4(0, 0, 0, 0), 0), v4(1, 1, 1, 1)));
        assert!(prefix_contains(
            &prefix(v4(10, 64, 0, 0), 10),
            v4(10, 100, 0, 1)
        ));
        assert!(!prefix_contains(
            &prefix(v4(10, 64, 0, 0), 10),
            v4(10, 200, 0, 1)
        ));
        // 2606:... starts with 0b0010_0110, so the ::/1 covering route
        // contains it; the other half (8000::/1) does not.
        assert!(prefix_contains(
            &prefix(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 1),
            probe_v6
        ));
        assert!(!prefix_contains(
            &prefix("8000::".parse().unwrap(), 1),
            probe_v6
        ));
        // A family mismatch never matches.
        assert!(!prefix_contains(&prefix(v4(0, 0, 0, 0), 1), probe_v6));
    }

    /// Crash recovery replays exactly what the state file recorded: the
    /// schema must round-trip every field (adapter identity, per-route
    /// entries, DNS, metric rows) through JSON unchanged.
    #[test]
    fn applied_state_serde_roundtrip() {
        let state = AppliedState {
            adapter_luid: Some(0x1234_5678_9abc_def0),
            adapter_guid: Some("{12345678-1234-1234-1234-1234567890ab}".to_string()),
            server_route: Some(ServerRoute {
                server_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)),
                gateway: Ipv4Addr::new(192, 0, 2, 1),
                interface_luid: 42,
            }),
            routes: vec![
                // Legacy shape: state files written before the on-link
                // change recorded the adapter address as the IPv4 next hop;
                // the schema must keep round-tripping it so crash recovery
                // can still delete those routes.
                CoveringRoute {
                    prefix: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                    prefix_len: 1,
                    next_hop: Some(IpAddr::V4(Ipv4Addr::new(10, 7, 0, 1))),
                },
                CoveringRoute {
                    prefix: "::".parse().unwrap(),
                    prefix_len: 1,
                    next_hop: None,
                },
            ],
            dns_servers: vec![
                IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                "::1".parse().unwrap(),
            ],
            interface_metrics: vec![
                InterfaceMetricState {
                    family: AF_INET.0,
                    use_automatic_metric: true,
                    metric: 0,
                },
                InterfaceMetricState {
                    family: AF_INET6.0,
                    use_automatic_metric: false,
                    metric: 25,
                },
            ],
        };
        let json = serde_json::to_string(&state).unwrap();
        let restored: AppliedState = serde_json::from_str(&json).unwrap();
        assert_eq!(restored, state);
        assert!(!restored.is_empty());
        assert!(AppliedState::default().is_empty());
    }

    /// The leak check accepts exactly the adapter's own LUID and rejects
    /// every other interface, so a lookup that would escape via the physical
    /// NIC fails verification.
    #[test]
    fn luid_matches_only_the_adapter() {
        let adapter = luid_from_value(0x1111_2222_3333_4444);
        let physical = luid_from_value(0x5555_6666_7777_8888);
        assert!(luid_matches(adapter, adapter));
        assert!(!luid_matches(physical, adapter));
    }

    // fn-pointer stubs cannot capture state, so the call log lives in
    // statics. Only apply_failure_rolls_back_partial_routes touches them.
    static STUB_ADD_CALLS: AtomicUsize = AtomicUsize::new(0);
    static STUB_DELETED: Mutex<Vec<(IpAddr, u8)>> = Mutex::new(Vec::new());

    /// Second install fails, as if the route table refused the route.
    fn stub_fail_on_second(_record: &CoveringRoute, _luid: NET_LUID_LH) -> Result<()> {
        if STUB_ADD_CALLS.fetch_add(1, Ordering::SeqCst) == 1 {
            bail!("injected install failure");
        }
        Ok(())
    }

    fn stub_record_delete(_luid: NET_LUID_LH, record: &CoveringRoute) -> Result<()> {
        STUB_DELETED
            .lock()
            .unwrap()
            .push((record.prefix, record.prefix_len));
        Ok(())
    }

    /// Fail closed: when a covering-route install fails mid-apply, apply must
    /// fail and roll back the route that did install — the client must never
    /// stay up with partial routing.
    #[test]
    fn apply_failure_rolls_back_partial_routes() {
        STUB_ADD_CALLS.store(0, Ordering::SeqCst);
        STUB_DELETED.lock().unwrap().clear();
        let ops = CoveringRouteOps {
            add: stub_fail_on_second,
            delete: stub_record_delete,
        };
        let cfg = RouteConfig {
            // Loopback skips the server pin and empty DNS skips the DNS
            // step, so the injected failure on the second covering route is
            // the only failure point reached.
            server_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            adapter_name: "test".to_string(),
            adapter_index: 0,
            dns_servers: vec![],
        };
        let state_path = std::env::temp_dir().join(format!(
            "rvpn-route-state-failclosed-test-{}.json",
            std::process::id()
        ));
        let result = apply_with_ops(
            cfg,
            &state_path,
            luid_from_value(0xbeef_beef),
            "{11111111-1111-1111-1111-111111111111}".to_string(),
            ops,
        );
        assert!(result.is_err());
        // Two installs were attempted; the second failed.
        assert_eq!(STUB_ADD_CALLS.load(Ordering::SeqCst), 2);
        // Intent is recorded before each install, so rollback removes every
        // recorded route in reverse order — including the one whose install
        // failed (deleting a never-installed route is a harmless no-op
        // against the real route table, so nothing partial is left behind).
        let deleted = STUB_DELETED.lock().unwrap();
        assert_eq!(
            deleted.as_slice(),
            [
                (IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1),
                (IpAddr::V4(Ipv4Addr::UNSPECIFIED), 1)
            ]
        );
        // Nothing remains, so the state file was removed.
        assert!(!state_path.exists());
    }

    const TEST_ADAPTER_LUID: u64 = 0xaaaa_aaaa;
    const TEST_PHYSICAL_LUID: u64 = 0xdead_dead;

    fn stub_adapter_ok(_luid: NET_LUID_LH) -> Result<()> {
        Ok(())
    }

    fn stub_adapter_gone(_luid: NET_LUID_LH) -> Result<()> {
        bail!("adapter gone")
    }

    fn stub_best_route_adapter(_dest: IpAddr) -> Result<NET_LUID_LH> {
        Ok(luid_from_value(TEST_ADAPTER_LUID))
    }

    fn stub_best_route_physical(_dest: IpAddr) -> Result<NET_LUID_LH> {
        Ok(luid_from_value(TEST_PHYSICAL_LUID))
    }

    /// Happy path: the adapter is up and both route lookups resolve via it,
    /// so the watchdog check passes and reports nothing.
    #[test]
    fn watchdog_check_passes_when_healthy() {
        let ops = WatchdogOps {
            adapter_up: stub_adapter_ok,
            best_route: stub_best_route_adapter,
        };
        assert!(watchdog_check(luid_from_value(TEST_ADAPTER_LUID), &ops).is_ok());
    }

    /// An adapter vanishing mid-connection must fail the watchdog check,
    /// naming the adapter as the failed check.
    #[test]
    fn watchdog_check_fails_when_adapter_disappears() {
        let ops = WatchdogOps {
            adapter_up: stub_adapter_gone,
            best_route: stub_best_route_adapter,
        };
        let e = watchdog_check(luid_from_value(TEST_ADAPTER_LUID), &ops).unwrap_err();
        assert!(format!("{e:#}").contains("adapter check failed"));
    }

    /// A route lookup resolving via the physical NIC instead of the adapter
    /// must fail the watchdog check, naming the leaked route.
    #[test]
    fn watchdog_check_fails_when_route_leaks() {
        let ops = WatchdogOps {
            adapter_up: stub_adapter_ok,
            best_route: stub_best_route_physical,
        };
        let e = watchdog_check(luid_from_value(TEST_ADAPTER_LUID), &ops).unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains("route lookup"));
        assert!(msg.contains("1.1.1.1"));
    }

    // ---- tunnel address DAD -------------------------------------------------

    fn dad_test_row(state: NL_DAD_STATE, luid: u64) -> MIB_UNICASTIPADDRESS_ROW {
        let mut row = MIB_UNICASTIPADDRESS_ROW::default();
        row.Address = sockaddr_inet(IpAddr::V4(Ipv4Addr::new(10, 200, 0, 3)));
        row.InterfaceLuid = luid_from_value(luid);
        row.DadState = state;
        row
    }

    static DAD_SET_STATES: Mutex<Vec<i32>> = Mutex::new(Vec::new());

    fn stub_dad_get_tentative(_addr: Ipv4Addr) -> Result<MIB_UNICASTIPADDRESS_ROW> {
        Ok(dad_test_row(IpDadStateTentative, TEST_ADAPTER_LUID))
    }

    fn stub_dad_get_preferred(_addr: Ipv4Addr) -> Result<MIB_UNICASTIPADDRESS_ROW> {
        Ok(dad_test_row(IpDadStatePreferred, TEST_ADAPTER_LUID))
    }

    fn stub_dad_get_duplicate(_addr: Ipv4Addr) -> Result<MIB_UNICASTIPADDRESS_ROW> {
        Ok(dad_test_row(IpDadStateDuplicate, TEST_ADAPTER_LUID))
    }

    fn stub_dad_get_wrong_interface(_addr: Ipv4Addr) -> Result<MIB_UNICASTIPADDRESS_ROW> {
        Ok(dad_test_row(IpDadStateTentative, TEST_PHYSICAL_LUID))
    }

    fn stub_dad_set_record(row: &MIB_UNICASTIPADDRESS_ROW) -> Result<()> {
        DAD_SET_STATES.lock().unwrap().push(row.DadState.0);
        Ok(())
    }

    fn stub_dad_set_fail(_row: &MIB_UNICASTIPADDRESS_ROW) -> Result<()> {
        bail!("SetUnicastIpAddressEntry must not be called")
    }

    /// A Tentative address (mid-DAD) is forced to Preferred: the row Windows
    /// handed back is written back with only DadState changed.
    #[test]
    fn dad_tentative_is_forced_to_preferred() {
        DAD_SET_STATES.lock().unwrap().clear();
        let ops = DadOps {
            get: stub_dad_get_tentative,
            set: stub_dad_set_record,
        };
        let result = force_dad_preferred_with_ops(
            luid_from_value(TEST_ADAPTER_LUID),
            Ipv4Addr::new(10, 200, 0, 3),
            ops,
        );
        assert_eq!(result.unwrap(), DadForce::Forced);
        assert_eq!(
            DAD_SET_STATES.lock().unwrap().as_slice(),
            [IpDadStatePreferred.0]
        );
    }

    /// An address already past DAD is left untouched (no Set call).
    #[test]
    fn dad_preferred_is_left_untouched() {
        let ops = DadOps {
            get: stub_dad_get_preferred,
            set: stub_dad_set_fail,
        };
        let result = force_dad_preferred_with_ops(
            luid_from_value(TEST_ADAPTER_LUID),
            Ipv4Addr::new(10, 200, 0, 3),
            ops,
        );
        assert_eq!(result.unwrap(), DadForce::AlreadyPreferred);
    }

    /// A DAD duplicate is a real address conflict: fail closed, never paper
    /// over it by forcing the state.
    #[test]
    fn dad_duplicate_fails_closed() {
        let ops = DadOps {
            get: stub_dad_get_duplicate,
            set: stub_dad_set_fail,
        };
        let e = force_dad_preferred_with_ops(
            luid_from_value(TEST_ADAPTER_LUID),
            Ipv4Addr::new(10, 200, 0, 3),
            ops,
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("duplicate"));
    }

    /// The address row must belong to our adapter; forcing the state of an
    /// address living on another interface is refused.
    #[test]
    fn dad_row_on_another_interface_is_refused() {
        let ops = DadOps {
            get: stub_dad_get_wrong_interface,
            set: stub_dad_set_fail,
        };
        let e = force_dad_preferred_with_ops(
            luid_from_value(TEST_ADAPTER_LUID),
            Ipv4Addr::new(10, 200, 0, 3),
            ops,
        )
        .unwrap_err();
        assert!(format!("{e:#}").contains("different interface"));
    }

    // ---- unicast-address wait -----------------------------------------------

    /// Same error shape the production path sees while the netsh-assigned
    /// row has not materialized yet: ERROR_FILE_NOT_FOUND with context.
    fn address_not_found_error() -> anyhow::Error {
        anyhow::Error::new(windows::core::Error::from(HRESULT::from_win32(
            ERROR_FILE_NOT_FOUND.0,
        )))
        .context("GetUnicastIpAddressEntry failed (Win32 error 2)")
    }

    fn stub_wait_sleep_noop(_d: Duration) {}

    static WAIT_LATE_CALLS: AtomicUsize = AtomicUsize::new(0);
    static WAIT_FATAL_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// Row appears on the third poll.
    fn stub_wait_get_late(_addr: Ipv4Addr) -> Result<MIB_UNICASTIPADDRESS_ROW> {
        if WAIT_LATE_CALLS.fetch_add(1, Ordering::SeqCst) >= 2 {
            Ok(dad_test_row(IpDadStatePreferred, TEST_ADAPTER_LUID))
        } else {
            Err(address_not_found_error())
        }
    }

    fn stub_wait_get_never(_addr: Ipv4Addr) -> Result<MIB_UNICASTIPADDRESS_ROW> {
        Err(address_not_found_error())
    }

    fn stub_wait_get_fatal(_addr: Ipv4Addr) -> Result<MIB_UNICASTIPADDRESS_ROW> {
        WAIT_FATAL_CALLS.fetch_add(1, Ordering::SeqCst);
        Err(anyhow::anyhow!("access denied"))
    }

    /// The wait helper polls until the row appears, then returns it.
    #[test]
    fn wait_returns_row_once_address_appears() {
        WAIT_LATE_CALLS.store(0, Ordering::SeqCst);
        let ops = AddressWaitOps {
            get: stub_wait_get_late,
            sleep: stub_wait_sleep_noop,
        };
        let row = wait_for_unicast_address_with_ops(
            Ipv4Addr::new(10, 200, 0, 3),
            Duration::from_secs(5),
            &ops,
        )
        .unwrap();
        assert_eq!(WAIT_LATE_CALLS.load(Ordering::SeqCst), 3);
        assert!(row.DadState == IpDadStatePreferred);
    }

    /// Only the not-found error is retried; any other failure bails on the
    /// first call.
    #[test]
    fn wait_bails_immediately_on_non_retryable_error() {
        WAIT_FATAL_CALLS.store(0, Ordering::SeqCst);
        let ops = AddressWaitOps {
            get: stub_wait_get_fatal,
            sleep: stub_wait_sleep_noop,
        };
        let e = wait_for_unicast_address_with_ops(
            Ipv4Addr::new(10, 200, 0, 3),
            Duration::from_secs(5),
            &ops,
        )
        .err()
        .expect("non-retryable error must fail the wait");
        assert!(format!("{e:#}").contains("access denied"));
        assert_eq!(WAIT_FATAL_CALLS.load(Ordering::SeqCst), 1);
    }

    /// A row that never appears fails with a clear timeout error.
    #[test]
    fn wait_times_out_when_address_never_appears() {
        let ops = AddressWaitOps {
            get: stub_wait_get_never,
            sleep: stub_wait_sleep_noop,
        };
        let e = wait_for_unicast_address_with_ops(
            Ipv4Addr::new(10, 200, 0, 3),
            Duration::from_millis(20),
            &ops,
        )
        .err()
        .expect("an address that never appears must time out");
        assert!(format!("{e:#}").contains("did not appear"));
    }

    // ---- elevated manual diagnostic probe -----------------------------------

    /// Name for one NL_DAD_STATE value in probe output.
    fn dad_state_name(state: NL_DAD_STATE) -> &'static str {
        if state == IpDadStateTentative {
            "Tentative"
        } else {
            match state.0 {
                0 => "Invalid",
                2 => "Duplicate",
                3 => "Deprecated",
                4 => "Preferred",
                _ => "Unknown",
            }
        }
    }

    /// Every route the probe installed, deleted newest-first on any exit path
    /// (including panics), so the machine is left clean even on failure.
    struct ProbeCleanup {
        rows: Vec<MIB_IPFORWARD_ROW2>,
    }

    impl ProbeCleanup {
        fn track(&mut self, row: MIB_IPFORWARD_ROW2) {
            self.rows.push(row);
        }

        /// Delete all tracked rows (used between variants and on drop).
        fn reset(&mut self) {
            let rows = std::mem::take(&mut self.rows);
            for row in rows.iter().rev() {
                let desc = format!(
                    "{}/{}",
                    sockaddr_display(&row.DestinationPrefix.Prefix),
                    row.DestinationPrefix.PrefixLength
                );
                match delete_route(row) {
                    Ok(()) => println!("probe cleanup: deleted route {desc}"),
                    Err(e) => println!("probe cleanup: FAILED to delete route {desc}: {e:#}"),
                }
            }
        }
    }

    impl Drop for ProbeCleanup {
        fn drop(&mut self) {
            self.reset();
        }
    }

    /// GetBestRoute2 with optional interface/source constraints, rendered as
    /// a one-line outcome for the results table.
    fn probe_lookup(
        dest: IpAddr,
        interface: Option<NET_LUID_LH>,
        source: Option<IpAddr>,
        adapter_luid: NET_LUID_LH,
    ) -> String {
        let dest_sa = sockaddr_inet(dest);
        let source_sa = source.map(sockaddr_inet);
        let mut row = MIB_IPFORWARD_ROW2::default();
        let mut best_source = SOCKADDR_INET::default();
        let err = unsafe {
            GetBestRoute2(
                interface.as_ref().map(|l| l as *const _),
                0,
                source_sa.as_ref().map(|sa| sa as *const _),
                &dest_sa,
                0,
                &mut row,
                &mut best_source,
            )
        };
        if err != ERROR_SUCCESS {
            return format!("FAIL: Win32 error {}", err.0);
        }
        format!(
            "ok: if_index={} luid={:#x} ({}) next_hop={} metric={} protocol={} source={}",
            row.InterfaceIndex,
            unsafe { row.InterfaceLuid.Value },
            if luid_matches(row.InterfaceLuid, adapter_luid) {
                "our adapter"
            } else {
                "NOT OUR ADAPTER"
            },
            sockaddr_display(&row.NextHop),
            row.Metric,
            row.Protocol.0,
            sockaddr_display(&best_source),
        )
    }

    /// Install the given routes, run the unconstrained target lookup, record
    /// the outcome and tear the routes down again.
    fn probe_scenario(
        cleanup: &mut ProbeCleanup,
        results: &mut Vec<(String, String)>,
        label: &str,
        rows: Vec<MIB_IPFORWARD_ROW2>,
        adapter_luid: NET_LUID_LH,
        target: IpAddr,
    ) {
        for row in &rows {
            match create_route(row) {
                Ok(()) => cleanup.track(*row),
                Err(e) => {
                    let outcome = format!("route install failed: {e:#}");
                    println!("probe: {label}: {outcome}");
                    results.push((label.to_string(), outcome));
                    cleanup.reset();
                    return;
                }
            }
        }
        let outcome = probe_lookup(target, None, None, adapter_luid);
        println!("probe: {label}: {outcome}");
        results.push((label.to_string(), outcome));
        cleanup.reset();
    }

    /// Elevated, read-only-apart-from-its-own-routes diagnostic probe for
    /// route-resolution failures on the wintun adapter (smoke-run failure:
    /// GetBestRoute2 for 1.1.1.1 fails with ERROR_NETWORK_UNREACHABLE even
    /// though the on-link /1 covering routes exist).
    ///
    /// Creates a throwaway adapter exactly the way the client does
    /// (TunDevice::create_with_ip), assigns 10.200.0.3/24 with MTU 1420,
    /// dumps the adapter/address/interface state (DAD included), installs the
    /// production covering routes via forward_row/create_route, and reports
    /// how GetBestRoute2 behaves for the production rows and a series of
    /// variants — including variant g, which applies the production
    /// force_dad_preferred fix and re-runs the lookup to prove whether
    /// forcing the address past DAD fixes ERROR_NETWORK_UNREACHABLE. Every
    /// route is deleted and the adapter destroyed on exit.
    ///
    /// Diagnostics only: always passes unless adapter creation itself fails.
    /// Run manually from an elevated shell with a signed wintun.dll
    /// resolvable (RVPN_WINTUN_DLL):
    ///
    ///   cargo test -p rvpn-client --lib route_diag_probe -- --ignored --nocapture
    ///
    /// Windows-only like the whole module; #[ignore] keeps it out of CI.
    #[test]
    #[ignore = "elevated manual diagnostic: creates a real wintun adapter"]
    fn route_diag_probe() {
        use crate::config::TunConfig;
        use crate::tun::TunDevice;

        const PROBE_IP: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 3);
        const PROBE_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 200, 0, 1);
        const PROBE_TARGET: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

        println!("=== rvpn route diagnostic probe ===");
        println!("probe: adapter rvpn-diag0, ip {PROBE_IP}/24, mtu 1420, target {PROBE_TARGET}");

        let config = TunConfig {
            interface_name: Some("rvpn-diag0".to_string()),
            dns_servers: Vec::new(),
            routes: Vec::new(),
            mtu: 1420,
            ..Default::default()
        };
        let device = match TunDevice::create_with_ip(&config, "10.200.0.3/24") {
            Ok(device) => device,
            Err(e) => panic!(
                "probe: adapter creation failed (run from an elevated shell with a \
                 signed wintun.dll resolvable, e.g. via RVPN_WINTUN_DLL): {e:#}"
            ),
        };
        // Declared after `device` so on scope exit the routes are deleted
        // first and the adapter destroyed second.
        let mut cleanup = ProbeCleanup { rows: Vec::new() };
        let mut results: Vec<(String, String)> = Vec::new();

        let if_index = match device.adapter_index() {
            Ok(index) => index,
            Err(e) => {
                println!("probe: could not resolve adapter index: {e:#}");
                return;
            }
        };
        let luid = match interface_luid(if_index) {
            Ok(luid) => luid,
            Err(e) => {
                println!("probe: could not resolve adapter LUID: {e:#}");
                return;
            }
        };
        println!(
            "probe: adapter '{}' if_index={} luid={:#x}",
            device.adapter_name().unwrap_or_else(|_| "?".to_string()),
            if_index,
            unsafe { luid.Value },
        );

        // --- adapter state ---
        let mut if_row = MIB_IF_ROW2 {
            InterfaceLuid: luid,
            ..Default::default()
        };
        let err = unsafe { GetIfEntry2(&mut if_row) };
        if err == ERROR_SUCCESS {
            println!(
                "probe: GetIfEntry2: oper_status={} if_type={} media_connect_state={} \
                 access_type={} tunnel_type={} mtu={}",
                if_row.OperStatus.0,
                if_row.Type,
                if_row.MediaConnectState.0,
                if_row.AccessType.0,
                if_row.TunnelType.0,
                if_row.Mtu,
            );
        } else {
            println!("probe: GetIfEntry2 failed: Win32 error {}", err.0);
        }

        // --- address state + DAD watch ---
        match get_unicast_address_row(PROBE_IP) {
            Ok(row) => {
                println!(
                    "probe: address {PROBE_IP}: dad_state={} ({}) prefix_origin={} \
                     suffix_origin={} valid_lifetime={} preferred_lifetime={} \
                     skip_as_source={} on_link_prefix_len={}",
                    row.DadState.0,
                    dad_state_name(row.DadState),
                    row.PrefixOrigin.0,
                    row.SuffixOrigin.0,
                    row.ValidLifetime,
                    row.PreferredLifetime,
                    row.SkipAsSource,
                    row.OnLinkPrefixLength,
                );
                results.push((
                    "initial DAD state".to_string(),
                    format!("{} ({})", row.DadState.0, dad_state_name(row.DadState)),
                ));
                if row.DadState == IpDadStateTentative {
                    println!("probe: DAD is Tentative; polling up to 10s for it to settle...");
                    let start = std::time::Instant::now();
                    let mut final_state = row.DadState;
                    while final_state == IpDadStateTentative
                        && start.elapsed() < std::time::Duration::from_secs(10)
                    {
                        std::thread::sleep(std::time::Duration::from_millis(250));
                        match get_unicast_address_row(PROBE_IP) {
                            Ok(current) => final_state = current.DadState,
                            Err(e) => {
                                println!("probe: DAD poll failed: {e:#}");
                                break;
                            }
                        }
                    }
                    let completed = final_state != IpDadStateTentative;
                    println!(
                        "probe: DAD {} after {:?}: state={} ({})",
                        if completed {
                            "settled"
                        } else {
                            "still Tentative"
                        },
                        start.elapsed(),
                        final_state.0,
                        dad_state_name(final_state),
                    );
                    results.push((
                        "DAD after polling".to_string(),
                        format!(
                            "{} ({})",
                            dad_state_name(final_state),
                            if completed {
                                "left Tentative"
                            } else {
                                "STUCK Tentative after 10s"
                            }
                        ),
                    ));
                }
            }
            Err(e) => println!("probe: GetUnicastIpAddressEntry({PROBE_IP}) failed: {e:#}"),
        }

        // --- per-family interface rows ---
        for family in [AF_INET, AF_INET6] {
            match get_ip_interface(luid, family) {
                Ok(Some(row)) => println!(
                    "probe: ip-interface family={}: metric={} use_automatic_metric={} \
                     nl_mtu={} dad_transmits={} connected={}",
                    family.0,
                    row.Metric,
                    row.UseAutomaticMetric,
                    row.NlMtu,
                    row.DadTransmits,
                    row.Connected,
                ),
                Ok(None) => println!("probe: no ip-interface row for family {}", family.0),
                Err(e) => println!(
                    "probe: GetIpInterfaceEntry family={} failed: {e:#}",
                    family.0
                ),
            }
        }

        let base_rows = || {
            vec![
                forward_row(luid, IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 1, None),
                forward_row(luid, IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)), 1, None),
            ]
        };
        let target = IpAddr::V4(PROBE_TARGET);

        // Baseline: the exact production covering routes.
        probe_scenario(
            &mut cleanup,
            &mut results,
            "baseline: /1 pair, metric 1, on-link, NETMGMT",
            base_rows(),
            luid,
            target,
        );

        // (a) Metric 0 instead of 1.
        let mut rows = base_rows();
        for row in &mut rows {
            row.Metric = 0;
        }
        probe_scenario(
            &mut cleanup,
            &mut results,
            "variant a: metric 0",
            rows,
            luid,
            target,
        );

        // (b) Next hop = the adapter's own address instead of on-link.
        let rows = vec![
            forward_row(
                luid,
                IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                1,
                Some(IpAddr::V4(PROBE_IP)),
            ),
            forward_row(
                luid,
                IpAddr::V4(Ipv4Addr::new(128, 0, 0, 0)),
                1,
                Some(IpAddr::V4(PROBE_IP)),
            ),
        ];
        probe_scenario(
            &mut cleanup,
            &mut results,
            "variant b: next hop = own address 10.200.0.3",
            rows,
            luid,
            target,
        );

        // (c) Protocol NT_STATIC instead of NETMGMT.
        let mut rows = base_rows();
        for row in &mut rows {
            row.Protocol = MIB_IPPROTO_NT_STATIC;
        }
        probe_scenario(
            &mut cleanup,
            &mut results,
            "variant c: protocol NT_STATIC",
            rows,
            luid,
            target,
        );

        // (d) A single 0.0.0.0/0 instead of the /1 pair.
        probe_scenario(
            &mut cleanup,
            &mut results,
            "variant d: single 0.0.0.0/0",
            vec![forward_row(
                luid,
                IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                0,
                None,
            )],
            luid,
            target,
        );

        // (e) + (f): constrained lookups and the gateway baseline, with the
        // production routes in place.
        let mut installed = true;
        for row in base_rows() {
            match create_route(&row) {
                Ok(()) => cleanup.track(row),
                Err(e) => {
                    println!("probe: variant e/f: route install failed: {e:#}");
                    results.push((
                        "variant e/f setup".to_string(),
                        format!("route install failed: {e:#}"),
                    ));
                    installed = false;
                    break;
                }
            }
        }
        if installed {
            let outcome = probe_lookup(target, None, Some(IpAddr::V4(PROBE_IP)), luid);
            println!("probe: variant e1 (source 10.200.0.3): {outcome}");
            results.push((
                "variant e1: explicit source 10.200.0.3".to_string(),
                outcome,
            ));

            let outcome = probe_lookup(target, Some(luid), None, luid);
            println!("probe: variant e2 (interface luid): {outcome}");
            results.push(("variant e2: explicit interface LUID".to_string(), outcome));

            let outcome = probe_lookup(target, Some(luid), Some(IpAddr::V4(PROBE_IP)), luid);
            println!("probe: variant e3 (source + interface): {outcome}");
            results.push(("variant e3: source + interface".to_string(), outcome));

            let outcome = probe_lookup(IpAddr::V4(PROBE_GATEWAY), None, None, luid);
            println!("probe: variant f (gateway {PROBE_GATEWAY}): {outcome}");
            results.push(("variant f: gateway 10.200.0.1 lookup".to_string(), outcome));
        }
        cleanup.reset();

        // (g) The client fix: force the address past DAD into Preferred
        // (force_dad_preferred, same as main.rs calls before route setup),
        // then re-install the production covering routes and re-run the
        // lookup — proof whether the DAD force fixes ERROR_NETWORK_UNREACHABLE.
        match force_dad_preferred(if_index, PROBE_IP) {
            Ok(()) => {
                match get_unicast_address_row(PROBE_IP) {
                    Ok(row) => println!(
                        "probe: variant g: force_dad_preferred ok; dad_state={} ({})",
                        row.DadState.0,
                        dad_state_name(row.DadState)
                    ),
                    Err(e) => println!("probe: variant g: address re-read failed: {e:#}"),
                }
                probe_scenario(
                    &mut cleanup,
                    &mut results,
                    "variant g: DAD forced Preferred + production routes",
                    base_rows(),
                    luid,
                    target,
                );
            }
            Err(e) => {
                let outcome = format!("force_dad_preferred failed: {e:#}");
                println!("probe: variant g: {outcome}");
                results.push((
                    "variant g: DAD forced Preferred + production routes".to_string(),
                    outcome,
                ));
            }
        }

        println!("\n=== PROBE RESULTS ===");
        for (label, outcome) in &results {
            println!("  {label}: {outcome}");
        }
        println!("probe: routes deleted; adapter is destroyed when the device drops");
    }
}
