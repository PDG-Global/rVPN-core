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

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use windows::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_BUFFER_OVERFLOW, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS,
    ERROR_SUCCESS, WIN32_ERROR,
};
use windows::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceIndexToLuid, CreateIpForwardEntry2, DNS_INTERFACE_SETTINGS,
    DNS_INTERFACE_SETTINGS_VERSION1, DNS_SETTING_NAMESERVER, DeleteIpForwardEntry2,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    GAA_FLAG_SKIP_UNICAST, GET_ADAPTERS_ADDRESSES_FLAGS, GetAdaptersAddresses, GetBestRoute2,
    GetIpInterfaceEntry, IP_ADAPTER_ADDRESSES_LH, IP_ADDRESS_PREFIX, MIB_IPFORWARD_ROW2,
    MIB_IPINTERFACE_ROW, SetInterfaceDnsSettings, SetIpInterfaceEntry,
};
use windows::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows::Win32::Networking::WinSock::{
    ADDRESS_FAMILY, AF_INET, AF_INET6, IN_ADDR, IN_ADDR_0, IN6_ADDR, IN6_ADDR_0,
    MIB_IPPROTO_NETMGMT, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
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

/// Everything needed to set up tunnel routing.
pub struct RouteConfig {
    /// IP of the VPN server we connect to (must stay routed via the
    /// physical gateway or the tunnel kills its own transport).
    pub server_ip: IpAddr,
    /// wintun adapter name (e.g. "rVPN").
    pub adapter_name: String,
    /// wintun adapter interface index.
    pub adapter_index: u32,
    /// IPv4 address assigned to the adapter (used as the on-link gateway).
    pub adapter_ipv4: Ipv4Addr,
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
    /// Next hop for IPv4 routes (the adapter address). IPv6 routes are
    /// on-link and record no next hop.
    next_hop: Option<IpAddr>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct InterfaceMetricState {
    /// Address family (AF_INET / AF_INET6) the recorded row belongs to.
    family: u16,
    use_automatic_metric: bool,
    metric: u32,
}

/// Handle returned by [`apply`]; dropping it reverses everything, using the
/// state file as the source of truth. A process that dies without dropping
/// leaves the state file behind, so the next start restores from it.
pub struct RouteGuard {
    state_path: PathBuf,
    cfg: RouteConfig,
    state: AppliedState,
}

/// Apply the full routing setup. Every change is persisted to the state
/// file before it is applied; any failure rolls back what was applied and
/// the file is left describing exactly what remains on the system.
pub fn apply(cfg: RouteConfig, state_path: &PathBuf) -> Result<RouteGuard> {
    // Resolve the adapter identity up front: the LUID scopes every route,
    // DNS and metric change (and its rollback) to this adapter.
    let adapter_luid = interface_luid(cfg.adapter_index)?;
    let adapter_guid = adapter_guid_string(cfg.adapter_index)?;
    let mut guard = RouteGuard {
        state_path: state_path.clone(),
        cfg,
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
    finish_restore(state_path, rollback_state(&state));
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
        self.state = rollback_state(&self.state);
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
        //    space without touching the physical default route).
        for (net, mask) in V4_COVERING {
            let record = CoveringRoute {
                prefix: net.into(),
                prefix_len: u32::from(mask).count_ones() as u8,
                next_hop: Some(self.cfg.adapter_ipv4.into()),
            };
            self.state.routes.push(record.clone());
            self.persist()?;
            route_add(&record, luid)?;
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
            route_add(&record, luid)?;
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
fn rollback_state(state: &AppliedState) -> AppliedState {
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
            let row = forward_row(luid, record.prefix, record.prefix_len, record.next_hop);
            if let Err(e) = delete_route(&row) {
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
fn force_interface_metric(mut row: MIB_IPINTERFACE_ROW) -> Result<()> {
    // Only rewrite the row when it actually differs: fewer changes to roll
    // back, and no churn on adapters already configured this way.
    if !row.UseAutomaticMetric && row.Metric == 1 {
        return Ok(());
    }
    row.UseAutomaticMetric = false;
    row.Metric = 1;
    let err = unsafe { SetIpInterfaceEntry(&mut row) };
    check(err, "SetIpInterfaceEntry")
}

/// Restore the recorded per-family metric state on exactly the recorded
/// interface (by LUID). Every other interface is left untouched.
fn restore_interface_metric(luid: NET_LUID_LH, record: &InterfaceMetricState) -> Result<()> {
    let Some(mut row) = get_ip_interface(luid, ADDRESS_FAMILY(record.family))? else {
        // The adapter (or the family on it) is gone; its metric died with it.
        return Ok(());
    };
    row.UseAutomaticMetric = record.use_automatic_metric;
    row.Metric = record.metric;
    let err = unsafe { SetIpInterfaceEntry(&mut row) };
    check(err, "SetIpInterfaceEntry")
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
}
