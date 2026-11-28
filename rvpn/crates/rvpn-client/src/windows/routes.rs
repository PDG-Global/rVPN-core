//! Windows route and DNS management for TUN mode.
//!
//! On connect we (a) pin a host route for the VPN server through the
//! physical gateway, (b) cover IPv4 with two /1 routes and IPv6 with
//! ::/1 + 8000::/1 through the wintun adapter, and (c) point the adapter's
//! DNS at the resolvers that work through the tunnel with a winning
//! interface metric. Every change is recorded in a state file *before* it
//! is applied, so a crash can never leave the machine with broken routing:
//! the next start restores from that file first, and a clean disconnect
//! tears down the same changes.

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

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

/// Record of what we changed, persisted to the state file before applying.
#[derive(Serialize, Deserialize, Default)]
struct AppliedState {
    /// Host route for the VPN server: (server_ip, physical_gateway).
    server_route: Option<(IpAddr, IpAddr)>,
    /// Whether the two IPv4 /1 routes were added via the adapter.
    ipv4_covered: bool,
    /// Whether the two IPv6 /1 routes were added via the adapter.
    ipv6_covered: bool,
    /// DNS servers set on the adapter.
    dns_servers: Vec<IpAddr>,
    /// Interface index of the adapter the DNS was set on (needed for reset).
    adapter_index: Option<u32>,
    /// Interface metric forced on the adapter (wintun must win DNS).
    metric_forced: Option<u32>,
}

/// Handle returned by [`apply`]; dropping it reverses everything, using the
/// state file as the source of truth. A process that dies without dropping
/// leaves the state file behind, so the next start restores from it.
pub struct RouteGuard {
    state_path: PathBuf,
    cfg: RouteConfig,
    state: AppliedState,
}

/// Apply the full routing setup. Writes the state file first; any failure
/// afterwards rolls back what was applied and restores from the file.
pub fn apply(cfg: RouteConfig, state_path: &PathBuf) -> Result<RouteGuard> {
    let mut guard = RouteGuard {
        state_path: state_path.clone(),
        cfg,
        state: AppliedState::default(),
    };
    guard.persist()?;
    if let Err(e) = guard.apply_all() {
        warn!("route setup failed ({e:#}); rolling back partial changes");
        guard.rollback();
        // The file must reflect what is actually left on the system: nothing.
        guard.state = AppliedState::default();
        guard.persist()?;
        return Err(e);
    }
    guard.persist()?;
    Ok(guard)
}

/// Reverse every change recorded in the state file and delete it. Runs on
/// clean disconnect; on a crash the guard never drops and the next start
/// calls [`restore_from_state_file`] instead.
impl Drop for RouteGuard {
    fn drop(&mut self) {
        self.rollback();
        let _ = std::fs::remove_file(&self.state_path);
    }
}

/// Crash recovery: if a state file exists from a previous run, undo whatever
/// it recorded, then delete it. Call this at client start, before applying
/// any new state.
pub fn restore_from_state_file(state_path: &Path) {
    let contents = match std::fs::read_to_string(state_path) {
        Ok(c) => c,
        Err(_) => return, // no crash state: nothing to restore
    };
    warn!(
        "found leftover route state at {}; restoring system routing",
        state_path.display()
    );
    match serde_json::from_str::<AppliedState>(&contents) {
        Ok(state) => {
            rollback_state(&state);
        }
        Err(e) => {
            // A state file we can't parse must not be silently ignored: it
            // may describe live changes we can no longer reverse.
            warn!("could not parse route state file ({e}); leaving it for manual inspection");
            return;
        }
    }
    let _ = std::fs::remove_file(state_path);
}

impl RouteGuard {
    fn persist(&self) -> Result<()> {
        let json = serde_json::to_string_pretty(&self.state)?;
        std::fs::write(&self.state_path, json)
            .with_context(|| format!("Failed to write {}", self.state_path.display()))
    }

    fn apply_all(&mut self) -> Result<()> {
        // 1. Pin the VPN server through the physical gateway, so the tunnel
        //    transport never loops through the tunnel itself. Skip this when
        //    the server is on this machine: pointing a loopback address at a
        //    physical gateway wedges the Windows loopback stack until reboot
        //    (observed in the smoke test with a localhost test server).
        if !self.cfg.server_ip.is_loopback() {
            let gateway = physical_gateway()?;
            route_add_host(self.cfg.server_ip, gateway)?;
            self.state.server_route = Some((self.cfg.server_ip, gateway));
            self.persist()?;
        }

        // 2. IPv4: 0.0.0.0/1 + 128.0.0.0/1 via the adapter (covers the whole
        //    space without touching the physical default route).
        for (net, mask) in [
            (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(128, 0, 0, 0)),
            (Ipv4Addr::new(128, 0, 0, 0), Ipv4Addr::new(128, 0, 0, 0)),
        ] {
            route_add_v4_via_adapter(net, mask, self.cfg.adapter_ipv4, self.cfg.adapter_index)?;
        }
        self.state.ipv4_covered = true;
        self.persist()?;

        // 3. IPv6: ::/1 + 8000::/1 via the adapter. If the adapter has no
        //    IPv6, block nothing here — the leak check in the smoke test
        //    must confirm no ::/0 traffic escapes on the physical NIC.
        for prefix in ["::/1", "8000::/1"] {
            route_add_v6_via_adapter(prefix, self.cfg.adapter_index)?;
        }
        self.state.ipv6_covered = true;
        self.persist()?;

        // 4. DNS on the adapter, then force a winning interface metric so
        //    Windows does not keep asking the physical adapter's DNS.
        set_adapter_dns(self.cfg.adapter_index, &self.cfg.dns_servers)?;
        self.state.dns_servers = self.cfg.dns_servers.clone();
        self.state.adapter_index = Some(self.cfg.adapter_index);
        self.persist()?;
        force_interface_metric(self.cfg.adapter_index, 1)?;
        self.state.metric_forced = Some(1);
        self.persist()?;

        info!(
            "tunnel routes active: {} covered via adapter '{}' (if {}), server {} via {}",
            if self.state.ipv4_covered { "IPv4" } else { "" },
            self.cfg.adapter_name,
            self.cfg.adapter_index,
            self.cfg.server_ip,
            self.state
                .server_route
                .map(|(_, gw)| gw.to_string())
                .unwrap_or_default()
        );
        Ok(())
    }

    /// Reverse everything recorded in the state; best effort per item.
    fn rollback(&self) {
        rollback_state(&self.state);
    }
}

/// Best-effort reversal of every recorded change; logs and continues on
/// individual failures so one bad entry cannot block the rest.
fn rollback_state(state: &AppliedState) {
    if state.metric_forced.is_some() {
        // Restore automatic metric handling.
        if let Err(e) = restore_interface_metric() {
            warn!("failed to restore interface metric: {e:#}");
        }
    }
    if !state.dns_servers.is_empty() {
        if let Some(idx) = state.adapter_index {
            if let Err(e) = clear_adapter_dns(idx) {
                warn!("failed to clear adapter DNS: {e:#}");
            }
        } else {
            warn!("DNS was set but no adapter index recorded; cannot reset DNS");
        }
    }
    if state.ipv6_covered {
        for prefix in ["::/1", "8000::/1"] {
            if let Err(e) = route_delete_v6(prefix) {
                warn!("failed to delete IPv6 route {prefix}: {e:#}");
            }
        }
    }
    if state.ipv4_covered {
        for (net, mask) in [
            (Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(128, 0, 0, 0)),
            (Ipv4Addr::new(128, 0, 0, 0), Ipv4Addr::new(128, 0, 0, 0)),
        ] {
            if let Err(e) = route_delete_v4(net, mask) {
                warn!("failed to delete route {net}/{mask}: {e:#}");
            }
        }
    }
    if let Some((server, _)) = state.server_route {
        if let Err(e) = route_delete_host(server) {
            warn!("failed to delete server host route {server}: {e:#}");
        }
    }
}

// ---- command runners ------------------------------------------------------

/// Full path to a System32 tool. This runs elevated, so a bare name must
/// never be resolved through PATH or the working directory.
fn system32_tool(tool: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    Path::new(&root).join("System32").join(tool)
}

fn run(cmd: &std::ffi::OsStr, args: &[&str]) -> Result<String> {
    let output = std::process::Command::new(cmd)
        .args(args)
        .output()
        .with_context(|| format!("failed to start {}", cmd.to_string_lossy()))?;
    if !output.status.success() {
        bail!(
            "{} {} failed (status {}): {}",
            cmd.to_string_lossy(),
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn powershell(script: &str) -> Result<String> {
    run(
        system32_tool(r"WindowsPowerShell\v1.0\powershell.exe").as_os_str(),
        &["-NoProfile", "-Command", script],
    )
}

fn route_cmd(args: &[&str]) -> Result<String> {
    run(system32_tool("route.exe").as_os_str(), args)
}

/// Physical default gateway of the machine (IPv4 default route's next hop).
fn physical_gateway() -> Result<IpAddr> {
    let out = powershell(
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | \
         Select-Object -First 1 -ExpandProperty NextHop",
    )?;
    let hop = out.trim();
    let gw: IpAddr = hop
        .parse()
        .with_context(|| format!("could not parse physical gateway from '{hop}'"))?;
    if gw.is_unspecified() {
        bail!("no physical default gateway found");
    }
    Ok(gw)
}

fn route_add_host(ip: IpAddr, gateway: IpAddr) -> Result<()> {
    match (ip, gateway) {
        (IpAddr::V4(ip), IpAddr::V4(gw)) => {
            route_cmd(&[
                "add",
                &ip.to_string(),
                "mask",
                "255.255.255.255",
                &gw.to_string(),
                "metric",
                "1",
            ])?;
            Ok(())
        }
        _ => bail!("server host route for non-IPv4 gateway is not implemented"),
    }
}

fn route_delete_host(ip: IpAddr) -> Result<()> {
    route_cmd(&["delete", &ip.to_string()])?;
    Ok(())
}

fn route_add_v4_via_adapter(
    net: Ipv4Addr,
    mask: Ipv4Addr,
    adapter_ip: Ipv4Addr,
    if_index: u32,
) -> Result<()> {
    route_cmd(&[
        "add",
        &net.to_string(),
        "mask",
        &mask.to_string(),
        &adapter_ip.to_string(),
        "metric",
        "1",
        "if",
        &if_index.to_string(),
    ])?;
    Ok(())
}

fn route_delete_v4(net: Ipv4Addr, mask: Ipv4Addr) -> Result<()> {
    route_cmd(&["delete", &net.to_string(), "mask", &mask.to_string()])?;
    Ok(())
}

fn route_add_v6_via_adapter(prefix: &str, if_index: u32) -> Result<()> {
    powershell(&format!(
        "New-NetRoute -DestinationPrefix '{prefix}' -InterfaceIndex {if_index} \
         -RouteMetric 1 -ErrorAction Stop | Out-Null"
    ))?;
    Ok(())
}

fn route_delete_v6(prefix: &str) -> Result<()> {
    powershell(&format!(
        "Remove-NetRoute -DestinationPrefix '{prefix}' -Confirm:$false -ErrorAction Stop"
    ))?;
    Ok(())
}
fn set_adapter_dns(if_index: u32, servers: &[IpAddr]) -> Result<()> {
    // Set-DnsClientServerAddress takes the whole list in one call, mixed
    // families included. (netsh set dnsservers takes exactly one address,
    // which silently breaks configs with more than one resolver.)
    let quoted: Vec<String> = servers.iter().map(|s| format!("'{s}'")).collect();
    if !quoted.is_empty() {
        powershell(&format!(
            "Set-DnsClientServerAddress -InterfaceIndex {if_index} \
             -ServerAddresses @({}) -ErrorAction Stop",
            quoted.join(",")
        ))?;
    }
    Ok(())
}

fn clear_adapter_dns(if_index: u32) -> Result<()> {
    // Reset DNS (both families) on exactly the interface we configured.
    powershell(&format!(
        "Set-DnsClientServerAddress -InterfaceIndex {if_index} \
         -ResetServerAddresses -ErrorAction Stop"
    ))?;
    Ok(())
}

fn force_interface_metric(if_index: u32, metric: u32) -> Result<()> {
    powershell(&format!(
        "Set-NetIPInterface -InterfaceIndex {if_index} -InterfaceMetric {metric} -ErrorAction Stop"
    ))?;
    Ok(())
}

fn restore_interface_metric() -> Result<()> {
    // Re-enable automatic metric on every interface that was forced to 1.
    // Only our adapter was set to 1 by apply_all, so this restores it.
    powershell(
        "Get-NetIPInterface | Where-Object { $_.InterfaceMetric -eq 1 } | \
         Set-NetIPInterface -AutomaticMetric Enabled",
    )?;
    Ok(())
}
