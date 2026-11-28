//! Fail-fast IPv6 blocking via Windows Filtering Platform (WFP).
//!
//! When the server assigns no IPv6 lease, the covering ::/1 + 8000::/1
//! routes in `routes.rs` already stop v6 from escaping through the physical
//! adapter — fail-closed, but as a blackhole: packets travel into the
//! tunnel and apps wait out long timeouts. The WFP block filters added
//! here make applications fail immediately instead, which is what users
//! and developers expect from a blocked protocol.
//!
//! The filters are non-persistent: they exist only while our engine handle
//! is open, and the OS closes that handle when this process exits or
//! crashes — so cleanup needs no state file, and a crash can never leave a
//! permanent v6 block behind. A loopback permit at higher weight keeps
//! ::1 working for local IPC while the block is active.

use std::ptr;

use anyhow::{Context, Result, bail};
use tracing::debug;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_ACTION_BLOCK, FWP_ACTION_PERMIT, FWP_ACTION_TYPE, FWP_CONDITION_VALUE0,
    FWP_MATCH_FLAGS_ALL_SET, FWP_UINT32, FWP_UINT64, FWP_VALUE0, FWPM_ACTION0, FWPM_CONDITION_FLAGS,
    FWPM_DISPLAY_DATA0, FWPM_FILTER_CONDITION0, FWPM_FILTER0, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6, FWPM_SESSION0, FWPM_SESSION_FLAG_DYNAMIC,
    FWPM_SUBLAYER_UNIVERSAL, FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0,
};
use windows::Win32::System::Com::CoCreateGuid;
use windows::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows::core::GUID;

/// Permit loopback (::1) so local IPC keeps working; block everything else.
/// The permit must outweigh the block.
const PERMIT_WEIGHT: u64 = u64::MAX;
const BLOCK_WEIGHT: u64 = u64::MAX - 1;

/// Layers where a block returns an immediate error to the application:
/// outbound connect (TCP and first-packet UDP) and inbound accept.
const BLOCK_LAYERS: [GUID; 2] = [
    FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
];

/// Guard holding the WFP engine handle. The engine was opened with a
/// `FWPM_SESSION_FLAG_DYNAMIC` session, so every filter we added is dynamic:
/// dropping the guard closes the handle and process death has the same
/// effect — the filters never outlive the client.
pub struct Ipv6BlockGuard(HANDLE);

impl Drop for Ipv6BlockGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = FwpmEngineClose0(self.0);
        }
        debug!("WFP engine closed; IPv6 block filters removed");
    }
}

/// Install the IPv6 fail-fast block. Requires no special privileges beyond
/// what the client already runs with (WFP filter add needs admin).
pub fn block_ipv6() -> Result<Ipv6BlockGuard> {
    let mut engine = HANDLE::default();
    // Dynamic session: all filters added through this handle are removed when
    // the handle closes or the process dies. Without FWPM_SESSION_FLAG_DYNAMIC
    // they would persist in the filter engine until explicitly deleted or
    // rebooted.
    let session_name = wide("rVPN IPv6 block");
    let session_desc = wide("Dynamic session: IPv6 fail-fast filters die with the client process");
    let session = FWPM_SESSION0 {
        displayData: FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(session_name.as_ptr() as *mut u16),
            description: windows::core::PWSTR(session_desc.as_ptr() as *mut u16),
        },
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        ..Default::default()
    };
    let err = unsafe {
        FwpmEngineOpen0(
            None::<&windows::core::PCWSTR>,
            RPC_C_AUTHN_WINNT,
            None,
            Some(&session),
            &mut engine,
        )
    };
    check(err, "FwpmEngineOpen0")?;

    match install_filters(engine) {
        Ok(()) => Ok(Ipv6BlockGuard(engine)),
        Err(e) => {
            unsafe {
                let _ = FwpmEngineClose0(engine);
            }
            Err(e)
        }
    }
}

fn install_filters(engine: HANDLE) -> Result<()> {
    // Permit loopback v6 at the top weight on both layers, then block the
    // rest just below it.
    for layer in BLOCK_LAYERS {
        let mut conditions = [FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_FLAGS,
            matchType: FWP_MATCH_FLAGS_ALL_SET,
            conditionValue: {
                let mut v = FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT32,
                    ..Default::default()
                };
                v.Anonymous.uint32 = windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_FLAG_IS_LOOPBACK;
                v
            },
        }];
        add_filter(
            engine,
            layer,
            "rVPN IPv6 loopback permit",
            "Allow ::1 traffic while IPv6 is blocked (local IPC)",
            FWP_ACTION_PERMIT,
            PERMIT_WEIGHT,
            conditions.as_mut_ptr(),
            1,
        )?;

        add_filter(
            engine,
            layer,
            "rVPN IPv6 block",
            "Fail-fast block: server assigned no IPv6 lease",
            FWP_ACTION_BLOCK,
            BLOCK_WEIGHT,
            ptr::null_mut(),
            0,
        )?;
    }
    Ok(())
}

fn add_filter(
    engine: HANDLE,
    layer: GUID,
    name: &str,
    description: &str,
    action_type: FWP_ACTION_TYPE,
    weight: u64,
    conditions: *mut FWPM_FILTER_CONDITION0,
    num_conditions: u32,
) -> Result<()> {
    let name_w = wide(name);
    let desc_w = wide(description);
    let key = unsafe { CoCreateGuid() }.context("CoCreateGuid failed")?;

    let mut filter = FWPM_FILTER0 {
        filterKey: key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: windows::core::PWSTR(name_w.as_ptr() as *mut u16),
            description: windows::core::PWSTR(desc_w.as_ptr() as *mut u16),
        },
        layerKey: layer,
        subLayerKey: FWPM_SUBLAYER_UNIVERSAL,
        weight: uint64_weight(weight),
        numFilterConditions: num_conditions,
        filterCondition: conditions,
        action: FWPM_ACTION0 {
            r#type: action_type,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut id = 0u64;
    let err = unsafe { FwpmFilterAdd0(engine, &mut filter, None, Some(&mut id)) };
    check(err, "FwpmFilterAdd0")?;
    debug!("WFP filter '{}' installed (id {})", name, id);
    Ok(())
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn uint64_weight(v: u64) -> FWP_VALUE0 {
    // FWP_UINT64 weight values are passed by pointer; the pointer must
    // outlive FwpmFilterAdd0, so leak one small box per filter.
    let mut value = FWP_VALUE0 {
        r#type: FWP_UINT64,
        ..Default::default()
    };
    value.Anonymous.uint64 = Box::leak(Box::new(v));
    value
}

fn check(err: u32, op: &str) -> Result<()> {
    if err == 0 {
        Ok(())
    } else {
        bail!("{op} failed: {}", windows::core::Error::from_win32())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin the fail-closed contract: with no server v6 lease the block must
    /// sit above nothing but the loopback permit.
    #[test]
    fn permit_outweighs_block() {
        assert!(PERMIT_WEIGHT > BLOCK_WEIGHT);
    }

    /// The block must cover both directions or inbound v6 could still reach
    /// listening apps directly.
    #[test]
    fn block_covers_both_directions() {
        assert_eq!(BLOCK_LAYERS.len(), 2);
        assert!(BLOCK_LAYERS.contains(&FWPM_LAYER_ALE_AUTH_CONNECT_V6));
        assert!(BLOCK_LAYERS.contains(&FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6));
    }
}
