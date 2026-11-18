// Copyright (C) 2024-2026 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of R-VPN.
//
// R-VPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! The privacy policy says servers keep no record of who connected, when,
//! or where they went. The server logs at INFO by default (`RUST_LOG=info`
//! in the systemd unit), so no `info!`/`warn!`/`error!` call may carry a
//! client identifier: the peer address, the tunnel IP handed to a client, a
//! destination host/port, or a DNS name. Those belong at `debug!` only,
//! which is off unless the operator passes `-v`.
//!
//! This is a denylist of identifier *names*, not taint analysis: a client
//! address bound to a new name (`let ip = conn.remote(); info!(%ip, ..)`)
//! passes. A green run is a fence around the known names, not proof that
//! nothing identifying is logged; review new log lines with that in mind.

/// Every non-test source file in `src/`; `every_server_source_is_scanned` fails
/// when a new file is added without being listed here.
const SOURCES: &[(&str, &str)] = &[
    ("config.rs", include_str!("../config.rs")),
    ("decoy.rs", include_str!("../decoy.rs")),
    ("egress.rs", include_str!("../egress.rs")),
    ("firewall.rs", include_str!("../firewall.rs")),
    ("handler.rs", include_str!("../handler.rs")),
    ("lib.rs", include_str!("../lib.rs")),
    ("main.rs", include_str!("../main.rs")),
    ("private_files.rs", include_str!("../private_files.rs")),
    ("tun_server.rs", include_str!("../tun_server.rs")),
];

const IDENTIFIERS: &[&str] = &[
    "peer_addr",
    "client_ip",
    "allocated_ip",
    "tun_assigned_ip",
    "dst_ip",
    "target_addr",
    "target_socket_addr",
    "connect_target",
    "query.domain",
    "target,",
];

/// Every `info!(`/`warn!(`/`error!(` call in `src`, as (line, full text).
fn default_level_calls(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for mac in ["info!(", "warn!(", "error!("] {
        let mut from = 0;
        while let Some(pos) = src[from..].find(mac) {
            let start = from + pos;
            from = start + mac.len();
            // Skip identifiers that merely end in the macro name (e.g. `tracing_info!(`).
            if src[..start]
                .chars()
                .last()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                continue;
            }
            let mut depth = 1;
            let mut end = from;
            for (i, c) in src[from..].char_indices() {
                match c {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                if depth == 0 {
                    end = from + i + 1;
                    break;
                }
            }
            let line = src[..start].matches('\n').count() + 1;
            out.push((line, src[start..end].to_string()));
        }
    }
    out
}

/// `id` appears in `call` as a whole token (so `allocated_ip_for_tun` in a
/// message string doesn't count as `allocated_ip`).
fn mentions(call: &str, id: &str) -> bool {
    let word = |c: char| c.is_alphanumeric() || c == '_';
    call.match_indices(id).any(|(i, _)| {
        let before = call[..i]
            .chars()
            .last()
            .map_or(true, |c| !word(c) || id.starts_with('.'));
        let after = call[i + id.len()..]
            .chars()
            .next()
            .map_or(true, |c| !word(c) || id.ends_with(','));
        before && after
    })
}

#[test]
fn no_client_identifier_is_logged_at_default_levels() {
    let mut offenders = Vec::new();
    for (file, src) in SOURCES {
        for (line, call) in default_level_calls(src) {
            // Inline format args (`{peer_addr}`) count as well as positional ones.
            if IDENTIFIERS.iter().any(|id| mentions(&call, id)) {
                offenders.push(format!(
                    "{file}:{line}: {}",
                    call.split_whitespace().collect::<Vec<_>>().join(" ")
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "client identifiers logged at INFO/WARN/ERROR (move to debug!):\n{}",
        offenders.join("\n")
    );
}

/// `#[instrument]` and spans record their fields at INFO by default, which
/// would log every argument (addresses included) without any `info!` call
/// for the test above to see. None are used in the server today; adding one
/// should be a reviewed decision, so this test fails until the list is kept.
#[test]
fn no_spans_or_instrument_in_server_sources() {
    for (file, src) in SOURCES {
        for needle in [
            "#[instrument",
            "tracing::instrument",
            "info_span!",
            "span!(",
        ] {
            assert!(
                !src.contains(needle),
                "{file} uses `{needle}`: spans log their fields at INFO by default; \
                 skip client identifiers in it and update this test deliberately"
            );
        }
    }
}

/// Keeps `SOURCES` complete: a new `src/*.rs` file must be added to the
/// scan, or this fails.
#[test]
fn every_server_source_is_scanned() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut on_disk: Vec<String> = std::fs::read_dir(&dir)
        .expect("read src/")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".rs"))
        .collect();
    on_disk.sort();
    let mut listed: Vec<String> = SOURCES.iter().map(|(f, _)| f.to_string()).collect();
    listed.sort();
    assert_eq!(
        on_disk, listed,
        "add new src/*.rs files to SOURCES in log_privacy.rs"
    );
}
