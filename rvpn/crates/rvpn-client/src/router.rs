// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Multi-server per-flow routing.

//! Re-export of the shared router, which lives in `rvpn-split-tunnel` so both
//! the CLI client and the mobile crate can use it. See
//! `rvpn_split_tunnel::router` for the implementation.

pub use rvpn_split_tunnel::router::Router;
