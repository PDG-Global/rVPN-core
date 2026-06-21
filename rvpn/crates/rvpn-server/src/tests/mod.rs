//! Tests for R-VPN server

mod server_tests;
mod routing_tests;

// Integration test helpers
pub mod integration;

// Integration tests - these spawn real processes
#[cfg(feature = "integration-tests")]
mod integration_tests;
