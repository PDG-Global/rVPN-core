//! Tests for R-VPN server

pub mod fixtures;
mod server_tests;
mod routing_tests;
mod log_privacy;
mod acme_challenge_tolerance;

// Integration test helpers
pub mod integration;

// Integration tests - these spawn real processes
#[cfg(feature = "integration-tests")]
mod integration_tests;
