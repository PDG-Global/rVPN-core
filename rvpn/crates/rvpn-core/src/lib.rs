//! R-VPN Core Library
//!
//! Core protocol definitions, cryptographic primitives, and shared types
//! for the R-VPN server and client.

#![warn(missing_docs)]
#![deny(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod frame_padding;
pub mod identity_pin;
pub mod protocol;
pub mod routing;

pub use error::{Error, Result};

/// Version of the protocol
pub const PROTOCOL_VERSION: u8 = 1;

/// Version string for handshake
pub const PROTOCOL_VERSION_STRING: &str = "R-VPN-v1";
