//! Length-prefixed JSON control protocol between rvpn-client (running
//! unelevated as the signed-in user) and this service (LocalSystem).
//!
//! Each message on the pipe is a 4-byte little-endian length followed by
//! that many bytes of JSON. Serde renders unit variants as plain strings
//! (`"Ping"`) and struct variants as tagged objects
//! (`{"Status": {...}}`).

use serde::{Deserialize, Serialize};

/// Largest accepted request payload; guards against a client advertising a
/// huge frame to exhaust memory.
pub const MAX_FRAME_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Request {
    Ping,
    Status,
    /// Will later carry the parameters needed to bring up the TUN session
    /// and apply routes/DNS (the logic that today lives in
    /// rvpn-client/src/windows/routes.rs).
    Connect,
    Disconnect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Reply {
    Pong,
    Status {
        /// SCM state the service last reported, e.g. "running".
        service_state: String,
        /// Whether a TUN session is currently up. Always false until
        /// Connect/Disconnect are implemented.
        tun_active: bool,
    },
    Error {
        message: String,
    },
}

impl Request {
    pub fn handle(&self, service_state: &str) -> Reply {
        match self {
            Request::Ping => Reply::Pong,
            Request::Status => Reply::Status {
                service_state: service_state.to_string(),
                tun_active: false,
            },
            Request::Connect | Request::Disconnect => Reply::Error {
                message: "not implemented: will host the TUN session and \
                          route/DNS application in a later milestone"
                    .to_string(),
            },
        }
    }
}
