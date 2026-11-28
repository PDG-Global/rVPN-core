//! rvpn-service — privileged Windows helper service for rVPN.
//!
//! Runs as LocalSystem and owns privileged operations (wintun adapter
//! creation, route/DNS changes). The rvpn-client desktop app never runs as
//! admin; it drives this service over the ACL'd named pipe
//! `\\.\pipe\rvpn-service` (see pipe.rs).

#[cfg(not(windows))]
compile_error!("rvpn-service is a Windows-only crate");

#[cfg(windows)]
mod pipe;
mod protocol;
#[cfg(windows)]
mod service;

use anyhow::Result;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let console = std::env::args().any(|arg| arg == "--console");
    if console {
        // Dev mode: run as a plain console process without installing the
        // service. Exit with Ctrl+C.
        #[cfg(windows)]
        pipe::serve("console")?;
        #[cfg(not(windows))]
        unreachable!();
        Ok(())
    } else {
        #[cfg(windows)]
        return service::run();
        #[cfg(not(windows))]
        unreachable!();
    }
}
