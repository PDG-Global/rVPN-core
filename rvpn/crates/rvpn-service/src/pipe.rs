//! Named-pipe control server on `\\.\pipe\rvpn-service`.
//!
//! The pipe is the only way rvpn-client talks to this service, so its
//! security descriptor is the access-control boundary of the whole
//! privileged surface:
//!
//!   D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)
//!
//!   - `SY` (LocalSystem): the service itself, so it can always reach its
//!     own pipe even if other ACEs change later.
//!   - `BA` (built-in Administrators): admin troubleshooting / management.
//!   - `IU` (INTERACTIVE), read/write only (`GRGW`): the signed-in desktop
//!     user's access token contains the INTERACTIVE SID (S-1-5-4), so the
//!     unelevated client process can connect — while service accounts,
//!     network logons and other accounts on the machine cannot. No GA:
//!     interactive users must not be able to create extra pipe instances or
//!     rewrite the descriptor. This is Thomas's "only the signed-in user
//!     drives the service" requirement.
//!
//! The descriptor is applied at pipe creation, and the pipe is created with
//! FILE_FLAG_FIRST_PIPE_INSTANCE so a squatting user pipe can never
//! pre-empt the service's name. A future config-folder ACL (user + SYSTEM)
//! is a separate mechanism and not handled here.

use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;
use std::os::windows::io::{FromRawHandle, IntoRawHandle};
use std::ptr;

use anyhow::{Context, Result, bail};
use tracing::{error, info, warn};
use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Memory::LocalFree;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

use crate::protocol::{MAX_FRAME_LEN, Reply, Request};

pub const PIPE_NAME: &str = r"\\.\pipe\rvpn-service";

/// See the module docs for the access-control rationale.
const SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

const BUFFER_SIZE: u32 = 4096;

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Create the server end of the named pipe with the ACL above.
pub(crate) fn create_pipe() -> Result<HANDLE> {
    let name = to_wide(PIPE_NAME);
    let sddl = to_wide(SDDL);
    unsafe {
        let mut sd = ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            ptr::null_mut(),
        ) == 0
        {
            bail!(
                "ConvertStringSecurityDescriptorToSecurityDescriptor failed: {}",
                std::io::Error::last_os_error()
            );
        }
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd,
            bInheritHandle: 0,
        };
        let handle = CreateNamedPipeW(
            name.as_ptr(),
            // First-instance: fail if another process is squatting on our
            // pipe name instead of becoming an instance of the attacker's
            // pipe.
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE,
            BUFFER_SIZE,
            0,
            &sa,
        );
        LocalFree(sd as _);
        if handle == INVALID_HANDLE_VALUE {
            bail!(
                "CreateNamedPipeW failed: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(handle)
    }
}

/// Run the pipe server forever, handling one client at a time. There is no
/// need for concurrency at this scale; parallel instances can be added if
/// the client ever needs more than one outstanding connection.
pub fn serve(service_state: &str) -> Result<()> {
    let handle = create_pipe()?;
    serve_loop(handle, service_state)
}

/// Serve on an already-created pipe handle. Kept separate from create_pipe
/// so the SCM path can fail the service start when creation fails.
pub(crate) fn serve_loop(handle: HANDLE, service_state: &str) -> Result<()> {
    info!(pipe = PIPE_NAME, "control pipe listening");
    loop {
        let connected = unsafe { ConnectNamedPipe(handle, ptr::null_mut()) };
        // ConnectNamedPipe reports ERROR_PIPE_CONNECTED when the client
        // beat us to the connection; that is success, not failure.
        if connected == 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(ERROR_PIPE_CONNECTED as i32) {
                warn!("ConnectNamedPipe failed: {err}");
                continue;
            }
        }
        if let Err(e) = serve_client(handle, service_state) {
            warn!("pipe client session ended: {e:#}");
        }
        unsafe {
            DisconnectNamedPipe(handle);
        }
    }
}

fn serve_client(handle: HANDLE, service_state: &str) -> Result<()> {
    // Wrap the raw handle for std IO, then hand ownership back so the pipe
    // handle survives for DisconnectNamedPipe and the next client.
    let mut file = unsafe { File::from_raw_handle(handle as _) };
    let result = serve_client_io(&mut file, service_state);
    let _ = file.into_raw_handle();
    result
}

fn serve_client_io(file: &mut File, service_state: &str) -> Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        if let Err(e) = file.read_exact(&mut len_buf) {
            // Client hung up; treat any read failure as end of session.
            info!("client disconnected ({e})");
            return Ok(());
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > MAX_FRAME_LEN {
            bail!("invalid frame length {len}");
        }
        let mut payload = vec![0u8; len];
        file.read_exact(&mut payload)
            .context("reading frame payload")?;
        let reply = match serde_json::from_slice::<Request>(&payload) {
            Ok(req) => req.handle(service_state),
            Err(e) => Reply::Error {
                message: format!("malformed request: {e}"),
            },
        };
        let out = serde_json::to_vec(&reply)?;
        let out_len = (out.len() as u32).to_le_bytes();
        file.write_all(&out_len).and_then(|_| file.write_all(&out))?;
        file.flush()?;
    }
}

/// Best-effort shutdown helper for the SCM pipe thread: on fatal error,
/// log instead of panicking so the SCM path can still report
/// SERVICE_STOPPED cleanly. Pipe creation itself is validated before
/// SERVICE_RUNNING is reported, so a failure here is mid-run only.
pub(crate) fn serve_loop_logged(handle: HANDLE, service_state: &str) {
    if let Err(e) = serve_loop(handle, service_state) {
        error!("control pipe server failed: {e:#}");
    }
}
