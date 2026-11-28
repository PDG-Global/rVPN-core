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
//!
//! Frame reads are bounded by an inactivity deadline (READ_TIMEOUT), so a
//! client that connects and then stalls — silent or drip-feeding a partial
//! frame — cannot hold the single-threaded server forever.

use std::fs::File;
use std::io::{Read, Write};
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle};
use std::ptr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use tracing::{error, info, warn};
use windows_sys::Win32::Foundation::{ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows_sys::Win32::System::Memory::LocalFree;
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_MESSAGE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    PeekNamedPipe,
};

use crate::protocol::{MAX_FRAME_LEN, Reply, Request};

pub const PIPE_NAME: &str = r"\\.\pipe\rvpn-service";

/// See the module docs for the access-control rationale.
const SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

const BUFFER_SIZE: u32 = 4096;

/// Inactivity deadline per frame: a connected-but-silent or drip-feeding
/// client must not hold the single-threaded server forever.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll interval while waiting for pipe data to arrive.
const PEEK_POLL_INTERVAL: Duration = Duration::from_millis(25);

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
        // One deadline covers the header and its payload, so a partial
        // frame cannot extend the session either.
        let deadline = Instant::now() + READ_TIMEOUT;
        let mut len_buf = [0u8; 4];
        if let Err(e) = read_exact_timeout(file, &mut len_buf, deadline) {
            // Client hung up or went silent past the deadline; end the
            // session instead of holding the server thread.
            info!("client session ended ({e:#})");
            return Ok(());
        }
        let len = u32::from_le_bytes(len_buf) as usize;
        if len == 0 || len > MAX_FRAME_LEN {
            bail!("invalid frame length {len}");
        }
        let mut payload = vec![0u8; len];
        read_exact_timeout(file, &mut payload, deadline)?;
        let reply = match serde_json::from_slice::<Request>(&payload) {
            Ok(req) => req.handle(service_state),
            Err(e) => Reply::Error {
                message: format!("malformed request: {e}"),
            },
        };
        let out = serde_json::to_vec(&reply)?;
        let out_len = (out.len() as u32).to_le_bytes();
        file.write_all(&out_len)
            .and_then(|_| file.write_all(&out))?;
        file.flush()?;
    }
}

/// read_exact bounded by `deadline`: poll for data with PeekNamedPipe
/// instead of blocking indefinitely, so a client that goes silent (or drip
/// feeds a partial frame) cannot hold the single-threaded server forever.
/// Peek failures (client hung up) and deadline expiry both surface as
/// errors; the caller ends the session on either.
fn read_exact_timeout(file: &mut File, buf: &mut [u8], deadline: Instant) -> Result<()> {
    loop {
        let mut available = 0;
        let peeked = unsafe {
            PeekNamedPipe(
                file.as_raw_handle() as HANDLE,
                ptr::null_mut(),
                0,
                ptr::null_mut(),
                &mut available,
                ptr::null_mut(),
            )
        };
        if peeked == 0 {
            bail!(
                "pipe client hung up while waiting for data: {}",
                std::io::Error::last_os_error()
            );
        }
        if available as usize >= buf.len() {
            return file.read_exact(buf).context("reading pipe frame");
        }
        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for {} bytes on the control pipe",
                buf.len()
            );
        }
        std::thread::sleep(PEEK_POLL_INTERVAL);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use std::sync::atomic::{AtomicU32, Ordering};

    static PIPE_SEQ: AtomicU32 = AtomicU32::new(0);

    /// A throwaway duplex message pipe pair on a unique name. The client
    /// connects up front and the server accepts it like the production
    /// serve flow, so read_exact_timeout runs against a real pipe.
    fn test_pipe_pair() -> (File, File) {
        let name = format!(
            r"\\.\pipe\rvpn-service-test-{}-{}",
            std::process::id(),
            PIPE_SEQ.fetch_add(1, Ordering::SeqCst)
        );
        let wide = to_wide(&name);
        let server = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                1,
                BUFFER_SIZE,
                BUFFER_SIZE,
                0,
                ptr::null(),
            )
        };
        assert_ne!(server, INVALID_HANDLE_VALUE);
        let client = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&name)
            .expect("client connect to test pipe");
        // Accept the client explicitly, matching the production serve flow
        // (ERROR_PIPE_CONNECTED means the client beat us to it; success).
        if unsafe { ConnectNamedPipe(server, ptr::null_mut()) } == 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(ERROR_PIPE_CONNECTED as i32)
            );
        }
        // SAFETY: `server` is a valid, owned pipe handle created above; the
        // File takes ownership and closes it on drop.
        (unsafe { File::from_raw_handle(server as _) }, client)
    }

    /// A connected but silent client must be timed out instead of holding
    /// the server thread.
    #[test]
    fn silent_client_times_out() {
        let (mut server, _client) = test_pipe_pair();
        let mut buf = [0u8; 4];
        let err = read_exact_timeout(
            &mut server,
            &mut buf,
            Instant::now() + Duration::from_millis(300),
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("timed out"));
    }

    /// A client that sends promptly is read normally; the timeout never
    /// engages.
    #[test]
    fn prompt_client_reads_immediately() {
        let (mut server, mut client) = test_pipe_pair();
        client.write_all(&42u32.to_le_bytes()).unwrap();
        let mut buf = [0u8; 4];
        read_exact_timeout(&mut server, &mut buf, Instant::now() + READ_TIMEOUT).unwrap();
        assert_eq!(u32::from_le_bytes(buf), 42);
    }
}
