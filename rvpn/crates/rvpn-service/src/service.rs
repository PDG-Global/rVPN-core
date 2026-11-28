//! Windows service entry: register with the Service Control Manager and
//! report status transitions. The SCM spawns this process, calls
//! `service_main` via `StartServiceCtrlDispatcherW`, and delivers control
//! codes (STOP / INTERROGATE) to `control_handler`.

use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use tracing::{error, info};
use windows_sys::Win32::Foundation::{ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR};
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};

const SERVICE_NAME: &str = "rvpn-service";

static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static STATUS_HANDLE: AtomicIsize = AtomicIsize::new(0);

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Hand control to the SCM dispatcher. Returns only when the service has
/// stopped (or fails immediately when not launched by the SCM, e.g. from a
/// console — use `--console` for that).
pub fn run() -> Result<()> {
    let mut name = to_wide(SERVICE_NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        bail!(
            "StartServiceCtrlDispatcherW failed: {} (not started by the SCM?)",
            std::io::Error::last_os_error()
        );
    }
    Ok(())
}

fn set_status(handle: SERVICE_STATUS_HANDLE, state: u32) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP
        } else {
            0
        },
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    unsafe {
        SetServiceStatus(handle, &status);
    }
}

/// Report a terminal failure to the SCM: a service-specific exit code so
/// `sc query` and the event log show the pipe could not be created.
fn set_status_failed(handle: SERVICE_STATUS_HANDLE, state: u32, specific: u32) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: 0,
        dwWin32ExitCode: ERROR_SERVICE_SPECIFIC_ERROR,
        dwServiceSpecificExitCode: specific,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    unsafe {
        SetServiceStatus(handle, &status);
    }
}

extern "system" fn service_main(_num_args: u32, _args: *mut windows_sys::core::PWSTR) {
    let name = to_wide(SERVICE_NAME);
    let handle = unsafe {
        RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control_handler), ptr::null_mut())
    };
    if handle == 0 {
        return;
    }
    STATUS_HANDLE.store(handle, Ordering::SeqCst);

    // Create the control pipe BEFORE reporting SERVICE_RUNNING: if someone
    // is squatting on the pipe name or creation otherwise fails, the
    // service must stop with an error instead of staying RUNNING with no
    // pipe.
    let pipe_handle = match crate::pipe::create_pipe() {
        Ok(h) => h,
        Err(e) => {
            error!("control pipe creation failed, stopping service: {e:#}");
            set_status_failed(handle, SERVICE_STOPPED, 1);
            return;
        }
    };
    set_status(handle, SERVICE_RUNNING);
    info!("service running");

    // The pipe server runs on its own thread; ConnectNamedPipe blocks, so
    // the STOP flag cannot interrupt it — acceptable for the skeleton, the
    // process exits when the SCM stops us here.
    std::thread::spawn(move || crate::pipe::serve_loop_logged(pipe_handle, "running"));

    while !STOP_REQUESTED.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }
    set_status(handle, SERVICE_STOPPED);
    info!("service stopped");
}

unsafe extern "system" fn control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut std::ffi::c_void,
    _context: *mut std::ffi::c_void,
) -> u32 {
    let handle = STATUS_HANDLE.load(Ordering::SeqCst);
    match control {
        SERVICE_CONTROL_STOP => {
            info!("SERVICE_CONTROL_STOP received");
            set_status(handle, SERVICE_STOP_PENDING);
            STOP_REQUESTED.store(true, Ordering::SeqCst);
        }
        SERVICE_CONTROL_INTERROGATE => {}
        _ => {}
    }
    NO_ERROR
}
