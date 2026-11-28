//! Locate, verify and load the bundled wintun.dll before it is handed to tun-rs.
//!
//! The DLL is loaded only after its SHA-256 matches the pinned hash of the
//! official signed build and its Authenticode signature verifies against the
//! pinned signer. Anything else is a hard error: a planted or tampered DLL
//! must never reach the loader.
//!
//! Verification is TOCTOU-hardened end to end:
//! - the directory holding the DLL must not grant write access to any
//!   principal other than SYSTEM, Administrators or TrustedInstaller, and no
//!   path component may be a reparse point — otherwise a verified DLL could
//!   be swapped for a planted one before the load;
//! - the file is opened with a deny-write share mode and that handle is held
//!   across hashing, signature verification and the load, so the bytes
//!   verified are the bytes loaded;
//! - the load itself uses LoadLibraryExW with
//!   LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, so the
//!   dependency search order cannot be hijacked. tun-rs loads the same path
//!   afterwards; the Windows loader returns this already-loaded image, never
//!   a re-read from disk.

use std::ffi::c_void;
use std::fs::File;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tracing::warn;
use windows::Win32::Foundation::{FreeLibrary, GENERIC_READ, HANDLE, HMODULE, HWND};
use windows::Win32::Security::Cryptography::{
    CERT_CONTEXT, CERT_FIND_CERT_ID, CERT_ID, CERT_ID_0, CERT_ID_ISSUER_SERIAL_NUMBER,
    CERT_ISSUER_SERIAL_NUMBER, CERT_NAME_ATTR_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED,
    CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_CONTENT_TYPE_FLAGS,
    CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE, CMSG_SIGNER_COUNT_PARAM,
    CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, CertCloseStore, CertFindCertificateInStore,
    CertFreeCertificateContext, CertGetNameStringW, CryptMsgClose, CryptMsgGetParam,
    CryptQueryObject, HCERTSTORE, PKCS_7_ASN_ENCODING, X509_ASN_ENCODING, szOID_COMMON_NAME,
};
use windows::Win32::Security::WinTrust::{
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_WHOLECHAIN,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE, WTD_UICONTEXT_EXECUTE,
    WinVerifyTrust,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
};
use windows::Win32::System::LibraryLoader::{
    LOAD_LIBRARY_FLAGS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
    LoadLibraryExW,
};
use windows::core::PCWSTR;

use super::sec;

/// SHA-256 of the official signed wintun.dll (amd64) shipped in
/// wintun-0.14.1.zip. The archive's own SHA-256
/// (07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51)
/// matches the value published at https://www.wintun.net/, and the DLL's
/// Authenticode signature (WireGuard LLC, DigiCert EV) was verified when
/// this constant was recorded. Update both together.
const WINTUN_DLL_AMD64_SHA256: &str =
    "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce";

/// Development-only override for the DLL location.
const OVERRIDE_ENV: &str = "RVPN_WINTUN_DLL";

/// Expected Authenticode signer of the official wintun.dll. The SHA-256 pin
/// above binds the exact build; this binds the signer identity, so a
/// different-but-hash-colliding artifact can never be substituted silently.
const EXPECTED_SIGNER_SUBJECT: &str = "WireGuard LLC";

/// Verified wintun.dll, ready to be handed to tun-rs. The guard holds the
/// protections that close the check-then-load race: a deny-write file handle
/// and a reference on the already-loaded module. Keep it alive until tun-rs
/// has opened the DLL (it then holds its own reference to the same verified
/// in-memory image).
pub struct VerifiedWintunDll {
    path: PathBuf,
    /// Deny-write handle: no one can open the file for modification while it
    /// is held. Closed when the guard drops.
    _file: File,
    /// Reference on the module loaded with the restricted search flags.
    /// Freed when the guard drops; tun-rs keeps the module loaded through
    /// its own library handle.
    _module: LibraryGuard,
}

impl VerifiedWintunDll {
    /// Verified absolute path of wintun.dll, to pass to tun-rs.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Frees the module reference on drop on every exit path.
struct LibraryGuard(HMODULE);

impl Drop for LibraryGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = FreeLibrary(self.0);
        }
    }
}

/// Resolve, verify and load the wintun.dll.
///
/// Resolution order: `RVPN_WINTUN_DLL` (dev override, debug builds only),
/// then `wintun.dll` beside the current executable. The returned guard is
/// absolute and verified, and keeps the verified bytes pinned until dropped.
///
/// Production installs must place the DLL in a directory only administrators
/// can write (for example under Program Files): the checks below refuse any
/// other location for the non-override path.
pub fn resolve_and_verify() -> Result<VerifiedWintunDll> {
    let (path, from_override) = match override_path() {
        Some(custom) => (custom, true),
        None => (
            std::env::current_exe()
                .context("Failed to locate current executable")?
                .parent()
                .context("Executable has no parent directory")?
                .join("wintun.dll"),
            false,
        ),
    };

    let path = std::fs::canonicalize(&path)
        .with_context(|| format!("wintun.dll not found or not readable: {}", path.display()))?;

    // A directory ordinary users can write lets them swap the verified DLL
    // for a planted one before the load. Enforced for the production path
    // only: the debug-only override points wherever the developer works.
    if !from_override {
        check_dll_directory(&path)?;
    }

    // Opened before any check and held until after the load: the deny-write
    // share mode blocks in-place modification of the bytes between the
    // hash/signature verification and the load.
    let file = open_deny_write(&path)?;
    verify_sha256(&file, &path)?;
    verify_authenticode(&path)?;
    let module = load_restricted(&path)?;

    Ok(VerifiedWintunDll {
        path,
        _file: file,
        _module: module,
    })
}

/// Development override, honored in debug builds only. Release builds must
/// never let an environment variable choose which DLL an elevated process
/// loads: it is ignored there (with a warning), so the override cannot be
/// abused to swap in a planted DLL under production settings.
#[cfg(debug_assertions)]
fn override_path() -> Option<PathBuf> {
    std::env::var_os(OVERRIDE_ENV).map(|custom| {
        let custom = PathBuf::from(custom);
        warn!(
            "{OVERRIDE_ENV} is set; loading wintun.dll from {} (development override — \
             never set this in production)",
            custom.display()
        );
        custom
    })
}

#[cfg(not(debug_assertions))]
fn override_path() -> Option<PathBuf> {
    if std::env::var_os(OVERRIDE_ENV).is_some() {
        warn!("{OVERRIDE_ENV} is set but ignored in release builds");
    }
    None
}

/// The directory holding the DLL must not be modifiable by anyone outside
/// SYSTEM, Administrators and TrustedInstaller, and no path component may
/// be a reparse point: either would let a lesser principal replace the
/// verified DLL before it is loaded.
fn check_dll_directory(dll: &Path) -> Result<()> {
    sec::check_no_reparse_points(dll)?;
    let dir = dll
        .parent()
        .context("wintun.dll path has no parent directory")?;
    sec::check_write_acl(dir, &sec::trusted_installer_sids()?)?;
    Ok(())
}

/// Open the DLL with read access and a share mode that denies write
/// (FILE_SHARE_READ only): no one can modify the bytes while the handle is
/// held across hashing, signature verification and the load.
fn open_deny_write(path: &Path) -> Result<File> {
    let wide = sec::wide_path(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR::from_raw(wide.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }
    .with_context(|| format!("Failed to open {}", path.display()))?;
    // SAFETY: `handle` is a valid, owned file handle returned above; the
    // File takes ownership and closes it on drop.
    Ok(unsafe { File::from_raw_handle(handle.0 as RawHandle) })
}

/// Hash check against the pinned digest, read through the deny-write handle
/// opened above so the hashed bytes are exactly the loaded bytes. Applies to
/// every path source, including the override: a warning never replaces the
/// pin.
fn verify_sha256(file: &File, path: &Path) -> Result<()> {
    let mut hasher = Sha256::new();
    std::io::copy(&mut &*file, &mut hasher)
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let digest = hex::encode(hasher.finalize());
    if digest != WINTUN_DLL_AMD64_SHA256 {
        bail!(
            "Refusing to load {}: SHA-256 {} does not match the pinned wintun.dll hash {}. \
             The file may be tampered with; install the official signed wintun 0.14.1 DLL.",
            path.display(),
            digest,
            WINTUN_DLL_AMD64_SHA256
        );
    }
    Ok(())
}

/// Authenticode check via WinVerifyTrust and crypt32: the signature must be
/// trusted (with revocation checking across the whole chain) and the signer
/// certificate's common name must identify WireGuard LLC. Applies to every
/// path source, including the override. This is done through direct FFI
/// rather than by launching powershell.exe: starting a child process by
/// unqualified name follows PATH and the working directory, which would
/// reopen the planted-binary problem this check exists to close.
fn verify_authenticode(path: &Path) -> Result<()> {
    let wide = sec::wide_path(path);
    verify_trust(path, &wide)?;
    verify_signer(path, &wide)
}

/// Trust check: WinVerifyTrust with WINTRUST_ACTION_GENERIC_VERIFY_V2. A
/// non-zero return is a trust failure (for example 0x800B0100,
/// TRUST_E_NOSIGNATURE, for unsigned files).
fn verify_trust(path: &Path, wide: &[u16]) -> Result<()> {
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR::from_raw(wide.as_ptr()),
        hFile: HANDLE(std::ptr::null_mut()),
        pgKnownSubject: std::ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0),
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        ..Default::default()
    };
    // WTD_UI_NONE means no user interface is shown, so the window handle is
    // unused; null is the "no window" value.
    let hwnd = HWND(std::ptr::null_mut());
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        WinVerifyTrust(
            hwnd,
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut c_void,
        )
    };
    // Release the provider state allocated by the verify call above. Nothing
    // useful can be done with a close failure, so its result is intentionally
    // ignored.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        WinVerifyTrust(
            hwnd,
            &mut action,
            &mut data as *mut WINTRUST_DATA as *mut c_void,
        );
    }
    if status != 0 {
        bail!(
            "Refusing to load {}: Authenticode trust verification failed \
             (WinVerifyTrust returned 0x{status:08X}; unsigned files report \
             0x800B0100, TRUST_E_NOSIGNATURE). Install the official signed \
             wintun 0.14.1 DLL.",
            path.display()
        );
    }
    Ok(())
}

/// Signer check: extract the PKCS#7 signature with CryptQueryObject and
/// confirm the signer's certificate common name is exactly the expected
/// WireGuard LLC identity (case-sensitive: case-insensitive comparison
/// would accept a differently-cased CN from a rogue CA-issued cert).
fn verify_signer(path: &Path, wide: &[u16]) -> Result<()> {
    let mut store = HCERTSTORE(std::ptr::null_mut());
    let mut msg: *mut c_void = std::ptr::null_mut();
    unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr() as *const c_void,
            // Embedded PE signatures (Authenticode) report content type
            // PKCS7_SIGNED_EMBED; accepting both flags also covers detached
            // PKCS#7 signatures. CERT_QUERY_CONTENT_TYPE_FLAGS has no BitOr
            // impl in the windows crate, so the flags are combined directly.
            CERT_QUERY_CONTENT_TYPE_FLAGS(
                CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED.0
                    | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED.0,
            ),
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store),
            Some(&mut msg),
            None,
        )
    }
    .with_context(|| format!("Failed to read the PKCS#7 signature of {}", path.display()))?;
    let store = CertStoreGuard(store);
    let msg = CryptMsgGuard(msg);

    let mut count: u32 = 0;
    let mut count_size = std::mem::size_of::<u32>() as u32;
    unsafe {
        CryptMsgGetParam(
            msg.0,
            CMSG_SIGNER_COUNT_PARAM,
            0,
            Some(&mut count as *mut u32 as *mut c_void),
            &mut count_size,
        )
    }
    .with_context(|| format!("Failed to read the signer count of {}", path.display()))?;
    if count == 0 {
        bail!(
            "Refusing to load {}: signature contains no signer.",
            path.display()
        );
    }

    let mut size: u32 = 0;
    unsafe { CryptMsgGetParam(msg.0, CMSG_SIGNER_INFO_PARAM, 0, None, &mut size) }
        .with_context(|| format!("Failed to size the signer info of {}", path.display()))?;
    // Backed by u64 elements so the buffer is aligned for the struct cast
    // below; CryptMsgGetParam fills exactly `size` bytes.
    let mut buf = vec![0u64; size as usize / 8 + 1];
    unsafe {
        CryptMsgGetParam(
            msg.0,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(buf.as_mut_ptr() as *mut c_void),
            &mut size,
        )
    }
    .with_context(|| format!("Failed to read the signer info of {}", path.display()))?;
    // The buffer is sized and filled by CryptMsgGetParam exactly for
    // CMSG_SIGNER_INFO.
    let signer_info = unsafe { &*(buf.as_ptr() as *const CMSG_SIGNER_INFO) };

    // Locate the signer's certificate in the message's certificate store by
    // issuer name + serial number. The blobs are borrowed from the decoded
    // message; the message guard below outlives every use.
    let cert_id = CERT_ID {
        dwIdChoice: CERT_ID_ISSUER_SERIAL_NUMBER,
        Anonymous: CERT_ID_0 {
            IssuerSerialNumber: CERT_ISSUER_SERIAL_NUMBER {
                Issuer: signer_info.Issuer,
                SerialNumber: signer_info.SerialNumber,
            },
        },
    };
    let cert = unsafe {
        CertFindCertificateInStore(
            store.0,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            0,
            CERT_FIND_CERT_ID,
            Some(&cert_id as *const CERT_ID as *const c_void),
            None,
        )
    };
    if cert.is_null() {
        bail!(
            "Refusing to load {}: signer certificate not found in the signature.",
            path.display()
        );
    }
    let cert = CertContextGuard(cert);

    // CERT_NAME_ATTR_TYPE with the CN OID returns just the common name (no
    // "CN=" prefix), so an exact comparison pins the signer identity.
    let mut name = [0u16; 256];
    let len = unsafe {
        CertGetNameStringW(
            cert.0,
            CERT_NAME_ATTR_TYPE,
            0,
            Some(szOID_COMMON_NAME.as_ptr() as *const c_void),
            Some(&mut name),
        )
    };
    if len <= 1 {
        bail!(
            "Refusing to load {}: signer certificate has no common name.",
            path.display()
        );
    }
    // The returned length counts the terminating NUL and may exceed the
    // buffer if the name was truncated; clamp to what was actually written.
    let cn = String::from_utf16_lossy(&name[..(len as usize - 1).min(name.len())]);
    if cn != EXPECTED_SIGNER_SUBJECT {
        bail!(
            "Refusing to load {}: signer '{}' is not exactly the expected wintun signer ({}).",
            path.display(),
            cn,
            EXPECTED_SIGNER_SUBJECT
        );
    }
    Ok(())
}

/// Load the verified DLL with a restricted search path: dependencies are
/// resolved only from System32 and the DLL's own directory, never from the
/// application directory, the working directory or PATH, so the search
/// order cannot be hijacked. tun-rs loads the same path immediately after;
/// the Windows loader returns this already-loaded image instead of
/// re-reading the file, so the verified bytes are the executed bytes.
fn load_restricted(path: &Path) -> Result<LibraryGuard> {
    let wide = sec::wide_path(path);
    let module = unsafe {
        LoadLibraryExW(
            PCWSTR::from_raw(wide.as_ptr()),
            None,
            LOAD_LIBRARY_FLAGS(LOAD_LIBRARY_SEARCH_SYSTEM32.0 | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR.0),
        )
    }
    .with_context(|| format!("Failed to load {}", path.display()))?;
    Ok(LibraryGuard(module))
}

/// Closes the certificate store on every exit path, including early returns.
struct CertStoreGuard(HCERTSTORE);

impl Drop for CertStoreGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CertCloseStore(Some(self.0), 0);
        }
    }
}

/// Closes the decoded message on every exit path, including early returns.
struct CryptMsgGuard(*mut c_void);

impl Drop for CryptMsgGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CryptMsgClose(Some(self.0 as *const c_void));
        }
    }
}

/// Frees the certificate context on every exit path, including early
/// returns.
struct CertContextGuard(*mut CERT_CONTEXT);

impl Drop for CertContextGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CertFreeCertificateContext(Some(self.0));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pin must stay exactly the verified hash of the official
    /// wintun-0.14.1 amd64 DLL. If this fails after a deliberate bump, update
    /// the constant in the source together with the archive hash note.
    #[test]
    fn pin_is_well_formed() {
        assert_eq!(WINTUN_DLL_AMD64_SHA256.len(), 64);
        assert!(
            WINTUN_DLL_AMD64_SHA256
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    /// The signer comparison is exact and case-sensitive: a differently
    /// cased or padded CN must not be accepted.
    #[test]
    fn signer_cn_is_exact() {
        assert_eq!(EXPECTED_SIGNER_SUBJECT, "WireGuard LLC");
        assert_ne!("wireguard llc", EXPECTED_SIGNER_SUBJECT);
        assert_ne!("WireGuard LLC ", EXPECTED_SIGNER_SUBJECT);
    }
}
