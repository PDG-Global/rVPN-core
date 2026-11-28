//! Shared Win32 security helpers for the route-state hardening (`routes.rs`)
//! and the wintun loader (`wintun.rs`): file attribute checks, well-known
//! SID lookups, and owner/ACL validation against a trusted principal set.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree, WIN32_ERROR};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid,
    GetAce, IsValidSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinCreatorGroupSid, WinCreatorOwnerSid,
    WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_REPARSE_POINT, GetFileAttributesW, INVALID_FILE_ATTRIBUTES,
};
use windows::core::{HRESULT, PCWSTR, PWSTR, w};

/// TrustedInstaller (NT SERVICE\TrustedInstaller) owns and services many
/// OS-managed directories (e.g. it holds full control on C:\Program Files).
/// No WELL_KNOWN_SID_TYPE exists for it, so it is converted from its string
/// form. It is a privileged service SID, not reachable by ordinary
/// user-mode malware.
const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

/// ACCESS_ALLOWED_ACE_TYPE (0x00): the windows crate does not export the
/// ACE type constants, so the one value we filter on is defined here.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;

/// Access-mask bits that let a principal modify a directory or the files in
/// it (add/replace/delete/rename — exactly what a DLL swap needs).
const WRITE_BITS: u32 = 0x1000_0000 // GENERIC_ALL
    | 0x4000_0000 // GENERIC_WRITE
    | 0x0001_0000 // DELETE
    | 0x0004_0000 // WRITE_DAC
    | 0x0008_0000 // WRITE_OWNER
    | 0x0000_0002 // FILE_WRITE_DATA / FILE_ADD_FILE
    | 0x0000_0004 // FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
    | 0x0000_0010 // FILE_WRITE_EA
    | 0x0000_0040 // FILE_DELETE_CHILD
    | 0x0000_0100; // FILE_WRITE_ATTRIBUTES

/// The principals trusted to own privileged state (route_state.json) and to
/// hold write access in directories a DLL is loaded from: SYSTEM and the
/// Administrators group.
pub(crate) fn trusted_system_sids() -> Result<Vec<Vec<u8>>> {
    Ok(vec![
        well_known_sid(WinLocalSystemSid)?,
        well_known_sid(WinBuiltinAdministratorsSid)?,
    ])
}

/// The system set plus TrustedInstaller, which legitimately holds full
/// control on C:\Program Files (where a release build's wintun.dll lives).
pub(crate) fn trusted_installer_sids() -> Result<Vec<Vec<u8>>> {
    let mut sids = trusted_system_sids()?;
    let mut sid = PSID(std::ptr::null_mut());
    unsafe {
        ConvertStringSidToSidW(
            w!("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"),
            &mut sid,
        )
    }
    .with_context(|| format!("failed to convert SID '{TRUSTED_INSTALLER_SID}'"))?;
    // Copy the SID bytes out; the ConvertStringSidToSidW allocation is
    // released immediately after.
    let bytes = unsafe { sid_bytes(sid) }?;
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid.0)));
    }
    sids.push(bytes);
    Ok(sids)
}

/// Byte length of a SID, from its sub-authority count.
fn sid_length(sid: PSID) -> Result<usize> {
    if !unsafe { IsValidSid(sid) }.as_bool() {
        bail!("invalid SID");
    }
    // SAFETY: validity checked above; layout is rev(u8), count(u8) at
    // offsets 0 and 1, authorities start at offset 8.
    let count = unsafe { *(sid.0 as *const u8).add(1) } as usize;
    Ok(8 + 4 * count)
}

/// Copy the bytes of a live SID pointer.
unsafe fn sid_bytes(sid: PSID) -> Result<Vec<u8>> {
    let len = sid_length(sid)?;
    // SAFETY: `sid` points to a valid SID of `len` bytes (checked above).
    Ok(unsafe { std::slice::from_raw_parts(sid.0 as *const u8, len) }.to_vec())
}

/// True when `sid` equals one of the trusted SIDs. EqualSid reports equality
/// as Ok(()) and inequality as Err; the error carries no extra information.
fn sid_in_set(sid: PSID, trusted: &[Vec<u8>]) -> bool {
    trusted
        .iter()
        .any(|t| unsafe { EqualSid(sid, PSID(t.as_ptr() as *mut c_void)) }.is_ok())
}

/// Bytes of a well-known SID (e.g. SYSTEM, Administrators), sized via the
/// required two-call CreateWellKnownSid pattern.
pub(crate) fn well_known_sid(kind: WELL_KNOWN_SID_TYPE) -> Result<Vec<u8>> {
    let mut size = 0u32;
    // Expected to fail with ERROR_INSUFFICIENT_BUFFER while filling `size`.
    let _ = unsafe { CreateWellKnownSid(kind, None, None, &mut size) };
    if size == 0 {
        bail!(
            "CreateWellKnownSid did not report a size for SID type {}",
            kind.0
        );
    }
    let mut sid = vec![0u8; size as usize];
    unsafe {
        CreateWellKnownSid(
            kind,
            None,
            Some(PSID(sid.as_mut_ptr() as *mut c_void)),
            &mut size,
        )
    }
    .context("CreateWellKnownSid failed")?;
    Ok(sid)
}

/// The object's owner SID is one of the trusted principals.
pub(crate) fn owner_is_trusted(path: &Path, trusted: &[Vec<u8>]) -> Result<bool> {
    let wide = wide_path(path);
    let mut owner = PSID(std::ptr::null_mut());
    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let err = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR::from_raw(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut descriptor,
        )
    };
    check(err, "GetNamedSecurityInfoW")?;
    // Frees the security descriptor on every exit path below.
    let _guard = LocalFreeGuard(descriptor.0);
    if owner.0.is_null() {
        bail!("{} has no owner SID", path.display());
    }
    Ok(sid_in_set(owner, trusted))
}

/// DACL check for a directory a privileged file is loaded from: no
/// ACCESS_ALLOWED_ACE may grant write to a principal outside `trusted`.
/// A missing DACL (grants everything to everyone) and an unreadable or
/// invalid SID are refused outright.
pub(crate) fn check_write_acl(dir: &Path, trusted: &[Vec<u8>]) -> Result<()> {
    let wide = wide_path(dir);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let err = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR::from_raw(wide.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut descriptor,
        )
    };
    check(err, "GetNamedSecurityInfoW")?;
    // Frees the security descriptor on every exit path below.
    let _guard = LocalFreeGuard(descriptor.0);
    if dacl.is_null() {
        bail!(
            "{} has no DACL (grants full access to everyone)",
            dir.display()
        );
    }

    // CREATOR OWNER / CREATOR GROUP are placeholders that only bind to the
    // principal creating a child object; they confer write access only on
    // someone who could already create the object through another ACE, so
    // they are not independently trusted or untrusted.
    let meta_sids = [
        well_known_sid(WinCreatorOwnerSid)?,
        well_known_sid(WinCreatorGroupSid)?,
    ];

    // SAFETY: `dacl` is a valid ACL from the call above and outlives the
    // loop (owned by `descriptor`).
    let ace_count = unsafe { (*dacl).AceCount } as u32;
    for index in 0..ace_count {
        let mut ace: *mut c_void = std::ptr::null_mut();
        unsafe { GetAce(dacl, index, &mut ace) }.context("GetAce failed")?;
        // SAFETY: GetAce returned a pointer to a valid ACE inside `dacl`.
        let header = unsafe { &*(ace as *const ACE_HEADER) };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE {
            continue;
        }
        // SAFETY: the header identified an ACCESS_ALLOWED_ACE.
        let ace = unsafe { &*(ace as *const ACCESS_ALLOWED_ACE) };
        if ace.Mask & WRITE_BITS == 0 {
            continue;
        }
        // The SID begins at SidStart (the first DWORD of the embedded SID).
        let sid = PSID(&ace.SidStart as *const u32 as *mut c_void);
        if !unsafe { IsValidSid(sid) }.as_bool() {
            bail!("{} has an ACE with an invalid SID", dir.display());
        }
        if sid_in_set(sid, &meta_sids) {
            continue;
        }
        if sid_in_set(sid, trusted) {
            continue;
        }
        bail!(
            "{} grants write access to untrusted principal {}",
            dir.display(),
            sid_display(sid)
        );
    }
    Ok(())
}

/// Render a SID as "S-1-..." for diagnostics; falls back to a placeholder.
fn sid_display(sid: PSID) -> String {
    let mut text = PWSTR(std::ptr::null_mut());
    if unsafe { ConvertSidToStringSidW(sid, &mut text) }.is_err() {
        return "(unprintable SID)".to_string();
    }
    // SAFETY: `text` is a valid NUL-terminated string from the call above.
    let rendered = unsafe { text.to_string() }.unwrap_or_else(|_| "(unprintable SID)".to_string());
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0 as *mut c_void)));
    }
    rendered
}

/// Attributes of a file system object (fails when it does not exist).
pub(crate) fn get_file_attributes(path: &Path) -> Result<u32> {
    let wide = wide_path(path);
    let attrs = unsafe { GetFileAttributesW(PCWSTR::from_raw(wide.as_ptr())) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Err(windows::core::Error::from_win32())
            .with_context(|| format!("GetFileAttributesW failed for {}", path.display()));
    }
    Ok(attrs)
}

/// True when the object itself is a reparse point (junction, symlink,
/// placeholder file) that could redirect an elevated process elsewhere.
pub(crate) fn is_reparse_point(path: &Path) -> Result<bool> {
    Ok(get_file_attributes(path)? & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0)
}

/// A path reduced to drive/share root components (`C:\`, `\\?\C:\`,
/// `\\server\share\`) names a volume root. A volume root is never a redirect
/// hazard, and some root forms are not queryable at all: the prefix-only
/// `\\?\C:` form fails GetFileAttributesW with ERROR_INVALID_PARAMETER.
fn is_volume_root(path: &Path) -> bool {
    use std::path::Component;
    path.components()
        .all(|c| matches!(c, Component::Prefix(_) | Component::RootDir))
}

/// Every component of `path` must be a real directory or file, never a
/// reparse point. `std::fs::canonicalize` already resolves reparse points
/// once; this re-checks the resolved path at use time, so a junction
/// planted between resolution and use is still caught. Volume roots are
/// exempt (see is_volume_root). Fail closed: a component that cannot be
/// inspected is untrusted and the path is refused, never walked past.
pub(crate) fn check_no_reparse_points(path: &Path) -> Result<()> {
    let mut prefix = std::path::PathBuf::new();
    for component in path.components() {
        prefix.push(component.as_os_str());
        if is_volume_root(&prefix) {
            continue;
        }
        match is_reparse_point(&prefix) {
            Ok(false) => {}
            Ok(true) => bail!("{} is a reparse point/junction", prefix.display()),
            Err(e) => {
                // A component that cannot be inspected is untrusted: refuse
                // rather than proceed past a possible redirect (fail closed).
                bail!(
                    "could not check {} for reparse points: {e:#}",
                    prefix.display()
                );
            }
        }
    }
    Ok(())
}

/// NUL-terminated UTF-16 encoding of a path for the Win32 wide APIs.
pub(crate) fn wide_path(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

pub(crate) fn check(err: WIN32_ERROR, op: &str) -> Result<()> {
    if err == ERROR_SUCCESS {
        Ok(())
    } else {
        // HRESULT::from_win32 keeps the original code for display.
        Err(windows::core::Error::from(HRESULT::from_win32(err.0)))
            .with_context(|| format!("{op} failed (Win32 error {})", err.0))
    }
}

/// Frees a local allocation (security descriptors and string SIDs returned
/// by the Win32 security APIs) on every exit path.
pub(crate) struct LocalFreeGuard(pub *mut c_void);

impl Drop for LocalFreeGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0)));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hardcoded TrustedInstaller string SID must remain well-formed:
    /// sid_display/ConvertStringSidToSidW both depend on it.
    #[test]
    fn trusted_installer_sid_parses() {
        let sids = trusted_installer_sids().unwrap();
        assert_eq!(sids.len(), 3);
        // SYSTEM (S-1-5-18) is 12 bytes, Administrators and TrustedInstaller
        // are larger; all must be valid SID lengths (8 + 4 * count).
        for sid in &sids {
            assert_eq!(sid.len() % 4, 0);
            assert!(sid.len() >= 12);
        }
    }

    /// The write-bits mask must cover the bits a DLL swap actually uses.
    #[test]
    fn write_bits_cover_file_creation_and_rename() {
        // FILE_ADD_FILE, FILE_ADD_SUBDIRECTORY, FILE_DELETE_CHILD, DELETE.
        assert_ne!(WRITE_BITS & 0x0000_0002, 0);
        assert_ne!(WRITE_BITS & 0x0000_0004, 0);
        assert_ne!(WRITE_BITS & 0x0000_0040, 0);
        assert_ne!(WRITE_BITS & 0x0001_0000, 0);
        // Read-only bits must NOT be flagged: FILE_READ_DATA / FILE_LIST_DIRECTORY.
        assert_eq!(WRITE_BITS & 0x0000_0001, 0);
        // FILE_READ_ATTRIBUTES (0x80) and READ_CONTROL (0x20000) neither.
        assert_eq!(WRITE_BITS & 0x0000_0080, 0);
        assert_eq!(WRITE_BITS & 0x0002_0000, 0);
    }

    /// Volume roots are exempt from the reparse-point check: the prefix-only
    /// `\\?\C:` form fails GetFileAttributesW, and a root is never a redirect
    /// hazard. Deeper paths must still be checked.
    #[test]
    fn volume_root_is_skipped() {
        assert!(is_volume_root(Path::new(r"\\?\C:")));
        assert!(is_volume_root(Path::new(r"\\?\C:\")));
        assert!(is_volume_root(Path::new(r"C:\")));
        assert!(is_volume_root(Path::new(r"\\server\share\")));
        assert!(!is_volume_root(Path::new(r"C:\Windows")));
        assert!(!is_volume_root(Path::new(r"\\?\C:\Windows")));
        assert!(!is_volume_root(Path::new(r"\\server\share\dir")));
    }
}
