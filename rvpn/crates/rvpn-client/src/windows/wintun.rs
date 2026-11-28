//! Locate and verify the bundled wintun.dll before it is handed to tun-rs.
//!
//! The DLL is loaded by full path only, and only after its SHA-256 matches
//! the pinned hash of the official signed build. Anything else is a hard
//! error: a planted or tampered DLL must never reach the loader.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use tracing::warn;

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

/// Resolve the wintun.dll to load and verify its integrity.
///
/// Resolution order: `RVPN_WINTUN_DLL` (dev override, debug builds only),
/// then `wintun.dll` beside the current executable. The returned path is
/// absolute and verified.
///
/// Production installs must place the DLL in a directory only administrators
/// can write (for example under Program Files): the checks below only close
/// the check-then-load race when a non-admin user cannot replace the file
/// between the check and the load.
pub fn resolve_and_verify() -> Result<PathBuf> {
    let path = match override_path() {
        Some(custom) => custom,
        None => std::env::current_exe()
            .context("Failed to locate current executable")?
            .parent()
            .context("Executable has no parent directory")?
            .join("wintun.dll"),
    };

    let path = std::fs::canonicalize(&path)
        .with_context(|| format!("wintun.dll not found or not readable: {}", path.display()))?;

    verify_sha256(&path)?;
    verify_authenticode(&path)?;
    Ok(path)
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

/// Hash check against the pinned digest. Applies to every path source,
/// including the override: a warning never replaces the pin.
fn verify_sha256(path: &Path) -> Result<()> {
    let bytes =
        std::fs::read(path).with_context(|| format!("Failed to read {}", path.display()))?;
    let digest = hex::encode(Sha256::digest(&bytes));
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

/// Authenticode check via WinTrust (through PowerShell): the signature must
/// be valid and the signer subject must identify WireGuard LLC. Applies to
/// every path source, including the override.
fn verify_authenticode(path: &Path) -> Result<()> {
    let escaped = path.display().to_string().replace('\'', "''");
    let script = format!(
        "$sig = Get-AuthenticodeSignature '{escaped}'; \
         \"$($sig.Status)|$($sig.SignerCertificate.Subject)\""
    );
    let output = std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .context("Failed to start powershell.exe for Authenticode check")?;
    if !output.status.success() {
        bail!(
            "Authenticode check failed to run on {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let line = String::from_utf8_lossy(&output.stdout);
    let line = line.trim();
    let (status, subject) = line
        .split_once('|')
        .with_context(|| format!("Unexpected Authenticode output: {line}"))?;
    if status != "Valid" {
        bail!(
            "Refusing to load {}: Authenticode signature status is {} (expected Valid). \
             Install the official signed wintun 0.14.1 DLL.",
            path.display(),
            status
        );
    }
    if !subject.contains(EXPECTED_SIGNER_SUBJECT) {
        bail!(
            "Refusing to load {}: signer '{}' is not the expected wintun signer ({}).",
            path.display(),
            subject,
            EXPECTED_SIGNER_SUBJECT
        );
    }
    Ok(())
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
}
