// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// This file is part of R-VPN.
//
// R-VPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

//! Private key-file validation and atomic persistence.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{bail, Context, Result};
use rvpn_core::crypto::{IdentityKey, X3DHResponder};

use crate::config::ServerConfig;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Reject private key files that other users can read or write.
pub fn require_private_file(path: &Path) -> Result<()> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("Cannot read private key file metadata for {path:?}"))?;
    if !metadata.is_file() {
        bail!("Private key file {path:?} is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            bail!(
                "Private key file {path:?} has mode {:04o}; run `chmod 600 {:?}` before restarting",
                mode & 0o777,
                path
            );
        }
    }
    Ok(())
}

/// Load an identity key only after validating its file permissions.
pub fn load_identity(path: &Path) -> Result<IdentityKey> {
    require_private_file(path)?;
    IdentityKey::load(path).with_context(|| {
        format!(
            "Cannot load identity key {path:?}; generate a replacement with `rvpn-server keygen --output {path:?}`"
        )
    })
}

/// Load the identity and deterministic signed prekey required by every handler.
pub fn load_responder(config: &ServerConfig) -> Result<X3DHResponder> {
    let identity = load_identity(&config.identity_key_file)?;
    let bundle_path = config.prekey_bundle_file.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "server.prekey_bundle_file is required; generate one with `rvpn-server prekey-bundle --identity {:?} --output <bundle.json>`",
            config.identity_key_file
        )
    })?;
    let private_path = bundle_path.with_extension("private.json");
    let signed_prekey = match load_signed_prekey(&private_path) {
        Ok(key) => key,
        Err(error) if private_path.exists() => return Err(error),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "Signed prekey is missing; generate it with `rvpn-server prekey-bundle --identity {:?} --output {:?}`",
                    config.identity_key_file,
                    bundle_path
                )
            });
        }
    };
    Ok(X3DHResponder::from_identity_with_bundle(
        identity,
        signed_prekey,
    ))
}

/// Load a signed prekey only after validating its file permissions.
pub fn load_signed_prekey(path: &Path) -> Result<[u8; 32]> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};

    require_private_file(path)?;
    let contents = fs::read_to_string(path)
        .with_context(|| format!("Cannot read signed prekey file {path:?}"))?;
    #[derive(serde::Deserialize)]
    struct PrivateKeyJson {
        signed_prekey_private: String,
    }
    let private: PrivateKeyJson = serde_json::from_str(&contents)
        .with_context(|| format!("Cannot parse signed prekey file {path:?}"))?;
    let decoded = BASE64
        .decode(private.signed_prekey_private)
        .context("Cannot decode signed_prekey_private as base64")?;
    if decoded.len() != 32 {
        bail!(
            "signed_prekey_private must be 32 bytes, got {}",
            decoded.len()
        );
    }
    let mut key = [0; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Write a file atomically with owner-only permissions.
pub fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("Private key output path {path:?} has no filename"))?;
    let temporary = temporary_path(parent, name);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("Cannot create private key file {temporary:?}"))?;
    if let Err(error) = write_and_publish(&mut file, &temporary, path, contents) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

fn temporary_path(parent: &Path, name: &std::ffi::OsStr) -> PathBuf {
    let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut temporary = name.to_owned();
    temporary.push(format!(".{}.{}.tmp", std::process::id(), sequence));
    parent.join(temporary)
}

fn write_and_publish(
    file: &mut fs::File,
    temporary: &Path,
    destination: &Path,
    contents: &[u8],
) -> Result<()> {
    file.write_all(contents)
        .with_context(|| format!("Cannot write private key file {temporary:?}"))?;
    file.sync_all()
        .with_context(|| format!("Cannot sync private key file {temporary:?}"))?;
    fs::rename(temporary, destination)
        .with_context(|| format!("Cannot atomically publish private key file {destination:?}"))?;
    let parent = destination
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::File::open(parent)
        .with_context(|| format!("Cannot open private key directory {parent:?}"))?
        .sync_all()
        .with_context(|| format!("Cannot sync private key directory {parent:?}"))?;
    Ok(())
}

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_creates_owner_only_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.key");
        atomic_write_private(&path, b"secret").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"secret");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_group_readable_private_file() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.key");
        atomic_write_private(&path, b"secret").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let error = require_private_file(&path).unwrap_err().to_string();
        assert!(error.contains("chmod 600"));
    }

    #[test]
    fn missing_prekey_stops_startup() {
        let directory = tempfile::tempdir().unwrap();
        let mut config = ServerConfig::default();
        crate::tests::fixtures::configure_test_keys(&mut config, directory.path());
        fs::remove_file(
            config
                .prekey_bundle_file
                .as_ref()
                .unwrap()
                .with_extension("private.json"),
        )
        .unwrap();
        let error = match load_responder(&config) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("startup unexpectedly succeeded"),
        };
        assert!(error.contains("Signed prekey is missing"));
    }

    #[cfg(unix)]
    #[test]
    fn insecure_prekey_suggests_chmod_not_regeneration() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let mut config = ServerConfig::default();
        crate::tests::fixtures::configure_test_keys(&mut config, directory.path());
        let private_path = config
            .prekey_bundle_file
            .as_ref()
            .unwrap()
            .with_extension("private.json");
        fs::set_permissions(&private_path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = match load_responder(&config) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("startup unexpectedly succeeded"),
        };
        assert!(error.contains("chmod 600"));
        assert!(!error.contains("prekey-bundle --identity"));
    }

    #[cfg(unix)]
    #[test]
    fn insecure_identity_stops_startup() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let mut config = ServerConfig::default();
        crate::tests::fixtures::configure_test_keys(&mut config, directory.path());
        fs::set_permissions(&config.identity_key_file, fs::Permissions::from_mode(0o644)).unwrap();
        let error = match load_responder(&config) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("startup unexpectedly succeeded"),
        };
        assert!(error.contains("chmod 600"));
    }
}
