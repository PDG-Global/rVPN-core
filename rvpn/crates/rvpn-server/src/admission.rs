// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Client admission control for rvpn-server (deny-by-default allow-list).
//!
//! Model (Thomas, #rVPN:#32): an unknown client identity key is refused at
//! the handshake, after the X3DH proof, with ONE outward refusal code for
//! unknown and revoked keys alike — an outsider must never learn whether a
//! key was ever approved. Refused keys are recorded in a pending list
//! (fingerprint + timestamps + attempt count only — **no IP addresses**, in
//! line with the no-logs claims). An operator approves or revokes with the
//! `rvpn-server clients ...` subcommands, which edit a root-0600 allow-list
//! file; the running server reloads it on change without a restart, and
//! revoking drops live sessions. Rollout: `learn` mode first (admit and
//! record the keys already connecting), then `enforce` once the operator has
//! reviewed the learned list. Admin is local only — no network admin API.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, info, warn};

/// The handshake error code sent for a refused client key (unknown OR
/// revoked — identical either way). Clients map this to their
/// "waiting for approval" state (Victoria, #rVPN:3865ad67).
pub const ADMISSION_REFUSAL_CODE: u16 = 20;

/// The refusal message body. Fixed and detail-free by design: it must not
/// say anything about which keys exist.
pub const ADMISSION_REFUSAL_MESSAGE: &str = "pending_approval";

/// Cap on pending-list entries (oldest untouched entries are evicted).
const PENDING_CAP: usize = 512;

/// Minimum seconds between pending-record updates for the same key
/// (rate-limits the pending list against handshake spam).
const PENDING_UPDATE_MIN_SECS: u64 = 60;

/// Operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdmissionMode {
    /// Admit every key and record it as learned (rollout phase 1).
    Learn,
    /// Admit only approved keys; refuse the rest (rollout phase 2).
    Enforce,
}

/// One approved client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowedClient {
    /// Full hex fingerprint (SHA-256 of the identity key).
    pub fingerprint: String,
    /// Operator-set label (e.g. "Frank MiniPC").
    #[serde(default)]
    pub label: String,
    /// Unix time of approval (or of learning in learn mode).
    pub approved_at: u64,
    /// True when recorded by learn mode rather than an explicit approve.
    #[serde(default)]
    pub learned: bool,
}

/// The on-disk allow-list.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AllowList {
    #[serde(default)]
    pub mode: Option<AdmissionMode>,
    #[serde(default)]
    pub clients: Vec<AllowedClient>,
}

/// One refused-key record in the pending list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEntry {
    pub fingerprint: String,
    pub first_seen: u64,
    pub last_seen: u64,
    pub attempts: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PendingList {
    #[serde(default)]
    entries: Vec<PendingEntry>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Parse a config-mode string. Unknown values fall back to learn (the
/// safer rollout mode) with a warning, since refusing every client on a
/// typo is worse.
pub fn parse_admission_mode(s: &str) -> AdmissionMode {
    match s.to_lowercase().as_str() {
        "enforce" => AdmissionMode::Enforce,
        "learn" => AdmissionMode::Learn,
        other => {
            warn!("admission: unknown mode '{other}', falling back to learn");
            AdmissionMode::Learn
        }
    }
}

/// SHA-256 fingerprint of a client identity key, full hex.
pub fn fingerprint_of(identity_key: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(identity_key))
}

/// Short form for display (first 16 hex chars).
pub fn short_fingerprint(fp: &str) -> String {
    fp.chars().take(16).collect()
}

/// Write a file root-0600 atomically (temp file + rename).
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path)?;
    Ok(())
}

fn read_json_or_default<T: Default + for<'de> Deserialize<'de>>(path: &Path) -> T {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => T::default(),
    }
}

/// The decision for one handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Key is approved (or mode is learn and the key was recorded).
    Admit,
    /// Key is not approved; refuse with the pending_approval shape.
    Refuse,
}

struct AdmissionState {
    allow: AllowList,
    mtime: Option<SystemTime>,
    /// fingerprint → session-close senders (revocation drops live sessions).
    sessions: HashMap<String, Vec<oneshot::Sender<()>>>,
}

/// Shared admission controller. Cheap to clone (Arc inside).
#[derive(Clone)]
pub struct Admission {
    inner: Arc<Mutex<AdmissionState>>,
    allow_path: PathBuf,
    pending_path: PathBuf,
    audit_path: PathBuf,
    /// Mode from the config file; the allow-list file's `mode` field (when
    /// set) wins, so operators can flip learn → enforce without a restart.
    config_mode: AdmissionMode,
    /// Admission disabled entirely (default until configured).
    enabled: bool,
}

impl Admission {
    /// Build from config values. `enabled=false` (the default) admits every
    /// key — pre-#32 behaviour, so nothing changes until an operator turns
    /// it on.
    pub fn new(
        enabled: bool,
        mode: AdmissionMode,
        allow_file: PathBuf,
        pending_file: PathBuf,
        audit_file: PathBuf,
    ) -> Self {
        let allow = read_json_or_default::<AllowList>(&allow_file);
        Self {
            inner: Arc::new(Mutex::new(AdmissionState {
                allow,
                mtime: fs::metadata(&allow_file).and_then(|m| m.modified()).ok(),
                sessions: HashMap::new(),
            })),
            allow_path: allow_file,
            pending_path: pending_file,
            audit_path: audit_file,
            config_mode: mode,
            enabled,
        }
    }

    /// An admission controller that admits everything (tests / disabled).
    pub fn disabled() -> Self {
        Self::new(
            false,
            AdmissionMode::Learn,
            PathBuf::new(),
            PathBuf::new(),
            PathBuf::new(),
        )
    }

    /// Effective mode: the allow-list file's `mode` wins over the config.
    fn effective_mode(&self, allow: &AllowList) -> AdmissionMode {
        allow.mode.unwrap_or(self.config_mode)
    }

    /// Reload the allow-list if the file changed; revoke live sessions whose
    /// fingerprint is no longer approved (enforce mode only).
    async fn reload_if_changed(&self) {
        let mtime = fs::metadata(&self.allow_path)
            .and_then(|m| m.modified())
            .ok();
        let mut st = self.inner.lock().await;
        if mtime == st.mtime {
            return;
        }
        st.mtime = mtime;
        let new_allow = read_json_or_default::<AllowList>(&self.allow_path);
        let mode = self.effective_mode(&new_allow);
        if mode == AdmissionMode::Enforce {
            // Drop live sessions whose fingerprint fell out of the list.
            let approved: std::collections::HashSet<&str> = new_allow
                .clients
                .iter()
                .map(|c| c.fingerprint.as_str())
                .collect();
            let mut dropped = Vec::new();
            st.sessions.retain(|fp, senders| {
                if approved.contains(fp.as_str()) {
                    true
                } else {
                    dropped.append(senders);
                    false
                }
            });
            for tx in dropped {
                let _ = tx.send(());
            }
            if !st.sessions.is_empty() || mode == AdmissionMode::Enforce {
                debug!("admission: reloaded allow-list (enforce), sessions pruned");
            }
        }
        st.allow = new_allow;
    }

    /// The handshake check. Call AFTER the X3DH agreement has succeeded, so
    /// only a client that holds its identity key is answered at all.
    ///
    /// - Learn mode: admit, and record the key as learned (once).
    /// - Enforce mode: admit approved keys; refuse the rest, recording the
    ///   refusal in the pending list (rate-limited, capped).
    ///
    /// Returns (decision, revocation receiver). The receiver fires when a
    /// later reload revokes the key; the connection task must drop the
    /// session when it does. `None` receiver when admission is disabled.
    pub async fn check(
        &self,
        identity_key: &[u8; 32],
    ) -> (AdmissionDecision, Option<oneshot::Receiver<()>>) {
        if !self.enabled {
            return (AdmissionDecision::Admit, None);
        }
        self.reload_if_changed().await;
        let fp = fingerprint_of(identity_key);
        let mut st = self.inner.lock().await;
        let mode = self.effective_mode(&st.allow);
        let approved = st.allow.clients.iter().any(|c| c.fingerprint == fp);
        let admit = match mode {
            AdmissionMode::Enforce => approved,
            AdmissionMode::Learn => {
                if !approved {
                    st.allow.clients.push(AllowedClient {
                        fingerprint: fp.clone(),
                        label: String::new(),
                        approved_at: now_unix(),
                        learned: true,
                    });
                    let allow = st.allow.clone();
                    let path = self.allow_path.clone();
                    drop(st);
                    if let Ok(json) = serde_json::to_vec_pretty(&allow) {
                        if let Err(e) = write_private(&path, &json) {
                            warn!("admission: failed to persist learned key: {e}");
                        }
                    }
                    st = self.inner.lock().await;
                    info!(
                        "admission: learned new client key {}",
                        short_fingerprint(&fp)
                    );
                }
                true
            }
        };
        if !admit {
            // Record the refusal (fingerprint + times + count only — NO IP).
            let mut pending = read_json_or_default::<PendingList>(&self.pending_path);
            let now = now_unix();
            let mut dirty = false;
            match pending.entries.iter_mut().find(|e| e.fingerprint == fp) {
                Some(e) => {
                    if now.saturating_sub(e.last_seen) >= PENDING_UPDATE_MIN_SECS {
                        e.last_seen = now;
                        e.attempts = e.attempts.saturating_add(1);
                        dirty = true;
                    }
                }
                None => {
                    if pending.entries.len() >= PENDING_CAP {
                        // Evict the entry with the oldest last_seen.
                        if let Some((idx, _)) = pending
                            .entries
                            .iter()
                            .enumerate()
                            .min_by_key(|(_, e)| e.last_seen)
                        {
                            pending.entries.remove(idx);
                        }
                    }
                    pending.entries.push(PendingEntry {
                        fingerprint: fp.clone(),
                        first_seen: now,
                        last_seen: now,
                        attempts: 1,
                    });
                    dirty = true;
                }
            }
            if dirty {
                if let Ok(json) = serde_json::to_vec_pretty(&pending) {
                    if let Err(e) = write_private(&self.pending_path, &json) {
                        warn!("admission: failed to persist pending list: {e}");
                    }
                }
            }
            debug!(
                "admission: refusing client key {} (pending approval)",
                short_fingerprint(&fp)
            );
            return (AdmissionDecision::Refuse, None);
        }
        // Register the session for revocation drop.
        let (tx, rx) = oneshot::channel();
        st.sessions.entry(fp).or_default().push(tx);
        (AdmissionDecision::Admit, Some(rx))
    }

    /// Forget a session's registration (call when the connection ends).
    pub async fn unregister(&self, identity_key: &[u8; 32]) {
        if !self.enabled {
            return;
        }
        let fp = fingerprint_of(identity_key);
        let mut st = self.inner.lock().await;
        if let Some(v) = st.sessions.get_mut(&fp) {
            v.pop();
            if v.is_empty() {
                st.sessions.remove(&fp);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Admin operations (the `rvpn-server clients ...` subcommands). These operate
// directly on the files; the running server picks changes up via the mtime
// reload. Local only — no network admin surface.
// ---------------------------------------------------------------------------

fn load_allow(path: &Path) -> AllowList {
    read_json_or_default(path)
}

fn save_allow(path: &Path, allow: &AllowList) -> std::io::Result<()> {
    let json = serde_json::to_vec_pretty(allow)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    write_private(path, &json)
}

fn audit(path: &Path, action: &str, fingerprint: &str) {
    let line = format!("{} {} {}\n", now_unix(), action, fingerprint);
    let res = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .and_then(|mut f| f.write_all(line.as_bytes()));
    if let Err(e) = res {
        warn!("admission: audit log write failed: {e}");
    }
}

/// Resolve a fingerprint argument: full 64-char hex, or a unique prefix.
fn resolve_fingerprint(
    allow: &AllowList,
    pending: &[PendingEntry],
    arg: &str,
) -> Result<String, String> {
    let arg = arg.to_lowercase();
    if arg.len() == 64 && arg.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(arg);
    }
    let mut matches: Vec<&str> = allow
        .clients
        .iter()
        .map(|c| c.fingerprint.as_str())
        .chain(pending.iter().map(|e| e.fingerprint.as_str()))
        .filter(|fp| fp.starts_with(&arg))
        .collect();
    matches.sort_unstable();
    matches.dedup();
    match matches.len() {
        0 => Err(format!("no known client key matches '{arg}'")),
        1 => Ok(matches[0].to_string()),
        n => Err(format!(
            "'{arg}' matches {n} client keys — use a longer prefix"
        )),
    }
}

/// `rvpn-server clients pending` — print the pending list.
pub fn cmd_pending(pending_path: &Path) -> i32 {
    let pending = read_json_or_default::<PendingList>(pending_path);
    if pending.entries.is_empty() {
        println!("no pending client keys");
        return 0;
    }
    for e in &pending.entries {
        println!(
            "{}  first={} last={} attempts={}",
            short_fingerprint(&e.fingerprint),
            e.first_seen,
            e.last_seen,
            e.attempts
        );
    }
    0
}

/// `rvpn-server clients list` — print the approved list.
pub fn cmd_list(allow_path: &Path) -> i32 {
    let allow = load_allow(allow_path);
    if allow.clients.is_empty() {
        println!("no approved client keys");
        return 0;
    }
    for c in &allow.clients {
        let origin = if c.learned { "learned" } else { "approved" };
        println!(
            "{}  {}{} at {} ({})",
            short_fingerprint(&c.fingerprint),
            if c.label.is_empty() {
                String::new()
            } else {
                format!("{} ", c.label)
            },
            c.fingerprint,
            c.approved_at,
            origin
        );
    }
    0
}

/// `rvpn-server clients approve <fingerprint> [--label ...]`.
pub fn cmd_approve(
    allow_path: &Path,
    pending_path: &Path,
    audit_path: &Path,
    arg: &str,
    label: Option<&str>,
) -> i32 {
    let mut allow = load_allow(allow_path);
    let pending = read_json_or_default::<PendingList>(pending_path);
    let fp = match resolve_fingerprint(&allow, &pending.entries, arg) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("rvpn-server: {e}");
            return 2;
        }
    };
    if allow.clients.iter().any(|c| c.fingerprint == fp) {
        println!("already approved: {}", short_fingerprint(&fp));
        return 0;
    }
    allow.clients.push(AllowedClient {
        fingerprint: fp.clone(),
        label: label.unwrap_or_default().to_string(),
        approved_at: now_unix(),
        learned: false,
    });
    if let Err(e) = save_allow(allow_path, &allow) {
        eprintln!("rvpn-server: failed to write allow-list: {e}");
        return 1;
    }
    audit(audit_path, "approve", &fp);
    println!("approved {}", short_fingerprint(&fp));
    0
}

/// `rvpn-server clients revoke <fingerprint>` — removes from the allow-list;
/// the running server drops the live session on its next reload.
pub fn cmd_revoke(allow_path: &Path, pending_path: &Path, audit_path: &Path, arg: &str) -> i32 {
    let mut allow = load_allow(allow_path);
    let pending = read_json_or_default::<PendingList>(pending_path);
    let fp = match resolve_fingerprint(&allow, &pending.entries, arg) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("rvpn-server: {e}");
            return 2;
        }
    };
    let before = allow.clients.len();
    allow.clients.retain(|c| c.fingerprint != fp);
    if allow.clients.len() == before {
        eprintln!(
            "rvpn-server: {} is not an approved client",
            short_fingerprint(&fp)
        );
        return 2;
    }
    if let Err(e) = save_allow(allow_path, &allow) {
        eprintln!("rvpn-server: failed to write allow-list: {e}");
        return 1;
    }
    audit(audit_path, "revoke", &fp);
    println!(
        "revoked {} — live sessions drop on the server's next reload",
        short_fingerprint(&fp)
    );
    0
}

/// `rvpn-server clients mode <learn|enforce>` — set the mode in the
/// allow-list file (the running server picks it up without a restart).
pub fn cmd_set_mode(allow_path: &Path, audit_path: &Path, mode: AdmissionMode) -> i32 {
    let mut allow = load_allow(allow_path);
    allow.mode = Some(mode);
    if let Err(e) = save_allow(allow_path, &allow) {
        eprintln!("rvpn-server: failed to write allow-list: {e}");
        return 1;
    }
    let name = match mode {
        AdmissionMode::Learn => "learn",
        AdmissionMode::Enforce => "enforce",
    };
    audit(audit_path, &format!("mode={name}"), "-");
    println!("admission mode: {name}");
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_admission(mode: AdmissionMode) -> (tempfile::TempDir, Admission) {
        let dir = tempfile::tempdir().unwrap();
        let a = Admission::new(
            true,
            mode,
            dir.path().join("clients.json"),
            dir.path().join("pending.json"),
            dir.path().join("audit.log"),
        );
        (dir, a)
    }

    #[tokio::test]
    async fn disabled_admits_everything() {
        let a = Admission::disabled();
        let key = [1u8; 32];
        let (d, rx) = a.check(&key).await;
        assert_eq!(d, AdmissionDecision::Admit);
        assert!(rx.is_none());
    }

    #[tokio::test]
    async fn learn_mode_admits_and_records() {
        let (dir, a) = tmp_admission(AdmissionMode::Learn);
        let key = [2u8; 32];
        let (d, _rx) = a.check(&key).await;
        assert_eq!(d, AdmissionDecision::Admit);
        let allow = read_json_or_default::<AllowList>(&dir.path().join("clients.json"));
        assert_eq!(allow.clients.len(), 1);
        assert!(allow.clients[0].learned);
        assert_eq!(allow.clients[0].fingerprint, fingerprint_of(&key));
    }

    #[tokio::test]
    async fn enforce_refuses_unknown_and_records_pending() {
        let (dir, a) = tmp_admission(AdmissionMode::Enforce);
        let key = [3u8; 32];
        let (d, rx) = a.check(&key).await;
        assert_eq!(d, AdmissionDecision::Refuse);
        assert!(rx.is_none());
        let pending = read_json_or_default::<PendingList>(&dir.path().join("pending.json"));
        assert_eq!(pending.entries.len(), 1);
        assert_eq!(pending.entries[0].fingerprint, fingerprint_of(&key));
        assert_eq!(pending.entries[0].attempts, 1);
    }

    #[tokio::test]
    async fn enforce_admits_approved_key() {
        let (dir, a) = tmp_admission(AdmissionMode::Enforce);
        let key = [4u8; 32];
        let fp = fingerprint_of(&key);
        // Approve via the admin op (writes the file; the server reloads).
        assert_eq!(
            cmd_approve(
                &dir.path().join("clients.json"),
                &dir.path().join("pending.json"),
                &dir.path().join("audit.log"),
                &fp,
                Some("test device"),
            ),
            0
        );
        let (d, rx) = a.check(&key).await;
        assert_eq!(d, AdmissionDecision::Admit);
        assert!(rx.is_some());
    }

    #[tokio::test]
    async fn revoke_drops_the_live_session() {
        let (dir, a) = tmp_admission(AdmissionMode::Enforce);
        let key = [5u8; 32];
        let fp = fingerprint_of(&key);
        cmd_approve(
            &dir.path().join("clients.json"),
            &dir.path().join("pending.json"),
            &dir.path().join("audit.log"),
            &fp,
            None,
        );
        let (d, rx) = a.check(&key).await;
        assert_eq!(d, AdmissionDecision::Admit);
        let mut rx = rx.expect("admitted session registers a revocation channel");
        assert_eq!(
            cmd_revoke(
                &dir.path().join("clients.json"),
                &dir.path().join("pending.json"),
                &dir.path().join("audit.log"),
                &fp,
            ),
            0
        );
        // The next check (any handshake) triggers the reload that drops the
        // revoked session.
        let other = [9u8; 32];
        let _ = a.check(&other).await;
        assert!(rx.try_recv().is_ok(), "revoked session must be dropped");
        // And the revoked key is refused on a fresh handshake.
        let (d, _) = a.check(&key).await;
        assert_eq!(d, AdmissionDecision::Refuse);
    }

    #[tokio::test]
    async fn prefix_resolution_is_unique() {
        let (dir, a) = tmp_admission(AdmissionMode::Learn);
        let key = [6u8; 32];
        a.check(&key).await;
        let fp = fingerprint_of(&key);
        // A unique prefix resolves (revoke finds the learned key).
        assert_eq!(
            cmd_revoke(
                &dir.path().join("clients.json"),
                &dir.path().join("pending.json"),
                &dir.path().join("audit.log"),
                &fp[..12],
            ),
            0
        );
        // Audit log has the revoke with the full fingerprint.
        let audit = fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(audit.contains("revoke"));
        assert!(audit.contains(&fp));
        // And an unknown prefix fails cleanly.
        assert_eq!(
            cmd_revoke(
                &dir.path().join("clients.json"),
                &dir.path().join("pending.json"),
                &dir.path().join("audit.log"),
                "ffffffffffff",
            ),
            2
        );
    }

    #[tokio::test]
    async fn unknown_and_revoked_get_one_identical_refusal() {
        // Constraint 1 (Thomas): unknown and revoked keys are refused with
        // the SAME outward code and message, so an outsider learns nothing
        // about which keys were ever approved.
        let (dir, a) = tmp_admission(AdmissionMode::Enforce);
        let unknown = [7u8; 32];
        let revoked = [8u8; 32];
        let revoked_fp = fingerprint_of(&revoked);
        cmd_approve(
            &dir.path().join("clients.json"),
            &dir.path().join("pending.json"),
            &dir.path().join("audit.log"),
            &revoked_fp,
            None,
        );
        cmd_revoke(
            &dir.path().join("clients.json"),
            &dir.path().join("pending.json"),
            &dir.path().join("audit.log"),
            &revoked_fp,
        );
        let (d_unknown, _) = a.check(&unknown).await;
        let (d_revoked, _) = a.check(&revoked).await;
        assert_eq!(d_unknown, d_revoked);
        assert_eq!(ADMISSION_REFUSAL_CODE, 20);
        assert_eq!(ADMISSION_REFUSAL_MESSAGE, "pending_approval");
        // Both refusals land in the pending list with identical shape.
        let pending = read_json_or_default::<PendingList>(&dir.path().join("pending.json"));
        assert_eq!(pending.entries.len(), 2);
    }

    #[tokio::test]
    async fn pending_recording_is_rate_limited() {
        let (dir, a) = tmp_admission(AdmissionMode::Enforce);
        let key = [11u8; 32];
        let _ = a.check(&key).await;
        let _ = a.check(&key).await;
        let _ = a.check(&key).await;
        let pending = read_json_or_default::<PendingList>(&dir.path().join("pending.json"));
        // Immediate repeats within the rate window don't bump the counter.
        assert_eq!(pending.entries.len(), 1);
        assert_eq!(pending.entries[0].attempts, 1);
    }

    #[test]
    fn allow_list_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.json");
        save_allow(&path, &AllowList::default()).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(mode.mode() & 0o777, 0o600);
        }
    }
}
