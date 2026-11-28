// Copyright (C) 2024-2025 PDG Global Limited (Hong Kong)
// SPDX-License-Identifier: AGPL-3.0-or-later
//
//! Client admission control for rvpn-server (deny-by-default allow-list).
//!
//! Model (Thomas, #rVPN:#32): an unknown client identity key is refused at
//! the handshake with ONE outward refusal shape for unknown and revoked keys
//! alike — an outsider must never learn whether a key was ever approved.
//! Admission runs only after the client has PROVED it holds its identity key
//! (S1: key-confirmation MAC over the Hello, verified before `check()`).
//! Refused keys are recorded in a pending list (fingerprint + timestamps +
//! attempt count only — **no IP addresses**, in line with the no-logs
//! claims). An operator approves or revokes with the
//! `rvpn-server clients ...` subcommands, which edit a root-0600 allow-list
//! file under an `flock`; the running server reloads it on change without a
//! restart, and revoking drops live sessions via a per-session registration
//! channel plus a background reload task. Rollout: `learn` mode first
//! (admit and record the PROVEN keys already connecting), then `enforce`
//! once the operator has reviewed the learned list. Admin is local only —
//! no network admin API.
//!
//! Failure policy (review round 2): a missing file is fine (empty list);
//! an UNREADABLE or UNPARSEABLE file keeps the last good list in memory,
//! and when the effective mode is `enforce` the server fails CLOSED —
//! refuses every key — rather than falling open to learn.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{oneshot, Mutex};
use tracing::{debug, info, warn};

/// The handshake error code sent for a refused client key (unknown OR
/// revoked — identical either way). Clients map this to their
/// "waiting for approval" state (Victoria, #rVPN:3865ad67).
pub const ADMISSION_REFUSAL_CODE: u16 = rvpn_core::crypto::admission::REFUSAL_CODE;

/// The refusal message body. Fixed and detail-free by design: it must not
/// say anything about which keys exist.
pub const ADMISSION_REFUSAL_MESSAGE: &str = rvpn_core::crypto::admission::REFUSAL_MESSAGE;

/// Cap on pending-list entries (oldest untouched entries are evicted).
const PENDING_CAP: usize = 512;

/// Minimum seconds between pending-record updates for the same key
/// (rate-limits the pending list against handshake spam).
const PENDING_UPDATE_MIN_SECS: u64 = 60;

/// Cap on learned keys. Beyond it, learn mode still admits but records no
/// more (the operator must review and enforce anyway).
const LEARNED_CAP: usize = 4096;

/// Process-wide refusal rate limit (tokens per second, burst 2×): a flood
/// of unknown keys cannot make the server do pending work at line rate.
const REFUSAL_RATE_PER_SEC: f64 = 30.0;

/// Pending-list flush interval (seconds) — the list lives in memory and is
/// persisted periodically, not on every refusal.
const PENDING_FLUSH_SECS: u64 = 30;

/// Minimum fingerprint-prefix length accepted by the admin commands.
pub const MIN_PREFIX_LEN: usize = 16;

/// Operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AdmissionMode {
    /// Admit every key; record PROVEN keys as learned (rollout phase 1).
    Learn,
    /// Admit only approved keys; refuse the rest (rollout phase 2).
    Enforce,
}

/// Parse a config-mode string. Unknown values are a startup ERROR (S7):
/// silently falling back could turn admission off.
pub fn parse_admission_mode(s: &str) -> Result<AdmissionMode, String> {
    match s.to_lowercase().as_str() {
        "enforce" => Ok(AdmissionMode::Enforce),
        "learn" => Ok(AdmissionMode::Learn),
        other => Err(format!(
            "admission.mode '{other}' is not one of: learn, enforce"
        )),
    }
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
    /// Explicitly revoked keys (S6): never re-learned, refused in BOTH
    /// modes. `revoke` adds here; `approve` removes.
    #[serde(default)]
    pub denied: Vec<String>,
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

/// SHA-256 fingerprint of a client identity key, full hex.
pub fn fingerprint_of(identity_key: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(identity_key))
}

/// Short form for display (first 16 hex chars).
pub fn short_fingerprint(fp: &str) -> String {
    fp.chars().take(16).collect()
}

/// Strip control characters from an operator label before printing it
/// (nit: labels must not smuggle terminal escapes into operator output).
fn sanitize_label(label: &str) -> String {
    label.chars().filter(|c| !c.is_control()).collect()
}

// ---------------------------------------------------------------------------
// File handling. Every write: unique temp file (create-new, no-follow) →
// write → fsync → rename → fsync the parent dir. Read-modify-write cycles
// in the CLI hold an flock on `<file>.lock`.
// ---------------------------------------------------------------------------

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// An flock guard for a path's lock file. Lock file is created 0600; the
/// lock releases on drop.
struct FileLock {
    file: fs::File,
}

impl FileLock {
    fn acquire(path: &Path) -> std::io::Result<Self> {
        let lock_path = path.with_extension("lock");
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)?;
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&file);
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let fd = std::os::unix::io::AsRawFd::as_raw_fd(&self.file);
        unsafe { libc::flock(fd, libc::LOCK_UN) };
    }
}

/// Write a file root-0600 atomically: unique temp (create-new, no-follow),
/// fsync, rename, fsync dir. A stale same-name temp can never be followed.
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let n = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp.{}.{}", std::process::id(), n));
    let res = (|| -> std::io::Result<()> {
        {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent() {
            if let Ok(d) = fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

/// Make sure an existing file is 0600 (nit: older temp/audit files may
/// carry looser modes from before this module).
fn tighten_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = fs::metadata(path) {
        let mode = md.permissions().mode() & 0o777;
        if mode != 0o600 {
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
        }
    }
}

/// File identity for change detection: (mtime, length, inode). Catches a
/// same-mtime replacement that mtime-only comparison misses (S3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    mtime: SystemTime,
    len: u64,
    ino: u64,
}

fn stamp_of(path: &Path) -> Option<FileStamp> {
    let md = fs::metadata(path).ok()?;
    Some(FileStamp {
        mtime: md.modified().ok()?,
        len: md.len(),
        ino: md.ino(),
    })
}

enum FileRead<T> {
    Ok(T),
    Missing,
    Corrupt,
}

/// Read a JSON file, distinguishing "missing" (empty default is fine) from
/// "corrupt" (keep the last good list — never silently wipe state, B2).
fn read_json<T: Default + for<'de> Deserialize<'de>>(path: &Path) -> FileRead<T> {
    match fs::read(path) {
        Ok(bytes) => match serde_json::from_slice(&bytes) {
            Ok(v) => FileRead::Ok(v),
            Err(_) => FileRead::Corrupt,
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileRead::Missing,
        Err(_) => FileRead::Corrupt,
    }
}

/// The decision for one handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionDecision {
    /// Key is approved (or mode is learn and the key is not denied).
    Admit,
    /// Key is not approved (or explicitly denied); refuse with the
    /// pending_approval shape.
    Refuse,
}

struct AdmissionState {
    allow: AllowList,
    stamp: Option<FileStamp>,
    /// The allow-list file could not be read/parsed at last attempt; the
    /// in-memory list is the last good one. In enforce mode this fails
    /// closed (B2).
    file_degraded: bool,
    /// fingerprint → live session registrations (revocation drops them).
    sessions: HashMap<String, Vec<(u64, oneshot::Sender<()>)>>,
    next_session_id: u64,
    /// In-memory pending list (flushed periodically, S4).
    pending: Vec<PendingEntry>,
    pending_dirty: bool,
    last_pending_flush: u64,
    /// Process-wide refusal token bucket.
    refusal_tokens: f64,
    refusal_refill_at: u64,
    /// Set when the allow-list file was corrupt at startup: refuse
    /// everything until a good file arrives (Thomas B3). Cleared on the
    /// first successful reload.
    startup_fail_closed: bool,
}

/// A live session's admission registration (S8: drop guard). When it
/// drops, the registration is removed — by id, so ending one session of a
/// key can never kill another of the same key (B3).
pub struct SessionRegistration {
    admission: Admission,
    fingerprint: String,
    id: u64,
    /// Fires with `Ok(())` when a reload revokes the key. `Err(Closed)`
    /// means the registration is stale (already removed) — it must NEVER be
    /// treated as a revocation.
    pub revoke_rx: Option<oneshot::Receiver<()>>,
}

impl Drop for SessionRegistration {
    fn drop(&mut self) {
        let admission = self.admission.clone();
        let fp = std::mem::take(&mut self.fingerprint);
        let id = self.id;
        // tokio::spawn panics outside a runtime context (nit): when there
        // is none — a handler future dropped during shutdown outside the
        // runtime, or a plain test — unregister on a short-lived thread
        // with its own current-thread runtime instead.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                admission.unregister_by_id(&fp, id).await;
            });
        } else {
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .build()
                    .expect("current-thread runtime");
                rt.block_on(admission.unregister_by_id(&fp, id));
            });
        }
    }
}

/// Shared admission controller. Cheap to clone (Arc inside); ONE instance
/// is built in `run_server` and shared by every handler (B1).
#[derive(Clone)]
pub struct Admission {
    inner: Arc<Mutex<AdmissionState>>,
    allow_path: Arc<PathBuf>,
    pending_path: Arc<PathBuf>,
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
        let allow = match read_json::<AllowList>(&allow_file) {
            FileRead::Ok(v) => v,
            _ => AllowList::default(),
        };
        let pending = match read_json::<PendingList>(&pending_file) {
            FileRead::Ok(v) => v.entries,
            _ => Vec::new(),
        };
        tighten_permissions(&allow_file);
        tighten_permissions(&pending_file);
        tighten_permissions(&audit_file);
        // Thomas's recovery-path ask: a REMOVED allow-list is also a
        // noteworthy start — it silently drops every stored approval and
        // mode, so say so loudly.
        if !allow_file.exists() {
            warn!(
                "admission: allow-list {} missing: starting empty in {:?} (any previous approvals and the stored mode are gone)",
                allow_file.display(),
                mode
            );
        }
        let degraded = matches!(read_json::<AllowList>(&allow_file), FileRead::Corrupt);
        if degraded {
            // A corrupt file at startup must not fall back to the config
            // mode: the FILE may have stored `enforce`, and swapping in an
            // empty default would admit everyone (Thomas B3). Fail closed
            // in EVERY mode until a good file arrives. A learn-mode
            // operator recovers by removing the corrupt file: a MISSING
            // file is a clean empty list, not a degraded one.
            warn!(
                "admission: allow-list file {} is unreadable/corrupt at startup; failing CLOSED (refusing every key) until it is readable or removed",
                allow_file.display()
            );
        }
        let startup_fail_closed = degraded;
        Self {
            inner: Arc::new(Mutex::new(AdmissionState {
                allow,
                stamp: stamp_of(&allow_file),
                file_degraded: degraded,
                sessions: HashMap::new(),
                next_session_id: 1,
                pending,
                pending_dirty: false,
                last_pending_flush: now_unix(),
                refusal_tokens: REFUSAL_RATE_PER_SEC,
                refusal_refill_at: now_unix(),
                startup_fail_closed,
            })),
            allow_path: Arc::new(allow_file),
            pending_path: Arc::new(pending_file),
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

    /// Reload the allow-list if the file changed (mtime + length + inode,
    /// S3). Parse errors keep the last good list and mark the file
    /// degraded; a recovered file clears the flag. Revoked live sessions
    /// are dropped (enforce mode).
    pub async fn reload_if_changed(&self) {
        if !self.enabled {
            return;
        }
        let stamp = stamp_of(&self.allow_path);
        let mut st = self.inner.lock().await;
        if stamp == st.stamp {
            return;
        }
        st.stamp = stamp;
        match read_json::<AllowList>(&self.allow_path) {
            FileRead::Ok(new_allow) => {
                if st.file_degraded {
                    info!("admission: allow-list file readable again");
                }
                st.file_degraded = false;
                st.startup_fail_closed = false;
                let mode = self.effective_mode(&new_allow);
                {
                    // Prune live sessions: a key on the DENY list drops in
                    // ANY mode (a revoke must drop sessions in learn too),
                    // and in enforce any key that fell out of the approved
                    // set drops as well.
                    let approved: std::collections::HashSet<&str> = new_allow
                        .clients
                        .iter()
                        .map(|c| c.fingerprint.as_str())
                        .filter(|fp| !new_allow.denied.iter().any(|d| d == fp))
                        .collect();
                    let denied: std::collections::HashSet<&str> =
                        new_allow.denied.iter().map(String::as_str).collect();
                    let mut dropped = Vec::new();
                    st.sessions.retain(|fp, senders| {
                        let drop_it = denied.contains(fp.as_str())
                            || (mode == AdmissionMode::Enforce && !approved.contains(fp.as_str()));
                        if drop_it {
                            dropped.append(senders);
                        }
                        !drop_it
                    });
                    for (_, tx) in dropped {
                        let _ = tx.send(());
                    }
                    debug!("admission: reloaded allow-list, sessions pruned");
                }
                st.allow = new_allow;
            }
            FileRead::Missing => {
                // Missing file = empty list, not an error (operator may
                // start admit-nobody on purpose by writing the file).
                if st.file_degraded {
                    info!("admission: allow-list file removed");
                }
                st.file_degraded = false;
                if self.effective_mode(&AllowList::default()) == AdmissionMode::Enforce
                    || self.config_mode == AdmissionMode::Enforce
                {
                    // Fail closed: with no file in enforce, nobody is
                    // approved — drop every live session.
                    let mut dropped = Vec::new();
                    for (_, senders) in st.sessions.drain() {
                        dropped.extend(senders);
                    }
                    for (_, tx) in dropped {
                        let _ = tx.send(());
                    }
                }
                st.allow = AllowList {
                    mode: st.allow.mode,
                    ..AllowList::default()
                };
            }
            FileRead::Corrupt => {
                if !st.file_degraded {
                    warn!(
                        "admission: allow-list file {} unreadable/corrupt; keeping last good list{}",
                        self.allow_path.display(),
                        if self.effective_mode(&st.allow) == AdmissionMode::Enforce {
                            " and failing closed (enforce)"
                        } else {
                            ""
                        }
                    );
                }
                st.file_degraded = true;
            }
        }
    }

    /// The handshake check. Call only AFTER the client proved it holds its
    /// identity key (S1: the admission MAC verified by the caller), or with
    /// `proven=false` for a legacy client without the capability.
    ///
    /// - Enforce mode: admit approved keys; refuse the rest. A degraded
    ///   allow-list file fails CLOSED here (refuse everything, B2).
    /// - Learn mode: admit everything except denied keys; only PROVEN keys
    ///   are recorded as learned (S1).
    ///
    /// On admit, returns a [`SessionRegistration`] whose receiver fires
    /// with `Ok(())` when a later reload revokes the key.
    pub async fn check(
        &self,
        identity_key: &[u8; 32],
        proven: bool,
    ) -> (AdmissionDecision, Option<SessionRegistration>) {
        if !self.enabled {
            return (AdmissionDecision::Admit, None);
        }
        self.reload_if_changed().await;
        let fp = fingerprint_of(identity_key);
        let mut st = self.inner.lock().await;
        if st.startup_fail_closed {
            // Corrupt file at startup: refuse everyone until a good file
            // arrives (Thomas B3).
            debug!(
                "admission: refusing client key {} (startup fail-closed)",
                short_fingerprint(&fp)
            );
            return (AdmissionDecision::Refuse, None);
        }
        let mode = self.effective_mode(&st.allow);
        let approved = st.allow.clients.iter().any(|c| c.fingerprint == fp)
            && !st.allow.denied.iter().any(|d| d == &fp);
        let denied = st.allow.denied.iter().any(|d| d == &fp);

        let admit = match mode {
            AdmissionMode::Enforce => {
                if st.file_degraded {
                    // Fail closed: without a readable list, approve nobody.
                    false
                } else {
                    // Proof is mandatory in enforce (Thomas B1): without it,
                    // a legacy Hello carrying an approved client's PUBLIC
                    // key would be admitted with no ClientAuth — an oracle
                    // and a TUN-route hijack.
                    approved && proven
                }
            }
            AdmissionMode::Learn => {
                if denied {
                    false
                } else if proven
                    && !approved
                    && !st.file_degraded
                    && st.allow.clients.len() < LEARNED_CAP
                {
                    let entry = AllowedClient {
                        fingerprint: fp.clone(),
                        label: String::new(),
                        approved_at: now_unix(),
                        learned: true,
                    };
                    st.allow.clients.push(entry.clone());
                    let path = (*self.allow_path).clone();
                    // Persist off the async reactor (S4) as a proper
                    // read-modify-write UNDER the flock (Thomas B2).
                    tokio::task::spawn_blocking(move || persist_learned(&path, entry));
                    info!(
                        "admission: learned new client key {}",
                        short_fingerprint(&fp)
                    );
                    true
                } else {
                    true
                }
            }
        };

        if !admit {
            // Global refusal rate limit (S4): beyond it, record nothing and
            // just refuse.
            let now = now_unix();
            if now > st.refusal_refill_at {
                // One second's worth per refill, so the sustained rate is
                // REFUSAL_RATE_PER_SEC — not a 2x burst every window.
                st.refusal_tokens = REFUSAL_RATE_PER_SEC;
                st.refusal_refill_at = now;
            }
            if st.refusal_tokens >= 1.0 {
                st.refusal_tokens -= 1.0;
                // Record the refusal (fingerprint + times + count only — NO
                // IP), in memory; flushed periodically (S4).
                match st.pending.iter_mut().find(|e| e.fingerprint == fp) {
                    Some(e) => {
                        if now.saturating_sub(e.last_seen) >= PENDING_UPDATE_MIN_SECS {
                            e.last_seen = now;
                            e.attempts = e.attempts.saturating_add(1);
                            st.pending_dirty = true;
                        }
                    }
                    None => {
                        if st.pending.len() >= PENDING_CAP {
                            if let Some((idx, _)) = st
                                .pending
                                .iter()
                                .enumerate()
                                .min_by_key(|(_, e)| e.last_seen)
                            {
                                st.pending.remove(idx);
                            }
                        }
                        st.pending.push(PendingEntry {
                            fingerprint: fp.clone(),
                            first_seen: now,
                            last_seen: now,
                            attempts: 1,
                        });
                        st.pending_dirty = true;
                    }
                }
            }
            self.maybe_flush_pending(&mut st);
            debug!(
                "admission: refusing client key {} (pending approval)",
                short_fingerprint(&fp)
            );
            return (AdmissionDecision::Refuse, None);
        }

        // Register the session for revocation drop (by id, B3).
        let id = st.next_session_id;
        st.next_session_id = st.next_session_id.wrapping_add(1);
        let (tx, rx) = oneshot::channel();
        st.sessions.entry(fp.clone()).or_default().push((id, tx));
        let reg = SessionRegistration {
            admission: self.clone(),
            fingerprint: fp,
            id,
            revoke_rx: Some(rx),
        };
        (AdmissionDecision::Admit, Some(reg))
    }

    /// Flush the in-memory pending list if it is due (S4).
    fn maybe_flush_pending(&self, st: &mut AdmissionState) {
        let now = now_unix();
        if !st.pending_dirty || now.saturating_sub(st.last_pending_flush) < PENDING_FLUSH_SECS {
            return;
        }
        let list = PendingList {
            entries: st.pending.clone(),
        };
        let path = (*self.pending_path).clone();
        st.pending_dirty = false;
        st.last_pending_flush = now;
        tokio::task::spawn_blocking(move || {
            if let Ok(_lock) = FileLock::acquire(&path) {
                if let Ok(json) = serde_json::to_vec_pretty(&list) {
                    if let Err(e) = write_private(&path, &json) {
                        warn!("admission: failed to flush pending list: {e}");
                    }
                }
            }
        });
    }

    /// Flush pending unconditionally (shutdown path).
    pub async fn flush_pending(&self) {
        if !self.enabled {
            return;
        }
        let mut st = self.inner.lock().await;
        st.last_pending_flush = 0;
        self.maybe_flush_pending(&mut st);
    }

    /// Remove ONE session registration by id (B3).
    async fn unregister_by_id(&self, fp: &str, id: u64) {
        if !self.enabled {
            return;
        }
        let mut st = self.inner.lock().await;
        if let Some(v) = st.sessions.get_mut(fp) {
            v.retain(|(rid, _)| *rid != id);
            if v.is_empty() {
                st.sessions.remove(fp);
            }
        }
    }

    /// Current counts for the startup log (S7).
    pub async fn startup_summary(&self) -> (AdmissionMode, usize, usize) {
        let st = self.inner.lock().await;
        let learned = st.allow.clients.iter().filter(|c| c.learned).count();
        (
            self.effective_mode(&st.allow),
            st.allow.clients.len(),
            learned,
        )
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// Spawn the background reload task (B1): every 2 seconds, pick up
/// allow-list changes and drop revoked sessions without waiting for a new
/// handshake. Runs for the life of the server.
pub fn spawn_reload_task(admission: Admission) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        let mut ticks = 0u32;
        loop {
            tick.tick().await;
            admission.reload_if_changed().await;
            // A quiet server that refuses nobody still flushes a dirty
            // pending list at least every ~30s (nit).
            ticks += 1;
            if ticks.is_multiple_of(15) {
                admission.flush_pending().await;
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Admin operations (the `rvpn-server clients ...` subcommands). These
// operate directly on the files under an flock; the running server picks
// changes up via the reload. Local only — no network admin surface.
// ---------------------------------------------------------------------------

fn load_allow(path: &Path) -> AllowList {
    match read_json::<AllowList>(path) {
        FileRead::Ok(v) => v,
        FileRead::Missing => AllowList::default(),
        FileRead::Corrupt => {
            eprintln!(
                "rvpn-server: allow-list {} is corrupt; refusing to touch it (fix or remove it manually)",
                path.display()
            );
            std::process::exit(1);
        }
    }
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
    tighten_permissions(path);
}

/// Resolve a fingerprint argument: full 64-char hex, or a unique prefix of
/// at least MIN_PREFIX_LEN hex characters.
fn resolve_fingerprint(
    allow: &AllowList,
    pending: &[PendingEntry],
    arg: &str,
) -> Result<String, String> {
    let arg = arg.to_lowercase();
    if arg.len() == 64 && arg.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(arg);
    }
    if arg.len() < MIN_PREFIX_LEN || !arg.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "'{arg}' is too short or not hex — give at least {MIN_PREFIX_LEN} hex characters"
        ));
    }
    let mut matches: Vec<&str> = allow
        .clients
        .iter()
        .map(|c| c.fingerprint.as_str())
        .chain(pending.iter().map(|e| e.fingerprint.as_str()))
        .chain(allow.denied.iter().map(String::as_str))
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

fn load_pending(path: &Path) -> Vec<PendingEntry> {
    match read_json::<PendingList>(path) {
        FileRead::Ok(v) => v.entries,
        _ => Vec::new(),
    }
}

/// `rvpn-server clients pending` — print the pending list.
/// Persist one learned key as a read-modify-write UNDER the flock:
/// re-read the file and merge, so a concurrent CLI approve/revoke is
/// never overwritten by a stale snapshot (Thomas B2).
fn persist_learned(path: &Path, entry: AllowedClient) {
    if let Ok(_lock) = FileLock::acquire(path) {
        let mut allow = match read_json::<AllowList>(path) {
            FileRead::Ok(a) => a,
            // Missing is a fresh list (create it); corrupt is left
            // strictly alone — the server will learn again once it is
            // readable.
            FileRead::Missing => AllowList::default(),
            FileRead::Corrupt => return,
        };
        if allow
            .clients
            .iter()
            .any(|c| c.fingerprint == entry.fingerprint)
            || allow.denied.iter().any(|d| d == &entry.fingerprint)
        {
            return;
        }
        allow.clients.push(entry);
        if let Ok(json) = serde_json::to_vec_pretty(&allow) {
            if let Err(e) = write_private(path, &json) {
                warn!("admission: failed to persist learned key: {e}");
            }
        }
    }
}

pub fn cmd_pending(pending_path: &Path) -> i32 {
    let entries = load_pending(pending_path);
    if entries.is_empty() {
        println!("no pending client keys");
        return 0;
    }
    for e in &entries {
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
                format!("{} ", sanitize_label(&c.label))
            },
            c.fingerprint,
            c.approved_at,
            origin
        );
    }
    0
}

/// `rvpn-server clients approve <fingerprint> [--label ...]`. Also clears
/// the key from the deny list (S6).
pub fn cmd_approve(
    allow_path: &Path,
    pending_path: &Path,
    audit_path: &Path,
    arg: &str,
    label: Option<&str>,
) -> i32 {
    let _lock = match FileLock::acquire(allow_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("rvpn-server: cannot lock allow-list: {e}");
            return 1;
        }
    };
    let mut allow = load_allow(allow_path);
    let pending = load_pending(pending_path);
    let fp = match resolve_fingerprint(&allow, &pending, arg) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("rvpn-server: {e}");
            return 2;
        }
    };
    allow.denied.retain(|d| d != &fp);
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

/// `rvpn-server clients revoke <fingerprint>` — removes from the allow-list
/// AND adds to the deny list (S6: the key is never re-learned, and revoke
/// therefore works in learn mode too). Live sessions drop within the
/// server's reload interval.
pub fn cmd_revoke(allow_path: &Path, pending_path: &Path, audit_path: &Path, arg: &str) -> i32 {
    let _lock = match FileLock::acquire(allow_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("rvpn-server: cannot lock allow-list: {e}");
            return 1;
        }
    };
    let mut allow = load_allow(allow_path);
    let pending = load_pending(pending_path);
    let fp = match resolve_fingerprint(&allow, &pending, arg) {
        Ok(fp) => fp,
        Err(e) => {
            eprintln!("rvpn-server: {e}");
            return 2;
        }
    };
    let before = allow.clients.len();
    allow.clients.retain(|c| c.fingerprint != fp);
    let was_approved = allow.clients.len() != before;
    if !allow.denied.contains(&fp) {
        allow.denied.push(fp.clone());
    }
    if let Err(e) = save_allow(allow_path, &allow) {
        eprintln!("rvpn-server: failed to write allow-list: {e}");
        return 1;
    }
    audit(audit_path, "revoke", &fp);
    if was_approved {
        println!(
            "revoked {} — live sessions drop within the server's reload interval",
            short_fingerprint(&fp)
        );
    } else {
        println!(
            "denied {} (was not approved; now blocked even in learn mode)",
            short_fingerprint(&fp)
        );
    }
    0
}

/// `rvpn-server clients mode <learn|enforce>` — set the mode in the
/// allow-list file (the running server picks it up without a restart).
/// Warns about learned keys when switching to enforce (S5).
pub fn cmd_set_mode(allow_path: &Path, audit_path: &Path, mode: AdmissionMode) -> i32 {
    let _lock = match FileLock::acquire(allow_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("rvpn-server: cannot lock allow-list: {e}");
            return 1;
        }
    };
    let mut allow = load_allow(allow_path);
    if mode == AdmissionMode::Enforce {
        let learned = allow.clients.iter().filter(|c| c.learned).count();
        if learned > 0 {
            println!(
                "note: {learned} of {} approved keys were auto-learned — review them before enforcing",
                allow.clients.len()
            );
        }
    }
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
        let (d, reg) = a.check(&key, true).await;
        assert_eq!(d, AdmissionDecision::Admit);
        assert!(reg.is_none());
    }

    #[tokio::test]
    async fn learn_records_only_proven_keys() {
        let (dir, a) = tmp_admission(AdmissionMode::Learn);
        let unproven = [2u8; 32];
        let proven = [3u8; 32];
        // Unproven keys are admitted but NOT recorded (S1).
        let (d, _) = a.check(&unproven, false).await;
        assert_eq!(d, AdmissionDecision::Admit);
        let (d, _) = a.check(&proven, true).await;
        assert_eq!(d, AdmissionDecision::Admit);
        // The learned key is persisted on the spawn_blocking write.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let allow = match read_json::<AllowList>(&dir.path().join("clients.json")) {
            FileRead::Ok(v) => v,
            _ => panic!("allow-list should exist"),
        };
        assert_eq!(allow.clients.len(), 1);
        assert!(allow.clients[0].learned);
        assert_eq!(allow.clients[0].fingerprint, fingerprint_of(&proven));
    }

    #[tokio::test]
    async fn enforce_refuses_unknown_and_records_pending() {
        let (_dir, a) = tmp_admission(AdmissionMode::Enforce);
        let key = [4u8; 32];
        let (d, reg) = a.check(&key, true).await;
        assert_eq!(d, AdmissionDecision::Refuse);
        assert!(reg.is_none());
        let st = a.inner.lock().await;
        assert_eq!(st.pending.len(), 1);
        assert_eq!(st.pending[0].fingerprint, fingerprint_of(&key));
        assert_eq!(st.pending[0].attempts, 1);
    }

    #[tokio::test]
    async fn enforce_admits_approved_key() {
        let (dir, a) = tmp_admission(AdmissionMode::Enforce);
        let key = [5u8; 32];
        let fp = fingerprint_of(&key);
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
        let (d, reg) = a.check(&key, true).await;
        assert_eq!(d, AdmissionDecision::Admit);
        assert!(reg.is_some());
    }

    #[tokio::test]
    async fn revoke_drops_the_live_session_and_denies_relearn() {
        let (dir, a) = tmp_admission(AdmissionMode::Enforce);
        let key = [6u8; 32];
        let fp = fingerprint_of(&key);
        cmd_approve(
            &dir.path().join("clients.json"),
            &dir.path().join("pending.json"),
            &dir.path().join("audit.log"),
            &fp,
            None,
        );
        let (d, reg) = a.check(&key, true).await;
        assert_eq!(d, AdmissionDecision::Admit);
        let mut reg = reg.expect("admitted session registers a revocation channel");
        assert_eq!(
            cmd_revoke(
                &dir.path().join("clients.json"),
                &dir.path().join("pending.json"),
                &dir.path().join("audit.log"),
                &fp,
            ),
            0
        );
        // The next reload (triggered by any check) drops the session.
        let other = [9u8; 32];
        let _ = a.check(&other, true).await;
        let mut rx = reg.revoke_rx.take().unwrap();
        match rx.try_recv() {
            Ok(()) => {}
            other => panic!("revoked session must be dropped, got {:?}", other.is_err()),
        }
        // The revoked key is denied: refused even in learn mode (S6).
        let (d, _) = a.check(&key, true).await;
        assert_eq!(d, AdmissionDecision::Refuse);
        let a2 = Admission::new(
            true,
            AdmissionMode::Learn,
            dir.path().join("clients.json"),
            dir.path().join("pending.json"),
            dir.path().join("audit.log"),
        );
        let (d, _) = a2.check(&key, true).await;
        assert_eq!(
            d,
            AdmissionDecision::Refuse,
            "denied key must not be re-learned"
        );
    }

    #[tokio::test]
    async fn ending_one_session_keeps_the_other_of_same_key() {
        // B3: two sessions of one key; ending the first must not drop the
        // second.
        let (dir, a) = tmp_admission(AdmissionMode::Enforce);
        let key = [7u8; 32];
        let fp = fingerprint_of(&key);
        cmd_approve(
            &dir.path().join("clients.json"),
            &dir.path().join("pending.json"),
            &dir.path().join("audit.log"),
            &fp,
            None,
        );
        let (_, reg1) = a.check(&key, true).await;
        let (_, reg2) = a.check(&key, true).await;
        let reg1 = reg1.unwrap();
        let mut reg2 = reg2.unwrap();
        drop(reg1); // ends session 1 (spawned unregister)
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        // Session 2's channel must NOT have fired.
        let mut rx2 = reg2.revoke_rx.take().unwrap();
        assert!(
            matches!(rx2.try_recv(), Err(oneshot::error::TryRecvError::Empty)),
            "ending one session must not revoke the other"
        );
    }

    #[tokio::test]
    async fn corrupt_file_fails_closed_in_enforce() {
        // B2: a corrupt allow-list must not fail open, and must not be
        // rewritten with an empty list.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.json");
        fs::write(&path, b"{not json").unwrap();
        let a = Admission::new(
            true,
            AdmissionMode::Enforce,
            path.clone(),
            dir.path().join("pending.json"),
            dir.path().join("audit.log"),
        );
        let key = [8u8; 32];
        let (d, _) = a.check(&key, true).await;
        assert_eq!(d, AdmissionDecision::Refuse, "corrupt file fails closed");
        // The corrupt content is untouched (no silent wipe).
        assert_eq!(fs::read(&path).unwrap(), b"{not json");
    }

    /// Thomas B1 pin: in enforce, an APPROVED key still needs proof of
    /// possession — a legacy client (proven=false) carrying an approved
    /// client's public key is refused with the same code as an unknown key.
    #[tokio::test]
    async fn enforce_refuses_unproven_even_when_approved() {
        let (dir, a) = tmp_admission(AdmissionMode::Enforce);
        let victim = [42u8; 32];
        cmd_approve(
            &dir.path().join("clients.json"),
            &dir.path().join("pending.json"),
            &dir.path().join("audit.log"),
            &fingerprint_of(&victim),
            None,
        );
        // Proven + approved: admitted.
        let (d, _) = a.check(&victim, true).await;
        assert_eq!(d, AdmissionDecision::Admit);
        // Unproven + approved (the public key is public!): refused.
        let (d, _) = a.check(&victim, false).await;
        assert_eq!(
            d,
            AdmissionDecision::Refuse,
            "enforce must refuse an unproven client even for an approved key"
        );
    }

    /// Thomas B2 pin: the learned-key persist merges into the CURRENT
    /// file under the flock — a CLI revoke that landed after the server's
    /// last reload must survive the write, and a key the CLI denied in
    /// the meantime must not be learned into the file.
    #[tokio::test]
    async fn learn_write_merges_with_concurrent_cli_changes() {
        let (dir, _a) = tmp_admission(AdmissionMode::Learn);
        let revoked_key = [50u8; 32];
        let learned_key = [51u8; 32];
        let allow_path = dir.path().join("clients.json");
        // The CLI revoke lands on disk; the server's in-memory snapshot
        // never sees it (no reload). The persist must still keep it.
        cmd_revoke(
            &allow_path,
            &dir.path().join("pending.json"),
            &dir.path().join("audit.log"),
            &fingerprint_of(&revoked_key),
        );
        persist_learned(
            &allow_path,
            AllowedClient {
                fingerprint: fingerprint_of(&learned_key),
                label: String::new(),
                approved_at: now_unix(),
                learned: true,
            },
        );
        let allow = match read_json::<AllowList>(&allow_path) {
            FileRead::Ok(v) => v,
            _ => panic!("allow-list should exist"),
        };
        assert!(
            allow
                .denied
                .iter()
                .any(|d| d == &fingerprint_of(&revoked_key)),
            "the CLI revoke must survive the concurrent learn write"
        );
        assert!(
            allow
                .clients
                .iter()
                .any(|c| c.fingerprint == fingerprint_of(&learned_key)),
            "the learned key must be persisted"
        );
        // And a key the CLI denied before the write is NOT resurrected as
        // learned.
        persist_learned(
            &allow_path,
            AllowedClient {
                fingerprint: fingerprint_of(&revoked_key),
                label: String::new(),
                approved_at: now_unix(),
                learned: true,
            },
        );
        let allow = match read_json::<AllowList>(&allow_path) {
            FileRead::Ok(v) => v,
            _ => panic!("allow-list should exist"),
        };
        assert!(
            !allow
                .clients
                .iter()
                .any(|c| c.fingerprint == fingerprint_of(&revoked_key)),
            "a denied key must not be learned back into the file"
        );
    }

    /// Thomas B3 pin: a corrupt allow-list at startup fails CLOSED in
    /// every mode — the file may have stored `enforce`, and falling back
    /// to config-learn would admit everyone (the probe scenario).
    #[tokio::test]
    async fn corrupt_file_at_startup_fails_closed_unless_config_learn() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("clients.json");
        fs::write(&path, b"{not json").unwrap();
        // Config says enforce -> refuse everything, even a "known" key.
        let a = Admission::new(
            true,
            AdmissionMode::Enforce,
            path.clone(),
            dir.path().join("pending.json"),
            dir.path().join("audit.log"),
        );
        let (d, _) = a.check(&[60u8; 32], true).await;
        assert_eq!(d, AdmissionDecision::Refuse);
        drop(a);
        // Config says learn but the file is corrupt: STILL closed — the
        // corrupt file may have stored `enforce`, and admitting everyone
        // here was Thomas's probe scenario (B3).
        let a = Admission::new(
            true,
            AdmissionMode::Learn,
            path.clone(),
            dir.path().join("pending.json"),
            dir.path().join("audit.log"),
        );
        let (d, _) = a.check(&[61u8; 32], true).await;
        assert_eq!(
            d,
            AdmissionDecision::Refuse,
            "corrupt file at startup must fail closed in every mode"
        );
        drop(a);
        // The learn-mode recovery path: remove the corrupt file -> a
        // MISSING file is a clean empty list, and learn resumes.
        fs::remove_file(&path).unwrap();
        let a = Admission::new(
            true,
            AdmissionMode::Learn,
            path.clone(),
            dir.path().join("pending.json"),
            dir.path().join("audit.log"),
        );
        let (d, _) = a.check(&[62u8; 32], true).await;
        assert_eq!(d, AdmissionDecision::Admit);
    }

    /// Should-fix pin: revoking a key drops its live session in LEARN
    /// mode too, not just in enforce.
    #[tokio::test]
    async fn revoke_drops_live_session_in_learn_mode() {
        let (dir, a) = tmp_admission(AdmissionMode::Learn);
        let key = [70u8; 32];
        let (d, reg) = a.check(&key, true).await;
        assert_eq!(d, AdmissionDecision::Admit);
        let mut reg = reg.unwrap();
        cmd_revoke(
            &dir.path().join("clients.json"),
            &dir.path().join("pending.json"),
            &dir.path().join("audit.log"),
            &fingerprint_of(&key),
        );
        a.reload_if_changed().await;
        let mut rx = reg.revoke_rx.take().unwrap();
        match rx.try_recv() {
            Ok(()) => {}
            other => panic!(
                "revoked session must drop in learn mode too, got {:?}",
                other.is_err()
            ),
        }
    }

    #[tokio::test]
    async fn unknown_and_revoked_get_one_identical_refusal() {
        let (dir, a) = tmp_admission(AdmissionMode::Enforce);
        let unknown = [10u8; 32];
        let revoked = [11u8; 32];
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
        let (d_unknown, _) = a.check(&unknown, true).await;
        let (d_revoked, _) = a.check(&revoked, true).await;
        assert_eq!(d_unknown, d_revoked);
        assert_eq!(ADMISSION_REFUSAL_CODE, 20);
        assert_eq!(ADMISSION_REFUSAL_MESSAGE, "pending_approval");
        let st = a.inner.lock().await;
        assert_eq!(st.pending.len(), 2);
    }

    #[tokio::test]
    async fn pending_recording_is_rate_limited() {
        let (_dir, a) = tmp_admission(AdmissionMode::Enforce);
        let key = [12u8; 32];
        let _ = a.check(&key, true).await;
        let _ = a.check(&key, true).await;
        let _ = a.check(&key, true).await;
        let st = a.inner.lock().await;
        assert_eq!(st.pending.len(), 1);
        assert_eq!(st.pending[0].attempts, 1);
    }

    #[tokio::test]
    async fn prefix_resolution_requires_16_hex_chars() {
        let (dir, a) = tmp_admission(AdmissionMode::Learn);
        let key = [13u8; 32];
        let _ = a.check(&key, true).await;
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let fp = fingerprint_of(&key);
        // 12-char prefix: refused (too short, nit).
        assert_eq!(
            cmd_revoke(
                &dir.path().join("clients.json"),
                &dir.path().join("pending.json"),
                &dir.path().join("audit.log"),
                &fp[..12],
            ),
            2
        );
        // 16-char unique prefix works.
        assert_eq!(
            cmd_revoke(
                &dir.path().join("clients.json"),
                &dir.path().join("pending.json"),
                &dir.path().join("audit.log"),
                &fp[..16],
            ),
            0
        );
        let audit = fs::read_to_string(dir.path().join("audit.log")).unwrap();
        assert!(audit.contains("revoke"));
        assert!(audit.contains(&fp));
    }

    #[test]
    fn mode_parse_rejects_garbage() {
        assert!(parse_admission_mode("learn").is_ok());
        assert!(parse_admission_mode("enforce").is_ok());
        assert!(
            parse_admission_mode("enfore").is_err(),
            "typo must be a startup error (S7)"
        );
        assert!(parse_admission_mode("").is_err());
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
