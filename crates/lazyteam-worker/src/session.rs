use std::{
    collections::HashMap,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRole {
    Implementation,
    Review,
}

impl Default for SessionRole {
    fn default() -> Self { Self::Implementation }
}

impl SessionRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Implementation => "implementation",
            Self::Review => "review",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSession {
    pub task_id: Uuid,
    pub role: SessionRole,
    pub backend: String,
    #[serde(default)]
    pub backend_session_id: Option<String>,
    pub data_dir: PathBuf,
    pub last_used_at_unix: u64,
}

/// RAII guard serializing all metadata updates for one logical
/// (task, role). The scheduler holds it across acquire → run → bind so
/// concurrent first runs cannot create duplicate backend sessions and orphan
/// one; direct `acquire` / `bind_backend_session` / `release` calls take it
/// internally for their read-modify-write critical sections.
#[derive(Debug)]
pub struct SessionLock {
    key: (Uuid, SessionRole),
    _guard: tokio::sync::OwnedMutexGuard<()>,
}

#[derive(Debug, Clone)]
pub struct SessionManager {
    state_dir: PathBuf,
    locks: Arc<Mutex<HashMap<(Uuid, SessionRole), Arc<tokio::sync::Mutex<()>>>>>,
}

impl SessionManager {
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self {
            state_dir: state_dir.into(),
            locks: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Hold the (task, role) lock across a full acquire → run → bind sequence
    /// to prevent concurrent retries from creating duplicate backend sessions.
    pub async fn lock_session(&self, task_id: Uuid, role: SessionRole) -> SessionLock {
        let entry = {
            let mut table = self
                .locks
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            table
                .entry((task_id, role))
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let guard = entry.lock_owned().await;
        SessionLock {
            key: (task_id, role),
            _guard: guard,
        }
    }

    fn check_lock(lock: &SessionLock, task_id: Uuid, role: SessionRole) -> anyhow::Result<()> {
        if lock.key == (task_id, role) {
            Ok(())
        } else {
            bail!("session lock covers a different (task, role)");
        }
    }

    pub async fn acquire(&self, task_id: Uuid, role: SessionRole, backend: &str) -> anyhow::Result<AgentSession> {
        let guard = self.lock_session(task_id, role).await;
        self.acquire_with(&guard, task_id, role, backend).await
    }

    pub async fn acquire_with(
        &self,
        lock: &SessionLock,
        task_id: Uuid,
        role: SessionRole,
        backend: &str,
    ) -> anyhow::Result<AgentSession> {
        Self::check_lock(lock, task_id, role)?;
        let backend = backend.trim();
        if backend.is_empty() {
            bail!("backend must not be empty");
        }
        let scoped_path = self.metadata_path(task_id, role, backend);
        if let Some(session) = self.load_matching(&scoped_path, backend).await {
            let mut session = session;
            // Never clobber a bound opaque ID: only backfill Pi's historical
            // caller-chosen ID when no binding exists yet.
            if session.backend_session_id.is_none() {
                if let Some(legacy) = legacy_backend_session_id(backend, task_id, role) {
                    session.backend_session_id = Some(legacy);
                }
            }
            session.last_used_at_unix = now_unix();
            self.persist_atomic(&scoped_path, &session).await?;
            return Ok(session);
        }

        // Adopt a record written before backend scoping (legacy single-record
        // or a previous sanitized-only name) when it belongs to the requested
        // backend. The historical data_dir is kept so in-flight sessions
        // survive without recreation.
        if let Some((session, source)) = self.load_adoptable(task_id, role, backend).await {
            let mut session = session;
            if session.backend_session_id.is_none() {
                if let Some(legacy) = legacy_backend_session_id(backend, task_id, role) {
                    session.backend_session_id = Some(legacy);
                }
            }
            session.last_used_at_unix = now_unix();
            tokio::fs::create_dir_all(&session.data_dir)
                .await
                .with_context(|| format!("create {} session directory", role.as_str()))?;
            self.persist_atomic(&scoped_path, &session).await?;
            if source != scoped_path {
                let _ = tokio::fs::remove_file(&source).await;
            }
            return Ok(session);
        }

        let data_dir = self.data_dir_for(task_id, role, backend);
        tokio::fs::create_dir_all(&data_dir)
            .await
            .with_context(|| format!("create {} session directory", role.as_str()))?;
        let session = AgentSession {
            task_id,
            role,
            backend: backend.to_string(),
            backend_session_id: legacy_backend_session_id(backend, task_id, role),
            data_dir,
            last_used_at_unix: now_unix(),
        };
        self.persist_atomic(&scoped_path, &session).await?;
        Ok(session)
    }

    /// Bind (or re-bind) the opaque backend session ID returned by a runtime
    /// to the logical (task, role, backend) session. Each backend owns an
    /// independent metadata record, so switching backends never overwrites an
    /// unrelated backend's identity. Writes are atomic (temp file + rename)
    /// so concurrent retries never leave partial metadata.
    pub async fn bind_backend_session(
        &self,
        task_id: Uuid,
        role: SessionRole,
        backend: &str,
        backend_session_id: &str,
    ) -> anyhow::Result<AgentSession> {
        let guard = self.lock_session(task_id, role).await;
        self.bind_with(&guard, task_id, role, backend, backend_session_id)
            .await
    }

    pub async fn bind_with(
        &self,
        lock: &SessionLock,
        task_id: Uuid,
        role: SessionRole,
        backend: &str,
        backend_session_id: &str,
    ) -> anyhow::Result<AgentSession> {
        Self::check_lock(lock, task_id, role)?;
        let backend = backend.trim();
        if backend.is_empty() {
            bail!("backend must not be empty");
        }
        let backend_session_id = backend_session_id.trim();
        if backend_session_id.is_empty() {
            bail!("backend session ID must not be empty");
        }
        let scoped_path = self.metadata_path(task_id, role, backend);
        if let Some(mut session) = self.load_matching(&scoped_path, backend).await {
            session.backend_session_id = Some(backend_session_id.to_string());
            session.last_used_at_unix = now_unix();
            self.persist_atomic(&scoped_path, &session).await?;
            return Ok(session);
        }

        // Adopt a matching pre-scoping record (preserving its historical
        // data_dir) rather than abandoning in-flight session data.
        if let Some((mut session, source)) = self.load_adoptable(task_id, role, backend).await {
            session.backend_session_id = Some(backend_session_id.to_string());
            session.last_used_at_unix = now_unix();
            tokio::fs::create_dir_all(&session.data_dir)
                .await
                .with_context(|| format!("create {} session directory", role.as_str()))?;
            self.persist_atomic(&scoped_path, &session).await?;
            if source != scoped_path {
                let _ = tokio::fs::remove_file(&source).await;
            }
            return Ok(session);
        }

        let data_dir = self.data_dir_for(task_id, role, backend);
        tokio::fs::create_dir_all(&data_dir)
            .await
            .with_context(|| format!("create {} session directory", role.as_str()))?;
        let session = AgentSession {
            task_id,
            role,
            backend: backend.to_string(),
            backend_session_id: Some(backend_session_id.to_string()),
            data_dir,
            last_used_at_unix: now_unix(),
        };
        self.persist_atomic(&scoped_path, &session).await?;
        Ok(session)
    }

    /// Remove every backend-scoped record plus any legacy record for this
    /// logical (task, role), along with each record's backend-local data dir.
    /// `release` is intentionally backend-agnostic: cleanup items carry only
    /// (task, role). Unlike earlier revisions, removal and enumeration
    /// failures (other than not-found) are propagated so cleanup is never
    /// acknowledged while data remains.
    pub async fn release(&self, task_id: Uuid, role: SessionRole) -> anyhow::Result<()> {
        let guard = self.lock_session(task_id, role).await;
        self.release_with(&guard, task_id, role).await
    }

    pub async fn release_with(
        &self,
        lock: &SessionLock,
        task_id: Uuid,
        role: SessionRole,
    ) -> anyhow::Result<()> {
        Self::check_lock(lock, task_id, role)?;
        let mut data_dirs: Vec<PathBuf> = Vec::new();
        let mut failures: Vec<String> = Vec::new();

        let scoped_dir = self.scoped_dir(task_id, role);
        match tokio::fs::read_dir(&scoped_dir).await {
            Ok(mut entries) => {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    let path = entry.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("json") {
                        continue;
                    }
                    if let Ok(raw) = tokio::fs::read_to_string(&path).await {
                        if let Ok(session) = serde_json::from_str::<AgentSession>(&raw) {
                            data_dirs.push(session.data_dir);
                        }
                    }
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => failures.push(format!(
                "list {}: {error:#}",
                scoped_dir.display()
            )),
        }

        let legacy_path = self.legacy_metadata_path(task_id, role);
        match tokio::fs::read_to_string(&legacy_path).await {
            Ok(raw) => {
                if let Ok(session) = serde_json::from_str::<AgentSession>(&raw) {
                    data_dirs.push(session.data_dir);
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => failures.push(format!(
                "read {}: {error:#}",
                legacy_path.display()
            )),
        }
        // Fallbacks for records that predate backend scoping or whose
        // metadata was already removed.
        data_dirs.push(match role {
            SessionRole::Implementation => self.state_dir.join("sessions").join(task_id.to_string()),
            SessionRole::Review => self.state_dir.join("review-sessions").join(task_id.to_string()),
        });
        // Best-effort: also cover backend-suffixed dirs from this manager.
        let session_base = match role {
            SessionRole::Implementation => self.state_dir.join("sessions"),
            SessionRole::Review => self.state_dir.join("review-sessions"),
        };
        match tokio::fs::read_dir(&session_base).await {
            Ok(mut entries) => {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    if let Some(name) = entry.file_name().to_str().map(str::to_string) {
                        if name == task_id.to_string() || name.starts_with(&format!("{task_id}.")) {
                            data_dirs.push(entry.path());
                        }
                    }
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => failures.push(format!(
                "list {}: {error:#}",
                session_base.display()
            )),
        }

        for dir in data_dirs {
            if dir.exists() {
                if let Err(error) = tokio::fs::remove_dir_all(&dir).await {
                    if error.kind() != ErrorKind::NotFound {
                        failures.push(format!("remove {}: {error:#}", dir.display()));
                    }
                }
            }
        }
        if scoped_dir.exists() {
            if let Err(error) = tokio::fs::remove_dir_all(&scoped_dir).await {
                if error.kind() != ErrorKind::NotFound {
                    failures.push(format!("remove {}: {error:#}", scoped_dir.display()));
                }
            }
        }
        if legacy_path.exists() {
            if let Err(error) = tokio::fs::remove_file(&legacy_path).await {
                if error.kind() != ErrorKind::NotFound {
                    failures.push(format!("remove {}: {error:#}", legacy_path.display()));
                }
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            bail!("session cleanup incomplete: {}", failures.join("; "))
        }
    }

    /// Load the scoped record only when its embedded backend matches the
    /// requested backend. The filename is a lookup hint; the raw
    /// `session.backend` field is the identity.
    async fn load_matching(&self, path: &Path, backend: &str) -> Option<AgentSession> {
        let raw = tokio::fs::read_to_string(path).await.ok()?;
        let session = serde_json::from_str::<AgentSession>(&raw).ok()?;
        (session.backend == backend).then_some(session)
    }

    /// Adoptable pre-scoping records: the legacy single-record file and the
    /// previous sanitized-only name. Returns the record plus the path it was
    /// read from so the caller can migrate it.
    async fn load_adoptable(
        &self,
        task_id: Uuid,
        role: SessionRole,
        backend: &str,
    ) -> Option<(AgentSession, PathBuf)> {
        let mut candidates = Vec::new();
        let previous = self.previous_scoped_path(task_id, role, backend);
        let current = self.metadata_path(task_id, role, backend);
        if previous != current {
            candidates.push(previous);
        }
        candidates.push(self.legacy_metadata_path(task_id, role));
        for path in candidates {
            if let Some(session) = self.load_matching(&path, backend).await {
                return Some((session, path));
            }
        }
        None
    }

    fn scoped_dir(&self, task_id: Uuid, role: SessionRole) -> PathBuf {
        self.state_dir
            .join("agent-session-index")
            .join(role.as_str())
            .join(task_id.to_string())
    }

    fn metadata_path(&self, task_id: Uuid, role: SessionRole, backend: &str) -> PathBuf {
        self.scoped_dir(task_id, role)
            .join(format!("{}.json", backend_file_key(backend)))
    }

    /// Previous sanitized-only naming (no hash suffix), checked only as a
    /// migration source for state written before collision-free keys.
    fn previous_scoped_path(&self, task_id: Uuid, role: SessionRole, backend: &str) -> PathBuf {
        self.scoped_dir(task_id, role)
            .join(format!("{}.json", sanitize_backend(backend)))
    }

    fn legacy_metadata_path(&self, task_id: Uuid, role: SessionRole) -> PathBuf {
        self.state_dir
            .join("agent-session-index")
            .join(role.as_str())
            .join(format!("{task_id}.json"))
    }

    fn data_dir_for(&self, task_id: Uuid, role: SessionRole, backend: &str) -> PathBuf {
        let base = match role {
            // Keep the historical implementation path so in-flight Pi sessions
            // survive the abstraction rollout.
            SessionRole::Implementation => self.state_dir.join("sessions"),
            SessionRole::Review => self.state_dir.join("review-sessions"),
        };
        if backend.trim() == "pi" {
            base.join(task_id.to_string())
        } else {
            base.join(format!("{task_id}.{}", backend_file_key(backend)))
        }
    }

    /// Atomic metadata update: serialize fully, write to a unique temp file
    /// in the same directory, then rename over the target. Readers therefore
    /// never observe a truncated record. Callers must hold the session lock
    /// so concurrent read-modify-write cycles cannot lose updates.
    async fn persist_atomic(&self, path: &Path, session: &AgentSession) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let body = serde_json::to_vec_pretty(session)?;
        let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4().as_simple()));
        let result = async {
            tokio::fs::write(&tmp, body).await?;
            tokio::fs::rename(&tmp, path).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&tmp).await;
        }
        result.with_context(|| format!("persist session {}", path.display()))?;
        Ok(())
    }
}

/// Collision-free backend key: a readable sanitized prefix plus an FNV-1a
/// hash of the exact backend string, so distinct backends such as
/// `opencode/foo` and `opencode_foo` never share a metadata file or data
/// directory. The raw backend string (stored in `AgentSession.backend`) is
/// the identity; the key is only a lookup hint. `pi` keeps the bare historic
/// name.
fn backend_file_key(backend: &str) -> String {
    let backend = backend.trim();
    if backend == "pi" {
        return "pi".to_string();
    }
    format!("{}-{:016x}", sanitize_backend(backend), fnv1a64(backend))
}

fn fnv1a64(value: &str) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn sanitize_backend(backend: &str) -> String {
    let trimmed = backend.trim();
    let mut out: String = trimmed
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if out.is_empty() {
        out.push_str("backend");
    }
    if out.len() > 64 {
        out.truncate(64);
    }
    out
}

/// Caller-chosen Pi session IDs predate backend-owned identities. Keep
/// fabricating them for new Pi sessions so existing paths survive without
/// migration; every other backend starts unbound and binds the opaque ID its
/// runtime creates.
fn legacy_backend_session_id(backend: &str, task_id: Uuid, role: SessionRole) -> Option<String> {
    if backend != "pi" {
        return None;
    }
    Some(match role {
        SessionRole::Implementation => task_id.to_string(),
        SessionRole::Review => format!("review-{task_id}"),
    })
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn logical_session_is_stable_until_release() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-test-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        let first = manager.acquire(task_id, SessionRole::Review, "pi").await.unwrap();
        let second = manager.acquire(task_id, SessionRole::Review, "pi").await.unwrap();
        assert_eq!(first.backend_session_id, second.backend_session_id);
        assert_eq!(first.data_dir, second.data_dir);
        manager.release(task_id, SessionRole::Review).await.unwrap();
        assert!(!first.data_dir.exists());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn pi_keeps_historical_task_derived_ids() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-pi-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        let implementation = manager.acquire(task_id, SessionRole::Implementation, "pi").await.unwrap();
        assert_eq!(implementation.backend_session_id.as_deref(), Some(task_id.to_string()).as_deref());
        let review = manager.acquire(task_id, SessionRole::Review, "pi").await.unwrap();
        assert_eq!(review.backend_session_id.as_deref(), Some(format!("review-{task_id}")).as_deref());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn non_pi_backend_starts_unbound_then_binds_opaque_id() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-opencode-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        let first = manager.acquire(task_id, SessionRole::Implementation, "opencode").await.unwrap();
        assert_eq!(first.backend_session_id, Option::<String>::None);
        let bound = manager.bind_backend_session(task_id, SessionRole::Implementation, "opencode", "ses_opaque_123").await.unwrap();
        assert_eq!(bound.backend_session_id.as_deref(), Some("ses_opaque_123"));
        assert_eq!(bound.data_dir, first.data_dir);
        let reacquired = manager.acquire(task_id, SessionRole::Implementation, "opencode").await.unwrap();
        assert_eq!(reacquired.backend_session_id.as_deref(), Some("ses_opaque_123"));
        assert_eq!(reacquired.data_dir, first.data_dir);
        // Re-binding a rotated opaque ID updates the same logical session.
        let rebound = manager.bind_backend_session(task_id, SessionRole::Implementation, "opencode", "ses_opaque_456").await.unwrap();
        assert_eq!(rebound.backend_session_id.as_deref(), Some("ses_opaque_456"));
        assert_eq!(rebound.data_dir, first.data_dir);
        manager.release(task_id, SessionRole::Implementation).await.unwrap();
        assert!(!first.data_dir.exists());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn changing_backend_does_not_reuse_incompatible_session_id() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-backend-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        manager.bind_backend_session(task_id, SessionRole::Implementation, "opencode", "ses_opaque_123").await.unwrap();
        let other = manager.acquire(task_id, SessionRole::Implementation, "pi").await.unwrap();
        assert_eq!(other.backend, "pi");
        assert_eq!(other.backend_session_id.as_deref(), Some(task_id.to_string()).as_deref());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn backend_switch_back_recovers_original_opaque_id() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-switch-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        let first = manager.bind_backend_session(task_id, SessionRole::Implementation, "opencode", "ses_opaque_A").await.unwrap();
        // Switching to another backend must not disturb the first binding.
        let pi = manager.acquire(task_id, SessionRole::Implementation, "pi").await.unwrap();
        assert_eq!(pi.backend_session_id.as_deref(), Some(task_id.to_string()).as_deref());
        let other = manager.bind_backend_session(task_id, SessionRole::Implementation, "other", "ses_other_1").await.unwrap();
        assert_eq!(other.backend_session_id.as_deref(), Some("ses_other_1"));
        assert_ne!(other.data_dir, first.data_dir);
        // Switching back recovers the original opaque ID and data dir.
        let back = manager.acquire(task_id, SessionRole::Implementation, "opencode").await.unwrap();
        assert_eq!(back.backend_session_id.as_deref(), Some("ses_opaque_A"));
        assert_eq!(back.data_dir, first.data_dir);
        let back_other = manager.acquire(task_id, SessionRole::Implementation, "other").await.unwrap();
        assert_eq!(back_other.backend_session_id.as_deref(), Some("ses_other_1"));
        assert_eq!(back_other.data_dir, other.data_dir);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn similar_backend_names_never_share_identity_or_data_dir() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-collide-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        // `opencode/foo` and `opencode_foo` sanitize identically but are
        // distinct backends and must not collide.
        assert_ne!(backend_file_key("opencode/foo"), backend_file_key("opencode_foo"));
        let slash = manager.bind_backend_session(task_id, SessionRole::Implementation, "opencode/foo", "ses_slash").await.unwrap();
        let underscore = manager.bind_backend_session(task_id, SessionRole::Implementation, "opencode_foo", "ses_underscore").await.unwrap();
        assert_ne!(slash.data_dir, underscore.data_dir);
        let back_slash = manager.acquire(task_id, SessionRole::Implementation, "opencode/foo").await.unwrap();
        assert_eq!(back_slash.backend_session_id.as_deref(), Some("ses_slash"));
        assert_eq!(back_slash.data_dir, slash.data_dir);
        let back_underscore = manager.acquire(task_id, SessionRole::Implementation, "opencode_foo").await.unwrap();
        assert_eq!(back_underscore.backend_session_id.as_deref(), Some("ses_underscore"));
        assert_eq!(back_underscore.data_dir, underscore.data_dir);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn concurrent_binds_leave_intact_metadata() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-conc-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        // Ensure the logical session exists before concurrent writers arrive.
        let initial = manager.acquire(task_id, SessionRole::Implementation, "opencode").await.unwrap();
        let mut handles = Vec::new();
        for i in 0..16 {
            let manager = manager.clone();
            handles.push(tokio::spawn(async move {
                manager
                    .bind_backend_session(task_id, SessionRole::Implementation, "opencode", &format!("ses_conc_{i:02}"))
                    .await
            }));
        }
        let mut bound_ids = Vec::new();
        for handle in handles {
            let session = handle.await.unwrap().unwrap();
            bound_ids.push(session.backend_session_id.unwrap());
            assert_eq!(session.data_dir, initial.data_dir);
        }
        // The persisted record must be intact JSON holding one of the raced
        // IDs — never a truncation or an empty binding.
        let final_session = manager.acquire(task_id, SessionRole::Implementation, "opencode").await.unwrap();
        let final_id = final_session.backend_session_id.unwrap();
        assert!(bound_ids.iter().any(|id| *id == final_id), "final {final_id} not among raced binds");
        assert_eq!(final_session.data_dir, initial.data_dir);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn concurrent_acquires_share_one_data_dir() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-conc-acq-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        let mut handles = Vec::new();
        for _ in 0..16 {
            let manager = manager.clone();
            handles.push(tokio::spawn(async move {
                manager.acquire(task_id, SessionRole::Review, "opencode").await
            }));
        }
        let mut dirs = Vec::new();
        for handle in handles {
            dirs.push(handle.await.unwrap().unwrap().data_dir);
        }
        assert!(dirs.iter().all(|d| *d == dirs[0]));
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn guarded_first_runs_create_only_one_backend_session() {
        use std::sync::Arc;

        let root = std::env::temp_dir().join(format!("lazyteam-session-guard-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        let created: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let mut handles = Vec::new();
        for i in 0..8 {
            let manager = manager.clone();
            let created = created.clone();
            handles.push(tokio::spawn(async move {
                // Hold the session lock across the whole acquire → create →
                // bind sequence, exactly as the scheduler does around an agent
                // run, so only the first arrival creates a backend session.
                let guard = manager.lock_session(task_id, SessionRole::Implementation).await;
                let session = manager.acquire_with(&guard, task_id, SessionRole::Implementation, "opencode").await.unwrap();
                if session.backend_session_id.is_none() {
                    let new_id = format!("ses_first_{i:02}");
                    created.lock().unwrap().push(new_id.clone());
                    manager.bind_with(&guard, task_id, SessionRole::Implementation, "opencode", &new_id).await.unwrap();
                    new_id
                } else {
                    session.backend_session_id.unwrap()
                }
            }));
        }
        let mut observed = Vec::new();
        for handle in handles {
            observed.push(handle.await.unwrap());
        }
        // Exactly one backend session was created and every retry agrees on it:
        // no orphaned second session exists.
        let created = created.lock().unwrap();
        assert_eq!(created.len(), 1, "expected a single created backend session, got {created:?}");
        assert!(observed.iter().all(|id| *id == created[0]));
        let stored = manager.acquire(task_id, SessionRole::Implementation, "opencode").await.unwrap();
        assert_eq!(stored.backend_session_id.as_deref(), Some(created[0].as_str()));
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn racing_acquires_never_lose_a_bound_id() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-race-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        for _ in 0..10 {
            let task_id = Uuid::new_v4();
            let manager_r = manager.clone();
            let binder = tokio::spawn(async move {
                manager_r.bind_backend_session(task_id, SessionRole::Implementation, "opencode", "ses_racy").await.unwrap();
            });
            let mut acquirers = Vec::new();
            for _ in 0..8 {
                let manager = manager.clone();
                acquirers.push(tokio::spawn(async move {
                    manager.acquire(task_id, SessionRole::Implementation, "opencode").await.unwrap()
                }));
            }
            binder.await.unwrap();
            let mut sessions = Vec::new();
            for handle in acquirers {
                sessions.push(handle.await.unwrap());
            }
            sessions.push(manager.acquire(task_id, SessionRole::Implementation, "opencode").await.unwrap());
            // A stale unbound write must never overwrite the bound ID: every
            // observed record is either still-unbound-from-before-the-bind or
            // the bound ID — and the final state is bound with a stable dir.
            let first_dir = sessions[0].data_dir.clone();
            assert!(sessions.iter().all(|s| s.data_dir == first_dir));
            let final_session = sessions.last().unwrap();
            assert_eq!(final_session.backend_session_id.as_deref(), Some("ses_racy"));
            for session in &sessions {
                match session.backend_session_id.as_deref() {
                    None | Some("ses_racy") => {}
                    Some(other) => panic!("unexpected backend session ID {other}"),
                }
            }
        }
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn legacy_pi_sessions_without_binding_are_backfilled() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-legacy-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        let metadata = root.join("agent-session-index").join("implementation").join(format!("{task_id}.json"));
        if let Some(parent) = metadata.parent() { tokio::fs::create_dir_all(parent).await.unwrap(); }
        let data_dir = root.join("sessions").join(task_id.to_string());
        tokio::fs::create_dir_all(&data_dir).await.unwrap();
        // Simulate a persisted session written before backend-owned IDs existed.
        let legacy = serde_json::json!({
            "task_id": task_id,
            "role": "implementation",
            "backend": "pi",
            "backend_session_id": task_id.to_string(),
            "data_dir": data_dir,
            "last_used_at_unix": 0
        });
        tokio::fs::write(&metadata, serde_json::to_vec_pretty(&legacy).unwrap()).await.unwrap();
        let reacquired = manager.acquire(task_id, SessionRole::Implementation, "pi").await.unwrap();
        assert_eq!(reacquired.backend_session_id.as_deref(), Some(task_id.to_string()).as_deref());
        assert_eq!(reacquired.data_dir, data_dir);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn legacy_record_migrates_without_touching_other_backends() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-migrate-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        // Legacy opencode record written before backend scoping.
        let legacy_path = root.join("agent-session-index").join("implementation").join(format!("{task_id}.json"));
        if let Some(parent) = legacy_path.parent() { tokio::fs::create_dir_all(parent).await.unwrap(); }
        let legacy_dir = root.join("sessions").join(task_id.to_string());
        tokio::fs::create_dir_all(&legacy_dir).await.unwrap();
        let legacy = serde_json::json!({
            "task_id": task_id,
            "role": "implementation",
            "backend": "opencode",
            "backend_session_id": "ses_legacy",
            "data_dir": legacy_dir,
            "last_used_at_unix": 0
        });
        tokio::fs::write(&legacy_path, serde_json::to_vec_pretty(&legacy).unwrap()).await.unwrap();
        // Matching backend adopts the legacy data dir.
        let adopted = manager.acquire(task_id, SessionRole::Implementation, "opencode").await.unwrap();
        assert_eq!(adopted.backend_session_id.as_deref(), Some("ses_legacy"));
        // A different backend gets an independent record and data dir.
        let pi = manager.acquire(task_id, SessionRole::Implementation, "pi").await.unwrap();
        assert_eq!(pi.backend_session_id.as_deref(), Some(task_id.to_string()).as_deref());
        // Original opencode binding still recoverable afterwards.
        let back = manager.acquire(task_id, SessionRole::Implementation, "opencode").await.unwrap();
        assert_eq!(back.backend_session_id.as_deref(), Some("ses_legacy"));
        assert_eq!(back.data_dir, adopted.data_dir);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn bind_rejects_empty_session_ids() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-empty-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        assert!(manager.bind_backend_session(task_id, SessionRole::Implementation, "opencode", "  ").await.is_err());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn lock_rejects_mismatched_task_role() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-lock-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        let guard = manager.lock_session(task_id, SessionRole::Implementation).await;
        assert!(manager.acquire_with(&guard, Uuid::new_v4(), SessionRole::Implementation, "pi").await.is_err());
        assert!(manager.acquire_with(&guard, task_id, SessionRole::Review, "pi").await.is_err());
        assert!(manager.bind_with(&guard, task_id, SessionRole::Review, "pi", "ses_x").await.is_err());
        assert!(manager.release_with(&guard, task_id, SessionRole::Review).await.is_err());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn cleanup_removes_bound_session_data() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-cleanup-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        let bound = manager.bind_backend_session(task_id, SessionRole::Review, "opencode", "ses_cleanup").await.unwrap();
        assert!(bound.data_dir.exists());
        manager.release(task_id, SessionRole::Review).await.unwrap();
        assert!(!bound.data_dir.exists());
        let reacquired = manager.acquire(task_id, SessionRole::Review, "opencode").await.unwrap();
        assert_eq!(reacquired.backend_session_id, Option::<String>::None);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn cleanup_removes_all_backends_for_task_role() {
        let root = std::env::temp_dir().join(format!("lazyteam-session-cleanup-all-{}", Uuid::new_v4()));
        let manager = SessionManager::new(&root);
        let task_id = Uuid::new_v4();
        let a = manager.bind_backend_session(task_id, SessionRole::Implementation, "opencode", "ses_a").await.unwrap();
        let b = manager.acquire(task_id, SessionRole::Implementation, "pi").await.unwrap();
        assert_ne!(a.data_dir, b.data_dir);
        manager.release(task_id, SessionRole::Implementation).await.unwrap();
        assert!(!a.data_dir.exists());
        assert!(!b.data_dir.exists());
        // Both backends restart unbound/pristine after cleanup.
        let fresh = manager.acquire(task_id, SessionRole::Implementation, "opencode").await.unwrap();
        assert_eq!(fresh.backend_session_id, Option::<String>::None);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn cleanup_propagates_failures() {
        // A state dir that is a regular file makes every metadata and data
        // access fail with a non-NotFound error, which release must report
        // instead of acknowledging cleanup while data remains.
        let file = std::env::temp_dir().join(format!("lazyteam-session-notadir-{}", Uuid::new_v4()));
        tokio::fs::write(&file, b"not a directory").await.unwrap();
        let manager = SessionManager::new(&file);
        let task_id = Uuid::new_v4();
        assert!(manager.acquire(task_id, SessionRole::Implementation, "pi").await.is_err());
        assert!(manager.release(task_id, SessionRole::Implementation).await.is_err());
        let _ = tokio::fs::remove_file(&file).await;
    }
}
