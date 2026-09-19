use std::{path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};

use anyhow::{bail, Context};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone)]
pub struct SessionManager {
    state_dir: PathBuf,
}

impl SessionManager {
    pub fn new(state_dir: impl Into<PathBuf>) -> Self {
        Self { state_dir: state_dir.into() }
    }

    pub async fn acquire(&self, task_id: Uuid, role: SessionRole, backend: &str) -> anyhow::Result<AgentSession> {
        let backend = backend.trim();
        if backend.is_empty() {
            bail!("backend must not be empty");
        }
        let scoped_path = self.metadata_path(task_id, role, backend);
        if let Ok(raw) = tokio::fs::read_to_string(&scoped_path).await {
            if let Ok(mut session) = serde_json::from_str::<AgentSession>(&raw) {
                if session.backend == backend {
                    if session.backend_session_id.is_none() {
                        if let Some(legacy) = legacy_backend_session_id(backend, task_id, role) {
                            session.backend_session_id = Some(legacy);
                        }
                    }
                    session.last_used_at_unix = now_unix();
                    self.persist_atomic(&scoped_path, &session).await?;
                    return Ok(session);
                }
            }
        }

        // Migrate a legacy single-record file (pre-backend-scoping) when it
        // belongs to the requested backend. The historical data_dir is kept
        // so in-flight Pi sessions survive without recreation.
        let legacy_path = self.legacy_metadata_path(task_id, role);
        if let Ok(raw) = tokio::fs::read_to_string(&legacy_path).await {
            if let Ok(mut session) = serde_json::from_str::<AgentSession>(&raw) {
                if session.backend == backend {
                    if session.backend_session_id.is_none() {
                        if let Some(legacy) = legacy_backend_session_id(backend, task_id, role) {
                            session.backend_session_id = Some(legacy);
                        }
                    }
                    session.last_used_at_unix = now_unix();
                    tokio::fs::create_dir_all(&session.data_dir).await.with_context(|| {
                        format!("create {} session directory", role.as_str())
                    })?;
                    self.persist_atomic(&scoped_path, &session).await?;
                    let _ = tokio::fs::remove_file(&legacy_path).await;
                    return Ok(session);
                }
            }
        }

        let data_dir = self.data_dir_for(task_id, role, backend);
        tokio::fs::create_dir_all(&data_dir).await
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
        let backend = backend.trim();
        if backend.is_empty() {
            bail!("backend must not be empty");
        }
        let backend_session_id = backend_session_id.trim();
        if backend_session_id.is_empty() {
            bail!("backend session ID must not be empty");
        }
        let scoped_path = self.metadata_path(task_id, role, backend);
        if let Ok(raw) = tokio::fs::read_to_string(&scoped_path).await {
            if let Ok(mut session) = serde_json::from_str::<AgentSession>(&raw) {
                if session.backend == backend {
                    session.backend_session_id = Some(backend_session_id.to_string());
                    session.last_used_at_unix = now_unix();
                    self.persist_atomic(&scoped_path, &session).await?;
                    return Ok(session);
                }
            }
        }

        // Adopt a matching legacy record (preserving its historical data_dir)
        // rather than abandoning in-flight session data.
        let legacy_path = self.legacy_metadata_path(task_id, role);
        if let Ok(raw) = tokio::fs::read_to_string(&legacy_path).await {
            if let Ok(mut session) = serde_json::from_str::<AgentSession>(&raw) {
                if session.backend == backend {
                    session.backend_session_id = Some(backend_session_id.to_string());
                    session.last_used_at_unix = now_unix();
                    tokio::fs::create_dir_all(&session.data_dir).await.with_context(|| {
                        format!("create {} session directory", role.as_str())
                    })?;
                    self.persist_atomic(&scoped_path, &session).await?;
                    let _ = tokio::fs::remove_file(&legacy_path).await;
                    return Ok(session);
                }
            }
        }

        let data_dir = self.data_dir_for(task_id, role, backend);
        tokio::fs::create_dir_all(&data_dir).await
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
    /// (task, role).
    pub async fn release(&self, task_id: Uuid, role: SessionRole) -> anyhow::Result<()> {
        let mut data_dirs: Vec<PathBuf> = Vec::new();

        let scoped_dir = self.scoped_dir(task_id, role);
        if let Ok(mut entries) = tokio::fs::read_dir(&scoped_dir).await {
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

        let legacy_path = self.legacy_metadata_path(task_id, role);
        if let Ok(raw) = tokio::fs::read_to_string(&legacy_path).await {
            if let Ok(session) = serde_json::from_str::<AgentSession>(&raw) {
                data_dirs.push(session.data_dir);
            }
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
        if let Ok(mut entries) = tokio::fs::read_dir(&session_base).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Some(name) = entry.file_name().to_str().map(str::to_string) {
                    if name == task_id.to_string() || name.starts_with(&format!("{task_id}.")) {
                        data_dirs.push(entry.path());
                    }
                }
            }
        }

        for dir in data_dirs {
            if dir.exists() {
                let _ = tokio::fs::remove_dir_all(&dir).await;
            }
        }
        if scoped_dir.exists() {
            let _ = tokio::fs::remove_dir_all(&scoped_dir).await;
        }
        if legacy_path.exists() {
            let _ = tokio::fs::remove_file(&legacy_path).await;
        }
        Ok(())
    }

    fn scoped_dir(&self, task_id: Uuid, role: SessionRole) -> PathBuf {
        self.state_dir
            .join("agent-session-index")
            .join(role.as_str())
            .join(task_id.to_string())
    }

    fn metadata_path(&self, task_id: Uuid, role: SessionRole, backend: &str) -> PathBuf {
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
        if backend == "pi" {
            base.join(task_id.to_string())
        } else {
            base.join(format!("{task_id}.{}", sanitize_backend(backend)))
        }
    }

    /// Atomic, concurrency-safe metadata update: serialize fully, write to a
    /// unique temp file in the same directory, then rename over the target.
    /// Readers therefore never observe a truncated record, and concurrent
    /// writers resolve to last-writer-wins with an intact document.
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
}
