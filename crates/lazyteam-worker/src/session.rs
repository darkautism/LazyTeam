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
        let metadata_path = self.metadata_path(task_id, role);
        if let Ok(raw) = tokio::fs::read_to_string(&metadata_path).await {
            if let Ok(mut session) = serde_json::from_str::<AgentSession>(&raw) {
                if session.backend == backend {
                    // Backfill historical Pi sessions that predate backend-owned
                    // identities or were persisted without one.
                    if session.backend_session_id.is_none() {
                        if let Some(legacy) = legacy_backend_session_id(backend, task_id, role) {
                            session.backend_session_id = Some(legacy);
                        }
                    }
                    session.last_used_at_unix = now_unix();
                    self.persist(&metadata_path, &session).await?;
                    return Ok(session);
                }
            }
        }

        let data_dir = match role {
            // Keep the historical implementation path so in-flight Pi sessions survive
            // the abstraction rollout.
            SessionRole::Implementation => self.state_dir.join("sessions").join(task_id.to_string()),
            SessionRole::Review => self.state_dir.join("review-sessions").join(task_id.to_string()),
        };
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
        self.persist(&metadata_path, &session).await?;
        Ok(session)
    }

    /// Atomically bind (or re-bind) the opaque backend session ID returned by a
    /// runtime to an existing logical session. The binding is scoped to the
    /// logical (task, role, backend) triple so a backend switch never reuses an
    /// incompatible ID.
    pub async fn bind_backend_session(
        &self,
        task_id: Uuid,
        role: SessionRole,
        backend: &str,
        backend_session_id: &str,
    ) -> anyhow::Result<AgentSession> {
        let backend_session_id = backend_session_id.trim();
        if backend_session_id.is_empty() {
            bail!("backend session ID must not be empty");
        }
        let metadata_path = self.metadata_path(task_id, role);
        if let Ok(raw) = tokio::fs::read_to_string(&metadata_path).await {
            if let Ok(mut session) = serde_json::from_str::<AgentSession>(&raw) {
                if session.backend == backend {
                    session.backend_session_id = Some(backend_session_id.to_string());
                    session.last_used_at_unix = now_unix();
                    self.persist(&metadata_path, &session).await?;
                    return Ok(session);
                }
            }
        }

        let data_dir = match role {
            SessionRole::Implementation => self.state_dir.join("sessions").join(task_id.to_string()),
            SessionRole::Review => self.state_dir.join("review-sessions").join(task_id.to_string()),
        };
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
        self.persist(&metadata_path, &session).await?;
        Ok(session)
    }

    pub async fn release(&self, task_id: Uuid, role: SessionRole) -> anyhow::Result<()> {
        let metadata_path = self.metadata_path(task_id, role);
        let data_dir = if let Ok(raw) = tokio::fs::read_to_string(&metadata_path).await {
            serde_json::from_str::<AgentSession>(&raw).ok().map(|session| session.data_dir)
        } else {
            None
        }.unwrap_or_else(|| match role {
            SessionRole::Implementation => self.state_dir.join("sessions").join(task_id.to_string()),
            SessionRole::Review => self.state_dir.join("review-sessions").join(task_id.to_string()),
        });
        if data_dir.exists() { tokio::fs::remove_dir_all(&data_dir).await?; }
        if metadata_path.exists() { tokio::fs::remove_file(&metadata_path).await?; }
        Ok(())
    }

    fn metadata_path(&self, task_id: Uuid, role: SessionRole) -> PathBuf {
        self.state_dir
            .join("agent-session-index")
            .join(role.as_str())
            .join(format!("{task_id}.json"))
    }

    async fn persist(&self, path: &Path, session: &AgentSession) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() { tokio::fs::create_dir_all(parent).await?; }
        let body = serde_json::to_vec_pretty(session)?;
        tokio::fs::write(path, body).await?;
        Ok(())
    }
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
}
