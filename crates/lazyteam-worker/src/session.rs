use std::{path::{Path, PathBuf}, time::{SystemTime, UNIX_EPOCH}};

use anyhow::Context;
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
    pub backend_session_id: String,
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
        let backend_session_id = match role {
            SessionRole::Implementation => task_id.to_string(),
            SessionRole::Review => format!("review-{task_id}"),
        };
        let session = AgentSession {
            task_id,
            role,
            backend: backend.to_string(),
            backend_session_id,
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
}
