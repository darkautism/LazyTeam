use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use chrono::Utc;
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::{ApiError, AppState};

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct TaskTransition {
    pub task_id: Uuid,
    pub state: String,
}

#[derive(Debug, Deserialize, Default)]
struct RetryRequest {
    reason: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct MergedRequest {
    merge_commit_sha: String,
}

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/tasks/{id}/retry", post(retry_task_http))
        .route("/api/tasks/{id}/merged", post(merged_task_http))
}

async fn retry_task_http(
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<TaskTransition>, ApiError> {
    let input = if body.is_empty() {
        RetryRequest::default()
    } else {
        serde_json::from_slice(&body).map_err(|error| (StatusCode::BAD_REQUEST, format!("invalid retry JSON: {error}")))?
    };
    retry_task(&state, id, input.reason.as_deref()).await.map(Json)
}

async fn merged_task_http(
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
    body: Bytes,
) -> Result<Json<TaskTransition>, ApiError> {
    let input = if body.is_empty() {
        MergedRequest::default()
    } else {
        serde_json::from_slice(&body).map_err(|error| (StatusCode::BAD_REQUEST, format!("invalid merged JSON: {error}")))?
    };
    merged_task(&state, id, &input.merge_commit_sha).await.map(Json)
}

pub(crate) async fn merged_task(state: &AppState, id: Uuid, merge_commit_sha: &str) -> Result<TaskTransition, ApiError> {
    let merge_commit_sha = merge_commit_sha.trim();
    if merge_commit_sha.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "merge_commit_sha is required before cleanup can begin".into()));
    }
    let latest: Option<(String, String)> = sqlx::query("SELECT id,worker_id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(id.to_string()).fetch_optional(&state.db).await.map_err(internal)?
        .map(|row| (row.try_get("id").unwrap_or_default(), row.try_get("worker_id").unwrap_or_default()));
    let Some((latest_execution_id, worker_id)) = latest.filter(|(_, w)| !w.is_empty()) else {
        return Err((StatusCode::CONFLICT, "task has no execution to clean up".into()));
    };
    // Durable gate detail: compare the published commit against the reviewed
    // candidate so Insights can separate clean fast-forwards from merges that
    // required reconciling an upstream that moved after review.
    let result_raw: Option<Option<String>> = sqlx::query_scalar("SELECT result FROM executions WHERE id=?")
        .bind(&latest_execution_id).fetch_optional(&state.db).await.map_err(internal)?;
    let candidate_sha: Option<String> = result_raw.flatten()
        .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
        .and_then(|value| value.get("commit_sha").and_then(|v| v.as_str()).map(str::to_string));
    let approved_integration: Option<(String, Option<String>)> = sqlx::query("SELECT integration_sha,upstream_sha FROM reviews WHERE task_id=? AND execution_id=? AND state='completed' AND integration_sha IS NOT NULL AND (verdict LIKE '%\"verdict\":\"approve\"%' OR verdict LIKE '%\"verdict\": \"approve\"%') ORDER BY finished_at DESC LIMIT 1")
        .bind(id.to_string()).bind(&latest_execution_id).fetch_optional(&state.db).await.map_err(internal)?
        .and_then(|row| {
            let integration: Option<String> = row.try_get("integration_sha").ok()?;
            integration.map(|sha| (sha, row.try_get("upstream_sha").ok().flatten()))
        });
    let now = Utc::now().to_rfc3339();
    // A merge commit that the reviewer explicitly saw is a normal reviewed
    // merge even when it is not the original implementation candidate. Only
    // a publish commit beyond that approved integration is an upstream move
    // after review.
    let (gate_kind, gate_reason) = match (candidate_sha.as_deref(), approved_integration.as_ref()) {
        (Some(candidate), _) if candidate == merge_commit_sha => ("merged", "fast-forward of reviewed candidate".to_string()),
        (_, Some((integration, upstream))) if integration == merge_commit_sha => (
            "merged",
            format!("published reviewed integration against upstream {}", upstream.as_deref().unwrap_or("unknown")),
        ),
        (Some(candidate), _) => ("upstream_moved", format!("upstream moved after review of {candidate}; host published {merge_commit_sha}")),
        (None, _) => ("merged", format!("host published {merge_commit_sha}")),
    };
    let gate_reason: String = gate_reason.chars().take(2000).collect();
    let gate_available = gate_table_exists(&state.db).await;
    let mut tx = state.db.begin().await.map_err(internal)?;
    let changed = sqlx::query("UPDATE tasks SET state='done',merge_commit_sha=?,sticky_worker_id=NULL,updated_at=? WHERE id=? AND state='merge_pending'")
        .bind(merge_commit_sha)
        .bind(&now).bind(id.to_string()).execute(&mut *tx).await.map_err(internal)?.rows_affected();
    if changed == 0 {
        tx.rollback().await.map_err(internal)?;
        return Err((StatusCode::CONFLICT, "task must be merge_pending before it can be marked merged".into()));
    }
    // Legacy implementation cleanup remains populated during rollout so an older
    // implementation worker can still clean its task workspace.
    sqlx::query("INSERT INTO task_cleanup(task_id,worker_id,created_at) VALUES(?,?,?) ON CONFLICT(task_id) DO UPDATE SET worker_id=excluded.worker_id,created_at=excluded.created_at")
        .bind(id.to_string()).bind(&worker_id).bind(&now).execute(&mut *tx).await.map_err(internal)?;
    // Logical sessions are retained across implementation/review retries. Release
    // every worker that ever owned one only after the task is merged.
    sqlx::query("INSERT OR IGNORE INTO agent_session_cleanup(task_id,worker_id,role,created_at) SELECT ?,worker_id,'implementation',? FROM executions WHERE task_id=?")
        .bind(id.to_string()).bind(&now).bind(id.to_string()).execute(&mut *tx).await.map_err(internal)?;
    sqlx::query("INSERT OR IGNORE INTO agent_session_cleanup(task_id,worker_id,role,created_at) SELECT ?,reviewer_worker_id,'review',? FROM reviews WHERE task_id=?")
        .bind(id.to_string()).bind(&now).bind(id.to_string()).execute(&mut *tx).await.map_err(internal)?;
    // The gate event commits atomically with the merge_pending -> done
    // transition, so a crash or database error cannot lose the outcome.
    // Databases from before the main-gate migration skip the row (Insights
    // then reports gate history as unavailable) without blocking the merge.
    if gate_available {
        sqlx::query("INSERT INTO main_gate_events(id,task_id,execution_id,kind,reason,merge_commit_sha,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string())
            .bind(id.to_string())
            .bind(Some(latest_execution_id.clone()))
            .bind(gate_kind)
            .bind(&gate_reason)
            .bind(Some(merge_commit_sha.to_string()))
            .bind(&now)
            .execute(&mut *tx).await.map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    Ok(TaskTransition { task_id: id, state: "done".into() })
}

pub(crate) async fn decide_task(
    state: &AppState,
    id: Uuid,
    candidate_sha: &str,
    verdict: &str,
    reason: &str,
) -> Result<TaskTransition, ApiError> {
    let candidate_sha = candidate_sha.trim();
    let reason = reason.trim();
    if candidate_sha.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "candidate_sha is required".into()));
    }
    if reason.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "review decision requires a reason".into()));
    }
    if !matches!(verdict, "approve" | "retry") {
        return Err((StatusCode::BAD_REQUEST, "verdict must be approve or retry".into()));
    }

    let now = Utc::now().to_rfc3339();
    let mut tx = state.db.begin().await.map_err(internal)?;
    let current: Option<String> = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
        .bind(id.to_string()).fetch_optional(&mut *tx).await.map_err(internal)?;
    if current.as_deref() != Some("review") {
        tx.rollback().await.map_err(internal)?;
        return Err((StatusCode::CONFLICT, "task must be in review for reviews_decide".into()));
    }
    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state IN ('assigned','running') AND lease_until>=?")
        .bind(id.to_string()).bind(&now).fetch_one(&mut *tx).await.map_err(internal)?;
    if active > 0 {
        tx.rollback().await.map_err(internal)?;
        return Err((StatusCode::CONFLICT, "task currently has an active reviewer lease".into()));
    }
    let execution = sqlx::query("SELECT id,worker_id,state,result FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(id.to_string()).fetch_optional(&mut *tx).await.map_err(internal)?
        .ok_or((StatusCode::CONFLICT, "task has no implementation execution to review".into()))?;
    let execution_state: String = execution.try_get("state").map_err(internal)?;
    if execution_state != "completed" {
        tx.rollback().await.map_err(internal)?;
        return Err((StatusCode::CONFLICT, "latest implementation execution is not completed".into()));
    }
    let result_json: Option<String> = execution.try_get("result").map_err(internal)?;
    let result_json = result_json.ok_or((StatusCode::CONFLICT, "completed implementation has no result".into()))?;
    let result: lazyteam_core::ExecutionResult = serde_json::from_str(&result_json).map_err(internal)?;
    let pinned_sha = result.commit_sha.as_deref().ok_or((StatusCode::CONFLICT, "completed implementation has no candidate commit".into()))?;
    if pinned_sha != candidate_sha {
        tx.rollback().await.map_err(internal)?;
        return Err((StatusCode::CONFLICT, format!("candidate_sha does not match latest implementation candidate {pinned_sha}")));
    }

    let next_state = if verdict == "approve" { "merge_pending" } else { "queued" };
    let changed = if verdict == "approve" {
        sqlx::query("UPDATE tasks SET state='merge_pending',review_feedback=?,updated_at=? WHERE id=? AND state='review'")
            .bind(reason).bind(&now).bind(id.to_string()).execute(&mut *tx).await.map_err(internal)?.rows_affected()
    } else {
        let worker_id: String = execution.try_get("worker_id").map_err(internal)?;
        sqlx::query("UPDATE tasks SET state='queued',review_feedback=?,sticky_worker_id=?,updated_at=? WHERE id=? AND state='review'")
            .bind(reason).bind(worker_id).bind(&now).bind(id.to_string()).execute(&mut *tx).await.map_err(internal)?.rows_affected()
    };
    if changed == 0 {
        tx.rollback().await.map_err(internal)?;
        return Err((StatusCode::CONFLICT, "task changed while recording review decision".into()));
    }
    tx.commit().await.map_err(internal)?;
    Ok(TaskTransition { task_id: id, state: next_state.into() })
}

pub(crate) async fn retry_task(state: &AppState, id: Uuid, reason: Option<&str>) -> Result<TaskTransition, ApiError> {
    retry_task_with_gate(state, id, reason, None).await
}

/// Retry with an explicit main-gate event kind for the merge_pending -> queued
/// transition. `None` records a main-agent send-back; `Some("merge_conflict")`
/// records a Host merge-conflict redispatch so Insights never folds merge
/// conflicts into reviewer/model quality. Other states record no gate event.
pub(crate) async fn retry_task_with_gate(state: &AppState, id: Uuid, reason: Option<&str>, gate_kind: Option<&str>) -> Result<TaskTransition, ApiError> {
    retry_task_with_gate_evidence(state, id, reason, gate_kind, None).await
}

pub(crate) async fn retry_task_with_gate_evidence(state: &AppState, id: Uuid, reason: Option<&str>, gate_kind: Option<&str>, evidence_json: Option<&str>) -> Result<TaskTransition, ApiError> {
    let current: Option<String> = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
        .bind(id.to_string()).fetch_optional(&state.db).await.map_err(internal)?;
    let Some(current) = current else { return Err((StatusCode::NOT_FOUND, "task not found".into())); };
    if !matches!(current.as_str(), "draft" | "review" | "merge_pending" | "failed" | "blocked") {
        return Err((StatusCode::CONFLICT, "task is not retryable from its current state".into()));
    }
    let reason = reason.map(str::trim).filter(|value| !value.is_empty());
    let review_retry = matches!(current.as_str(), "review" | "merge_pending");
    if current == "review" { ensure_no_active_reviewer(state, id).await?; }
    if review_retry && reason.is_none() {
        return Err((StatusCode::BAD_REQUEST, "review retry requires a reason for the next worker attempt".into()));
    }
    // A manual publish/re-publish/retry always starts a fresh review cycle:
    // bump the durable tasks.review_cycle epoch so the per-cycle retry
    // counter resets to zero while lifetime history stays intact. Automatic
    // reviewer retry redispatch (finish_review) never touches this column and
    // remains in the same cycle. Historical review rows keep their original
    // review_cycle values and are never deleted to fake a reset. The latest
    // implementation owner is kept for every retry state (the scheduler may
    // release that ownership later); a manual retry never discards a reusable
    // backend session.
    let sticky_worker_id: Option<String> = sqlx::query_scalar("SELECT worker_id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(id.to_string()).fetch_optional(&state.db).await.map_err(internal)?;
    let latest_execution_id: Option<String> = sqlx::query_scalar("SELECT id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(id.to_string()).fetch_optional(&state.db).await.map_err(internal)?;
    // Durable main-gate history: only merge_pending -> queued is a gate
    // outcome (sent back / overturned after reviewer approval, or a Host
    // merge conflict). Review-state retries are reviewer-quality signals
    // already captured in durable review verdict rows.
    let gate = if current == "merge_pending" {
        let kind = match gate_kind {
            Some("merge_conflict") => "merge_conflict",
            _ => "sent_back",
        };
        Some((kind, reason.unwrap_or("").chars().take(2000).collect::<String>()))
    } else {
        None
    };
    // Gate pre-migration databases keep serving the retry without the row;
    // Insights reports gate history as unavailable in that case.
    let gate_available = if gate.is_some() { gate_table_exists(&state.db).await } else { false };
    let now = Utc::now().to_rfc3339();
    let mut tx = state.db.begin().await.map_err(internal)?;
    let changed = if let Some(reason) = reason {
        sqlx::query("UPDATE tasks SET state='queued',review_cycle=review_cycle+1,review_feedback=?,sticky_worker_id=COALESCE(?,sticky_worker_id),updated_at=? WHERE id=? AND state=?")
            .bind(reason).bind(sticky_worker_id).bind(&now).bind(id.to_string()).bind(&current)
            .execute(&mut *tx).await.map_err(internal)?.rows_affected()
    } else {
        sqlx::query("UPDATE tasks SET state='queued',review_cycle=review_cycle+1,sticky_worker_id=COALESCE(?,sticky_worker_id),updated_at=? WHERE id=? AND state=?")
            .bind(sticky_worker_id).bind(&now).bind(id.to_string()).bind(&current)
            .execute(&mut *tx).await.map_err(internal)?.rows_affected()
    };
    if changed == 0 {
        tx.rollback().await.map_err(internal)?;
        return Err((StatusCode::CONFLICT, "task changed while retrying".into()));
    }
    // The gate event commits atomically with the merge_pending -> queued
    // transition so the outcome cannot be lost between the two writes.
    if let (Some((kind, gate_reason)), true) = (gate, gate_available) {
        let evidence = if kind == "merge_conflict" {
            evidence_json.map(|raw| raw.chars().take(16_384).collect::<String>())
        } else {
            None
        };
        sqlx::query("INSERT INTO main_gate_events(id,task_id,execution_id,kind,reason,merge_commit_sha,created_at,evidence) VALUES(?,?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string())
            .bind(id.to_string())
            .bind(latest_execution_id)
            .bind(kind)
            .bind(gate_reason)
            .bind(Option::<String>::None)
            .bind(&now)
            .bind(evidence)
            .execute(&mut *tx).await.map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;
    Ok(TaskTransition { task_id: id, state: "queued".into() })
}

/// Upstream moved after an approval, but the candidate still integrates
/// cleanly with a materially different effective diff. No implementation work
/// is needed: return the same execution directly to review without bumping the
/// quality review cycle or creating a fake reviewer retry.
pub(crate) async fn rereview_after_upstream_move(state: &AppState, id: Uuid, reason: &str) -> Result<TaskTransition, ApiError> {
    let now = Utc::now().to_rfc3339();
    let changed = sqlx::query("UPDATE tasks SET state='review',review_feedback=?,updated_at=? WHERE id=? AND state='merge_pending'")
        .bind(reason.chars().take(2000).collect::<String>()).bind(&now).bind(id.to_string())
        .execute(&state.db).await.map_err(internal)?.rows_affected();
    if changed == 0 {
        return Err((StatusCode::CONFLICT, "task changed while returning updated integration to review".into()));
    }
    Ok(TaskTransition { task_id: id, state: "review".into() })
}

async fn ensure_no_active_reviewer(state: &AppState, id: Uuid) -> Result<(), ApiError> {
    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state IN ('assigned','running')")
        .bind(id.to_string()).fetch_one(&state.db).await.map_err(internal)?;
    if active > 0 {
        return Err((StatusCode::CONFLICT, "task is currently claimed by a reviewer worker".into()));
    }
    Ok(())
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn memory_db() -> sqlx::SqlitePool {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        db
    }

    fn state_with(db: sqlx::SqlitePool) -> AppState {
        AppState {
            db,
            public_url: None,
            oauth_password: None,
            git_credential_key: None,
            git_root: std::env::temp_dir(),
            agent_auth_updates: Default::default(),
            model_refresh_requests: Default::default(),
        }
    }

    async fn seed_merge_pending(db: &sqlx::SqlitePool, candidate: &str) -> (Uuid, String) {
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(db).await.unwrap();
        sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(&worker_id).bind("w").bind("worker").bind("idle").bind("linux").bind("x86_64")
            .bind(6_i64).bind("test").bind(&now).bind(&now)
            .execute(db).await.unwrap();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(&project_id).bind("t").bind("").bind("").bind("merge_pending").bind(&now).bind(&now)
            .execute(db).await.unwrap();
        let exec_id = Uuid::new_v4().to_string();
        let result = format!(r#"{{"status":"completed","summary":"s","commit_sha":"{candidate}","base_sha":"base","review_ref":"r"}}"#);
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,result,created_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(&exec_id).bind(task_id.to_string()).bind(&worker_id).bind(1_i64).bind("completed").bind(&now).bind(result).bind(&now)
            .execute(db).await.unwrap();
        (task_id, exec_id)
    }

    async fn gate_kind(db: &sqlx::SqlitePool, task_id: Uuid) -> Option<String> {
        sqlx::query_scalar::<_, String>("SELECT kind FROM main_gate_events WHERE task_id=?")
            .bind(task_id.to_string())
            .fetch_optional(db)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn merged_task_records_merged_atomically() {
        let db = memory_db().await;
        let (task_id, _) = seed_merge_pending(&db, "abc").await;
        let state = state_with(db.clone());
        let transition = merged_task(&state, task_id, "abc").await.unwrap();
        assert_eq!(transition.state, "done");
        assert_eq!(gate_kind(&db, task_id).await.as_deref(), Some("merged"));
    }

    #[tokio::test]
    async fn merged_task_records_upstream_moved_as_distinct_kind() {
        let db = memory_db().await;
        let (task_id, _) = seed_merge_pending(&db, "abc").await;
        let state = state_with(db.clone());
        merged_task(&state, task_id, "merged-sha").await.unwrap();
        assert_eq!(gate_kind(&db, task_id).await.as_deref(), Some("upstream_moved"));
    }

    #[tokio::test]
    async fn merged_task_treats_explicitly_reviewed_integration_as_merged() {
        let db = memory_db().await;
        let (task_id, execution_id) = seed_merge_pending(&db, "candidate").await;
        let reviewer = Uuid::new_v4().to_string();
        let now = Utc::now().to_rfc3339();
        sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(&reviewer).bind("reviewer").bind("reviewer").bind("idle").bind("linux").bind("x86_64")
            .bind(6_i64).bind("test").bind(&now).bind(&now).execute(&db).await.unwrap();
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,started_at,finished_at,verdict,created_at,upstream_sha,integration_sha,effective_diff_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(task_id.to_string()).bind(&execution_id).bind(&reviewer)
            .bind("completed").bind(&now).bind(&now).bind(&now).bind(r#"{"verdict":"approve","reason":"ok"}"#).bind(&now)
            .bind("upstream").bind("reviewed-merge").bind("hash").execute(&db).await.unwrap();
        let state = state_with(db.clone());
        merged_task(&state, task_id, "reviewed-merge").await.unwrap();
        assert_eq!(gate_kind(&db, task_id).await.as_deref(), Some("merged"));
        let reason: String = sqlx::query_scalar("SELECT reason FROM main_gate_events WHERE task_id=?")
            .bind(task_id.to_string()).fetch_one(&db).await.unwrap();
        assert!(reason.contains("reviewed integration"));
    }

    #[tokio::test]
    async fn rereview_after_upstream_move_reuses_same_cycle_and_execution() {
        let db = memory_db().await;
        let (task_id, execution_id) = seed_merge_pending(&db, "candidate").await;
        sqlx::query("UPDATE tasks SET review_cycle=7 WHERE id=?").bind(task_id.to_string()).execute(&db).await.unwrap();
        let state = state_with(db.clone());
        let transition = rereview_after_upstream_move(&state, task_id, "upstream changed effective integration").await.unwrap();
        assert_eq!(transition.state, "review");
        let row = sqlx::query("SELECT state,review_cycle,review_feedback FROM tasks WHERE id=?")
            .bind(task_id.to_string()).fetch_one(&db).await.unwrap();
        assert_eq!(row.try_get::<String, _>("state").unwrap(), "review");
        assert_eq!(row.try_get::<i64, _>("review_cycle").unwrap(), 7);
        assert!(row.try_get::<String, _>("review_feedback").unwrap().contains("upstream changed"));
        let latest_execution: String = sqlx::query_scalar("SELECT id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
            .bind(task_id.to_string()).fetch_one(&db).await.unwrap();
        assert_eq!(latest_execution, execution_id);
        assert_eq!(gate_kind(&db, task_id).await, None);
    }

    #[tokio::test]
    async fn merge_conflict_gate_uses_existing_event_row_for_evidence() {
        let db = memory_db().await;
        let (task_id, _) = seed_merge_pending(&db, "candidate").await;
        let state = state_with(db.clone());
        let evidence = r#"{"candidate_sha":"candidate","candidate_base_sha":"base","upstream_sha":"new-head","default_branch":"main","files":[],"truncated":false}"#;
        retry_task_with_gate_evidence(&state, task_id, Some("conflict"), Some("merge_conflict"), Some(evidence)).await.unwrap();
        let row = sqlx::query("SELECT kind,evidence FROM main_gate_events WHERE task_id=?")
            .bind(task_id.to_string()).fetch_one(&db).await.unwrap();
        assert_eq!(row.try_get::<String, _>("kind").unwrap(), "merge_conflict");
        assert_eq!(row.try_get::<Option<String>, _>("evidence").unwrap().as_deref(), Some(evidence));
    }

    #[tokio::test]
    async fn retry_from_merge_pending_records_sent_back_atomically() {
        let db = memory_db().await;
        let (task_id, _) = seed_merge_pending(&db, "abc").await;
        let state = state_with(db.clone());
        let transition = retry_task(&state, task_id, Some("stale candidate")).await.unwrap();
        assert_eq!(transition.state, "queued");
        assert_eq!(gate_kind(&db, task_id).await.as_deref(), Some("sent_back"));
        // Manual retry also bumps the review-cycle epoch in the same commit.
        let cycle: i64 = sqlx::query_scalar("SELECT review_cycle FROM tasks WHERE id=?")
            .bind(task_id.to_string())
            .fetch_one(&db)
            .await
            .unwrap();
        assert_eq!(cycle, 1);
    }

    #[tokio::test]
    async fn retry_with_conflict_kind_records_merge_conflict() {
        let db = memory_db().await;
        let (task_id, _) = seed_merge_pending(&db, "abc").await;
        let state = state_with(db.clone());
        retry_task_with_gate(&state, task_id, Some("merge conflict with current main"), Some("merge_conflict"))
            .await
            .unwrap();
        assert_eq!(gate_kind(&db, task_id).await.as_deref(), Some("merge_conflict"));
    }

    #[tokio::test]
    async fn retry_from_review_records_no_gate_event() {
        let db = memory_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(&project_id).bind("t").bind("").bind("").bind("review").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let state = state_with(db.clone());
        retry_task(&state, task_id, Some("needs work")).await.unwrap();
        assert_eq!(gate_kind(&db, task_id).await, None);
    }
}

/// True when the main-gate event table exists. Lets merges/retries on
/// pre-migration databases skip the gate row (Insights then reports gate
/// history as unavailable) without blocking the transition itself.
async fn gate_table_exists(db: &sqlx::SqlitePool) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='main_gate_events'")
        .fetch_one(db)
        .await
        .unwrap_or(0)
        > 0
}
