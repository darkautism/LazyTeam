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
    let worker_id: Option<String> = sqlx::query_scalar("SELECT worker_id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(id.to_string()).fetch_optional(&state.db).await.map_err(internal)?;
    let Some(worker_id) = worker_id else {
        return Err((StatusCode::CONFLICT, "task has no execution to clean up".into()));
    };
    let now = Utc::now().to_rfc3339();
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
    let changed = if let Some(reason) = reason {
        sqlx::query("UPDATE tasks SET state='queued',review_cycle=review_cycle+1,review_feedback=?,sticky_worker_id=COALESCE(?,sticky_worker_id),updated_at=? WHERE id=? AND state=?")
            .bind(reason).bind(sticky_worker_id).bind(Utc::now().to_rfc3339()).bind(id.to_string()).bind(&current)
            .execute(&state.db).await.map_err(internal)?.rows_affected()
    } else {
        sqlx::query("UPDATE tasks SET state='queued',review_cycle=review_cycle+1,sticky_worker_id=COALESCE(?,sticky_worker_id),updated_at=? WHERE id=? AND state=?")
            .bind(sticky_worker_id).bind(Utc::now().to_rfc3339()).bind(id.to_string()).bind(&current)
            .execute(&state.db).await.map_err(internal)?.rows_affected()
    };
    if changed == 0 { return Err((StatusCode::CONFLICT, "task changed while retrying".into())); }
    Ok(TaskTransition { task_id: id, state: "queued".into() })
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
