use std::sync::Arc;

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{ApiError, AppState};

#[derive(Debug, Serialize)]
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
        .route("/api/tasks/{id}/approve", post(approve_task_http))
        .route("/api/tasks/{id}/retry", post(retry_task_http))
        .route("/api/tasks/{id}/merged", post(merged_task_http))
}

async fn approve_task_http(
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
) -> Result<Json<TaskTransition>, ApiError> {
    approve_task(&state, id).await.map(Json)
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

pub(crate) async fn approve_task(state: &AppState, id: Uuid) -> Result<TaskTransition, ApiError> {
    let changed = sqlx::query("UPDATE tasks SET state='merge_pending', updated_at=? WHERE id=? AND state='review'")
        .bind(Utc::now().to_rfc3339())
        .bind(id.to_string())
        .execute(&state.db)
        .await
        .map_err(internal)?
        .rows_affected();
    if changed == 0 {
        return Err((StatusCode::CONFLICT, "task must be in review before approval".into()));
    }
    Ok(TaskTransition { task_id: id, state: "merge_pending".into() })
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
    sqlx::query("INSERT INTO task_cleanup(task_id,worker_id,created_at) VALUES(?,?,?) ON CONFLICT(task_id) DO UPDATE SET worker_id=excluded.worker_id,created_at=excluded.created_at")
        .bind(id.to_string()).bind(worker_id).bind(&now).execute(&mut *tx).await.map_err(internal)?;
    tx.commit().await.map_err(internal)?;
    Ok(TaskTransition { task_id: id, state: "done".into() })
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
    if review_retry && reason.is_none() {
        return Err((StatusCode::BAD_REQUEST, "review retry requires a reason for the next worker attempt".into()));
    }
    let sticky_worker_id: Option<String> = if review_retry {
        sqlx::query_scalar("SELECT worker_id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
            .bind(id.to_string()).fetch_optional(&state.db).await.map_err(internal)?
    } else { None };
    let changed = if let Some(reason) = reason {
        sqlx::query("UPDATE tasks SET state='queued',review_feedback=?,sticky_worker_id=COALESCE(?,sticky_worker_id),updated_at=? WHERE id=? AND state=?")
            .bind(reason).bind(sticky_worker_id).bind(Utc::now().to_rfc3339()).bind(id.to_string()).bind(&current)
            .execute(&state.db).await.map_err(internal)?.rows_affected()
    } else {
        sqlx::query("UPDATE tasks SET state='queued',updated_at=? WHERE id=? AND state=?")
            .bind(Utc::now().to_rfc3339()).bind(id.to_string()).bind(&current)
            .execute(&state.db).await.map_err(internal)?.rows_affected()
    };
    if changed == 0 { return Err((StatusCode::CONFLICT, "task changed while retrying".into())); }
    Ok(TaskTransition { task_id: id, state: "queued".into() })
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}
