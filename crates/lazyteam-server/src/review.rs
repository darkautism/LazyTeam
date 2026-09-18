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

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/tasks/{id}/approve", post(approve_task_http))
        .route("/api/tasks/{id}/retry", post(retry_task_http))
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

pub(crate) async fn approve_task(state: &AppState, id: Uuid) -> Result<TaskTransition, ApiError> {
    let changed = sqlx::query("UPDATE tasks SET state='done', updated_at=? WHERE id=? AND state='review'")
        .bind(Utc::now().to_rfc3339())
        .bind(id.to_string())
        .execute(&state.db)
        .await
        .map_err(internal)?
        .rows_affected();
    if changed == 0 {
        return Err((StatusCode::CONFLICT, "task must be in review before approval".into()));
    }
    Ok(TaskTransition { task_id: id, state: "done".into() })
}

pub(crate) async fn retry_task(state: &AppState, id: Uuid, reason: Option<&str>) -> Result<TaskTransition, ApiError> {
    let current: Option<String> = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
        .bind(id.to_string()).fetch_optional(&state.db).await.map_err(internal)?;
    let Some(current) = current else { return Err((StatusCode::NOT_FOUND, "task not found".into())); };
    if !matches!(current.as_str(), "review" | "failed" | "blocked") {
        return Err((StatusCode::CONFLICT, "task is not retryable from its current state".into()));
    }
    let reason = reason.map(str::trim).filter(|value| !value.is_empty());
    if current == "review" && reason.is_none() {
        return Err((StatusCode::BAD_REQUEST, "review retry requires a reason for the next worker attempt".into()));
    }
    let changed = if let Some(reason) = reason {
        sqlx::query("UPDATE tasks SET state='queued',review_feedback=?,updated_at=? WHERE id=? AND state=?")
            .bind(reason).bind(Utc::now().to_rfc3339()).bind(id.to_string()).bind(&current)
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
