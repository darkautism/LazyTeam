use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::post,
    Json, Router,
};
use chrono::Utc;
use serde::Serialize;
use uuid::Uuid;

use crate::{ApiError, AppState};

#[derive(Debug, Serialize)]
pub(crate) struct TaskTransition {
    pub task_id: Uuid,
    pub state: String,
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
) -> Result<Json<TaskTransition>, ApiError> {
    retry_task(&state, id).await.map(Json)
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

pub(crate) async fn retry_task(state: &AppState, id: Uuid) -> Result<TaskTransition, ApiError> {
    let changed = sqlx::query("UPDATE tasks SET state='queued', updated_at=? WHERE id=? AND state IN ('review','failed','blocked')")
        .bind(Utc::now().to_rfc3339())
        .bind(id.to_string())
        .execute(&state.db)
        .await
        .map_err(internal)?
        .rows_affected();
    if changed == 0 {
        return Err((StatusCode::CONFLICT, "task is not retryable from its current state".into()));
    }
    Ok(TaskTransition { task_id: id, state: "queued".into() })
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}
