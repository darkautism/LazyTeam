use std::{collections::{BTreeMap, BTreeSet}, net::SocketAddr, sync::Arc, time::Duration};

use anyhow::Context;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use clap::Parser;
use lazyteam_core::{
    worker_matches_task, Assignment, Execution, ExecutionResult, ExecutionState, Project, Tags, Task,
    TaskState, Worker, WorkerState,
};
use serde::Deserialize;
use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};
use tokio::time::interval;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use uuid::Uuid;

mod oauth;

const PROTOCOL_VERSION: u32 = 1;
const DEFAULT_LEASE_SECONDS: i64 = 120;

type ApiError = (StatusCode, String);
type ApiResult<T> = Result<Json<T>, ApiError>;

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, env = "LAZYTEAM_LISTEN", default_value = "0.0.0.0:8787")]
    listen: SocketAddr,
    #[arg(long, env = "LAZYTEAM_DATABASE_URL", default_value = "sqlite://data/lazyteam.db?mode=rwc")]
    database_url: String,
    #[arg(long, env = "LAZYTEAM_PUBLIC_URL")]
    public_url: Option<String>,
    #[arg(long, env = "LAZYTEAM_OAUTH_PASSWORD")]
    oauth_password: Option<String>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    db: SqlitePool,
    public_url: Option<String>,
    oauth_password: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateProject {
    slug: String,
    name: String,
    repo_url: String,
    #[serde(default = "default_branch")]
    default_branch: String,
    #[serde(default)]
    required_worker_tags: Tags,
    #[serde(default)]
    default_task_tags: Tags,
}

fn default_branch() -> String { "main".into() }

#[derive(Debug, Deserialize)]
struct CreateTask {
    project_id: Uuid,
    title: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    expected_outcome: String,
    #[serde(default)]
    acceptance_criteria: Vec<String>,
    #[serde(default)]
    required_tags: Tags,
    #[serde(default)]
    preferred_tags: Tags,
    #[serde(default)]
    dependencies: Vec<Uuid>,
    #[serde(default)]
    priority: i32,
}

#[derive(Debug, Deserialize)]
struct RegisterWorker {
    id: Option<Uuid>,
    name: String,
    os: String,
    arch: String,
    #[serde(default)]
    tags: Tags,
    #[serde(default)]
    allowed_projects: BTreeSet<String>,
    #[serde(default = "default_slots")]
    slots: u32,
    #[serde(default)]
    worker_version: String,
    #[serde(default = "default_protocol")]
    protocol_version: u32,
}

fn default_slots() -> u32 { 1 }
fn default_protocol() -> u32 { PROTOCOL_VERSION }

#[derive(Debug, Deserialize)]
struct FinishExecution {
    result: ExecutionResult,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    if args.database_url.starts_with("sqlite://data/") {
        tokio::fs::create_dir_all("data").await?;
    }
    let db = SqlitePoolOptions::new()
        .max_connections(8)
        .connect(&args.database_url)
        .await
        .context("connect sqlite")?;
    sqlx::migrate!().run(&db).await.context("run migrations")?;

    let state = Arc::new(AppState {
        db,
        public_url: args.public_url.map(|s| s.trim_end_matches('/').to_string()),
        oauth_password: args.oauth_password,
    });

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/projects", get(list_projects).post(create_project))
        .route("/api/tasks", get(list_tasks).post(create_task))
        .route("/api/workers", get(list_workers))
        .route("/api/workers/register", post(register_worker))
        .route("/api/workers/{id}/heartbeat", post(worker_heartbeat))
        .route("/api/workers/{id}/claim", post(claim_task))
        .route("/api/executions/{id}/renew", post(renew_execution))
        .route("/api/executions/{id}/finish", post(finish_execution))
        .merge(oauth::router())
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    tokio::spawn(reaper(state.clone()));

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    info!(listen = %args.listen, "LazyTeam control plane listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str { "ok" }

async fn create_project(State(state): State<Arc<AppState>>, Json(input): Json<CreateProject>) -> ApiResult<Project> {
    if input.slug.is_empty() || !input.slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
        return Err((StatusCode::BAD_REQUEST, "invalid project slug".into()));
    }
    let now = Utc::now();
    let project = Project {
        id: Uuid::new_v4(), slug: input.slug, name: input.name, repo_url: input.repo_url,
        default_branch: input.default_branch, required_worker_tags: input.required_worker_tags,
        default_task_tags: input.default_task_tags, enabled: true, created_at: now, updated_at: now,
    };
    sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,required_worker_tags,default_task_tags,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
        .bind(project.id.to_string()).bind(&project.slug).bind(&project.name).bind(&project.repo_url)
        .bind(&project.default_branch).bind(json(&project.required_worker_tags)?).bind(json(&project.default_task_tags)?)
        .bind(1_i64).bind(ts(project.created_at)).bind(ts(project.updated_at))
        .execute(&state.db).await.map_err(db_conflict)?;
    Ok(Json(project))
}

async fn list_projects(State(state): State<Arc<AppState>>) -> ApiResult<Vec<Project>> {
    let rows = sqlx::query("SELECT * FROM projects ORDER BY slug").fetch_all(&state.db).await.map_err(db_error)?;
    rows.iter().map(project_from_row).collect::<Result<Vec<_>,_>>().map(Json)
}

async fn create_task(State(state): State<Arc<AppState>>, Json(input): Json<CreateTask>) -> ApiResult<Task> {
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects WHERE id=? AND enabled=1")
        .bind(input.project_id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    if exists == 0 { return Err((StatusCode::BAD_REQUEST, "unknown or disabled project".into())); }
    for dep in &input.dependencies {
        let dep_project: Option<String> = sqlx::query_scalar("SELECT project_id FROM tasks WHERE id=?")
            .bind(dep.to_string()).fetch_optional(&state.db).await.map_err(db_error)?;
        if dep_project.as_deref() != Some(&input.project_id.to_string()) {
            return Err((StatusCode::BAD_REQUEST, "dependencies must exist in the same project".into()));
        }
    }
    let now = Utc::now();
    let task = Task {
        id: Uuid::new_v4(), project_id: input.project_id, title: input.title, description: input.description,
        expected_outcome: input.expected_outcome, acceptance_criteria: input.acceptance_criteria,
        required_tags: input.required_tags, preferred_tags: input.preferred_tags, dependencies: input.dependencies,
        priority: input.priority, state: TaskState::Queued, created_at: now, updated_at: now,
    };
    sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,acceptance_criteria,required_tags,preferred_tags,dependencies,priority,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(task.id.to_string()).bind(task.project_id.to_string()).bind(&task.title).bind(&task.description)
        .bind(&task.expected_outcome).bind(json(&task.acceptance_criteria)?).bind(json(&task.required_tags)?)
        .bind(json(&task.preferred_tags)?).bind(json(&task.dependencies)?).bind(task.priority).bind("queued")
        .bind(ts(task.created_at)).bind(ts(task.updated_at)).execute(&state.db).await.map_err(db_error)?;
    Ok(Json(task))
}

async fn list_tasks(State(state): State<Arc<AppState>>) -> ApiResult<Vec<Task>> {
    let rows = sqlx::query("SELECT * FROM tasks ORDER BY priority DESC, created_at ASC").fetch_all(&state.db).await.map_err(db_error)?;
    rows.iter().map(task_from_row).collect::<Result<Vec<_>,_>>().map(Json)
}

async fn register_worker(State(state): State<Arc<AppState>>, Json(input): Json<RegisterWorker>) -> ApiResult<Worker> {
    if input.protocol_version != PROTOCOL_VERSION {
        return Err((StatusCode::BAD_REQUEST, format!("unsupported worker protocol {}; expected {}", input.protocol_version, PROTOCOL_VERSION)));
    }
    let id = input.id.unwrap_or_else(Uuid::new_v4);
    let now = Utc::now();
    let mut tags = input.tags;
    tags.entry("os".into()).or_insert_with(|| input.os.clone());
    tags.entry("arch".into()).or_insert_with(|| input.arch.clone());
    let worker = Worker { id, name: input.name, state: WorkerState::Idle, os: input.os, arch: input.arch, tags,
        allowed_projects: input.allowed_projects, slots: input.slots.max(1), running_slots: 0,
        protocol_version: input.protocol_version, worker_version: input.worker_version, last_heartbeat_at: now };
    sqlx::query("INSERT INTO workers(id,name,state,os,arch,tags,allowed_projects,slots,running_slots,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,state=CASE WHEN workers.running_slots>0 THEN 'busy' ELSE 'idle' END,os=excluded.os,arch=excluded.arch,tags=excluded.tags,allowed_projects=excluded.allowed_projects,slots=excluded.slots,protocol_version=excluded.protocol_version,worker_version=excluded.worker_version,last_heartbeat_at=excluded.last_heartbeat_at")
        .bind(id.to_string()).bind(&worker.name).bind("idle").bind(&worker.os).bind(&worker.arch).bind(json(&worker.tags)?)
        .bind(json(&worker.allowed_projects)?).bind(worker.slots as i64).bind(0_i64).bind(worker.protocol_version as i64)
        .bind(&worker.worker_version).bind(ts(now)).bind(ts(now)).execute(&state.db).await.map_err(db_error)?;
    let row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    Ok(Json(worker_from_row(&row)?))
}

async fn list_workers(State(state): State<Arc<AppState>>) -> ApiResult<Vec<Worker>> {
    let rows = sqlx::query("SELECT * FROM workers ORDER BY name").fetch_all(&state.db).await.map_err(db_error)?;
    rows.iter().map(worker_from_row).collect::<Result<Vec<_>,_>>().map(Json)
}

async fn worker_heartbeat(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>) -> Result<StatusCode, ApiError> {
    let changed = sqlx::query("UPDATE workers SET last_heartbeat_at=?, state=CASE WHEN state='draining' THEN state WHEN running_slots>0 THEN 'busy' ELSE 'idle' END WHERE id=?")
        .bind(ts(Utc::now())).bind(id.to_string()).execute(&state.db).await.map_err(db_error)?.rows_affected();
    if changed == 0 { return Err((StatusCode::NOT_FOUND, "worker not found".into())); }
    Ok(StatusCode::NO_CONTENT)
}

async fn claim_task(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>) -> Result<Response, ApiError> {
    let row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let worker = worker_from_row(&row)?;
    if worker.running_slots >= worker.slots || matches!(worker.state, WorkerState::Draining | WorkerState::Degraded | WorkerState::Offline) {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    let rows = sqlx::query("SELECT * FROM tasks WHERE state='queued' ORDER BY priority DESC, created_at ASC LIMIT 100")
        .fetch_all(&state.db).await.map_err(db_error)?;
    for row in rows {
        let task = task_from_row(&row)?;
        if !dependencies_satisfied(&state.db, &task).await? { continue; }
        let project_row = sqlx::query("SELECT * FROM projects WHERE id=? AND enabled=1").bind(task.project_id.to_string())
            .fetch_optional(&state.db).await.map_err(db_error)?;
        let Some(project_row) = project_row else { continue };
        let project = project_from_row(&project_row)?;
        if !worker_matches_task(&worker, &project, &task) { continue; }

        let now = Utc::now();
        let lease_until = now + chrono::Duration::seconds(DEFAULT_LEASE_SECONDS);
        let attempt: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(attempt),0)+1 FROM executions WHERE task_id=?")
            .bind(task.id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
        let execution = Execution { id: Uuid::new_v4(), task_id: task.id, worker_id: worker.id, attempt: attempt as u32,
            state: ExecutionState::Assigned, lease_until, started_at: None, finished_at: None, result: None };

        let mut tx = state.db.begin().await.map_err(db_error)?;
        let claimed = sqlx::query("UPDATE tasks SET state='assigned',updated_at=? WHERE id=? AND state='queued'")
            .bind(ts(now)).bind(task.id.to_string()).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
        if claimed == 0 { tx.rollback().await.map_err(db_error)?; continue; }
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(execution.id.to_string()).bind(task.id.to_string()).bind(worker.id.to_string()).bind(attempt)
            .bind("assigned").bind(ts(lease_until)).bind(ts(now)).execute(&mut *tx).await.map_err(db_error)?;
        sqlx::query("UPDATE workers SET running_slots=running_slots+1,state='busy' WHERE id=?")
            .bind(worker.id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        let mut assigned_task = task; assigned_task.state = TaskState::Assigned; assigned_task.updated_at = now;
        return Ok(Json(Assignment { project, task: assigned_task, execution }).into_response());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn renew_execution(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>) -> Result<StatusCode, ApiError> {
    let now = Utc::now();
    let lease = now + chrono::Duration::seconds(DEFAULT_LEASE_SECONDS);
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let row = sqlx::query("SELECT task_id FROM executions WHERE id=? AND state IN ('assigned','running')")
        .bind(id.to_string()).fetch_optional(&mut *tx).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "execution is not active".into()))?;
    let task_id: String = row.try_get("task_id").map_err(internal)?;
    if !is_latest_execution(&mut tx, &task_id, id).await? { return Err((StatusCode::CONFLICT, "stale execution".into())); }
    sqlx::query("UPDATE executions SET state='running',lease_until=?,started_at=COALESCE(started_at,?) WHERE id=?")
        .bind(ts(lease)).bind(ts(now)).bind(id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
    sqlx::query("UPDATE tasks SET state='running',updated_at=? WHERE id=? AND state IN ('assigned','running')")
        .bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn finish_execution(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, Json(input): Json<FinishExecution>) -> Result<StatusCode, ApiError> {
    let now = Utc::now();
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let row = sqlx::query("SELECT task_id,worker_id FROM executions WHERE id=? AND state IN ('assigned','running')")
        .bind(id.to_string()).fetch_optional(&mut *tx).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "execution is not active".into()))?;
    let task_id: String = row.try_get("task_id").map_err(internal)?;
    let worker_id: String = row.try_get("worker_id").map_err(internal)?;
    if !is_latest_execution(&mut tx, &task_id, id).await? { return Err((StatusCode::CONFLICT, "stale execution".into())); }
    let success = input.result.status == "completed";
    sqlx::query("UPDATE executions SET state=?,finished_at=?,result=? WHERE id=?")
        .bind(if success { "completed" } else { "failed" }).bind(ts(now)).bind(json(&input.result)?).bind(id.to_string())
        .execute(&mut *tx).await.map_err(db_error)?;
    sqlx::query("UPDATE tasks SET state=?,updated_at=? WHERE id=?")
        .bind(if success { "review" } else { "failed" }).bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?;
    sqlx::query("UPDATE workers SET running_slots=MAX(running_slots-1,0),state=CASE WHEN state='draining' THEN state WHEN running_slots<=1 THEN 'idle' ELSE 'busy' END WHERE id=?")
        .bind(&worker_id).execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn dependencies_satisfied(db: &SqlitePool, task: &Task) -> Result<bool, ApiError> {
    for dep in &task.dependencies {
        let state: Option<String> = sqlx::query_scalar("SELECT state FROM tasks WHERE id=? AND project_id=?")
            .bind(dep.to_string()).bind(task.project_id.to_string()).fetch_optional(db).await.map_err(db_error)?;
        if state.as_deref() != Some("done") { return Ok(false); }
    }
    Ok(true)
}

async fn is_latest_execution(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, task_id: &str, execution_id: Uuid) -> Result<bool, ApiError> {
    let latest: Option<String> = sqlx::query_scalar("SELECT id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(task_id).fetch_optional(&mut **tx).await.map_err(db_error)?;
    Ok(latest.as_deref() == Some(execution_id.to_string().as_str()))
}

async fn reaper(state: Arc<AppState>) {
    let mut tick = interval(Duration::from_secs(15));
    loop {
        tick.tick().await;
        if let Err(error) = reap_once(&state.db).await { warn!(%error, "lease reaper failed"); }
    }
}

async fn reap_once(db: &SqlitePool) -> anyhow::Result<()> {
    let now = ts(Utc::now());
    let expired = sqlx::query("SELECT id,task_id,worker_id FROM executions WHERE state IN ('assigned','running') AND lease_until < ?")
        .bind(&now).fetch_all(db).await?;
    for row in expired {
        let id: String = row.try_get("id")?; let task_id: String = row.try_get("task_id")?; let worker_id: String = row.try_get("worker_id")?;
        let mut tx = db.begin().await?;
        let latest: Option<String> = sqlx::query_scalar("SELECT id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
            .bind(&task_id).fetch_optional(&mut *tx).await?;
        sqlx::query("UPDATE executions SET state='lost',finished_at=? WHERE id=? AND state IN ('assigned','running')")
            .bind(&now).bind(&id).execute(&mut *tx).await?;
        if latest.as_deref() == Some(id.as_str()) {
            sqlx::query("UPDATE tasks SET state='queued',updated_at=? WHERE id=? AND state IN ('assigned','running')")
                .bind(&now).bind(&task_id).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE workers SET running_slots=MAX(running_slots-1,0),state=CASE WHEN state='draining' THEN state WHEN running_slots<=1 THEN 'idle' ELSE 'busy' END WHERE id=?")
            .bind(&worker_id).execute(&mut *tx).await?;
        tx.commit().await?;
    }
    Ok(())
}

fn project_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Project, ApiError> {
    Ok(Project {
        id: uuid(row.try_get("id").map_err(internal)?)?, slug: row.try_get("slug").map_err(internal)?, name: row.try_get("name").map_err(internal)?,
        repo_url: row.try_get("repo_url").map_err(internal)?, default_branch: row.try_get("default_branch").map_err(internal)?,
        required_worker_tags: dejson(row.try_get("required_worker_tags").map_err(internal)?)?, default_task_tags: dejson(row.try_get("default_task_tags").map_err(internal)?)?,
        enabled: row.try_get::<i64,_>("enabled").map_err(internal)? != 0, created_at: datetime(row.try_get("created_at").map_err(internal)?)?,
        updated_at: datetime(row.try_get("updated_at").map_err(internal)?)?,
    })
}

fn worker_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Worker, ApiError> {
    let state: String = row.try_get("state").map_err(internal)?;
    Ok(Worker { id: uuid(row.try_get("id").map_err(internal)?)?, name: row.try_get("name").map_err(internal)?,
        state: match state.as_str() { "busy" => WorkerState::Busy, "draining" => WorkerState::Draining, "degraded" => WorkerState::Degraded, "offline" => WorkerState::Offline, _ => WorkerState::Idle },
        os: row.try_get("os").map_err(internal)?, arch: row.try_get("arch").map_err(internal)?, tags: dejson(row.try_get("tags").map_err(internal)?)?,
        allowed_projects: dejson(row.try_get("allowed_projects").map_err(internal)?)?, slots: row.try_get::<i64,_>("slots").map_err(internal)? as u32,
        running_slots: row.try_get::<i64,_>("running_slots").map_err(internal)? as u32, protocol_version: row.try_get::<i64,_>("protocol_version").map_err(internal)? as u32,
        worker_version: row.try_get("worker_version").map_err(internal)?, last_heartbeat_at: datetime(row.try_get("last_heartbeat_at").map_err(internal)?)? })
}

fn task_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Task, ApiError> {
    let state: String = row.try_get("state").map_err(internal)?;
    Ok(Task { id: uuid(row.try_get("id").map_err(internal)?)?, project_id: uuid(row.try_get("project_id").map_err(internal)?)?,
        title: row.try_get("title").map_err(internal)?, description: row.try_get("description").map_err(internal)?, expected_outcome: row.try_get("expected_outcome").map_err(internal)?,
        acceptance_criteria: dejson(row.try_get("acceptance_criteria").map_err(internal)?)?, required_tags: dejson(row.try_get("required_tags").map_err(internal)?)?,
        preferred_tags: dejson(row.try_get("preferred_tags").map_err(internal)?)?, dependencies: dejson(row.try_get("dependencies").map_err(internal)?)?, priority: row.try_get("priority").map_err(internal)?,
        state: match state.as_str() { "draft"=>TaskState::Draft,"assigned"=>TaskState::Assigned,"running"=>TaskState::Running,"review"=>TaskState::Review,"done"=>TaskState::Done,"blocked"=>TaskState::Blocked,"failed"=>TaskState::Failed,"cancelled"=>TaskState::Cancelled,_=>TaskState::Queued },
        created_at: datetime(row.try_get("created_at").map_err(internal)?)?, updated_at: datetime(row.try_get("updated_at").map_err(internal)?)? })
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, ApiError> { serde_json::to_string(value).map_err(internal) }
fn dejson<T: serde::de::DeserializeOwned>(value: String) -> Result<T, ApiError> { serde_json::from_str(&value).map_err(internal) }
fn ts(value: DateTime<Utc>) -> String { value.to_rfc3339() }
fn datetime(value: String) -> Result<DateTime<Utc>, ApiError> { DateTime::parse_from_rfc3339(&value).map(|d| d.with_timezone(&Utc)).map_err(internal) }
fn uuid(value: String) -> Result<Uuid, ApiError> { Uuid::parse_str(&value).map_err(internal) }
fn internal(error: impl std::fmt::Display) -> ApiError { (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()) }
fn db_error(error: sqlx::Error) -> ApiError { internal(error) }
fn db_conflict(error: sqlx::Error) -> ApiError {
    if matches!(error, sqlx::Error::Database(ref e) if e.is_unique_violation()) { (StatusCode::CONFLICT, error.to_string()) } else { db_error(error) }
}
