use std::{collections::BTreeSet, sync::Arc, time::Duration};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use lazyteam_core::{
    worker_matches_task, AgentCapabilities, AgentConfig, Assignment, Execution, ExecutionResult,
    ExecutionState, GitAuthConfig, GitAuthMode, GitCredential, Project, ReviewerConfig, ReviewerMode,
    Tags, Task, TaskState, Worker, WorkerState,
    DEFAULT_REVIEWER_PROMPT, DEFAULT_WORKER_PROMPT,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use tokio::time::interval;
use tracing::warn;
use uuid::Uuid;

pub(crate) const PROTOCOL_VERSION: u32 = 2;
const MIN_PROTOCOL_VERSION: u32 = 1;
const DEFAULT_LEASE_SECONDS: i64 = 120;
const WORKER_CREDENTIAL_HEADER: &str = "x-lazyteam-worker-credential";

pub(crate) type ApiError = (StatusCode, String);
pub(crate) type ApiResult<T> = Result<Json<T>, ApiError>;

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) db: SqlitePool,
    pub(crate) public_url: Option<String>,
    pub(crate) oauth_password: Option<String>,
    pub(crate) git_credential_key: Option<[u8; 32]>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateProject {
    pub(crate) slug: String,
    pub(crate) name: String,
    pub(crate) repo_url: String,
    #[serde(default = "default_branch")]
    pub(crate) default_branch: String,
    #[serde(default)]
    pub(crate) required_worker_tags: Tags,
    #[serde(default)]
    pub(crate) default_task_tags: Tags,
    #[serde(default)]
    pub(crate) reviewer: ReviewerConfig,
    #[serde(default)]
    pub(crate) git_auth: ProjectGitAuthInput,
}

fn default_branch() -> String { "main".into() }

#[derive(Debug, Deserialize, Default)]
pub(crate) struct ProjectGitAuthInput {
    #[serde(default)]
    pub(crate) mode: GitAuthMode,
    #[serde(default)]
    pub(crate) username: Option<String>,
    #[serde(default)]
    pub(crate) secret: Option<String>,
}

#[derive(Debug)]
struct StoredGitAuth {
    mode: GitAuthMode,
    username: Option<String>,
    encrypted_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct UpdateProject {
    slug: Option<String>,
    name: Option<String>,
    repo_url: Option<String>,
    default_branch: Option<String>,
    required_worker_tags: Option<Tags>,
    default_task_tags: Option<Tags>,
    reviewer: Option<ReviewerConfig>,
    git_auth: Option<ProjectGitAuthInput>,
    enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WorkerRef {
    id: Uuid,
    name: String,
}

#[derive(Debug, Serialize)]
struct TaskBoardItem {
    task: Task,
    worker: Option<WorkerRef>,
    result: Option<ExecutionResult>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReviewCheckout {
    pub(crate) repo_url: String,
    pub(crate) default_branch: String,
    pub(crate) review_ref: Option<String>,
    pub(crate) commit_sha: Option<String>,
    pub(crate) base_sha: Option<String>,
    pub(crate) pullable: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReviewEvidence {
    pub(crate) project: Project,
    pub(crate) task: Task,
    pub(crate) execution: Execution,
    pub(crate) worker: Worker,
    pub(crate) checkout: ReviewCheckout,
}

#[derive(Debug, Serialize)]
struct WorkerCleanup {
    task_id: Uuid,
    project_slug: String,
    review_ref: String,
    git_credential: GitCredential,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateTask {
    pub(crate) project_id: Uuid,
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) description: String,
    #[serde(default)]
    pub(crate) expected_outcome: String,
    #[serde(default)]
    pub(crate) acceptance_criteria: Vec<String>,
    #[serde(default)]
    pub(crate) required_tags: Tags,
    #[serde(default)]
    pub(crate) preferred_tags: Tags,
    #[serde(default)]
    pub(crate) dependencies: Vec<Uuid>,
    #[serde(default)]
    pub(crate) priority: i32,
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
    #[serde(default = "default_agent_type")]
    agent_type: String,
    #[serde(default)]
    agent_capabilities: AgentCapabilities,
}

#[derive(Debug, Deserialize)]
struct UpdateWorker {
    name: Option<String>,
    tags: Option<Tags>,
    allowed_projects: Option<BTreeSet<String>>,
    slots: Option<u32>,
    agent_type: Option<String>,
    provider: Option<String>,
    model: Option<String>,
    clear_model: Option<bool>,
    initial_prompt: Option<String>,
}

#[derive(Debug, Serialize)]
struct WorkerRuntimeConfig {
    agent: AgentConfig,
}

fn default_slots() -> u32 { 1 }
fn default_protocol() -> u32 { PROTOCOL_VERSION }
fn default_agent_type() -> String { "pi".into() }

#[derive(Debug, Deserialize)]
struct FinishExecution {
    result: ExecutionResult,
}

#[derive(Debug, Serialize)]
struct WorkerJoinCode {
    join_code: String,
    server: String,
    expires_at: DateTime<Utc>,
}

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health))
        .route("/api/projects", get(list_projects).post(create_project))
        .route("/api/projects/{id}", axum::routing::patch(update_project).delete(delete_project))
        .route("/api/tasks", get(list_tasks).post(create_task))
        .route("/api/tasks/{id}/review", get(review_evidence))
        .route("/api/task-board", get(task_board))
        .route("/api/workers", get(list_workers))
        .route("/api/workers/{id}", axum::routing::patch(update_worker))
        .route("/api/worker-join", post(create_worker_join_code))
        .route("/api/workers/register", post(register_worker))
        .route("/api/workers/{id}/config", get(worker_runtime_config))
        .route("/api/workers/{id}/capabilities", post(update_worker_capabilities))
        .route("/api/workers/{id}/heartbeat", post(worker_heartbeat))
        .route("/api/workers/{id}/cleanup", get(worker_cleanup))
        .route("/api/workers/{id}/cleanup/{task_id}", post(worker_cleanup_ack))
        .route("/api/workers/{id}/claim", post(claim_task))
        .route("/api/executions/{id}/renew", post(renew_execution))
        .route("/api/executions/{id}/finish", post(finish_execution))
}

async fn health() -> &'static str { "ok" }

async fn create_worker_join_code(State(state): State<Arc<AppState>>) -> ApiResult<WorkerJoinCode> {
    let server = state.public_url.as_deref().ok_or((
        StatusCode::CONFLICT,
        "LAZYTEAM_PUBLIC_URL is required to generate a worker join code".into(),
    ))?;
    let (join_code, exp) = crate::security::issue_worker_join_code(server).map_err(internal)?;
    let expires_at = DateTime::from_timestamp(exp, 0)
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "invalid worker join expiry".into()))?;
    Ok(Json(WorkerJoinCode {
        join_code,
        server: server.to_string(),
        expires_at,
    }))
}

pub(crate) async fn create_project(State(state): State<Arc<AppState>>, Json(input): Json<CreateProject>) -> ApiResult<Project> {
    if input.slug.is_empty() || !input.slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
        return Err((StatusCode::BAD_REQUEST, "invalid project slug".into()));
    }
    if input.name.trim().is_empty() || input.repo_url.trim().is_empty() || input.default_branch.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "project name, repository, and default branch are required".into()));
    }
    if input.reviewer.initial_prompt.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "reviewer initial prompt must not be empty".into()));
    }
    let stored_git_auth = resolve_new_git_auth(&state, input.git_auth)?;
    let now = Utc::now();
    let project = Project {
        id: Uuid::new_v4(), slug: input.slug, name: input.name.trim().into(), repo_url: input.repo_url.trim().into(),
        default_branch: input.default_branch.trim().into(), required_worker_tags: input.required_worker_tags,
        default_task_tags: input.default_task_tags, reviewer: input.reviewer,
        git_auth: git_auth_summary(&stored_git_auth), enabled: true, created_at: now, updated_at: now,
    };
    sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,required_worker_tags,default_task_tags,reviewer_mode,reviewer_prompt,git_auth_mode,git_auth_username,git_auth_secret,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(project.id.to_string()).bind(&project.slug).bind(&project.name).bind(&project.repo_url)
        .bind(&project.default_branch).bind(json(&project.required_worker_tags)?).bind(json(&project.default_task_tags)?)
        .bind(reviewer_mode_str(&project.reviewer.mode)).bind(&project.reviewer.initial_prompt)
        .bind(git_auth_mode_str(&stored_git_auth.mode)).bind(&stored_git_auth.username).bind(&stored_git_auth.encrypted_secret)
        .bind(1_i64).bind(ts(project.created_at)).bind(ts(project.updated_at))
        .execute(&state.db).await.map_err(db_conflict)?;
    Ok(Json(project))
}

pub(crate) async fn list_projects(State(state): State<Arc<AppState>>) -> ApiResult<Vec<Project>> {
    let rows = sqlx::query("SELECT * FROM projects ORDER BY slug").fetch_all(&state.db).await.map_err(db_error)?;
    rows.iter().map(project_from_row).collect::<Result<Vec<_>,_>>().map(Json)
}

async fn update_project(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, Json(input): Json<UpdateProject>) -> ApiResult<Project> {
    let row = sqlx::query("SELECT * FROM projects WHERE id=?")
        .bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "project not found".into()))?;
    let current = project_from_row(&row)?;
    let slug = input.slug.unwrap_or(current.slug);
    if slug.is_empty() || !slug.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_') {
        return Err((StatusCode::BAD_REQUEST, "invalid project slug".into()));
    }
    let name = input.name.unwrap_or(current.name);
    let repo_url = input.repo_url.unwrap_or(current.repo_url);
    let default_branch = input.default_branch.unwrap_or(current.default_branch);
    if name.trim().is_empty() || repo_url.trim().is_empty() || default_branch.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "project name, repository, and default branch are required".into()));
    }
    let reviewer = input.reviewer.unwrap_or(current.reviewer);
    if reviewer.initial_prompt.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "reviewer initial prompt must not be empty".into()));
    }
    let stored_git_auth = resolve_updated_git_auth(&state, &row, input.git_auth)?;
    sqlx::query("UPDATE projects SET slug=?,name=?,repo_url=?,default_branch=?,required_worker_tags=?,default_task_tags=?,reviewer_mode=?,reviewer_prompt=?,git_auth_mode=?,git_auth_username=?,git_auth_secret=?,enabled=?,updated_at=? WHERE id=?")
        .bind(&slug).bind(name.trim()).bind(repo_url.trim()).bind(default_branch.trim())
        .bind(json(&input.required_worker_tags.unwrap_or(current.required_worker_tags))?)
        .bind(json(&input.default_task_tags.unwrap_or(current.default_task_tags))?)
        .bind(reviewer_mode_str(&reviewer.mode)).bind(reviewer.initial_prompt.trim())
        .bind(git_auth_mode_str(&stored_git_auth.mode)).bind(&stored_git_auth.username).bind(&stored_git_auth.encrypted_secret)
        .bind(if input.enabled.unwrap_or(current.enabled) { 1_i64 } else { 0_i64 })
        .bind(ts(Utc::now())).bind(id.to_string()).execute(&state.db).await.map_err(db_conflict)?;
    let row = sqlx::query("SELECT * FROM projects WHERE id=?").bind(id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    Ok(Json(project_from_row(&row)?))
}

async fn delete_project(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>) -> Result<StatusCode, ApiError> {
    let task_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE project_id=?")
        .bind(id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    if task_count > 0 {
        return Err((StatusCode::CONFLICT, "project has task history; disable it instead of deleting it".into()));
    }
    let changed = sqlx::query("DELETE FROM projects WHERE id=?").bind(id.to_string()).execute(&state.db).await.map_err(db_error)?.rows_affected();
    if changed == 0 { return Err((StatusCode::NOT_FOUND, "project not found".into())); }
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn create_task(State(state): State<Arc<AppState>>, Json(input): Json<CreateTask>) -> ApiResult<Task> {
    let project_id = input.project_id.to_string();
    let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM projects WHERE id=? AND enabled=1")
        .bind(&project_id).fetch_one(&state.db).await.map_err(db_error)?;
    if exists == 0 { return Err((StatusCode::BAD_REQUEST, "unknown or disabled project".into())); }
    for dep in &input.dependencies {
        let dep_project: Option<String> = sqlx::query_scalar("SELECT project_id FROM tasks WHERE id=?")
            .bind(dep.to_string()).fetch_optional(&state.db).await.map_err(db_error)?;
        if dep_project.as_deref() != Some(project_id.as_str()) {
            return Err((StatusCode::BAD_REQUEST, "dependencies must exist in the same project".into()));
        }
    }
    let now = Utc::now();
    let task = Task {
        id: Uuid::new_v4(), project_id: input.project_id, title: input.title, description: input.description,
        expected_outcome: input.expected_outcome, acceptance_criteria: input.acceptance_criteria,
        required_tags: input.required_tags, preferred_tags: input.preferred_tags, dependencies: input.dependencies,
        review_feedback: String::new(), priority: input.priority, state: TaskState::Queued, created_at: now, updated_at: now,
    };
    sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,acceptance_criteria,required_tags,preferred_tags,dependencies,review_feedback,priority,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(task.id.to_string()).bind(task.project_id.to_string()).bind(&task.title).bind(&task.description)
        .bind(&task.expected_outcome).bind(json(&task.acceptance_criteria)?).bind(json(&task.required_tags)?)
        .bind(json(&task.preferred_tags)?).bind(json(&task.dependencies)?).bind(&task.review_feedback).bind(task.priority).bind("queued")
        .bind(ts(task.created_at)).bind(ts(task.updated_at)).execute(&state.db).await.map_err(db_error)?;
    Ok(Json(task))
}

pub(crate) async fn list_tasks(State(state): State<Arc<AppState>>) -> ApiResult<Vec<Task>> {
    let rows = sqlx::query("SELECT * FROM tasks ORDER BY priority DESC, created_at ASC").fetch_all(&state.db).await.map_err(db_error)?;
    rows.iter().map(task_from_row).collect::<Result<Vec<_>,_>>().map(Json)
}

pub(crate) async fn review_evidence(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>) -> ApiResult<ReviewEvidence> {
    let task_row = sqlx::query("SELECT * FROM tasks WHERE id=?").bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "task not found".into()))?;
    let task = task_from_row(&task_row)?;
    if !matches!(task.state, TaskState::Review | TaskState::MergePending | TaskState::Done) {
        return Err((StatusCode::CONFLICT, "review evidence is available only for review/merge_pending/done tasks".into()));
    }
    let project_row = sqlx::query("SELECT * FROM projects WHERE id=?").bind(task.project_id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    let project = project_from_row(&project_row)?;
    let execution_row = sqlx::query("SELECT * FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(task.id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "task has no execution to review".into()))?;
    let execution = execution_from_row(&execution_row)?;
    let worker_row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(execution.worker_id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    let worker = worker_from_row(&worker_row)?;
    let result = execution.result.as_ref();
    let checkout = ReviewCheckout {
        repo_url: project.repo_url.clone(),
        default_branch: project.default_branch.clone(),
        review_ref: result.and_then(|value| value.review_ref.clone()),
        commit_sha: result.and_then(|value| value.commit_sha.clone()),
        base_sha: result.and_then(|value| value.base_sha.clone()),
        pullable: result.is_some_and(|value| value.review_ref.is_some() && value.commit_sha.is_some()),
    };
    Ok(Json(ReviewEvidence { project, task, execution, worker, checkout }))
}

async fn task_board(State(state): State<Arc<AppState>>) -> ApiResult<Vec<TaskBoardItem>> {
    let rows = sqlx::query("SELECT t.*, e.worker_id AS board_worker_id, w.name AS board_worker_name, e.result AS board_result FROM tasks t LEFT JOIN executions e ON e.id=(SELECT e2.id FROM executions e2 WHERE e2.task_id=t.id ORDER BY e2.attempt DESC LIMIT 1) LEFT JOIN workers w ON w.id=e.worker_id ORDER BY t.priority DESC, t.created_at ASC")
        .fetch_all(&state.db).await.map_err(db_error)?;
    rows.iter().map(|row| {
        let task = task_from_row(row)?;
        let worker_id: Option<String> = row.try_get("board_worker_id").map_err(internal)?;
        let worker_name: Option<String> = row.try_get("board_worker_name").map_err(internal)?;
        let worker = match (worker_id, worker_name) {
            (Some(id), Some(name)) => Some(WorkerRef { id: uuid(id)?, name }),
            _ => None,
        };
        let result: Option<String> = row.try_get("board_result").map_err(internal)?;
        let result = result.map(dejson).transpose()?;
        Ok(TaskBoardItem { task, worker, result })
    }).collect::<Result<Vec<_>, ApiError>>().map(Json)
}

async fn register_worker(State(state): State<Arc<AppState>>, Json(input): Json<RegisterWorker>) -> Result<Response, ApiError> {
    if !(MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&input.protocol_version) {
        return Err((StatusCode::BAD_REQUEST, format!("unsupported worker protocol {}; supported {}..={}", input.protocol_version, MIN_PROTOCOL_VERSION, PROTOCOL_VERSION)));
    }
    let id = input.id.unwrap_or_else(Uuid::new_v4);
    let now = Utc::now();
    let credential = format!("ltw_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let credential_hash = hash_secret(&credential);
    let mut tags = input.tags;
    tags.entry("os".into()).or_insert_with(|| input.os.clone());
    tags.entry("arch".into()).or_insert_with(|| input.arch.clone());
    if input.agent_type != "pi" {
        return Err((StatusCode::BAD_REQUEST, "unsupported agent type".into()));
    }
    let agent_capabilities = json(&input.agent_capabilities)?;
    sqlx::query("INSERT INTO workers(id,name,state,os,arch,tags,allowed_projects,slots,running_slots,protocol_version,worker_version,last_heartbeat_at,created_at,credential_hash,agent_type,agent_provider,agent_model,initial_prompt,agent_capabilities) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,state=CASE WHEN workers.running_slots>0 THEN 'busy' ELSE 'idle' END,os=excluded.os,arch=excluded.arch,protocol_version=excluded.protocol_version,worker_version=excluded.worker_version,last_heartbeat_at=excluded.last_heartbeat_at,credential_hash=excluded.credential_hash,agent_capabilities=excluded.agent_capabilities")
        .bind(id.to_string()).bind(&input.name).bind("idle").bind(&input.os).bind(&input.arch).bind(json(&tags)?)
        .bind(json(&input.allowed_projects)?).bind(input.slots.max(1) as i64).bind(0_i64).bind(input.protocol_version as i64)
        .bind(&input.worker_version).bind(ts(now)).bind(ts(now)).bind(credential_hash).bind(&input.agent_type)
        .bind(Option::<String>::None).bind(Option::<String>::None).bind(DEFAULT_WORKER_PROMPT).bind(agent_capabilities)
        .execute(&state.db).await.map_err(db_error)?;
    let row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    let mut response = Json(worker_from_row(&row)?).into_response();
    response.headers_mut().insert(
        HeaderName::from_static(WORKER_CREDENTIAL_HEADER),
        HeaderValue::from_str(&credential).map_err(internal)?,
    );
    Ok(response)
}

pub(crate) async fn list_workers(State(state): State<Arc<AppState>>) -> ApiResult<Vec<Worker>> {
    let rows = sqlx::query("SELECT * FROM workers ORDER BY name").fetch_all(&state.db).await.map_err(db_error)?;
    rows.iter().map(worker_from_row).collect::<Result<Vec<_>,_>>().map(Json)
}

async fn update_worker(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, Json(input): Json<UpdateWorker>) -> ApiResult<Worker> {
    let row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let current = worker_from_row(&row)?;
    let agent_type = input.agent_type.unwrap_or(current.agent.agent_type);
    if agent_type != "pi" { return Err((StatusCode::BAD_REQUEST, "unsupported agent type".into())); }
    let (provider, model) = if input.clear_model.unwrap_or(false) {
        (None, None)
    } else {
        (input.provider.or(current.agent.provider), input.model.or(current.agent.model))
    };
    if provider.is_some() != model.is_some() {
        return Err((StatusCode::BAD_REQUEST, "provider and model must be set or cleared together".into()));
    }
    if let (Some(provider), Some(model)) = (&provider, &model) {
        if !current.agent_capabilities.models.is_empty()
            && !current.agent_capabilities.models.iter().any(|candidate| &candidate.provider == provider && &candidate.id == model)
        {
            return Err((StatusCode::BAD_REQUEST, "selected provider/model is not reported by this worker".into()));
        }
    }
    let initial_prompt = input.initial_prompt.unwrap_or(current.agent.initial_prompt);
    if initial_prompt.trim().is_empty() { return Err((StatusCode::BAD_REQUEST, "initial prompt must not be empty".into())); }
    let name = input.name.unwrap_or(current.name);
    if name.trim().is_empty() { return Err((StatusCode::BAD_REQUEST, "worker name must not be empty".into())); }
    let tags = input.tags.unwrap_or(current.tags);
    let allowed_projects = input.allowed_projects.unwrap_or(current.allowed_projects);
    let slots = input.slots.unwrap_or(current.slots).max(1);
    sqlx::query("UPDATE workers SET name=?,tags=?,allowed_projects=?,slots=?,agent_type=?,agent_provider=?,agent_model=?,initial_prompt=? WHERE id=?")
        .bind(name.trim()).bind(json(&tags)?).bind(json(&allowed_projects)?).bind(slots as i64)
        .bind(&agent_type).bind(&provider).bind(&model).bind(initial_prompt.trim()).bind(id.to_string())
        .execute(&state.db).await.map_err(db_error)?;
    let row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    Ok(Json(worker_from_row(&row)?))
}

async fn worker_runtime_config(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<WorkerRuntimeConfig> {
    require_worker(&state.db, id, &headers).await?;
    let row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    let worker = worker_from_row(&row)?;
    Ok(Json(WorkerRuntimeConfig { agent: worker.agent }))
}

async fn update_worker_capabilities(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap, Json(capabilities): Json<AgentCapabilities>) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let changed = sqlx::query("UPDATE workers SET agent_capabilities=? WHERE id=?")
        .bind(json(&capabilities)?).bind(id.to_string()).execute(&state.db).await.map_err(db_error)?.rows_affected();
    if changed == 0 { return Err((StatusCode::NOT_FOUND, "worker not found".into())); }
    Ok(StatusCode::NO_CONTENT)
}

async fn worker_heartbeat(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let changed = sqlx::query("UPDATE workers SET last_heartbeat_at=?, state=CASE WHEN state='draining' THEN state WHEN running_slots>0 THEN 'busy' ELSE 'idle' END WHERE id=?")
        .bind(ts(Utc::now())).bind(id.to_string()).execute(&state.db).await.map_err(db_error)?.rows_affected();
    if changed == 0 { return Err((StatusCode::NOT_FOUND, "worker not found".into())); }
    Ok(StatusCode::NO_CONTENT)
}

async fn worker_cleanup(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Vec<WorkerCleanup>> {
    require_worker(&state.db, id, &headers).await?;
    let rows = sqlx::query("SELECT c.task_id,t.project_id,p.slug FROM task_cleanup c JOIN tasks t ON t.id=c.task_id JOIN projects p ON p.id=t.project_id WHERE c.worker_id=? ORDER BY c.created_at ASC")
        .bind(id.to_string()).fetch_all(&state.db).await.map_err(db_error)?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        let task_id = uuid(row.try_get("task_id").map_err(internal)?)?;
        let project_id: String = row.try_get("project_id").map_err(internal)?;
        let project_row = sqlx::query("SELECT * FROM projects WHERE id=?")
            .bind(project_id).fetch_one(&state.db).await.map_err(db_error)?;
        items.push(WorkerCleanup {
            task_id,
            project_slug: row.try_get("slug").map_err(internal)?,
            review_ref: format!("lazyteam/task-{}", task_id.simple()),
            git_credential: git_credential_from_row(&state, &project_row)?,
        });
    }
    Ok(Json(items))
}

async fn worker_cleanup_ack(Path((id, task_id)): Path<(Uuid, Uuid)>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let changed = sqlx::query("DELETE FROM task_cleanup WHERE task_id=? AND worker_id=?")
        .bind(task_id.to_string()).bind(id.to_string()).execute(&state.db).await.map_err(db_error)?.rows_affected();
    if changed == 0 { return Err((StatusCode::NOT_FOUND, "cleanup item not found".into())); }
    Ok(StatusCode::NO_CONTENT)
}

async fn claim_task(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let worker = worker_from_row(&row)?;
    if worker.running_slots >= worker.slots || matches!(worker.state, WorkerState::Draining | WorkerState::Degraded | WorkerState::Offline) {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    let rows = sqlx::query("SELECT * FROM tasks WHERE state='queued' ORDER BY priority DESC, created_at ASC LIMIT 100")
        .fetch_all(&state.db).await.map_err(db_error)?;
    let worker_id_text = worker.id.to_string();
    for row in rows {
        let sticky_worker_id: Option<String> = row.try_get("sticky_worker_id").map_err(internal)?;
        if sticky_worker_id.as_deref().is_some_and(|sticky| sticky != worker_id_text) { continue; }
        let task = task_from_row(&row)?;
        if !dependencies_satisfied(&state.db, &task).await? { continue; }
        let project_row = sqlx::query("SELECT * FROM projects WHERE id=? AND enabled=1").bind(task.project_id.to_string())
            .fetch_optional(&state.db).await.map_err(db_error)?;
        let Some(project_row) = project_row else { continue };
        let project = project_from_row(&project_row)?;
        if !worker_matches_task(&worker, &project, &task) { continue; }
        if project.git_auth.mode != GitAuthMode::Worker && worker.protocol_version < 2 { continue; }
        let git_credential = git_credential_from_row(&state, &project_row)?;

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
        return Ok(Json(Assignment { project, task: assigned_task, execution, git_credential }).into_response());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn renew_execution(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    let now = Utc::now();
    let lease = now + chrono::Duration::seconds(DEFAULT_LEASE_SECONDS);
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let row = sqlx::query("SELECT task_id,worker_id FROM executions WHERE id=? AND state IN ('assigned','running')")
        .bind(id.to_string()).fetch_optional(&mut *tx).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "execution is not active".into()))?;
    let task_id: String = row.try_get("task_id").map_err(internal)?;
    let worker_id: String = row.try_get("worker_id").map_err(internal)?;
    let worker_id = uuid(worker_id)?;
    require_worker(&state.db, worker_id, &headers).await?;
    if !is_latest_execution(&mut tx, &task_id, id).await? { return Err((StatusCode::CONFLICT, "stale execution".into())); }
    sqlx::query("UPDATE executions SET state='running',lease_until=?,started_at=COALESCE(started_at,?) WHERE id=?")
        .bind(ts(lease)).bind(ts(now)).bind(id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
    sqlx::query("UPDATE tasks SET state='running',updated_at=? WHERE id=? AND state IN ('assigned','running')")
        .bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn finish_execution(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap, Json(input): Json<FinishExecution>) -> Result<StatusCode, ApiError> {
    let now = Utc::now();
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let row = sqlx::query("SELECT task_id,worker_id FROM executions WHERE id=? AND state IN ('assigned','running')")
        .bind(id.to_string()).fetch_optional(&mut *tx).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "execution is not active".into()))?;
    let task_id: String = row.try_get("task_id").map_err(internal)?;
    let worker_id: String = row.try_get("worker_id").map_err(internal)?;
    require_worker(&state.db, uuid(worker_id.clone())?, &headers).await?;
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

async fn require_worker(db: &SqlitePool, worker_id: Uuid, headers: &HeaderMap) -> Result<(), ApiError> {
    let supplied = headers
        .get(WORKER_CREDENTIAL_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "worker credential required".into()))?;
    let stored: Option<String> = sqlx::query_scalar("SELECT credential_hash FROM workers WHERE id=?")
        .bind(worker_id.to_string())
        .fetch_optional(db)
        .await
        .map_err(db_error)?
        .flatten();
    let Some(stored) = stored else {
        return Err((StatusCode::UNAUTHORIZED, "worker credential rejected".into()));
    };
    if !secure_hash_eq(&hash_secret(supplied), &stored) {
        return Err((StatusCode::UNAUTHORIZED, "worker credential rejected".into()));
    }
    Ok(())
}

fn hash_secret(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

fn secure_hash_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes()) { diff |= x ^ y; }
    diff == 0
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
    let expected = execution_id.to_string();
    Ok(latest.as_deref() == Some(expected.as_str()))
}

pub(crate) async fn reaper(state: Arc<AppState>) {
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

fn git_auth_mode_str(mode: &GitAuthMode) -> &'static str {
    match mode {
        GitAuthMode::Worker => "worker",
        GitAuthMode::SshKey => "ssh_key",
        GitAuthMode::HttpsBasic => "https_basic",
    }
}

fn git_auth_mode(value: &str) -> Result<GitAuthMode, ApiError> {
    match value {
        "worker" => Ok(GitAuthMode::Worker),
        "ssh_key" => Ok(GitAuthMode::SshKey),
        "https_basic" => Ok(GitAuthMode::HttpsBasic),
        _ => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("invalid Git auth mode {value}"))),
    }
}

fn stored_git_auth_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<StoredGitAuth, ApiError> {
    let mode: String = row.try_get("git_auth_mode").map_err(internal)?;
    Ok(StoredGitAuth {
        mode: git_auth_mode(&mode)?,
        username: row.try_get("git_auth_username").map_err(internal)?,
        encrypted_secret: row.try_get("git_auth_secret").map_err(internal)?,
    })
}

fn git_auth_summary(stored: &StoredGitAuth) -> GitAuthConfig {
    GitAuthConfig {
        mode: stored.mode.clone(),
        credential_configured: stored.encrypted_secret.is_some(),
        username: stored.username.clone(),
    }
}

fn git_credential_key(state: &AppState) -> Result<&[u8; 32], ApiError> {
    state.git_credential_key.as_ref().ok_or((
        StatusCode::CONFLICT,
        "LAZYTEAM_GIT_CREDENTIAL_KEY must be configured before storing or using server-managed Git credentials".into(),
    ))
}

fn encrypt_git_secret(state: &AppState, secret: &str) -> Result<String, ApiError> {
    crate::git_credentials::encrypt(git_credential_key(state)?, secret).map_err(internal)
}

fn decrypt_git_secret(state: &AppState, ciphertext: &str) -> Result<String, ApiError> {
    crate::git_credentials::decrypt(git_credential_key(state)?, ciphertext).map_err(|error| (
        StatusCode::INTERNAL_SERVER_ERROR,
        format!("stored project Git credential cannot be decrypted: {error}"),
    ))
}

fn nonempty_secret(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.trim().is_empty())
}

fn resolve_new_git_auth(state: &AppState, input: ProjectGitAuthInput) -> Result<StoredGitAuth, ApiError> {
    match input.mode {
        GitAuthMode::Worker => {
            if nonempty_secret(input.secret).is_some() {
                return Err((StatusCode::BAD_REQUEST, "worker-managed Git auth must not include a server-side secret".into()));
            }
            Ok(StoredGitAuth { mode: GitAuthMode::Worker, username: None, encrypted_secret: None })
        }
        GitAuthMode::SshKey => {
            let secret = nonempty_secret(input.secret).ok_or((
                StatusCode::BAD_REQUEST,
                "SSH key mode requires a private key".into(),
            ))?;
            Ok(StoredGitAuth {
                mode: GitAuthMode::SshKey,
                username: None,
                encrypted_secret: Some(encrypt_git_secret(state, &secret)?),
            })
        }
        GitAuthMode::HttpsBasic => {
            let username = input.username.map(|value| value.trim().to_string()).filter(|value| !value.is_empty()).ok_or((
                StatusCode::BAD_REQUEST,
                "HTTPS username + password/token mode requires a username".into(),
            ))?;
            let secret = nonempty_secret(input.secret).ok_or((
                StatusCode::BAD_REQUEST,
                "HTTPS username + password/token mode requires a password or token".into(),
            ))?;
            Ok(StoredGitAuth {
                mode: GitAuthMode::HttpsBasic,
                username: Some(username),
                encrypted_secret: Some(encrypt_git_secret(state, &secret)?),
            })
        }
    }
}

fn resolve_updated_git_auth(
    state: &AppState,
    row: &sqlx::sqlite::SqliteRow,
    input: Option<ProjectGitAuthInput>,
) -> Result<StoredGitAuth, ApiError> {
    let current = stored_git_auth_from_row(row)?;
    let Some(input) = input else { return Ok(current); };
    match input.mode {
        GitAuthMode::Worker => Ok(StoredGitAuth {
            mode: GitAuthMode::Worker,
            username: None,
            encrypted_secret: None,
        }),
        GitAuthMode::SshKey => {
            let encrypted_secret = match nonempty_secret(input.secret) {
                Some(secret) => Some(encrypt_git_secret(state, &secret)?),
                None if current.mode == GitAuthMode::SshKey && current.encrypted_secret.is_some() => current.encrypted_secret,
                None => return Err((StatusCode::BAD_REQUEST, "switching to SSH key mode requires a private key".into())),
            };
            Ok(StoredGitAuth {
                mode: GitAuthMode::SshKey,
                username: None,
                encrypted_secret,
            })
        }
        GitAuthMode::HttpsBasic => {
            let username = input
                .username
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .or_else(|| (current.mode == GitAuthMode::HttpsBasic).then(|| current.username.clone()).flatten())
                .ok_or((StatusCode::BAD_REQUEST, "HTTPS username + password/token mode requires a username".into()))?;
            let encrypted_secret = match nonempty_secret(input.secret) {
                Some(secret) => Some(encrypt_git_secret(state, &secret)?),
                None if current.mode == GitAuthMode::HttpsBasic && current.encrypted_secret.is_some() => current.encrypted_secret,
                None => return Err((StatusCode::BAD_REQUEST, "switching to HTTPS auth requires a password or token".into())),
            };
            Ok(StoredGitAuth {
                mode: GitAuthMode::HttpsBasic,
                username: Some(username),
                encrypted_secret,
            })
        }
    }
}

fn git_credential_from_row(state: &AppState, row: &sqlx::sqlite::SqliteRow) -> Result<GitCredential, ApiError> {
    let stored = stored_git_auth_from_row(row)?;
    match stored.mode {
        GitAuthMode::Worker => Ok(GitCredential::Worker),
        GitAuthMode::SshKey => {
            let encrypted = stored.encrypted_secret.ok_or((
                StatusCode::CONFLICT,
                "project SSH credential is not configured".into(),
            ))?;
            Ok(GitCredential::SshKey { private_key: decrypt_git_secret(state, &encrypted)? })
        }
        GitAuthMode::HttpsBasic => {
            let username = stored.username.ok_or((
                StatusCode::CONFLICT,
                "project HTTPS Git username is not configured".into(),
            ))?;
            let encrypted = stored.encrypted_secret.ok_or((
                StatusCode::CONFLICT,
                "project HTTPS Git password/token is not configured".into(),
            ))?;
            Ok(GitCredential::HttpsBasic {
                username,
                secret: decrypt_git_secret(state, &encrypted)?,
            })
        }
    }
}

fn project_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Project, ApiError> {
    Ok(Project {
        id: uuid(row.try_get("id").map_err(internal)?)?, slug: row.try_get("slug").map_err(internal)?, name: row.try_get("name").map_err(internal)?,
        repo_url: row.try_get("repo_url").map_err(internal)?, default_branch: row.try_get("default_branch").map_err(internal)?,
        required_worker_tags: dejson(row.try_get("required_worker_tags").map_err(internal)?)?, default_task_tags: dejson(row.try_get("default_task_tags").map_err(internal)?)?,
        reviewer: ReviewerConfig {
            mode: reviewer_mode(row.try_get("reviewer_mode").map_err(internal)?)?,
            initial_prompt: {
                let value: String = row.try_get("reviewer_prompt").map_err(internal)?;
                if value.trim().is_empty() { DEFAULT_REVIEWER_PROMPT.into() } else { value }
            },
        },
        git_auth: git_auth_summary(&stored_git_auth_from_row(row)?),
        enabled: row.try_get::<i64,_>("enabled").map_err(internal)? != 0, created_at: datetime(row.try_get("created_at").map_err(internal)?)?,
        updated_at: datetime(row.try_get("updated_at").map_err(internal)?)?,
    })
}

fn worker_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Worker, ApiError> {
    let state: String = row.try_get("state").map_err(internal)?;
    let initial_prompt: String = row.try_get("initial_prompt").map_err(internal)?;
    let capabilities_raw: String = row.try_get("agent_capabilities").map_err(internal)?;
    let capabilities = serde_json::from_str::<AgentCapabilities>(&capabilities_raw).unwrap_or_default();
    Ok(Worker { id: uuid(row.try_get("id").map_err(internal)?)?, name: row.try_get("name").map_err(internal)?,
        state: match state.as_str() { "busy" => WorkerState::Busy, "draining" => WorkerState::Draining, "degraded" => WorkerState::Degraded, "offline" => WorkerState::Offline, _ => WorkerState::Idle },
        os: row.try_get("os").map_err(internal)?, arch: row.try_get("arch").map_err(internal)?, tags: dejson(row.try_get("tags").map_err(internal)?)?,
        allowed_projects: dejson(row.try_get("allowed_projects").map_err(internal)?)?, slots: row.try_get::<i64,_>("slots").map_err(internal)? as u32,
        running_slots: row.try_get::<i64,_>("running_slots").map_err(internal)? as u32, protocol_version: row.try_get::<i64,_>("protocol_version").map_err(internal)? as u32,
        worker_version: row.try_get("worker_version").map_err(internal)?, last_heartbeat_at: datetime(row.try_get("last_heartbeat_at").map_err(internal)?)?,
        agent: AgentConfig {
            agent_type: row.try_get("agent_type").map_err(internal)?,
            provider: row.try_get("agent_provider").map_err(internal)?,
            model: row.try_get("agent_model").map_err(internal)?,
            initial_prompt: if initial_prompt.trim().is_empty() { DEFAULT_WORKER_PROMPT.into() } else { initial_prompt },
        },
        agent_capabilities: capabilities })
}

fn execution_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Execution, ApiError> {
    let state: String = row.try_get("state").map_err(internal)?;
    let result: Option<String> = row.try_get("result").map_err(internal)?;
    Ok(Execution {
        id: uuid(row.try_get("id").map_err(internal)?)?,
        task_id: uuid(row.try_get("task_id").map_err(internal)?)?,
        worker_id: uuid(row.try_get("worker_id").map_err(internal)?)?,
        attempt: row.try_get::<i64,_>("attempt").map_err(internal)? as u32,
        state: match state.as_str() { "running"=>ExecutionState::Running,"completed"=>ExecutionState::Completed,"failed"=>ExecutionState::Failed,"lost"=>ExecutionState::Lost,"cancelled"=>ExecutionState::Cancelled,_=>ExecutionState::Assigned },
        lease_until: datetime(row.try_get("lease_until").map_err(internal)?)?,
        started_at: row.try_get::<Option<String>,_>("started_at").map_err(internal)?.map(datetime).transpose()?,
        finished_at: row.try_get::<Option<String>,_>("finished_at").map_err(internal)?.map(datetime).transpose()?,
        result: result.map(dejson).transpose()?,
    })
}

fn reviewer_mode_str(mode: &ReviewerMode) -> &'static str {
    match mode { ReviewerMode::Manual => "manual", ReviewerMode::Mcp => "mcp" }
}

fn reviewer_mode(value: String) -> Result<ReviewerMode, ApiError> {
    match value.as_str() { "manual" => Ok(ReviewerMode::Manual), "mcp" => Ok(ReviewerMode::Mcp), _ => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("invalid reviewer mode {value}"))) }
}

fn task_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Task, ApiError> {
    let state: String = row.try_get("state").map_err(internal)?;
    Ok(Task { id: uuid(row.try_get("id").map_err(internal)?)?, project_id: uuid(row.try_get("project_id").map_err(internal)?)?,
        title: row.try_get("title").map_err(internal)?, description: row.try_get("description").map_err(internal)?, expected_outcome: row.try_get("expected_outcome").map_err(internal)?,
        acceptance_criteria: dejson(row.try_get("acceptance_criteria").map_err(internal)?)?, required_tags: dejson(row.try_get("required_tags").map_err(internal)?)?,
        preferred_tags: dejson(row.try_get("preferred_tags").map_err(internal)?)?, dependencies: dejson(row.try_get("dependencies").map_err(internal)?)?, review_feedback: row.try_get("review_feedback").map_err(internal)?, priority: row.try_get("priority").map_err(internal)?,
        state: match state.as_str() { "draft"=>TaskState::Draft,"assigned"=>TaskState::Assigned,"running"=>TaskState::Running,"review"=>TaskState::Review,"merge_pending"=>TaskState::MergePending,"done"=>TaskState::Done,"blocked"=>TaskState::Blocked,"failed"=>TaskState::Failed,"cancelled"=>TaskState::Cancelled,_=>TaskState::Queued },
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
