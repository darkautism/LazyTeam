use std::{collections::{BTreeSet, HashMap}, path::PathBuf, sync::Arc, time::Duration};

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
    managed_capability_tag, worker_can_run_project, worker_matches_task, AgentCapabilities, AgentConfig,
    AgentRole, Assignment, ContributorIdentity, Execution, ExecutionResult, ExecutionState, GitAuthConfig,
    GitAuthMode, GitCredential, Project, ReviewAssignment, ReviewCheckout as WorkerReviewCheckout, ReviewLease,
    ReviewerConfig, ReviewerMode, ReviewVerdict, ReviewVerdictKind, Tags, Task, TaskState, Worker,
    WorkerState, DEFAULT_REVIEWER_PROMPT, DEFAULT_WORKER_PROMPT, LEASE_CAPABILITY_HEADER,
    MANAGED_CAPABILITY_IDS,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use tokio::{sync::Mutex, time::interval};
use tracing::warn;
use uuid::Uuid;

pub(crate) const PROTOCOL_VERSION: u32 = 6;
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
    pub(crate) git_root: PathBuf,
    pub(crate) agent_auth_updates: Arc<Mutex<HashMap<Uuid, PendingAgentAuth>>>,
}

pub(crate) struct PendingAgentAuth {
    id: Uuid,
    provider: String,
    api_key: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateProject {
    pub(crate) slug: String,
    pub(crate) name: String,
    pub(crate) repo_url: String,
    #[serde(default = "default_branch")]
    pub(crate) default_branch: String,
    #[serde(default)]
    pub(crate) contributor: ContributorIdentity,
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

fn normalize_contributor(mut contributor: ContributorIdentity) -> Result<ContributorIdentity, ApiError> {
    contributor.name = contributor.name.trim().to_string();
    contributor.email = contributor.email.trim().to_string();
    if contributor.name.is_empty() || contributor.email.is_empty() || !contributor.email.contains('@') || contributor.email.chars().any(char::is_whitespace) {
        return Err((StatusCode::BAD_REQUEST, "contributor name and a valid email are required".into()));
    }
    Ok(contributor)
}

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
    contributor: Option<ContributorIdentity>,
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
    reviewer: Option<WorkerRef>,
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
    role: AgentRole,
    #[serde(default)]
    agent_capabilities: AgentCapabilities,
}

#[derive(Debug, Deserialize)]
struct UpdateWorker {
    name: Option<String>,
    role: Option<AgentRole>,
    tags: Option<Tags>,
    managed_capabilities: Option<BTreeSet<String>>,
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
    role: AgentRole,
    agent: AgentConfig,
    slots: u32,
    managed_capabilities: BTreeSet<String>,
    installed_capabilities: BTreeSet<String>,
}

#[derive(Deserialize)]
struct AgentApiKeyInput {
    provider: String,
    api_key: String,
}

#[derive(Debug, Serialize)]
struct AgentAuthQueued {
    id: Uuid,
    provider: String,
    queued: bool,
}

#[derive(Serialize)]
struct AgentAuthDelivery {
    id: Uuid,
    provider: String,
    api_key: String,
}

#[derive(Debug, Serialize)]
struct ManagedCapabilityOption {
    id: &'static str,
    label: &'static str,
    tag: String,
}

#[derive(Debug, Deserialize)]
struct CapabilityBuildReport {
    #[serde(default)]
    installed_capabilities: BTreeSet<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    log_tail: Option<String>,
}

fn bounded_capability_log(raw: Option<&str>) -> String {
    const MAX_CHARS: usize = 16_000;
    let raw = raw.unwrap_or_default();
    let count = raw.chars().count();
    if count <= MAX_CHARS { return raw.to_string(); }
    raw.chars().skip(count - MAX_CHARS).collect()
}

fn managed_capability_label(id: &str) -> &'static str {
    match id {
        "rust" => "Rust",
        "python" => "Python",
        "node" => "Node.js",
        "go" => "Go",
        "gcc" => "GCC / C",
        "cpp" => "C++",
        "clang" => "Clang / LLVM",
        "java" => "Java",
        "cmake" => "CMake / Ninja",
        "ruby" => "Ruby",
        "php" => "PHP CLI",
        _ => "Unknown",
    }
}

fn validate_managed_capabilities(capabilities: &BTreeSet<String>) -> Result<(), ApiError> {
    if let Some(unknown) = capabilities.iter().find(|id| !MANAGED_CAPABILITY_IDS.contains(&id.as_str())) {
        return Err((StatusCode::BAD_REQUEST, format!("unknown managed capability {unknown}")));
    }
    Ok(())
}

fn validate_user_tags(tags: &Tags) -> Result<(), ApiError> {
    if let Some(key) = tags.keys().find(|key| key.as_str() == "os" || key.as_str() == "arch" || key.starts_with("tool.")) {
        return Err((StatusCode::BAD_REQUEST, format!("tag {key} is managed by LazyTeam and cannot be edited as a user tag")));
    }
    Ok(())
}

fn effective_worker_tags(os: &str, arch: &str, user_tags: &Tags, managed: &BTreeSet<String>, installed: &BTreeSet<String>) -> Tags {
    let mut tags = Tags::from([("os".into(), os.into()), ("arch".into(), arch.into())]);
    tags.extend(user_tags.clone());
    for capability in managed.intersection(installed) {
        if let Some(tag) = managed_capability_tag(capability) {
            tags.insert(tag, "true".into());
        }
    }
    tags
}

fn worker_state_str(state: &WorkerState) -> &'static str {
    match state {
        WorkerState::Idle => "idle",
        WorkerState::Busy => "busy",
        WorkerState::Pending => "pending",
        WorkerState::Draining => "draining",
        WorkerState::Degraded => "degraded",
        WorkerState::Offline => "offline",
    }
}

fn default_slots() -> u32 { 1 }
fn default_protocol() -> u32 { PROTOCOL_VERSION }
fn default_agent_type() -> String { "pi".into() }

#[derive(Debug, Deserialize)]
struct FinishExecution {
    result: ExecutionResult,
}

#[derive(Debug, Deserialize)]
struct FinishReview {
    #[serde(default = "default_completed_status")]
    status: String,
    #[serde(default)]
    verdict: Option<ReviewVerdict>,
    #[serde(default)]
    error: Option<String>,
}

fn default_completed_status() -> String { "completed".into() }

#[derive(Debug, Serialize)]
struct WorkerJoinCode {
    join_code: String,
    server: String,
    expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct GitProbeResult {
    ok: bool,
    message: String,
    checked_at: DateTime<Utc>,
}

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health))
        .route("/api/projects", get(list_projects).post(create_project))
        .route("/api/projects/{id}", axum::routing::patch(update_project).delete(delete_project))
        .route("/api/projects/{id}/git-probe", post(probe_project_git))
        .route("/api/tasks", get(list_tasks).post(create_task))
        .route("/api/tasks/{id}", axum::routing::delete(delete_task))
        .route("/api/tasks/{id}/review", get(review_evidence))
        .route("/api/task-board", get(task_board))
        .route("/api/workers", get(list_workers))
        .route("/api/worker-capabilities", get(worker_capability_catalog))
        .route("/api/workers/{id}", axum::routing::patch(update_worker).delete(delete_worker))
        .route("/api/worker-join", post(create_worker_join_code))
        .route("/api/workers/register", post(register_worker))
        .route("/api/workers/{id}/config", get(worker_runtime_config))
        .route("/api/workers/{id}/provider-key", post(queue_worker_provider_key))
        .route("/api/workers/{id}/agent-auth", get(worker_agent_auth))
        .route("/api/workers/{id}/capabilities", post(update_worker_capabilities))
        .route("/api/workers/{id}/capability-build", post(report_capability_build))
        .route("/api/workers/{id}/heartbeat", post(worker_heartbeat))
        .route("/api/workers/{id}/cleanup", get(worker_cleanup))
        .route("/api/workers/{id}/cleanup/{task_id}", post(worker_cleanup_ack))
        .route("/api/workers/{id}/claim", post(claim_task))
        .route("/api/workers/{id}/review-claim", post(claim_review))
        .route("/api/executions/{id}/renew", post(renew_execution))
        .route("/api/executions/{id}/finish", post(finish_execution))
        .route("/api/reviews/{id}/renew", post(renew_review))
        .route("/api/reviews/{id}/finish", post(finish_review))
}

async fn health() -> &'static str { "ok" }

async fn worker_capability_catalog() -> Json<Vec<ManagedCapabilityOption>> {
    Json(MANAGED_CAPABILITY_IDS.iter().filter_map(|id| {
        managed_capability_tag(id).map(|tag| ManagedCapabilityOption {
            id,
            label: managed_capability_label(id),
            tag,
        })
    }).collect())
}

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
    let contributor = normalize_contributor(input.contributor)?;
    let stored_git_auth = resolve_new_git_auth(&state, input.git_auth)?;
    let now = Utc::now();
    let project = Project {
        id: Uuid::new_v4(), slug: input.slug, name: input.name.trim().into(), repo_url: input.repo_url.trim().into(),
        default_branch: input.default_branch.trim().into(), contributor, required_worker_tags: input.required_worker_tags,
        default_task_tags: input.default_task_tags, reviewer: input.reviewer,
        git_auth: git_auth_summary(&stored_git_auth), enabled: true, created_at: now, updated_at: now,
    };
    sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,contributor_name,contributor_email,required_worker_tags,default_task_tags,reviewer_mode,reviewer_prompt,git_auth_mode,git_auth_username,git_auth_secret,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(project.id.to_string()).bind(&project.slug).bind(&project.name).bind(&project.repo_url)
        .bind(&project.default_branch).bind(&project.contributor.name).bind(&project.contributor.email)
        .bind(json(&project.required_worker_tags)?).bind(json(&project.default_task_tags)?)
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

async fn probe_project_git(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>) -> ApiResult<GitProbeResult> {
    let row = sqlx::query("SELECT * FROM projects WHERE id=?")
        .bind(id.to_string())
        .fetch_optional(&state.db)
        .await
        .map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "project not found".into()))?;
    let project = project_from_row(&row)?;
    let credential = git_credential_from_row(&state, &row)?;
    let checked_at = Utc::now();
    let result = crate::git_broker::probe_project(&state, &project, &credential).await;
    let (ok, message) = match result {
        Ok(()) => (true, format!("Host can read refs/heads/{}", project.default_branch)),
        Err(error) => {
            let mut message = error.replace(['\r', '\n'], " ");
            if message.chars().count() > 600 {
                message = message.chars().take(600).collect::<String>() + "…";
            }
            (false, message)
        }
    };
    Ok(Json(GitProbeResult { ok, message, checked_at }))
}

async fn update_project(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, Json(input): Json<UpdateProject>) -> ApiResult<Project> {
    let row = sqlx::query("SELECT * FROM projects WHERE id=?")
        .bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "project not found".into()))?;
    let current = project_from_row(&row)?;
    let enabled = input.enabled.unwrap_or(current.enabled);
    let disabling = current.enabled && !enabled;
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
    let contributor = normalize_contributor(input.contributor.unwrap_or(current.contributor))?;
    let reviewer = input.reviewer.unwrap_or(current.reviewer);
    if reviewer.initial_prompt.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "reviewer initial prompt must not be empty".into()));
    }
    let stored_git_auth = resolve_updated_git_auth(&state, &row, input.git_auth)?;
    let now = ts(Utc::now());
    let mut tx = state.db.begin().await.map_err(db_error)?;
    sqlx::query("UPDATE projects SET slug=?,name=?,repo_url=?,default_branch=?,contributor_name=?,contributor_email=?,required_worker_tags=?,default_task_tags=?,reviewer_mode=?,reviewer_prompt=?,git_auth_mode=?,git_auth_username=?,git_auth_secret=?,enabled=?,updated_at=? WHERE id=?")
        .bind(&slug).bind(name.trim()).bind(repo_url.trim()).bind(default_branch.trim())
        .bind(&contributor.name).bind(&contributor.email)
        .bind(json(&input.required_worker_tags.unwrap_or(current.required_worker_tags))?)
        .bind(json(&input.default_task_tags.unwrap_or(current.default_task_tags))?)
        .bind(reviewer_mode_str(&reviewer.mode)).bind(reviewer.initial_prompt.trim())
        .bind(git_auth_mode_str(&stored_git_auth.mode)).bind(&stored_git_auth.username).bind(&stored_git_auth.encrypted_secret)
        .bind(if enabled { 1_i64 } else { 0_i64 })
        .bind(&now).bind(id.to_string()).execute(&mut *tx).await.map_err(db_conflict)?;
    if disabling {
        sqlx::query("UPDATE executions SET lease_capability_hash=NULL,lease_until=? WHERE state IN ('assigned','running') AND task_id IN (SELECT id FROM tasks WHERE project_id=?)")
            .bind(&now).bind(id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
        sqlx::query("UPDATE reviews SET lease_capability_hash=NULL,lease_until=? WHERE state IN ('assigned','running') AND task_id IN (SELECT id FROM tasks WHERE project_id=?)")
            .bind(&now).bind(id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
    }
    let row = sqlx::query("SELECT * FROM projects WHERE id=?").bind(id.to_string()).fetch_one(&mut *tx).await.map_err(db_error)?;
    let project = project_from_row(&row)?;
    tx.commit().await.map_err(db_error)?;
    Ok(Json(project))
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
    let rows = sqlx::query("SELECT * FROM tasks WHERE state!='cancelled' ORDER BY priority DESC, created_at ASC").fetch_all(&state.db).await.map_err(db_error)?;
    rows.iter().map(task_from_row).collect::<Result<Vec<_>,_>>().map(Json)
}

pub(crate) async fn delete_task(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>) -> Result<StatusCode, ApiError> {
    let task_id = id.to_string();
    let current: Option<String> = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
        .bind(&task_id).fetch_optional(&state.db).await.map_err(db_error)?;
    let Some(current) = current else { return Err((StatusCode::NOT_FOUND, "task not found".into())); };
    if matches!(current.as_str(), "assigned" | "running" | "merge_pending" | "done") {
        return Err((StatusCode::CONFLICT, "active, merge-pending, or completed tasks cannot be deleted".into()));
    }

    let rows = sqlx::query("SELECT id,dependencies FROM tasks WHERE id!=? AND state!='cancelled'")
        .bind(&task_id).fetch_all(&state.db).await.map_err(db_error)?;
    for row in rows {
        let other_id: String = row.try_get("id").map_err(internal)?;
        let dependencies_raw: String = row.try_get("dependencies").map_err(internal)?;
        let dependencies: Vec<Uuid> = serde_json::from_str(&dependencies_raw).map_err(internal)?;
        if dependencies.contains(&id) {
            return Err((StatusCode::CONFLICT, format!("task is still required by dependent task {other_id}")));
        }
    }

    let worker_id: Option<String> = sqlx::query_scalar("SELECT worker_id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(&task_id).fetch_optional(&state.db).await.map_err(db_error)?;
    let now = ts(Utc::now());
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let changed = sqlx::query("UPDATE tasks SET state='cancelled',sticky_worker_id=NULL,updated_at=? WHERE id=? AND state NOT IN ('assigned','running','merge_pending','done')")
        .bind(&now).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
    if changed == 0 {
        tx.rollback().await.map_err(db_error)?;
        return Err((StatusCode::CONFLICT, "task changed while deleting".into()));
    }
    if current == "review" {
        sqlx::query("UPDATE reviews SET lease_capability_hash=NULL,lease_until=? WHERE task_id=? AND state IN ('assigned','running')")
            .bind(&now).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?;
    }
    if let Some(worker_id) = worker_id {
        sqlx::query("INSERT INTO task_cleanup(task_id,worker_id,created_at) VALUES(?,?,?) ON CONFLICT(task_id) DO UPDATE SET worker_id=excluded.worker_id,created_at=excluded.created_at")
            .bind(&task_id).bind(worker_id).bind(&now).execute(&mut *tx).await.map_err(db_error)?;
    }
    tx.commit().await.map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
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
        repo_url: crate::git_broker::task_repo_url(&state, execution.id)?,
        default_branch: project.default_branch.clone(),
        review_ref: result.and_then(|value| value.review_ref.clone()),
        commit_sha: result.and_then(|value| value.commit_sha.clone()),
        base_sha: result.and_then(|value| value.base_sha.clone()),
        pullable: false,
    };
    Ok(Json(ReviewEvidence { project, task, execution, worker, checkout }))
}

async fn task_board(State(state): State<Arc<AppState>>) -> ApiResult<Vec<TaskBoardItem>> {
    let rows = sqlx::query("SELECT t.*, e.worker_id AS board_worker_id, w.name AS board_worker_name, e.result AS board_result, r.reviewer_worker_id AS board_reviewer_id, rw.name AS board_reviewer_name, r.state AS board_review_state FROM tasks t LEFT JOIN executions e ON e.id=(SELECT e2.id FROM executions e2 WHERE e2.task_id=t.id ORDER BY e2.attempt DESC LIMIT 1) LEFT JOIN workers w ON w.id=e.worker_id LEFT JOIN reviews r ON r.id=(SELECT r2.id FROM reviews r2 WHERE r2.task_id=t.id ORDER BY r2.created_at DESC LIMIT 1) LEFT JOIN workers rw ON rw.id=r.reviewer_worker_id WHERE t.state!='cancelled' ORDER BY t.priority DESC, t.created_at ASC")
        .fetch_all(&state.db).await.map_err(db_error)?;
    rows.iter().map(|row| {
        let task = task_from_row(row)?;
        let worker_id: Option<String> = row.try_get("board_worker_id").map_err(internal)?;
        let worker_name: Option<String> = row.try_get("board_worker_name").map_err(internal)?;
        let show_worker = matches!(task.state, TaskState::Assigned | TaskState::Running | TaskState::Review | TaskState::MergePending | TaskState::Done);
        let worker = if show_worker {
            match (worker_id, worker_name) {
                (Some(id), Some(name)) => Some(WorkerRef { id: uuid(id)?, name }),
                _ => None,
            }
        } else {
            None
        };
        let reviewer_id: Option<String> = row.try_get("board_reviewer_id").map_err(internal)?;
        let reviewer_name: Option<String> = row.try_get("board_reviewer_name").map_err(internal)?;
        let review_state: Option<String> = row.try_get("board_review_state").map_err(internal)?;
        let show_reviewer = match task.state {
            TaskState::Review => matches!(review_state.as_deref(), Some("assigned") | Some("running")),
            TaskState::MergePending => matches!(review_state.as_deref(), Some("completed")),
            _ => false,
        };
        let reviewer = if show_reviewer {
            match (reviewer_id, reviewer_name) {
                (Some(id), Some(name)) => Some(WorkerRef { id: uuid(id)?, name }),
                _ => None,
            }
        } else {
            None
        };
        let result: Option<String> = row.try_get("board_result").map_err(internal)?;
        let result = result.map(dejson).transpose()?;
        Ok(TaskBoardItem { task, worker, reviewer, result })
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
    let tags = input.tags;
    validate_user_tags(&tags)?;
    if input.agent_type != "pi" {
        return Err((StatusCode::BAD_REQUEST, "unsupported agent type".into()));
    }
    let agent_capabilities = json(&input.agent_capabilities)?;
    let role = agent_role_str(&input.role);
    let default_prompt = match input.role { AgentRole::Worker => DEFAULT_WORKER_PROMPT, AgentRole::Reviewer => DEFAULT_REVIEWER_PROMPT };
    sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,tags,allowed_projects,slots,running_slots,protocol_version,worker_version,last_heartbeat_at,created_at,credential_hash,agent_type,agent_provider,agent_model,initial_prompt,agent_capabilities) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,state=CASE WHEN workers.state IN ('pending','draining','degraded') THEN workers.state WHEN workers.running_slots>0 THEN 'busy' ELSE 'idle' END,os=excluded.os,arch=excluded.arch,protocol_version=excluded.protocol_version,worker_version=excluded.worker_version,last_heartbeat_at=excluded.last_heartbeat_at,credential_hash=excluded.credential_hash,agent_capabilities=excluded.agent_capabilities")
        .bind(id.to_string()).bind(&input.name).bind(role).bind("idle").bind(&input.os).bind(&input.arch).bind(json(&tags)?)
        .bind(json(&input.allowed_projects)?).bind(input.slots.max(1) as i64).bind(0_i64).bind(input.protocol_version as i64)
        .bind(&input.worker_version).bind(ts(now)).bind(ts(now)).bind(credential_hash).bind(&input.agent_type)
        .bind(Option::<String>::None).bind(Option::<String>::None).bind(default_prompt).bind(agent_capabilities)
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

pub(crate) async fn delete_worker(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>) -> Result<StatusCode, ApiError> {
    let worker_id = id.to_string();
    let row = sqlx::query("SELECT running_slots FROM workers WHERE id=?")
        .bind(&worker_id).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let running_slots: i64 = row.try_get("running_slots").map_err(internal)?;
    if running_slots != 0 {
        return Err((StatusCode::CONFLICT, "worker has active slots and cannot be deleted".into()));
    }
    let execution_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM executions WHERE worker_id=?")
        .bind(&worker_id).fetch_one(&state.db).await.map_err(db_error)?;
    let review_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE reviewer_worker_id=?")
        .bind(&worker_id).fetch_one(&state.db).await.map_err(db_error)?;
    if execution_count != 0 || review_count != 0 {
        return Err((StatusCode::CONFLICT, "worker has task/review history and cannot be deleted without erasing audit history".into()));
    }
    let changed = sqlx::query("DELETE FROM workers WHERE id=? AND running_slots=0")
        .bind(&worker_id).execute(&state.db).await.map_err(db_error)?.rows_affected();
    if changed == 0 {
        return Err((StatusCode::CONFLICT, "worker changed while deleting".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn update_worker(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, Json(input): Json<UpdateWorker>) -> ApiResult<Worker> {
    let row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let current = worker_from_row(&row)?;
    let authority_changed = input.role.as_ref().is_some_and(|value| value != &current.role)
        || input.allowed_projects.as_ref().is_some_and(|value| value != &current.allowed_projects);
    let role = input.role.unwrap_or_else(|| current.role.clone());
    if role == AgentRole::Reviewer && current.protocol_version < PROTOCOL_VERSION {
        return Err((StatusCode::CONFLICT, format!("update/restart this worker with protocol {PROTOCOL_VERSION} before assigning the reviewer role")));
    }
    let agent_type = input.agent_type.unwrap_or_else(|| current.agent.agent_type.clone());
    if agent_type != "pi" { return Err((StatusCode::BAD_REQUEST, "unsupported agent type".into())); }
    let (provider, model) = if input.clear_model.unwrap_or(false) {
        (None, None)
    } else {
        (input.provider.or_else(|| current.agent.provider.clone()), input.model.or_else(|| current.agent.model.clone()))
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
    let initial_prompt = input.initial_prompt.unwrap_or_else(|| current.agent.initial_prompt.clone());
    if initial_prompt.trim().is_empty() { return Err((StatusCode::BAD_REQUEST, "initial prompt must not be empty".into())); }
    let name = input.name.unwrap_or_else(|| current.name.clone());
    if name.trim().is_empty() { return Err((StatusCode::BAD_REQUEST, "worker name must not be empty".into())); }
    let tags = input.tags.unwrap_or_else(|| current.user_tags.clone());
    validate_user_tags(&tags)?;
    let managed_capabilities = input.managed_capabilities.unwrap_or_else(|| current.managed_capabilities.clone());
    validate_managed_capabilities(&managed_capabilities)?;
    if managed_capabilities != current.managed_capabilities && current.protocol_version < 5 {
        return Err((StatusCode::CONFLICT, "update/restart this worker with protocol 5 before changing managed tools".into()));
    }
    let allowed_projects = input.allowed_projects.unwrap_or_else(|| current.allowed_projects.clone());
    let slots = input.slots.unwrap_or(current.slots).max(1);
    let needs_build = !managed_capabilities.is_subset(&current.installed_capabilities);
    let recovering_capability_state = matches!(current.state, WorkerState::Pending)
        || (matches!(current.state, WorkerState::Degraded) && current.capability_error.is_some());
    let next_state = if needs_build {
        "pending"
    } else if recovering_capability_state {
        if current.running_slots > 0 { "busy" } else { "idle" }
    } else {
        worker_state_str(&current.state)
    };
    let capability_error = if needs_build || recovering_capability_state { None } else { current.capability_error.as_deref() };
    let capability_phase = if needs_build { Some("queued") } else { current.capability_phase.as_deref() };
    let capability_log = if needs_build { "" } else { current.capability_log.as_str() };
    let now = ts(Utc::now());
    let mut tx = state.db.begin().await.map_err(db_error)?;
    sqlx::query("UPDATE workers SET name=?,role=?,tags=?,managed_capabilities=?,capability_error=?,capability_phase=?,capability_log=?,state=?,allowed_projects=?,slots=?,agent_type=?,agent_provider=?,agent_model=?,initial_prompt=? WHERE id=?")
        .bind(name.trim()).bind(agent_role_str(&role)).bind(json(&tags)?).bind(json(&managed_capabilities)?)
        .bind(capability_error).bind(capability_phase).bind(capability_log).bind(next_state).bind(json(&allowed_projects)?).bind(slots as i64)
        .bind(&agent_type).bind(&provider).bind(&model).bind(initial_prompt.trim()).bind(id.to_string())
        .execute(&mut *tx).await.map_err(db_error)?;
    if authority_changed {
        sqlx::query("UPDATE executions SET lease_capability_hash=NULL,lease_until=? WHERE worker_id=? AND state IN ('assigned','running')")
            .bind(&now).bind(id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
        sqlx::query("UPDATE reviews SET lease_capability_hash=NULL,lease_until=? WHERE reviewer_worker_id=? AND state IN ('assigned','running')")
            .bind(&now).bind(id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
    }
    let row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_one(&mut *tx).await.map_err(db_error)?;
    let worker = worker_from_row(&row)?;
    tx.commit().await.map_err(db_error)?;
    Ok(Json(worker))
}

async fn worker_runtime_config(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<WorkerRuntimeConfig> {
    require_worker(&state.db, id, &headers).await?;
    let row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    let worker = worker_from_row(&row)?;
    Ok(Json(WorkerRuntimeConfig {
        role: worker.role,
        agent: worker.agent,
        slots: worker.slots.max(1),
        managed_capabilities: worker.managed_capabilities,
        installed_capabilities: worker.installed_capabilities,
    }))
}

async fn queue_worker_provider_key(
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
    Json(input): Json<AgentApiKeyInput>,
) -> ApiResult<AgentAuthQueued> {
    let provider = input.provider.trim();
    if provider.is_empty() || input.api_key.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "provider and API key are required".into()));
    }
    let row = sqlx::query("SELECT * FROM workers WHERE id=?")
        .bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let worker = worker_from_row(&row)?;
    if worker.protocol_version < 4 {
        return Err((StatusCode::CONFLICT, "update/restart this worker with protocol 4 before configuring provider credentials".into()));
    }
    let candidate = worker.agent_capabilities.providers.iter()
        .find(|candidate| candidate.id == provider)
        .ok_or((StatusCode::BAD_REQUEST, "provider is not reported by this worker's Pi runtime".into()))?;
    if candidate.api_key_label.is_none() {
        return Err((StatusCode::BAD_REQUEST, "this provider does not expose API-key authentication in Pi".into()));
    }
    let update = PendingAgentAuth {
        id: Uuid::new_v4(),
        provider: provider.to_string(),
        api_key: input.api_key,
    };
    let response = AgentAuthQueued { id: update.id, provider: update.provider.clone(), queued: true };
    state.agent_auth_updates.lock().await.insert(id, update);
    Ok(Json(response))
}

async fn worker_agent_auth(
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let update = state.agent_auth_updates.lock().await.remove(&id);
    match update {
        Some(update) => Ok(Json(AgentAuthDelivery {
            id: update.id,
            provider: update.provider,
            api_key: update.api_key,
        }).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

async fn update_worker_capabilities(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap, Json(capabilities): Json<AgentCapabilities>) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let protocol_version = headers
        .get("x-lazyteam-worker-protocol-version")
        .and_then(|value| value.to_str().ok())
        .map(str::parse::<u32>)
        .transpose()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid worker protocol version header".into()))?;
    if protocol_version.is_some_and(|version| !(MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&version)) {
        return Err((StatusCode::BAD_REQUEST, "unsupported worker protocol version".into()));
    }
    let worker_version = headers
        .get("x-lazyteam-worker-version")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.trim().is_empty());
    let changed = sqlx::query("UPDATE workers SET agent_capabilities=?, protocol_version=COALESCE(?,protocol_version), worker_version=COALESCE(?,worker_version) WHERE id=?")
        .bind(json(&capabilities)?)
        .bind(protocol_version.map(i64::from))
        .bind(worker_version)
        .bind(id.to_string())
        .execute(&state.db).await.map_err(db_error)?.rows_affected();
    if changed == 0 { return Err((StatusCode::NOT_FOUND, "worker not found".into())); }
    Ok(StatusCode::NO_CONTENT)
}

async fn report_capability_build(
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(report): Json<CapabilityBuildReport>,
) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    validate_managed_capabilities(&report.installed_capabilities)?;
    let row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let worker = worker_from_row(&row)?;
    if worker.protocol_version < 5 {
        return Err((StatusCode::CONFLICT, "worker protocol 5 is required for managed tool builds".into()));
    }
    let log_tail = bounded_capability_log(report.log_tail.as_deref());
    if let Some(error) = report.error.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
        let phase = report.phase.as_deref().map(str::trim).filter(|value| !value.is_empty()).unwrap_or("failed");
        sqlx::query("UPDATE workers SET state='degraded',capability_error=?,capability_phase=?,capability_log=? WHERE id=?")
            .bind(error).bind(phase).bind(log_tail).bind(id.to_string()).execute(&state.db).await.map_err(db_error)?;
        return Ok(StatusCode::NO_CONTENT);
    }
    if !worker.installed_capabilities.is_subset(&report.installed_capabilities) {
        return Err((StatusCode::CONFLICT, "managed tool builds are monotonic; installed capabilities cannot be removed".into()));
    }
    let ready = worker.managed_capabilities.is_subset(&report.installed_capabilities);
    let next_state = if ready {
        if worker.running_slots > 0 { "busy" } else { "idle" }
    } else {
        "pending"
    };
    let phase = report.phase.as_deref().map(str::trim).filter(|value| !value.is_empty())
        .unwrap_or(if ready { "ready" } else { "building" });
    sqlx::query("UPDATE workers SET installed_capabilities=?,capability_error=NULL,capability_phase=?,capability_log=?,state=? WHERE id=?")
        .bind(json(&report.installed_capabilities)?).bind(phase).bind(log_tail).bind(next_state).bind(id.to_string())
        .execute(&state.db).await.map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn worker_heartbeat(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let changed = sqlx::query("UPDATE workers SET last_heartbeat_at=?, state=CASE WHEN state IN ('pending','draining','degraded') THEN state WHEN running_slots>0 THEN 'busy' ELSE 'idle' END WHERE id=?")
        .bind(ts(Utc::now())).bind(id.to_string()).execute(&state.db).await.map_err(db_error)?.rows_affected();
    if changed == 0 { return Err((StatusCode::NOT_FOUND, "worker not found".into())); }
    Ok(StatusCode::NO_CONTENT)
}

async fn worker_cleanup(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Vec<WorkerCleanup>> {
    require_worker(&state.db, id, &headers).await?;
    let rows = sqlx::query("SELECT c.task_id,p.slug FROM task_cleanup c JOIN tasks t ON t.id=c.task_id JOIN projects p ON p.id=t.project_id WHERE c.worker_id=? ORDER BY c.created_at ASC")
        .bind(id.to_string()).fetch_all(&state.db).await.map_err(db_error)?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(WorkerCleanup {
            task_id: uuid(row.try_get("task_id").map_err(internal)?)?,
            project_slug: row.try_get("slug").map_err(internal)?,
        });
    }
    Ok(Json(items))
}

async fn worker_cleanup_ack(Path((id, task_id)): Path<(Uuid, Uuid)>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let execution_id: Option<String> = sqlx::query_scalar("SELECT id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(task_id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?;
    if let Some(execution_id) = execution_id {
        crate::git_broker::remove_task_repo(&state, uuid(execution_id)?).await?;
    }
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
    if worker.role != AgentRole::Worker || worker.protocol_version < PROTOCOL_VERSION {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    if worker.running_slots >= worker.slots || !matches!(worker.state, WorkerState::Idle | WorkerState::Busy) {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    let rows = sqlx::query("SELECT * FROM tasks WHERE state='queued' ORDER BY priority DESC, created_at ASC LIMIT 100")
        .fetch_all(&state.db).await.map_err(db_error)?;
    let worker_id_text = worker.id.to_string();
    for row in rows {
        let sticky_worker_id: Option<String> = row.try_get("sticky_worker_id").map_err(internal)?;
        let task = task_from_row(&row)?;
        if !dependencies_satisfied(&state.db, &task).await? { continue; }
        let project_row = sqlx::query("SELECT * FROM projects WHERE id=? AND enabled=1").bind(task.project_id.to_string())
            .fetch_optional(&state.db).await.map_err(db_error)?;
        let Some(project_row) = project_row else { continue };
        let project = project_from_row(&project_row)?;
        if let Some(sticky_worker_id) = sticky_worker_id.as_deref().filter(|sticky| *sticky != worker_id_text) {
            if sticky_worker_reservation_active(&state.db, sticky_worker_id, &project, &task).await? {
                continue;
            }
            sqlx::query("UPDATE tasks SET sticky_worker_id=NULL,updated_at=? WHERE id=? AND state='queued' AND sticky_worker_id=?")
                .bind(ts(Utc::now())).bind(task.id.to_string()).bind(sticky_worker_id)
                .execute(&state.db).await.map_err(db_error)?;
        }
        if !worker_matches_task(&worker, &project, &task) { continue; }
        let git_credential = git_credential_from_row(&state, &project_row)?;

        let now = Utc::now();
        let lease_until = now + chrono::Duration::seconds(DEFAULT_LEASE_SECONDS);
        let attempt: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(attempt),0)+1 FROM executions WHERE task_id=?")
            .bind(task.id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
        let execution = Execution { id: Uuid::new_v4(), task_id: task.id, worker_id: worker.id, attempt: attempt as u32,
            state: ExecutionState::Assigned, lease_until, started_at: None, finished_at: None, result: None };
        let (lease_capability, lease_capability_hash) = issue_lease_capability();
        crate::git_broker::prepare_task_repo(&state, &project, task.id, execution.id, &git_credential).await?;
        let mut worker_project = project.clone();
        worker_project.repo_url = crate::git_broker::task_repo_url(&state, execution.id)?;
        worker_project.git_auth = GitAuthConfig::default();

        let mut tx = state.db.begin().await.map_err(db_error)?;
        let claimed = sqlx::query("UPDATE tasks SET state='assigned',updated_at=? WHERE id=? AND state='queued'")
            .bind(ts(now)).bind(task.id.to_string()).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
        if claimed == 0 {
            tx.rollback().await.map_err(db_error)?;
            crate::git_broker::remove_task_repo(&state, execution.id).await?;
            continue;
        }
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,lease_capability_hash) VALUES(?,?,?,?,?,?,?,?)")
            .bind(execution.id.to_string()).bind(task.id.to_string()).bind(worker.id.to_string()).bind(attempt)
            .bind("assigned").bind(ts(lease_until)).bind(ts(now)).bind(lease_capability_hash).execute(&mut *tx).await.map_err(db_error)?;
        sqlx::query("UPDATE workers SET running_slots=running_slots+1,state='busy' WHERE id=?")
            .bind(worker.id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;
        let mut assigned_task = task; assigned_task.state = TaskState::Assigned; assigned_task.updated_at = now;
        return Ok(Json(Assignment { project: worker_project, task: assigned_task, execution, lease_capability }).into_response());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn claim_review(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let worker_row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let worker = worker_from_row(&worker_row)?;
    if worker.role != AgentRole::Reviewer || worker.protocol_version < PROTOCOL_VERSION {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    if worker.running_slots >= worker.slots || !matches!(worker.state, WorkerState::Idle | WorkerState::Busy) {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }

    let rows = sqlx::query("SELECT * FROM tasks WHERE state='review' ORDER BY priority DESC, updated_at ASC LIMIT 100")
        .fetch_all(&state.db).await.map_err(db_error)?;
    for row in rows {
        let task = task_from_row(&row)?;
        let project_row = sqlx::query("SELECT * FROM projects WHERE id=? AND enabled=1")
            .bind(task.project_id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?;
        let Some(project_row) = project_row else { continue };
        let project = project_from_row(&project_row)?;
        if !worker_can_run_project(&worker, &project) { continue; }
        if review_reserved_for_live_preferred_reviewer(&state.db, &task, &project, worker.id).await? { continue; }

        let execution_row = sqlx::query("SELECT * FROM executions WHERE task_id=? AND state='completed' ORDER BY attempt DESC LIMIT 1")
            .bind(task.id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?;
        let Some(execution_row) = execution_row else { continue };
        let execution = execution_from_row(&execution_row)?;
        if execution.worker_id == worker.id { continue; }
        let Some(result) = execution.result.as_ref() else { continue };
        let (Some(review_ref), Some(commit_sha)) = (result.review_ref.clone(), result.commit_sha.clone()) else { continue };

        let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state IN ('assigned','running')")
            .bind(task.id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
        if active > 0 { continue; }

        let implementation_row = sqlx::query("SELECT * FROM workers WHERE id=?")
            .bind(execution.worker_id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
        let implementation_worker = worker_from_row(&implementation_row)?;
        let now = Utc::now();
        let lease_until = now + chrono::Duration::seconds(DEFAULT_LEASE_SECONDS);
        let review = ReviewLease {
            id: Uuid::new_v4(),
            task_id: task.id,
            execution_id: execution.id,
            reviewer_worker_id: worker.id,
            lease_until,
        };
        let (lease_capability, lease_capability_hash) = issue_lease_capability();

        let mut tx = state.db.begin().await.map_err(db_error)?;
        let still_review: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tasks WHERE id=? AND state='review'")
            .bind(task.id.to_string()).fetch_one(&mut *tx).await.map_err(db_error)?;
        let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state IN ('assigned','running')")
            .bind(task.id.to_string()).fetch_one(&mut *tx).await.map_err(db_error)?;
        if still_review == 0 || active > 0 {
            tx.rollback().await.map_err(db_error)?;
            continue;
        }
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,lease_capability_hash) VALUES(?,?,?,?,?,?,?,?)")
            .bind(review.id.to_string()).bind(task.id.to_string()).bind(execution.id.to_string()).bind(worker.id.to_string())
            .bind("assigned").bind(ts(lease_until)).bind(ts(now)).bind(lease_capability_hash).execute(&mut *tx).await.map_err(db_conflict)?;
        sqlx::query("UPDATE workers SET running_slots=running_slots+1,state='busy' WHERE id=?")
            .bind(worker.id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
        tx.commit().await.map_err(db_error)?;

        let review_repo_url = crate::git_broker::review_repo_url(&state, review.id)?;
        let mut worker_project = project.clone();
        worker_project.repo_url = review_repo_url.clone();
        worker_project.git_auth = GitAuthConfig::default();
        let checkout = WorkerReviewCheckout {
            repo_url: review_repo_url,
            default_branch: project.default_branch.clone(),
            review_ref,
            commit_sha,
            base_sha: result.base_sha.clone(),
        };
        return Ok(Json(ReviewAssignment {
            review,
            project: worker_project,
            task,
            execution,
            implementation_worker,
            checkout,
            lease_capability,
        }).into_response());
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

async fn renew_review(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    let now = Utc::now();
    let lease = now + chrono::Duration::seconds(DEFAULT_LEASE_SECONDS);
    let row = sqlx::query("SELECT reviewer_worker_id,lease_capability_hash FROM reviews WHERE id=? AND state IN ('assigned','running') AND lease_until>=? AND lease_capability_hash IS NOT NULL")
        .bind(id.to_string()).bind(ts(now)).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "review is not active".into()))?;
    let reviewer_worker_id = uuid(row.try_get("reviewer_worker_id").map_err(internal)?)?;
    let capability_hash: String = row.try_get("lease_capability_hash").map_err(internal)?;
    require_worker(&state.db, reviewer_worker_id, &headers).await?;
    require_lease_capability(&headers, &capability_hash)?;
    sqlx::query("UPDATE reviews SET state='running',lease_until=?,started_at=COALESCE(started_at,?) WHERE id=? AND state IN ('assigned','running')")
        .bind(ts(lease)).bind(ts(now)).bind(id.to_string()).execute(&state.db).await.map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn finish_review(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap, Json(input): Json<FinishReview>) -> Result<StatusCode, ApiError> {
    let now = Utc::now();
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let row = sqlx::query("SELECT task_id,execution_id,reviewer_worker_id,lease_capability_hash FROM reviews WHERE id=? AND state IN ('assigned','running') AND lease_until>=? AND lease_capability_hash IS NOT NULL")
        .bind(id.to_string()).bind(ts(now)).fetch_optional(&mut *tx).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "review is not active".into()))?;
    let task_id: String = row.try_get("task_id").map_err(internal)?;
    let execution_id: String = row.try_get("execution_id").map_err(internal)?;
    let reviewer_worker_id: String = row.try_get("reviewer_worker_id").map_err(internal)?;
    let capability_hash: String = row.try_get("lease_capability_hash").map_err(internal)?;
    require_worker(&state.db, uuid(reviewer_worker_id.clone())?, &headers).await?;
    require_lease_capability(&headers, &capability_hash)?;

    let current_state: Option<String> = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
        .bind(&task_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
    if current_state.as_deref() != Some("review") {
        return Err((StatusCode::CONFLICT, "task is no longer awaiting review".into()));
    }
    let latest_execution: Option<String> = sqlx::query_scalar("SELECT id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(&task_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
    if latest_execution.as_deref() != Some(execution_id.as_str()) {
        return Err((StatusCode::CONFLICT, "review targets a stale execution".into()));
    }
    if input.status == "failed" {
        let error = input.error.unwrap_or_else(|| "reviewer failed without an error message".into());
        sqlx::query("UPDATE reviews SET state='failed',finished_at=?,verdict=?,lease_capability_hash=NULL WHERE id=?")
            .bind(ts(now)).bind(json(&serde_json::json!({"error": error}))?).bind(id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
    } else {
        let verdict = input.verdict.ok_or((StatusCode::BAD_REQUEST, "completed review requires a verdict".into()))?;
        let reason = verdict.reason.trim();
        if reason.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "review verdict requires a reason".into()));
        }
        sqlx::query("UPDATE reviews SET state='completed',finished_at=?,verdict=?,lease_capability_hash=NULL WHERE id=?")
            .bind(ts(now)).bind(json(&verdict)?).bind(id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
        match verdict.verdict {
            ReviewVerdictKind::Approve => {
                sqlx::query("UPDATE tasks SET state='merge_pending',updated_at=? WHERE id=? AND state='review'")
                    .bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?;
            }
            ReviewVerdictKind::Retry => {
                let implementation_worker_id: String = sqlx::query_scalar("SELECT worker_id FROM executions WHERE id=?")
                    .bind(&execution_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                sqlx::query("UPDATE tasks SET state='queued',review_feedback=?,sticky_worker_id=?,updated_at=? WHERE id=? AND state='review'")
                    .bind(reason).bind(implementation_worker_id).bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?;
            }
        }
    }
    sqlx::query("UPDATE workers SET running_slots=MAX(running_slots-1,0),state=CASE WHEN state IN ('pending','draining','degraded') THEN state WHEN running_slots<=1 THEN 'idle' ELSE 'busy' END WHERE id=?")
        .bind(&reviewer_worker_id).execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn renew_execution(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    let now = Utc::now();
    let lease = now + chrono::Duration::seconds(DEFAULT_LEASE_SECONDS);
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let row = sqlx::query("SELECT task_id,worker_id,lease_capability_hash FROM executions WHERE id=? AND state IN ('assigned','running') AND lease_until>=? AND lease_capability_hash IS NOT NULL")
        .bind(id.to_string()).bind(ts(now)).fetch_optional(&mut *tx).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "execution is not active".into()))?;
    let task_id: String = row.try_get("task_id").map_err(internal)?;
    let worker_id: String = row.try_get("worker_id").map_err(internal)?;
    let capability_hash: String = row.try_get("lease_capability_hash").map_err(internal)?;
    let worker_id = uuid(worker_id)?;
    require_worker(&state.db, worker_id, &headers).await?;
    require_lease_capability(&headers, &capability_hash)?;
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
    let row = sqlx::query("SELECT task_id,worker_id,lease_capability_hash FROM executions WHERE id=? AND state IN ('assigned','running') AND lease_until>=? AND lease_capability_hash IS NOT NULL")
        .bind(id.to_string()).bind(ts(now)).fetch_optional(&mut *tx).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "execution is not active".into()))?;
    let task_id: String = row.try_get("task_id").map_err(internal)?;
    let worker_id: String = row.try_get("worker_id").map_err(internal)?;
    let capability_hash: String = row.try_get("lease_capability_hash").map_err(internal)?;
    require_worker(&state.db, uuid(worker_id.clone())?, &headers).await?;
    require_lease_capability(&headers, &capability_hash)?;
    if !is_latest_execution(&mut tx, &task_id, id).await? { return Err((StatusCode::CONFLICT, "stale execution".into())); }
    let success = input.result.status == "completed";
    sqlx::query("UPDATE executions SET state=?,finished_at=?,result=?,lease_capability_hash=NULL WHERE id=?")
        .bind(if success { "completed" } else { "failed" }).bind(ts(now)).bind(json(&input.result)?).bind(id.to_string())
        .execute(&mut *tx).await.map_err(db_error)?;
    sqlx::query("UPDATE tasks SET state=?,sticky_worker_id=CASE WHEN ? THEN sticky_worker_id ELSE NULL END,updated_at=? WHERE id=?")
        .bind(if success { "review" } else { "failed" }).bind(success).bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?;
    sqlx::query("UPDATE workers SET running_slots=MAX(running_slots-1,0),state=CASE WHEN state IN ('pending','draining','degraded') THEN state WHEN running_slots<=1 THEN 'idle' ELSE 'busy' END WHERE id=?")
        .bind(&worker_id).execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn issue_lease_capability() -> (String, String) {
    let capability = format!("ltc_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let hash = hash_secret(&capability);
    (capability, hash)
}

pub(crate) fn require_lease_capability(headers: &HeaderMap, stored_hash: &str) -> Result<(), ApiError> {
    let supplied = headers
        .get(LEASE_CAPABILITY_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "lease capability required".into()))?;
    if !secure_hash_eq(&hash_secret(supplied), stored_hash) {
        return Err((StatusCode::UNAUTHORIZED, "lease capability rejected".into()));
    }
    Ok(())
}

pub(crate) async fn require_worker(db: &SqlitePool, worker_id: Uuid, headers: &HeaderMap) -> Result<(), ApiError> {
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

async fn sticky_worker_reservation_active(
    db: &SqlitePool,
    worker_id: &str,
    project: &Project,
    task: &Task,
) -> Result<bool, ApiError> {
    let row = sqlx::query("SELECT * FROM workers WHERE id=?")
        .bind(worker_id)
        .fetch_optional(db)
        .await
        .map_err(db_error)?;
    let Some(row) = row else { return Ok(false); };
    let preferred = worker_from_row(&row)?;
    let fresh_after = Utc::now() - chrono::Duration::seconds(45);
    Ok(preferred.role == AgentRole::Worker
        && preferred.protocol_version >= PROTOCOL_VERSION
        && preferred.running_slots < preferred.slots
        && matches!(preferred.state, WorkerState::Idle | WorkerState::Busy)
        && preferred.last_heartbeat_at >= fresh_after
        && worker_matches_task(&preferred, project, task))
}

async fn review_reserved_for_live_preferred_reviewer(
    db: &SqlitePool,
    task: &Task,
    project: &Project,
    claimant_id: Uuid,
) -> Result<bool, ApiError> {
    let preferred_id: Option<String> = sqlx::query_scalar(
        "SELECT reviewer_worker_id FROM reviews WHERE task_id=? AND state='completed' ORDER BY created_at DESC LIMIT 1",
    )
    .bind(task.id.to_string())
    .fetch_optional(db)
    .await
    .map_err(db_error)?;
    let Some(preferred_id) = preferred_id else { return Ok(false); };
    if preferred_id == claimant_id.to_string() { return Ok(false); }
    let row = sqlx::query("SELECT * FROM workers WHERE id=?")
        .bind(&preferred_id)
        .fetch_optional(db)
        .await
        .map_err(db_error)?;
    let Some(row) = row else { return Ok(false); };
    let preferred = worker_from_row(&row)?;
    let fresh_after = Utc::now() - chrono::Duration::seconds(45);
    let live = preferred.role == AgentRole::Reviewer
        && preferred.protocol_version >= PROTOCOL_VERSION
        && preferred.running_slots < preferred.slots
        && matches!(preferred.state, WorkerState::Idle | WorkerState::Busy)
        && preferred.last_heartbeat_at >= fresh_after
        && worker_can_run_project(&preferred, project);
    Ok(live)
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
        sqlx::query("UPDATE executions SET state='lost',finished_at=?,lease_capability_hash=NULL WHERE id=? AND state IN ('assigned','running')")
            .bind(&now).bind(&id).execute(&mut *tx).await?;
        if latest.as_deref() == Some(id.as_str()) {
            sqlx::query("UPDATE tasks SET state='queued',updated_at=? WHERE id=? AND state IN ('assigned','running')")
                .bind(&now).bind(&task_id).execute(&mut *tx).await?;
        }
        sqlx::query("UPDATE workers SET running_slots=MAX(running_slots-1,0),state=CASE WHEN state IN ('pending','draining','degraded') THEN state WHEN running_slots<=1 THEN 'idle' ELSE 'busy' END WHERE id=?")
            .bind(&worker_id).execute(&mut *tx).await?;
        tx.commit().await?;
    }

    let expired_reviews = sqlx::query("SELECT id,reviewer_worker_id FROM reviews WHERE state IN ('assigned','running') AND lease_until < ?")
        .bind(&now).fetch_all(db).await?;
    for row in expired_reviews {
        let id: String = row.try_get("id")?;
        let reviewer_worker_id: String = row.try_get("reviewer_worker_id")?;
        let mut tx = db.begin().await?;
        let changed = sqlx::query("UPDATE reviews SET state='lost',finished_at=?,lease_capability_hash=NULL WHERE id=? AND state IN ('assigned','running')")
            .bind(&now).bind(&id).execute(&mut *tx).await?.rows_affected();
        if changed > 0 {
            sqlx::query("UPDATE workers SET running_slots=MAX(running_slots-1,0),state=CASE WHEN state IN ('pending','draining','degraded') THEN state WHEN running_slots<=1 THEN 'idle' ELSE 'busy' END WHERE id=?")
                .bind(&reviewer_worker_id).execute(&mut *tx).await?;
        }
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
        "Host Git credential encryption key is unavailable".into(),
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

pub(crate) fn git_credential_from_row(state: &AppState, row: &sqlx::sqlite::SqliteRow) -> Result<GitCredential, ApiError> {
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
        contributor: ContributorIdentity {
            name: row.try_get("contributor_name").map_err(internal)?,
            email: row.try_get("contributor_email").map_err(internal)?,
        },
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
    let os: String = row.try_get("os").map_err(internal)?;
    let arch: String = row.try_get("arch").map_err(internal)?;
    let user_tags: Tags = dejson(row.try_get("tags").map_err(internal)?)?;
    let managed_capabilities: BTreeSet<String> = dejson(row.try_get("managed_capabilities").map_err(internal)?)?;
    let installed_capabilities: BTreeSet<String> = dejson(row.try_get("installed_capabilities").map_err(internal)?)?;
    let system_tags = Tags::from([("os".into(), os.clone()), ("arch".into(), arch.clone())]);
    let tags = effective_worker_tags(&os, &arch, &user_tags, &managed_capabilities, &installed_capabilities);
    Ok(Worker { id: uuid(row.try_get("id").map_err(internal)?)?, name: row.try_get("name").map_err(internal)?,
        role: agent_role(row.try_get("role").map_err(internal)?)?,
        state: match state.as_str() { "busy" => WorkerState::Busy, "pending" => WorkerState::Pending, "draining" => WorkerState::Draining, "degraded" => WorkerState::Degraded, "offline" => WorkerState::Offline, _ => WorkerState::Idle },
        os, arch, system_tags, user_tags, managed_capabilities, installed_capabilities,
        capability_error: row.try_get("capability_error").map_err(internal)?,
        capability_phase: row.try_get("capability_phase").map_err(internal)?,
        capability_log: row.try_get("capability_log").map_err(internal)?, tags,
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

fn agent_role_str(role: &AgentRole) -> &'static str {
    match role { AgentRole::Worker => "worker", AgentRole::Reviewer => "reviewer" }
}

fn agent_role(value: String) -> Result<AgentRole, ApiError> {
    match value.as_str() { "worker" => Ok(AgentRole::Worker), "reviewer" => Ok(AgentRole::Reviewer), _ => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("invalid agent role {value}"))) }
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
