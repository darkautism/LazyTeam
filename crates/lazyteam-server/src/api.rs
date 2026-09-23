use std::{collections::{BTreeSet, HashMap, HashSet, VecDeque}, path::PathBuf, sync::Arc, time::Duration};

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
    can_claim_work, host_agent_selection_ready, managed_capability_tag,
    tag_mismatches, worker_can_run_project, worker_matches_task, worker_tags_scope_match,
    AgentCapabilities, AgentConfig, AgentRole, Assignment, ContributorIdentity, Execution, ExecutionResult,
    ExecutionState, GitAuthConfig, GitAuthMode, GitCredential, Project, ReviewAssignment,
    ReviewCheckout as WorkerReviewCheckout, ReviewLease, ReviewVerdict, ReviewVerdictKind, Tags, Task,
    TaskState, Worker, WorkerState, DEFAULT_REVIEWER_PROMPT, DEFAULT_WORKER_PROMPT,
    LEGACY_DEFAULT_REVIEWER_PROMPT, LEGACY_FULL_SWEEP_REVIEWER_PROMPT, LEASE_CAPABILITY_HEADER, MANAGED_CAPABILITY_IDS,
    redact_oauth_secret_text,
};
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use tokio::{sync::Mutex, time::interval};
use tracing::warn;
use uuid::Uuid;

pub(crate) const PROTOCOL_VERSION: u32 = 6;
const DEFAULT_LEASE_SECONDS: i64 = 120;
const DEFAULT_SESSION_AFFINITY_SECONDS: i64 = 15 * 60;
const DEFAULT_REVIEW_FAILURE_LIMIT: i64 = 3;
const DEFAULT_REVIEW_RETRY_LIMIT: i64 = 3;
const MIN_REVIEW_LIMIT: i64 = 1;
const MAX_REVIEW_LIMIT: i64 = 50;
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
    pub(crate) agent_auth_updates: Arc<Mutex<HashMap<Uuid, VecDeque<PendingAgentAuth>>>>,
    pub(crate) model_refresh_requests: Arc<Mutex<HashMap<Uuid, VecDeque<PendingModelRefresh>>>>,
    pub(crate) oauth_login_states: Arc<Mutex<HashMap<Uuid, AgentOAuthLoginState>>>,
    pub(crate) interactive_sandboxes: crate::interactive_sandbox::InteractiveSandboxManager,
}

#[derive(Clone)]
pub(crate) struct PendingAgentAuth {
    id: Uuid,
    provider: String,
    api_key: String,
}

#[derive(Clone)]
pub(crate) struct PendingModelRefresh {
    id: Uuid,
    provider: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AgentOAuthLoginState {
    id: Uuid,
    provider: String,
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verification_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_code: Option<String>,
    /// Real browser authorization URL reported by the worker's Pi runtime
    /// (`auth_url` notify event). Surfaced as a copyable bar in the Host UI
    /// so the human browser can be on any machine; the worker never assumes
    /// Host, worker, and browser share localhost.
    #[serde(skip_serializing_if = "Option::is_none")]
    authorization_url: Option<String>,
    /// Paste-back prompt Pi shows when its localhost callback cannot be
    /// reached remotely (Pi's `manual_code` prompt: paste the final
    /// redirect URL or authorization code). Answered via the Host relay
    /// endpoint; the pasted value is consumed only by the worker.
    #[serde(skip_serializing_if = "Option::is_none")]
    paste_prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paste_placeholder: Option<String>,
    /// Single-use pasted redirect URL/code from the Host. In-memory only,
    /// never serialized to UI responses, logs, or Host durable storage.
    /// Delivery is acknowledged only after the worker writes it to Pi stdin.
    #[serde(skip_serializing)]
    pending_input: Option<PendingOAuthInput>,
}

#[derive(Debug, Clone)]
struct PendingOAuthInput {
    id: Uuid,
    input: String,
}

#[derive(Debug, Deserialize)]
struct AgentOAuthStartInput { provider: String }

#[derive(Debug, Serialize, Deserialize)]
struct AgentOAuthClaim { id: Uuid, provider: String }

#[derive(Debug, Deserialize)]
struct AgentOAuthEventInput {
    kind: String,
    #[serde(default)] message: Option<String>,
    #[serde(default)] verification_uri: Option<String>,
    #[serde(default)] user_code: Option<String>,
    #[serde(default)] authorization_url: Option<String>,
    #[serde(default)] paste_prompt: Option<String>,
    #[serde(default)] paste_placeholder: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AgentOAuthInputSubmit { input: String }

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentOAuthInputDelivery { id: Uuid, input: String }

#[derive(Debug, Clone, Serialize, JsonSchema)]
pub(crate) struct HostSettings {
    pub(crate) review_retry_limit: i64,
    pub(crate) review_failure_limit: i64,
    pub(crate) task_lease_seconds: i64,
    pub(crate) session_affinity_seconds: i64,
}

#[derive(Debug, Deserialize)]
struct UpdateHostSettings {
    review_retry_limit: Option<i64>,
    review_failure_limit: Option<i64>,
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
    credential_revision: Option<String>,
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
    git_auth: Option<ProjectGitAuthInput>,
    enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct WorkerRef {
    id: Uuid,
    name: String,
}

/// Lightweight scheduler diagnostic for a waiting task: the primary
/// machine-readable reason plus a concise human detail. Computed read-only
/// from the same predicates used by claim selection (dependencies,
/// tags/project scope, sticky affinity, role/protocol, Host-selected
/// backend availability, reviewer failure budget, slot/state), so it cannot
/// silently drift from claim behavior. Only populated for waiting states
/// (`queued` implementation tasks and `review` tasks); actively
/// running/reviewing cards never carry it. Never contains credentials, raw
/// auth state, or provider secrets: backend unavailability may name the
/// provider/model, never keys or tokens.
#[derive(Debug, Clone, Serialize, JsonSchema)]
pub(crate) struct WaitingInfo {
    pub(crate) reason: String,
    pub(crate) detail: String,
}

fn waiting(reason: &str, detail: String) -> WaitingInfo {
    let mut detail: String = detail.chars().take(280).collect();
    if detail.trim().is_empty() { detail = reason.to_string(); }
    WaitingInfo { reason: reason.into(), detail }
}

#[derive(Debug, Serialize)]
struct TaskBoardItem {
    task: Task,
    worker: Option<WorkerRef>,
    reviewer: Option<WorkerRef>,
    result: Option<ExecutionResult>,
    #[serde(default)]
    attempt: u32,
    /// Completed reviews only (`reviews.state='completed'`). Runtime
    /// `failed` rows and expired `lost` leases are reported separately via
    /// `review_runtime_failures`/`review_lost_leases` and never folded into
    /// this count, so "Reviews N" always means N completed rounds with a
    /// clear denominator.
    #[serde(default)]
    review_rounds: i64,
    /// Reviewer runtime/infrastructure failures (`reviews.state='failed'`)
    /// for this task. Never counted as completed reviews or quality retries.
    #[serde(default)]
    review_runtime_failures: i64,
    /// Expired review leases (`reviews.state='lost'`) for this task. Never
    /// counted as completed reviews or quality retries.
    #[serde(default)]
    review_lost_leases: i64,
    /// Current-cycle completed reviewer `retry` verdicts. This is the count
    /// the configured per-cycle limit applies to. Kept for backward
    /// compatibility; equals `current_cycle_reviewer_retries`.
    #[serde(default)]
    reviewer_retries: i64,
    /// Completed reviewer `retry` verdicts in the task's current review
    /// cycle only. Manual re-publish/retry starts a new cycle and resets
    /// this to zero; automatic reviewer redispatch stays in the same cycle.
    #[serde(default)]
    current_cycle_reviewer_retries: i64,
    /// Durable lifetime total of completed reviewer `retry` verdicts across
    /// all cycles. Historical review rows are never deleted; this only grows.
    #[serde(default)]
    lifetime_reviewer_retries: i64,
    /// Scheduler diagnostic for waiting tasks only (`queued`/`review`).
    /// `None` for actively running/reviewing or terminal states so cards
    /// that are making progress are never spammed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    waiting: Option<WaitingInfo>,
}

#[cfg(test)]
fn task_board_looping(attempt: u32, reviewer_retries: i64) -> bool {
    attempt >= 4 || reviewer_retries >= 3
}

#[cfg(test)]
fn is_reviewer_retry_verdict(verdict_json: Option<&str>) -> bool {
    let Some(raw) = verdict_json else { return false; };
    raw.contains("\"verdict\":\"retry\"") || raw.contains("\"verdict\": \"retry\"")
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct TaskStatus {
    pub(crate) task: Task,
    pub(crate) latest_execution: Option<Execution>,
    /// Completed reviewer `retry` verdicts in the task's current review cycle.
    #[serde(default)]
    pub(crate) current_cycle_reviewer_retries: i64,
    /// Durable lifetime total of completed reviewer `retry` verdicts.
    #[serde(default)]
    pub(crate) lifetime_reviewer_retries: i64,
    /// Completed reviews (`state='completed'`) with a clear denominator for
    /// approve/retry statistics. Failed/lost infrastructure attempts are
    /// reported separately and never folded in.
    #[serde(default)]
    pub(crate) completed_reviews: i64,
    /// Reviewer runtime failures (`state='failed'`). Infrastructure only.
    #[serde(default)]
    pub(crate) review_runtime_failures: i64,
    /// Expired review leases (`state='lost'`). Infrastructure only.
    #[serde(default)]
    pub(crate) review_lost_leases: i64,
    /// Per-candidate denominator for the task's latest implementation
    /// execution only: completed reviews for that execution. Mixed history
    /// across older candidates stays in the task-wide counters above; this
    /// is the unambiguous denominator for the current candidate.
    #[serde(default)]
    pub(crate) candidate_completed_reviews: i64,
    /// Completed `approve` verdicts for the latest execution.
    #[serde(default)]
    pub(crate) candidate_completed_approvals: i64,
    /// Completed `retry` verdicts for the latest execution. Never includes
    /// failed/lost infrastructure attempts.
    #[serde(default)]
    pub(crate) candidate_completed_retries: i64,
    /// Runtime `failed` attempts for the latest execution.
    #[serde(default)]
    pub(crate) candidate_runtime_failures: i64,
    /// Expired `lost` leases for the latest execution.
    #[serde(default)]
    pub(crate) candidate_lost_leases: i64,
    /// Scheduler diagnostic for waiting tasks only (`queued`/`review`).
    /// `None` for actively running/reviewing or terminal states.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) waiting: Option<WaitingInfo>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ReviewCheckout {
    pub(crate) repo_url: String,
    pub(crate) default_branch: String,
    pub(crate) review_ref: Option<String>,
    pub(crate) commit_sha: Option<String>,
    pub(crate) base_sha: Option<String>,
    /// Host integration snapshot the reviewer actually sees.
    pub(crate) upstream_sha: Option<String>,
    pub(crate) integration_sha: Option<String>,
    pub(crate) effective_diff_hash: Option<String>,
    pub(crate) pullable: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
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
    role: String,
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
    #[serde(default)]
    pub(crate) conflict_group: Option<String>,
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
    paused: Option<bool>,
}

#[derive(Debug, Serialize)]
struct WorkerRuntimeConfig {
    role: AgentRole,
    agent: AgentConfig,
    slots: u32,
    managed_capabilities: BTreeSet<String>,
    installed_capabilities: BTreeSet<String>,
    paused: bool,
    model_refresh: Option<AgentModelRefreshDelivery>,
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

#[derive(Debug, Deserialize)]
struct AgentModelRefreshInput {
    provider: String,
}

#[derive(Debug, Clone, Serialize)]
struct AgentModelRefreshDelivery {
    id: Uuid,
    provider: String,
}

#[derive(Debug, Serialize)]
struct AgentModelRefreshQueued {
    id: Uuid,
    provider: String,
    queued: bool,
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
    read_ok: bool,
    write_ok: bool,
    credential_revision: Option<String>,
    message: String,
    checked_at: DateTime<Utc>,
}

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/health", get(health))
        .route("/api/settings", get(get_host_settings).patch(update_host_settings))
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
        .route("/api/workers/{id}/agent-auth/{request_id}/ack", post(ack_worker_agent_auth))
        .route("/api/workers/{id}/oauth-login", get(worker_oauth_login_state).post(start_worker_oauth_login))
        .route("/api/workers/{id}/oauth-login/input", post(submit_worker_oauth_login_input))
        .route("/api/workers/{id}/oauth-login/claim", get(claim_worker_oauth_login))
        .route("/api/workers/{id}/oauth-login/{request_id}/event", post(report_worker_oauth_login_event))
        .route("/api/workers/{id}/oauth-login/{request_id}/input", get(claim_worker_oauth_login_input))
        .route("/api/workers/{id}/oauth-login/{request_id}/input/{input_id}/ack", post(ack_worker_oauth_login_input))
        .route("/api/workers/{id}/models/refresh", post(queue_worker_model_refresh))
        .route("/api/workers/{id}/models/refresh/{request_id}/ack", post(ack_worker_model_refresh))
        .route("/api/workers/{id}/capabilities", post(update_worker_capabilities))
        .route("/api/workers/{id}/capability-build", post(report_capability_build))
        .route("/api/workers/{id}/heartbeat", post(worker_heartbeat))
        .route("/api/workers/{id}/cleanup", get(worker_cleanup))
        .route("/api/workers/{id}/cleanup/{task_id}", post(worker_cleanup_ack_legacy))
        .route("/api/workers/{id}/cleanup/{task_id}/{role}", post(worker_cleanup_ack))
        .route("/api/workers/{id}/claim", post(claim_task))
        .route("/api/workers/{id}/review-claim", post(claim_review))
        .route("/api/executions/{id}/renew", post(renew_execution))
        .route("/api/executions/{id}/finish", post(finish_execution))
        .route("/api/executions/{id}/release", post(release_execution))
        .route("/api/reviews/{id}/renew", post(renew_review))
        .route("/api/reviews/{id}/finish", post(finish_review))
        .route("/api/reviews/{id}/release", post(release_review))
}

async fn health() -> &'static str { "ok" }

async fn load_host_settings(db: &SqlitePool) -> Result<HostSettings, ApiError> {
    let row = sqlx::query("SELECT review_retry_limit,review_failure_limit FROM host_settings WHERE id=1")
        .fetch_optional(db).await.map_err(db_error)?;
    let (review_retry_limit, review_failure_limit) = if let Some(row) = row {
        (
            row.try_get::<i64,_>("review_retry_limit").map_err(internal)?,
            row.try_get::<i64,_>("review_failure_limit").map_err(internal)?,
        )
    } else {
        (DEFAULT_REVIEW_RETRY_LIMIT, DEFAULT_REVIEW_FAILURE_LIMIT)
    };
    Ok(HostSettings {
        review_retry_limit,
        review_failure_limit,
        task_lease_seconds: DEFAULT_LEASE_SECONDS,
        session_affinity_seconds: session_affinity_seconds(),
    })
}

async fn get_host_settings(State(state): State<Arc<AppState>>) -> ApiResult<HostSettings> {
    load_host_settings(&state.db).await.map(Json)
}

async fn update_host_settings(State(state): State<Arc<AppState>>, Json(input): Json<UpdateHostSettings>) -> ApiResult<HostSettings> {
    let current = load_host_settings(&state.db).await?;
    let review_retry_limit = input.review_retry_limit.unwrap_or(current.review_retry_limit);
    let review_failure_limit = input.review_failure_limit.unwrap_or(current.review_failure_limit);
    for (name, value) in [
        ("review_retry_limit", review_retry_limit),
        ("review_failure_limit", review_failure_limit),
    ] {
        if !(MIN_REVIEW_LIMIT..=MAX_REVIEW_LIMIT).contains(&value) {
            return Err((StatusCode::BAD_REQUEST, format!("{name} must be between {MIN_REVIEW_LIMIT} and {MAX_REVIEW_LIMIT}")));
        }
    }
    sqlx::query("INSERT INTO host_settings(id,review_retry_limit,review_failure_limit,updated_at) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET review_retry_limit=excluded.review_retry_limit,review_failure_limit=excluded.review_failure_limit,updated_at=excluded.updated_at")
        .bind(review_retry_limit).bind(review_failure_limit).bind(ts(Utc::now()))
        .execute(&state.db).await.map_err(db_error)?;
    load_host_settings(&state.db).await.map(Json)
}

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
    let contributor = normalize_contributor(input.contributor)?;
    let stored_git_auth = resolve_new_git_auth(&state, input.git_auth)?;
    let now = Utc::now();
    let project = Project {
        id: Uuid::new_v4(), slug: input.slug, name: input.name.trim().into(), repo_url: input.repo_url.trim().into(),
        default_branch: input.default_branch.trim().into(), contributor, required_worker_tags: input.required_worker_tags,
        default_task_tags: input.default_task_tags,
        git_auth: git_auth_summary(&stored_git_auth), enabled: true, created_at: now, updated_at: now,
    };
    sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,contributor_name,contributor_email,required_worker_tags,default_task_tags,git_auth_mode,git_auth_username,git_auth_secret,git_auth_revision,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(project.id.to_string()).bind(&project.slug).bind(&project.name).bind(&project.repo_url)
        .bind(&project.default_branch).bind(&project.contributor.name).bind(&project.contributor.email)
        .bind(json(&project.required_worker_tags)?).bind(json(&project.default_task_tags)?)
        .bind(git_auth_mode_str(&stored_git_auth.mode)).bind(&stored_git_auth.username).bind(&stored_git_auth.encrypted_secret).bind(&stored_git_auth.credential_revision)
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
    let (read_ok, write_ok, mut message) = match result {
        Ok(status) => (status.read_ok, status.write_ok, status.message),
        Err(error) => (false, false, error),
    };
    message = message.replace(['\r', '\n'], " ");
    if message.chars().count() > 600 {
        message = message.chars().take(600).collect::<String>() + "…";
    }
    let credential_revision = project.git_auth.credential_revision.clone();
    Ok(Json(GitProbeResult {
        ok: read_ok && write_ok,
        read_ok,
        write_ok,
        credential_revision,
        message,
        checked_at,
    }))
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
    let stored_git_auth = resolve_updated_git_auth(&state, &row, input.git_auth)?;
    let now = ts(Utc::now());
    let mut tx = state.db.begin().await.map_err(db_error)?;
    sqlx::query("UPDATE projects SET slug=?,name=?,repo_url=?,default_branch=?,contributor_name=?,contributor_email=?,required_worker_tags=?,default_task_tags=?,git_auth_mode=?,git_auth_username=?,git_auth_secret=?,git_auth_revision=?,enabled=?,updated_at=? WHERE id=?")
        .bind(&slug).bind(name.trim()).bind(repo_url.trim()).bind(default_branch.trim())
        .bind(&contributor.name).bind(&contributor.email)
        .bind(json(&input.required_worker_tags.unwrap_or(current.required_worker_tags))?)
        .bind(json(&input.default_task_tags.unwrap_or(current.default_task_tags))?)
        .bind(git_auth_mode_str(&stored_git_auth.mode)).bind(&stored_git_auth.username).bind(&stored_git_auth.encrypted_secret).bind(&stored_git_auth.credential_revision)
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
    let conflict_group = lazyteam_core::normalize_conflict_group(input.conflict_group.as_deref())
        .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    let task = Task {
        id: Uuid::new_v4(), project_id: input.project_id, title: input.title, description: input.description,
        expected_outcome: input.expected_outcome, acceptance_criteria: input.acceptance_criteria,
        required_tags: input.required_tags, preferred_tags: input.preferred_tags, dependencies: input.dependencies,
        review_feedback: String::new(), priority: input.priority, state: TaskState::Queued, review_cycle: 0,
        conflict_group, created_at: now, updated_at: now,
    };
    sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,acceptance_criteria,required_tags,preferred_tags,dependencies,review_feedback,priority,state,conflict_group,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
        .bind(task.id.to_string()).bind(task.project_id.to_string()).bind(&task.title).bind(&task.description)
        .bind(&task.expected_outcome).bind(json(&task.acceptance_criteria)?).bind(json(&task.required_tags)?)
        .bind(json(&task.preferred_tags)?).bind(json(&task.dependencies)?).bind(&task.review_feedback).bind(task.priority).bind("queued")
        .bind(&task.conflict_group).bind(ts(task.created_at)).bind(ts(task.updated_at)).execute(&state.db).await.map_err(db_error)?;
    Ok(Json(task))
}

pub(crate) async fn list_tasks(State(state): State<Arc<AppState>>) -> ApiResult<Vec<Task>> {
    let rows = sqlx::query("SELECT * FROM tasks WHERE state!='cancelled' ORDER BY priority DESC, created_at ASC").fetch_all(&state.db).await.map_err(db_error)?;
    rows.iter().map(task_from_row).collect::<Result<Vec<_>,_>>().map(Json)
}

pub(crate) async fn task_status(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<TaskStatus> {
    let task_row = sqlx::query("SELECT * FROM tasks WHERE id=? AND state!='cancelled'")
        .bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "task not found".into()))?;
    let task = task_from_row(&task_row)?;
    let execution_row = sqlx::query("SELECT * FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?;
    let latest_execution = execution_row.as_ref().map(execution_from_row).transpose()?;
    let lifetime_reviewer_retries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state='completed' AND (verdict LIKE '%\"verdict\":\"retry\"%' OR verdict LIKE '%\"verdict\": \"retry\"%')")
        .bind(id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    let current_cycle_reviewer_retries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND review_cycle=? AND state='completed' AND (verdict LIKE '%\"verdict\":\"retry\"%' OR verdict LIKE '%\"verdict\": \"retry\"%')")
        .bind(id.to_string()).bind(task.review_cycle).fetch_one(&state.db).await.map_err(db_error)?;
    // Completed vs infrastructure attempts stay separate with a clear
    // denominator: completed counts completed verdict rows only, while
    // failed/lost rows are runtime/infrastructure attempts that never count
    // as quality retries.
    let completed_reviews: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state='completed'")
        .bind(id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    let review_runtime_failures: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state='failed'")
        .bind(id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    let review_lost_leases: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state='lost'")
        .bind(id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    // Per-candidate breakdown for the latest implementation execution only,
    // so mixed history across older candidates has an unambiguous current
    // denominator. Approve/retry split uses completed verdict JSON only.
    let latest_execution_id = latest_execution.as_ref().map(|e| e.id.to_string());
    let (candidate_completed_reviews, candidate_completed_approvals, candidate_completed_retries, candidate_runtime_failures, candidate_lost_leases) = if let Some(execution_id) = latest_execution_id {
        let completed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='completed'")
            .bind(id.to_string()).bind(&execution_id).fetch_one(&state.db).await.map_err(db_error)?;
        let approvals: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='completed' AND (verdict LIKE '%\"verdict\":\"approve\"%' OR verdict LIKE '%\"verdict\": \"approve\"%')")
            .bind(id.to_string()).bind(&execution_id).fetch_one(&state.db).await.map_err(db_error)?;
        let retries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='completed' AND (verdict LIKE '%\"verdict\":\"retry\"%' OR verdict LIKE '%\"verdict\": \"retry\"%')")
            .bind(id.to_string()).bind(&execution_id).fetch_one(&state.db).await.map_err(db_error)?;
        let failed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='failed'")
            .bind(id.to_string()).bind(&execution_id).fetch_one(&state.db).await.map_err(db_error)?;
        let lost: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='lost'")
            .bind(id.to_string()).bind(&execution_id).fetch_one(&state.db).await.map_err(db_error)?;
        (completed, approvals, retries, failed, lost)
    } else {
        (0, 0, 0, 0, 0)
    };
    let waiting = waiting_for_task(&state.db, &task).await?;
    Ok(Json(TaskStatus { task, latest_execution, current_cycle_reviewer_retries: current_cycle_reviewer_retries.max(0), lifetime_reviewer_retries: lifetime_reviewer_retries.max(0), completed_reviews: completed_reviews.max(0), review_runtime_failures: review_runtime_failures.max(0), review_lost_leases: review_lost_leases.max(0), candidate_completed_reviews: candidate_completed_reviews.max(0), candidate_completed_approvals: candidate_completed_approvals.max(0), candidate_completed_retries: candidate_completed_retries.max(0), candidate_runtime_failures: candidate_runtime_failures.max(0), candidate_lost_leases: candidate_lost_leases.max(0), waiting }))
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
    sqlx::query("INSERT OR IGNORE INTO agent_session_cleanup(task_id,worker_id,role,created_at) SELECT ?,worker_id,'implementation',? FROM executions WHERE task_id=?")
        .bind(&task_id).bind(&now).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?;
    sqlx::query("INSERT OR IGNORE INTO agent_session_cleanup(task_id,worker_id,role,created_at) SELECT ?,reviewer_worker_id,'review',? FROM reviews WHERE task_id=?")
        .bind(&task_id).bind(&now).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?;
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
    let integration = result.and_then(|value| value.integration.as_ref());
    let checkout = ReviewCheckout {
        repo_url: crate::git_broker::task_repo_url(&state, execution.id)?,
        default_branch: project.default_branch.clone(),
        review_ref: result.and_then(|value| value.review_ref.clone()),
        commit_sha: result.and_then(|value| value.commit_sha.clone()),
        base_sha: result.and_then(|value| value.base_sha.clone()),
        upstream_sha: integration.map(|value| value.upstream_sha.clone()),
        integration_sha: integration.and_then(|value| value.integration_sha.clone()),
        effective_diff_hash: integration.and_then(|value| value.effective_diff_hash.clone()),
        pullable: false,
    };
    Ok(Json(ReviewEvidence { project, task, execution, worker, checkout }))
}

async fn task_board(State(state): State<Arc<AppState>>) -> ApiResult<Vec<TaskBoardItem>> {
    let rows = sqlx::query("SELECT t.*, e.worker_id AS board_worker_id, w.name AS board_worker_name, e.result AS board_result, r.reviewer_worker_id AS board_reviewer_id, rw.name AS board_reviewer_name, r.state AS board_review_state, COALESCE((SELECT MAX(e2.attempt) FROM executions e2 WHERE e2.task_id=t.id),0) AS board_attempt, (SELECT COUNT(*) FROM reviews r2 WHERE r2.task_id=t.id AND r2.state='completed') AS board_review_rounds, (SELECT COUNT(*) FROM reviews r2f WHERE r2f.task_id=t.id AND r2f.state='failed') AS board_review_failures, (SELECT COUNT(*) FROM reviews r2l WHERE r2l.task_id=t.id AND r2l.state='lost') AS board_review_lost, (SELECT COUNT(*) FROM reviews r3 WHERE r3.task_id=t.id AND r3.state='completed' AND (r3.verdict LIKE '%\"verdict\":\"retry\"%' OR r3.verdict LIKE '%\"verdict\": \"retry\"%')) AS board_lifetime_retries, (SELECT COUNT(*) FROM reviews r4 WHERE r4.task_id=t.id AND r4.review_cycle=t.review_cycle AND r4.state='completed' AND (r4.verdict LIKE '%\"verdict\":\"retry\"%' OR r4.verdict LIKE '%\"verdict\": \"retry\"%')) AS board_current_retries FROM tasks t LEFT JOIN executions e ON e.id=(SELECT e2.id FROM executions e2 WHERE e2.task_id=t.id ORDER BY e2.attempt DESC LIMIT 1) LEFT JOIN workers w ON w.id=e.worker_id LEFT JOIN reviews r ON r.id=(SELECT r2.id FROM reviews r2 WHERE r2.task_id=t.id ORDER BY r2.created_at DESC LIMIT 1) LEFT JOIN workers rw ON rw.id=r.reviewer_worker_id WHERE t.state!='cancelled' ORDER BY t.priority DESC, t.created_at ASC")
        .fetch_all(&state.db).await.map_err(db_error)?;
    let mut items = Vec::with_capacity(rows.len());
    // One shared diagnostic context for the whole board: a single fleet
    // scan, project load, and settings read no matter how many waiting
    // tasks are rendered. Waiting itself is computed only for queued/review
    // rows; all other states skip it without extra queries.
    let diag_ctx = load_diag_context(&state.db).await?;
    for row in &rows {
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
        let attempt: i64 = row.try_get("board_attempt").map_err(internal)?;
        let review_rounds: i64 = row.try_get("board_review_rounds").map_err(internal)?;
        let review_runtime_failures: i64 = row.try_get("board_review_failures").map_err(internal)?;
        let review_lost_leases: i64 = row.try_get("board_review_lost").map_err(internal)?;
        let lifetime_reviewer_retries: i64 = row.try_get("board_lifetime_retries").map_err(internal)?;
        let current_cycle_reviewer_retries: i64 = row.try_get("board_current_retries").map_err(internal)?;
        let current_cycle_reviewer_retries = current_cycle_reviewer_retries.max(0);
        let lifetime_reviewer_retries = lifetime_reviewer_retries.max(current_cycle_reviewer_retries);
        // Waiting diagnostics only for waiting states; actively
        // running/reviewing cards stay unspammed. Read-only, same
        // predicates as claim selection, inline in the existing board
        // refresh (no extra polling).
        let waiting = waiting_for_task_with_ctx(&state.db, &diag_ctx, &task).await?;
        items.push(TaskBoardItem { task, worker, reviewer, result, attempt: attempt.max(0) as u32, review_rounds: review_rounds.max(0), review_runtime_failures: review_runtime_failures.max(0), review_lost_leases: review_lost_leases.max(0), reviewer_retries: current_cycle_reviewer_retries, current_cycle_reviewer_retries, lifetime_reviewer_retries, waiting });
    }
    Ok(Json(items))
}

async fn register_worker(State(state): State<Arc<AppState>>, Json(input): Json<RegisterWorker>) -> Result<Response, ApiError> {
    if input.protocol_version != PROTOCOL_VERSION {
        return Err((StatusCode::BAD_REQUEST, format!("unsupported worker protocol {}; upgrade to worker protocol {PROTOCOL_VERSION} or enroll as a new worker", input.protocol_version)));
    }
    let id = input.id.unwrap_or_else(Uuid::new_v4);
    let retired: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workers WHERE id=? AND retired_at IS NOT NULL")
        .bind(id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
    if retired != 0 {
        return Err((StatusCode::CONFLICT, "retired worker IDs cannot be re-registered; enroll as a new worker".into()));
    }
    let now = Utc::now();
    let credential = format!("ltw_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let credential_hash = hash_secret(&credential);
    let tags = input.tags;
    validate_user_tags(&tags)?;
    if input.agent_type != "pi" {
        return Err((StatusCode::BAD_REQUEST, "unsupported agent type".into()));
    }
    let agent_capabilities = json(&input.agent_capabilities)?;
    // Re-registration (same worker id) refreshes identity, heartbeat, and capability
    // state only. Host-owned selections (role, agent provider/model, prompt, tags,
    // projects, slots) are intentionally absent from the ON CONFLICT UPDATE clause
    // below so re-enrollment never resets them.
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
    let rows = sqlx::query("SELECT * FROM workers WHERE retired_at IS NULL AND internal_actor=0 ORDER BY name").fetch_all(&state.db).await.map_err(db_error)?;
    rows.iter().map(worker_from_row).collect::<Result<Vec<_>,_>>().map(Json)
}

pub(crate) async fn delete_worker(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>) -> Result<StatusCode, ApiError> {
    let worker_id = id.to_string();
    let row = sqlx::query("SELECT running_slots,retired_at FROM workers WHERE id=?")
        .bind(&worker_id).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let running_slots: i64 = row.try_get("running_slots").map_err(internal)?;
    let retired_at: Option<String> = row.try_get("retired_at").map_err(internal)?;
    if retired_at.is_some() { return Ok(StatusCode::NO_CONTENT); }
    if running_slots != 0 {
        return Err((StatusCode::CONFLICT, "worker has active slots; Stop it before retiring it".into()));
    }
    let now = ts(Utc::now());
    let changed = sqlx::query("UPDATE workers SET retired_at=?,credential_hash=NULL,state='draining',running_slots=0 WHERE id=? AND retired_at IS NULL AND running_slots=0")
        .bind(&now).bind(&worker_id).execute(&state.db).await.map_err(db_error)?.rows_affected();
    if changed == 0 {
        return Err((StatusCode::CONFLICT, "worker changed while retiring".into()));
    }
    state.agent_auth_updates.lock().await.remove(&id);
    Ok(StatusCode::NO_CONTENT)
}

/// Resolve the Host-owned agent selection for a worker update.
///
/// Omitted fields preserve the current Host-owned selection. Clearing is only
/// possible through an explicit `clear_model: true`, which must not be combined
/// with replacement values; a bare null/absent provider or model never clears.
fn resolve_agent_selection(
    current: &AgentConfig,
    provider: Option<String>,
    model: Option<String>,
    clear_model: bool,
) -> Result<(Option<String>, Option<String>), ApiError> {
    if clear_model {
        if provider.is_some() || model.is_some() {
            return Err((StatusCode::BAD_REQUEST, "clear_model cannot be combined with provider/model".into()));
        }
        return Ok((None, None));
    }
    let provider = provider.or_else(|| current.provider.clone());
    let model = model.or_else(|| current.model.clone());
    if provider.is_some() != model.is_some() {
        return Err((StatusCode::BAD_REQUEST, "provider and model must be set or cleared together".into()));
    }
    Ok((provider, model))
}

async fn update_worker(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, Json(input): Json<UpdateWorker>) -> ApiResult<Worker> {
    let row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let current = worker_from_row(&row)?;
    let currently_paused = matches!(current.state, WorkerState::Draining);
    let paused = input.paused.unwrap_or(currently_paused);
    let pause_requested = paused && !currently_paused;
    let authority_changed = input.role.as_ref().is_some_and(|value| value != &current.role)
        || input.allowed_projects.as_ref().is_some_and(|value| value != &current.allowed_projects);
    let role = input.role.unwrap_or_else(|| current.role.clone());
    if role == AgentRole::Reviewer && current.protocol_version < PROTOCOL_VERSION {
        return Err((StatusCode::CONFLICT, format!("update/restart this worker with protocol {PROTOCOL_VERSION} before assigning the reviewer role")));
    }
    let agent_type = input.agent_type.unwrap_or_else(|| current.agent.agent_type.clone());
    if agent_type != "pi" { return Err((StatusCode::BAD_REQUEST, "unsupported agent type".into())); }
    let (provider, model) = resolve_agent_selection(&current.agent, input.provider, input.model, input.clear_model.unwrap_or(false))?;
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
    let allowed_projects = input.allowed_projects.unwrap_or_else(|| current.allowed_projects.clone());
    let slots = input.slots.unwrap_or(current.slots).max(1);
    let needs_build = !managed_capabilities.is_subset(&current.installed_capabilities);
    let recovering_capability_state = matches!(current.state, WorkerState::Pending)
        || (matches!(current.state, WorkerState::Degraded) && current.capability_error.is_some());
    let next_state = if paused {
        "draining"
    } else if needs_build {
        "pending"
    } else if recovering_capability_state || currently_paused {
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
    if pause_requested {
        sqlx::query("UPDATE tasks SET state='queued',sticky_worker_id=NULL,updated_at=? WHERE state IN ('assigned','running') AND id IN (SELECT task_id FROM executions WHERE worker_id=? AND state IN ('assigned','running'))")
            .bind(&now).bind(id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
        sqlx::query("UPDATE executions SET state='lost',finished_at=?,lease_capability_hash=NULL,lease_until=? WHERE worker_id=? AND state IN ('assigned','running')")
            .bind(&now).bind(&now).bind(id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
        sqlx::query("UPDATE reviews SET state='lost',finished_at=?,lease_capability_hash=NULL,lease_until=? WHERE reviewer_worker_id=? AND state IN ('assigned','running')")
            .bind(&now).bind(&now).bind(id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
        // Infrastructure-loss path: freshly lost reviewer leases count toward
        // the same per-candidate runtime budget as expiries/failures. Only
        // the latest execution's budget can block; stale candidates never
        // block. History is preserved.
        {
            let review_failure_limit: i64 = sqlx::query_scalar("SELECT review_failure_limit FROM host_settings WHERE id=1")
                .fetch_optional(&mut *tx).await.map_err(db_error)?.flatten().unwrap_or(DEFAULT_REVIEW_FAILURE_LIMIT);
            let affected: Vec<(String, String)> = sqlx::query("SELECT DISTINCT task_id,execution_id FROM reviews WHERE reviewer_worker_id=? AND state='lost' AND finished_at=?")
                .bind(id.to_string()).bind(&now).fetch_all(&mut *tx).await.map_err(db_error)?.iter().map(|row| {
                    let task_id: String = row.try_get("task_id").map_err(internal)?;
                    let execution_id: String = row.try_get("execution_id").map_err(internal)?;
                    Ok::<_, ApiError>((task_id, execution_id))
                }).collect::<Result<Vec<_>, _>>()?;
            for (task_id, execution_id) in affected {
                let latest: Option<String> = sqlx::query_scalar("SELECT id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
                    .bind(&task_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
                if latest.as_deref() != Some(execution_id.as_str()) {
                    continue;
                }
                let failed_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='failed'")
                    .bind(&task_id).bind(&execution_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                let lost_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='lost'")
                    .bind(&task_id).bind(&execution_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                if review_runtime_failures_exhausted(failed_count, lost_count, review_failure_limit) {
                    let feedback = review_runtime_blocked_feedback(failed_count, lost_count, review_failure_limit, "Last reviewer lease lost (worker paused).");
                    sqlx::query("UPDATE tasks SET state='blocked',review_feedback=?,updated_at=? WHERE id=? AND state='review'")
                        .bind(feedback).bind(&now).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?;
                }
            }
        }
        sqlx::query("UPDATE workers SET running_slots=0,state='draining' WHERE id=?")
            .bind(id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
    } else if authority_changed {
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
    let model_refresh = state.model_refresh_requests.lock().await
        .get(&id)
        .and_then(|queue| queue.front())
        .map(|request| AgentModelRefreshDelivery { id: request.id, provider: request.provider.clone() });
    Ok(Json(WorkerRuntimeConfig {
        role: worker.role,
        agent: worker.agent,
        slots: worker.slots.max(1),
        managed_capabilities: worker.managed_capabilities,
        installed_capabilities: worker.installed_capabilities,
        paused: matches!(worker.state, WorkerState::Draining),
        model_refresh,
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
    state.agent_auth_updates.lock().await.entry(id).or_default().push_back(update);
    Ok(Json(response))
}

async fn worker_agent_auth(
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let update = state.agent_auth_updates.lock().await
        .get(&id)
        .and_then(|queue| queue.front())
        .cloned();
    match update {
        Some(update) => Ok(Json(AgentAuthDelivery {
            id: update.id,
            provider: update.provider,
            api_key: update.api_key,
        }).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

async fn ack_worker_agent_auth(
    Path((id, request_id)): Path<(Uuid, Uuid)>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let mut updates = state.agent_auth_updates.lock().await;
    let mut remove_worker_queue = false;
    if let Some(queue) = updates.get_mut(&id) {
        if queue.front().is_some_and(|update| update.id == request_id) {
            queue.pop_front();
            remove_worker_queue = queue.is_empty();
        } else if queue.iter().any(|update| update.id == request_id) {
            return Err((StatusCode::CONFLICT, "provider credential ACK is out of order".into()));
        }
    }
    if remove_worker_queue {
        updates.remove(&id);
    }
    Ok(StatusCode::NO_CONTENT)
}

fn bounded_oauth_text(value: Option<String>, max: usize) -> Option<String> {
    value.map(|value| value.chars().take(max).collect::<String>()).filter(|value| !value.trim().is_empty())
}

/// Worker-supplied OAuth diagnostic text, safe to store and display.
///
/// Upstream provider errors forwarded by the worker can embed raw
/// token-response JSON (Pi's parsers include the response body when fields
/// are missing), so every worker-supplied message is redacted for
/// credential-shaped values before it reaches Host state or UI responses.
/// Static Host-authored fallback strings bypass this (they never carry
/// upstream text), but redacting them too would be harmless.
fn oauth_diagnostic(message: Option<String>, max: usize) -> Option<String> {
    bounded_oauth_text(message.map(|message| redact_oauth_secret_text(&message)), max)
}

async fn start_worker_oauth_login(
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
    Json(input): Json<AgentOAuthStartInput>,
) -> ApiResult<AgentOAuthLoginState> {
    let provider = input.provider.trim();
    if provider.is_empty() { return Err((StatusCode::BAD_REQUEST, "provider is required".into())); }
    let row = sqlx::query("SELECT * FROM workers WHERE id=?")
        .bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let worker = worker_from_row(&row)?;
    let candidate = worker.agent_capabilities.providers.iter()
        .find(|candidate| candidate.id == provider)
        .ok_or((StatusCode::BAD_REQUEST, "provider is not reported by this worker's Pi runtime".into()))?;
    if candidate.oauth_label.is_none() {
        return Err((StatusCode::BAD_REQUEST, "this provider does not expose OAuth authentication in Pi".into()));
    }
    let mut logins = state.oauth_login_states.lock().await;
    if let Some(existing) = logins.get(&id) {
        if !matches!(existing.status.as_str(), "complete" | "failed") {
            return Err((StatusCode::CONFLICT, format!("OAuth login is already {}", existing.status)));
        }
    }
    let login = AgentOAuthLoginState {
        id: Uuid::new_v4(), provider: provider.to_string(), status: "queued".into(),
        message: Some("Waiting for the worker to start Pi OAuth. The authorization URL will appear here; open it on any machine, then paste back the redirect URL if asked.".into()), verification_uri: None, user_code: None,
        authorization_url: None, paste_prompt: None, paste_placeholder: None, pending_input: None,
    };
    logins.insert(id, login.clone());
    Ok(Json(login))
}

async fn worker_oauth_login_state(
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
) -> Result<Response, ApiError> {
    match state.oauth_login_states.lock().await.get(&id).cloned() {
        Some(login) => Ok(Json(login).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

async fn claim_worker_oauth_login(
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let mut logins = state.oauth_login_states.lock().await;
    let Some(login) = logins.get_mut(&id) else { return Ok(StatusCode::NO_CONTENT.into_response()); };
    if login.status != "queued" { return Ok(StatusCode::NO_CONTENT.into_response()); }
    login.status = "running".into();
    login.message = Some("Pi OAuth login started on the worker; waiting for the authorization URL.".into());
    Ok(Json(AgentOAuthClaim { id: login.id, provider: login.provider.clone() }).into_response())
}

async fn report_worker_oauth_login_event(
    Path((id, request_id)): Path<(Uuid, Uuid)>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<AgentOAuthEventInput>,
) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let mut logins = state.oauth_login_states.lock().await;
    let login = logins.get_mut(&id).ok_or((StatusCode::NOT_FOUND, "OAuth login not found".into()))?;
    if login.id != request_id { return Err((StatusCode::CONFLICT, "OAuth login request was replaced".into())); }
    match input.kind.as_str() {
        "device_code" => {
            login.status = "waiting_user".into();
            login.message = oauth_diagnostic(input.message, 512).or(Some("Waiting for authorization: open the verification page and enter the device code.".into()));
            login.verification_uri = bounded_oauth_text(input.verification_uri, 2048);
            login.user_code = bounded_oauth_text(input.user_code, 128);
        }
        "auth_url" => {
            // Pi's real browser flow (`auth_url` notify): the human browser
            // opens this URL on any machine. Pi listens on worker-local
            // localhost, so completion arrives via the paste-back relay.
            login.status = "awaiting_authorization".into();
            login.message = oauth_diagnostic(input.message, 512).or(Some("Waiting for authorization: open the URL below in any browser.".into()));
            login.authorization_url = bounded_oauth_text(input.authorization_url.or(input.verification_uri), 4096);
        }
        "awaiting_input" => {
            // Pi's `manual_code` prompt is active on the worker: the browser
            // redirect landed on localhost unreachable from the worker, so
            // the user must paste the final redirect URL/code via the Host.
            login.status = "awaiting_callback".into();
            login.message = oauth_diagnostic(input.message, 512).or(Some("Waiting for callback: paste the final redirect URL or authorization code below.".into()));
            login.paste_prompt = bounded_oauth_text(input.paste_prompt, 512);
            login.paste_placeholder = bounded_oauth_text(input.paste_placeholder, 512);
        }
        "progress" | "info" => login.message = oauth_diagnostic(input.message, 512),
        "complete" => {
            login.status = "complete".into();
            login.message = oauth_diagnostic(input.message, 512).or(Some("OAuth login completed.".into()));
            login.pending_input = None;
        }
        "failed" => {
            login.status = "failed".into();
            login.message = oauth_diagnostic(input.message, 1024).or(Some("OAuth login failed.".into()));
            login.pending_input = None;
        }
        _ => return Err((StatusCode::BAD_REQUEST, "unknown OAuth login event kind".into())),
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Host relay for Pi's localhost OAuth callback (remote completion bridge).
///
/// Pi's browser flows redirect the human browser to worker-local localhost
/// (`http://localhost:1455/auth/callback` for openai-codex, similar loopback
/// listeners for other providers). When the worker is on another machine the
/// human browser cannot reach that listener, but Pi also accepts the pasted
/// final redirect URL/authorization code via its `manual_code` prompt. The
/// Host UI collects that paste and stores it here, in memory only; the
/// worker polls the companion endpoint and feeds it to Pi, whose token
/// exchange then lands only in the worker's isolated Pi auth store. The
/// pasted single-use code is never serialized to UI responses, never logged,
/// and never persisted to Host durable storage.
async fn submit_worker_oauth_login_input(
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
    Json(input): Json<AgentOAuthInputSubmit>,
) -> ApiResult<AgentOAuthLoginState> {
    let pasted = input.input.trim().to_string();
    if pasted.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "pasted redirect URL or authorization code is required".into()));
    }
    if pasted.chars().count() > 4096 {
        return Err((StatusCode::BAD_REQUEST, "pasted value is too long".into()));
    }
    let mut logins = state.oauth_login_states.lock().await;
    let login = logins.get_mut(&id).ok_or((StatusCode::NOT_FOUND, "OAuth login not found".into()))?;
    if !matches!(login.status.as_str(), "awaiting_authorization" | "awaiting_callback" | "running" | "waiting_user") {
        return Err((StatusCode::CONFLICT, format!("OAuth login is {} and is not waiting for input", login.status)));
    }
    if login.pending_input.is_some() {
        return Err((StatusCode::CONFLICT, "OAuth callback input is already pending delivery".into()));
    }
    login.pending_input = Some(PendingOAuthInput { id: Uuid::new_v4(), input: pasted });
    if login.status != "awaiting_callback" {
        login.status = "awaiting_callback".into();
    }
    login.message = Some("Callback received; waiting for the worker to complete the Pi token exchange.".into());
    Ok(Json(login.clone()))
}

/// Worker poll for Host-relayed OAuth callback input. Delivery is
/// at-least-once until the worker ACKs successful handoff to Pi stdin.
async fn claim_worker_oauth_login_input(
    Path((id, request_id)): Path<(Uuid, Uuid)>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let logins = state.oauth_login_states.lock().await;
    let login = logins.get(&id).ok_or((StatusCode::NOT_FOUND, "OAuth login not found".into()))?;
    if login.id != request_id { return Err((StatusCode::CONFLICT, "OAuth login request was replaced".into())); }
    match login.pending_input.as_ref() {
        Some(input) => Ok(Json(AgentOAuthInputDelivery { id: input.id, input: input.input.clone() }).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

async fn ack_worker_oauth_login_input(
    Path((id, request_id, input_id)): Path<(Uuid, Uuid, Uuid)>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let mut logins = state.oauth_login_states.lock().await;
    let login = logins.get_mut(&id).ok_or((StatusCode::NOT_FOUND, "OAuth login not found".into()))?;
    if login.id != request_id { return Err((StatusCode::CONFLICT, "OAuth login request was replaced".into())); }
    if login.pending_input.as_ref().is_some_and(|input| input.id == input_id) {
        login.pending_input = None;
    } else if login.pending_input.is_some() {
        return Err((StatusCode::CONFLICT, "OAuth callback input was replaced".into()));
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn queue_worker_model_refresh(
    Path(id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
    Json(input): Json<AgentModelRefreshInput>,
) -> ApiResult<AgentModelRefreshQueued> {
    let provider = input.provider.trim();
    if provider.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "provider is required".into()));
    }
    let row = sqlx::query("SELECT * FROM workers WHERE id=?")
        .bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let worker = worker_from_row(&row)?;
    let candidate = worker.agent_capabilities.providers.iter()
        .find(|candidate| candidate.id == provider)
        .ok_or((StatusCode::BAD_REQUEST, "provider is not reported by this worker's agent runtime".into()))?;
    if !candidate.configured {
        return Err((StatusCode::CONFLICT, "provider authentication must be configured before refreshing its model catalog".into()));
    }
    let request = PendingModelRefresh { id: Uuid::new_v4(), provider: provider.to_string() };
    let response = AgentModelRefreshQueued { id: request.id, provider: request.provider.clone(), queued: true };
    state.model_refresh_requests.lock().await.entry(id).or_default().push_back(request);
    Ok(Json(response))
}

async fn ack_worker_model_refresh(
    Path((id, request_id)): Path<(Uuid, Uuid)>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let mut requests = state.model_refresh_requests.lock().await;
    let mut remove_worker_queue = false;
    if let Some(queue) = requests.get_mut(&id) {
        if queue.front().is_some_and(|request| request.id == request_id) {
            queue.pop_front();
            remove_worker_queue = queue.is_empty();
        } else if queue.iter().any(|request| request.id == request_id) {
            return Err((StatusCode::CONFLICT, "model refresh ACK is out of order".into()));
        }
    }
    if remove_worker_queue {
        requests.remove(&id);
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn update_worker_capabilities(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap, Json(capabilities): Json<AgentCapabilities>) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let protocol_version = headers
        .get("x-lazyteam-worker-protocol-version")
        .and_then(|value| value.to_str().ok())
        .map(str::parse::<u32>)
        .transpose()
        .map_err(|_| (StatusCode::BAD_REQUEST, "invalid worker protocol version header".into()))?;
    if protocol_version.is_some_and(|version| version != PROTOCOL_VERSION) {
        return Err((StatusCode::BAD_REQUEST, format!("unsupported worker protocol version; upgrade to worker protocol {PROTOCOL_VERSION} or enroll as a new worker")));
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
    let next_state = if matches!(worker.state, WorkerState::Draining) {
        "draining"
    } else if ready {
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
    let rows = sqlx::query("SELECT c.task_id,c.role,p.slug FROM agent_session_cleanup c JOIN tasks t ON t.id=c.task_id JOIN projects p ON p.id=t.project_id WHERE c.worker_id=? ORDER BY c.created_at ASC")
        .bind(id.to_string()).fetch_all(&state.db).await.map_err(db_error)?;
    let mut items = Vec::with_capacity(rows.len());
    for row in rows {
        items.push(WorkerCleanup {
            task_id: uuid(row.try_get("task_id").map_err(internal)?)?,
            project_slug: row.try_get("slug").map_err(internal)?,
            role: row.try_get("role").map_err(internal)?,
        });
    }
    Ok(Json(items))
}

async fn worker_cleanup_ack_legacy(Path((id, task_id)): Path<(Uuid, Uuid)>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    let execution_id: Option<String> = sqlx::query_scalar("SELECT id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(task_id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?;
    if let Some(execution_id) = execution_id { crate::git_broker::remove_task_repo(&state, uuid(execution_id)?).await?; }
    sqlx::query("DELETE FROM task_cleanup WHERE task_id=? AND worker_id=?")
        .bind(task_id.to_string()).bind(id.to_string()).execute(&state.db).await.map_err(db_error)?;
    sqlx::query("DELETE FROM agent_session_cleanup WHERE task_id=? AND worker_id=?")
        .bind(task_id.to_string()).bind(id.to_string()).execute(&state.db).await.map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn worker_cleanup_ack(Path((id, task_id, role)): Path<(Uuid, Uuid, String)>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    if !matches!(role.as_str(), "implementation" | "review") {
        return Err((StatusCode::BAD_REQUEST, "invalid session cleanup role".into()));
    }
    if role == "implementation" {
        let execution_id: Option<String> = sqlx::query_scalar("SELECT id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
            .bind(task_id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?;
        if let Some(execution_id) = execution_id { crate::git_broker::remove_task_repo(&state, uuid(execution_id)?).await?; }
        sqlx::query("DELETE FROM task_cleanup WHERE task_id=? AND worker_id=?")
            .bind(task_id.to_string()).bind(id.to_string()).execute(&state.db).await.map_err(db_error)?;
    }
    sqlx::query("DELETE FROM agent_session_cleanup WHERE task_id=? AND worker_id=? AND role=?")
        .bind(task_id.to_string()).bind(id.to_string()).bind(&role).execute(&state.db).await.map_err(db_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn ensure_internal_work_actor(state: &AppState, role: AgentRole) -> Result<Uuid, ApiError> {
    let (id, name, role_name) = match role {
        AgentRole::Worker => (Uuid::from_u128(0x101), "__lazyteam_interactive_implementation", "worker"),
        AgentRole::Reviewer => (Uuid::from_u128(0x102), "__lazyteam_interactive_review", "reviewer"),
    };
    let now = ts(Utc::now());
    sqlx::query("INSERT OR IGNORE INTO workers(id,name,role,state,os,arch,tags,allowed_projects,slots,running_slots,protocol_version,worker_version,last_heartbeat_at,created_at,internal_actor) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)")
        .bind(id.to_string()).bind(name).bind(role_name).bind("idle").bind("internal").bind("internal")
        .bind("{}").bind("[\"*\"]").bind(1024_i64).bind(0_i64).bind(PROTOCOL_VERSION as i64).bind("internal")
        .bind(&now).bind(&now).execute(&state.db).await.map_err(db_error)?;
    sqlx::query("UPDATE workers SET protocol_version=?,worker_version='internal',last_heartbeat_at=?,internal_actor=1,retired_at=NULL WHERE id=?")
        .bind(PROTOCOL_VERSION as i64).bind(&now).bind(id.to_string()).execute(&state.db).await.map_err(db_error)?;
    Ok(id)
}

async fn persist_task_claim(
    state: &AppState,
    task: &Task,
    worker: &Worker,
    execution: &Execution,
    attempt: i64,
    lease_capability_hash: &str,
    now: DateTime<Utc>,
) -> Result<bool, ApiError> {
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let claimed = sqlx::query("UPDATE tasks SET state='assigned',sticky_worker_id=COALESCE(sticky_worker_id,?),updated_at=? WHERE id=? AND state='queued'")
        .bind(worker.id.to_string()).bind(ts(now)).bind(task.id.to_string()).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
    if claimed == 0 {
        tx.rollback().await.map_err(db_error)?;
        return Ok(false);
    }
    sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,lease_capability_hash,worker_agent_type,worker_provider,worker_model) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
        .bind(execution.id.to_string()).bind(task.id.to_string()).bind(worker.id.to_string()).bind(attempt)
        .bind("assigned").bind(ts(execution.lease_until)).bind(ts(now)).bind(lease_capability_hash)
        .bind(worker.agent.agent_type.clone()).bind(worker.agent.provider.clone()).bind(worker.agent.model.clone())
        .execute(&mut *tx).await.map_err(db_error)?;
    sqlx::query("UPDATE workers SET running_slots=running_slots+1,state='busy' WHERE id=?")
        .bind(worker.id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(true)
}

async fn persist_review_claim(
    state: &AppState,
    task: &Task,
    worker: &Worker,
    execution: &Execution,
    review: &ReviewLease,
    lease_capability_hash: &str,
    result: &ExecutionResult,
    upstream_sha: &str,
    integration_sha: &str,
    effective_diff_hash: &str,
    now: DateTime<Utc>,
) -> Result<bool, ApiError> {
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let inserted = match sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,lease_capability_hash,reviewer_agent_type,reviewer_provider,reviewer_model,review_cycle,upstream_sha,integration_sha,effective_diff_hash) SELECT ?,?,?,?,?,?,?,?,?,?,?,?,?,?,? WHERE EXISTS (SELECT 1 FROM tasks WHERE id=? AND state='review') AND NOT EXISTS (SELECT 1 FROM reviews WHERE task_id=? AND state IN ('assigned','running'))")
        .bind(review.id.to_string()).bind(task.id.to_string()).bind(execution.id.to_string()).bind(worker.id.to_string())
        .bind("assigned").bind(ts(review.lease_until)).bind(ts(now)).bind(lease_capability_hash)
        .bind(worker.agent.agent_type.clone()).bind(worker.agent.provider.clone()).bind(worker.agent.model.clone()).bind(task.review_cycle)
        .bind(upstream_sha).bind(integration_sha).bind(effective_diff_hash)
        .bind(task.id.to_string()).bind(task.id.to_string())
        .execute(&mut *tx).await {
            Ok(result) => result.rows_affected(),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
                tx.rollback().await.map_err(db_error)?;
                return Ok(false);
            }
            Err(error) => return Err(db_error(error)),
        };
    if inserted != 1 {
        tx.rollback().await.map_err(db_error)?;
        return Ok(false);
    }
    sqlx::query("UPDATE executions SET result=? WHERE id=? AND state='completed'")
        .bind(json(result)?).bind(execution.id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
    sqlx::query("UPDATE workers SET running_slots=running_slots+1,state='busy' WHERE id=?")
        .bind(worker.id.to_string()).execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(true)
}

async fn claim_task(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    match claim_task_for_worker(&state, id, None).await? {
        Some(assignment) => Ok(Json(assignment).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

pub(crate) async fn claim_task_for_worker(state: &AppState, id: Uuid, task_id: Option<Uuid>) -> Result<Option<Assignment>, ApiError> {
    let row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let worker = worker_from_row(&row)?;
    let internal_actor: i64 = row.try_get("internal_actor").unwrap_or(0);
    if worker.role != AgentRole::Worker || worker.protocol_version < PROTOCOL_VERSION {
        return Ok(None);
    }
    if worker.running_slots >= worker.slots || !matches!(worker.state, WorkerState::Idle | WorkerState::Busy) {
        return Ok(None);
    }
    let worker_id_text = worker.id.to_string();
    let rows = if let Some(task_id) = task_id {
        sqlx::query("SELECT * FROM tasks WHERE id=? AND state='queued' LIMIT 1")
            .bind(task_id.to_string()).fetch_all(&state.db).await.map_err(db_error)?
    } else {
        sqlx::query("SELECT * FROM tasks WHERE state='queued' ORDER BY CASE WHEN sticky_worker_id=? THEN 0 WHEN sticky_worker_id IS NULL THEN 1 ELSE 2 END, priority DESC, created_at ASC LIMIT 100")
            .bind(&worker_id_text).fetch_all(&state.db).await.map_err(db_error)?
    };
    for row in rows {
        let sticky_worker_id: Option<String> = row.try_get("sticky_worker_id").map_err(internal)?;
        let task = task_from_row(&row)?;
        if !dependencies_satisfied(&state.db, &task).await? { continue; }
        let project_row = sqlx::query("SELECT * FROM projects WHERE id=? AND enabled=1").bind(task.project_id.to_string())
            .fetch_optional(&state.db).await.map_err(db_error)?;
        let Some(project_row) = project_row else { continue };
        let project = project_from_row(&project_row)?;
        if internal_actor == 0 {
            if let Some(sticky_worker_id) = sticky_worker_id.as_deref().filter(|sticky| *sticky != worker_id_text) {
                if sticky_worker_reservation_active(&state.db, sticky_worker_id, &project, &task).await? {
                    continue;
                }
                sqlx::query("UPDATE tasks SET sticky_worker_id=NULL,updated_at=? WHERE id=? AND state='queued' AND sticky_worker_id=?")
                    .bind(ts(Utc::now())).bind(task.id.to_string()).bind(sticky_worker_id)
                    .execute(&state.db).await.map_err(db_error)?;
            }
            if !worker_matches_task(&worker, &project, &task) { continue; }
        }
        let git_credential = git_credential_from_row(state, &project_row)?;

        let now = Utc::now();
        let lease_until = now + chrono::Duration::seconds(DEFAULT_LEASE_SECONDS);
        let attempt: i64 = sqlx::query_scalar("SELECT COALESCE(MAX(attempt),0)+1 FROM executions WHERE task_id=?")
            .bind(task.id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
        let execution = Execution { id: Uuid::new_v4(), task_id: task.id, worker_id: worker.id, attempt: attempt as u32,
            state: ExecutionState::Assigned, lease_until, started_at: None, finished_at: None, result: None };
        let (lease_capability, lease_capability_hash) = issue_lease_capability();
        crate::git_broker::prepare_task_repo(state, &project, task.id, execution.id, &git_credential).await?;
        let mut worker_project = project.clone();
        worker_project.repo_url = crate::git_broker::task_repo_url(state, execution.id)?;
        worker_project.git_auth = GitAuthConfig::default();

        if !persist_task_claim(state, &task, &worker, &execution, attempt, &lease_capability_hash, now).await? {
            crate::git_broker::remove_task_repo(state, execution.id).await?;
            continue;
        }
        let mut assigned_task = task; assigned_task.state = TaskState::Assigned; assigned_task.updated_at = now;
        return Ok(Some(Assignment { project: worker_project, task: assigned_task, execution, lease_capability }));
    }
    Ok(None)
}

async fn claim_review(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<Response, ApiError> {
    require_worker(&state.db, id, &headers).await?;
    match claim_review_for_worker(&state, id, None).await? {
        Some(assignment) => Ok(Json(assignment).into_response()),
        None => Ok(StatusCode::NO_CONTENT.into_response()),
    }
}

pub(crate) async fn claim_review_for_worker(state: &AppState, id: Uuid, task_id: Option<Uuid>) -> Result<Option<ReviewAssignment>, ApiError> {
    let worker_row = sqlx::query("SELECT * FROM workers WHERE id=?").bind(id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?
        .ok_or((StatusCode::NOT_FOUND, "worker not found".into()))?;
    let worker = worker_from_row(&worker_row)?;
    let internal_actor: i64 = worker_row.try_get("internal_actor").unwrap_or(0);
    if worker.role != AgentRole::Reviewer || worker.protocol_version < PROTOCOL_VERSION {
        return Ok(None);
    }
    if worker.running_slots >= worker.slots || !matches!(worker.state, WorkerState::Idle | WorkerState::Busy) {
        return Ok(None);
    }

    let settings = load_host_settings(&state.db).await?;
    let rows = if let Some(task_id) = task_id {
        sqlx::query("SELECT * FROM tasks WHERE id=? AND state='review' LIMIT 1")
            .bind(task_id.to_string()).fetch_all(&state.db).await.map_err(db_error)?
    } else {
        sqlx::query("SELECT * FROM tasks WHERE state='review' ORDER BY CASE WHEN (SELECT reviewer_worker_id FROM reviews r0 WHERE r0.task_id=tasks.id ORDER BY r0.created_at DESC LIMIT 1)=? THEN 0 ELSE 1 END, priority DESC, updated_at ASC LIMIT 100")
            .bind(worker.id.to_string()).fetch_all(&state.db).await.map_err(db_error)?
    };
    for row in rows {
        let task = task_from_row(&row)?;
        let project_row = sqlx::query("SELECT * FROM projects WHERE id=? AND enabled=1")
            .bind(task.project_id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?;
        let Some(project_row) = project_row else { continue };
        let project = project_from_row(&project_row)?;
        if internal_actor == 0 && !worker_can_run_project(&worker, &project) { continue; }
        if internal_actor == 0 && review_reserved_for_live_preferred_reviewer(&state.db, &task, &project, worker.id).await? { continue; }

        let execution_row = sqlx::query("SELECT * FROM executions WHERE task_id=? AND state='completed' ORDER BY attempt DESC LIMIT 1")
            .bind(task.id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?;
        let Some(execution_row) = execution_row else { continue };
        let mut execution = execution_from_row(&execution_row)?;
        if execution.worker_id == worker.id { continue; }
        let Some(mut result) = execution.result.clone() else { continue };
        let (Some(review_ref), Some(commit_sha)) = (result.review_ref.clone(), result.commit_sha.clone()) else { continue };

        let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state IN ('assigned','running')")
            .bind(task.id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
        if active > 0 { continue; }

        // Bound lost-review loops: expired (`lost`) leases count as reviewer
        // runtime failures for this implementation candidate. When
        // failed+lost reaches the configured limit, block instead of
        // allowing another automatic reclaim. History is preserved.
        let failed_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='failed'")
            .bind(task.id.to_string()).bind(execution.id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
        let lost_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='lost'")
            .bind(task.id.to_string()).bind(execution.id.to_string()).fetch_one(&state.db).await.map_err(db_error)?;
        if review_runtime_failures_exhausted(failed_count, lost_count, settings.review_failure_limit) {
            let feedback = review_runtime_blocked_feedback(failed_count, lost_count, settings.review_failure_limit, "No further automatic review reclaim.");
            sqlx::query("UPDATE tasks SET state='blocked',review_feedback=?,updated_at=? WHERE id=? AND state='review'")
                .bind(feedback).bind(ts(Utc::now())).bind(task.id.to_string()).execute(&state.db).await.map_err(db_error)?;
            continue;
        }

        // Runtime-only reviewer reclaims must keep the exact clean snapshot
        // from the failed/lost lease instead of silently changing the review
        // target when upstream moves. A fresh candidate/quality retry has no
        // such pinned failed/lost snapshot and is reconciled against current
        // upstream below.
        let prior_runtime_pins = sqlx::query("SELECT upstream_sha,integration_sha,effective_diff_hash FROM reviews WHERE task_id=? AND execution_id=? AND state IN ('failed','lost') AND upstream_sha IS NOT NULL AND integration_sha IS NOT NULL AND effective_diff_hash IS NOT NULL ORDER BY created_at DESC LIMIT 1")
            .bind(task.id.to_string()).bind(execution.id.to_string()).fetch_optional(&state.db).await.map_err(db_error)?;
        let reusable = prior_runtime_pins.and_then(|row| {
            let upstream_sha: Option<String> = row.try_get("upstream_sha").ok()?;
            let integration_sha: Option<String> = row.try_get("integration_sha").ok()?;
            let effective_diff_hash: Option<String> = row.try_get("effective_diff_hash").ok()?;
            let saved = result.integration.clone()?;
            (saved.conflict.is_none()
                && upstream_sha.as_deref() == Some(saved.upstream_sha.as_str())
                && integration_sha.as_deref() == saved.integration_sha.as_deref()
                && effective_diff_hash.as_deref() == saved.effective_diff_hash.as_deref()).then_some(saved)
        });
        // Reconcile every fresh review target against current upstream before
        // a reviewer spends a turn. A Git conflict is implementation work,
        // not a reviewer-quality retry, so no review row is created here.
        let integration = match reusable {
            Some(snapshot) => snapshot,
            None => crate::git_broker::prepare_integration_snapshot(state, &project, execution.id, &result).await?,
        };
        if let Some(conflict) = integration.conflict.as_ref() {
            result.integration = Some(integration.clone());
            execution.result = Some(result.clone());
            sqlx::query("UPDATE executions SET result=? WHERE id=? AND state='completed'")
                .bind(json(&result)?).bind(execution.id.to_string()).execute(&state.db).await.map_err(db_error)?;
            let feedback = format!(
                "{}

This is an upstream integration retry, not a new implementation or reviewer rejection. Preserve current upstream changes, preserve the original task intent, resolve only the integration conflict, then validate the task again. Current upstream HEAD is {}.",
                crate::git_broker::conflict_summary(conflict), conflict.upstream_sha
            );
            sqlx::query("UPDATE tasks SET state='queued',review_feedback=?,sticky_worker_id=?,updated_at=? WHERE id=? AND state='review'")
                .bind(feedback).bind(execution.worker_id.to_string()).bind(ts(Utc::now())).bind(task.id.to_string())
                .execute(&state.db).await.map_err(db_error)?;
            continue;
        }
        let integration_sha = integration.integration_sha.clone().ok_or((StatusCode::CONFLICT, "clean integration snapshot has no integrated commit".into()))?;
        let effective_diff_hash = integration.effective_diff_hash.clone().ok_or((StatusCode::CONFLICT, "clean integration snapshot has no effective diff hash".into()))?;

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

        // Only the claimant that wins the atomic review insert may publish
        // the clean integration snapshot into the execution envelope.
        result.integration = Some(integration.clone());
        execution.result = Some(result.clone());
        if !persist_review_claim(
            state,
            &task,
            &worker,
            &execution,
            &review,
            &lease_capability_hash,
            &result,
            &integration.upstream_sha,
            &integration_sha,
            &effective_diff_hash,
            now,
        ).await? {
            continue;
        }

        let review_repo_url = crate::git_broker::review_repo_url(state, review.id)?;
        let mut worker_project = project.clone();
        worker_project.repo_url = review_repo_url.clone();
        worker_project.git_auth = GitAuthConfig::default();
        let checkout = WorkerReviewCheckout {
            repo_url: review_repo_url,
            default_branch: project.default_branch.clone(),
            review_ref,
            commit_sha,
            base_sha: result.base_sha.clone(),
            upstream_sha: Some(integration.upstream_sha.clone()),
            integration_sha: Some(integration_sha),
        };
        return Ok(Some(ReviewAssignment {
            review,
            project: worker_project,
            task,
            execution,
            implementation_worker,
            checkout,
            lease_capability,
        }));
    }
    Ok(None)
}

async fn release_review(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    let capability = lease_capability_from_headers(&headers)?.to_string();
    release_review_for_capability(&state, id, &capability, Some(&headers)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn renew_review(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    let capability = lease_capability_from_headers(&headers)?.to_string();
    renew_review_for_capability(&state, id, &capability, Some(&headers)).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn renew_review_for_capability(state: &AppState, id: Uuid, capability: &str, worker_headers: Option<&HeaderMap>) -> Result<(), ApiError> {
    let now = Utc::now();
    let lease = now + chrono::Duration::seconds(DEFAULT_LEASE_SECONDS);
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let row = sqlx::query("SELECT task_id,execution_id,reviewer_worker_id,lease_capability_hash FROM reviews WHERE id=? AND state IN ('assigned','running') AND lease_until>=? AND lease_capability_hash IS NOT NULL")
        .bind(id.to_string()).bind(ts(now)).fetch_optional(&mut *tx).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "review is not active".into()))?;
    let task_id: String = row.try_get("task_id").map_err(internal)?;
    let execution_id: String = row.try_get("execution_id").map_err(internal)?;
    let reviewer_worker_id: String = row.try_get("reviewer_worker_id").map_err(internal)?;
    let capability_hash: String = row.try_get("lease_capability_hash").map_err(internal)?;
    if let Some(headers) = worker_headers { require_worker(&state.db, uuid(reviewer_worker_id.clone())?, headers).await?; }
    require_lease_capability_value(capability, &capability_hash)?;
    let current_state: Option<String> = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
        .bind(&task_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
    if current_state.as_deref() != Some("review") { return Err((StatusCode::CONFLICT, "task is no longer awaiting review".into())); }
    let latest_execution: Option<String> = sqlx::query_scalar("SELECT id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(&task_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
    if latest_execution.as_deref() != Some(execution_id.as_str()) { return Err((StatusCode::CONFLICT, "review targets a stale execution".into())); }
    let changed = sqlx::query("UPDATE reviews SET state='running',lease_until=?,started_at=COALESCE(started_at,?) WHERE id=? AND state IN ('assigned','running') AND lease_capability_hash=?")
        .bind(ts(lease)).bind(ts(now)).bind(id.to_string()).bind(&capability_hash).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
    if changed != 1 { return Err((StatusCode::CONFLICT, "review lease changed".into())); }
    tx.commit().await.map_err(db_error)?;
    Ok(())
}

async fn finish_review(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap, Json(input): Json<FinishReview>) -> Result<StatusCode, ApiError> {
    let capability = lease_capability_from_headers(&headers)?.to_string();
    finish_review_for_capability(&state, id, &capability, &input.status, input.verdict, input.error, Some(&headers)).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn finish_review_for_capability(state: &AppState, id: Uuid, capability: &str, status: &str, verdict: Option<ReviewVerdict>, error: Option<String>, worker_headers: Option<&HeaderMap>) -> Result<(), ApiError> {
    let settings = load_host_settings(&state.db).await?;
    let now = Utc::now();
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let row = sqlx::query("SELECT task_id,execution_id,reviewer_worker_id,lease_capability_hash FROM reviews WHERE id=? AND state IN ('assigned','running') AND lease_until>=? AND lease_capability_hash IS NOT NULL")
        .bind(id.to_string()).bind(ts(now)).fetch_optional(&mut *tx).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "review is not active".into()))?;
    let task_id: String = row.try_get("task_id").map_err(internal)?;
    let execution_id: String = row.try_get("execution_id").map_err(internal)?;
    let reviewer_worker_id: String = row.try_get("reviewer_worker_id").map_err(internal)?;
    let capability_hash: String = row.try_get("lease_capability_hash").map_err(internal)?;
    if let Some(headers) = worker_headers { require_worker(&state.db, uuid(reviewer_worker_id.clone())?, headers).await?; }
    require_lease_capability_value(capability, &capability_hash)?;

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
    if status == "failed" {
        let error = error.unwrap_or_else(|| "reviewer failed without an error message".into());
        let changed = sqlx::query("UPDATE reviews SET state='failed',finished_at=?,verdict=?,lease_capability_hash=NULL WHERE id=? AND state IN ('assigned','running') AND lease_capability_hash=?")
            .bind(ts(now)).bind(json(&serde_json::json!({"error": error}))?).bind(id.to_string()).bind(&capability_hash).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
        if changed != 1 { return Err((StatusCode::CONFLICT, "review lease changed".into())); }
        // Lost leases count as reviewer runtime/infrastructure failures for
        // the same implementation candidate: combine failed+lost rows when
        // enforcing review_failure_limit. Historical rows are preserved.
        let failed_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='failed'")
            .bind(&task_id).bind(&execution_id).fetch_one(&mut *tx).await.map_err(db_error)?;
        let lost_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='lost'")
            .bind(&task_id).bind(&execution_id).fetch_one(&mut *tx).await.map_err(db_error)?;
        if review_runtime_failures_exhausted(failed_count, lost_count, settings.review_failure_limit) {
            let feedback = review_runtime_blocked_feedback(failed_count, lost_count, settings.review_failure_limit, &format!("Last error: {error}"));
            let task_changed = sqlx::query("UPDATE tasks SET state='blocked',review_feedback=?,updated_at=? WHERE id=? AND state='review'")
                .bind(feedback).bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
            if task_changed != 1 { return Err((StatusCode::CONFLICT, "task review ownership changed".into())); }
        } else {
            let task_changed = sqlx::query("UPDATE tasks SET updated_at=? WHERE id=? AND state='review'")
                .bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
            if task_changed != 1 { return Err((StatusCode::CONFLICT, "task review ownership changed".into())); }
        }
    } else {
        let verdict = verdict.ok_or((StatusCode::BAD_REQUEST, "completed review requires a verdict".into()))?;
        let reason = verdict.reason.trim();
        if reason.is_empty() {
            return Err((StatusCode::BAD_REQUEST, "review verdict requires a reason".into()));
        }
        let changed = sqlx::query("UPDATE reviews SET state='completed',finished_at=?,verdict=?,lease_capability_hash=NULL WHERE id=? AND state IN ('assigned','running') AND lease_capability_hash=?")
            .bind(ts(now)).bind(json(&verdict)?).bind(id.to_string()).bind(&capability_hash).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
        if changed != 1 { return Err((StatusCode::CONFLICT, "review lease changed".into())); }
        match verdict.verdict {
            ReviewVerdictKind::Approve => {
                let task_changed = sqlx::query("UPDATE tasks SET state='merge_pending',updated_at=? WHERE id=? AND state='review'")
                    .bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
                if task_changed != 1 { return Err((StatusCode::CONFLICT, "task review ownership changed".into())); }
            }
            ReviewVerdictKind::Retry => {
                let implementation_worker_id: String = sqlx::query_scalar("SELECT worker_id FROM executions WHERE id=?")
                    .bind(&execution_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                // The per-cycle quality-retry limit counts only completed
                // reviewer `retry` verdicts stamped with the task's current
                // review cycle. Manual re-publish/retry starts a new cycle
                // and resets this count; automatic redispatch here stays in
                // the same cycle. Lifetime history is never consulted for
                // blocking. Runtime `failed` review rows are intentionally
                // excluded: they are gated separately by review_failure_limit
                // per implementation candidate below, never by this counter.
                let review_cycle: i64 = sqlx::query_scalar("SELECT review_cycle FROM tasks WHERE id=?")
                    .bind(&task_id).fetch_one(&mut *tx).await.map_err(db_error)?;
                let reviewer_retries: i64 = sqlx::query_scalar(
                    "SELECT COUNT(*) FROM reviews WHERE task_id=? AND review_cycle=? AND state='completed' AND (verdict LIKE '%\"verdict\":\"retry\"%' OR verdict LIKE '%\"verdict\": \"retry\"%')"
                )
                    .bind(&task_id).bind(review_cycle).fetch_one(&mut *tx).await.map_err(db_error)?;
                if review_retries_exhausted(reviewer_retries, settings.review_retry_limit) {
                    let feedback = format!(
                        "Reviewer requested implementation changes {reviewer_retries} times in the current review cycle; automatic redispatch stopped at loop limit {}. Last feedback: {reason}", settings.review_retry_limit
                    );
                    let task_changed = sqlx::query("UPDATE tasks SET state='blocked',review_feedback=?,sticky_worker_id=?,updated_at=? WHERE id=? AND state='review'")
                        .bind(feedback).bind(implementation_worker_id).bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
                    if task_changed != 1 { return Err((StatusCode::CONFLICT, "task review ownership changed".into())); }
                } else {
                    let task_changed = sqlx::query("UPDATE tasks SET state='queued',review_feedback=?,sticky_worker_id=?,updated_at=? WHERE id=? AND state='review'")
                        .bind(reason).bind(implementation_worker_id).bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
                    if task_changed != 1 { return Err((StatusCode::CONFLICT, "task review ownership changed".into())); }
                }
            }
        }
    }
    sqlx::query("UPDATE workers SET running_slots=MAX(running_slots-1,0),state=CASE WHEN state IN ('pending','draining','degraded') THEN state WHEN running_slots<=1 THEN 'idle' ELSE 'busy' END WHERE id=?")
        .bind(&reviewer_worker_id).execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(())
}

async fn release_execution(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    let capability = lease_capability_from_headers(&headers)?.to_string();
    release_execution_for_capability(&state, id, &capability, Some(&headers)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn renew_execution(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap) -> Result<StatusCode, ApiError> {
    let capability = lease_capability_from_headers(&headers)?.to_string();
    renew_execution_for_capability(&state, id, &capability, Some(&headers)).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn renew_execution_for_capability(state: &AppState, id: Uuid, capability: &str, worker_headers: Option<&HeaderMap>) -> Result<(), ApiError> {
    let now = Utc::now();
    let lease = now + chrono::Duration::seconds(DEFAULT_LEASE_SECONDS);
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let row = sqlx::query("SELECT task_id,worker_id,lease_capability_hash FROM executions WHERE id=? AND state IN ('assigned','running') AND lease_until>=? AND lease_capability_hash IS NOT NULL")
        .bind(id.to_string()).bind(ts(now)).fetch_optional(&mut *tx).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "execution is not active".into()))?;
    let task_id: String = row.try_get("task_id").map_err(internal)?;
    let worker_id: String = row.try_get("worker_id").map_err(internal)?;
    let capability_hash: String = row.try_get("lease_capability_hash").map_err(internal)?;
    if let Some(headers) = worker_headers { require_worker(&state.db, uuid(worker_id.clone())?, headers).await?; }
    require_lease_capability_value(capability, &capability_hash)?;
    if !is_latest_execution(&mut tx, &task_id, id).await? { return Err((StatusCode::CONFLICT, "stale execution".into())); }
    let changed = sqlx::query("UPDATE executions SET state='running',lease_until=?,started_at=COALESCE(started_at,?) WHERE id=? AND state IN ('assigned','running') AND lease_capability_hash=?")
        .bind(ts(lease)).bind(ts(now)).bind(id.to_string()).bind(&capability_hash).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
    if changed != 1 { return Err((StatusCode::CONFLICT, "execution lease changed".into())); }
    let task_changed = sqlx::query("UPDATE tasks SET state='running',updated_at=? WHERE id=? AND state IN ('assigned','running')")
        .bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
    if task_changed != 1 { return Err((StatusCode::CONFLICT, "task ownership changed".into())); }
    tx.commit().await.map_err(db_error)?;
    Ok(())
}

async fn finish_execution(Path(id): Path<Uuid>, State(state): State<Arc<AppState>>, headers: HeaderMap, Json(input): Json<FinishExecution>) -> Result<StatusCode, ApiError> {
    let capability = lease_capability_from_headers(&headers)?.to_string();
    finish_execution_for_capability(&state, id, &capability, input.result, Some(&headers)).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub(crate) async fn finish_execution_for_capability(state: &AppState, id: Uuid, capability: &str, result: ExecutionResult, worker_headers: Option<&HeaderMap>) -> Result<(), ApiError> {
    let now = Utc::now();
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let row = sqlx::query("SELECT task_id,worker_id,lease_capability_hash FROM executions WHERE id=? AND state IN ('assigned','running') AND lease_until>=? AND lease_capability_hash IS NOT NULL")
        .bind(id.to_string()).bind(ts(now)).fetch_optional(&mut *tx).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "execution is not active".into()))?;
    let task_id: String = row.try_get("task_id").map_err(internal)?;
    let worker_id: String = row.try_get("worker_id").map_err(internal)?;
    let capability_hash: String = row.try_get("lease_capability_hash").map_err(internal)?;
    if let Some(headers) = worker_headers { require_worker(&state.db, uuid(worker_id.clone())?, headers).await?; }
    require_lease_capability_value(capability, &capability_hash)?;
    if !is_latest_execution(&mut tx, &task_id, id).await? { return Err((StatusCode::CONFLICT, "stale execution".into())); }
    let success = result.status == "completed";
    let changed = sqlx::query("UPDATE executions SET state=?,finished_at=?,result=?,lease_capability_hash=NULL WHERE id=? AND state IN ('assigned','running') AND lease_capability_hash=?")
        .bind(if success { "completed" } else { "failed" }).bind(ts(now)).bind(json(&result)?).bind(id.to_string()).bind(&capability_hash)
        .execute(&mut *tx).await.map_err(db_error)?.rows_affected();
    if changed != 1 { return Err((StatusCode::CONFLICT, "execution lease changed".into())); }
    let task_changed = sqlx::query("UPDATE tasks SET state=?,sticky_worker_id=CASE WHEN ? THEN sticky_worker_id ELSE NULL END,updated_at=? WHERE id=? AND state IN ('assigned','running')")
        .bind(if success { "review" } else { "failed" }).bind(success).bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
    if task_changed != 1 { return Err((StatusCode::CONFLICT, "task ownership changed".into())); }
    sqlx::query("UPDATE workers SET running_slots=MAX(running_slots-1,0),state=CASE WHEN state IN ('pending','draining','degraded') THEN state WHEN running_slots<=1 THEN 'idle' ELSE 'busy' END WHERE id=?")
        .bind(&worker_id).execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkLeaseKind { Implementation, Review }

pub(crate) async fn release_execution_for_capability(state: &AppState, id: Uuid, capability: &str, worker_headers: Option<&HeaderMap>) -> Result<(), ApiError> {
    let now = Utc::now();
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let row = sqlx::query("SELECT task_id,worker_id,lease_capability_hash FROM executions WHERE id=? AND state IN ('assigned','running') AND lease_until>=? AND lease_capability_hash IS NOT NULL")
        .bind(id.to_string()).bind(ts(now)).fetch_optional(&mut *tx).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "execution is not active".into()))?;
    let task_id: String = row.try_get("task_id").map_err(internal)?;
    let worker_id: String = row.try_get("worker_id").map_err(internal)?;
    let capability_hash: String = row.try_get("lease_capability_hash").map_err(internal)?;
    if let Some(headers) = worker_headers { require_worker(&state.db, uuid(worker_id.clone())?, headers).await?; }
    require_lease_capability_value(capability, &capability_hash)?;
    if !is_latest_execution(&mut tx, &task_id, id).await? { return Err((StatusCode::CONFLICT, "stale execution".into())); }
    let task_state: Option<String> = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
        .bind(&task_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
    if !matches!(task_state.as_deref(), Some("assigned") | Some("running")) { return Err((StatusCode::CONFLICT, "task is no longer owned by this execution".into())); }
    let changed = sqlx::query("UPDATE executions SET state='cancelled',finished_at=?,lease_capability_hash=NULL WHERE id=? AND state IN ('assigned','running') AND lease_capability_hash=?")
        .bind(ts(now)).bind(id.to_string()).bind(&capability_hash).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
    if changed != 1 { return Err((StatusCode::CONFLICT, "execution lease changed".into())); }
    let task_changed = sqlx::query("UPDATE tasks SET state='queued',sticky_worker_id=NULL,updated_at=? WHERE id=? AND state IN ('assigned','running')")
        .bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
    if task_changed != 1 { return Err((StatusCode::CONFLICT, "task ownership changed".into())); }
    sqlx::query("UPDATE workers SET running_slots=MAX(running_slots-1,0),state=CASE WHEN state IN ('pending','draining','degraded') THEN state WHEN running_slots<=1 THEN 'idle' ELSE 'busy' END WHERE id=?")
        .bind(&worker_id).execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    if let Err((_, message)) = crate::git_broker::remove_task_repo(state, id).await {
        warn!(execution_id=%id, error=%message, "released execution repo cleanup failed");
    }
    Ok(())
}

pub(crate) async fn release_review_for_capability(state: &AppState, id: Uuid, capability: &str, worker_headers: Option<&HeaderMap>) -> Result<(), ApiError> {
    let now = Utc::now();
    let mut tx = state.db.begin().await.map_err(db_error)?;
    let row = sqlx::query("SELECT task_id,execution_id,reviewer_worker_id,lease_capability_hash FROM reviews WHERE id=? AND state IN ('assigned','running') AND lease_until>=? AND lease_capability_hash IS NOT NULL")
        .bind(id.to_string()).bind(ts(now)).fetch_optional(&mut *tx).await.map_err(db_error)?
        .ok_or((StatusCode::CONFLICT, "review is not active".into()))?;
    let task_id: String = row.try_get("task_id").map_err(internal)?;
    let execution_id: String = row.try_get("execution_id").map_err(internal)?;
    let reviewer_worker_id: String = row.try_get("reviewer_worker_id").map_err(internal)?;
    let capability_hash: String = row.try_get("lease_capability_hash").map_err(internal)?;
    if let Some(headers) = worker_headers { require_worker(&state.db, uuid(reviewer_worker_id.clone())?, headers).await?; }
    require_lease_capability_value(capability, &capability_hash)?;
    let current_state: Option<String> = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
        .bind(&task_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
    if current_state.as_deref() != Some("review") { return Err((StatusCode::CONFLICT, "task is no longer awaiting review".into())); }
    let latest_execution: Option<String> = sqlx::query_scalar("SELECT id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
        .bind(&task_id).fetch_optional(&mut *tx).await.map_err(db_error)?;
    if latest_execution.as_deref() != Some(execution_id.as_str()) { return Err((StatusCode::CONFLICT, "review targets a stale execution".into())); }
    let changed = sqlx::query("UPDATE reviews SET state='cancelled',finished_at=?,lease_capability_hash=NULL WHERE id=? AND state IN ('assigned','running') AND lease_capability_hash=?")
        .bind(ts(now)).bind(id.to_string()).bind(&capability_hash).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
    if changed != 1 { return Err((StatusCode::CONFLICT, "review lease changed".into())); }
    let task_changed = sqlx::query("UPDATE tasks SET updated_at=? WHERE id=? AND state='review'")
        .bind(ts(now)).bind(&task_id).execute(&mut *tx).await.map_err(db_error)?.rows_affected();
    if task_changed != 1 { return Err((StatusCode::CONFLICT, "task review ownership changed".into())); }
    sqlx::query("UPDATE workers SET running_slots=MAX(running_slots-1,0),state=CASE WHEN state IN ('pending','draining','degraded') THEN state WHEN running_slots<=1 THEN 'idle' ELSE 'busy' END WHERE id=?")
        .bind(&reviewer_worker_id).execute(&mut *tx).await.map_err(db_error)?;
    tx.commit().await.map_err(db_error)?;
    Ok(())
}

fn issue_lease_capability() -> (String, String) {
    let capability = format!("ltc_{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let hash = hash_secret(&capability);
    (capability, hash)
}

fn lease_capability_from_headers(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(LEASE_CAPABILITY_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "lease capability required".into()))
}

fn require_lease_capability_value(supplied: &str, stored_hash: &str) -> Result<(), ApiError> {
    if !secure_hash_eq(&hash_secret(supplied), stored_hash) {
        return Err((StatusCode::UNAUTHORIZED, "lease capability rejected".into()));
    }
    Ok(())
}

pub(crate) fn require_lease_capability(headers: &HeaderMap, stored_hash: &str) -> Result<(), ApiError> {
    require_lease_capability_value(lease_capability_from_headers(headers)?, stored_hash)
}

pub(crate) async fn require_worker(db: &SqlitePool, worker_id: Uuid, headers: &HeaderMap) -> Result<(), ApiError> {
    let supplied = headers
        .get(WORKER_CREDENTIAL_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or((StatusCode::UNAUTHORIZED, "worker credential required".into()))?;
    let stored: Option<String> = sqlx::query_scalar("SELECT credential_hash FROM workers WHERE id=? AND retired_at IS NULL")
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
    let internal_actor: i64 = row.try_get("internal_actor").unwrap_or(0);
    if internal_actor != 0 { return Ok(false); }
    let preferred = worker_from_row(&row)?;
    let fresh_after = Utc::now() - chrono::Duration::seconds(45);
    Ok(preferred.role == AgentRole::Worker
        && preferred.protocol_version >= PROTOCOL_VERSION
        && matches!(preferred.state, WorkerState::Idle | WorkerState::Busy)
        && preferred.last_heartbeat_at >= fresh_after
        && session_affinity_fresh(task.updated_at)
        && worker_matches_task(&preferred, project, task))
}

async fn review_reserved_for_live_preferred_reviewer(
    db: &SqlitePool,
    task: &Task,
    project: &Project,
    claimant_id: Uuid,
) -> Result<bool, ApiError> {
    let preferred_id: Option<String> = sqlx::query_scalar(
        "SELECT reviewer_worker_id FROM reviews WHERE task_id=? ORDER BY created_at DESC LIMIT 1",
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
    let internal_actor: i64 = row.try_get("internal_actor").unwrap_or(0);
    if internal_actor != 0 { return Ok(false); }
    let preferred = worker_from_row(&row)?;
    let fresh_after = Utc::now() - chrono::Duration::seconds(45);
    let live = preferred.role == AgentRole::Reviewer
        && preferred.protocol_version >= PROTOCOL_VERSION
        && matches!(preferred.state, WorkerState::Idle | WorkerState::Busy)
        && preferred.last_heartbeat_at >= fresh_after
        && session_affinity_fresh(task.updated_at)
        && worker_can_run_project(&preferred, project);
    Ok(live)
}

fn session_affinity_seconds() -> i64 {
    std::env::var("LAZYTEAM_SESSION_AFFINITY_SECS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(DEFAULT_SESSION_AFFINITY_SECONDS)
        .clamp(60, 24 * 60 * 60)
}

fn session_affinity_fresh(since: DateTime<Utc>) -> bool {
    since >= Utc::now() - chrono::Duration::seconds(session_affinity_seconds())
}

async fn dependencies_satisfied(db: &SqlitePool, task: &Task) -> Result<bool, ApiError> {
    for dep in &task.dependencies {
        let state: Option<String> = sqlx::query_scalar("SELECT state FROM tasks WHERE id=? AND project_id=?")
            .bind(dep.to_string()).bind(task.project_id.to_string()).fetch_optional(db).await.map_err(db_error)?;
        if state.as_deref() != Some("done") { return Ok(false); }
    }
    Ok(true)
}

/// Pending (not `done`) dependencies in task order, via batched indexed
/// lookups. Exact over the full dependency list — never capped at a display
/// window — so the waiting detail stays accurate no matter how far down
/// the unresolved dependency sits. Read-only.
async fn pending_dependencies(db: &SqlitePool, task: &Task) -> Result<Vec<Uuid>, ApiError> {
    let mut done: HashSet<String> = HashSet::new();
    for chunk in task.dependencies.chunks(500) {
        if chunk.is_empty() { continue; }
        let placeholders = chunk.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!("SELECT id FROM tasks WHERE project_id=? AND state='done' AND id IN ({placeholders})");
        let mut query = sqlx::query(&sql).bind(task.project_id.to_string());
        for dep in chunk { query = query.bind(dep.to_string()); }
        let rows = query.fetch_all(db).await.map_err(db_error)?;
        for row in rows { done.insert(row.try_get("id").map_err(internal)?); }
    }
    Ok(task.dependencies.iter().filter(|dep| !done.contains(&dep.to_string())).copied().collect())
}

fn short_id(id: &str) -> String { id.chars().take(8).collect() }

/// Diagnostic worker universe, equivalent to the claimant universe.
///
/// Only rows that can actually satisfy `require_worker` are included:
/// retired workers and rows with no `credential_hash` (never-enrolled or
/// retired workers whose credential was cleared) are excluded, since the
/// claim endpoints reject them before any scheduler predicate runs. The
/// full fleet is loaded in deterministic `id` order with no `LIMIT`, so a
/// large fleet can never silently omit a free eligible worker and produce
/// a false `no_eligible_worker` / `no_free_slot` / backend reason. Fleets
/// are small (one row per worker); this is a single indexed scan per
/// board/status/history request, shared across all waiting tasks in it.
async fn load_diagnostic_workers(db: &SqlitePool) -> Result<Vec<Worker>, ApiError> {
    let rows = sqlx::query("SELECT * FROM workers WHERE retired_at IS NULL AND credential_hash IS NOT NULL ORDER BY id")
        .fetch_all(db).await.map_err(db_error)?;
    rows.iter().map(worker_from_row).collect::<Result<Vec<_>, _>>()
}

/// Preloaded per-request diagnostic context. The worker fleet, project map,
/// and reviewer failure limit are each read once per board/status/history
/// request and shared across every waiting task in it, so per-task work
/// stays a bounded handful of indexed lookups (dependency states, sticky
/// id, review counts) instead of a fresh fleet scan per row.
pub(crate) struct DiagContext {
    workers: Vec<Worker>,
    projects: HashMap<Uuid, Project>,
    review_failure_limit: i64,
}

pub(crate) async fn load_diag_context(db: &SqlitePool) -> Result<DiagContext, ApiError> {
    let workers = load_diagnostic_workers(db).await?;
    let project_rows = sqlx::query("SELECT * FROM projects").fetch_all(db).await.map_err(db_error)?;
    let mut projects = HashMap::new();
    for row in &project_rows {
        let project = project_from_row(row)?;
        projects.insert(project.id, project);
    }
    let review_failure_limit: i64 = sqlx::query_scalar("SELECT review_failure_limit FROM host_settings WHERE id=1")
        .fetch_optional(db).await.map_err(db_error)?.flatten().unwrap_or(DEFAULT_REVIEW_FAILURE_LIMIT);
    Ok(DiagContext { workers, projects, review_failure_limit })
}

fn backend_unavailable_detail(worker: &Worker) -> String {
    match (&worker.agent.provider, &worker.agent.model) {
        (Some(provider), Some(model)) => format!(
            "worker {} Host provider '{provider}' model '{model}' unavailable in Pi catalog",
            worker.name),
        _ => format!("worker {} has no Host provider/model selection", worker.name),
    }
}

/// Primary waiting reason for a `queued` implementation task, derived from
/// the same predicates as `claim_task`: dependencies, sticky reservation,
/// role/protocol, tags/project scope (`worker_tags_scope_match` /
/// `tag_mismatches`), Host backend availability (`can_claim_work`), and
/// slot/state (`worker_matches_task`). Read-only: never clears a stale
/// sticky reservation the way the claim path does.
async fn queued_waiting_info(
    db: &SqlitePool,
    ctx: &DiagContext,
    task: &Task,
    project: &Project,
    sticky_worker_id: Option<&str>,
) -> Result<Option<WaitingInfo>, ApiError> {
    if !dependencies_satisfied(db, task).await? {
        let pending = pending_dependencies(db, task).await?;
        let detail = match pending.len() {
            // Dep completed between the predicate and the detail lookup;
            // stay concise rather than emitting an empty sample.
            0 => "waiting on dependencies".into(),
            1 => format!("waiting on dependency {}", short_id(&pending[0].to_string())),
            n => format!("waiting on {n} dependencies (e.g. {})", short_id(&pending[0].to_string())),
        };
        return Ok(Some(waiting("blocked_dependencies", detail)));
    }
    if let Some(sticky) = sticky_worker_id {
        // Mirror `claim_task` exactly: another worker is refused when the
        // sticky reservation predicate holds, with no additional gates.
        // (Read-only: unlike the claim path, this never clears a stale
        // reservation.)
        if sticky_worker_reservation_active(db, sticky, project, task).await? {
            let name: Option<String> = sqlx::query_scalar("SELECT name FROM workers WHERE id=?")
                .bind(sticky).fetch_optional(db).await.map_err(db_error)?;
            let detail = match name {
                Some(name) => format!("reserved for worker {name} by recent retry affinity"),
                None => "reserved for previous worker by recent retry affinity".into(),
            };
            return Ok(Some(waiting("sticky_reserved", detail)));
        }
    }
    let workers = &ctx.workers;
    let live: Vec<&Worker> = workers.iter()
        .filter(|w| w.role == AgentRole::Worker && w.protocol_version >= PROTOCOL_VERSION
            && matches!(w.state, WorkerState::Idle | WorkerState::Busy))
        .collect();
    if live.is_empty() {
        return Ok(Some(waiting("no_eligible_worker",
            "no worker with role worker, current protocol, and idle/busy state".into())));
    }
    let scoped: Vec<&Worker> = live.iter()
        .filter(|w| worker_tags_scope_match(w, project, task))
        .copied()
        .collect();
    if scoped.is_empty() {
        let mut scope_excluded = 0;
        let mut tag_excluded = 0;
        for worker in &live {
            if !worker_can_run_project(worker, project) { scope_excluded += 1; }
            else { tag_excluded += 1; }
        }
        let mut sample = String::new();
        for worker in live.iter() {
            if !worker_tags_scope_match(worker, project, task) {
                let mismatches = tag_mismatches(worker, project, task);
                if let Some((key, wanted)) = mismatches.first() {
                    sample = format!("e.g. worker {} needs {key}={wanted}", worker.name);
                    break;
                }
                if !worker_can_run_project(worker, project) {
                    sample = format!("e.g. worker {} not scoped to project {}", worker.name, project.slug);
                    break;
                }
            }
        }
        let mut detail = format!("{scope_excluded} excluded by project scope, {tag_excluded} by required tags");
        if !sample.is_empty() { detail = format!("{detail}; {sample}"); }
        return Ok(Some(waiting("no_eligible_worker", detail)));
    }
    let backend_ready: Vec<&Worker> = scoped.iter()
        .filter(|w| can_claim_work(&w.agent, &w.agent_capabilities))
        .copied()
        .collect();
    if backend_ready.is_empty() {
        let mut unselected = 0;
        for worker in &scoped {
            if !host_agent_selection_ready(&worker.agent) { unselected += 1; }
        }
        let unavailable = scoped.len() - unselected;
        let mut detail = if unselected > 0 && unavailable > 0 {
            format!("{unselected} without Host provider/model selection, {unavailable} with selection unavailable in Pi catalog")
        } else if unselected > 0 {
            format!("{unselected} eligible workers without Host provider/model selection")
        } else {
            format!("{} eligible workers with Host selection unavailable in Pi catalog", unavailable.max(1))
        };
        if let Some(first) = scoped.first() {
            // Names the provider/model only; never keys, tokens, or auth state.
            if host_agent_selection_ready(&first.agent) {
                if let (Some(provider), Some(model)) = (&first.agent.provider, &first.agent.model) {
                    detail = format!("{detail}; e.g. provider '{provider}' model '{model}'");
                }
            }
        }
        return Ok(Some(waiting("backend_unavailable", detail)));
    }
    let free: Vec<&Worker> = backend_ready.iter()
        .filter(|w| w.running_slots < w.slots && worker_matches_task(w, project, task))
        .copied()
        .collect();
    if free.is_empty() {
        return Ok(Some(waiting("no_free_slot",
            format!("{} eligible workers with backend ready, all at capacity", backend_ready.len()))));
    }
    Ok(Some(waiting("awaiting_claim",
        format!("eligible worker {} has a free slot; waiting for claim poll", free[0].name))))
}

/// Primary waiting reason for a `review` task, mirroring the exact check
/// order of `claim_review`: reviewer affinity reservation (same predicate,
/// nil claimant), candidate readiness, reviewer scope/self-review exclusion,
/// active lease, reviewer runtime-failure budget
/// (`review_runtime_failures_exhausted`), then Host backend availability and
/// reviewer slot capacity. Read-only.
#[allow(clippy::too_many_arguments)]
async fn review_waiting_info(
    db: &SqlitePool,
    ctx: &DiagContext,
    task: &Task,
    project: &Project,
) -> Result<Option<WaitingInfo>, ApiError> {
    let review_failure_limit = ctx.review_failure_limit;
    // Reservation first, exactly as `claim_review` refuses a non-preferred
    // claimant before looking at the candidate, lease, or failure budget.
    // No additional gates: a live preferred reviewer reserves the task even
    // when full or backend-unready, and even at the failure limit.
    let reserved = review_reserved_for_live_preferred_reviewer(db, task, project, Uuid::nil()).await?;
    if reserved {
        let preferred_id: Option<String> = sqlx::query_scalar(
            "SELECT reviewer_worker_id FROM reviews WHERE task_id=? ORDER BY created_at DESC LIMIT 1")
            .bind(task.id.to_string()).fetch_optional(db).await.map_err(db_error)?;
        let name: Option<String> = match preferred_id {
            Some(id) => sqlx::query_scalar("SELECT name FROM workers WHERE id=?")
                .bind(id).fetch_optional(db).await.map_err(db_error)?,
            None => None,
        };
        let detail = match name {
            Some(name) => format!("reserved for reviewer {name} by recent review affinity"),
            None => "reserved for previous reviewer by recent review affinity".into(),
        };
        return Ok(Some(waiting("reviewer_reserved", detail)));
    }
    let execution_row = sqlx::query("SELECT * FROM executions WHERE task_id=? AND state='completed' ORDER BY attempt DESC LIMIT 1")
        .bind(task.id.to_string()).fetch_optional(db).await.map_err(db_error)?;
    let Some(execution_row) = execution_row else {
        return Ok(Some(waiting("candidate_not_ready", "no completed implementation candidate to review".into())));
    };
    let execution = execution_from_row(&execution_row)?;
    let has_candidate = execution.result.as_ref().is_some_and(|result|
        result.review_ref.is_some() && result.commit_sha.is_some());
    if !has_candidate {
        return Ok(Some(waiting("candidate_not_ready", "latest implementation has no reviewable candidate".into())));
    }
    // Scope and self-review exclusion precede the lease and failure-budget
    // checks, exactly as `claim_review` skips out-of-scope and self-review
    // claimants before consulting them: when no reviewer remains eligible,
    // the reason is eligibility even when a lease is active or the budget
    // is exhausted (e.g. the implementation worker reassigned to reviewer
    // is refused for self-review, never for the budget).
    let workers = &ctx.workers;
    let live: Vec<&Worker> = workers.iter()
        .filter(|w| w.role == AgentRole::Reviewer && w.protocol_version >= PROTOCOL_VERSION
            && matches!(w.state, WorkerState::Idle | WorkerState::Busy))
        .collect();
    if live.is_empty() {
        return Ok(Some(waiting("no_eligible_reviewer",
            "no reviewer with current protocol and idle/busy state".into())));
    }
    let scoped: Vec<&Worker> = live.iter()
        .filter(|w| worker_can_run_project(w, project) && w.id != execution.worker_id)
        .copied()
        .collect();
    if scoped.is_empty() {
        let self_only = live.iter().all(|w| !worker_can_run_project(w, project) || w.id == execution.worker_id);
        let detail = if live.iter().any(|w| w.id == execution.worker_id)
            && live.iter().filter(|w| worker_can_run_project(w, project)).count() <= 1 && self_only {
            "only available reviewer is the implementation worker (self-review is not allowed)".into()
        } else {
            format!("{} reviewers excluded by project scope or self-review rule", live.len())
        };
        return Ok(Some(waiting("no_eligible_reviewer", detail)));
    }
    let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state IN ('assigned','running')")
        .bind(task.id.to_string()).fetch_one(db).await.map_err(db_error)?;
    if active > 0 {
        return Ok(Some(waiting("review_lease_active", "a reviewer lease is already active".into())));
    }
    let failed_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='failed'")
        .bind(task.id.to_string()).bind(execution.id.to_string()).fetch_one(db).await.map_err(db_error)?;
    let lost_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='lost'")
        .bind(task.id.to_string()).bind(execution.id.to_string()).fetch_one(db).await.map_err(db_error)?;
    if review_runtime_failures_exhausted(failed_count, lost_count, review_failure_limit) {
        return Ok(Some(waiting("review_failure_limit", format!(
            "reviewer runtime failed {} times ({failed_count} failed, {lost_count} lost); automatic reclaim stopped at limit {review_failure_limit}",
            failed_count + lost_count))));
    }
    let backend_ready: Vec<&Worker> = scoped.iter()
        .filter(|w| can_claim_work(&w.agent, &w.agent_capabilities))
        .copied()
        .collect();
    if backend_ready.is_empty() {
        let detail = backend_unavailable_detail(scoped[0]);
        return Ok(Some(waiting("review_backend_unavailable", detail)));
    }
    let free = backend_ready.iter().filter(|w| w.running_slots < w.slots).count();
    if free == 0 {
        return Ok(Some(waiting("reviewer_no_capacity",
            format!("{} eligible reviewers with backend ready, all at capacity", backend_ready.len()))));
    }
    Ok(Some(waiting("awaiting_claim",
        format!("eligible reviewer {} has a free slot; waiting for claim poll", backend_ready[0].name))))
}

/// Dispatcher for waiting diagnostics. Returns `None` for states that are
/// actively progressing so those cards are never spammed. Takes the shared
/// per-request [`DiagContext`] so board requests scan the fleet, projects,
/// and settings once no matter how many waiting tasks they render.
pub(crate) async fn waiting_for_task_with_ctx(db: &SqlitePool, ctx: &DiagContext, task: &Task) -> Result<Option<WaitingInfo>, ApiError> {
    match task.state {
        TaskState::Queued => {
            let Some(project) = ctx.projects.get(&task.project_id) else {
                return Ok(Some(waiting("no_eligible_worker", "project is missing".into())));
            };
            if !project.enabled {
                return Ok(Some(waiting("no_eligible_worker",
                    format!("project {} is disabled", project.slug))));
            }
            let sticky: Option<String> = sqlx::query_scalar("SELECT sticky_worker_id FROM tasks WHERE id=?")
                .bind(task.id.to_string()).fetch_optional(db).await.map_err(db_error)?.flatten();
            queued_waiting_info(db, ctx, task, project, sticky.as_deref()).await
        }
        TaskState::Review => {
            let Some(project) = ctx.projects.get(&task.project_id) else {
                return Ok(Some(waiting("no_eligible_reviewer", "project is missing".into())));
            };
            if !project.enabled {
                return Ok(Some(waiting("no_eligible_reviewer",
                    format!("project {} is disabled", project.slug))));
            }
            review_waiting_info(db, ctx, task, project).await
        }
        _ => Ok(None),
    }
}

/// Single-task convenience wrapper that loads a fresh [`DiagContext`].
/// Board requests should prefer [`waiting_for_task_with_ctx`] with one
/// shared context per request.
pub(crate) async fn waiting_for_task(db: &SqlitePool, task: &Task) -> Result<Option<WaitingInfo>, ApiError> {
    let ctx = load_diag_context(db).await?;
    waiting_for_task_with_ctx(db, &ctx, task).await
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

pub(crate) async fn reap_once(db: &SqlitePool) -> anyhow::Result<()> {
    let now = ts(Utc::now());
    // Reviewer runtime-failure budget for expired leases. Falls back to the
    // compiled default when host_settings is absent (fresh memory DBs).
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

    let review_failure_limit: i64 = sqlx::query_scalar("SELECT review_failure_limit FROM host_settings WHERE id=1")
        .fetch_optional(db).await?.flatten().unwrap_or(DEFAULT_REVIEW_FAILURE_LIMIT);
    let expired_reviews = sqlx::query("SELECT id,task_id,execution_id,reviewer_worker_id FROM reviews WHERE state IN ('assigned','running') AND lease_until < ?")
        .bind(&now).fetch_all(db).await?;
    for row in expired_reviews {
        let id: String = row.try_get("id")?;
        let task_id: String = row.try_get("task_id")?;
        let execution_id: String = row.try_get("execution_id")?;
        let reviewer_worker_id: String = row.try_get("reviewer_worker_id")?;
        let mut tx = db.begin().await?;
        let changed = sqlx::query("UPDATE reviews SET state='lost',finished_at=?,lease_capability_hash=NULL WHERE id=? AND state IN ('assigned','running')")
            .bind(&now).bind(&id).execute(&mut *tx).await?.rows_affected();
        if changed > 0 {
            // Expired/lost reviewer attempts are bounded as reviewer runtime
            // failures for the same (latest) implementation candidate. Below
            // the limit the task stays in review for another claim; at the
            // limit it becomes blocked with explicit failed/lost counts.
            // A stale expired review for an old candidate never blocks the
            // task: only the latest execution's budget can gate reclaim.
            // Historical review rows are preserved; only task state changes.
            let latest: Option<String> = sqlx::query_scalar("SELECT id FROM executions WHERE task_id=? ORDER BY attempt DESC LIMIT 1")
                .bind(&task_id).fetch_optional(&mut *tx).await?;
            if latest.as_deref() != Some(execution_id.as_str()) {
                sqlx::query("UPDATE tasks SET updated_at=? WHERE id=? AND state='review'")
                    .bind(&now).bind(&task_id).execute(&mut *tx).await?;
            } else {
                let failed_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='failed'")
                    .bind(&task_id).bind(&execution_id).fetch_optional(&mut *tx).await?.unwrap_or(0);
                let lost_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='lost'")
                    .bind(&task_id).bind(&execution_id).fetch_optional(&mut *tx).await?.unwrap_or(0);
                if failed_count + lost_count >= review_failure_limit {
                    let total = failed_count + lost_count;
                    let feedback = format!(
                        "Reviewer runtime failed {total} times ({failed_count} failed, {lost_count} lost) for this implementation; automatic review retries stopped at limit {review_failure_limit}. Last lease expired without a verdict.",
                    );
                    sqlx::query("UPDATE tasks SET state='blocked',review_feedback=?,updated_at=? WHERE id=? AND state='review'")
                        .bind(feedback).bind(&now).bind(&task_id).execute(&mut *tx).await?;
                } else {
                    sqlx::query("UPDATE tasks SET updated_at=? WHERE id=? AND state='review'")
                        .bind(&now).bind(&task_id).execute(&mut *tx).await?;
                }
            }
            sqlx::query("UPDATE workers SET running_slots=MAX(running_slots-1,0),state=CASE WHEN state IN ('pending','draining','degraded') THEN state WHEN running_slots<=1 THEN 'idle' ELSE 'busy' END WHERE id=?")
                .bind(&reviewer_worker_id).execute(&mut *tx).await?;
        }
        tx.commit().await?;
    }
    Ok(())
}

fn git_auth_mode_str(mode: &GitAuthMode) -> &'static str {
    match mode {
        GitAuthMode::Host => "host",
        GitAuthMode::SshKey => "ssh_key",
        GitAuthMode::HttpsBasic => "https_basic",
    }
}

fn git_auth_mode(value: &str) -> Result<GitAuthMode, ApiError> {
    match value {
        "host" => Ok(GitAuthMode::Host),
        // Legacy migration default wrote `worker` for Host-mode projects;
        // treat it as Host so read-only diagnostics never fail on old rows.
        "worker" => Ok(GitAuthMode::Host),
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
        credential_revision: row.try_get("git_auth_revision").map_err(internal)?,
    })
}

fn git_auth_summary(stored: &StoredGitAuth) -> GitAuthConfig {
    GitAuthConfig {
        mode: stored.mode.clone(),
        credential_configured: stored.encrypted_secret.is_some(),
        username: stored.username.clone(),
        credential_revision: stored.credential_revision.clone(),
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
        GitAuthMode::Host => {
            if nonempty_secret(input.secret).is_some() {
                return Err((StatusCode::BAD_REQUEST, "host Git auth must not include a server-side secret".into()));
            }
            Ok(StoredGitAuth { mode: GitAuthMode::Host, username: None, encrypted_secret: None, credential_revision: None })
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
                credential_revision: Some(Uuid::new_v4().to_string()),
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
                credential_revision: Some(Uuid::new_v4().to_string()),
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
        GitAuthMode::Host => Ok(StoredGitAuth {
            mode: GitAuthMode::Host,
            username: None,
            encrypted_secret: None,
            credential_revision: None,
        }),
        GitAuthMode::SshKey => {
            let (encrypted_secret, credential_revision) = match nonempty_secret(input.secret) {
                Some(secret) => (
                    Some(encrypt_git_secret(state, &secret)?),
                    Some(Uuid::new_v4().to_string()),
                ),
                None if current.mode == GitAuthMode::SshKey && current.encrypted_secret.is_some() => {
                    (current.encrypted_secret, current.credential_revision)
                }
                None => return Err((StatusCode::BAD_REQUEST, "switching to SSH key mode requires a private key".into())),
            };
            Ok(StoredGitAuth {
                mode: GitAuthMode::SshKey,
                username: None,
                encrypted_secret,
                credential_revision,
            })
        }
        GitAuthMode::HttpsBasic => {
            let username = input
                .username
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .or_else(|| (current.mode == GitAuthMode::HttpsBasic).then(|| current.username.clone()).flatten())
                .ok_or((StatusCode::BAD_REQUEST, "HTTPS username + password/token mode requires a username".into()))?;
            let (encrypted_secret, credential_revision) = match nonempty_secret(input.secret) {
                Some(secret) => (
                    Some(encrypt_git_secret(state, &secret)?),
                    Some(Uuid::new_v4().to_string()),
                ),
                None if current.mode == GitAuthMode::HttpsBasic && current.encrypted_secret.is_some() => {
                    (current.encrypted_secret, current.credential_revision)
                }
                None => return Err((StatusCode::BAD_REQUEST, "switching to HTTPS auth requires a password or token".into())),
            };
            Ok(StoredGitAuth {
                mode: GitAuthMode::HttpsBasic,
                username: Some(username),
                encrypted_secret,
                credential_revision,
            })
        }
    }
}

pub(crate) fn git_credential_from_row(state: &AppState, row: &sqlx::sqlite::SqliteRow) -> Result<GitCredential, ApiError> {
    let stored = stored_git_auth_from_row(row)?;
    match stored.mode {
        GitAuthMode::Host => Ok(GitCredential::Host),
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
        git_auth: git_auth_summary(&stored_git_auth_from_row(row)?),
        enabled: row.try_get::<i64,_>("enabled").map_err(internal)? != 0, created_at: datetime(row.try_get("created_at").map_err(internal)?)?,
        updated_at: datetime(row.try_get("updated_at").map_err(internal)?)?,
    })
}

fn worker_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Worker, ApiError> {
    let state: String = row.try_get("state").map_err(internal)?;
    let initial_prompt: String = row.try_get("initial_prompt").map_err(internal)?;
    let role = agent_role(row.try_get("role").map_err(internal)?)?;
    let initial_prompt = resolved_initial_prompt(&role, initial_prompt);
    let capabilities_raw: String = row.try_get("agent_capabilities").map_err(internal)?;
    let capabilities = serde_json::from_str::<AgentCapabilities>(&capabilities_raw).unwrap_or_default();
    let os: String = row.try_get("os").map_err(internal)?;
    let arch: String = row.try_get("arch").map_err(internal)?;
    let user_tags: Tags = dejson(row.try_get("tags").map_err(internal)?)?;
    let managed_capabilities: BTreeSet<String> = dejson(row.try_get("managed_capabilities").map_err(internal)?)?;
    let installed_capabilities: BTreeSet<String> = dejson(row.try_get("installed_capabilities").map_err(internal)?)?;
    let tags = effective_worker_tags(&os, &arch, &user_tags, &managed_capabilities, &installed_capabilities);
    Ok(Worker { id: uuid(row.try_get("id").map_err(internal)?)?, name: row.try_get("name").map_err(internal)?,
        role,
        state: match state.as_str() { "busy" => WorkerState::Busy, "pending" => WorkerState::Pending, "draining" => WorkerState::Draining, "degraded" => WorkerState::Degraded, "offline" => WorkerState::Offline, _ => WorkerState::Idle },
        os, arch, user_tags, managed_capabilities, installed_capabilities,
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
            initial_prompt,
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

fn resolved_initial_prompt(role: &AgentRole, initial_prompt: String) -> String {
    if initial_prompt.trim().is_empty() {
        return match role {
            AgentRole::Worker => DEFAULT_WORKER_PROMPT.into(),
            AgentRole::Reviewer => DEFAULT_REVIEWER_PROMPT.into(),
        };
    }
    if matches!(role, AgentRole::Reviewer)
        && (initial_prompt == LEGACY_DEFAULT_REVIEWER_PROMPT
            || initial_prompt == LEGACY_FULL_SWEEP_REVIEWER_PROMPT)
    {
        return DEFAULT_REVIEWER_PROMPT.into();
    }
    initial_prompt
}

fn agent_role_str(role: &AgentRole) -> &'static str {
    match role { AgentRole::Worker => "worker", AgentRole::Reviewer => "reviewer" }
}

fn agent_role(value: String) -> Result<AgentRole, ApiError> {
    match value.as_str() { "worker" => Ok(AgentRole::Worker), "reviewer" => Ok(AgentRole::Reviewer), _ => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("invalid agent role {value}"))) }
}

pub(crate) fn task_from_row(row: &sqlx::sqlite::SqliteRow) -> Result<Task, ApiError> {
    let state: String = row.try_get("state").map_err(internal)?;
    // review_cycle was added by migration 0018; default to 0 for rows that
    // predate the column so old history keeps counting as cycle 0.
    let review_cycle: i64 = row.try_get("review_cycle").unwrap_or(0);
    Ok(Task { id: uuid(row.try_get("id").map_err(internal)?)?, project_id: uuid(row.try_get("project_id").map_err(internal)?)?,
        title: row.try_get("title").map_err(internal)?, description: row.try_get("description").map_err(internal)?, expected_outcome: row.try_get("expected_outcome").map_err(internal)?,
        acceptance_criteria: dejson(row.try_get("acceptance_criteria").map_err(internal)?)?, required_tags: dejson(row.try_get("required_tags").map_err(internal)?)?,
        preferred_tags: dejson(row.try_get("preferred_tags").map_err(internal)?)?, dependencies: dejson(row.try_get("dependencies").map_err(internal)?)?, review_feedback: row.try_get("review_feedback").map_err(internal)?, priority: row.try_get("priority").map_err(internal)?,
        state: match state.as_str() { "draft"=>TaskState::Draft,"assigned"=>TaskState::Assigned,"running"=>TaskState::Running,"review"=>TaskState::Review,"merge_pending"=>TaskState::MergePending,"done"=>TaskState::Done,"blocked"=>TaskState::Blocked,"failed"=>TaskState::Failed,"cancelled"=>TaskState::Cancelled,_=>TaskState::Queued },
        review_cycle: review_cycle.max(0),
        conflict_group: row.try_get::<Option<String>, _>("conflict_group").unwrap_or(None),
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

#[allow(dead_code)]
fn review_failures_exhausted(failed_reviews: i64, limit: i64) -> bool {
    failed_reviews >= limit
}

/// Reviewer runtime/infrastructure failure budget: `failed` + `lost` rows for
/// the same implementation execution count together toward
/// `review_failure_limit`. Completed verdicts (approve/retry) never count
/// here, and these rows never count as quality retries.
fn review_runtime_failures_exhausted(failed: i64, lost: i64, limit: i64) -> bool {
    failed + lost >= limit
}

fn review_runtime_blocked_feedback(failed: i64, lost: i64, limit: i64, detail: &str) -> String {
    let total = failed + lost;
    format!(
        "Reviewer runtime failed {total} times ({failed} failed, {lost} lost) for this implementation; automatic review retries stopped at limit {limit}. {detail}",
    )
}

fn review_retries_exhausted(reviewer_retries: i64, limit: i64) -> bool {
    reviewer_retries >= limit
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};

    #[test]
    fn reviewer_runtime_failures_are_bounded() {
        assert!(!review_failures_exhausted(2, 3));
        assert!(review_failures_exhausted(3, 3));
        assert!(!review_failures_exhausted(3, 4));
    }

    #[test]
    fn reviewer_quality_retries_are_bounded() {
        assert!(!review_retries_exhausted(2, 3));
        assert!(review_retries_exhausted(3, 3));
        assert!(!review_retries_exhausted(3, 5));
    }

    #[test]
    fn legacy_default_reviewer_prompt_upgrades_without_touching_custom_prompt() {
        assert_eq!(resolved_initial_prompt(&AgentRole::Reviewer, LEGACY_DEFAULT_REVIEWER_PROMPT.into()), DEFAULT_REVIEWER_PROMPT);
        assert_eq!(resolved_initial_prompt(&AgentRole::Reviewer, LEGACY_FULL_SWEEP_REVIEWER_PROMPT.into()), DEFAULT_REVIEWER_PROMPT);
        assert_eq!(resolved_initial_prompt(&AgentRole::Reviewer, "custom".into()), "custom");
        assert_eq!(resolved_initial_prompt(&AgentRole::Worker, String::new()), DEFAULT_WORKER_PROMPT);
    }

    #[tokio::test]
    async fn host_review_settings_persist_and_reload() {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let state = Arc::new(AppState {
            db,
            public_url: None,
            oauth_password: None,
            git_credential_key: None,
            git_root: std::env::temp_dir(),
            agent_auth_updates: Default::default(),
            model_refresh_requests: Default::default(), oauth_login_states: Default::default(), interactive_sandboxes: Default::default(),
        });
        let Json(saved) = update_host_settings(
            State(state.clone()),
            Json(UpdateHostSettings { review_retry_limit: Some(7), review_failure_limit: Some(4) }),
        ).await.unwrap();
        assert_eq!(saved.review_retry_limit, 7);
        assert_eq!(saved.review_failure_limit, 4);
        let Json(reloaded) = get_host_settings(State(state)).await.unwrap();
        assert_eq!(reloaded.review_retry_limit, 7);
        assert_eq!(reloaded.review_failure_limit, 4);
    }

    #[tokio::test]
    async fn conflict_group_create_read_round_trip_and_validation() {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(project_id.to_string()).bind("p").bind("P").bind("https://example.invalid/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let state = Arc::new(AppState {
            db,
            public_url: None,
            oauth_password: None,
            git_credential_key: None,
            git_root: std::env::temp_dir(),
            agent_auth_updates: Default::default(),
            model_refresh_requests: Default::default(), oauth_login_states: Default::default(), interactive_sandboxes: Default::default(),
        });
        let input = CreateTask {
            project_id,
            title: "grouped".into(),
            description: String::new(),
            expected_outcome: String::new(),
            acceptance_criteria: vec![],
            required_tags: Default::default(),
            preferred_tags: Default::default(),
            dependencies: vec![],
            priority: 0,
            conflict_group: Some("  Server-API  ".into()),
        };
        let Json(created) = create_task(State(state.clone()), Json(input)).await.unwrap();
        assert_eq!(created.conflict_group.as_deref(), Some("server-api"));
        let Json(tasks) = list_tasks(State(state.clone())).await.unwrap();
        assert_eq!(tasks.iter().find(|t| t.id == created.id).unwrap().conflict_group.as_deref(), Some("server-api"));

        let invalid = CreateTask {
            project_id,
            title: "bad".into(),
            description: String::new(),
            expected_outcome: String::new(),
            acceptance_criteria: vec![],
            required_tags: Default::default(),
            preferred_tags: Default::default(),
            dependencies: vec![],
            priority: 0,
            conflict_group: Some("has space".into()),
        };
        let error = create_task(State(state), Json(invalid)).await.unwrap_err();
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn reviewer_prompt_requires_complete_sweep_before_retry() {
        assert!(DEFAULT_REVIEWER_PROMPT.contains("Do not stop after finding the first defect"));
        assert!(DEFAULT_REVIEWER_PROMPT.contains("every acceptance criterion"));
        assert!(DEFAULT_REVIEWER_PROMPT.contains("all discovered blockers"));
        assert!(DEFAULT_REVIEWER_PROMPT.contains("submit_review"));
        assert!(!DEFAULT_REVIEWER_PROMPT.contains("final response must be exactly one JSON"));
    }

    fn selected_agent() -> AgentConfig {
        AgentConfig {
            agent_type: "pi".into(),
            provider: Some("host-provider".into()),
            model: Some("host-model".into()),
            initial_prompt: "prompt".into(),
        }
    }

    #[test]
    fn agent_selection_update_preserves_omitted_host_values() {
        let current = selected_agent();
        assert_eq!(
            resolve_agent_selection(&current, None, None, false).unwrap(),
            (Some("host-provider".into()), Some("host-model".into()))
        );
        assert_eq!(
            resolve_agent_selection(&current, Some("next-provider".into()), Some("next-model".into()), false).unwrap(),
            (Some("next-provider".into()), Some("next-model".into()))
        );
        let unselected = AgentConfig {
            agent_type: "pi".into(),
            provider: None,
            model: None,
            initial_prompt: "prompt".into(),
        };
        assert_eq!(resolve_agent_selection(&unselected, None, None, false).unwrap(), (None, None));
    }

    #[test]
    fn agent_selection_clearing_requires_explicit_clear_model() {
        let current = selected_agent();
        assert_eq!(resolve_agent_selection(&current, None, None, true).unwrap(), (None, None));
        assert!(resolve_agent_selection(&current, Some("next-provider".into()), Some("next-model".into()), true).is_err());
        assert!(resolve_agent_selection(&current, Some("next-provider".into()), None, true).is_err());
        let unselected = AgentConfig {
            agent_type: "pi".into(),
            provider: None,
            model: None,
            initial_prompt: "prompt".into(),
        };
        assert!(resolve_agent_selection(&unselected, Some("only-provider".into()), None, false).is_err());
        assert!(resolve_agent_selection(&unselected, None, Some("only-model".into()), false).is_err());
    }


    async fn lease_test_state() -> Arc<AppState> {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        Arc::new(AppState {
            db,
            public_url: None,
            oauth_password: None,
            git_credential_key: None,
            git_root: std::env::temp_dir().join(format!("lazyteam-work-lease-test-{}", Uuid::new_v4())),
            agent_auth_updates: Default::default(),
            model_refresh_requests: Default::default(),
            oauth_login_states: Default::default(), interactive_sandboxes: Default::default(),
        })
    }


    async fn race_lease_test_state() -> Arc<AppState> {
        let root = std::env::temp_dir().join(format!("lazyteam-work-race-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let options = SqliteConnectOptions::new()
            .filename(root.join("state.db"))
            .create_if_missing(true)
            .busy_timeout(std::time::Duration::from_secs(5));
        let db = SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        Arc::new(AppState {
            db,
            public_url: None,
            oauth_password: None,
            git_credential_key: None,
            git_root: root.join("git"),
            agent_auth_updates: Default::default(),
            model_refresh_requests: Default::default(),
            oauth_login_states: Default::default(), interactive_sandboxes: Default::default(),
        })
    }

    async fn task_for_test(state: &AppState, task_id: Uuid) -> Task {
        let row = sqlx::query("SELECT * FROM tasks WHERE id=?")
            .bind(task_id.to_string()).fetch_one(&state.db).await.unwrap();
        task_from_row(&row).unwrap()
    }

    async fn worker_for_test(state: &AppState, worker_id: Uuid) -> Worker {
        let row = sqlx::query("SELECT * FROM workers WHERE id=?")
            .bind(worker_id.to_string()).fetch_one(&state.db).await.unwrap();
        worker_from_row(&row).unwrap()
    }

    async fn seed_real_race_worker(state: &AppState, role: AgentRole) -> Worker {
        let id = Uuid::new_v4();
        let now = ts(Utc::now());
        let role_name = match role { AgentRole::Worker => "worker", AgentRole::Reviewer => "reviewer" };
        sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,tags,allowed_projects,slots,running_slots,protocol_version,worker_version,last_heartbeat_at,created_at,agent_provider,agent_model,agent_capabilities) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(id.to_string()).bind(format!("race-{role_name}")).bind(role_name).bind("idle").bind("linux").bind("x86_64")
            .bind("{}").bind("[\"*\"]").bind(1_i64).bind(0_i64).bind(PROTOCOL_VERSION as i64).bind("test")
            .bind(&now).bind(&now).bind("prov").bind("mod")
            .bind(r#"{"models":[{"provider":"prov","id":"mod"}]}"#)
            .execute(&state.db).await.unwrap();
        worker_for_test(state, id).await
    }

    fn test_execution(task_id: Uuid, worker_id: Uuid, id: Uuid, attempt: u32) -> Execution {
        Execution {
            id,
            task_id,
            worker_id,
            attempt,
            state: ExecutionState::Assigned,
            lease_until: Utc::now() + chrono::Duration::minutes(5),
            started_at: None,
            finished_at: None,
            result: None,
        }
    }

    fn completed_test_result() -> ExecutionResult {
        ExecutionResult {
            status: "completed".into(),
            summary: "done".into(),
            commit_sha: Some("candidate".into()),
            base_sha: Some("base".into()),
            patch: None,
            patch_truncated: false,
            workspace_clean: Some(true),
            review_ref: Some("lazyteam/test".into()),
            changed_files: vec![],
            validation: vec![],
            warnings: vec![],
            artifacts: vec![],
            integration: None,
        }
    }

    async fn seed_completed_execution_for_race(state: &AppState, task_id: Uuid) -> Execution {
        let impl_id = ensure_internal_work_actor(state, AgentRole::Worker).await.unwrap();
        let now = Utc::now();
        let mut execution = test_execution(task_id, impl_id, Uuid::new_v4(), 1);
        execution.state = ExecutionState::Completed;
        execution.finished_at = Some(now);
        execution.result = Some(completed_test_result());
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,finished_at,result,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(execution.id.to_string()).bind(task_id.to_string()).bind(impl_id.to_string()).bind(1_i64).bind("completed")
            .bind(ts(execution.lease_until)).bind(ts(now)).bind(json(execution.result.as_ref().unwrap()).unwrap()).bind(ts(now))
            .execute(&state.db).await.unwrap();
        execution
    }

    async fn seed_lease_test_project_task(state: &AppState, task_state: &str) -> (Uuid, Uuid) {
        let now = ts(Utc::now());
        let project_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(project_id.to_string()).bind(format!("p-{project_id}")).bind("P").bind("https://example.invalid/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&state.db).await.unwrap();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(project_id.to_string()).bind("lease task").bind("").bind("").bind(task_state).bind(&now).bind(&now)
            .execute(&state.db).await.unwrap();
        (project_id, task_id)
    }


    async fn seed_active_review_lease(state: &AppState, retry_limit: i64) -> (Uuid, Uuid, String, Uuid) {
        sqlx::query("UPDATE host_settings SET review_retry_limit=? WHERE id=1")
            .bind(retry_limit).execute(&state.db).await.unwrap();
        let (_, task_id) = seed_lease_test_project_task(state, "review").await;
        let implementation_worker = ensure_internal_work_actor(state, AgentRole::Worker).await.unwrap();
        let reviewer = ensure_internal_work_actor(state, AgentRole::Reviewer).await.unwrap();
        let execution_id = Uuid::new_v4();
        let review_id = Uuid::new_v4();
        let now = Utc::now();
        let lease_until = now + chrono::Duration::minutes(5);
        let result = ExecutionResult {
            status: "completed".into(),
            summary: "done".into(),
            commit_sha: Some("candidate".into()),
            base_sha: Some("base".into()),
            patch: None,
            patch_truncated: false,
            workspace_clean: Some(true),
            review_ref: Some("lazyteam/test".into()),
            changed_files: vec![],
            validation: vec![],
            warnings: vec![],
            artifacts: vec![],
            integration: None,
        };
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,finished_at,result,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(execution_id.to_string()).bind(task_id.to_string()).bind(implementation_worker.to_string()).bind(1_i64).bind("completed")
            .bind(ts(now)).bind(ts(now)).bind(json(&result).unwrap()).bind(ts(now))
            .execute(&state.db).await.unwrap();
        let (capability, capability_hash) = issue_lease_capability();
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,lease_capability_hash,review_cycle) VALUES(?,?,?,?,?,?,?,?,0)")
            .bind(review_id.to_string()).bind(task_id.to_string()).bind(execution_id.to_string()).bind(reviewer.to_string()).bind("assigned")
            .bind(ts(lease_until)).bind(ts(now)).bind(capability_hash)
            .execute(&state.db).await.unwrap();
        sqlx::query("UPDATE workers SET running_slots=1,state='busy' WHERE id=?")
            .bind(reviewer.to_string()).execute(&state.db).await.unwrap();
        (task_id, review_id, capability, implementation_worker)
    }


    #[tokio::test]
    async fn two_interactive_implementation_picks_have_one_authoritative_owner() {
        let state = race_lease_test_state().await;
        let (_, task_id) = seed_lease_test_project_task(&state, "queued").await;
        let task = task_for_test(&state, task_id).await;
        let actor_id = ensure_internal_work_actor(&state, AgentRole::Worker).await.unwrap();
        let actor = worker_for_test(&state, actor_id).await;
        let a = test_execution(task_id, actor_id, Uuid::new_v4(), 1);
        let b = test_execution(task_id, actor_id, Uuid::new_v4(), 1);
        let (_, ah) = issue_lease_capability();
        let (_, bh) = issue_lease_capability();
        let now = Utc::now();

        let (ra, rb) = tokio::join!(
            persist_task_claim(&state, &task, &actor, &a, 1, &ah, now),
            persist_task_claim(&state, &task, &actor, &b, 1, &bh, now),
        );
        let won = [ra.unwrap(), rb.unwrap()].into_iter().filter(|won| *won).count();
        assert_eq!(won, 1);
        let owners: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM executions WHERE task_id=? AND state IN ('assigned','running')")
            .bind(task_id.to_string()).fetch_one(&state.db).await.unwrap();
        assert_eq!(owners, 1);
    }

    #[tokio::test]
    async fn interactive_implementation_and_rest_worker_share_one_claim_cas() {
        let state = race_lease_test_state().await;
        let (_, task_id) = seed_lease_test_project_task(&state, "queued").await;
        let task = task_for_test(&state, task_id).await;
        let actor_id = ensure_internal_work_actor(&state, AgentRole::Worker).await.unwrap();
        let actor = worker_for_test(&state, actor_id).await;
        let rest_worker = seed_real_race_worker(&state, AgentRole::Worker).await;
        let interactive = test_execution(task_id, actor.id, Uuid::new_v4(), 1);
        let rest = test_execution(task_id, rest_worker.id, Uuid::new_v4(), 1);
        let (_, ih) = issue_lease_capability();
        let (_, rh) = issue_lease_capability();
        let now = Utc::now();

        let (ri, rr) = tokio::join!(
            persist_task_claim(&state, &task, &actor, &interactive, 1, &ih, now),
            persist_task_claim(&state, &task, &rest_worker, &rest, 1, &rh, now),
        );
        let won = [ri.unwrap(), rr.unwrap()].into_iter().filter(|won| *won).count();
        assert_eq!(won, 1);
        let owners: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM executions WHERE task_id=? AND state IN ('assigned','running')")
            .bind(task_id.to_string()).fetch_one(&state.db).await.unwrap();
        assert_eq!(owners, 1);
    }

    #[tokio::test]
    async fn two_interactive_review_picks_have_one_authoritative_owner() {
        let state = race_lease_test_state().await;
        let (_, task_id) = seed_lease_test_project_task(&state, "review").await;
        let task = task_for_test(&state, task_id).await;
        let execution = seed_completed_execution_for_race(&state, task_id).await;
        let actor_id = ensure_internal_work_actor(&state, AgentRole::Reviewer).await.unwrap();
        let actor = worker_for_test(&state, actor_id).await;
        let now = Utc::now();
        let a = ReviewLease { id: Uuid::new_v4(), task_id, execution_id: execution.id, reviewer_worker_id: actor.id, lease_until: now + chrono::Duration::minutes(5) };
        let b = ReviewLease { id: Uuid::new_v4(), task_id, execution_id: execution.id, reviewer_worker_id: actor.id, lease_until: now + chrono::Duration::minutes(5) };
        let (_, ah) = issue_lease_capability();
        let (_, bh) = issue_lease_capability();
        let result = completed_test_result();

        let (ra, rb) = tokio::join!(
            persist_review_claim(&state, &task, &actor, &execution, &a, &ah, &result, "upstream", "integration", "diff", now),
            persist_review_claim(&state, &task, &actor, &execution, &b, &bh, &result, "upstream", "integration", "diff", now),
        );
        let won = [ra.unwrap(), rb.unwrap()].into_iter().filter(|won| *won).count();
        assert_eq!(won, 1);
        let owners: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state IN ('assigned','running')")
            .bind(task_id.to_string()).fetch_one(&state.db).await.unwrap();
        assert_eq!(owners, 1);
    }

    #[tokio::test]
    async fn interactive_review_and_rest_reviewer_share_one_claim_cas() {
        let state = race_lease_test_state().await;
        let (_, task_id) = seed_lease_test_project_task(&state, "review").await;
        let task = task_for_test(&state, task_id).await;
        let execution = seed_completed_execution_for_race(&state, task_id).await;
        let actor_id = ensure_internal_work_actor(&state, AgentRole::Reviewer).await.unwrap();
        let actor = worker_for_test(&state, actor_id).await;
        let rest_reviewer = seed_real_race_worker(&state, AgentRole::Reviewer).await;
        let now = Utc::now();
        let interactive = ReviewLease { id: Uuid::new_v4(), task_id, execution_id: execution.id, reviewer_worker_id: actor.id, lease_until: now + chrono::Duration::minutes(5) };
        let rest = ReviewLease { id: Uuid::new_v4(), task_id, execution_id: execution.id, reviewer_worker_id: rest_reviewer.id, lease_until: now + chrono::Duration::minutes(5) };
        let (_, ih) = issue_lease_capability();
        let (_, rh) = issue_lease_capability();
        let result = completed_test_result();

        let (ri, rr) = tokio::join!(
            persist_review_claim(&state, &task, &actor, &execution, &interactive, &ih, &result, "upstream", "integration", "diff", now),
            persist_review_claim(&state, &task, &rest_reviewer, &execution, &rest, &rh, &result, "upstream", "integration", "diff", now),
        );
        let won = [ri.unwrap(), rr.unwrap()].into_iter().filter(|won| *won).count();
        assert_eq!(won, 1);
        let owners: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state IN ('assigned','running')")
            .bind(task_id.to_string()).fetch_one(&state.db).await.unwrap();
        assert_eq!(owners, 1);
    }

    #[tokio::test]
    async fn internal_work_actors_are_hidden_from_worker_inventory() {
        let state = lease_test_state().await;
        let implementation = ensure_internal_work_actor(&state, AgentRole::Worker).await.unwrap();
        let review = ensure_internal_work_actor(&state, AgentRole::Reviewer).await.unwrap();
        assert_ne!(implementation, review);

        let Json(workers) = list_workers(State(state.clone())).await.unwrap();
        assert!(workers.is_empty(), "internal actors leaked into workers_list");

        let internal_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workers WHERE internal_actor=1")
            .fetch_one(&state.db).await.unwrap();
        assert_eq!(internal_count, 2);
    }


    #[tokio::test]
    async fn expired_implementation_lease_cannot_finish() {
        let state = lease_test_state().await;
        let (_, task_id) = seed_lease_test_project_task(&state, "assigned").await;
        let worker_id = ensure_internal_work_actor(&state, AgentRole::Worker).await.unwrap();
        let execution_id = Uuid::new_v4();
        let now = Utc::now();
        let expired = now - chrono::Duration::seconds(1);
        let (capability, capability_hash) = issue_lease_capability();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,lease_capability_hash) VALUES(?,?,?,?,?,?,?,?)")
            .bind(execution_id.to_string()).bind(task_id.to_string()).bind(worker_id.to_string()).bind(1_i64).bind("assigned")
            .bind(ts(expired)).bind(ts(now)).bind(capability_hash)
            .execute(&state.db).await.unwrap();
        let error = finish_execution_for_capability(
            &state,
            execution_id,
            &capability,
            completed_test_result(),
            None,
        ).await.unwrap_err();
        assert_eq!(error.0, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn implementation_release_requeues_without_failure_and_revokes_capability() {
        let state = lease_test_state().await;
        let (_, task_id) = seed_lease_test_project_task(&state, "assigned").await;
        let worker_id = ensure_internal_work_actor(&state, AgentRole::Worker).await.unwrap();
        let execution_id = Uuid::new_v4();
        let now = Utc::now();
        let lease_until = now + chrono::Duration::minutes(5);
        let (capability, capability_hash) = issue_lease_capability();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,lease_capability_hash) VALUES(?,?,?,?,?,?,?,?)")
            .bind(execution_id.to_string()).bind(task_id.to_string()).bind(worker_id.to_string()).bind(1_i64).bind("assigned")
            .bind(ts(lease_until)).bind(ts(now)).bind(capability_hash)
            .execute(&state.db).await.unwrap();
        sqlx::query("UPDATE workers SET running_slots=1,state='busy' WHERE id=?")
            .bind(worker_id.to_string()).execute(&state.db).await.unwrap();

        release_execution_for_capability(&state, execution_id, &capability, None).await.unwrap();

        let task_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?").bind(task_id.to_string()).fetch_one(&state.db).await.unwrap();
        let execution_state: String = sqlx::query_scalar("SELECT state FROM executions WHERE id=?").bind(execution_id.to_string()).fetch_one(&state.db).await.unwrap();
        let capability_after: Option<String> = sqlx::query_scalar("SELECT lease_capability_hash FROM executions WHERE id=?").bind(execution_id.to_string()).fetch_one(&state.db).await.unwrap();
        assert_eq!(task_state, "queued");
        assert_eq!(execution_state, "cancelled");
        assert!(capability_after.is_none());

        let stale = renew_execution_for_capability(&state, execution_id, &capability, None).await.unwrap_err();
        assert_eq!(stale.0, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn review_release_keeps_review_state_and_does_not_count_retry_or_failure() {
        let state = lease_test_state().await;
        let (_, task_id) = seed_lease_test_project_task(&state, "review").await;
        let implementation_worker = ensure_internal_work_actor(&state, AgentRole::Worker).await.unwrap();
        let reviewer = ensure_internal_work_actor(&state, AgentRole::Reviewer).await.unwrap();
        let execution_id = Uuid::new_v4();
        let review_id = Uuid::new_v4();
        let now = Utc::now();
        let lease_until = now + chrono::Duration::minutes(5);
        let result = ExecutionResult {
            status: "completed".into(),
            summary: "done".into(),
            commit_sha: Some("candidate".into()),
            base_sha: Some("base".into()),
            patch: None,
            patch_truncated: false,
            workspace_clean: Some(true),
            review_ref: Some("lazyteam/test".into()),
            changed_files: vec![],
            validation: vec![],
            warnings: vec![],
            artifacts: vec![],
            integration: None,
        };
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,finished_at,result,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(execution_id.to_string()).bind(task_id.to_string()).bind(implementation_worker.to_string()).bind(1_i64).bind("completed")
            .bind(ts(now)).bind(ts(now)).bind(json(&result).unwrap()).bind(ts(now))
            .execute(&state.db).await.unwrap();
        let (capability, capability_hash) = issue_lease_capability();
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,lease_capability_hash) VALUES(?,?,?,?,?,?,?,?)")
            .bind(review_id.to_string()).bind(task_id.to_string()).bind(execution_id.to_string()).bind(reviewer.to_string()).bind("assigned")
            .bind(ts(lease_until)).bind(ts(now)).bind(capability_hash)
            .execute(&state.db).await.unwrap();
        sqlx::query("UPDATE workers SET running_slots=1,state='busy' WHERE id=?")
            .bind(reviewer.to_string()).execute(&state.db).await.unwrap();

        release_review_for_capability(&state, review_id, &capability, None).await.unwrap();

        let task_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?").bind(task_id.to_string()).fetch_one(&state.db).await.unwrap();
        let review_state: String = sqlx::query_scalar("SELECT state FROM reviews WHERE id=?").bind(review_id.to_string()).fetch_one(&state.db).await.unwrap();
        let counted: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE id=? AND state IN ('failed','lost','completed')")
            .bind(review_id.to_string()).fetch_one(&state.db).await.unwrap();
        assert_eq!(task_state, "review");
        assert_eq!(review_state, "cancelled");
        assert_eq!(counted, 0);

        let stale = renew_review_for_capability(&state, review_id, &capability, None).await.unwrap_err();
        assert_eq!(stale.0, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn review_finish_rejects_lease_pinned_to_old_execution() {
        let state = lease_test_state().await;
        let (_, task_id) = seed_lease_test_project_task(&state, "review").await;
        let implementation_worker = ensure_internal_work_actor(&state, AgentRole::Worker).await.unwrap();
        let reviewer = ensure_internal_work_actor(&state, AgentRole::Reviewer).await.unwrap();
        let now = Utc::now();
        let lease_until = now + chrono::Duration::minutes(5);
        let old_execution = Uuid::new_v4();
        let new_execution = Uuid::new_v4();
        let review_id = Uuid::new_v4();
        let result = ExecutionResult {
            status: "completed".into(),
            summary: "done".into(),
            commit_sha: Some("candidate".into()),
            base_sha: Some("base".into()),
            patch: None,
            patch_truncated: false,
            workspace_clean: Some(true),
            review_ref: Some("lazyteam/test".into()),
            changed_files: vec![],
            validation: vec![],
            warnings: vec![],
            artifacts: vec![],
            integration: None,
        };
        for (execution_id, attempt) in [(old_execution, 1_i64), (new_execution, 2_i64)] {
            sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,finished_at,result,created_at) VALUES(?,?,?,?,?,?,?,?,?)")
                .bind(execution_id.to_string()).bind(task_id.to_string()).bind(implementation_worker.to_string()).bind(attempt).bind("completed")
                .bind(ts(now)).bind(ts(now)).bind(json(&result).unwrap()).bind(ts(now))
                .execute(&state.db).await.unwrap();
        }
        let (capability, capability_hash) = issue_lease_capability();
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,lease_capability_hash) VALUES(?,?,?,?,?,?,?,?)")
            .bind(review_id.to_string()).bind(task_id.to_string()).bind(old_execution.to_string()).bind(reviewer.to_string()).bind("assigned")
            .bind(ts(lease_until)).bind(ts(now)).bind(capability_hash)
            .execute(&state.db).await.unwrap();

        let verdict = ReviewVerdict { verdict: ReviewVerdictKind::Approve, reason: "approved".into(), validation: vec![] };
        let error = finish_review_for_capability(&state, review_id, &capability, "completed", Some(verdict), None, None).await.unwrap_err();
        assert_eq!(error.0, StatusCode::CONFLICT);
        assert!(error.1.contains("stale execution"));

        let task_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?").bind(task_id.to_string()).fetch_one(&state.db).await.unwrap();
        assert_eq!(task_state, "review");
    }


    #[tokio::test]
    async fn review_approve_moves_task_to_merge_pending() {
        let state = lease_test_state().await;
        let (task_id, review_id, capability, _) = seed_active_review_lease(&state, 5).await;
        let verdict = ReviewVerdict { verdict: ReviewVerdictKind::Approve, reason: "approved".into(), validation: vec![] };
        finish_review_for_capability(&state, review_id, &capability, "completed", Some(verdict), None, None).await.unwrap();
        let task_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
            .bind(task_id.to_string()).fetch_one(&state.db).await.unwrap();
        assert_eq!(task_state, "merge_pending");
    }

    #[tokio::test]
    async fn review_retry_requeues_and_retry_limit_blocks() {
        let state = lease_test_state().await;
        let (task_id, review_id, capability, implementation_worker) = seed_active_review_lease(&state, 2).await;
        let verdict = ReviewVerdict { verdict: ReviewVerdictKind::Retry, reason: "fix".into(), validation: vec![] };
        finish_review_for_capability(&state, review_id, &capability, "completed", Some(verdict), None, None).await.unwrap();
        let row = sqlx::query("SELECT state,sticky_worker_id FROM tasks WHERE id=?")
            .bind(task_id.to_string()).fetch_one(&state.db).await.unwrap();
        let task_state: String = row.try_get("state").unwrap();
        let sticky: Option<String> = row.try_get("sticky_worker_id").unwrap();
        assert_eq!(task_state, "queued");
        let expected_worker = implementation_worker.to_string();
        assert_eq!(sticky.as_deref(), Some(expected_worker.as_str()));

        let state = lease_test_state().await;
        let (task_id, review_id, capability, _) = seed_active_review_lease(&state, 1).await;
        let verdict = ReviewVerdict { verdict: ReviewVerdictKind::Retry, reason: "still wrong".into(), validation: vec![] };
        finish_review_for_capability(&state, review_id, &capability, "completed", Some(verdict), None, None).await.unwrap();
        let task_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
            .bind(task_id.to_string()).fetch_one(&state.db).await.unwrap();
        assert_eq!(task_state, "blocked");
    }

    #[tokio::test]
    async fn worker_reregistration_preserves_host_owned_agent_selection() {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let state = Arc::new(AppState {
            db,
            public_url: None,
            oauth_password: None,
            git_credential_key: None,
            git_root: std::env::temp_dir(),
            agent_auth_updates: Default::default(),
            model_refresh_requests: Default::default(), oauth_login_states: Default::default(), interactive_sandboxes: Default::default(),
        });
        let worker_id = Uuid::new_v4();
        let input = || RegisterWorker {
            id: Some(worker_id),
            name: "worker-01".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            tags: Default::default(),
            allowed_projects: BTreeSet::from(["*".to_string()]),
            slots: 1,
            worker_version: "test".into(),
            protocol_version: PROTOCOL_VERSION,
            agent_type: "pi".into(),
            role: AgentRole::Worker,
            agent_capabilities: AgentCapabilities::default(),
        };
        register_worker(State(state.clone()), Json(input())).await.unwrap();
        sqlx::query("UPDATE workers SET agent_provider=?,agent_model=? WHERE id=?")
            .bind("host-provider")
            .bind("host-model")
            .bind(worker_id.to_string())
            .execute(&state.db)
            .await
            .unwrap();
        register_worker(State(state.clone()), Json(input())).await.unwrap();
        let row = sqlx::query("SELECT agent_provider,agent_model FROM workers WHERE id=?")
            .bind(worker_id.to_string())
            .fetch_one(&state.db)
            .await
            .unwrap();
        let provider: Option<String> = row.try_get("agent_provider").unwrap();
        let model: Option<String> = row.try_get("agent_model").unwrap();
        assert_eq!(provider.as_deref(), Some("host-provider"));
        assert_eq!(model.as_deref(), Some("host-model"));
    }

    #[test]
    fn default_session_affinity_window_is_fifteen_minutes() {
        assert_eq!(DEFAULT_SESSION_AFFINITY_SECONDS, 15 * 60);
    }

    #[test]
    fn review_loop_badge_stays_quiet_on_first_pass() {
        assert!(!task_board_looping(1, 0));
        assert!(!task_board_looping(2, 0));
        assert!(!task_board_looping(3, 2));
        assert!(!task_board_looping(0, 0));
    }

    #[test]
    fn review_loop_badge_triggers_on_conservative_threshold() {
        assert!(task_board_looping(4, 0));
        assert!(task_board_looping(9, 0));
        assert!(task_board_looping(1, 3));
        assert!(task_board_looping(2, 5));
    }

    #[test]
    fn reviewer_retry_verdict_uses_durable_verdict_json_only() {
        assert!(is_reviewer_retry_verdict(Some(r#"{"verdict":"retry","reason":"fix it"}"#)));
        assert!(is_reviewer_retry_verdict(Some(r#"{"verdict": "retry","reason":"fix it"}"#)));
        assert!(!is_reviewer_retry_verdict(Some(r#"{"verdict":"approve","reason":"looks good"}"#)));
        assert!(!is_reviewer_retry_verdict(Some(r#"{"error":"runtime exploded"}"#)));
        assert!(!is_reviewer_retry_verdict(None));
        // Prose that merely mentions retry/merge conflict must not qualify.
        assert!(!is_reviewer_retry_verdict(Some("please retry, Host merge conflict in main gate")));
    }

    #[test]
    fn task_board_item_serializes_attempt_and_review_counts() {
        let item = TaskBoardItem {
            task: Task {
                id: Uuid::new_v4(),
                project_id: Uuid::new_v4(),
                title: "t".into(),
                description: String::new(),
                expected_outcome: String::new(),
                acceptance_criteria: vec![],
                required_tags: Default::default(),
                preferred_tags: Default::default(),
                dependencies: vec![],
                review_feedback: "Host merge conflict in main gate overturned".into(),
                priority: 0,
                state: TaskState::Review,
                review_cycle: 2,
                conflict_group: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            worker: None,
            reviewer: None,
            result: None,
            attempt: 3,
            review_rounds: 2,
            review_runtime_failures: 1,
            review_lost_leases: 1,
            reviewer_retries: 1,
            current_cycle_reviewer_retries: 1,
            lifetime_reviewer_retries: 4,
            waiting: None,
        };
        let value = serde_json::to_value(&item).unwrap();
        assert_eq!(value["attempt"], 3);
        assert_eq!(value["review_rounds"], 2);
        assert_eq!(value["review_runtime_failures"], 1);
        assert_eq!(value["review_lost_leases"], 1);
        assert_eq!(value["reviewer_retries"], 1);
        assert_eq!(value["current_cycle_reviewer_retries"], 1);
        assert_eq!(value["lifetime_reviewer_retries"], 4);
    }

    #[tokio::test]
    async fn task_board_counts_come_from_database_history() {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4().to_string();
        let worker_id = Uuid::new_v4().to_string();
        let reviewer_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        for (id, role) in [(&worker_id, "worker"), (&reviewer_id, "reviewer")] {
            sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
                .bind(id).bind(role).bind(role).bind("idle").bind("linux").bind("x86_64")
                .bind(PROTOCOL_VERSION as i64).bind("test").bind(&now).bind(&now)
                .execute(&db).await.unwrap();
        }
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,review_feedback,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(&task_id).bind(&project_id).bind("looping task").bind("").bind("").bind("review")
            .bind("Host merge conflict in main gate; please retry")
            .bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        // Two implementation attempts; latest attempt number must be 2.
        for attempt in [1_i64, 2_i64] {
            let execution_id = Uuid::new_v4().to_string();
            sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
                .bind(&execution_id).bind(&task_id).bind(&worker_id).bind(attempt).bind("completed").bind(&now).bind(&now)
                .execute(&db).await.unwrap();
            if attempt == 2 {
                // Four review rows on the latest execution: one completed
                // approve and one completed retry, plus one runtime `failed`
                // and one `lost` row. Failed/lost rows are reported
                // separately and must not count as completed reviews or
                // reviewer disagreement.
                for (verdict, state) in [
                    (r#"{"verdict":"approve","reason":"ok","validation":[]}"#, "completed"),
                    (r#"{"verdict":"retry","reason":"fix it","validation":[]}"#, "completed"),
                    (r#"{"error":"runner crashed"}"#, "failed"),
                ] {
                    sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict) VALUES(?,?,?,?,?,?,?,?)")
                        .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&execution_id).bind(&reviewer_id)
                        .bind(state).bind(&now).bind(&now).bind(verdict)
                        .execute(&db).await.unwrap();
                }
                sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
                    .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&execution_id).bind(&reviewer_id)
                    .bind("lost").bind(&now).bind(&now)
                    .execute(&db).await.unwrap();
            }
        }
        let state = Arc::new(AppState {
            db,
            public_url: None,
            oauth_password: None,
            git_credential_key: None,
            git_root: std::env::temp_dir(),
            agent_auth_updates: Default::default(),
            model_refresh_requests: Default::default(), oauth_login_states: Default::default(), interactive_sandboxes: Default::default(),
        });
        let board = task_board(State(state)).await.unwrap().0;
        assert_eq!(board.len(), 1);
        assert_eq!(board[0].attempt, 2);
        assert_eq!(board[0].review_rounds, 2);
        assert_eq!(board[0].review_runtime_failures, 1);
        assert_eq!(board[0].review_lost_leases, 1);
        assert_eq!(board[0].reviewer_retries, 1);
        assert_eq!(board[0].current_cycle_reviewer_retries, 1);
        assert_eq!(board[0].lifetime_reviewer_retries, 1);
        assert!(!task_board_looping(board[0].attempt, board[0].reviewer_retries));
    }

    /// Regression: an old task whose lifetime reviewer retries exceed the
    /// configured per-cycle limit can be manually republished and then
    /// receive fewer than the limit in the new cycle without blocking.
    ///
    /// Manual `retry_task` (blocked/failed/merge-gate re-publish) starts a new
    /// review cycle and resets only the current-cycle counter; automatic
    /// reviewer redispatch stays in the same cycle. Historical review rows are
    /// never deleted and remain counted in lifetime totals.
    #[tokio::test]
    async fn manual_republish_resets_current_cycle_but_keeps_lifetime() {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4().to_string();
        let worker_id = Uuid::new_v4().to_string();
        let reviewer_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        for (id, role) in [(&worker_id, "worker"), (&reviewer_id, "reviewer")] {
            sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
                .bind(id).bind(role).bind(role).bind("idle").bind("linux").bind("x86_64")
                .bind(PROTOCOL_VERSION as i64).bind("test").bind(&now).bind(&now)
                .execute(&db).await.unwrap();
        }
        // Old blocked task in cycle 0 with four historical reviewer retries,
        // above the default per-cycle limit of 3.
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,review_feedback,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(&task_id).bind(&project_id).bind("old blocked task").bind("").bind("").bind("blocked")
            .bind("Reviewer requested implementation changes 4 times")
            .bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let execution_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&execution_id).bind(&task_id).bind(&worker_id).bind(1_i64).bind("completed").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        for _ in 0..4 {
            sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict,review_cycle) VALUES(?,?,?,?,?,?,?,?,?)")
                .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&execution_id).bind(&reviewer_id)
                .bind("completed").bind(&now).bind(&now)
                .bind(r#"{"verdict":"retry","reason":"fix it","validation":[]}"#).bind(0_i64)
                .execute(&db).await.unwrap();
        }
        let state = Arc::new(AppState {
            db,
            public_url: None,
            oauth_password: None,
            git_credential_key: None,
            git_root: std::env::temp_dir(),
            agent_auth_updates: Default::default(),
            model_refresh_requests: Default::default(), oauth_login_states: Default::default(), interactive_sandboxes: Default::default(),
        });
        let task_uuid = Uuid::parse_str(&task_id).unwrap();
        // Before republish, lifetime history exceeds the limit.
        let Json(status) = task_status(State(state.clone()), Path(task_uuid)).await.unwrap();
        assert_eq!(status.lifetime_reviewer_retries, 4);
        assert_eq!(status.current_cycle_reviewer_retries, 4);
        assert_eq!(status.task.review_cycle, 0);
        assert!(review_retries_exhausted(status.current_cycle_reviewer_retries, 3));
        // Manual re-publish starts a new review cycle.
        let transition = crate::review::retry_task(&state, task_uuid, Some("republish with fixes")).await.unwrap();
        assert_eq!(transition.state, "queued");
        let Json(status) = task_status(State(state.clone()), Path(task_uuid)).await.unwrap();
        assert_eq!(status.task.state, TaskState::Queued);
        assert_eq!(status.task.review_cycle, 1);
        // Historical rows are never deleted: lifetime stays 4 while the
        // current cycle resets to 0, so the task is not immediately blocked.
        let remaining: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=?")
            .bind(&task_id).fetch_one(&state.db).await.unwrap();
        assert_eq!(remaining, 4);
        assert_eq!(status.lifetime_reviewer_retries, 4);
        assert_eq!(status.current_cycle_reviewer_retries, 0);
        assert!(!review_retries_exhausted(status.current_cycle_reviewer_retries, 3));
        let board = task_board(State(state.clone())).await.unwrap().0;
        assert_eq!(board.len(), 1);
        assert_eq!(board[0].lifetime_reviewer_retries, 4);
        assert_eq!(board[0].current_cycle_reviewer_retries, 0);
        assert_eq!(board[0].reviewer_retries, 0);
        assert!(!task_board_looping(board[0].attempt, board[0].reviewer_retries));
        // Two automatic reviewer retries in the new cycle stay below the
        // per-cycle limit: no blocking even though lifetime totals (6) now
        // far exceed it. Blocking consults the current cycle only.
        let execution_id_2 = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&execution_id_2).bind(&task_id).bind(&worker_id).bind(2_i64).bind("completed").bind(&now).bind(&now)
            .execute(&state.db).await.unwrap();
        for _ in 0..2 {
            sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict,review_cycle) VALUES(?,?,?,?,?,?,?,?,?)")
                .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&execution_id_2).bind(&reviewer_id)
                .bind("completed").bind(&now).bind(&now)
                .bind(r#"{"verdict":"retry","reason":"another fix","validation":[]}"#).bind(1_i64)
                .execute(&state.db).await.unwrap();
        }
        let Json(status) = task_status(State(state.clone()), Path(task_uuid)).await.unwrap();
        assert_eq!(status.current_cycle_reviewer_retries, 2);
        assert_eq!(status.lifetime_reviewer_retries, 6);
        assert!(!review_retries_exhausted(status.current_cycle_reviewer_retries, 3));
        // Runtime reviewer failures stay separate: a `failed` review row must
        // not inflate the quality-retry counter, and the failure limit still
        // applies per implementation candidate on its own.
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict,review_cycle) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&execution_id_2).bind(&reviewer_id)
            .bind("failed").bind(&now).bind(&now)
            .bind(r#"{"error":"runner crashed"}"#).bind(1_i64)
            .execute(&state.db).await.unwrap();
        let Json(status) = task_status(State(state.clone()), Path(task_uuid)).await.unwrap();
        assert_eq!(status.current_cycle_reviewer_retries, 2);
        assert_eq!(status.lifetime_reviewer_retries, 6);
        let failed_reviews: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='failed'")
            .bind(&task_id).bind(&execution_id_2).fetch_one(&state.db).await.unwrap();
        assert_eq!(failed_reviews, 1);
        assert!(!review_failures_exhausted(failed_reviews, 3));
    }

    #[test]
    fn lost_leases_combine_with_failed_for_runtime_budget() {
        assert!(!review_runtime_failures_exhausted(0, 0, 3));
        assert!(!review_runtime_failures_exhausted(1, 0, 3));
        assert!(!review_runtime_failures_exhausted(0, 2, 3));
        assert!(review_runtime_failures_exhausted(1, 2, 3));
        assert!(review_runtime_failures_exhausted(0, 3, 3));
        assert!(review_runtime_failures_exhausted(2, 2, 3));
        let feedback = review_runtime_blocked_feedback(1, 2, 3, "Last error: boom");
        assert!(feedback.contains("1 failed"));
        assert!(feedback.contains("2 lost"));
        assert!(feedback.contains("limit 3"));
    }

    #[tokio::test]
    async fn expired_reviewer_leases_are_bounded_as_runtime_failures() {
        let db = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let now = Utc::now().to_rfc3339();
        let expired = "2000-01-01T00:00:00+00:00";
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4().to_string();
        let worker_id = Uuid::new_v4().to_string();
        let reviewer_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        for (id, role) in [(&worker_id, "worker"), (&reviewer_id, "reviewer")] {
            sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
                .bind(id).bind(role).bind(role).bind("idle").bind("linux").bind("x86_64")
                .bind(PROTOCOL_VERSION as i64).bind("test").bind(&now).bind(&now)
                .execute(&db).await.unwrap();
        }
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,review_feedback,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(&task_id).bind(&project_id).bind("lease loop").bind("").bind("").bind("review").bind("").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let execution_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&execution_id).bind(&task_id).bind(&worker_id).bind(1_i64).bind("completed").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict) VALUES(?,?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&execution_id).bind(&reviewer_id)
            .bind("failed").bind(&now).bind(&now).bind(r#"{"error":"runner crashed"}"#)
            .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&execution_id).bind(&reviewer_id)
            .bind("assigned").bind(expired).bind(&now)
            .execute(&db).await.unwrap();
        reap_once(&db).await.unwrap();
        let task_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?").bind(&task_id).fetch_one(&db).await.unwrap();
        assert_eq!(task_state, "review");
        let lost: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state='lost'").bind(&task_id).fetch_one(&db).await.unwrap();
        assert_eq!(lost, 1);
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&execution_id).bind(&reviewer_id)
            .bind("assigned").bind(expired).bind(&now)
            .execute(&db).await.unwrap();
        reap_once(&db).await.unwrap();
        let task_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?").bind(&task_id).fetch_one(&db).await.unwrap();
        assert_eq!(task_state, "blocked");
        let feedback: String = sqlx::query_scalar("SELECT review_feedback FROM tasks WHERE id=?").bind(&task_id).fetch_one(&db).await.unwrap();
        assert!(feedback.contains("1 failed"), "feedback: {feedback}");
        assert!(feedback.contains("2 lost"), "feedback: {feedback}");
        assert!(feedback.contains("limit 3"), "feedback: {feedback}");
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=?").bind(&task_id).fetch_one(&db).await.unwrap();
        assert_eq!(total, 3);
        let state = Arc::new(AppState { db, public_url: None, oauth_password: None, git_credential_key: None, git_root: std::env::temp_dir(), agent_auth_updates: Default::default(), model_refresh_requests: Default::default(), oauth_login_states: Default::default(), interactive_sandboxes: Default::default() });
        let task_uuid = Uuid::parse_str(&task_id).unwrap();
        let Json(status) = task_status(State(state.clone()), Path(task_uuid)).await.unwrap();
        assert_eq!(status.current_cycle_reviewer_retries, 0);
        assert_eq!(status.lifetime_reviewer_retries, 0);
        assert_eq!(status.completed_reviews, 0);
        assert_eq!(status.review_runtime_failures, 1);
        assert_eq!(status.review_lost_leases, 2);
        let board = task_board(State(state.clone())).await.unwrap().0;
        assert_eq!(board.len(), 1);
        assert_eq!(board[0].review_rounds, 0);
        assert_eq!(board[0].review_runtime_failures, 1);
        assert_eq!(board[0].review_lost_leases, 2);
        assert_eq!(status.candidate_completed_reviews, 0);
        assert_eq!(status.candidate_completed_approvals, 0);
        assert_eq!(status.candidate_completed_retries, 0);
        assert_eq!(status.candidate_runtime_failures, 1);
        assert_eq!(status.candidate_lost_leases, 2);
    }

    #[tokio::test]
    async fn stale_expired_review_never_blocks_new_candidate() {
        let db = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let now = Utc::now().to_rfc3339();
        let expired = "2000-01-01T00:00:00+00:00";
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4().to_string();
        let worker_id = Uuid::new_v4().to_string();
        let reviewer_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        for (id, role) in [(&worker_id, "worker"), (&reviewer_id, "reviewer")] {
            sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
                .bind(id).bind(role).bind(role).bind("idle").bind("linux").bind("x86_64")
                .bind(PROTOCOL_VERSION as i64).bind("test").bind(&now).bind(&now)
                .execute(&db).await.unwrap();
        }
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,review_feedback,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(&task_id).bind(&project_id).bind("stale").bind("").bind("").bind("review").bind("").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let old_execution = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&old_execution).bind(&task_id).bind(&worker_id).bind(1_i64).bind("completed").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let latest_execution = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&latest_execution).bind(&task_id).bind(&worker_id).bind(2_i64).bind("completed").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        for _ in 0..2 {
            sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict) VALUES(?,?,?,?,?,?,?,?)")
                .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&old_execution).bind(&reviewer_id)
                .bind("failed").bind(&now).bind(&now).bind(r#"{"error":"old runner crashed"}"#)
                .execute(&db).await.unwrap();
        }
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&old_execution).bind(&reviewer_id)
            .bind("assigned").bind(expired).bind(&now)
            .execute(&db).await.unwrap();
        reap_once(&db).await.unwrap();
        let stale_lost: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND execution_id=? AND state='lost'")
            .bind(&task_id).bind(&old_execution).fetch_one(&db).await.unwrap();
        assert_eq!(stale_lost, 1);
        let task_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?").bind(&task_id).fetch_one(&db).await.unwrap();
        assert_eq!(task_state, "review");
        let feedback: String = sqlx::query_scalar("SELECT review_feedback FROM tasks WHERE id=?").bind(&task_id).fetch_one(&db).await.unwrap();
        assert!(feedback.is_empty(), "stale candidate must not write blocked feedback, got: {feedback}");
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=?").bind(&task_id).fetch_one(&db).await.unwrap();
        assert_eq!(total, 3);
    }

    #[tokio::test]
    async fn review_reclaim_via_claim_review_is_bounded() {
        use axum::http::HeaderMap;
        let db = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let now = Utc::now().to_rfc3339();
        let expired = "2000-01-01T00:00:00+00:00";
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4().to_string();
        let worker_id = Uuid::new_v4().to_string();
        let reviewer_id = Uuid::new_v4();
        let reviewer_cred = "test-reviewer-cred";
        let reviewer_hash = hash_secret(reviewer_cred);
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,git_auth_mode,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind("host").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at,allowed_projects,credential_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(worker_id.clone()).bind("worker").bind("worker").bind("idle").bind("linux").bind("x86_64")
            .bind(PROTOCOL_VERSION as i64).bind("test").bind(&now).bind(&now).bind(r#"["*"]"#).bind(Option::<String>::None)
            .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at,allowed_projects,credential_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(reviewer_id.to_string()).bind("reviewer").bind("reviewer").bind("idle").bind("linux").bind("x86_64")
            .bind(PROTOCOL_VERSION as i64).bind("test").bind(&now).bind(&now).bind(r#"["*"]"#).bind(&reviewer_hash)
            .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,review_feedback,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(&task_id).bind(&project_id).bind("claim loop").bind("").bind("").bind("review").bind("").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let execution_id = Uuid::new_v4().to_string();
        let result_json = serde_json::json!({"status":"completed","summary":"x","commit_sha":"abc123","base_sha":"base","review_ref":"refs/task/candidate","integration":{"candidate_sha":"abc123","candidate_base_sha":"base","upstream_sha":"upstream-pinned","integration_sha":"integration-pinned","effective_diff_hash":"diff-hash","conflict":null}}).to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,result) VALUES(?,?,?,?,?,?,?,?)")
            .bind(&execution_id).bind(&task_id).bind(&worker_id).bind(1_i64).bind("completed").bind(&now).bind(&now).bind(&result_json)
            .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict,upstream_sha,integration_sha,effective_diff_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&execution_id).bind(reviewer_id.to_string())
            .bind("failed").bind(&now).bind(&now).bind(r#"{"error":"runner crashed"}"#)
            .bind("upstream-pinned").bind("integration-pinned").bind("diff-hash")
            .execute(&db).await.unwrap();
        let state = Arc::new(AppState { db, public_url: Some("https://example.com".into()), oauth_password: None, git_credential_key: None, git_root: std::env::temp_dir(), agent_auth_updates: Default::default(), model_refresh_requests: Default::default(), oauth_login_states: Default::default(), interactive_sandboxes: Default::default() });
        let headers = || {
            let mut h = HeaderMap::new();
            h.insert("x-lazyteam-worker-credential", reviewer_cred.parse().unwrap());
            h
        };
        let is_assignment = |response: axum::response::Response| response.status() != axum::http::StatusCode::NO_CONTENT;
        let claimed_first = claim_review(Path(reviewer_id), State(state.clone()), headers()).await.unwrap();
        assert!(is_assignment(claimed_first), "below-limit reclaim must allow another reviewer claim");
        let active: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=? AND state IN ('assigned','running')")
            .bind(&task_id).fetch_one(&state.db).await.unwrap();
        assert_eq!(active, 1);
        let active_id: String = sqlx::query_scalar("SELECT id FROM reviews WHERE task_id=? AND state IN ('assigned','running') LIMIT 1")
            .bind(&task_id).fetch_one(&state.db).await.unwrap();
        sqlx::query("UPDATE reviews SET lease_until=? WHERE id=?").bind(expired).bind(&active_id).execute(&state.db).await.unwrap();
        reap_once(&state.db).await.unwrap();
        let task_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?").bind(&task_id).fetch_one(&state.db).await.unwrap();
        assert_eq!(task_state, "review");
        let claimed_second = claim_review(Path(reviewer_id), State(state.clone()), headers()).await.unwrap();
        assert!(is_assignment(claimed_second), "at 2/3 failures reclaim must still be allowed");
        let active_id2: String = sqlx::query_scalar("SELECT id FROM reviews WHERE task_id=? AND state IN ('assigned','running') LIMIT 1")
            .bind(&task_id).fetch_one(&state.db).await.unwrap();
        sqlx::query("UPDATE reviews SET lease_until=? WHERE id=?").bind(expired).bind(&active_id2).execute(&state.db).await.unwrap();
        reap_once(&state.db).await.unwrap();
        let task_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?").bind(&task_id).fetch_one(&state.db).await.unwrap();
        assert_eq!(task_state, "blocked");
        let feedback: String = sqlx::query_scalar("SELECT review_feedback FROM tasks WHERE id=?").bind(&task_id).fetch_one(&state.db).await.unwrap();
        assert!(feedback.contains("1 failed"), "feedback: {feedback}");
        assert!(feedback.contains("2 lost"), "feedback: {feedback}");
        assert!(feedback.contains("limit 3"), "feedback: {feedback}");
        let claimed_third = claim_review(Path(reviewer_id), State(state.clone()), headers()).await.unwrap();
        assert!(!is_assignment(claimed_third), "at-limit claim must stop automatic reclaim");
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM reviews WHERE task_id=?").bind(&task_id).fetch_one(&state.db).await.unwrap();
        assert_eq!(total, 3);
    }

    #[tokio::test]
    async fn mixed_review_counters_keep_completed_separate_from_runtime() {
        let db = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4().to_string();
        let worker_id = Uuid::new_v4().to_string();
        let reviewer_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        for (id, role) in [(&worker_id, "worker"), (&reviewer_id, "reviewer")] {
            sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
                .bind(id).bind(role).bind(role).bind("idle").bind("linux").bind("x86_64")
                .bind(PROTOCOL_VERSION as i64).bind("test").bind(&now).bind(&now)
                .execute(&db).await.unwrap();
        }
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,review_feedback,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(&task_id).bind(&project_id).bind("mixed").bind("").bind("").bind("review").bind("").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let execution_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&execution_id).bind(&task_id).bind(&worker_id).bind(1_i64).bind("completed").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        for (verdict, state) in [
            (r#"{"verdict":"retry","reason":"fix it","validation":[]}"#, "completed"),
            (r#"{"verdict":"approve","reason":"ok","validation":[]}"#, "completed"),
            (r#"{"error":"runner crashed"}"#, "failed"),
        ] {
            sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict) VALUES(?,?,?,?,?,?,?,?)")
                .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&execution_id).bind(&reviewer_id)
                .bind(state).bind(&now).bind(&now).bind(verdict)
                .execute(&db).await.unwrap();
        }
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&execution_id).bind(&reviewer_id)
            .bind("lost").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let state = Arc::new(AppState { db, public_url: None, oauth_password: None, git_credential_key: None, git_root: std::env::temp_dir(), agent_auth_updates: Default::default(), model_refresh_requests: Default::default(), oauth_login_states: Default::default(), interactive_sandboxes: Default::default() });
        let task_uuid = Uuid::parse_str(&task_id).unwrap();
        let Json(status) = task_status(State(state.clone()), Path(task_uuid)).await.unwrap();
        assert_eq!(status.completed_reviews, 2);
        assert_eq!(status.review_runtime_failures, 1);
        assert_eq!(status.review_lost_leases, 1);
        assert_eq!(status.current_cycle_reviewer_retries, 1);
        assert_eq!(status.lifetime_reviewer_retries, 1);
        // Per-candidate denominator is unambiguous for the latest execution.
        assert_eq!(status.candidate_completed_reviews, 2);
        assert_eq!(status.candidate_completed_approvals, 1);
        assert_eq!(status.candidate_completed_retries, 1);
        assert_eq!(status.candidate_runtime_failures, 1);
        assert_eq!(status.candidate_lost_leases, 1);
        let board = task_board(State(state.clone())).await.unwrap().0;
        assert_eq!(board.len(), 1);
        assert_eq!(board[0].review_rounds, 2);
        assert_eq!(board[0].review_runtime_failures, 1);
        assert_eq!(board[0].review_lost_leases, 1);
        assert_eq!(board[0].current_cycle_reviewer_retries, 1);
        assert_eq!(board[0].lifetime_reviewer_retries, 1);
        assert_eq!(board[0].reviewer_retries, 1);
    }

    #[tokio::test]
    async fn mixed_candidates_keep_per_candidate_denominator() {
        let db = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4().to_string();
        let worker_id = Uuid::new_v4().to_string();
        let reviewer_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        for (id, role) in [(&worker_id, "worker"), (&reviewer_id, "reviewer")] {
            sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
                .bind(id).bind(role).bind(role).bind("idle").bind("linux").bind("x86_64")
                .bind(PROTOCOL_VERSION as i64).bind("test").bind(&now).bind(&now)
                .execute(&db).await.unwrap();
        }
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,review_feedback,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(&task_id).bind(&project_id).bind("two candidates").bind("").bind("").bind("review").bind("").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let old_execution = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&old_execution).bind(&task_id).bind(&worker_id).bind(1_i64).bind("completed").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let latest_execution = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&latest_execution).bind(&task_id).bind(&worker_id).bind(2_i64).bind("completed").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict) VALUES(?,?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&old_execution).bind(&reviewer_id)
            .bind("completed").bind(&now).bind(&now).bind(r#"{"verdict":"retry","reason":"old fix","validation":[]}"#)
            .execute(&db).await.unwrap();
        for (verdict, state) in [
            (r#"{"verdict":"approve","reason":"ok","validation":[]}"#, "completed"),
            (r#"{"error":"runner crashed"}"#, "failed"),
        ] {
            sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict) VALUES(?,?,?,?,?,?,?,?)")
                .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&latest_execution).bind(&reviewer_id)
                .bind(state).bind(&now).bind(&now).bind(verdict)
                .execute(&db).await.unwrap();
        }
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(&task_id).bind(&latest_execution).bind(&reviewer_id)
            .bind("lost").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let state = Arc::new(AppState { db, public_url: None, oauth_password: None, git_credential_key: None, git_root: std::env::temp_dir(), agent_auth_updates: Default::default(), model_refresh_requests: Default::default(), oauth_login_states: Default::default(), interactive_sandboxes: Default::default() });
        let task_uuid = Uuid::parse_str(&task_id).unwrap();
        let Json(status) = task_status(State(state.clone()), Path(task_uuid)).await.unwrap();
        assert_eq!(status.completed_reviews, 2);
        assert_eq!(status.lifetime_reviewer_retries, 1);
        assert_eq!(status.review_runtime_failures, 1);
        assert_eq!(status.review_lost_leases, 1);
        assert_eq!(status.candidate_completed_reviews, 1);
        assert_eq!(status.candidate_completed_approvals, 1);
        assert_eq!(status.candidate_completed_retries, 0);
        assert_eq!(status.candidate_runtime_failures, 1);
        assert_eq!(status.candidate_lost_leases, 1);
    }

    async fn waiting_test_db() -> SqlitePool {
        let db = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        db
    }

    fn waiting_state(db: SqlitePool) -> Arc<AppState> {
        Arc::new(AppState { db, public_url: None, oauth_password: None, git_credential_key: None, git_root: std::env::temp_dir(), agent_auth_updates: Default::default(), model_refresh_requests: Default::default(), oauth_login_states: Default::default(), interactive_sandboxes: Default::default() })
    }

    async fn seed_backend_ready_worker(db: &SqlitePool, id: &str, name: &str, role: &str, now: &str, cred: Option<&str>) {
        seed_backend_ready_worker_scoped(db, id, name, role, now, cred, r#"["*"]"#).await;
    }

    async fn seed_backend_ready_worker_scoped(db: &SqlitePool, id: &str, name: &str, role: &str, now: &str, cred: Option<&str>, allowed_projects: &str) {
        let hash = cred.map(hash_secret);
        sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at,allowed_projects,credential_hash,agent_provider,agent_model,agent_capabilities) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(id).bind(name).bind(role).bind("idle").bind("linux").bind("x86_64")
            .bind(PROTOCOL_VERSION as i64).bind("test").bind(now).bind(now).bind(allowed_projects).bind(hash)
            .bind("prov").bind("mod")
            .bind(r#"{"models":[{"provider":"prov","id":"mod"}]}"#)
            .execute(db).await.unwrap();
    }

    /// Credentialed worker with no Host provider/model selection and an
    /// empty Pi catalog: live by the server predicates but never
    /// backend-ready. Used to prove reservation reasons follow the exact
    /// claim predicate rather than backend readiness.
    async fn seed_worker_no_backend(db: &SqlitePool, id: &str, name: &str, role: &str, now: &str, cred: &str) {
        let hash = hash_secret(cred);
        sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at,allowed_projects,credential_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(id).bind(name).bind(role).bind("idle").bind("linux").bind("x86_64")
            .bind(PROTOCOL_VERSION as i64).bind("test").bind(now).bind(now).bind(r#"["*"]"#).bind(hash)
            .execute(db).await.unwrap();
    }

    fn worker_headers(cred: &str) -> axum::http::HeaderMap {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-lazyteam-worker-credential", cred.parse().unwrap());
        headers
    }

    async fn waiting_reason(db: &SqlitePool, task_id: Uuid) -> (String, String) {
        let row = sqlx::query("SELECT * FROM tasks WHERE id=?").bind(task_id.to_string()).fetch_one(db).await.unwrap();
        let task = task_from_row(&row).unwrap();
        waiting_for_task(db, &task).await.unwrap().map(|w| (w.reason, w.detail)).unwrap()
    }

    #[tokio::test]
    async fn waiting_dependency_matches_claim_refusal() {
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let dep_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4();
        let cred = "dep-cred";
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        seed_backend_ready_worker(&db, &worker_id.to_string(), "w", "worker", &now, Some(cred)).await;
        for (id, state) in [(&dep_id.to_string(), "blocked"), (&task_id.to_string(), "queued")] {
            let deps = if id == &task_id.to_string() { serde_json::to_string(&vec![dep_id]).unwrap() } else { "[]".into() };
            sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,dependencies,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
                .bind(id).bind(&project_id).bind("t").bind("").bind("").bind(state).bind(deps).bind(&now).bind(&now)
                .execute(&db).await.unwrap();
        }
        let state = waiting_state(db.clone());
        let response = claim_task(Path(worker_id), State(state.clone()), worker_headers(cred)).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        let (reason, detail) = waiting_reason(&db, task_id).await;
        assert_eq!(reason, "blocked_dependencies");
        assert!(detail.contains("dependency") || detail.contains("waiting"), "detail: {detail}");
        let Json(status) = task_status(State(state.clone()), Path(task_id)).await.unwrap();
        assert_eq!(status.waiting.as_ref().map(|w| w.reason.as_str()), Some("blocked_dependencies"));
        assert!(!status.waiting.as_ref().unwrap().detail.contains("ltw_") && !status.waiting.as_ref().unwrap().detail.contains("token"));
        // The same reason is exposed in the task-board payload Home renders.
        let board = task_board(State(state.clone())).await.unwrap().0;
        let item = board.iter().find(|item| item.task.id == task_id).expect("task on board");
        assert_eq!(item.waiting.as_ref().map(|w| w.reason.as_str()), Some("blocked_dependencies"));
    }

    #[tokio::test]
    async fn waiting_tag_scope_matches_claim_refusal() {
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4();
        let cred = "tag-cred";
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        seed_backend_ready_worker(&db, &worker_id.to_string(), "w", "worker", &now, Some(cred)).await;
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,required_tags,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(&project_id).bind("t").bind("").bind("").bind("queued")
            .bind(r#"{"gpu":"true"}"#).bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let state = waiting_state(db.clone());
        let response = claim_task(Path(worker_id), State(state.clone()), worker_headers(cred)).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        let (reason, detail) = waiting_reason(&db, task_id).await;
        assert_eq!(reason, "no_eligible_worker");
        assert!(detail.contains("gpu"), "detail: {detail}");
    }

    #[tokio::test]
    async fn waiting_project_scope_matches_claim_refusal() {
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4();
        let cred = "scope-cred";
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        // Worker matches every tag but is scoped to another project, so the
        // project-scope predicate (shared with claim selection) refuses it.
        seed_backend_ready_worker_scoped(&db, &worker_id.to_string(), "w", "worker", &now, Some(cred), r#"["other"]"#).await;
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(&project_id).bind("t").bind("").bind("").bind("queued").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let state = waiting_state(db.clone());
        let response = claim_task(Path(worker_id), State(state.clone()), worker_headers(cred)).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        let (reason, detail) = waiting_reason(&db, task_id).await;
        assert_eq!(reason, "no_eligible_worker");
        assert!(detail.contains("project scope"), "detail: {detail}");
        let board = task_board(State(state.clone())).await.unwrap().0;
        let item = board.iter().find(|item| item.task.id == task_id).expect("task on board");
        assert_eq!(item.waiting.as_ref().map(|w| w.reason.as_str()), Some("no_eligible_worker"));
    }

    #[tokio::test]
    async fn waiting_sticky_affinity_matches_claim_refusal() {
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4();
        let sticky_id = Uuid::new_v4();
        let claimant_id = Uuid::new_v4();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        seed_backend_ready_worker(&db, &sticky_id.to_string(), "sticky", "worker", &now, Some("sticky-cred")).await;
        seed_backend_ready_worker(&db, &claimant_id.to_string(), "claimant", "worker", &now, Some("claim-cred")).await;
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,sticky_worker_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(&project_id).bind("t").bind("").bind("").bind("queued")
            .bind(sticky_id.to_string()).bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let state = waiting_state(db.clone());
        let response = claim_task(Path(claimant_id), State(state), worker_headers("claim-cred")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        let (reason, detail) = waiting_reason(&db, task_id).await;
        assert_eq!(reason, "sticky_reserved");
        assert!(detail.contains("sticky"), "detail: {detail}");
    }

    #[tokio::test]
    async fn waiting_no_slot_matches_claim_refusal() {
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4();
        let cred = "slot-cred";
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        seed_backend_ready_worker(&db, &worker_id.to_string(), "w", "worker", &now, Some(cred)).await;
        sqlx::query("UPDATE workers SET running_slots=1,slots=1,state='busy' WHERE id=?")
            .bind(worker_id.to_string()).execute(&db).await.unwrap();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(&project_id).bind("t").bind("").bind("").bind("queued").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let state = waiting_state(db.clone());
        let response = claim_task(Path(worker_id), State(state), worker_headers(cred)).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        let (reason, _) = waiting_reason(&db, task_id).await;
        assert_eq!(reason, "no_free_slot");
    }

    #[tokio::test]
    async fn waiting_self_review_beats_failure_limit() {
        // The only reviewer is the implementation worker (reassigned to the
        // reviewer role) and the failure budget is exhausted. `claim_review`
        // rejects them for self-review before consulting the budget, so
        // diagnostics must report eligibility, never the budget.
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4();
        let history_id = Uuid::new_v4().to_string();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        seed_backend_ready_worker(&db, &worker_id.to_string(), "w", "reviewer", &now, Some("w-cred")).await;
        seed_backend_ready_worker(&db, &history_id, "old", "reviewer", &now, Some("old-cred")).await;
        // The history owner is stopped, so it is neither a live preferred
        // reviewer nor a live pool member: the only live reviewer is the
        // implementation worker itself.
        sqlx::query("UPDATE workers SET last_heartbeat_at=?,state='draining' WHERE id=?")
            .bind("2000-01-01T00:00:00+00:00").bind(&history_id).execute(&db).await.unwrap();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(&project_id).bind("t").bind("").bind("").bind("review").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let execution_id = Uuid::new_v4().to_string();
        let result_json = serde_json::json!({"status":"completed","summary":"x","commit_sha":"abc","base_sha":"base","review_ref":"refs/task/candidate"}).to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,result) VALUES(?,?,?,?,?,?,?,?)")
            .bind(&execution_id).bind(task_id.to_string()).bind(worker_id.to_string()).bind(1_i64).bind("completed").bind(&now).bind(&now).bind(&result_json)
            .execute(&db).await.unwrap();
        for i in 0..2 {
            sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict) VALUES(?,?,?,?,?,?,?,?)")
                .bind(Uuid::new_v4().to_string()).bind(task_id.to_string()).bind(&execution_id).bind(&history_id)
                .bind("failed").bind(&now).bind(&now).bind(format!(r#"{{"error":"boom {i}"}}"#))
                .execute(&db).await.unwrap();
        }
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(task_id.to_string()).bind(&execution_id).bind(&history_id)
            .bind("lost").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let state = waiting_state(db.clone());
        let response = claim_review(Path(worker_id), State(state), worker_headers("w-cred")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        let (reason, detail) = waiting_reason(&db, task_id).await;
        assert_eq!(reason, "no_eligible_reviewer");
        assert!(detail.contains("self-review"), "detail: {detail}");
    }

    #[tokio::test]
    async fn waiting_dependency_detail_is_exact_past_display_window() {
        // 51 done dependencies followed by one blocked dependency: the
        // unresolved dep sits past the old 50-item window, yet the detail
        // must still name it with an exact count.
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4();
        let cred = "dep-cred";
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        seed_backend_ready_worker(&db, &worker_id.to_string(), "w", "worker", &now, Some(cred)).await;
        let mut deps = Vec::new();
        for (id, state) in (0..51).map(|_| (Uuid::new_v4(), "done")).chain(std::iter::once((Uuid::new_v4(), "blocked"))) {
            sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
                .bind(id.to_string()).bind(&project_id).bind("d").bind("").bind("").bind(state).bind(&now).bind(&now)
                .execute(&db).await.unwrap();
            deps.push(id);
        }
        let blocked = deps.last().unwrap();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,dependencies,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(&project_id).bind("t").bind("").bind("").bind("queued")
            .bind(serde_json::to_string(&deps).unwrap()).bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let (reason, detail) = waiting_reason(&db, task_id).await;
        assert_eq!(reason, "blocked_dependencies");
        let sample: String = blocked.to_string().chars().take(8).collect();
        assert_eq!(detail, format!("waiting on dependency {sample}"));
    }

    #[tokio::test]
    async fn waiting_reviewer_cooldown_matches_claim_refusal() {
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4().to_string();
        let reviewer_id = Uuid::new_v4();
        // Prior runtime history belongs to a stale-heartbeat reviewer, so no
        // live preferred reviewer reserves the task and the failure budget
        // is the reason the claimant is refused.
        let history_id = Uuid::new_v4().to_string();
        let cred = "reviewer-cred";
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        seed_backend_ready_worker(&db, &worker_id, "impl", "worker", &now, None).await;
        seed_backend_ready_worker(&db, &reviewer_id.to_string(), "rev", "reviewer", &now, Some(cred)).await;
        seed_backend_ready_worker(&db, &history_id, "old", "reviewer", &now, Some("old-cred")).await;
        sqlx::query("UPDATE workers SET last_heartbeat_at=? WHERE id=?")
            .bind("2000-01-01T00:00:00+00:00").bind(&history_id).execute(&db).await.unwrap();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(&project_id).bind("t").bind("").bind("").bind("review").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let execution_id = Uuid::new_v4().to_string();
        let result_json = serde_json::json!({"status":"completed","summary":"x","commit_sha":"abc","base_sha":"base","review_ref":"refs/task/candidate"}).to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,result) VALUES(?,?,?,?,?,?,?,?)")
            .bind(&execution_id).bind(task_id.to_string()).bind(&worker_id).bind(1_i64).bind("completed").bind(&now).bind(&now).bind(&result_json)
            .execute(&db).await.unwrap();
        for i in 0..2 {
            sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict) VALUES(?,?,?,?,?,?,?,?)")
                .bind(Uuid::new_v4().to_string()).bind(task_id.to_string()).bind(&execution_id).bind(&history_id)
                .bind("failed").bind(&now).bind(&now).bind(format!(r#"{{"error":"boom {i}"}}"#))
                .execute(&db).await.unwrap();
        }
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(task_id.to_string()).bind(&execution_id).bind(&history_id)
            .bind("lost").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let (reason, detail) = waiting_reason(&db, task_id).await;
        assert_eq!(reason, "review_failure_limit");
        assert!(detail.contains("limit 3"), "detail: {detail}");
        let state = waiting_state(db.clone());
        // The same cooldown reason is exposed in the task-board payload.
        let board = task_board(State(state.clone())).await.unwrap().0;
        let item = board.iter().find(|item| item.task.id == task_id).expect("task on board");
        assert_eq!(item.waiting.as_ref().map(|w| w.reason.as_str()), Some("review_failure_limit"));
        let response = claim_review(Path(reviewer_id), State(state), worker_headers(cred)).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn waiting_sticky_beats_backend_unavailable_for_preferred() {
        // The sticky worker is live by the exact server reservation
        // predicate but has no Host backend, so the pool alone would say
        // `backend_unavailable`. `claim_task` still refuses other workers
        // for the sticky reservation, and diagnostics must agree.
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4();
        let sticky_id = Uuid::new_v4();
        let claimant_id = Uuid::new_v4();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        seed_worker_no_backend(&db, &sticky_id.to_string(), "sticky", "worker", &now, "sticky-cred").await;
        seed_backend_ready_worker(&db, &claimant_id.to_string(), "claimant", "worker", &now, Some("claim-cred")).await;
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,sticky_worker_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(&project_id).bind("t").bind("").bind("").bind("queued")
            .bind(sticky_id.to_string()).bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let state = waiting_state(db.clone());
        let response = claim_task(Path(claimant_id), State(state), worker_headers("claim-cred")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        let (reason, _) = waiting_reason(&db, task_id).await;
        assert_eq!(reason, "sticky_reserved");
    }

    #[tokio::test]
    async fn waiting_reviewer_reservation_beats_full_slots() {
        // The preferred reviewer is live by the exact reservation predicate
        // but holds no free slot. `claim_review` refuses other reviewers
        // for the reservation before capacity is ever considered.
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4().to_string();
        let preferred_id = Uuid::new_v4();
        let claimant_id = Uuid::new_v4();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        seed_backend_ready_worker(&db, &worker_id, "impl", "worker", &now, None).await;
        seed_backend_ready_worker(&db, &preferred_id.to_string(), "preferred", "reviewer", &now, Some("pref-cred")).await;
        seed_backend_ready_worker(&db, &claimant_id.to_string(), "claimant", "reviewer", &now, Some("claim-cred")).await;
        sqlx::query("UPDATE workers SET running_slots=1,slots=1,state='busy' WHERE id=?")
            .bind(preferred_id.to_string()).execute(&db).await.unwrap();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(&project_id).bind("t").bind("").bind("").bind("review").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let execution_id = Uuid::new_v4().to_string();
        let result_json = serde_json::json!({"status":"completed","summary":"x","commit_sha":"abc","base_sha":"base","review_ref":"refs/task/candidate"}).to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,result) VALUES(?,?,?,?,?,?,?,?)")
            .bind(&execution_id).bind(task_id.to_string()).bind(&worker_id).bind(1_i64).bind("completed").bind(&now).bind(&now).bind(&result_json)
            .execute(&db).await.unwrap();
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict) VALUES(?,?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(task_id.to_string()).bind(&execution_id).bind(preferred_id.to_string())
            .bind("completed").bind(&now).bind(&now).bind(r#"{"verdict":"retry","reason":"fix it","validation":[]}"#)
            .execute(&db).await.unwrap();
        let state = waiting_state(db.clone());
        let response = claim_review(Path(claimant_id), State(state), worker_headers("claim-cred")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        let task_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
            .bind(task_id.to_string()).fetch_one(&db).await.unwrap();
        assert_eq!(task_state, "review");
        let (reason, _) = waiting_reason(&db, task_id).await;
        assert_eq!(reason, "reviewer_reserved");
    }

    #[tokio::test]
    async fn waiting_reviewer_reservation_beats_failure_limit() {
        // Failure budget is exhausted AND a preferred reviewer is live.
        // `claim_review` checks the reservation first, so another reviewer
        // is refused for affinity without tripping the failure-limit block;
        // diagnostics must report the same primary reason.
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4().to_string();
        let task_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4().to_string();
        let preferred_id = Uuid::new_v4();
        let claimant_id = Uuid::new_v4();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(&project_id).bind("p").bind("P").bind("https://example/repo.git").bind("main").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        seed_backend_ready_worker(&db, &worker_id, "impl", "worker", &now, None).await;
        seed_backend_ready_worker(&db, &preferred_id.to_string(), "preferred", "reviewer", &now, Some("pref-cred")).await;
        seed_backend_ready_worker(&db, &claimant_id.to_string(), "claimant", "reviewer", &now, Some("claim-cred")).await;
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(&project_id).bind("t").bind("").bind("").bind("review").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let execution_id = Uuid::new_v4().to_string();
        let result_json = serde_json::json!({"status":"completed","summary":"x","commit_sha":"abc","base_sha":"base","review_ref":"refs/task/candidate"}).to_string();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,result) VALUES(?,?,?,?,?,?,?,?)")
            .bind(&execution_id).bind(task_id.to_string()).bind(&worker_id).bind(1_i64).bind("completed").bind(&now).bind(&now).bind(&result_json)
            .execute(&db).await.unwrap();
        for i in 0..2 {
            sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at,verdict) VALUES(?,?,?,?,?,?,?,?)")
                .bind(Uuid::new_v4().to_string()).bind(task_id.to_string()).bind(&execution_id).bind(preferred_id.to_string())
                .bind("failed").bind(&now).bind(&now).bind(format!(r#"{{"error":"boom {i}"}}"#))
                .execute(&db).await.unwrap();
        }
        sqlx::query("INSERT INTO reviews(id,task_id,execution_id,reviewer_worker_id,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(Uuid::new_v4().to_string()).bind(task_id.to_string()).bind(&execution_id).bind(preferred_id.to_string())
            .bind("lost").bind(&now).bind(&now)
            .execute(&db).await.unwrap();
        let state = waiting_state(db.clone());
        let response = claim_review(Path(claimant_id), State(state), worker_headers("claim-cred")).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NO_CONTENT);
        let task_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
            .bind(task_id.to_string()).fetch_one(&db).await.unwrap();
        assert_eq!(task_state, "review");
        let (reason, _) = waiting_reason(&db, task_id).await;
        assert_eq!(reason, "reviewer_reserved");
    }

    async fn seed_oauth_worker(db: &SqlitePool, id: &Uuid, now: &str, cred: &str) {
        let catalog = serde_json::json!({
            "model_discovery": true,
            "providers": [
                {"id": "openai-codex", "name": "OpenAI Codex", "configured": false, "oauth_label": "OpenAI (ChatGPT Plus/Pro)"},
                {"id": "key-only", "name": "Key Only", "configured": false, "api_key_label": "API key"},
                {"id": "bare", "name": "Bare", "configured": false}
            ],
            "models": []
        }).to_string();
        sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at,allowed_projects,credential_hash,agent_capabilities) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)")
            .bind(id.to_string()).bind("oauth-worker").bind("worker").bind("idle").bind("linux").bind("x86_64")
            .bind(PROTOCOL_VERSION as i64).bind("test").bind(now).bind(now).bind(r#"["*"]"#).bind(hash_secret(cred)).bind(catalog)
            .execute(db).await.unwrap();
    }

    fn oauth_event(kind: &str) -> AgentOAuthEventInput {
        AgentOAuthEventInput {
            kind: kind.into(),
            message: None,
            verification_uri: None,
            user_code: None,
            authorization_url: None,
            paste_prompt: None,
            paste_placeholder: None,
        }
    }

    #[tokio::test]
    async fn provider_key_delivery_waits_for_ack_and_preserves_order() {
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let worker_id = Uuid::new_v4();
        seed_oauth_worker(&db, &worker_id, &now, "oauth-cred").await;
        let state = waiting_state(db.clone());

        let Json(first) = queue_worker_provider_key(
            Path(worker_id),
            State(state.clone()),
            Json(AgentApiKeyInput { provider: "key-only".into(), api_key: "secret-a".into() }),
        ).await.unwrap();
        let Json(second) = queue_worker_provider_key(
            Path(worker_id),
            State(state.clone()),
            Json(AgentApiKeyInput { provider: "key-only".into(), api_key: "secret-b".into() }),
        ).await.unwrap();

        {
            let updates = state.agent_auth_updates.lock().await;
            let queue = updates.get(&worker_id).unwrap();
            assert_eq!(queue.len(), 2);
            assert_eq!(queue.front().unwrap().id, first.id);
            assert_eq!(queue.back().unwrap().id, second.id);
        }

        let response = worker_agent_auth(
            Path(worker_id),
            State(state.clone()),
            worker_headers("oauth-cred"),
        ).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(state.agent_auth_updates.lock().await.get(&worker_id).unwrap().len(), 2);

        let err = ack_worker_agent_auth(
            Path((worker_id, second.id)),
            State(state.clone()),
            worker_headers("oauth-cred"),
        ).await.unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);

        ack_worker_agent_auth(
            Path((worker_id, first.id)),
            State(state.clone()),
            worker_headers("oauth-cred"),
        ).await.unwrap();
        {
            let updates = state.agent_auth_updates.lock().await;
            let queue = updates.get(&worker_id).unwrap();
            assert_eq!(queue.len(), 1);
            assert_eq!(queue.front().unwrap().id, second.id);
        }

        ack_worker_agent_auth(
            Path((worker_id, second.id)),
            State(state.clone()),
            worker_headers("oauth-cred"),
        ).await.unwrap();
        assert!(!state.agent_auth_updates.lock().await.contains_key(&worker_id));
    }


    #[tokio::test]
    async fn model_refresh_delivery_waits_for_ack_and_preserves_order() {
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let worker_id = Uuid::new_v4();
        seed_oauth_worker(&db, &worker_id, &now, "oauth-cred").await;
        let catalog = serde_json::json!({
            "model_discovery": true,
            "providers": [
                {"id": "key-only", "name": "Key Only", "configured": true, "api_key_label": "API key"}
            ],
            "models": []
        }).to_string();
        sqlx::query("UPDATE workers SET agent_capabilities=? WHERE id=?")
            .bind(catalog)
            .bind(worker_id.to_string())
            .execute(&db).await.unwrap();
        let state = waiting_state(db.clone());

        let Json(first) = queue_worker_model_refresh(
            Path(worker_id),
            State(state.clone()),
            Json(AgentModelRefreshInput { provider: "key-only".into() }),
        ).await.unwrap();
        let Json(second) = queue_worker_model_refresh(
            Path(worker_id),
            State(state.clone()),
            Json(AgentModelRefreshInput { provider: "key-only".into() }),
        ).await.unwrap();

        {
            let requests = state.model_refresh_requests.lock().await;
            let queue = requests.get(&worker_id).unwrap();
            assert_eq!(queue.len(), 2);
            assert_eq!(queue.front().unwrap().id, first.id);
            assert_eq!(queue.back().unwrap().id, second.id);
        }

        let Json(config) = worker_runtime_config(
            Path(worker_id),
            State(state.clone()),
            worker_headers("oauth-cred"),
        ).await.unwrap();
        assert_eq!(config.model_refresh.as_ref().unwrap().id, first.id);
        assert_eq!(state.model_refresh_requests.lock().await.get(&worker_id).unwrap().len(), 2);

        let err = ack_worker_model_refresh(
            Path((worker_id, second.id)),
            State(state.clone()),
            worker_headers("oauth-cred"),
        ).await.unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);

        ack_worker_model_refresh(
            Path((worker_id, first.id)),
            State(state.clone()),
            worker_headers("oauth-cred"),
        ).await.unwrap();
        let Json(config) = worker_runtime_config(
            Path(worker_id),
            State(state.clone()),
            worker_headers("oauth-cred"),
        ).await.unwrap();
        assert_eq!(config.model_refresh.as_ref().unwrap().id, second.id);

        ack_worker_model_refresh(
            Path((worker_id, second.id)),
            State(state.clone()),
            worker_headers("oauth-cred"),
        ).await.unwrap();
        assert!(!state.model_refresh_requests.lock().await.contains_key(&worker_id));
    }

    #[tokio::test]
    async fn provider_auth_endpoints_are_capability_gated() {
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let worker_id = Uuid::new_v4();
        seed_oauth_worker(&db, &worker_id, &now, "oauth-cred").await;
        let state = waiting_state(db.clone());
        // An API-key-only provider has no OAuth capability.
        let err = start_worker_oauth_login(
            Path(worker_id),
            State(state.clone()),
            Json(AgentOAuthStartInput { provider: "key-only".into() }),
        ).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        // A provider with neither capability supports neither login.
        let err = start_worker_oauth_login(
            Path(worker_id),
            State(state.clone()),
            Json(AgentOAuthStartInput { provider: "bare".into() }),
        ).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        // An OAuth-only provider has no API-key capability.
        let err = queue_worker_provider_key(
            Path(worker_id),
            State(state.clone()),
            Json(AgentApiKeyInput { provider: "openai-codex".into(), api_key: "secret".into() }),
        ).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        // Unknown providers are rejected for both logins.
        let err = queue_worker_provider_key(
            Path(worker_id),
            State(state.clone()),
            Json(AgentApiKeyInput { provider: "nope".into(), api_key: "secret".into() }),
        ).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn pi_oauth_remote_bridge_exposes_url_and_paste_completion() {
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let worker_id = Uuid::new_v4();
        seed_oauth_worker(&db, &worker_id, &now, "oauth-cred").await;
        let state = waiting_state(db.clone());
        let Json(login) = start_worker_oauth_login(
            Path(worker_id),
            State(state.clone()),
            Json(AgentOAuthStartInput { provider: "openai-codex".into() }),
        ).await.unwrap();
        assert_eq!(login.status, "queued");
        assert!(login.message.as_deref().unwrap_or_default().contains("authorization URL"));
        // Starting another login while this one is active must not silently
        // replace the request that the worker is about to claim.
        let err = start_worker_oauth_login(
            Path(worker_id),
            State(state.clone()),
            Json(AgentOAuthStartInput { provider: "openai-codex".into() }),
        ).await.unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        assert_eq!(state.oauth_login_states.lock().await.get(&worker_id).unwrap().id, login.id);
        // The worker claims the queued request; the Host must not claim completion yet.
        let claimed = claim_worker_oauth_login(Path(worker_id), State(state.clone()), worker_headers("oauth-cred")).await.unwrap();
        assert_eq!(claimed.status(), StatusCode::OK);
        // Pi's real auth_url notify carries the worker's authorization URL.
        let mut event = oauth_event("auth_url");
        event.message = Some("A browser window should open. Complete login to finish.".into());
        event.authorization_url = Some("https://auth.openai.com/oauth/authorize?client_id=x".into());
        report_worker_oauth_login_event(Path((worker_id, login.id)), State(state.clone()), worker_headers("oauth-cred"), Json(event)).await.unwrap();
        let current = state.oauth_login_states.lock().await.get(&worker_id).cloned().unwrap();
        assert_eq!(current.status, "awaiting_authorization");
        assert_eq!(current.authorization_url.as_deref(), Some("https://auth.openai.com/oauth/authorize?client_id=x"));
        assert!(current.message.as_deref().unwrap_or_default().contains("browser window should open"));
        // Pi's manual_code prompt means its worker-local localhost callback
        // cannot be reached; the Host UI must offer the paste-back relay.
        let mut waiting = oauth_event("awaiting_input");
        waiting.message = Some("Complete login in your browser, or paste the authorization code / redirect URL here:".into());
        waiting.paste_prompt = Some("Complete login in your browser, or paste the authorization code / redirect URL here:".into());
        waiting.paste_placeholder = Some("http://localhost:1455/auth/callback".into());
        report_worker_oauth_login_event(Path((worker_id, login.id)), State(state.clone()), worker_headers("oauth-cred"), Json(waiting)).await.unwrap();
        let current = state.oauth_login_states.lock().await.get(&worker_id).cloned().unwrap();
        assert_eq!(current.status, "awaiting_callback");
        assert!(current.paste_prompt.as_deref().unwrap_or_default().contains("paste the authorization code"));
        // The Host relay accepts the pasted localhost redirect without
        // leaking the single-use code into the UI response.
        let Json(updated) = submit_worker_oauth_login_input(
            Path(worker_id),
            State(state.clone()),
            Json(AgentOAuthInputSubmit { input: "http://localhost:1455/auth/callback?code=abc&state=xyz".into() }),
        ).await.unwrap();
        assert_eq!(updated.status, "awaiting_callback");
        let raw = serde_json::to_value(&updated).unwrap();
        assert!(raw.get("pending_input").is_none(), "pasted code must never serialize to Host UI");
        assert!(!raw.to_string().contains("code=abc"), "pasted code must never leak into UI responses");
        let pending_before = state.oauth_login_states.lock().await.get(&worker_id).unwrap().pending_input.clone().unwrap();
        let err = submit_worker_oauth_login_input(
            Path(worker_id),
            State(state.clone()),
            Json(AgentOAuthInputSubmit { input: "replacement-must-not-win".into() }),
        ).await.unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        let pending_after = state.oauth_login_states.lock().await.get(&worker_id).unwrap().pending_input.clone().unwrap();
        assert_eq!(pending_after.id, pending_before.id);
        assert_eq!(pending_after.input, pending_before.input);
        // The worker can refetch the same paste until it ACKs the
        // successful handoff to Pi stdin.
        let first = claim_worker_oauth_login_input(Path((worker_id, login.id)), State(state.clone()), worker_headers("oauth-cred")).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let body = axum::body::to_bytes(first.into_body(), 1024 * 1024).await.unwrap();
        let delivery: AgentOAuthInputDelivery = serde_json::from_slice(&body).unwrap();
        assert_eq!(delivery.input, "http://localhost:1455/auth/callback?code=abc&state=xyz");
        let second = claim_worker_oauth_login_input(Path((worker_id, login.id)), State(state.clone()), worker_headers("oauth-cred")).await.unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let body = axum::body::to_bytes(second.into_body(), 1024 * 1024).await.unwrap();
        let redelivery: AgentOAuthInputDelivery = serde_json::from_slice(&body).unwrap();
        assert_eq!(redelivery.id, delivery.id);
        assert_eq!(redelivery.input, delivery.input);
        ack_worker_oauth_login_input(
            Path((worker_id, login.id, delivery.id)),
            State(state.clone()),
            worker_headers("oauth-cred"),
        ).await.unwrap();
        let consumed = claim_worker_oauth_login_input(Path((worker_id, login.id)), State(state.clone()), worker_headers("oauth-cred")).await.unwrap();
        assert_eq!(consumed.status(), StatusCode::NO_CONTENT);
        // A replaced login request cannot consume another request's paste.
        let err = claim_worker_oauth_login_input(Path((worker_id, Uuid::new_v4())), State(state.clone()), worker_headers("oauth-cred")).await.unwrap_err();
        assert_eq!(err.0, StatusCode::CONFLICT);
        // Completion keeps working and reports worker-local storage only.
        let mut done = oauth_event("complete");
        done.message = Some("Pi stored the OAuth credential in this worker's isolated auth store.".into());
        report_worker_oauth_login_event(Path((worker_id, login.id)), State(state.clone()), worker_headers("oauth-cred"), Json(done)).await.unwrap();
        let current = state.oauth_login_states.lock().await.get(&worker_id).cloned().unwrap();
        assert_eq!(current.status, "complete");
        let raw = serde_json::to_value(&current).unwrap().to_string();
        assert!(!raw.contains("access"), "no OAuth tokens in Host UI state");
        assert!(!raw.contains("refresh"), "no OAuth tokens in Host UI state");
        // Unknown event kinds are rejected with an actionable error.
        let err = report_worker_oauth_login_event(Path((worker_id, login.id)), State(state.clone()), worker_headers("oauth-cred"), Json(oauth_event("bogus"))).await.unwrap_err();
        assert_eq!(err.0, StatusCode::BAD_REQUEST);
        // Terminal state is replaceable by an explicitly requested new login.
        let Json(restarted) = start_worker_oauth_login(
            Path(worker_id),
            State(state.clone()),
            Json(AgentOAuthStartInput { provider: "openai-codex".into() }),
        ).await.unwrap();
        assert_eq!(restarted.status, "queued");
        assert_ne!(restarted.id, login.id);
    }

    #[tokio::test]
    async fn pi_oauth_failure_with_embedded_tokens_never_reaches_host_state() {
        // Pi's token parsers embed the raw token-response JSON in the error
        // when required fields are missing. A failing helper therefore
        // reports a `failed` message containing synthetic live tokens; the
        // Host must redact them before storing, so neither Host state nor
        // the serialized UI response carries them.
        let db = waiting_test_db().await;
        let now = Utc::now().to_rfc3339();
        let worker_id = Uuid::new_v4();
        seed_oauth_worker(&db, &worker_id, &now, "oauth-cred").await;
        let state = waiting_state(db.clone());
        let Json(login) = start_worker_oauth_login(
            Path(worker_id),
            State(state.clone()),
            Json(AgentOAuthStartInput { provider: "openai-codex".into() }),
        ).await.unwrap();
        let claimed = claim_worker_oauth_login(Path(worker_id), State(state.clone()), worker_headers("oauth-cred")).await.unwrap();
        assert_eq!(claimed.status(), StatusCode::OK);
        let mut failed = oauth_event("failed");
        failed.message = Some(
            r#"OpenAI Codex token exchange response missing fields: {"access_token":"synth-host-access-1","refresh_token":"synth-host-refresh-2","expires_in":3600}"#.into(),
        );
        report_worker_oauth_login_event(Path((worker_id, login.id)), State(state.clone()), worker_headers("oauth-cred"), Json(failed)).await.unwrap();
        let current = state.oauth_login_states.lock().await.get(&worker_id).cloned().unwrap();
        assert_eq!(current.status, "failed");
        let stored = current.message.clone().unwrap_or_default();
        assert!(!stored.contains("synth-host-access-1"), "{stored}");
        assert!(!stored.contains("synth-host-refresh-2"), "{stored}");
        assert!(stored.contains("[REDACTED]"), "{stored}");
        // The exact payload served to the Host UI carries no tokens either.
        let response = worker_oauth_login_state(Path(worker_id), State(state.clone())).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let ui = String::from_utf8(body.to_vec()).unwrap();
        assert!(!ui.contains("synth-host-access-1"), "{ui}");
        assert!(!ui.contains("synth-host-refresh-2"), "{ui}");
        // Progress/info diagnostics are redacted through the same path.
        let Json(login) = start_worker_oauth_login(
            Path(worker_id),
            State(state.clone()),
            Json(AgentOAuthStartInput { provider: "openai-codex".into() }),
        ).await.unwrap();
        let mut progress = oauth_event("progress");
        progress.message = Some(r#"token refresh failed: {"refresh_token":"synth-host-refresh-3"}"#.into());
        report_worker_oauth_login_event(Path((worker_id, login.id)), State(state.clone()), worker_headers("oauth-cred"), Json(progress)).await.unwrap();
        let current = state.oauth_login_states.lock().await.get(&worker_id).cloned().unwrap();
        let stored = current.message.clone().unwrap_or_default();
        assert!(!stored.contains("synth-host-refresh-3"), "{stored}");
    }
}
