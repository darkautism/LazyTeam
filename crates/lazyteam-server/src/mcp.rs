use std::{collections::BTreeMap, sync::Arc};

use axum::{extract::{Path, State}, http::StatusCode, Json};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    api::delete_worker,
    create_project, create_task, delete_task, list_projects, list_tasks, list_workers, review, review_evidence, task_status, AppState,
    CreateProject, CreateTask,
};

#[derive(Clone)]
pub struct LazyTeamMcp {
    state: Arc<AppState>,
    tool_router: ToolRouter<LazyTeamMcp>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProjectCreateParams {
    pub slug: String,
    pub name: String,
    pub repo_url: String,
    #[serde(default = "default_branch")]
    pub default_branch: String,
    #[serde(default = "default_contributor_name")]
    pub contributor_name: String,
    #[serde(default = "default_contributor_email")]
    pub contributor_email: String,
    #[serde(default)]
    pub required_worker_tags: BTreeMap<String, String>,
    #[serde(default)]
    pub default_task_tags: BTreeMap<String, String>,
}

fn default_branch() -> String { "main".into() }
fn default_contributor_name() -> String { "LazyTeam Worker".into() }
fn default_contributor_email() -> String { "lazyteam@local".into() }

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskCreateParams {
    pub project_id: String,
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub expected_outcome: String,
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
    #[serde(default)]
    pub required_tags: BTreeMap<String, String>,
    #[serde(default)]
    pub preferred_tags: BTreeMap<String, String>,
    #[serde(default)]
    pub dependencies: Vec<String>,
    #[serde(default)]
    pub priority: i32,
    #[serde(default)]
    pub conflict_group: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskIdParams {
    pub task_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskRetryParams {
    /// Task to send back to implementation.
    pub task_id: String,
    /// Concise rejection reason delivered to the next worker attempt. Required when
    /// retrying from review or merge_pending (merge-gate rejection).
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ReviewRevision {
    Candidate,
    Base,
}

impl ReviewRevision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Base => "base",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ReviewDecision {
    Approve,
    Retry,
}

impl ReviewDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Retry => "retry",
        }
    }
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReviewShowParams {
    pub task_id: String,
    #[serde(default = "default_review_path")]
    pub path: String,
    #[serde(default = "default_review_revision")]
    pub revision: ReviewRevision,
    #[serde(default = "default_start_line")]
    pub start_line: usize,
    #[serde(default = "default_review_limit")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReviewGrepParams {
    pub task_id: String,
    pub pattern: String,
    #[serde(default = "default_review_revision")]
    pub revision: ReviewRevision,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default = "default_start_line")]
    pub start_line: usize,
    #[serde(default = "default_review_limit")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReviewDiffParams {
    pub task_id: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_start_line")]
    pub start_line: usize,
    #[serde(default = "default_review_limit")]
    pub limit: usize,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReviewDecideParams {
    pub task_id: String,
    pub candidate_sha: String,
    pub verdict: ReviewDecision,
    pub reason: String,
}

fn default_review_revision() -> ReviewRevision { ReviewRevision::Candidate }
fn default_review_path() -> String { ".".into() }
fn default_start_line() -> usize { 1 }
fn default_review_limit() -> usize { 200 }

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WorkerIdParams {
    pub worker_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ConfirmMergeParams {
    pub task_id: String,
    pub merge_commit_sha: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ReviewDecisionOutput {
    task_id: Uuid,
    state: String,
    candidate_sha: String,
    verdict: String,
    reason: String,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct TaskMergeOutput {
    task_id: Uuid,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    merge_commit_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    merge_conflict: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    rereview_reason: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct TaskDeletedOutput {
    task_id: Uuid,
    deleted: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct WorkerRetiredOutput {
    worker_id: Uuid,
    retired: bool,
}

#[tool_router]
impl LazyTeamMcp {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state, tool_router: Self::tool_router() }
    }

    #[tool(
        name = "projects_list",
        title = "List projects",
        description = "List all LazyTeam projects",
        annotations(
            title = "List projects",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn projects_list(&self) -> Result<rmcp::Json<Vec<lazyteam_core::Project>>, McpError> {
        let Json(items) = list_projects(State(self.state.clone())).await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(items))
    }

    #[tool(
        name = "projects_create",
        title = "Create project",
        description = "Create a LazyTeam project bound to a Git repository",
        annotations(
            title = "Create project",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn projects_create(
        &self,
        Parameters(input): Parameters<ProjectCreateParams>,
    ) -> Result<rmcp::Json<lazyteam_core::Project>, McpError> {
        let Json(project) = create_project(
            State(self.state.clone()),
            Json(CreateProject {
                slug: input.slug,
                name: input.name,
                repo_url: input.repo_url,
                default_branch: input.default_branch,
                contributor: lazyteam_core::ContributorIdentity { name: input.contributor_name, email: input.contributor_email },
                required_worker_tags: input.required_worker_tags,
                default_task_tags: input.default_task_tags,
                git_auth: crate::api::ProjectGitAuthInput::default(),
            }),
        ).await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(project))
    }

    #[tool(
        name = "tasks_list",
        title = "List tasks",
        description = "List tasks across all LazyTeam projects",
        annotations(
            title = "List tasks",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn tasks_list(&self) -> Result<rmcp::Json<Vec<lazyteam_core::Task>>, McpError> {
        let Json(items) = list_tasks(State(self.state.clone())).await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(items))
    }

    #[tool(
        name = "tasks_get",
        title = "Get task status",
        description = "Get one task together with its latest execution result, including failure summary and attempt metadata",
        annotations(
            title = "Get task status",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn tasks_get(
        &self,
        Parameters(input): Parameters<TaskIdParams>,
    ) -> Result<rmcp::Json<crate::api::TaskStatus>, McpError> {
        let task_id = Uuid::parse_str(&input.task_id)
            .map_err(|e| McpError::invalid_params("invalid task_id", Some(serde_json::json!({"error": e.to_string()}))))?;
        let Json(status) = task_status(State(self.state.clone()), Path(task_id)).await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(status))
    }

    #[tool(
        name = "tasks_create",
        title = "Create task",
        description = "Create and queue a task in a LazyTeam project",
        annotations(
            title = "Create task",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn tasks_create(
        &self,
        Parameters(input): Parameters<TaskCreateParams>,
    ) -> Result<rmcp::Json<lazyteam_core::Task>, McpError> {
        let project_id = Uuid::parse_str(&input.project_id)
            .map_err(|e| McpError::invalid_params("invalid project_id", Some(serde_json::json!({"error": e.to_string()}))))?;
        let dependencies = input.dependencies.into_iter()
            .map(|id| Uuid::parse_str(&id))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| McpError::invalid_params("invalid dependency id", Some(serde_json::json!({"error": e.to_string()}))))?;
        let Json(task) = create_task(
            State(self.state.clone()),
            Json(CreateTask {
                project_id,
                title: input.title,
                description: input.description,
                expected_outcome: input.expected_outcome,
                acceptance_criteria: input.acceptance_criteria,
                required_tags: input.required_tags,
                preferred_tags: input.preferred_tags,
                dependencies,
                priority: input.priority,
                conflict_group: input.conflict_group,
            }),
        ).await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(task))
    }

    #[tool(
        name = "reviews_get",
        title = "Get review evidence",
        description = "Get compact metadata for the latest pinned review candidate in review or merge_pending: task requirements, worker/execution summary, candidate/base SHA, review ref, changed files, validation, and warnings. The full patch is intentionally omitted; use reviews_diff for repository-backed diff content.",
        annotations(
            title = "Get review evidence",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn reviews_get(
        &self,
        Parameters(input): Parameters<TaskIdParams>,
    ) -> Result<rmcp::Json<crate::api::ReviewEvidence>, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let Json(mut evidence) = review_evidence(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        if let Some(result) = evidence.execution.result.as_mut() {
            result.patch = None;
        }
        Ok(rmcp::Json(evidence))
    }

    #[tool(
        name = "reviews_show",
        title = "Show pinned review path",
        description = "Git-show-like read of the complete pinned candidate or base snapshot. Read a UTF-8 file or list a directory; path defaults to '.' for the repository root. Pagination uses one-based output line numbers. Arbitrary repositories, branches, SHAs, .git internals, and writes are not allowed.",
        annotations(title = "Show pinned review path", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn reviews_show(&self, Parameters(input): Parameters<ReviewShowParams>) -> Result<rmcp::Json<crate::git_broker::ReviewTextPage>, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let Json(evidence) = review_evidence(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        let page = crate::git_broker::review_show(&self.state, &evidence, input.revision.as_str(), &input.path, input.start_line, input.limit)
            .await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(page))
    }

    #[tool(
        name = "reviews_grep",
        title = "Grep pinned review repository",
        description = "Git-grep-like fixed-string search of the complete pinned candidate or base snapshot, optionally restricted to repository-relative paths. Output is path:line:text without repeating the candidate SHA. No shell, arbitrary revision, or external repository access.",
        annotations(title = "Grep pinned review repository", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn reviews_grep(&self, Parameters(input): Parameters<ReviewGrepParams>) -> Result<rmcp::Json<crate::git_broker::ReviewTextPage>, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let Json(evidence) = review_evidence(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        let page = crate::git_broker::review_grep(&self.state, &evidence, input.revision.as_str(), &input.pattern, &input.paths, input.start_line, input.limit)
            .await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(page))
    }

    #[tool(
        name = "reviews_diff",
        title = "Diff pinned review candidate",
        description = "Git-diff-like view of pinned base to candidate, optionally restricted to one repository-relative path. Generated from the Host task repository; pagination uses one-based output line numbers.",
        annotations(title = "Diff pinned review candidate", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn reviews_diff(&self, Parameters(input): Parameters<ReviewDiffParams>) -> Result<rmcp::Json<crate::git_broker::ReviewTextPage>, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let Json(evidence) = review_evidence(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        let page = crate::git_broker::review_diff(&self.state, &evidence, input.path.as_deref(), input.start_line, input.limit)
            .await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(page))
    }

    #[tool(
        name = "reviews_decide",
        title = "Decide pinned review candidate",
        description = "Record approve or retry for the exact pinned candidate SHA while the task is in review and no reviewer-worker lease is active. Approve moves to merge_pending; retry returns the task to implementation. This never merges or writes repository content.",
        annotations(title = "Decide pinned review candidate", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = false)
    )]
    async fn reviews_decide(&self, Parameters(input): Parameters<ReviewDecideParams>) -> Result<rmcp::Json<ReviewDecisionOutput>, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let Json(evidence) = review_evidence(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        crate::git_broker::verify_review_snapshot(&self.state, &evidence, &input.candidate_sha).await.map_err(api_to_mcp)?;
        let verdict = input.verdict.as_str();
        let transition = review::decide_task(&self.state, task_id, &input.candidate_sha, verdict, &input.reason)
            .await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(ReviewDecisionOutput {
            task_id: transition.task_id,
            state: transition.state,
            candidate_sha: input.candidate_sha,
            verdict: verdict.to_string(),
            reason: input.reason,
        }))
    }

    #[tool(
        name = "tasks_merge",
        title = "Merge reviewed task",
        description = "Publish an approved reviewed candidate from the LazyTeam Host using Host-only Git credentials. Fast-forwards when possible; if upstream moved, merges in a private Host scratch workspace. Merge conflicts are re-dispatched to the implementation worker for resolution and re-review, never to the main agent's filesystem.",
        annotations(
            title = "Merge reviewed task",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn tasks_merge(
        &self,
        Parameters(input): Parameters<TaskIdParams>,
    ) -> Result<rmcp::Json<TaskMergeOutput>, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let Json(evidence) = review_evidence(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        if evidence.task.state != lazyteam_core::TaskState::MergePending {
            return Err(McpError::internal_error("task must be merge_pending before Host publish", None));
        }
        use crate::git_broker::PublishReviewedOutcome;
        let merge_commit_sha = match crate::git_broker::publish_reviewed_task(&self.state, &evidence).await.map_err(api_to_mcp)? {
            PublishReviewedOutcome::Merged(sha) => sha,
            PublishReviewedOutcome::Conflict(conflict) => {
                let summary = crate::git_broker::conflict_summary(&conflict);
                let reason = format!("Host final integration hit current upstream after review. {summary}\n\nThis is an upstream integration conflict, not a reviewer-quality rejection. Resolve against current upstream {}, preserve both upstream behavior and the original task intent, then return through the normal integration check and review flow.", conflict.upstream_sha);
                let evidence_json = serde_json::to_string(&conflict).map_err(|error| McpError::internal_error(error.to_string(), None))?;
                let transition = review::retry_task_with_gate_evidence(&self.state, task_id, Some(&reason), Some("merge_conflict"), Some(&evidence_json)).await.map_err(api_to_mcp)?;
                return Ok(rmcp::Json(TaskMergeOutput {
                    task_id: transition.task_id,
                    state: transition.state,
                    merge_commit_sha: None,
                    merge_conflict: Some(summary),
                    rereview_reason: None,
                }));
            }
            PublishReviewedOutcome::Rereview(snapshot) => {
                let reviewed_upstream = evidence.checkout.upstream_sha.as_deref().unwrap_or("unknown");
                let reason = format!("Upstream advanced after approval from {} to {}. The same candidate still integrates cleanly, but its effective integrated diff changed, so implementation is not being rerun; review the refreshed integration snapshot against the same task contract.", reviewed_upstream, snapshot.upstream_sha);
                let transition = review::rereview_after_upstream_move(&self.state, task_id, &reason).await.map_err(api_to_mcp)?;
                return Ok(rmcp::Json(TaskMergeOutput {
                    task_id: transition.task_id,
                    state: transition.state,
                    merge_commit_sha: None,
                    merge_conflict: None,
                    rereview_reason: Some(reason),
                }));
            }
        };
        let transition = review::merged_task(&self.state, task_id, &merge_commit_sha).await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(TaskMergeOutput {
            task_id: transition.task_id,
            state: transition.state,
            merge_commit_sha: Some(merge_commit_sha),
            merge_conflict: None,
            rereview_reason: None,
        }))
    }

    #[tool(
        name = "tasks_confirm_merge",
        title = "Confirm externally merged task",
        description = "Compatibility recovery for an approved task already merged outside tasks_merge. Verifies the upstream commit contains the exact reviewed file content before marking the task done and queuing cleanup.",
        annotations(
            title = "Confirm externally merged task",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = true
        )
    )]
    async fn tasks_confirm_merge(
        &self,
        Parameters(input): Parameters<ConfirmMergeParams>,
    ) -> Result<rmcp::Json<crate::review::TaskTransition>, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let Json(evidence) = review_evidence(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        crate::git_broker::verify_external_merge(&self.state, &evidence, &input.merge_commit_sha).await.map_err(api_to_mcp)?;
        let transition = review::merged_task(&self.state, task_id, &input.merge_commit_sha).await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(transition))
    }

    #[tool(
        name = "tasks_retry",
        title = "Retry task",
        description = "Retry according to the task's current state (draft, review, merge_pending, failed, or blocked). Review or merge-gate rejection requires a concise reason for the next attempt; inspect the current task/review state before calling.",
        annotations(
            title = "Retry task",
            read_only_hint = false,
            destructive_hint = false,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn tasks_retry(
        &self,
        Parameters(input): Parameters<TaskRetryParams>,
    ) -> Result<rmcp::Json<crate::review::TaskTransition>, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        match review_evidence(Path(task_id), State(self.state.clone())).await {
            Ok(_) | Err((StatusCode::CONFLICT, _)) => {}
            Err(error) => return Err(api_to_mcp(error)),
        }
        let transition = review::retry_task(&self.state, task_id, input.reason.as_deref()).await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(transition))
    }

    #[tool(
        name = "tasks_delete",
        title = "Delete task",
        description = "Remove an obsolete unclaimed/review/failed task from LazyTeam views and queue cleanup on its last worker. Active, merge-pending, and completed tasks are protected.",
        annotations(
            title = "Delete task",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn tasks_delete(
        &self,
        Parameters(input): Parameters<TaskIdParams>,
    ) -> Result<rmcp::Json<TaskDeletedOutput>, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        delete_task(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(TaskDeletedOutput { task_id, deleted: true }))
    }

    #[tool(
        name = "workers_list",
        title = "List workers",
        description = "List registered LazyTeam workers and their capabilities",
        annotations(
            title = "List workers",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn workers_list(&self) -> Result<rmcp::Json<Vec<lazyteam_core::Worker>>, McpError> {
        let Json(items) = list_workers(State(self.state.clone())).await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(items))
    }

    #[tool(
        name = "workers_retire",
        title = "Retire inactive worker",
        description = "Retire an inactive LazyTeam worker from the active pool while preserving execution/review audit history. Active workers must be stopped first.",
        annotations(
            title = "Retire inactive worker",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn workers_retire(
        &self,
        Parameters(input): Parameters<WorkerIdParams>,
    ) -> Result<rmcp::Json<WorkerRetiredOutput>, McpError> {
        let worker_id = Uuid::parse_str(&input.worker_id)
            .map_err(|e| McpError::invalid_params("invalid worker_id", Some(serde_json::json!({"error": e.to_string()}))))?;
        delete_worker(Path(worker_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(WorkerRetiredOutput { worker_id, retired: true }))
    }
}

#[tool_handler]
impl ServerHandler for LazyTeamMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "LazyTeam controls projects, tasks, executions, reviews, Host-owned Git publishing, and a distributed AI worker pool. Workers and reviewer workers never receive upstream Git credentials; they use task-scoped repositories served by the LazyTeam Host. A completed reviewer-worker approve verdict or an exact-candidate main-agent reviews_decide approve may move a review task to merge_pending. Main-agent review can inspect the complete pinned repository with reviews_show, reviews_grep, and reviews_diff without shell access. For a merge_pending task, inspect the candidate with reviews_get, then call tasks_merge when the candidate is acceptable: the Host revalidates the pinned base/candidate, publishes upstream with Host-only credentials, marks the task done, and queues worker cleanup. When the merge_pending candidate is stale or unsafe, do not merge; call tasks_retry with a concrete reason to send it back through implementation + independent review instead of attempting an unsafe merge or inventing another recovery path. Do not merge upstream from a worker or external checkout. On tasks_retry, give a concrete reason; review and merge-gate (merge_pending) retries require a concise reason and stay pinned to the implementation worker workspace/session when applicable.".to_string(),
            )
    }
}

fn parse_task_id(raw: &str) -> Result<Uuid, McpError> {
    Uuid::parse_str(raw)
        .map_err(|e| McpError::invalid_params("invalid task_id", Some(serde_json::json!({"error": e.to_string()}))))
}

fn api_to_mcp((status, message): crate::ApiError) -> McpError {
    McpError::internal_error(
        message,
        Some(serde_json::json!({"http_status": status.as_u16()})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mcp() -> LazyTeamMcp {
        use sqlx::sqlite::SqlitePoolOptions;
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_lazy("sqlite::memory:")
            .expect("in-memory pool");
        let state = Arc::new(AppState {
            db,
            public_url: None,
            oauth_password: None,
            git_credential_key: None,
            git_root: std::path::PathBuf::from("/tmp/lazyteam-mcp-test-git"),
            agent_auth_updates: Default::default(),
            model_refresh_requests: Default::default(), oauth_login_states: Default::default(),
        });
        LazyTeamMcp::new(state)
    }

    #[tokio::test]
    async fn every_mcp_tool_advertises_output_schema() {
        let mcp = test_mcp();
        let missing = mcp
            .tool_router
            .list_all()
            .into_iter()
            .filter(|tool| tool.output_schema.is_none())
            .map(|tool| tool.name.to_string())
            .collect::<Vec<_>>();
        assert!(missing.is_empty(), "MCP tools missing outputSchema: {missing:?}");
    }

    #[tokio::test]
    async fn tasks_retry_description_advertises_merge_pending_with_reason() {
        let mcp = test_mcp();
        let tool = mcp
            .tool_router
            .get("tasks_retry")
            .expect("tasks_retry tool must be registered");
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(
            description.contains("merge_pending"),
            "tasks_retry description must explicitly include merge_pending: {description}"
        );
        let lowered = description.to_lowercase();
        assert!(
            lowered.contains("reason"),
            "tasks_retry description must state a reason is required/expected: {description}"
        );
        assert!(
            lowered.contains("requir") || lowered.contains("expected"),
            "tasks_retry description must state the reason is required/expected for review or merge-gate rejection: {description}"
        );
    }

    #[tokio::test]
    async fn server_instructions_explain_merge_gate_retry_path() {
        let mcp = test_mcp();
        let instructions = mcp.get_info().instructions.unwrap_or_default();
        let lowered = instructions.to_lowercase();
        assert!(
            lowered.contains("merge_pending"),
            "server instructions must mention merge_pending: {instructions}"
        );
        assert!(
            lowered.contains("reviews_get") || lowered.contains("inspect"),
            "server instructions must tell the agent to inspect the merge_pending candidate: {instructions}"
        );
        assert!(
            instructions.contains("tasks_merge"),
            "server instructions must mention tasks_merge for acceptable candidates: {instructions}"
        );
        assert!(
            instructions.contains("tasks_retry"),
            "server instructions must mention tasks_retry for rejected candidates: {instructions}"
        );
        assert!(
            lowered.contains("concrete reason") || lowered.contains("concise reason"),
            "server instructions must require a concrete/concise tasks_retry reason: {instructions}"
        );
    }

    #[tokio::test]
    async fn merge_pending_review_evidence_is_advertised_for_inspection() {
        let mcp = test_mcp();
        let tool = mcp
            .tool_router
            .get("reviews_get")
            .expect("reviews_get tool must be registered");
        let description = tool.description.as_deref().unwrap_or_default();
        assert!(
            description.contains("merge_pending"),
            "reviews_get description must advertise merge_pending inspection: {description}"
        );
    }

    #[tokio::test]
    async fn review_tool_surface_uses_git_like_names() {
        let mcp = test_mcp();
        for name in ["reviews_show", "reviews_grep", "reviews_diff", "reviews_decide", "tasks_confirm_merge", "workers_retire"] {
            assert!(mcp.tool_router.get(name).is_some(), "{name} must be registered");
        }
        for old in ["reviews_read", "reviews_search", "tasks_merged", "workers_delete"] {
            assert!(mcp.tool_router.get(old).is_none(), "obsolete MCP tool {old} must not remain registered");
        }
    }
}
