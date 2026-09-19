use std::{collections::BTreeMap, sync::Arc};

use axum::{extract::{Path, State}, http::StatusCode, Json};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    api::delete_worker,
    create_project, create_task, delete_task, list_projects, list_tasks, list_workers, review, review_evidence, AppState,
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
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskIdParams {
    pub task_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct TaskRetryParams {
    pub task_id: String,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WorkerIdParams {
    pub worker_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MergedTaskParams {
    pub task_id: String,
    pub merge_commit_sha: String,
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
    async fn projects_list(&self) -> Result<CallToolResult, McpError> {
        let Json(items) = list_projects(State(self.state.clone())).await.map_err(api_to_mcp)?;
        json_result(&items)
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
    ) -> Result<CallToolResult, McpError> {
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
                reviewer: lazyteam_core::ReviewerConfig::default(),
                git_auth: crate::api::ProjectGitAuthInput::default(),
            }),
        ).await.map_err(api_to_mcp)?;
        json_result(&project)
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
    async fn tasks_list(&self) -> Result<CallToolResult, McpError> {
        let Json(items) = list_tasks(State(self.state.clone())).await.map_err(api_to_mcp)?;
        json_result(&items)
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
    ) -> Result<CallToolResult, McpError> {
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
            }),
        ).await.map_err(api_to_mcp)?;
        json_result(&task)
    }

    #[tool(
        name = "reviews_get",
        title = "Get review evidence",
        description = "Get the latest pinned execution evidence for a task in review, including the implementation worker, candidate commit, base commit, review ref, patch/summary evidence, and Host repository metadata.",
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
    ) -> Result<CallToolResult, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let Json(evidence) = review_evidence(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        json_result(&evidence)
    }

    #[tool(
        name = "tasks_approve",
        title = "Approve task",
        description = "Approve a task after main-agent review when no reviewer worker has already decided it. Moves review to merge_pending; dependencies remain blocked until tasks_merge performs Host-side publish.",
        annotations(
            title = "Approve task",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn tasks_approve(
        &self,
        Parameters(input): Parameters<TaskIdParams>,
    ) -> Result<CallToolResult, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let _ = review_evidence(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        let transition = review::approve_task(&self.state, task_id).await.map_err(api_to_mcp)?;
        json_result(&transition)
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
    ) -> Result<CallToolResult, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let Json(evidence) = review_evidence(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        if evidence.task.state != lazyteam_core::TaskState::MergePending {
            return Err(McpError::internal_error("task must be merge_pending before Host publish", None));
        }
        let merge_commit_sha = match crate::git_broker::publish_reviewed_task(&self.state, &evidence).await {
            Ok(sha) => sha,
            Err((StatusCode::CONFLICT, message)) if message.starts_with("merge conflict with current ") => {
                let reason = format!("Host merge could not be completed cleanly. {message}. Resolve the merge conflicts against the current default branch, preserve the reviewed task intent, validate the result, and resubmit for review.");
                let transition = review::retry_task(&self.state, task_id, Some(&reason)).await.map_err(api_to_mcp)?;
                return json_result(&serde_json::json!({
                    "task_id": transition.task_id,
                    "state": transition.state,
                    "merge_conflict": message,
                }));
            }
            Err(error) => return Err(api_to_mcp(error)),
        };
        let transition = review::merged_task(&self.state, task_id, &merge_commit_sha).await.map_err(api_to_mcp)?;
        json_result(&serde_json::json!({
            "task_id": transition.task_id,
            "state": transition.state,
            "merge_commit_sha": merge_commit_sha,
        }))
    }

    #[tool(
        name = "tasks_merged",
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
    async fn tasks_merged(
        &self,
        Parameters(input): Parameters<MergedTaskParams>,
    ) -> Result<CallToolResult, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let Json(evidence) = review_evidence(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        crate::git_broker::verify_external_merge(&self.state, &evidence, &input.merge_commit_sha).await.map_err(api_to_mcp)?;
        let transition = review::merged_task(&self.state, task_id, &input.merge_commit_sha).await.map_err(api_to_mcp)?;
        json_result(&transition)
    }

    #[tool(
        name = "tasks_retry",
        title = "Retry task",
        description = "Re-dispatch an unclaimed/draft, review, failed, or blocked task. A review retry requires a concise reason, which is delivered to the next worker attempt",
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
    ) -> Result<CallToolResult, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        match review_evidence(Path(task_id), State(self.state.clone())).await {
            Ok(_) | Err((StatusCode::CONFLICT, _)) => {}
            Err(error) => return Err(api_to_mcp(error)),
        }
        let transition = review::retry_task(&self.state, task_id, input.reason.as_deref()).await.map_err(api_to_mcp)?;
        json_result(&transition)
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
    ) -> Result<CallToolResult, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        delete_task(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        json_result(&serde_json::json!({"task_id": task_id, "deleted": true}))
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
    async fn workers_list(&self) -> Result<CallToolResult, McpError> {
        let Json(items) = list_workers(State(self.state.clone())).await.map_err(api_to_mcp)?;
        json_result(&items)
    }

    #[tool(
        name = "workers_delete",
        title = "Delete inactive worker",
        description = "Retire an inactive LazyTeam worker from the active pool while preserving execution/review audit history. Active workers must be stopped first.",
        annotations(
            title = "Delete inactive worker",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn workers_delete(
        &self,
        Parameters(input): Parameters<WorkerIdParams>,
    ) -> Result<CallToolResult, McpError> {
        let worker_id = Uuid::parse_str(&input.worker_id)
            .map_err(|e| McpError::invalid_params("invalid worker_id", Some(serde_json::json!({"error": e.to_string()}))))?;
        delete_worker(Path(worker_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        json_result(&serde_json::json!({"worker_id": worker_id, "retired": true}))
    }
}

#[tool_handler]
impl ServerHandler for LazyTeamMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "LazyTeam controls projects, tasks, executions, reviews, Host-owned Git publishing, and a distributed AI worker pool. Workers and reviewer workers never receive upstream Git credentials; they use task-scoped repositories served by the LazyTeam Host. Reviewer workers normally move approved tasks to merge_pending automatically. For a merge_pending task, call tasks_merge: the Host revalidates the pinned base/candidate, publishes upstream with Host-only credentials, marks the task done, and queues worker cleanup. Do not merge upstream from a worker or external checkout. On tasks_retry, give a concrete reason; review retries stay pinned to the implementation worker workspace/session when applicable.".to_string(),
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

fn json_result(value: &impl serde::Serialize) -> Result<CallToolResult, McpError> {
    let text = serde_json::to_string_pretty(value)
        .map_err(|e| McpError::internal_error(e.to_string(), None))?;
    Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
}
