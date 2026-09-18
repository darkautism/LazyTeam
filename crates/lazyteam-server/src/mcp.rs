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
    create_project, create_task, list_projects, list_tasks, list_workers, review, review_evidence, AppState,
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
    #[serde(default)]
    pub required_worker_tags: BTreeMap<String, String>,
    #[serde(default)]
    pub default_task_tags: BTreeMap<String, String>,
}

fn default_branch() -> String { "main".into() }

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
pub struct TaskMergedParams {
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
        description = "Get the latest execution evidence for a task in review, including reviewer policy, the full worker execution environment, and a pullable repository/ref/commit checkout. Patch/summary data are supplemental; reviewers should fetch the review ref into an execution environment and validate the project when practical before approving or retrying.",
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
        description = "Approve the review verdict after reading reviews_get and validating the pullable review ref. Moves the task to merge_pending; it is not done and dependencies are not released until the reviewed ref is actually merged and tasks_merged is called",
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
        let Json(evidence) = review_evidence(Path(task_id), State(self.state.clone())).await.map_err(api_to_mcp)?;
        if evidence.project.reviewer.mode != lazyteam_core::ReviewerMode::Mcp {
            return Err(McpError::internal_error("project reviewer mode is manual; approve from the admin UI or switch the project to ChatGPT / MCP reviewer", None));
        }
        let transition = review::approve_task(&self.state, task_id).await.map_err(api_to_mcp)?;
        json_result(&transition)
    }

    #[tool(
        name = "tasks_merged",
        title = "Mark task merged",
        description = "Confirm that an approved task's reviewed ref has actually been merged into the project's default branch. Marks the task done, releases dependencies, and queues cleanup of the original worker workspace and agent session. Never call this before the merge is complete.",
        annotations(
            title = "Mark task merged",
            read_only_hint = false,
            destructive_hint = true,
            idempotent_hint = false,
            open_world_hint = false
        )
    )]
    async fn tasks_merged(
        &self,
        Parameters(input): Parameters<TaskMergedParams>,
    ) -> Result<CallToolResult, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let transition = review::merged_task(&self.state, task_id, &input.merge_commit_sha).await.map_err(api_to_mcp)?;
        json_result(&transition)
    }

    #[tool(
        name = "tasks_retry",
        title = "Retry task",
        description = "Requeue a task from review, failed, or blocked. A review retry requires a concise reason, which is delivered to the next worker attempt",
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
            Ok(Json(evidence)) => {
                if evidence.project.reviewer.mode != lazyteam_core::ReviewerMode::Mcp {
                    return Err(McpError::internal_error("project reviewer mode is manual; retry from the admin UI or switch the project to ChatGPT / MCP reviewer", None));
                }
            }
            Err((StatusCode::CONFLICT, _)) => {}
            Err(error) => return Err(api_to_mcp(error)),
        }
        let transition = review::retry_task(&self.state, task_id, input.reason.as_deref()).await.map_err(api_to_mcp)?;
        json_result(&transition)
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
}

#[tool_handler]
impl ServerHandler for LazyTeamMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "LazyTeam controls projects, tasks, executions, reviews, merges, and a distributed AI worker pool. For review: call reviews_get, fetch the pullable checkout ref into an execution environment when practical, and validate the task contract. tasks_approve records only the review verdict and moves the task to merge_pending. Merge the reviewed ref into the default branch, then call tasks_merged; only that marks done and allows the original worker to delete its persistent workspace/session. On tasks_retry, give a concrete reason; review retries are pinned to the same worker so its workspace and agent session can be reused.".to_string(),
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
