use std::{collections::BTreeMap, sync::Arc};

use axum::{extract::State, Json};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, ContentBlock, Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    create_project, create_task, list_projects, list_tasks, list_workers, review, AppState,
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

#[tool_router]
impl LazyTeamMcp {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state, tool_router: Self::tool_router() }
    }

    #[tool(name = "projects_list", description = "List all LazyTeam projects")]
    async fn projects_list(&self) -> Result<CallToolResult, McpError> {
        let Json(items) = list_projects(State(self.state.clone())).await.map_err(api_to_mcp)?;
        json_result(&items)
    }

    #[tool(name = "projects_create", description = "Create a LazyTeam project bound to a Git repository")]
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
            }),
        ).await.map_err(api_to_mcp)?;
        json_result(&project)
    }

    #[tool(name = "tasks_list", description = "List tasks across all LazyTeam projects")]
    async fn tasks_list(&self) -> Result<CallToolResult, McpError> {
        let Json(items) = list_tasks(State(self.state.clone())).await.map_err(api_to_mcp)?;
        json_result(&items)
    }

    #[tool(name = "tasks_create", description = "Create and queue a task in a LazyTeam project")]
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

    #[tool(name = "tasks_approve", description = "Approve a task in review, mark it done, and release dependent tasks")]
    async fn tasks_approve(
        &self,
        Parameters(input): Parameters<TaskIdParams>,
    ) -> Result<CallToolResult, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let transition = review::approve_task(&self.state, task_id).await.map_err(api_to_mcp)?;
        json_result(&transition)
    }

    #[tool(name = "tasks_retry", description = "Requeue a task from review, failed, or blocked")]
    async fn tasks_retry(
        &self,
        Parameters(input): Parameters<TaskIdParams>,
    ) -> Result<CallToolResult, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let transition = review::retry_task(&self.state, task_id).await.map_err(api_to_mcp)?;
        json_result(&transition)
    }

    #[tool(name = "workers_list", description = "List registered LazyTeam workers and their capabilities")]
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
                "LazyTeam controls projects, tasks, executions, and a distributed AI worker pool. Use project-scoped tasks; workers are matched deterministically by project access and capability tags. Approve reviewed tasks to release their dependencies.".to_string(),
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
