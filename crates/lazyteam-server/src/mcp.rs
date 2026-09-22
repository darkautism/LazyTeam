use std::{collections::{BTreeMap, HashMap}, sync::Arc};

use axum::{extract::{Path, State}, Json};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use lazyteam_core::{AgentRole, Execution, ExecutionState, Project, ReviewVerdict, ReviewVerdictKind, Task, TaskState, Worker};

use crate::{
    api::{
        claim_review_for_worker, claim_task_for_worker, ensure_internal_work_actor,
        release_execution_for_capability, release_review_for_capability,
    },
    interactive_sandbox::SandboxRole,
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

#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ReviewDecision {
    Approve,
    Retry,
}

#[derive(Debug, Clone, Copy, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum WorkRole {
    Implementation,
    Review,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WorkPickParams {
    pub role: WorkRole,
    #[serde(default)]
    pub task_id: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SandboxIdParams {
    pub sandbox_id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReadParams {
    pub sandbox_id: String,
    pub path: String,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WriteParams {
    pub sandbox_id: String,
    pub path: String,
    pub content: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReplaceEdit {
    #[serde(rename = "oldText")]
    pub old_text: String,
    #[serde(rename = "newText")]
    pub new_text: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct EditParams {
    pub sandbox_id: String,
    pub path: String,
    pub edits: Vec<ReplaceEdit>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BashParams {
    pub sandbox_id: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub pid: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WorkFinishParams {
    pub sandbox_id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub validation: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub artifacts: Vec<String>,
    #[serde(default)]
    pub verdict: Option<ReviewDecision>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct TextToolOutput {
    output: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema, Default)]
pub struct TaskListParams {
    #[serde(default)]
    pub state: Option<TaskState>,
    #[serde(default)]
    pub project_id: Option<String>,
    /// Exact project routing tags. Example: {"smart":"true"}.
    #[serde(default)]
    pub project_required_tags: BTreeMap<String, String>,
    /// Exact task required tags.
    #[serde(default)]
    pub task_required_tags: BTreeMap<String, String>,
    /// Maximum results; defaults to 50 and is capped at 100.
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, schemars::JsonSchema)]
struct ProjectRef {
    id: Uuid,
    slug: String,
    name: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    required_worker_tags: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    default_task_tags: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ProjectOutput {
    id: Uuid,
    slug: String,
    name: String,
    repo_url: String,
    default_branch: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    required_worker_tags: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    default_task_tags: BTreeMap<String, String>,
    enabled: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ProjectsListOutput {
    projects: Vec<ProjectOutput>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct TaskListItem {
    id: Uuid,
    project: ProjectRef,
    title: String,
    state: TaskState,
    priority: i32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    required_tags: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    preferred_tags: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct TasksListOutput {
    tasks: Vec<TaskListItem>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct TaskDetail {
    id: Uuid,
    title: String,
    state: TaskState,
    priority: i32,
    description: String,
    expected_outcome: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    acceptance_criteria: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    required_tags: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    preferred_tags: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    dependencies: Vec<Uuid>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    review_feedback: String,
    review_cycle: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    conflict_group: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ExecutionSummary {
    attempt: u32,
    state: ExecutionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    summary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    changed_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    validation: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_clean: Option<bool>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct ReviewSummary {
    current_cycle_retries: i64,
    lifetime_retries: i64,
    candidate_reviews: i64,
    candidate_approvals: i64,
    candidate_retries: i64,
    candidate_runtime_failures: i64,
    candidate_lost_leases: i64,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct TaskGetOutput {
    project: ProjectRef,
    task: TaskDetail,
    #[serde(skip_serializing_if = "Option::is_none")]
    latest_execution: Option<ExecutionSummary>,
    review: ReviewSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    waiting: Option<crate::api::WaitingInfo>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct AgentSummary {
    agent_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct WorkerOutput {
    id: Uuid,
    name: String,
    role: AgentRole,
    state: lazyteam_core::WorkerState,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    tags: BTreeMap<String, String>,
    allowed_projects: Vec<String>,
    slots: u32,
    running_slots: u32,
    agent: AgentSummary,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct WorkersListOutput {
    workers: Vec<WorkerOutput>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct WorkReviewContext {
    #[serde(skip_serializing_if = "Option::is_none")]
    candidate_summary: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    changed_files: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    validation: Vec<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct WorkPickOutput {
    picked: bool,
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project: Option<ProjectRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    task: Option<TaskDetail>,
    #[serde(skip_serializing_if = "Option::is_none")]
    review: Option<WorkReviewContext>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct AckOutput {
    ok: bool,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct BashToolOutput {
    status: String,
    pid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    output: String,
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    instruction: Option<String>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct WorkActionOutput {
    sandbox_id: String,
    state: String,
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

fn project_ref(project: &Project) -> ProjectRef {
    ProjectRef {
        id: project.id,
        slug: project.slug.clone(),
        name: project.name.clone(),
        required_worker_tags: project.required_worker_tags.clone(),
        default_task_tags: project.default_task_tags.clone(),
    }
}

fn project_output(project: Project) -> ProjectOutput {
    ProjectOutput {
        id: project.id,
        slug: project.slug,
        name: project.name,
        repo_url: project.repo_url,
        default_branch: project.default_branch,
        required_worker_tags: project.required_worker_tags,
        default_task_tags: project.default_task_tags,
        enabled: project.enabled,
    }
}

fn task_list_item(task: Task, project: &Project) -> TaskListItem {
    TaskListItem {
        id: task.id,
        project: project_ref(project),
        title: task.title,
        state: task.state,
        priority: task.priority,
        required_tags: task.required_tags,
        preferred_tags: task.preferred_tags,
    }
}

fn task_detail(task: Task) -> TaskDetail {
    TaskDetail {
        id: task.id,
        title: task.title,
        state: task.state,
        priority: task.priority,
        description: task.description,
        expected_outcome: task.expected_outcome,
        acceptance_criteria: task.acceptance_criteria,
        required_tags: task.required_tags,
        preferred_tags: task.preferred_tags,
        dependencies: task.dependencies,
        review_feedback: task.review_feedback,
        review_cycle: task.review_cycle,
        conflict_group: task.conflict_group,
    }
}

fn execution_summary(execution: Execution) -> ExecutionSummary {
    let (summary, changed_files, validation, warnings, workspace_clean) = execution
        .result
        .map(|result| {
            (
                Some(result.summary),
                result.changed_files,
                result.validation,
                result.warnings,
                result.workspace_clean,
            )
        })
        .unwrap_or_default();
    ExecutionSummary {
        attempt: execution.attempt,
        state: execution.state,
        summary,
        changed_files,
        validation,
        warnings,
        workspace_clean,
    }
}

fn worker_output(worker: Worker) -> WorkerOutput {
    WorkerOutput {
        id: worker.id,
        name: worker.name,
        role: worker.role,
        state: worker.state,
        tags: worker.tags,
        allowed_projects: worker.allowed_projects.into_iter().collect(),
        slots: worker.slots,
        running_slots: worker.running_slots,
        agent: AgentSummary {
            agent_type: worker.agent.agent_type,
            provider: worker.agent.provider,
            model: worker.agent.model,
        },
    }
}

fn tags_match(actual: &BTreeMap<String, String>, required: &BTreeMap<String, String>) -> bool {
    required.iter().all(|(key, value)| actual.get(key) == Some(value))
}

async fn mcp_projects(state: Arc<AppState>) -> Result<Vec<Project>, McpError> {
    let Json(projects) = list_projects(State(state)).await.map_err(api_to_mcp)?;
    Ok(projects)
}

#[tool_router]
impl LazyTeamMcp {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state, tool_router: Self::tool_router() }
    }

    #[tool(
        name = "projects_list",
        title = "List projects",
        description = "List projects with routing tags.",
        annotations(
            title = "List projects",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn projects_list(&self) -> Result<rmcp::Json<ProjectsListOutput>, McpError> {
        let projects = mcp_projects(self.state.clone()).await?;
        Ok(rmcp::Json(ProjectsListOutput {
            projects: projects.into_iter().map(project_output).collect(),
        }))
    }

    #[tool(
        name = "projects_create",
        title = "Create project",
        description = "Create a project.",
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
    ) -> Result<rmcp::Json<ProjectOutput>, McpError> {
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
        Ok(rmcp::Json(project_output(project)))
    }

    #[tool(
        name = "tasks_list",
        title = "List tasks",
        description = "List tasks. Example: state=queued, project_required_tags={\"smart\":\"true\"}.",
        annotations(
            title = "List tasks",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn tasks_list(
        &self,
        Parameters(input): Parameters<TaskListParams>,
    ) -> Result<rmcp::Json<TasksListOutput>, McpError> {
        let project_id = input
            .project_id
            .as_deref()
            .map(|raw| Uuid::parse_str(raw)
                .map_err(|e| McpError::invalid_params("invalid project_id", Some(serde_json::json!({"error": e.to_string()})))))
            .transpose()?;
        let limit = input.limit.unwrap_or(50);
        if !(1..=100).contains(&limit) {
            return Err(McpError::invalid_params("limit must be 1..=100", None));
        }

        let projects = mcp_projects(self.state.clone()).await?;
        let project_map = projects
            .into_iter()
            .map(|project| (project.id, project))
            .collect::<HashMap<_, _>>();
        let Json(items) = list_tasks(State(self.state.clone())).await.map_err(api_to_mcp)?;

        let mut tasks = Vec::new();
        for task in items {
            if input.state.as_ref().is_some_and(|state| &task.state != state) {
                continue;
            }
            if project_id.is_some_and(|id| task.project_id != id) {
                continue;
            }
            if !tags_match(&task.required_tags, &input.task_required_tags) {
                continue;
            }
            let Some(project) = project_map.get(&task.project_id) else {
                continue;
            };
            if !tags_match(&project.required_worker_tags, &input.project_required_tags) {
                continue;
            }
            tasks.push(task_list_item(task, project));
            if tasks.len() == limit {
                break;
            }
        }
        Ok(rmcp::Json(TasksListOutput { tasks }))
    }

    #[tool(
        name = "tasks_get",
        title = "Get task status",
        description = "Get task, project routing tags, latest result summary, and review counters; patch omitted.",
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
    ) -> Result<rmcp::Json<TaskGetOutput>, McpError> {
        let task_id = parse_task_id(&input.task_id)?;
        let Json(status) = task_status(State(self.state.clone()), Path(task_id)).await.map_err(api_to_mcp)?;
        let project = mcp_projects(self.state.clone())
            .await?
            .into_iter()
            .find(|project| project.id == status.task.project_id)
            .ok_or_else(|| McpError::internal_error("task project not found", None))?;
        let review = ReviewSummary {
            current_cycle_retries: status.current_cycle_reviewer_retries,
            lifetime_retries: status.lifetime_reviewer_retries,
            candidate_reviews: status.candidate_completed_reviews,
            candidate_approvals: status.candidate_completed_approvals,
            candidate_retries: status.candidate_completed_retries,
            candidate_runtime_failures: status.candidate_runtime_failures,
            candidate_lost_leases: status.candidate_lost_leases,
        };
        Ok(rmcp::Json(TaskGetOutput {
            project: project_ref(&project),
            task: task_detail(status.task),
            latest_execution: status.latest_execution.map(execution_summary),
            review,
            waiting: status.waiting,
        }))
    }

    #[tool(
        name = "tasks_create",
        title = "Create task",
        description = "Create and queue a task.",
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
    ) -> Result<rmcp::Json<TaskListItem>, McpError> {
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
        let project = mcp_projects(self.state.clone())
            .await?
            .into_iter()
            .find(|project| project.id == task.project_id)
            .ok_or_else(|| McpError::internal_error("task project not found", None))?;
        Ok(rmcp::Json(task_list_item(task, &project)))
    }


    #[tool(
        name = "work_pick",
        title = "Pick work",
        description = "Claim work; returns sandbox_id + task/project context. Then use read/write/edit/bash.",
        annotations(title = "Pick work", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = false)
    )]
    async fn work_pick(&self, Parameters(input): Parameters<WorkPickParams>) -> Result<rmcp::Json<WorkPickOutput>, McpError> {
        let task_id = input.task_id.as_deref().map(parse_task_id).transpose()?;
        match input.role {
            WorkRole::Implementation => {
                let actor = ensure_internal_work_actor(&self.state, AgentRole::Worker).await.map_err(api_to_mcp)?;
                let assignment = claim_task_for_worker(&self.state, actor, task_id).await.map_err(api_to_mcp)?;
                let Some(assignment) = assignment else {
                    if task_id.is_some() {
                        return Err(McpError::internal_error("task is not claimable for implementation", Some(serde_json::json!({"http_status": 409}))));
                    }
                    return Ok(rmcp::Json(WorkPickOutput { picked: false, role: "implementation".into(), sandbox_id: None, project: None, task: None, review: None }));
                };
                let sandbox_id = match self.state.interactive_sandboxes.attach_implementation(self.state.clone(), &assignment).await {
                    Ok(sandbox_id) => sandbox_id,
                    Err(error) => {
                        let _ = release_execution_for_capability(&self.state, assignment.execution.id, &assignment.lease_capability, None).await;
                        return Err(api_to_mcp(error));
                    }
                };
                Ok(rmcp::Json(WorkPickOutput {
                    picked: true,
                    role: "implementation".into(),
                    sandbox_id: Some(sandbox_id.to_string()),
                    project: Some(project_ref(&assignment.project)),
                    task: Some(task_detail(assignment.task)),
                    review: None,
                }))
            }
            WorkRole::Review => {
                let actor = ensure_internal_work_actor(&self.state, AgentRole::Reviewer).await.map_err(api_to_mcp)?;
                let assignment = claim_review_for_worker(&self.state, actor, task_id).await.map_err(api_to_mcp)?;
                let Some(assignment) = assignment else {
                    if task_id.is_some() {
                        return Err(McpError::internal_error("task is not claimable for review", Some(serde_json::json!({"http_status": 409}))));
                    }
                    return Ok(rmcp::Json(WorkPickOutput { picked: false, role: "review".into(), sandbox_id: None, project: None, task: None, review: None }));
                };
                let sandbox_id = match self.state.interactive_sandboxes.attach_review(self.state.clone(), &assignment).await {
                    Ok(sandbox_id) => sandbox_id,
                    Err(error) => {
                        let _ = release_review_for_capability(&self.state, assignment.review.id, &assignment.lease_capability, None).await;
                        return Err(api_to_mcp(error));
                    }
                };
                let review = assignment.execution.result.as_ref().map(|result| WorkReviewContext {
                    candidate_summary: Some(result.summary.clone()),
                    changed_files: result.changed_files.clone(),
                    validation: result.validation.clone(),
                });
                Ok(rmcp::Json(WorkPickOutput {
                    picked: true,
                    role: "review".into(),
                    sandbox_id: Some(sandbox_id.to_string()),
                    project: Some(project_ref(&assignment.project)),
                    task: Some(task_detail(assignment.task)),
                    review,
                }))
            }
        }
    }

    #[tool(
        name = "read",
        title = "Read file",
        description = "Read UTF-8 file in sandbox; use offset/limit for large files.",
        annotations(title = "Read file", read_only_hint = true, destructive_hint = false, idempotent_hint = true, open_world_hint = false)
    )]
    async fn read(&self, Parameters(input): Parameters<ReadParams>) -> Result<rmcp::Json<TextToolOutput>, McpError> {
        let sandbox_id = parse_sandbox_id(&input.sandbox_id)?;
        let text = self.state.interactive_sandboxes
            .read(&self.state, sandbox_id, &input.path, input.offset, input.limit)
            .await
            .map_err(api_to_mcp)?;
        Ok(rmcp::Json(TextToolOutput { output: text }))
    }

    #[tool(
        name = "write",
        title = "Write file",
        description = "Write file in sandbox.",
        annotations(title = "Write file", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn write(&self, Parameters(input): Parameters<WriteParams>) -> Result<rmcp::Json<AckOutput>, McpError> {
        let sandbox_id = parse_sandbox_id(&input.sandbox_id)?;
        self.state.interactive_sandboxes
            .write(&self.state, sandbox_id, &input.path, &input.content)
            .await
            .map_err(api_to_mcp)?;
        Ok(rmcp::Json(AckOutput { ok: true }))
    }

    #[tool(
        name = "edit",
        title = "Edit file",
        description = "Replace exact text in sandbox; each oldText must match once.",
        annotations(title = "Edit file", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = false)
    )]
    async fn edit(&self, Parameters(input): Parameters<EditParams>) -> Result<rmcp::Json<AckOutput>, McpError> {
        let sandbox_id = parse_sandbox_id(&input.sandbox_id)?;
        let edits = input.edits.iter()
            .map(|edit| (edit.old_text.clone(), edit.new_text.clone()))
            .collect::<Vec<_>>();
        self.state.interactive_sandboxes
            .edit(&self.state, sandbox_id, &input.path, &edits)
            .await
            .map_err(api_to_mcp)?;
        Ok(rmcp::Json(AckOutput { ok: true }))
    }

    #[tool(
        name = "bash",
        title = "Run shell command",
        description = "Run bash in sandbox; >10s returns pid, then call bash(pid=...) later.",
        annotations(title = "Run shell command", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn bash(&self, Parameters(input): Parameters<BashParams>) -> Result<rmcp::Json<BashToolOutput>, McpError> {
        let sandbox_id = parse_sandbox_id(&input.sandbox_id)?;
        let result = self.state.interactive_sandboxes
            .bash(&self.state, sandbox_id, input.command, input.pid)
            .await
            .map_err(api_to_mcp)?;
        Ok(rmcp::Json(BashToolOutput {
            status: result.status.into(),
            pid: result.pid,
            exit_code: result.exit_code,
            output: result.output,
            truncated: result.truncated,
            instruction: result.instruction.map(str::to_string),
        }))
    }

    #[tool(
        name = "work_finish",
        title = "Finish work",
        description = "Finish sandbox work. Implementation: summary; review: verdict + reason.",
        annotations(title = "Finish work", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = false)
    )]
    async fn work_finish(&self, Parameters(input): Parameters<WorkFinishParams>) -> Result<rmcp::Json<WorkActionOutput>, McpError> {
        let sandbox_id = parse_sandbox_id(&input.sandbox_id)?;
        let role = self.state.interactive_sandboxes.role(sandbox_id).await
            .ok_or_else(|| McpError::invalid_params("sandbox_id is not attached", None))?;
        match role {
            SandboxRole::Implementation => {
                if input.verdict.is_some() {
                    return Err(McpError::invalid_params("implementation finish does not accept a review verdict", None));
                }
                self.state.interactive_sandboxes.finish_implementation(
                    &self.state,
                    sandbox_id,
                    input.summary.clone().unwrap_or_default(),
                    input.validation.clone(),
                    input.warnings.clone(),
                    input.artifacts.clone(),
                ).await.map_err(api_to_mcp)?;
            }
            SandboxRole::Review => {
                let verdict = input.verdict.ok_or_else(|| McpError::invalid_params("review finish requires verdict=approve|retry", None))?;
                let reason = input.reason.clone().unwrap_or_default();
                if reason.trim().is_empty() {
                    return Err(McpError::invalid_params("review finish requires a non-empty reason", None));
                }
                let verdict = ReviewVerdict {
                    verdict: match verdict { ReviewDecision::Approve => ReviewVerdictKind::Approve, ReviewDecision::Retry => ReviewVerdictKind::Retry },
                    reason,
                    validation: input.validation.clone(),
                };
                self.state.interactive_sandboxes.finish_review(&self.state, sandbox_id, verdict)
                    .await.map_err(api_to_mcp)?;
            }
        }
        Ok(rmcp::Json(WorkActionOutput { sandbox_id: sandbox_id.to_string(), state: "finished".into() }))
    }

    #[tool(
        name = "work_release",
        title = "Release work",
        description = "Release sandbox work without recording a failure.",
        annotations(title = "Release work", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = false)
    )]
    async fn work_release(&self, Parameters(input): Parameters<SandboxIdParams>) -> Result<rmcp::Json<WorkActionOutput>, McpError> {
        let sandbox_id = parse_sandbox_id(&input.sandbox_id)?;
        self.state.interactive_sandboxes.release(&self.state, sandbox_id)
            .await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(WorkActionOutput { sandbox_id: sandbox_id.to_string(), state: "released".into() }))
    }

    #[tool(
        name = "tasks_merge",
        title = "Merge reviewed task",
        description = "Publish an approved merge_pending task; conflicts return to implementation/review.",
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
        name = "tasks_delete",
        title = "Delete task",
        description = "Delete a non-active task.",
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
        description = "List workers with routing tags and current agent.",
        annotations(
            title = "List workers",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn workers_list(&self) -> Result<rmcp::Json<WorkersListOutput>, McpError> {
        let Json(items) = list_workers(State(self.state.clone())).await.map_err(api_to_mcp)?;
        Ok(rmcp::Json(WorkersListOutput {
            workers: items.into_iter().map(worker_output).collect(),
        }))
    }

}

#[tool_handler]
impl ServerHandler for LazyTeamMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "work_pick → read/write/edit/bash(sandbox_id) → work_finish or work_release. Review approve → merge_pending; tasks_merge publishes.".to_string(),

            )
    }
}

fn parse_task_id(raw: &str) -> Result<Uuid, McpError> {
    Uuid::parse_str(raw)
        .map_err(|e| McpError::invalid_params("invalid task_id", Some(serde_json::json!({"error": e.to_string()}))))
}

fn parse_sandbox_id(raw: &str) -> Result<Uuid, McpError> {
    Uuid::parse_str(raw)
        .map_err(|e| McpError::invalid_params("invalid sandbox_id", Some(serde_json::json!({"error": e.to_string()}))))
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
            model_refresh_requests: Default::default(), oauth_login_states: Default::default(), interactive_sandboxes: Default::default(),
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
    async fn mcp_surface_is_small_and_lease_authoritative() {
        let mcp = test_mcp();
        let expected = [
            "projects_list", "projects_create",
            "tasks_list", "tasks_get", "tasks_create", "tasks_delete",
            "workers_list",
            "work_pick", "read", "write", "edit", "bash", "work_finish", "work_release",
            "tasks_merge",
        ];
        let mut actual = mcp.tool_router.list_all().into_iter().map(|tool| tool.name.to_string()).collect::<Vec<_>>();
        actual.sort();
        let mut expected = expected.into_iter().map(str::to_string).collect::<Vec<_>>();
        expected.sort();
        assert_eq!(actual, expected);
        for legacy in ["reviews_get", "reviews_show", "reviews_grep", "reviews_diff", "reviews_decide", "tasks_retry", "tasks_confirm_merge", "workers_retire"] {
            assert!(mcp.tool_router.get(legacy).is_none(), "legacy MCP tool {legacy} must not remain registered");
        }
        assert!(mcp.tool_router.get("work_renew").is_none(), "lease renewal must be internal");
        let pick = mcp.tool_router.get("work_pick").expect("work_pick must be registered");
        let description = pick.description.as_deref().unwrap_or_default();
        assert!(description.contains("sandbox_id"), "work_pick must advertise sandbox attachment: {description}");
    }

    #[tokio::test]
    async fn mcp_context_stays_compact_and_typed() {
        let mcp = test_mcp();
        for tool in mcp.tool_router.list_all() {
            let description = tool.description.as_deref().unwrap_or_default();
            assert!(
                description.len() <= 120,
                "{} description is too long: {} bytes",
                tool.name,
                description.len()
            );
        }

        let tasks_list = mcp.tool_router.get("tasks_list").expect("tasks_list");
        let list_input = serde_json::to_string(&tasks_list.input_schema).unwrap();
        let list_output = serde_json::to_string(tasks_list.output_schema.as_ref().unwrap()).unwrap();
        assert!(list_input.contains("project_required_tags"));
        assert!(list_output.contains("required_worker_tags"));
        assert!(list_output.contains("required_tags"));

        let tasks_get = mcp.tool_router.get("tasks_get").expect("tasks_get");
        let get_output = serde_json::to_string(tasks_get.output_schema.as_ref().unwrap()).unwrap();
        for forbidden in ["patch", "integration", "lease_until", "commit_sha"] {
            assert!(!get_output.contains(forbidden), "tasks_get schema leaked heavy field {forbidden}");
        }

        let workers = mcp.tool_router.get("workers_list").expect("workers_list");
        let workers_output = serde_json::to_string(workers.output_schema.as_ref().unwrap()).unwrap();
        for forbidden in ["agent_capabilities", "initial_prompt", "capability_log"] {
            assert!(!workers_output.contains(forbidden), "workers_list schema leaked heavy field {forbidden}");
        }

        let pick = mcp.tool_router.get("work_pick").expect("work_pick");
        let pick_output = serde_json::to_string(pick.output_schema.as_ref().unwrap()).unwrap();
        for forbidden in ["checkout", "implementation_worker", "lease_capability", "lease_until"] {
            assert!(!pick_output.contains(forbidden), "work_pick schema leaked internal field {forbidden}");
        }
    }

    #[tokio::test]
    async fn server_instructions_describe_single_work_lifecycle() {
        let mcp = test_mcp();
        let instructions = mcp.get_info().instructions.unwrap_or_default();
        for name in ["work_pick", "read", "write", "edit", "bash", "work_finish", "work_release", "tasks_merge"] {
            assert!(instructions.contains(name), "server instructions must mention {name}: {instructions}");
        }
        assert!(!instructions.contains("work_renew"));
        assert!(!instructions.contains("reviews_decide"));
        assert!(!instructions.contains("tasks_retry"));
    }
}
