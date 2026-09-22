use std::{collections::BTreeMap, sync::Arc};

use axum::{extract::{Path, State}, Json};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{Implementation, ServerCapabilities, ServerConfig},
    schemars, tool, tool_handler, tool_router,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use lazyteam_core::{AgentRole, ReviewVerdict, ReviewVerdictKind};

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

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct WorkPickOutput {
    picked: bool,
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sandbox_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
struct WorkActionOutput {
    sandbox_id: String,
    lease_id: String,
    lease_type: String,
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
        name = "work_pick",
        title = "Pick work",
        description = "Claim implementation or review work. LazyTeam prepares and attaches an isolated coding sandbox, keeps the authoritative lease alive internally, and returns sandbox_id plus the task context. Use read/write/edit/bash with sandbox_id, then work_finish or work_release.",
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
                    return Ok(rmcp::Json(WorkPickOutput { picked: false, role: "implementation".into(), sandbox_id: None, context: None }));
                };
                let sandbox_id = match self.state.interactive_sandboxes.attach_implementation(self.state.clone(), &assignment).await {
                    Ok(sandbox_id) => sandbox_id,
                    Err(error) => {
                        let _ = release_execution_for_capability(&self.state, assignment.execution.id, &assignment.lease_capability, None).await;
                        return Err(api_to_mcp(error));
                    }
                };
                let context = serde_json::json!({
                    "project": assignment.project,
                    "task": assignment.task,
                    "execution": assignment.execution,
                    "instructions": "Use read/write/edit/bash with sandbox_id. Git publication and lease renewal are Host-owned.",
                });
                Ok(rmcp::Json(WorkPickOutput { picked: true, role: "implementation".into(), sandbox_id: Some(sandbox_id.to_string()), context: Some(context) }))
            }
            WorkRole::Review => {
                let actor = ensure_internal_work_actor(&self.state, AgentRole::Reviewer).await.map_err(api_to_mcp)?;
                let assignment = claim_review_for_worker(&self.state, actor, task_id).await.map_err(api_to_mcp)?;
                let Some(assignment) = assignment else {
                    if task_id.is_some() {
                        return Err(McpError::internal_error("task is not claimable for review", Some(serde_json::json!({"http_status": 409}))));
                    }
                    return Ok(rmcp::Json(WorkPickOutput { picked: false, role: "review".into(), sandbox_id: None, context: None }));
                };
                let sandbox_id = match self.state.interactive_sandboxes.attach_review(self.state.clone(), &assignment).await {
                    Ok(sandbox_id) => sandbox_id,
                    Err(error) => {
                        let _ = release_review_for_capability(&self.state, assignment.review.id, &assignment.lease_capability, None).await;
                        return Err(api_to_mcp(error));
                    }
                };
                let effective_diff_hash = assignment.execution.result.as_ref()
                    .and_then(|result| result.integration.as_ref())
                    .and_then(|integration| integration.effective_diff_hash.clone());
                let review_cycle = assignment.task.review_cycle;
                let context = serde_json::json!({
                    "project": assignment.project,
                    "task": assignment.task,
                    "review": assignment.review,
                    "implementation_execution": assignment.execution,
                    "implementation_worker": assignment.implementation_worker,
                    "checkout": assignment.checkout,
                    "effective_diff_hash": effective_diff_hash,
                    "review_cycle": review_cycle,
                    "instructions": "Inspect the pinned integration using read/write/edit/bash with sandbox_id. Sandbox edits are disposable review notes and never change the candidate.",
                });
                Ok(rmcp::Json(WorkPickOutput { picked: true, role: "review".into(), sandbox_id: Some(sandbox_id.to_string()), context: Some(context) }))
            }
        }
    }

    #[tool(
        name = "read",
        title = "Read file",
        description = "Read a UTF-8 text file inside the attached LazyTeam sandbox. Relative paths resolve from the sandbox workspace. Output is bounded to 2000 lines or 50KB; use offset/limit to continue large files. Every successful access validates and renews the authoritative work lease.",
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
        description = "Write a file inside the attached LazyTeam sandbox. Relative paths resolve from the sandbox workspace; parent directories are created automatically. The sandbox cannot access Host Git credentials or files outside its allowlist.",
        annotations(title = "Write file", read_only_hint = false, destructive_hint = true, idempotent_hint = true, open_world_hint = false)
    )]
    async fn write(&self, Parameters(input): Parameters<WriteParams>) -> Result<rmcp::Json<TextToolOutput>, McpError> {
        let sandbox_id = parse_sandbox_id(&input.sandbox_id)?;
        self.state.interactive_sandboxes
            .write(&self.state, sandbox_id, &input.path, &input.content)
            .await
            .map_err(api_to_mcp)?;
        Ok(rmcp::Json(TextToolOutput { output: format!("Successfully wrote to {}", input.path) }))
    }

    #[tool(
        name = "edit",
        title = "Edit file",
        description = "Make precise exact-text replacements inside the attached LazyTeam sandbox. Each edits[].oldText must match exactly once in the original file and edits may not overlap.",
        annotations(title = "Edit file", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = false)
    )]
    async fn edit(&self, Parameters(input): Parameters<EditParams>) -> Result<rmcp::Json<TextToolOutput>, McpError> {
        let sandbox_id = parse_sandbox_id(&input.sandbox_id)?;
        let edits = input.edits.iter()
            .map(|edit| (edit.old_text.clone(), edit.new_text.clone()))
            .collect::<Vec<_>>();
        self.state.interactive_sandboxes
            .edit(&self.state, sandbox_id, &input.path, &edits)
            .await
            .map_err(api_to_mcp)?;
        Ok(rmcp::Json(TextToolOutput { output: format!("Successfully applied {} edit(s) to {}", input.edits.len(), input.path) }))
    }

    #[tool(
        name = "bash",
        title = "Run shell command",
        description = "Run a non-interactive bash command inside the attached LazyTeam sandbox, or attach to a PID returned by an earlier call. Synchronous wait is capped at 10 seconds; longer commands continue in the sandbox and return a PID. Pipes and redirection are supported; interactive TTY programs are not.",
        annotations(title = "Run shell command", read_only_hint = false, destructive_hint = true, idempotent_hint = false, open_world_hint = true)
    )]
    async fn bash(&self, Parameters(input): Parameters<BashParams>) -> Result<rmcp::Json<crate::interactive_sandbox::BashResult>, McpError> {
        let sandbox_id = parse_sandbox_id(&input.sandbox_id)?;
        let result = self.state.interactive_sandboxes
            .bash(&self.state, sandbox_id, input.command, input.pid)
            .await
            .map_err(api_to_mcp)?;
        Ok(rmcp::Json(result))
    }

    #[tool(
        name = "work_finish",
        title = "Finish work",
        description = "Finish the work attached to sandbox_id. For implementation, LazyTeam syncs the sandbox, creates the trusted commit and task ref, then moves the task to review. For review, provide verdict=approve|retry and a non-empty reason. Lease identity, capability, renewal, Git publication, and cleanup are Host-owned.",
        annotations(title = "Finish work", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = false)
    )]
    async fn work_finish(&self, Parameters(input): Parameters<WorkFinishParams>) -> Result<rmcp::Json<WorkActionOutput>, McpError> {
        let sandbox_id = parse_sandbox_id(&input.sandbox_id)?;
        let role = self.state.interactive_sandboxes.role(sandbox_id).await
            .ok_or_else(|| McpError::invalid_params("sandbox_id is not attached", None))?;
        let (lease_id, lease_type) = match role {
            SandboxRole::Implementation => {
                if input.verdict.is_some() {
                    return Err(McpError::invalid_params("implementation finish does not accept a review verdict", None));
                }
                let lease_id = self.state.interactive_sandboxes.finish_implementation(
                    &self.state,
                    sandbox_id,
                    input.summary.clone().unwrap_or_default(),
                    input.validation.clone(),
                    input.warnings.clone(),
                    input.artifacts.clone(),
                ).await.map_err(api_to_mcp)?;
                (lease_id, "implementation")
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
                let lease_id = self.state.interactive_sandboxes.finish_review(&self.state, sandbox_id, verdict)
                    .await.map_err(api_to_mcp)?;
                (lease_id, "review")
            }
        };
        Ok(rmcp::Json(WorkActionOutput { sandbox_id: sandbox_id.to_string(), lease_id: lease_id.to_string(), lease_type: lease_type.into(), state: "finished".into() }))
    }

    #[tool(
        name = "work_release",
        title = "Release work",
        description = "Voluntarily release the work attached to sandbox_id without recording a failure. Implementation returns to queued; review stays in review. LazyTeam invalidates the lease, stops sandbox processes, and removes the sandbox.",
        annotations(title = "Release work", read_only_hint = false, destructive_hint = false, idempotent_hint = false, open_world_hint = false)
    )]
    async fn work_release(&self, Parameters(input): Parameters<SandboxIdParams>) -> Result<rmcp::Json<WorkActionOutput>, McpError> {
        let sandbox_id = parse_sandbox_id(&input.sandbox_id)?;
        let (lease_id, kind) = self.state.interactive_sandboxes.release(&self.state, sandbox_id)
            .await.map_err(api_to_mcp)?;
        let lease_type = match kind {
            crate::api::WorkLeaseKind::Implementation => "implementation",
            crate::api::WorkLeaseKind::Review => "review",
        };
        Ok(rmcp::Json(WorkActionOutput { sandbox_id: sandbox_id.to_string(), lease_id: lease_id.to_string(), lease_type: lease_type.into(), state: "released".into() }))
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

}

#[tool_handler]
impl ServerHandler for LazyTeamMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions(
                "LazyTeam has one authoritative work-ownership model. Use work_pick(role=implementation|review) to claim work and receive sandbox_id. Then use the four PC-style tools read, write, edit, and bash with that sandbox_id. LazyTeam owns lease renewal, Git credentials, trusted commit/ref publication, process cleanup, and sandbox teardown. Finish with work_finish(sandbox_id, ...), or voluntarily return work with work_release(sandbox_id) without counting a failure. Review sandboxes are pinned to the exact reviewed integration; sandbox edits during review are disposable and cannot change the candidate. An approve verdict moves the task to merge_pending; the main agent may then call tasks_merge.".to_string(),

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
