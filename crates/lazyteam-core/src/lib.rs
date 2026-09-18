use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub type Tags = BTreeMap<String, String>;

pub const DEFAULT_WORKER_PROMPT: &str = "You are an autonomous LazyTeam coding worker. Execute only the assigned task in the provided repository workspace. Treat the task description and acceptance criteria as the contract. Inspect before editing, make the smallest correct change, preserve unrelated behavior, and follow repository instructions. Run relevant validation and never wait for interactive input. Do not broaden scope. If blocked, stop and report the concrete blocker. Do not expose secrets or modify external systems unless the task explicitly requires it. Finish with a concise summary of what changed, validation performed, and any remaining risks.";

pub const DEFAULT_REVIEWER_PROMPT: &str = "You are an independent LazyTeam reviewer. Verify the completed execution against the task description and every acceptance criterion. Inspect the execution summary, changed files, validation evidence, warnings, commit/base identifiers, and patch when available. Do not approve merely because the worker says it succeeded. Approve only when the available evidence supports the contract. If evidence is missing, contradictory, or the implementation is incorrect, retry the task with a concise reason describing what must be fixed or what evidence is required.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewerMode {
    Manual,
    Mcp,
}

impl Default for ReviewerMode {
    fn default() -> Self { Self::Manual }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewerConfig {
    #[serde(default)]
    pub mode: ReviewerMode,
    #[serde(default = "default_reviewer_prompt")]
    pub initial_prompt: String,
}

fn default_reviewer_prompt() -> String { DEFAULT_REVIEWER_PROMPT.into() }

impl Default for ReviewerConfig {
    fn default() -> Self {
        Self { mode: ReviewerMode::Manual, initial_prompt: DEFAULT_REVIEWER_PROMPT.into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentLoginMode {
    Unsupported,
    LocalInteractive,
    Remote,
}

impl Default for AgentLoginMode {
    fn default() -> Self { Self::Unsupported }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentModel {
    pub provider: String,
    pub id: String,
    #[serde(default)]
    pub context_window: Option<u64>,
    #[serde(default)]
    pub reasoning: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AgentCapabilities {
    #[serde(default)]
    pub model_discovery: bool,
    #[serde(default)]
    pub login_mode: AgentLoginMode,
    #[serde(default)]
    pub models: Vec<AgentModel>,
    #[serde(default)]
    pub probe_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentConfig {
    pub agent_type: String,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub initial_prompt: String,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_type: "pi".into(),
            provider: None,
            model: None,
            initial_prompt: DEFAULT_WORKER_PROMPT.into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub repo_url: String,
    pub default_branch: String,
    #[serde(default)]
    pub required_worker_tags: Tags,
    #[serde(default)]
    pub default_task_tags: Tags,
    #[serde(default)]
    pub reviewer: ReviewerConfig,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkerState {
    Idle,
    Busy,
    Draining,
    Degraded,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Worker {
    pub id: Uuid,
    pub name: String,
    pub state: WorkerState,
    pub os: String,
    pub arch: String,
    #[serde(default)]
    pub tags: Tags,
    #[serde(default)]
    pub allowed_projects: BTreeSet<String>,
    pub slots: u32,
    pub running_slots: u32,
    pub protocol_version: u32,
    pub worker_version: String,
    pub last_heartbeat_at: DateTime<Utc>,
    pub agent: AgentConfig,
    pub agent_capabilities: AgentCapabilities,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Draft,
    Queued,
    Assigned,
    Running,
    Review,
    Done,
    Blocked,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: Uuid,
    pub project_id: Uuid,
    pub title: String,
    pub description: String,
    pub expected_outcome: String,
    #[serde(default)]
    pub acceptance_criteria: Vec<String>,
    #[serde(default)]
    pub required_tags: Tags,
    #[serde(default)]
    pub preferred_tags: Tags,
    #[serde(default)]
    pub dependencies: Vec<Uuid>,
    #[serde(default)]
    pub review_feedback: String,
    pub priority: i32,
    pub state: TaskState,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Assigned,
    Running,
    Completed,
    Failed,
    Lost,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Execution {
    pub id: Uuid,
    pub task_id: Uuid,
    pub worker_id: Uuid,
    pub attempt: u32,
    pub state: ExecutionState,
    pub lease_until: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub finished_at: Option<DateTime<Utc>>,
    pub result: Option<ExecutionResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub status: String,
    pub summary: String,
    pub commit_sha: Option<String>,
    #[serde(default)]
    pub base_sha: Option<String>,
    #[serde(default)]
    pub patch: Option<String>,
    #[serde(default)]
    pub patch_truncated: bool,
    #[serde(default)]
    pub workspace_clean: Option<bool>,
    #[serde(default)]
    pub changed_files: Vec<String>,
    #[serde(default)]
    pub validation: Vec<String>,
    #[serde(default)]
    pub warnings: Vec<String>,
    #[serde(default)]
    pub artifacts: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    pub worker_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assignment {
    pub project: Project,
    pub task: Task,
    pub execution: Execution,
}

pub fn worker_can_run_project(worker: &Worker, project: &Project) -> bool {
    worker.allowed_projects.is_empty()
        || worker.allowed_projects.contains("*")
        || worker.allowed_projects.contains(&project.slug)
}

pub fn worker_matches_task(worker: &Worker, project: &Project, task: &Task) -> bool {
    if worker.state != WorkerState::Idle && worker.state != WorkerState::Busy {
        return false;
    }
    if worker.running_slots >= worker.slots || !worker_can_run_project(worker, project) {
        return false;
    }

    let mut required = project.required_worker_tags.clone();
    required.extend(task.required_tags.clone());

    required.into_iter().all(|(key, wanted)| {
        if wanted == "*" || wanted.eq_ignore_ascii_case("any") {
            return true;
        }
        worker
            .tags
            .get(&key)
            .is_some_and(|actual| actual == &wanted || actual == "*" || actual.eq_ignore_ascii_case("any"))
    })
}

pub fn worker_preference_score(worker: &Worker, task: &Task) -> i32 {
    task.preferred_tags
        .iter()
        .filter(|(key, wanted)| {
            wanted.as_str() == "*"
                || wanted.eq_ignore_ascii_case("any")
                || worker.tags.get(*key).is_some_and(|actual| actual == *wanted)
        })
        .count() as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    fn worker() -> Worker {
        Worker {
            id: Uuid::new_v4(),
            name: "rk".into(),
            state: WorkerState::Idle,
            os: "linux".into(),
            arch: "aarch64".into(),
            tags: BTreeMap::from([
                ("os".into(), "linux".into()),
                ("arch".into(), "aarch64".into()),
                ("cpu".into(), "rk3588".into()),
            ]),
            allowed_projects: BTreeSet::from(["rocknpu".into()]),
            slots: 1,
            running_slots: 0,
            protocol_version: 1,
            worker_version: "dev".into(),
            last_heartbeat_at: Utc::now(),
            agent: AgentConfig::default(),
            agent_capabilities: AgentCapabilities::default(),
        }
    }

    #[test]
    fn project_and_tags_are_both_enforced() {
        let project = Project {
            id: Uuid::new_v4(),
            slug: "rocknpu".into(),
            name: "RockNPU".into(),
            repo_url: "git@example/RockNPU".into(),
            default_branch: "main".into(),
            required_worker_tags: BTreeMap::from([("cpu".into(), "rk3588".into())]),
            default_task_tags: BTreeMap::new(),
            reviewer: ReviewerConfig::default(),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let task = Task {
            id: Uuid::new_v4(),
            project_id: project.id,
            title: "bench".into(),
            description: String::new(),
            expected_outcome: String::new(),
            acceptance_criteria: vec![],
            required_tags: BTreeMap::from([("os".into(), "linux".into())]),
            preferred_tags: BTreeMap::new(),
            dependencies: vec![],
            review_feedback: String::new(),
            priority: 0,
            state: TaskState::Queued,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(worker_matches_task(&worker(), &project, &task));
    }
}
