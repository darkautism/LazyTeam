use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{collections::{BTreeMap, BTreeSet}, fmt};
use uuid::Uuid;

pub type Tags = BTreeMap<String, String>;

pub const BUILD_GIT_SHA: &str = env!("LAZYTEAM_BUILD_GIT_SHA");
pub const LEASE_CAPABILITY_HEADER: &str = "x-lazyteam-lease-capability";

pub const MANAGED_CAPABILITY_IDS: &[&str] = &["rust", "python", "node", "go", "gcc", "cpp", "clang", "java", "cmake", "ruby", "php"];

pub fn managed_capability_tag(id: &str) -> Option<String> {
    MANAGED_CAPABILITY_IDS.contains(&id).then(|| format!("tool.{id}"))
}

pub const DEFAULT_WORKER_PROMPT: &str = "You are an autonomous LazyTeam coding worker. Execute only the assigned task in the provided repository workspace. Treat the task description and acceptance criteria as the contract. Inspect before editing, make the smallest correct change, preserve unrelated behavior, and follow repository instructions. Run relevant validation and never wait for interactive input. Do not broaden scope. If blocked, stop and report the concrete blocker. Do not expose secrets or modify external systems unless the task explicitly requires it. Finish with a concise summary of what changed, validation performed, and any remaining risks.";

pub const LEGACY_DEFAULT_REVIEWER_PROMPT: &str = "You are an independent senior LazyTeam reviewer. Review the exact pinned candidate commit in the provided repository checkout, not the worker's claims. Read the task contract and acceptance criteria, inspect the implementation and surrounding code, and run focused validation when practical. Treat the implementation worker as untrusted evidence: verify changed behavior yourself. Do not modify source code, create commits, push branches, merge, or broaden scope. Approve only when the candidate is correct, complete, scoped, and supported by evidence. Otherwise request a retry with a concise, actionable reason. Your final response must be exactly one JSON object with this shape: {\"verdict\":\"approve\"|\"retry\",\"reason\":\"...\",\"validation\":[\"...\"]}.";

pub const DEFAULT_REVIEWER_PROMPT: &str = "You are an independent senior LazyTeam reviewer. Review the exact pinned candidate commit in the provided repository checkout, not the worker's claims. Treat the task description and every acceptance criterion as the review contract. Before deciding, complete one full review sweep: map every acceptance criterion to concrete evidence, inspect the entire candidate diff plus relevant surrounding code, check for unrelated or generated-file changes, and run focused validation when practical. Do not stop after finding the first defect. Collect every material blocker you can substantiate during this pass, then report them together so the implementation worker can fix them in one retry. If some area cannot be reviewed because of a concrete blocker, say what could not be checked. Treat the implementation worker as untrusted evidence: verify changed behavior yourself. Do not modify source code, create commits, push branches, merge, or broaden scope. Approve only when the candidate is correct, complete, scoped, and supported by evidence. Otherwise request a retry whose reason enumerates all discovered blockers from the completed sweep, with file/criterion context where useful. Your final response must be exactly one JSON object with this shape: {\"verdict\":\"approve\"|\"retry\",\"reason\":\"...\",\"validation\":[\"...\"]}.";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentLoginMode {
    Unsupported,
    LocalInteractive,
    Remote,
}

impl Default for AgentLoginMode {
    fn default() -> Self { Self::Unsupported }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Default)]
pub struct AgentModelCost {
    #[serde(default)]
    pub input: f64,
    #[serde(default)]
    pub output: f64,
    #[serde(default)]
    pub cache_read: f64,
    #[serde(default)]
    pub cache_write: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct AgentProvider {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub configured: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct AgentModel {
    pub provider: String,
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub context_window: Option<u64>,
    #[serde(default)]
    pub reasoning: bool,
    #[serde(default)]
    pub cost: Option<AgentModelCost>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Default)]
pub struct AgentCapabilities {
    #[serde(default)]
    pub model_discovery: bool,
    #[serde(default)]
    pub login_mode: AgentLoginMode,
    #[serde(default)]
    pub providers: Vec<AgentProvider>,
    #[serde(default)]
    pub models: Vec<AgentModel>,
    #[serde(default)]
    pub probe_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    #[default]
    Worker,
    Reviewer,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum GitAuthMode {
    #[default]
    Host,
    SshKey,
    HttpsBasic,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
pub struct GitAuthConfig {
    #[serde(default)]
    pub mode: GitAuthMode,
    #[serde(default)]
    pub credential_configured: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_revision: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum GitCredential {
    #[default]
    Host,
    SshKey { private_key: String },
    HttpsBasic { username: String, secret: String },
}

impl fmt::Debug for GitCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host => formatter.write_str("GitCredential::Host"),
            Self::SshKey { .. } => formatter.write_str("GitCredential::SshKey { private_key: [REDACTED] }"),
            Self::HttpsBasic { username, .. } => formatter
                .debug_struct("GitCredential::HttpsBasic")
                .field("username", username)
                .field("secret", &"[REDACTED]")
                .finish(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ContributorIdentity {
    pub name: String,
    pub email: String,
}

impl Default for ContributorIdentity {
    fn default() -> Self {
        Self { name: "LazyTeam Worker".into(), email: "lazyteam@local".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Project {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub repo_url: String,
    pub default_branch: String,
    #[serde(default)]
    pub contributor: ContributorIdentity,
    #[serde(default)]
    pub required_worker_tags: Tags,
    #[serde(default)]
    pub default_task_tags: Tags,
    #[serde(default)]
    pub git_auth: GitAuthConfig,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkerState {
    Idle,
    Busy,
    Pending,
    Draining,
    Degraded,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct Worker {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub role: AgentRole,
    pub state: WorkerState,
    pub os: String,
    pub arch: String,
    #[serde(default)]
    pub system_tags: Tags,
    #[serde(default)]
    pub user_tags: Tags,
    #[serde(default)]
    pub managed_capabilities: BTreeSet<String>,
    #[serde(default)]
    pub installed_capabilities: BTreeSet<String>,
    #[serde(default)]
    pub capability_error: Option<String>,
    #[serde(default)]
    pub capability_phase: Option<String>,
    #[serde(default)]
    pub capability_log: String,
    /// Effective scheduler tags: system + user + selected managed capabilities that are installed.
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TaskState {
    Draft,
    Queued,
    Assigned,
    Running,
    Review,
    MergePending,
    Done,
    Blocked,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionState {
    Assigned,
    Running,
    Completed,
    Failed,
    Lost,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
    pub review_ref: Option<String>,
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
    pub lease_capability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewLease {
    pub id: Uuid,
    pub task_id: Uuid,
    pub execution_id: Uuid,
    pub reviewer_worker_id: Uuid,
    pub lease_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewCheckout {
    pub repo_url: String,
    pub default_branch: String,
    pub review_ref: String,
    pub commit_sha: String,
    pub base_sha: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewAssignment {
    pub review: ReviewLease,
    pub project: Project,
    pub task: Task,
    pub execution: Execution,
    pub implementation_worker: Worker,
    pub checkout: ReviewCheckout,
    pub lease_capability: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReviewVerdictKind {
    Approve,
    Retry,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewVerdict {
    pub verdict: ReviewVerdictKind,
    pub reason: String,
    #[serde(default)]
    pub validation: Vec<String>,
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
            role: AgentRole::Worker,
            state: WorkerState::Idle,
            os: "linux".into(),
            arch: "aarch64".into(),
            system_tags: BTreeMap::from([
                ("os".into(), "linux".into()),
                ("arch".into(), "aarch64".into()),
            ]),
            user_tags: BTreeMap::from([("cpu".into(), "rk3588".into())]),
            managed_capabilities: BTreeSet::new(),
            installed_capabilities: BTreeSet::new(),
            capability_error: None,
            capability_phase: None,
            capability_log: String::new(),
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
            contributor: ContributorIdentity::default(),
            required_worker_tags: BTreeMap::from([("cpu".into(), "rk3588".into())]),
            default_task_tags: BTreeMap::new(),
            git_auth: GitAuthConfig::default(),
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

    #[test]
    fn allowed_projects_blocks_other_projects() {
        let mut project = Project {
            id: Uuid::new_v4(),
            slug: "lazyteam".into(),
            name: "LazyTeam".into(),
            repo_url: "git@example/LazyTeam".into(),
            default_branch: "main".into(),
            contributor: ContributorIdentity::default(),
            required_worker_tags: BTreeMap::new(),
            default_task_tags: BTreeMap::new(),
            git_auth: GitAuthConfig::default(),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let w = worker();
        assert!(!worker_can_run_project(&w, &project));
        project.slug = "rocknpu".into();
        assert!(worker_can_run_project(&w, &project));
    }

    #[test]
    fn project_runner_labels_are_all_required() {
        let mut w = worker();
        w.tags.insert("tool.rust".into(), "true".into());
        let mut project = Project {
            id: Uuid::new_v4(),
            slug: "rocknpu".into(),
            name: "RockNPU".into(),
            repo_url: "git@example/RockNPU".into(),
            default_branch: "main".into(),
            contributor: ContributorIdentity::default(),
            required_worker_tags: BTreeMap::from([
                ("os".into(), "linux".into()),
                ("arch".into(), "aarch64".into()),
                ("tool.rust".into(), "true".into()),
            ]),
            default_task_tags: BTreeMap::new(),
            git_auth: GitAuthConfig::default(),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let task = Task {
            id: Uuid::new_v4(),
            project_id: project.id,
            title: "labels".into(),
            description: String::new(),
            expected_outcome: String::new(),
            acceptance_criteria: vec![],
            required_tags: BTreeMap::new(),
            preferred_tags: BTreeMap::new(),
            dependencies: vec![],
            review_feedback: String::new(),
            priority: 0,
            state: TaskState::Queued,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(worker_matches_task(&w, &project, &task));
        project.required_worker_tags.insert("site".into(), "lab".into());
        assert!(!worker_matches_task(&w, &project, &task));
    }
}
