use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub type Tags = BTreeMap<String, String>;

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
            priority: 0,
            state: TaskState::Queued,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(worker_matches_task(&worker(), &project, &task));
    }
}
