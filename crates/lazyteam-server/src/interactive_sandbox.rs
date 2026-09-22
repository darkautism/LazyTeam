use std::{
    collections::HashMap,
    fs::OpenOptions,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use anyhow::{bail, Context};
use lazyteam_core::{Assignment, ExecutionResult, ReviewAssignment, ReviewVerdict};
use lazyteam_sandbox::{prepare_agent_workspace, sync_agent_workspace, AgentSandbox};
use serde::Serialize;
use tokio::{
    io::AsyncWriteExt,
    process::Command,
    sync::{Notify, RwLock},
};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    api::{
        finish_execution_for_capability, finish_review_for_capability,
        release_execution_for_capability, release_review_for_capability,
        renew_execution_for_capability, renew_review_for_capability, WorkLeaseKind,
    },
    ApiError, AppState,
};

const MAX_OUTPUT_BYTES: usize = 50 * 1024;
const MAX_OUTPUT_LINES: usize = 2000;
const MAX_REVIEW_PATCH_BYTES: usize = 256 * 1024;
const SYNC_WAIT: Duration = Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SandboxRole {
    Implementation,
    Review,
}

#[derive(Clone, Default)]
pub(crate) struct InteractiveSandboxManager {
    inner: Arc<RwLock<HashMap<Uuid, Arc<Attachment>>>>,
}

struct Attachment {
    id: Uuid,
    role: SandboxRole,
    lease_id: Uuid,
    capability: String,
    root: PathBuf,
    trusted_workspace: PathBuf,
    agent_workspace: PathBuf,
    sandbox: Arc<AgentSandbox>,
    cancel: CancellationToken,
    processes: RwLock<HashMap<u32, Arc<ProcessEntry>>>,
    implementation: Option<ImplementationMeta>,
}

#[derive(Clone)]
struct ImplementationMeta {
    contributor_name: String,
    contributor_email: String,
    task_title: String,
    review_ref: String,
    base_sha: String,
}

struct ProcessEntry {
    pid: u32,
    log_path: PathBuf,
    state: RwLock<ProcessState>,
    notify: Notify,
}

#[derive(Clone, Copy)]
struct ProcessState {
    finished: bool,
    exit_code: Option<i32>,
}

#[derive(Debug, Serialize, schemars::JsonSchema)]
pub(crate) struct BashResult {
    pub(crate) status: &'static str,
    pub(crate) pid: u32,
    pub(crate) exit_code: Option<i32>,
    pub(crate) output: String,
    pub(crate) full_output_path: Option<String>,
    pub(crate) truncated: bool,
    pub(crate) instruction: Option<&'static str>,
}

pub(crate) async fn cleanup_stale_sandboxes(git_root: &Path) -> anyhow::Result<()> {
    let root = git_root.join("interactive-sandboxes");
    match tokio::fs::remove_dir_all(&root).await {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context(format!("remove stale interactive sandbox root {}", root.display())),
    }
    tokio::fs::create_dir_all(&root)
        .await
        .with_context(|| format!("create interactive sandbox root {}", root.display()))?;
    Ok(())
}

impl InteractiveSandboxManager {
    pub(crate) async fn attach_implementation(
        &self,
        state: Arc<AppState>,
        assignment: &Assignment,
    ) -> Result<Uuid, ApiError> {
        let sandbox_id = Uuid::new_v4();
        let root = sandbox_root(&state, sandbox_id);
        let trusted = root.join("trusted");
        let agent = root.join("agent");
        let sandbox_state = root.join("sandbox");
        tokio::fs::create_dir_all(&sandbox_state).await.map_err(internal)?;

        let task_repo = task_repo_path(&state, assignment.execution.id);
        let review_ref = format!("lazyteam/task-{}", assignment.task.id.simple());
        let base_sha = prepare_implementation_checkout(
            &task_repo,
            &trusted,
            &assignment.project.default_branch,
            &review_ref,
        )
        .await
        .map_err(internal)?;
        prepare_agent_workspace(&trusted, &agent, Some(&base_sha))
            .await
            .map_err(internal)?;

        let sandbox = Arc::new(
            AgentSandbox::prepare(&sandbox_state, "bash", None)
                .await
                .map_err(internal)?,
        );
        let attachment = Arc::new(Attachment {
            id: sandbox_id,
            role: SandboxRole::Implementation,
            lease_id: assignment.execution.id,
            capability: assignment.lease_capability.clone(),
            root,
            trusted_workspace: trusted,
            agent_workspace: agent,
            sandbox,
            cancel: CancellationToken::new(),
            processes: RwLock::new(HashMap::new()),
            implementation: Some(ImplementationMeta {
                contributor_name: assignment.project.contributor.name.clone(),
                contributor_email: assignment.project.contributor.email.clone(),
                task_title: assignment.task.title.clone(),
                review_ref,
                base_sha,
            }),
        });
        self.insert_and_start_heartbeat(state, attachment).await;
        Ok(sandbox_id)
    }

    pub(crate) async fn attach_review(
        &self,
        state: Arc<AppState>,
        assignment: &ReviewAssignment,
    ) -> Result<Uuid, ApiError> {
        let sandbox_id = Uuid::new_v4();
        let root = sandbox_root(&state, sandbox_id);
        let trusted = root.join("trusted");
        let agent = root.join("agent");
        let sandbox_state = root.join("sandbox");
        tokio::fs::create_dir_all(&sandbox_state).await.map_err(internal)?;

        let task_repo = task_repo_path(&state, assignment.execution.id);
        let integration_sha = assignment
            .checkout
            .integration_sha
            .as_deref()
            .unwrap_or(&assignment.checkout.commit_sha);
        let upstream_sha = assignment
            .checkout
            .upstream_sha
            .as_deref()
            .or(assignment.checkout.base_sha.as_deref())
            .ok_or_else(|| conflict("review checkout has no pinned upstream/base SHA"))?;
        prepare_review_checkout(
            &task_repo,
            &trusted,
            &assignment.project.default_branch,
            &assignment.checkout.review_ref,
            &assignment.checkout.commit_sha,
            integration_sha,
        )
        .await
        .map_err(internal)?;
        prepare_agent_workspace(&trusted, &agent, Some(upstream_sha))
            .await
            .map_err(internal)?;

        let sandbox = Arc::new(
            AgentSandbox::prepare(&sandbox_state, "bash", None)
                .await
                .map_err(internal)?,
        );
        let attachment = Arc::new(Attachment {
            id: sandbox_id,
            role: SandboxRole::Review,
            lease_id: assignment.review.id,
            capability: assignment.lease_capability.clone(),
            root,
            trusted_workspace: trusted,
            agent_workspace: agent,
            sandbox,
            cancel: CancellationToken::new(),
            processes: RwLock::new(HashMap::new()),
            implementation: None,
        });
        self.insert_and_start_heartbeat(state, attachment).await;
        Ok(sandbox_id)
    }

    async fn insert_and_start_heartbeat(&self, state: Arc<AppState>, attachment: Arc<Attachment>) {
        self.inner.write().await.insert(attachment.id, attachment.clone());
        let manager = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = attachment.cancel.cancelled() => break,
                    _ = tokio::time::sleep(HEARTBEAT_INTERVAL) => {
                        if renew_attachment(&state, &attachment).await.is_err() {
                            manager.detach_local(attachment.id).await;
                            break;
                        }
                    }
                }
            }
        });
    }

    async fn attachment(&self, state: &Arc<AppState>, sandbox_id: Uuid) -> Result<Arc<Attachment>, ApiError> {
        let attachment = self
            .inner
            .read()
            .await
            .get(&sandbox_id)
            .cloned()
            .ok_or_else(|| conflict("sandbox_id is not attached"))?;
        renew_attachment(state, &attachment).await?;
        Ok(attachment)
    }

    pub(crate) async fn read(
        &self,
        state: &Arc<AppState>,
        sandbox_id: Uuid,
        path: &str,
        offset: Option<usize>,
        limit: Option<usize>,
    ) -> Result<String, ApiError> {
        let attachment = self.attachment(state, sandbox_id).await?;
        let text = read_full(&attachment, path).await?;
        Ok(bounded_lines(&text, offset, limit))
    }

    pub(crate) async fn write(
        &self,
        state: &Arc<AppState>,
        sandbox_id: Uuid,
        path: &str,
        content: &str,
    ) -> Result<(), ApiError> {
        let attachment = self.attachment(state, sandbox_id).await?;
        let mut command = attachment
            .sandbox
            .command("/bin/sh", &attachment.agent_workspace, None)
            .map_err(internal)?;
        command
            .args([
                "-c",
                "mkdir -p -- \"$(dirname -- \"$1\")\" && cat > \"$1\"",
                "lazyteam-write",
            ])
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = command.spawn().map_err(internal)?;
        child
            .stdin
            .take()
            .ok_or_else(|| internal(anyhow::anyhow!("sandbox write stdin unavailable")))?
            .write_all(content.as_bytes())
            .await
            .map_err(internal)?;
        let output = child.wait_with_output().await.map_err(internal)?;
        if !output.status.success() {
            return Err(conflict(format!(
                "write {path}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }
        Ok(())
    }

    pub(crate) async fn edit(
        &self,
        state: &Arc<AppState>,
        sandbox_id: Uuid,
        path: &str,
        edits: &[(String, String)],
    ) -> Result<(), ApiError> {
        if edits.is_empty() {
            return Err(conflict("edits must not be empty"));
        }
        let attachment = self.attachment(state, sandbox_id).await?;
        let original = read_full(&attachment, path).await?;
        let mut replacements = Vec::with_capacity(edits.len());
        for (old, new) in edits {
            if old.is_empty() {
                return Err(conflict("edits[].oldText must not be empty"));
            }
            let matches: Vec<_> = original.match_indices(old).collect();
            if matches.len() != 1 {
                return Err(conflict(format!(
                    "edits[].oldText must match exactly once; matched {} times",
                    matches.len()
                )));
            }
            replacements.push((matches[0].0, matches[0].0 + old.len(), new.clone()));
        }
        replacements.sort_by_key(|(start, _, _)| *start);
        for pair in replacements.windows(2) {
            if pair[0].1 > pair[1].0 {
                return Err(conflict("edits overlap; merge nearby edits into one replacement"));
            }
        }
        let mut updated = original;
        for (start, end, new) in replacements.into_iter().rev() {
            updated.replace_range(start..end, &new);
        }
        self.write(state, sandbox_id, path, &updated).await
    }

    pub(crate) async fn bash(
        &self,
        state: &Arc<AppState>,
        sandbox_id: Uuid,
        command: Option<String>,
        pid: Option<u32>,
    ) -> Result<BashResult, ApiError> {
        let attachment = self.attachment(state, sandbox_id).await?;
        match (command, pid) {
            (Some(command), None) => start_command(attachment, command).await,
            (None, Some(pid)) => attach_process(attachment, pid).await,
            _ => Err(conflict("provide exactly one of command or pid")),
        }
    }

    pub(crate) async fn finish_implementation(
        &self,
        state: &Arc<AppState>,
        sandbox_id: Uuid,
        summary: String,
        validation: Vec<String>,
        warnings: Vec<String>,
        artifacts: Vec<String>,
    ) -> Result<Uuid, ApiError> {
        let attachment = self.attachment(state, sandbox_id).await?;
        if attachment.role != SandboxRole::Implementation {
            return Err(conflict("sandbox is not implementation work"));
        }
        let meta = attachment
            .implementation
            .clone()
            .ok_or_else(|| conflict("implementation sandbox metadata is missing"))?;

        sync_agent_workspace(&attachment.agent_workspace, &attachment.trusted_workspace)
            .await
            .map_err(internal)?;
        auto_commit(&attachment.trusted_workspace, &meta)
            .await
            .map_err(internal)?;

        let head_sha = git_output(&attachment.trusted_workspace, &["rev-parse", "HEAD"])
            .await
            .map_err(internal)?;
        let head_tree = git_output(&attachment.trusted_workspace, &["rev-parse", "HEAD^{tree}"])
            .await
            .map_err(internal)?;
        let base_tree = git_output(
            &attachment.trusted_workspace,
            &["rev-parse", &format!("{}^{{tree}}", meta.base_sha)],
        )
        .await
        .map_err(internal)?;
        if head_tree == base_tree {
            return Err(conflict("agent completed without producing any tracked change"));
        }

        command_ok(
            &attachment.trusted_workspace,
            &[
                "push",
                "origin",
                &format!("HEAD:refs/heads/{}", meta.review_ref),
            ],
        )
        .await
        .map_err(internal)?;

        let changed_files = git_output(
            &attachment.trusted_workspace,
            &["diff", "--name-only", &meta.base_sha],
        )
        .await
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
        let raw_patch = git_output(
            &attachment.trusted_workspace,
            &["diff", "--no-ext-diff", "--unified=40", &meta.base_sha],
        )
        .await
        .unwrap_or_default();
        let (patch, patch_truncated) = bounded_patch(raw_patch, MAX_REVIEW_PATCH_BYTES);
        let workspace_clean = git_output(&attachment.trusted_workspace, &["status", "--porcelain"])
            .await
            .map(|value| value.is_empty())
            .ok();

        let result = ExecutionResult {
            status: "completed".into(),
            summary,
            commit_sha: Some(head_sha),
            base_sha: Some(meta.base_sha),
            patch: (!patch.is_empty()).then_some(patch),
            patch_truncated,
            workspace_clean,
            review_ref: Some(meta.review_ref),
            changed_files,
            validation,
            warnings,
            artifacts,
            integration: None,
        };
        finish_execution_for_capability(
            state,
            attachment.lease_id,
            &attachment.capability,
            result,
            None,
        )
        .await?;
        let lease_id = attachment.lease_id;
        self.detach_local(sandbox_id).await;
        Ok(lease_id)
    }

    pub(crate) async fn finish_review(
        &self,
        state: &Arc<AppState>,
        sandbox_id: Uuid,
        verdict: ReviewVerdict,
    ) -> Result<Uuid, ApiError> {
        let attachment = self.attachment(state, sandbox_id).await?;
        if attachment.role != SandboxRole::Review {
            return Err(conflict("sandbox is not review work"));
        }
        finish_review_for_capability(
            state,
            attachment.lease_id,
            &attachment.capability,
            "completed",
            Some(verdict),
            None,
            None,
        )
        .await?;
        let lease_id = attachment.lease_id;
        self.detach_local(sandbox_id).await;
        Ok(lease_id)
    }

    pub(crate) async fn release(
        &self,
        state: &Arc<AppState>,
        sandbox_id: Uuid,
    ) -> Result<(Uuid, WorkLeaseKind), ApiError> {
        let attachment = self.attachment(state, sandbox_id).await?;
        let kind = match attachment.role {
            SandboxRole::Implementation => {
                release_execution_for_capability(
                    state,
                    attachment.lease_id,
                    &attachment.capability,
                    None,
                )
                .await?;
                WorkLeaseKind::Implementation
            }
            SandboxRole::Review => {
                release_review_for_capability(
                    state,
                    attachment.lease_id,
                    &attachment.capability,
                    None,
                )
                .await?;
                WorkLeaseKind::Review
            }
        };
        let lease_id = attachment.lease_id;
        self.detach_local(sandbox_id).await;
        Ok((lease_id, kind))
    }

    pub(crate) async fn detach_local(&self, sandbox_id: Uuid) {
        let attachment = self.inner.write().await.remove(&sandbox_id);
        if let Some(attachment) = attachment {
            attachment.cancel.cancel();
            let _ = tokio::fs::remove_dir_all(&attachment.root).await;
        }
    }

    pub(crate) async fn role(&self, sandbox_id: Uuid) -> Option<SandboxRole> {
        self.inner.read().await.get(&sandbox_id).map(|attachment| attachment.role)
    }

    #[cfg(test)]
    pub(crate) async fn contains(&self, sandbox_id: Uuid) -> bool {
        self.inner.read().await.contains_key(&sandbox_id)
    }
}

async fn renew_attachment(state: &Arc<AppState>, attachment: &Attachment) -> Result<(), ApiError> {
    match attachment.role {
        SandboxRole::Implementation => {
            renew_execution_for_capability(
                state,
                attachment.lease_id,
                &attachment.capability,
                None,
            )
            .await
        }
        SandboxRole::Review => {
            renew_review_for_capability(
                state,
                attachment.lease_id,
                &attachment.capability,
                None,
            )
            .await
        }
    }
}

async fn read_full(attachment: &Attachment, path: &str) -> Result<String, ApiError> {
    let mut command = attachment
        .sandbox
        .command("/bin/cat", &attachment.agent_workspace, None)
        .map_err(internal)?;
    let output = command.arg("--").arg(path).output().await.map_err(internal)?;
    if !output.status.success() {
        return Err(conflict(format!(
            "read {path}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    String::from_utf8(output.stdout)
        .map_err(|_| conflict(format!("{path} is not a UTF-8 text file")))
}

async fn start_command(attachment: Arc<Attachment>, command: String) -> Result<BashResult, ApiError> {
    let log_dir = attachment.root.join("logs");
    tokio::fs::create_dir_all(&log_dir).await.map_err(internal)?;
    let log_path = log_dir.join(format!("{}.log", Uuid::new_v4()));
    let stdout_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(internal)?;
    let stderr_file = stdout_file.try_clone().map_err(internal)?;

    let mut child = attachment
        .sandbox
        .command("/bin/bash", &attachment.agent_workspace, None)
        .map_err(internal)?;
    child
        .args(["-lc", &command])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    let mut child = child.spawn().map_err(internal)?;
    let pid = child
        .id()
        .ok_or_else(|| internal(anyhow::anyhow!("spawned bash has no pid")))?;
    let entry = Arc::new(ProcessEntry {
        pid,
        log_path,
        state: RwLock::new(ProcessState {
            finished: false,
            exit_code: None,
        }),
        notify: Notify::new(),
    });
    attachment.processes.write().await.insert(pid, entry.clone());

    let cancel = attachment.cancel.clone();
    let watcher = entry.clone();
    tokio::spawn(async move {
        let exit_code = tokio::select! {
            waited = child.wait() => waited.ok().and_then(|status| status.code()),
            _ = cancel.cancelled() => {
                let _ = child.kill().await;
                child.wait().await.ok().and_then(|status| status.code())
            }
        };
        let mut state = watcher.state.write().await;
        state.finished = true;
        state.exit_code = exit_code;
        drop(state);
        watcher.notify.notify_waiters();
    });

    let notified = entry.notify.notified();
    if !entry.state.read().await.finished {
        let _ = tokio::time::timeout(SYNC_WAIT, notified).await;
    }
    process_result(&entry).await
}

async fn attach_process(attachment: Arc<Attachment>, pid: u32) -> Result<BashResult, ApiError> {
    let entry = attachment
        .processes
        .read()
        .await
        .get(&pid)
        .cloned()
        .ok_or_else(|| conflict(format!("unknown pid {pid}")))?;
    let notified = entry.notify.notified();
    if !entry.state.read().await.finished {
        let _ = tokio::time::timeout(SYNC_WAIT, notified).await;
    }
    process_result(&entry).await
}

async fn process_result(entry: &Arc<ProcessEntry>) -> Result<BashResult, ApiError> {
    let state = *entry.state.read().await;
    let (output, truncated) = bounded_tail(&entry.log_path).await?;
    if !state.finished {
        return Ok(BashResult {
            status: "running",
            pid: entry.pid,
            exit_code: None,
            output,
            full_output_path: Some(entry.log_path.to_string_lossy().to_string()),
            truncated,
            instruction: Some(
                "This task is taking longer than 10 seconds. Continue with other independent work and attach this pid later. Do not immediately wait on it again unless its result is now required.",
            ),
        });
    }
    Ok(BashResult {
        status: "exited",
        pid: entry.pid,
        exit_code: state.exit_code,
        output,
        full_output_path: Some(entry.log_path.to_string_lossy().to_string()),
        truncated,
        instruction: None,
    })
}

async fn prepare_implementation_checkout(
    task_repo: &Path,
    trusted: &Path,
    default_branch: &str,
    review_ref: &str,
) -> anyhow::Result<String> {
    clone_default(task_repo, trusted, default_branch).await?;
    let base_sha = git_output(trusted, &["rev-parse", "HEAD"]).await?;
    let seeded_ref = format!("refs/heads/{review_ref}");
    if git_ref_exists(task_repo, &seeded_ref).await? {
        command_ok(
            trusted,
            &[
                "fetch",
                "origin",
                &format!("+{seeded_ref}:refs/remotes/origin/lazyteam-seeded"),
            ],
        )
        .await?;
        command_ok(
            trusted,
            &["checkout", "-b", "lazyteam-task", "refs/remotes/origin/lazyteam-seeded"],
        )
        .await?;
        command_ok(trusted, &["merge", "--no-edit", &base_sha]).await?;
    } else {
        command_ok(trusted, &["checkout", "-b", "lazyteam-task"]).await?;
    }
    sanitize_trusted_checkout(trusted).await?;
    Ok(base_sha)
}

async fn prepare_review_checkout(
    task_repo: &Path,
    trusted: &Path,
    default_branch: &str,
    review_ref: &str,
    candidate_sha: &str,
    integration_sha: &str,
) -> anyhow::Result<()> {
    clone_default(task_repo, trusted, default_branch).await?;
    if integration_sha == candidate_sha {
        let source_ref = format!("refs/heads/{review_ref}");
        command_ok(
            trusted,
            &[
                "fetch",
                "origin",
                &format!("+{source_ref}:refs/remotes/origin/lazyteam-review"),
            ],
        )
        .await?;
    } else {
        let source_ref = format!("refs/lazyteam/integration/{integration_sha}");
        command_ok(
            trusted,
            &[
                "fetch",
                "origin",
                &format!("+{source_ref}:refs/remotes/origin/lazyteam-review"),
            ],
        )
        .await?;
    }
    let actual = git_output(
        trusted,
        &["rev-parse", "--verify", "refs/remotes/origin/lazyteam-review"],
    )
    .await?;
    if actual != integration_sha {
        bail!("review integration ref moved: expected {integration_sha}, got {actual}");
    }
    command_ok(trusted, &["checkout", "--detach", integration_sha]).await?;
    sanitize_trusted_checkout(trusted).await
}

async fn clone_default(task_repo: &Path, trusted: &Path, default_branch: &str) -> anyhow::Result<()> {
    if let Some(parent) = trusted.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let output = trusted_git_command()
        .args([
            "clone",
            "--no-local",
            "--branch",
            default_branch,
            "--single-branch",
        ])
        .arg(task_repo)
        .arg(trusted)
        .output()
        .await?;
    if !output.status.success() {
        bail!(
            "clone trusted task checkout failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

async fn sanitize_trusted_checkout(path: &Path) -> anyhow::Result<()> {
    command_ok(path, &["config", "--local", "core.hooksPath", "/dev/null"]).await?;
    command_ok(path, &["config", "--local", "credential.helper", ""]).await?;
    command_ok(path, &["config", "--local", "core.fsmonitor", "false"]).await
}

async fn auto_commit(path: &Path, meta: &ImplementationMeta) -> anyhow::Result<()> {
    command_ok(path, &["reset"]).await?;
    command_ok(path, &["add", "-A"]).await?;
    let status = trusted_git_command()
        .args(["diff", "--cached", "--quiet"])
        .current_dir(path)
        .status()
        .await?;
    if status.success() {
        return Ok(());
    }
    command_ok(
        path,
        &[
            "-c",
            &format!("user.name={}", meta.contributor_name),
            "-c",
            &format!("user.email={}", meta.contributor_email),
            "commit",
            "-m",
            &format!("lazyteam: {}", meta.task_title),
        ],
    )
    .await
}

fn trusted_git_command() -> Command {
    let mut command = Command::new("git");
    command
        .args(["-c", "core.hooksPath=/dev/null"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

async fn command_ok(path: &Path, args: &[&str]) -> anyhow::Result<()> {
    let output = trusted_git_command().args(args).current_dir(path).output().await?;
    if !output.status.success() {
        bail!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

async fn git_output(path: &Path, args: &[&str]) -> anyhow::Result<String> {
    let output = trusted_git_command().args(args).current_dir(path).output().await?;
    if !output.status.success() {
        bail!(
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

async fn git_ref_exists(repo: &Path, reference: &str) -> anyhow::Result<bool> {
    let status = trusted_git_command()
        .arg("--git-dir")
        .arg(repo)
        .args(["show-ref", "--verify", "--quiet", reference])
        .status()
        .await?;
    Ok(status.success())
}

fn sandbox_root(state: &AppState, sandbox_id: Uuid) -> PathBuf {
    state
        .git_root
        .join("interactive-sandboxes")
        .join(sandbox_id.to_string())
}

fn task_repo_path(state: &AppState, execution_id: Uuid) -> PathBuf {
    state
        .git_root
        .join("tasks")
        .join(format!("{execution_id}.git"))
}

fn bounded_lines(text: &str, offset: Option<usize>, limit: Option<usize>) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let start = offset.unwrap_or(1).saturating_sub(1).min(lines.len());
    let end = limit
        .map(|limit| start.saturating_add(limit).min(lines.len()))
        .unwrap_or(lines.len());
    let selected = &lines[start..end];
    let mut output = String::new();
    let mut count = 0usize;
    for line in selected {
        let needed = line.len() + usize::from(!output.is_empty());
        if count >= MAX_OUTPUT_LINES || output.len().saturating_add(needed) > MAX_OUTPUT_BYTES {
            output.push_str(&format!(
                "\n\n[Output truncated. Continue reading with offset={}.]",
                start + count + 1
            ));
            break;
        }
        if !output.is_empty() {
            output.push('\n');
        }
        output.push_str(line);
        count += 1;
    }
    output
}

async fn bounded_tail(path: &Path) -> Result<(String, bool), ApiError> {
    let bytes = tokio::fs::read(path).await.map_err(internal)?;
    let text = String::from_utf8_lossy(&bytes);
    let total_lines = text.lines().count();
    if bytes.len() <= MAX_OUTPUT_BYTES && total_lines <= MAX_OUTPUT_LINES {
        return Ok((text.into_owned(), false));
    }
    let mut lines: Vec<&str> = text.lines().rev().take(MAX_OUTPUT_LINES).collect();
    lines.reverse();
    let mut output = lines.join("\n");
    if output.len() > MAX_OUTPUT_BYTES {
        let start = output.len() - MAX_OUTPUT_BYTES;
        let mut boundary = start;
        while !output.is_char_boundary(boundary) {
            boundary += 1;
        }
        output = output[boundary..].to_string();
        if let Some(newline) = output.find('\n') {
            output = output[newline + 1..].to_string();
        }
    }
    output.push_str(&format!(
        "\n\n[Output truncated. Showing the last bounded portion. Full output: {}]",
        path.display()
    ));
    Ok((output, true))
}

fn bounded_patch(mut patch: String, max_bytes: usize) -> (String, bool) {
    if patch.len() <= max_bytes {
        return (patch, false);
    }
    let mut end = max_bytes.min(patch.len());
    while !patch.is_char_boundary(end) {
        end -= 1;
    }
    patch.truncate(end);
    patch.push_str("\n\n[LazyTeam review patch truncated]\n");
    (patch, true)
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    (axum::http::StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

fn conflict(message: impl Into<String>) -> ApiError {
    (axum::http::StatusCode::CONFLICT, message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{claim_review_for_worker, claim_task_for_worker, ensure_internal_work_actor};
    use chrono::Utc;
    use lazyteam_core::{AgentRole, ReviewVerdictKind};
    use sqlx::sqlite::SqlitePoolOptions;

    fn git_ok(cwd: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .args(["-c", "core.hooksPath=/dev/null"])
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    fn git_stdout(cwd: &Path, args: &[&str]) -> String {
        let output = std::process::Command::new("git")
            .args(["-c", "core.hooksPath=/dev/null"])
            .args(args)
            .current_dir(cwd)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        assert!(output.status.success(), "git {args:?} failed: {}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    async fn e2e_state() -> (Arc<AppState>, Uuid, PathBuf) {
        let root = std::env::temp_dir().join(format!("lazyteam-interactive-sandbox-e2e-{}", Uuid::new_v4()));
        let source = root.join("source");
        let upstream = root.join("upstream.git");
        let git_root = root.join("host-git");
        tokio::fs::create_dir_all(&source).await.unwrap();
        tokio::fs::create_dir_all(&git_root).await.unwrap();

        git_ok(&source, &["init", "-q", "-b", "main"]);
        git_ok(&source, &["config", "user.name", "Test"]);
        git_ok(&source, &["config", "user.email", "test@example.invalid"]);
        tokio::fs::write(source.join("README.md"), "hello from base\n").await.unwrap();
        git_ok(&source, &["add", "README.md"]);
        git_ok(&source, &["commit", "-q", "-m", "base"]);
        let clone = std::process::Command::new("git")
            .args(["clone", "-q", "--bare"])
            .arg(&source)
            .arg(&upstream)
            .output()
            .unwrap();
        assert!(clone.status.success(), "bare clone failed: {}", String::from_utf8_lossy(&clone.stderr));

        let db = SqlitePoolOptions::new()
            .max_connections(4)
            .connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let state = Arc::new(AppState {
            db,
            public_url: Some("http://localhost:8787".into()),
            oauth_password: None,
            git_credential_key: None,
            git_root,
            agent_auth_updates: Default::default(),
            model_refresh_requests: Default::default(),
            oauth_login_states: Default::default(),
            interactive_sandboxes: Default::default(),
        });

        let project_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        let now = Utc::now().to_rfc3339();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,git_auth_mode,contributor_name,contributor_email,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(project_id.to_string())
            .bind("sandbox-e2e")
            .bind("Sandbox E2E")
            .bind(upstream.to_string_lossy().to_string())
            .bind("main")
            .bind("host")
            .bind("LazyTeam Test")
            .bind("lazyteam-test@example.invalid")
            .bind(&now)
            .bind(&now)
            .execute(&state.db)
            .await
            .unwrap();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string())
            .bind(project_id.to_string())
            .bind("Edit README through sandbox")
            .bind("Use the interactive sandbox")
            .bind("README changes")
            .bind("queued")
            .bind(&now)
            .bind(&now)
            .execute(&state.db)
            .await
            .unwrap();

        (state, task_id, root)
    }

    #[tokio::test]
    #[ignore = "requires LAZYTEAM_SANDBOX_LAUNCHER pointing at a built lazyteam-server binary"]
    async fn interactive_sandbox_runs_implementation_and_review_end_to_end() {
        let (state, task_id, root) = e2e_state().await;
        let worker = ensure_internal_work_actor(&state, AgentRole::Worker).await.unwrap();
        let assignment = claim_task_for_worker(&state, worker, Some(task_id))
            .await.unwrap().expect("implementation claim");
        let execution_id = assignment.execution.id;

        let sandbox_id = state.interactive_sandboxes
            .attach_implementation(state.clone(), &assignment).await.unwrap();
        assert!(state.interactive_sandboxes.contains(sandbox_id).await);
        assert_eq!(
            state.interactive_sandboxes.read(&state, sandbox_id, "README.md", None, None).await.unwrap(),
            "hello from base"
        );

        state.interactive_sandboxes.edit(
            &state,
            sandbox_id,
            "README.md",
            &[("hello from base".into(), "hello from sandbox".into())],
        ).await.unwrap();

        let bash = state.interactive_sandboxes
            .bash(&state, sandbox_id, Some("git diff -- README.md".into()), None)
            .await.unwrap();
        assert_eq!(bash.status, "exited");
        assert_eq!(bash.exit_code, Some(0));
        assert!(bash.output.contains("hello from sandbox"));

        state.interactive_sandboxes.finish_implementation(
            &state,
            sandbox_id,
            "changed README".into(),
            vec!["git diff inspected".into()],
            vec![],
            vec![],
        ).await.unwrap();
        assert!(!state.interactive_sandboxes.contains(sandbox_id).await);

        let task_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
            .bind(task_id.to_string()).fetch_one(&state.db).await.unwrap();
        assert_eq!(task_state, "review");

        let result_json: String = sqlx::query_scalar("SELECT result FROM executions WHERE id=?")
            .bind(execution_id.to_string()).fetch_one(&state.db).await.unwrap();
        let result: ExecutionResult = serde_json::from_str(&result_json).unwrap();
        let candidate = result.commit_sha.clone().expect("candidate SHA");
        let review_ref = result.review_ref.clone().expect("review ref");
        assert_eq!(
            git_stdout(&task_repo_path(&state, execution_id), &["rev-parse", "--verify", &format!("refs/heads/{review_ref}")]),
            candidate
        );

        let reviewer = ensure_internal_work_actor(&state, AgentRole::Reviewer).await.unwrap();
        let review_assignment = claim_review_for_worker(&state, reviewer, Some(task_id))
            .await.unwrap().expect("review claim");
        let review_sandbox = state.interactive_sandboxes
            .attach_review(state.clone(), &review_assignment).await.unwrap();
        assert_eq!(
            state.interactive_sandboxes.read(&state, review_sandbox, "README.md", None, None).await.unwrap(),
            "hello from sandbox"
        );

        let review_diff = state.interactive_sandboxes
            .bash(&state, review_sandbox, Some("git diff lazyteam-base..HEAD -- README.md".into()), None)
            .await.unwrap();
        assert_eq!(review_diff.exit_code, Some(0));
        assert!(review_diff.output.contains("hello from sandbox"));

        state.interactive_sandboxes.finish_review(
            &state,
            review_sandbox,
            ReviewVerdict {
                verdict: ReviewVerdictKind::Approve,
                reason: "sandbox review passed".into(),
                validation: vec!["pinned README diff inspected".into()],
            },
        ).await.unwrap();

        let final_state: String = sqlx::query_scalar("SELECT state FROM tasks WHERE id=?")
            .bind(task_id.to_string()).fetch_one(&state.db).await.unwrap();
        assert_eq!(final_state, "merge_pending");
        assert!(!state.interactive_sandboxes.contains(review_sandbox).await);
        let _ = tokio::fs::remove_dir_all(root).await;
    }
}
