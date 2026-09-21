use std::{path::{Path, PathBuf}, process::Stdio, sync::Arc};

use axum::{
    body::{to_bytes, Body},
    extract::{Path as AxumPath, Request, State},
    http::{header, HeaderName, HeaderValue, Response, StatusCode},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use lazyteam_core::{GitCredential, IntegrationSnapshot, MergeConflictEvidence, MergeConflictFile, Project};
use rmcp::schemars::JsonSchema;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::Row;
use tokio::{io::AsyncWriteExt, process::Command};
use uuid::Uuid;

use crate::{api, ApiError, AppState};

const MAX_GIT_BODY: usize = 256 * 1024 * 1024;

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/git/task/{execution_id}/repo.git/{*path}",
            get(task_git).post(task_git),
        )
        .route(
            "/git/review/{review_id}/repo.git/{*path}",
            get(review_git).post(review_git),
        )
}

pub(crate) fn task_repo_url(state: &AppState, execution_id: Uuid) -> Result<String, ApiError> {
    broker_url(state, "task", execution_id)
}

pub(crate) fn review_repo_url(state: &AppState, review_id: Uuid) -> Result<String, ApiError> {
    broker_url(state, "review", review_id)
}

fn broker_url(state: &AppState, kind: &str, id: Uuid) -> Result<String, ApiError> {
    let base = state.public_url.as_deref().ok_or((
        StatusCode::CONFLICT,
        "LAZYTEAM_PUBLIC_URL is required for worker Git broker URLs".into(),
    ))?;
    Ok(format!("{base}/git/{kind}/{id}/repo.git"))
}

pub(crate) struct GitProbeStatus {
    pub(crate) read_ok: bool,
    pub(crate) write_ok: bool,
    pub(crate) message: String,
}

pub(crate) async fn probe_project(
    state: &AppState,
    project: &Project,
    credential: &GitCredential,
) -> Result<GitProbeStatus, String> {
    let upstream_url = upstream_repo_url(&project.repo_url, credential)
        .map_err(|error| error.to_string())?;
    let auth = HostGitAuth::prepare(state, credential)
        .await
        .map_err(|error| error.to_string())?;
    let default_ref = format!("refs/heads/{}", project.default_branch);
    let probe_root = state.git_root.join("probes");
    tokio::fs::create_dir_all(&probe_root).await.map_err(|error| format!("create Host Git probe directory: {error}"))?;
    let probe_repo = probe_root.join(format!("{}.git", Uuid::new_v4()));

    let result = async {
        let mut init = Command::new("git");
        init.args(["init", "--bare"]).arg(&probe_repo);
        probe_git_command(&HostGitAuth::none(), &mut init, "initialize Host Git probe").await?;

        let refspec = format!("{default_ref}:{default_ref}");
        let mut fetch = Command::new("git");
        fetch.arg("-C").arg(&probe_repo).args(["fetch", "--no-tags", &upstream_url, &refspec]);
        if let Err(error) = probe_git_command(&auth, &mut fetch, "read upstream default branch").await {
            return Ok(GitProbeStatus {
                read_ok: false,
                write_ok: false,
                message: format!("Host cannot read {default_ref}: {error}"),
            });
        }

        let mut push = Command::new("git");
        push.arg("-C").arg(&probe_repo).args(["push", "--dry-run", &upstream_url, &refspec]);
        if let Err(error) = probe_git_command(&auth, &mut push, "dry-run upstream write").await {
            return Ok(GitProbeStatus {
                read_ok: true,
                write_ok: false,
                message: format!("Host can read {default_ref}, but upstream rejected dry-run write: {error}"),
            });
        }

        Ok(GitProbeStatus {
            read_ok: true,
            write_ok: true,
            message: format!("Host can read and dry-run write {default_ref}"),
        })
    }.await;

    let _ = tokio::fs::remove_dir_all(&probe_repo).await;
    auth.cleanup().await;
    result
}

async fn probe_git_command(auth: &HostGitAuth, command: &mut Command, step: &str) -> Result<(), String> {
    auth.apply(command);
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    match tokio::time::timeout(std::time::Duration::from_secs(12), command.output()).await {
        Ok(Ok(output)) if output.status.success() => Ok(()),
        Ok(Ok(output)) => {
            let message = String::from_utf8_lossy(&output.stderr).trim().to_string();
            Err(if message.is_empty() { format!("{step} failed") } else { message })
        }
        Ok(Err(error)) => Err(format!("{step}: {error}")),
        Err(_) => Err(format!("{step} timed out after 12 seconds")),
    }
}

pub(crate) async fn prepare_task_repo(
    state: &AppState,
    project: &Project,
    task_id: Uuid,
    execution_id: Uuid,
    credential: &GitCredential,
) -> Result<(), ApiError> {
    tokio::fs::create_dir_all(projects_root(state)).await.map_err(internal)?;
    tokio::fs::create_dir_all(tasks_root(state)).await.map_err(internal)?;
    let upstream_url = upstream_repo_url(&project.repo_url, credential).map_err(internal)?;
    let auth = HostGitAuth::prepare(state, credential).await.map_err(internal)?;
    let result = prepare_task_repo_inner(state, project, task_id, execution_id, &upstream_url, &auth).await;
    auth.cleanup().await;
    result
}

async fn prepare_task_repo_inner(
    state: &AppState,
    project: &Project,
    task_id: Uuid,
    execution_id: Uuid,
    upstream_url: &str,
    auth: &HostGitAuth,
) -> Result<(), ApiError> {
    let mirror = project_mirror(state, project.id);
    if mirror.exists() {
        git_ok(
            auth,
            Command::new("git")
                .arg("-C").arg(&mirror)
                .args(["remote", "set-url", "origin", upstream_url]),
        ).await?;
        git_ok(
            auth,
            Command::new("git")
                .arg("-C").arg(&mirror)
                .args(["fetch", "--prune", "origin"]),
        ).await?;
    } else {
        git_ok(
            auth,
            Command::new("git")
                .args(["clone", "--mirror", upstream_url])
                .arg(&mirror),
        ).await?;
    }

    let default_ref = format!("refs/heads/{}", project.default_branch);
    let verify = git_output(
        auth,
        Command::new("git")
            .arg("-C").arg(&mirror)
            .args(["rev-parse", "--verify", &default_ref]),
    ).await?;
    if verify.trim().is_empty() {
        return Err((StatusCode::CONFLICT, format!("upstream default branch {} is missing", project.default_branch)));
    }

    let task_repo = task_repo_path(state, execution_id);
    if task_repo.exists() {
        tokio::fs::remove_dir_all(&task_repo).await.map_err(internal)?;
    }
    git_ok(
        &HostGitAuth::none(),
        Command::new("git")
            .args(["init", "--bare"])
            .arg(&task_repo),
    ).await?;
    let default_refspec = format!("{default_ref}:{default_ref}");
    git_ok(
        &HostGitAuth::none(),
        Command::new("git")
            .arg("-C").arg(&task_repo)
            .arg("fetch")
            .arg("--no-tags")
            .arg(&mirror)
            .arg(&default_refspec),
    ).await?;
    git_ok(
        &HostGitAuth::none(),
        Command::new("git")
            .arg("-C").arg(&task_repo)
            .args(["symbolic-ref", "HEAD", &default_ref]),
    ).await?;
    git_ok(
        &HostGitAuth::none(),
        Command::new("git")
            .arg("-C").arg(&task_repo)
            .args(["config", "http.receivepack", "true"]),
    ).await?;

    let allowed_ref = format!("refs/heads/lazyteam/task-{}", task_id.simple());
    install_receive_hook(&task_repo, &allowed_ref).await.map_err(internal)?;
    // Manual retry/re-publish of a failed or blocked task must start with the
    // last implementation candidate available, otherwise a fresh workspace
    // sees no tracked delta and fails the no-change guard. Fail closed: a
    // plausible candidate that cannot be reconstructed fails the claim rather
    // than silently restarting from base.
    seed_prior_candidate(state, task_id, &task_repo, &allowed_ref).await?;
    Ok(())
}

/// Retry continuity: copy the latest valid implementation candidate for this
/// task into the fresh execution repository so the next worker attempt
/// (including a fresh workspace on another worker) starts with the prior
/// delta available to amend.
///
/// Scoped strictly to `completed` executions of the same task whose recorded
/// review ref matches this task's allowed branch and whose recorded base is
/// an ancestor of the recorded candidate (mirroring the reviewer ancestry
/// check, so stale, corrupt, or cross-history rows are never selected).
/// Reviewer checkouts and other tasks/projects are never consulted.
///
/// Fail-closed: returns `Ok(true)` once a candidate is seeded and `Ok(false)`
/// when no valid prior candidate exists (genuinely fresh task). When a
/// plausible candidate exists but cannot be reconstructed, returns `Err` so
/// the claim fails instead of silently restarting from base and reproducing
/// the no-tracked-change failure.
async fn seed_prior_candidate(state: &AppState, task_id: Uuid, task_repo: &Path, allowed_ref: &str) -> Result<bool, ApiError> {
    let rows = sqlx::query("SELECT id,result FROM executions WHERE task_id=? AND state='completed' ORDER BY attempt DESC")
        .bind(task_id.to_string())
        .fetch_all(&state.db)
        .await
        .map_err(|error| {
            tracing::warn!(%task_id, %error, "prior-candidate lookup failed; refusing to start from base");
            internal(error)
        })?;
    let mut plausible_error: Option<String> = None;
    for row in rows {
        let Some((commit_sha, base_sha, prior_repo)) = plausible_candidate_row(state, &row, task_id, task_repo, allowed_ref) else {
            continue;
        };
        match seed_candidate_ref(&prior_repo, task_repo, allowed_ref, &commit_sha, &base_sha).await {
            Ok(()) => return Ok(true),
            Err((_, message)) => {
                tracing::warn!(%task_id, %commit_sha, %message, "prior candidate could not be reconstructed; trying older candidate");
                plausible_error = Some(message);
            }
        }
    }
    if let Some(message) = plausible_error {
        return Err((StatusCode::CONFLICT, format!("prior implementation candidate for task {task_id} exists but could not be reconstructed in the fresh execution repository; refusing to start from base: {message}")));
    }
    Ok(false)
}

/// Structural validity for a candidate row: parses as an execution result
/// with a non-empty recorded commit, a review ref matching this task's
/// allowed branch, a non-empty recorded base, and a prior execution
/// repository distinct from the fresh one. Rows failing these checks are
/// stale, corrupt, cross-task, or legacy-unverifiable and are skipped, never
/// selected. Materialization (base ancestry, ref stability, fetch) is
/// verified separately in [`seed_candidate_ref`].
fn plausible_candidate_row(
    state: &AppState,
    row: &sqlx::sqlite::SqliteRow,
    task_id: Uuid,
    task_repo: &Path,
    allowed_ref: &str,
) -> Option<(String, String, PathBuf)> {
    let execution_id: String = row.try_get("id").ok()?;
    let result: Option<String> = row.try_get("result").unwrap_or(None);
    let result: lazyteam_core::ExecutionResult = serde_json::from_str(&result?).ok()?;
    let commit_sha = result.commit_sha?.trim().to_string();
    let review_ref = result.review_ref?.trim().to_string();
    let base_sha = result.base_sha?.trim().to_string();
    if commit_sha.is_empty() || base_sha.is_empty() || format!("refs/heads/{review_ref}") != allowed_ref {
        return None;
    }
    let prior_repo = task_repo_path(state, Uuid::parse_str(&execution_id).ok()?);
    if prior_repo == *task_repo {
        tracing::warn!(%task_id, "prior candidate execution matches the fresh execution repository; skipping");
        return None;
    }
    Some((commit_sha, base_sha, prior_repo))
}

async fn seed_candidate_ref(
    prior_repo: &Path,
    task_repo: &Path,
    allowed_ref: &str,
    commit_sha: &str,
    base_sha: &str,
) -> Result<(), ApiError> {
    if !prior_repo.exists() {
        return Err((StatusCode::CONFLICT, "prior execution repository is missing".into()));
    }
    let base_kind = git_output(
        &HostGitAuth::none(),
        Command::new("git").arg("-C").arg(prior_repo).args(["cat-file", "-t", base_sha]),
    )
    .await?;
    if base_kind.trim() != "commit" {
        return Err((StatusCode::CONFLICT, "recorded candidate base is not a commit".into()));
    }
    let actual = git_output(
        &HostGitAuth::none(),
        Command::new("git").arg("-C").arg(prior_repo).args(["rev-parse", "--verify", allowed_ref]),
    )
    .await?;
    if actual.trim() != commit_sha {
        return Err((StatusCode::CONFLICT, format!("prior candidate ref moved: expected {commit_sha}")));
    }
    let merge_base = git_output(
        &HostGitAuth::none(),
        Command::new("git").arg("-C").arg(prior_repo).args(["merge-base", base_sha, commit_sha]),
    )
    .await?;
    if merge_base.trim() != base_sha {
        return Err((StatusCode::CONFLICT, "recorded candidate is not based on the recorded base commit".into()));
    }
    let refspec = format!("{allowed_ref}:{allowed_ref}");
    git_ok(
        &HostGitAuth::none(),
        Command::new("git").arg("-C").arg(task_repo).args(["fetch", "--no-tags", &prior_repo.to_string_lossy(), &refspec]),
    )
    .await?;
    let seeded = git_output(
        &HostGitAuth::none(),
        Command::new("git").arg("-C").arg(task_repo).args(["rev-parse", "--verify", allowed_ref]),
    )
    .await?;
    if seeded.trim() != commit_sha {
        return Err((StatusCode::CONFLICT, "prior candidate seed verification failed".into()));
    }
    Ok(())
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ReviewTextPage {
    pub(crate) revision: Option<String>,
    pub(crate) path: Option<String>,
    pub(crate) start_line: usize,
    pub(crate) end_line: usize,
    pub(crate) limit: usize,
    pub(crate) total_lines: usize,
    pub(crate) content: String,
    pub(crate) next_start_line: Option<usize>,
}

const MAX_REVIEW_PAGE_LINES: usize = 400;

fn review_page(text: &str, revision: Option<&str>, path: Option<&str>, start_line: usize, limit: usize) -> ReviewTextPage {
    let lines: Vec<&str> = text.lines().collect();
    let total_lines = lines.len();
    let limit = limit.clamp(1, MAX_REVIEW_PAGE_LINES);
    let requested_start = start_line.max(1);
    let start = requested_start.saturating_sub(1).min(total_lines);
    let end = start.saturating_add(limit).min(total_lines);
    ReviewTextPage {
        revision: revision.map(str::to_string),
        path: path.map(str::to_string),
        start_line: if total_lines == 0 { 0 } else { start + 1 },
        end_line: end,
        limit,
        total_lines,
        content: lines[start..end].join("\n"),
        next_start_line: (end < total_lines).then_some(end + 1),
    }
}

fn normalize_review_path(raw: &str) -> Result<String, ApiError> {
    use std::path::Component;
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 4096 {
        return Err((StatusCode::BAD_REQUEST, "review path must be a non-empty repository-relative path".into()));
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        return Err((StatusCode::BAD_REQUEST, "review path must be repository-relative".into()));
    }
    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                if part == ".git" {
                    return Err((StatusCode::BAD_REQUEST, ".git internals are not readable through review tools".into()));
                }
                parts.push(part.to_string_lossy().into_owned());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err((StatusCode::BAD_REQUEST, "review path may not escape the repository".into()));
            }
        }
    }
    Ok(parts.join("/"))
}

async fn verified_review_repo(
    state: &AppState,
    evidence: &api::ReviewEvidence,
) -> Result<(PathBuf, String, String), ApiError> {
    let candidate_sha = evidence.checkout.commit_sha.as_deref().ok_or((StatusCode::CONFLICT, "reviewed execution has no candidate commit".into()))?;
    let base_sha = evidence.checkout.base_sha.as_deref().ok_or((StatusCode::CONFLICT, "reviewed execution has no pinned base commit".into()))?;
    let review_ref = evidence.checkout.review_ref.as_deref().ok_or((StatusCode::CONFLICT, "reviewed execution has no candidate ref".into()))?;
    let task_repo = task_repo_path(state, evidence.execution.id);
    verify_reviewed_candidate(&task_repo, review_ref, candidate_sha, base_sha).await?;
    Ok((task_repo, candidate_sha.to_string(), base_sha.to_string()))
}

fn review_revision<'a>(revision: &str, candidate_sha: &'a str, base_sha: &'a str) -> Result<&'a str, ApiError> {
    match revision {
        "candidate" => Ok(candidate_sha),
        "base" => Ok(base_sha),
        _ => Err((StatusCode::BAD_REQUEST, "revision must be candidate or base".into())),
    }
}

pub(crate) async fn verify_review_snapshot(
    state: &AppState,
    evidence: &api::ReviewEvidence,
    candidate_sha: &str,
) -> Result<(), ApiError> {
    let (_, pinned_candidate, _) = verified_review_repo(state, evidence).await?;
    if candidate_sha.trim() != pinned_candidate {
        return Err((StatusCode::CONFLICT, format!("candidate_sha does not match pinned review candidate {pinned_candidate}")));
    }
    Ok(())
}

pub(crate) async fn review_show(
    state: &AppState,
    evidence: &api::ReviewEvidence,
    revision: &str,
    path: &str,
    start_line: usize,
    limit: usize,
) -> Result<ReviewTextPage, ApiError> {
    let path = normalize_review_path(path)?;
    let display_path = if path.is_empty() { "." } else { &path };
    let (repo, candidate_sha, base_sha) = verified_review_repo(state, evidence).await?;
    let sha = review_revision(revision, &candidate_sha, &base_sha)?;
    let spec = if path.is_empty() { format!("{sha}:") } else { format!("{sha}:{path}") };
    let output = git_run(
        &HostGitAuth::none(),
        Command::new("git").arg("-C").arg(&repo).args(["show", "--no-ext-diff", &spec]),
    ).await?;
    if !output.status.success() {
        return Err((StatusCode::NOT_FOUND, format!("path {display_path} does not exist in {revision}")));
    }
    let text = String::from_utf8(output.stdout)
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("path {display_path} is not UTF-8 text")))?;
    Ok(review_page(&text, Some(revision), Some(display_path), start_line, limit))
}

pub(crate) async fn review_grep(
    state: &AppState,
    evidence: &api::ReviewEvidence,
    revision: &str,
    pattern: &str,
    paths: &[String],
    start_line: usize,
    limit: usize,
) -> Result<ReviewTextPage, ApiError> {
    let pattern = pattern.trim();
    if pattern.is_empty() || pattern.len() > 1024 {
        return Err((StatusCode::BAD_REQUEST, "review grep pattern must be 1..=1024 characters".into()));
    }
    let (repo, candidate_sha, base_sha) = verified_review_repo(state, evidence).await?;
    let sha = review_revision(revision, &candidate_sha, &base_sha)?;
    let mut command = Command::new("git");
    command.arg("-C").arg(&repo).args(["grep", "-n", "-I", "-F", "-e", pattern, sha, "--"]);
    if paths.is_empty() {
        command.arg(".");
    } else {
        for path in paths {
            let path = normalize_review_path(path)?;
            if path.is_empty() {
                command.arg(".");
            } else {
                command.arg(format!(":(literal){path}"));
            }
        }
    }
    let output = git_run(&HostGitAuth::none(), &mut command).await?;
    if !output.status.success() && output.status.code() != Some(1) {
        return Err((StatusCode::BAD_GATEWAY, format!("host Git grep failed: {}", String::from_utf8_lossy(&output.stderr).trim())));
    }
    let text = String::from_utf8(output.stdout).map_err(internal)?;
    let prefix = format!("{sha}:");
    let text = text.lines()
        .map(|line| line.strip_prefix(&prefix).unwrap_or(line))
        .collect::<Vec<_>>()
        .join("\n");
    Ok(review_page(&text, Some(revision), None, start_line, limit))
}

pub(crate) async fn review_diff(
    state: &AppState,
    evidence: &api::ReviewEvidence,
    path: Option<&str>,
    start_line: usize,
    limit: usize,
) -> Result<ReviewTextPage, ApiError> {
    let (repo, candidate_sha, base_sha) = verified_review_repo(state, evidence).await?;
    let clean_path = path.map(normalize_review_path).transpose()?;
    let mut command = Command::new("git");
    command.arg("-C").arg(&repo).args(["diff", "--no-ext-diff", "--unified=3", &base_sha, &candidate_sha, "--"]);
    if let Some(path) = clean_path.as_deref().filter(|path| !path.is_empty()) {
        command.arg(format!(":(literal){path}"));
    }
    let output = git_run(&HostGitAuth::none(), &mut command).await?;
    if !output.status.success() {
        return Err((StatusCode::BAD_GATEWAY, format!("host Git diff failed: {}", String::from_utf8_lossy(&output.stderr).trim())));
    }
    let text = String::from_utf8(output.stdout).map_err(internal)?;
    let display_path = clean_path.as_deref().map(|path| if path.is_empty() { "." } else { path });
    Ok(review_page(&text, None, display_path, start_line, limit))
}

const MAX_CONFLICT_FILES: usize = 20;
const MAX_CONFLICT_FILE_CHARS: usize = 2_000;
const MAX_CONFLICT_TOTAL_CHARS: usize = 8_000;
const MAX_CONFLICT_TEXT_BYTES: u64 = 64 * 1024;

fn conflict_kind(status: &str) -> &'static str {
    match status {
        "UU" => "both_modified",
        "AA" => "both_added",
        "DD" => "both_deleted",
        "DU" => "deleted_by_us",
        "UD" => "deleted_by_them",
        "AU" => "added_by_us",
        "UA" => "added_by_them",
        _ => "unmerged",
    }
}

fn truncate_chars(value: &str, max_chars: usize) -> (String, bool) {
    let mut chars = value.chars();
    let out: String = chars.by_ref().take(max_chars).collect();
    (out, chars.next().is_some())
}

async fn effective_diff_hash(repo: &Path, upstream_sha: &str, integration_sha: &str) -> Result<String, ApiError> {
    let output = git_run(
        &HostGitAuth::none(),
        Command::new("git").arg("-C").arg(repo).args(["diff", "--no-ext-diff", "--binary", upstream_sha, integration_sha, "--"]),
    ).await?;
    if !output.status.success() {
        return Err((StatusCode::BAD_GATEWAY, format!("host Git integration diff failed: {}", String::from_utf8_lossy(&output.stderr).trim())));
    }
    Ok(format!("{:x}", Sha256::digest(&output.stdout)))
}

async fn collect_conflict_evidence(
    workspace: &Path,
    candidate_sha: &str,
    base_sha: &str,
    upstream_sha: &str,
    default_branch: &str,
) -> MergeConflictEvidence {
    let unmerged = git_output(
        &HostGitAuth::none(),
        Command::new("git").arg("-C").arg(workspace).args(["diff", "--name-only", "--diff-filter=U"]),
    ).await.unwrap_or_default();
    let porcelain = git_output(
        &HostGitAuth::none(),
        Command::new("git").arg("-C").arg(workspace).args(["status", "--porcelain=v1", "--untracked-files=no"]),
    ).await.unwrap_or_default();
    let mut status_by_path = std::collections::BTreeMap::new();
    for line in porcelain.lines() {
        if line.len() < 4 { continue; }
        let status = line.chars().take(2).collect::<String>();
        if !matches!(status.as_str(), "UU" | "AA" | "DD" | "DU" | "UD" | "AU" | "UA") { continue; }
        let raw = line[3..].trim();
        let path = raw.split_once(" -> ").map(|(_, new)| new).unwrap_or(raw).trim_matches('"').to_string();
        status_by_path.insert(path, status);
    }
    let mut paths = unmerged.lines().map(str::trim).filter(|p| !p.is_empty()).map(str::to_string).collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    let mut truncated = paths.len() > MAX_CONFLICT_FILES;
    let mut remaining = MAX_CONFLICT_TOTAL_CHARS;
    let mut files = Vec::new();
    for path in paths.into_iter().take(MAX_CONFLICT_FILES) {
        let status = status_by_path.get(&path).cloned().unwrap_or_else(|| "UU".to_string());
        let kind = conflict_kind(&status).to_string();
        let worktree_path = workspace.join(&path);
        let size_bytes = tokio::fs::metadata(&worktree_path).await.ok().map(|m| m.len());
        if size_bytes.is_some_and(|size| size > MAX_CONFLICT_TEXT_BYTES) {
            files.push(MergeConflictFile { path, status, kind, binary: false, size_bytes, excerpt: None, excerpt_truncated: true });
            truncated = true;
            continue;
        }
        let bytes = tokio::fs::read(&worktree_path).await.unwrap_or_default();
        if bytes.contains(&0) || std::str::from_utf8(&bytes).is_err() {
            files.push(MergeConflictFile { path, status, kind, binary: true, size_bytes, excerpt: None, excerpt_truncated: false });
            continue;
        }
        let text = std::str::from_utf8(&bytes).unwrap_or_default();
        let marker_excerpt = if let Some(start) = text.find("<<<<<<<") {
            let end = text[start..].find(">>>>>>>").map(|offset| start + offset + ">>>>>>>".len()).unwrap_or(text.len());
            Some(&text[start..end])
        } else {
            None
        };
        let fallback;
        let source = if let Some(excerpt) = marker_excerpt {
            excerpt
        } else {
            fallback = git_output(
                &HostGitAuth::none(),
                Command::new("git").arg("-C").arg(workspace).args(["diff", "--cc", "--no-ext-diff", "--unified=3", "--", &path]),
            ).await.unwrap_or_default();
            fallback.as_str()
        };
        let cap = MAX_CONFLICT_FILE_CHARS.min(remaining);
        let (excerpt, excerpt_truncated) = if cap == 0 || source.trim().is_empty() {
            (None, cap == 0)
        } else {
            let (excerpt, cut) = truncate_chars(source, cap);
            remaining = remaining.saturating_sub(excerpt.chars().count());
            (Some(excerpt), cut)
        };
        if excerpt_truncated || remaining == 0 { truncated = true; }
        files.push(MergeConflictFile { path, status, kind, binary: false, size_bytes, excerpt, excerpt_truncated });
    }
    MergeConflictEvidence {
        candidate_sha: candidate_sha.to_string(),
        candidate_base_sha: base_sha.to_string(),
        upstream_sha: upstream_sha.to_string(),
        default_branch: default_branch.to_string(),
        files,
        truncated,
    }
}

pub(crate) fn conflict_summary(evidence: &MergeConflictEvidence) -> String {
    let mut out = format!(
        "Integration conflict: candidate {} (base {}) against current {} {}. Conflicted files:",
        evidence.candidate_sha.chars().take(12).collect::<String>(),
        evidence.candidate_base_sha.chars().take(12).collect::<String>(),
        evidence.default_branch,
        evidence.upstream_sha.chars().take(12).collect::<String>(),
    );
    for file in &evidence.files {
        out.push_str(&format!("\n- {} [{}:{}]", file.path, file.kind, file.status));
    }
    if evidence.truncated { out.push_str("\n- [conflict evidence truncated]"); }
    out
}

/// Reconcile one implementation candidate with the current upstream before a
/// reviewer is allowed to spend a turn. The result is stored inside the
/// existing ExecutionResult and immutable Git objects/refs in that execution's
/// task repository; no new workflow entity is created.
pub(crate) async fn prepare_integration_snapshot(
    state: &AppState,
    project: &Project,
    execution_id: Uuid,
    result: &lazyteam_core::ExecutionResult,
) -> Result<IntegrationSnapshot, ApiError> {
    let candidate_sha = result.commit_sha.as_deref().ok_or((StatusCode::CONFLICT, "implementation execution has no candidate commit".into()))?;
    let base_sha = result.base_sha.as_deref().ok_or((StatusCode::CONFLICT, "implementation execution has no pinned base commit".into()))?;
    let review_ref = result.review_ref.as_deref().ok_or((StatusCode::CONFLICT, "implementation execution has no candidate ref".into()))?;
    let task_repo = task_repo_path(state, execution_id);
    verify_reviewed_candidate(&task_repo, review_ref, candidate_sha, base_sha).await?;

    let project_row = sqlx::query("SELECT * FROM projects WHERE id=?")
        .bind(project.id.to_string()).fetch_one(&state.db).await.map_err(internal)?;
    let credential = api::git_credential_from_row(state, &project_row)?;
    let upstream_url = upstream_repo_url(&project.repo_url, &credential).map_err(internal)?;
    let auth = HostGitAuth::prepare(state, &credential).await.map_err(internal)?;
    let integration_result = async {
        let mirror = project_mirror(state, project.id);
        if !mirror.exists() {
            return Err((StatusCode::CONFLICT, "Host project mirror is missing; retry the task to rebuild it".into()));
        }
        refresh_project_mirror(&mirror, &upstream_url, &auth).await?;
        let default_ref = format!("refs/heads/{}", project.default_branch);
        let upstream_sha = git_output(
            &auth,
            Command::new("git").arg("-C").arg(&mirror).args(["rev-parse", "--verify", &default_ref]),
        ).await?;
        let upstream_sha = upstream_sha.trim().to_string();
        let upstream_ref = format!("refs/lazyteam/upstream/{upstream_sha}");
        git_ok(
            &HostGitAuth::none(),
            Command::new("git").arg("-C").arg(&task_repo).args(["fetch", "--no-tags", &mirror.to_string_lossy(), &format!("{default_ref}:{upstream_ref}")]),
        ).await?;

        if upstream_sha == base_sha {
            let integration_ref = format!("refs/lazyteam/integration/{candidate_sha}");
            git_ok(
                &HostGitAuth::none(),
                Command::new("git").arg("-C").arg(&task_repo).args(["update-ref", &integration_ref, candidate_sha]),
            ).await?;
            let effective_diff_hash = effective_diff_hash(&task_repo, &upstream_sha, candidate_sha).await?;
            return Ok(IntegrationSnapshot {
                candidate_sha: candidate_sha.to_string(), candidate_base_sha: base_sha.to_string(), upstream_sha,
                integration_sha: Some(candidate_sha.to_string()), effective_diff_hash: Some(effective_diff_hash), conflict: None,
            });
        }

        let root = state.git_root.join("integrations");
        tokio::fs::create_dir_all(&root).await.map_err(internal)?;
        let workspace = root.join(format!("{execution_id}-{}", Uuid::new_v4()));
        if workspace.exists() { tokio::fs::remove_dir_all(&workspace).await.map_err(internal)?; }
        let snapshot = async {
            git_ok(&HostGitAuth::none(), Command::new("git").args(["clone", "--no-checkout"]).arg(&mirror).arg(&workspace)).await?;
            git_ok(&HostGitAuth::none(), Command::new("git").arg("-C").arg(&workspace).args(["checkout", "-B", "lazyteam-integration", &upstream_sha])).await?;
            let candidate_ref = format!("refs/heads/{review_ref}:refs/lazyteam/candidate");
            git_ok(&HostGitAuth::none(), Command::new("git").arg("-C").arg(&workspace).arg("fetch").arg(&task_repo).arg(candidate_ref)).await?;
            let merge = git_run(
                &HostGitAuth::none(),
                Command::new("git").arg("-C").arg(&workspace)
                    .args(["-c", &format!("user.name={}", project.contributor.name)])
                    .args(["-c", &format!("user.email={}", project.contributor.email)])
                    .args(["merge", "--no-edit", "refs/lazyteam/candidate"]),
            ).await?;
            if !merge.status.success() {
                let conflict = collect_conflict_evidence(&workspace, candidate_sha, base_sha, &upstream_sha, &project.default_branch).await;
                return Ok(IntegrationSnapshot {
                    candidate_sha: candidate_sha.to_string(), candidate_base_sha: base_sha.to_string(), upstream_sha: upstream_sha.clone(),
                    integration_sha: None, effective_diff_hash: None, conflict: Some(conflict),
                });
            }
            let integration_sha = git_output(&HostGitAuth::none(), Command::new("git").arg("-C").arg(&workspace).args(["rev-parse", "HEAD"])).await?;
            let integration_sha = integration_sha.trim().to_string();
            let integration_ref = format!("refs/lazyteam/integration/{integration_sha}");
            git_ok(
                &HostGitAuth::none(),
                Command::new("git").arg("-C").arg(&task_repo).args(["fetch", "--no-tags", &workspace.to_string_lossy(), &format!("{integration_sha}:{integration_ref}")]),
            ).await?;
            let effective_diff_hash = effective_diff_hash(&workspace, &upstream_sha, &integration_sha).await?;
            Ok(IntegrationSnapshot {
                candidate_sha: candidate_sha.to_string(), candidate_base_sha: base_sha.to_string(), upstream_sha: upstream_sha.clone(),
                integration_sha: Some(integration_sha), effective_diff_hash: Some(effective_diff_hash), conflict: None,
            })
        }.await;
        let _ = tokio::fs::remove_dir_all(&workspace).await;
        snapshot
    }.await;
    auth.cleanup().await;
    integration_result
}

pub(crate) enum PublishReviewedOutcome {
    Merged(String),
    Conflict(MergeConflictEvidence),
    Rereview(IntegrationSnapshot),
}

pub(crate) async fn publish_reviewed_task(
    state: &AppState,
    evidence: &api::ReviewEvidence,
) -> Result<PublishReviewedOutcome, ApiError> {
    let review_ref = evidence.checkout.review_ref.as_deref().ok_or((StatusCode::CONFLICT, "reviewed execution has no candidate ref".into()))?;
    let candidate_sha = evidence.checkout.commit_sha.as_deref().ok_or((StatusCode::CONFLICT, "reviewed execution has no candidate commit".into()))?;
    let base_sha = evidence.checkout.base_sha.as_deref().ok_or((StatusCode::CONFLICT, "reviewed execution has no pinned base commit".into()))?;

    // Pin final publication to the exact integration context approved by the
    // latest completed reviewer for this execution. Legacy rows without pins
    // fall back to the previous safe Host merge behavior.
    let reviewed = sqlx::query("SELECT upstream_sha,integration_sha,effective_diff_hash FROM reviews WHERE task_id=? AND execution_id=? AND state='completed' AND (verdict LIKE '%\"verdict\":\"approve\"%' OR verdict LIKE '%\"verdict\": \"approve\"%') ORDER BY finished_at DESC LIMIT 1")
        .bind(evidence.task.id.to_string()).bind(evidence.execution.id.to_string())
        .fetch_optional(&state.db).await.map_err(internal)?;
    let reviewed_pins = reviewed.as_ref().and_then(|row| {
        Some((
            row.try_get::<Option<String>, _>("upstream_sha").ok()??,
            row.try_get::<Option<String>, _>("integration_sha").ok()??,
            row.try_get::<Option<String>, _>("effective_diff_hash").ok()??,
        ))
    });

    if reviewed_pins.is_none() {
        let project_row = sqlx::query("SELECT * FROM projects WHERE id=?").bind(evidence.project.id.to_string()).fetch_one(&state.db).await.map_err(internal)?;
        let credential = api::git_credential_from_row(state, &project_row)?;
        let upstream_url = upstream_repo_url(&evidence.project.repo_url, &credential).map_err(internal)?;
        let auth = HostGitAuth::prepare(state, &credential).await.map_err(internal)?;
        let legacy = publish_reviewed_task_inner(state, evidence, review_ref, candidate_sha, base_sha, &upstream_url, &auth).await;
        auth.cleanup().await;
        return legacy.map(PublishReviewedOutcome::Merged);
    }
    let (reviewed_upstream, reviewed_integration, reviewed_diff_hash) = reviewed_pins.unwrap();

    let mut execution_result = evidence.execution.result.clone().ok_or((StatusCode::CONFLICT, "reviewed execution has no result".into()))?;
    let current = prepare_integration_snapshot(state, &evidence.project, evidence.execution.id, &execution_result).await?;
    execution_result.integration = Some(current.clone());
    sqlx::query("UPDATE executions SET result=? WHERE id=? AND state='completed'")
        .bind(serde_json::to_string(&execution_result).map_err(internal)?)
        .bind(evidence.execution.id.to_string()).execute(&state.db).await.map_err(internal)?;

    if let Some(conflict) = current.conflict.clone() {
        return Ok(PublishReviewedOutcome::Conflict(conflict));
    }
    let current_integration = current.integration_sha.clone().ok_or((StatusCode::CONFLICT, "clean final integration has no commit".into()))?;
    let current_diff_hash = current.effective_diff_hash.as_deref().ok_or((StatusCode::CONFLICT, "clean final integration has no effective diff hash".into()))?;

    let publish_sha = if current.upstream_sha == reviewed_upstream {
        // Same upstream world the reviewer saw: publish the exact reviewed
        // integration commit, not a freshly-created equivalent merge commit.
        reviewed_integration
    } else if current_diff_hash == reviewed_diff_hash {
        // Upstream moved, but the effective candidate delta is byte-for-byte
        // unchanged. This is unrelated upstream movement, not a reason to
        // spend another reviewer turn.
        current_integration
    } else {
        return Ok(PublishReviewedOutcome::Rereview(current));
    };

    let task_repo = task_repo_path(state, evidence.execution.id);
    verify_reviewed_candidate(&task_repo, review_ref, candidate_sha, base_sha).await?;
    let kind = git_output(&HostGitAuth::none(), Command::new("git").arg("-C").arg(&task_repo).args(["cat-file", "-t", &publish_sha])).await?;
    if kind.trim() != "commit" {
        return Err((StatusCode::CONFLICT, "reviewed integration object is missing from the task repository".into()));
    }
    let project_row = sqlx::query("SELECT * FROM projects WHERE id=?").bind(evidence.project.id.to_string()).fetch_one(&state.db).await.map_err(internal)?;
    let credential = api::git_credential_from_row(state, &project_row)?;
    let upstream_url = upstream_repo_url(&evidence.project.repo_url, &credential).map_err(internal)?;
    let auth = HostGitAuth::prepare(state, &credential).await.map_err(internal)?;
    let destination = format!("{publish_sha}:refs/heads/{}", evidence.project.default_branch);
    let pushed = git_push_ok(&auth, Command::new("git").arg("-C").arg(&task_repo).arg("push").arg(&upstream_url).arg(destination)).await;
    auth.cleanup().await;
    pushed?;
    Ok(PublishReviewedOutcome::Merged(publish_sha))
}

async fn publish_reviewed_task_inner(
    state: &AppState,
    evidence: &api::ReviewEvidence,
    review_ref: &str,
    candidate_sha: &str,
    base_sha: &str,
    upstream_url: &str,
    auth: &HostGitAuth,
) -> Result<String, ApiError> {
    let mirror = project_mirror(state, evidence.project.id);
    if !mirror.exists() {
        return Err((StatusCode::CONFLICT, "Host project mirror is missing; retry the task to rebuild it".into()));
    }
    refresh_project_mirror(&mirror, upstream_url, auth).await?;
    let default_ref = format!("refs/heads/{}", evidence.project.default_branch);
    let upstream_sha = git_output(
        auth,
        Command::new("git").arg("-C").arg(&mirror).args(["rev-parse", "--verify", &default_ref]),
    ).await?;

    let task_repo = task_repo_path(state, evidence.execution.id);
    verify_reviewed_candidate(&task_repo, review_ref, candidate_sha, base_sha).await?;

    if upstream_sha.trim() == base_sha {
        let destination = format!("{candidate_sha}:{default_ref}");
        git_push_ok(
            auth,
            Command::new("git").arg("-C").arg(&task_repo).arg("push").arg(upstream_url).arg(destination),
        ).await?;
        return Ok(candidate_sha.to_string());
    }

    merge_in_host_workspace(
        state,
        evidence,
        &mirror,
        &task_repo,
        review_ref,
        upstream_sha.trim(),
        upstream_url,
        auth,
    ).await
}

async fn refresh_project_mirror(mirror: &Path, upstream_url: &str, auth: &HostGitAuth) -> Result<(), ApiError> {
    git_ok(
        auth,
        Command::new("git").arg("-C").arg(mirror).args(["remote", "set-url", "origin", upstream_url]),
    ).await?;
    git_ok(
        auth,
        Command::new("git").arg("-C").arg(mirror).args(["fetch", "--prune", "origin"]),
    ).await
}

async fn verify_candidate_ref(task_repo: &Path, review_ref: &str, candidate_sha: &str) -> Result<(), ApiError> {
    if !task_repo.exists() {
        return Err((StatusCode::CONFLICT, "Host task repository is missing".into()));
    }
    let candidate_ref = format!("refs/heads/{review_ref}");
    let actual_candidate = git_output(
        &HostGitAuth::none(),
        Command::new("git").arg("-C").arg(task_repo).args(["rev-parse", "--verify", &candidate_ref]),
    ).await?;
    if actual_candidate.trim() != candidate_sha {
        return Err((StatusCode::CONFLICT, format!("candidate ref moved after review: expected {candidate_sha}, found {}", actual_candidate.trim())));
    }
    Ok(())
}

async fn verify_reviewed_candidate(task_repo: &Path, review_ref: &str, candidate_sha: &str, base_sha: &str) -> Result<(), ApiError> {
    verify_candidate_ref(task_repo, review_ref, candidate_sha).await?;
    let merge_base = git_output(
        &HostGitAuth::none(),
        Command::new("git").arg("-C").arg(task_repo).args(["merge-base", base_sha, candidate_sha]),
    ).await?;
    if merge_base.trim() != base_sha {
        return Err((StatusCode::CONFLICT, "reviewed candidate is not based on the pinned upstream commit".into()));
    }
    Ok(())
}

async fn merge_in_host_workspace(
    state: &AppState,
    evidence: &api::ReviewEvidence,
    mirror: &Path,
    task_repo: &Path,
    review_ref: &str,
    upstream_sha: &str,
    upstream_url: &str,
    auth: &HostGitAuth,
) -> Result<String, ApiError> {
    let merge_root = state.git_root.join("merges");
    tokio::fs::create_dir_all(&merge_root).await.map_err(internal)?;
    let workspace = merge_root.join(evidence.task.id.to_string());
    if workspace.exists() { tokio::fs::remove_dir_all(&workspace).await.map_err(internal)?; }

    let result = async {
        git_ok(
            &HostGitAuth::none(),
            Command::new("git").args(["clone", "--no-checkout"]).arg(mirror).arg(&workspace),
        ).await?;
        git_ok(
            &HostGitAuth::none(),
            Command::new("git").arg("-C").arg(&workspace).args(["checkout", "-B", "lazyteam-merge", upstream_sha]),
        ).await?;
        let candidate_ref = format!("refs/heads/{review_ref}:refs/lazyteam/candidate");
        git_ok(
            &HostGitAuth::none(),
            Command::new("git").arg("-C").arg(&workspace).arg("fetch").arg(task_repo).arg(candidate_ref),
        ).await?;

        let merge_output = git_run(
            &HostGitAuth::none(),
            Command::new("git")
                .arg("-C").arg(&workspace)
                .args(["-c", &format!("user.name={}", evidence.project.contributor.name)])
                .args(["-c", &format!("user.email={}", evidence.project.contributor.email)])
                .args(["merge", "--no-edit", "refs/lazyteam/candidate"]),
        ).await?;
        if !merge_output.status.success() {
            let conflicts = git_output(
                &HostGitAuth::none(),
                Command::new("git").arg("-C").arg(&workspace).args(["diff", "--name-only", "--diff-filter=U"]),
            ).await.unwrap_or_default();
            let detail = if conflicts.trim().is_empty() {
                String::from_utf8_lossy(&merge_output.stderr).trim().to_string()
            } else {
                conflicts.lines().collect::<Vec<_>>().join(", ")
            };
            return Err((StatusCode::CONFLICT, format!("merge conflict with current {} {}: {detail}", evidence.project.default_branch, upstream_sha)));
        }
        let merged_sha = git_output(
            &HostGitAuth::none(),
            Command::new("git").arg("-C").arg(&workspace).args(["rev-parse", "HEAD"]),
        ).await?;
        let destination = format!("{}:refs/heads/{}", merged_sha.trim(), evidence.project.default_branch);
        git_push_ok(
            auth,
            Command::new("git").arg("-C").arg(&workspace).arg("push").arg(upstream_url).arg(destination),
        ).await?;
        Ok(merged_sha.trim().to_string())
    }.await;

    let _ = tokio::fs::remove_dir_all(&workspace).await;
    result
}

pub(crate) async fn verify_external_merge(
    state: &AppState,
    evidence: &api::ReviewEvidence,
    merge_commit_sha: &str,
) -> Result<(), ApiError> {
    let candidate_sha = evidence.checkout.commit_sha.as_deref().ok_or((StatusCode::CONFLICT, "reviewed execution has no candidate commit".into()))?;
    let base_sha = evidence.checkout.base_sha.as_deref().ok_or((StatusCode::CONFLICT, "reviewed execution has no pinned base commit".into()))?;
    let review_ref = evidence.checkout.review_ref.as_deref().ok_or((StatusCode::CONFLICT, "reviewed execution has no candidate ref".into()))?;
    let task_repo = task_repo_path(state, evidence.execution.id);
    // External-merge recovery verifies the exact reviewed ref and compares the
    // complete tree delta against the supplied upstream commit. It intentionally
    // does not require candidate ancestry: older retry workspaces could produce
    // a tree-correct reviewed candidate on stale history.
    verify_candidate_ref(&task_repo, review_ref, candidate_sha).await?;

    let project_row = sqlx::query("SELECT * FROM projects WHERE id=?")
        .bind(evidence.project.id.to_string()).fetch_one(&state.db).await.map_err(internal)?;
    let credential = api::git_credential_from_row(state, &project_row)?;
    let upstream_url = upstream_repo_url(&evidence.project.repo_url, &credential).map_err(internal)?;
    let auth = HostGitAuth::prepare(state, &credential).await.map_err(internal)?;
    let result = async {
        let mirror = project_mirror(state, evidence.project.id);
        refresh_project_mirror(&mirror, &upstream_url, &auth).await?;
        let default_ref = format!("refs/heads/{}", evidence.project.default_branch);
        let ancestor = git_run(
            &HostGitAuth::none(),
            Command::new("git").arg("-C").arg(&mirror).args(["merge-base", "--is-ancestor", merge_commit_sha, &default_ref]),
        ).await?;
        if !ancestor.status.success() {
            return Err((StatusCode::CONFLICT, format!("merge commit {merge_commit_sha} is not on current {}", evidence.project.default_branch)));
        }
        let changed = git_output(
            &HostGitAuth::none(),
            Command::new("git").arg("-C").arg(&task_repo).args(["diff", "--name-only", base_sha, candidate_sha]),
        ).await?;
        for path in changed.lines().filter(|path| !path.is_empty()) {
            let candidate = git_object_id(&task_repo, &format!("{candidate_sha}:{path}")).await?;
            let merged = git_object_id(&mirror, &format!("{merge_commit_sha}:{path}")).await?;
            if candidate != merged {
                return Err((StatusCode::CONFLICT, format!("external merge does not preserve reviewed content for {path}")));
            }
        }
        Ok(())
    }.await;
    auth.cleanup().await;
    result
}

async fn git_object_id(repo: &Path, spec: &str) -> Result<Option<String>, ApiError> {
    let output = git_run(
        &HostGitAuth::none(),
        Command::new("git").arg("-C").arg(repo).args(["rev-parse", "--verify", spec]),
    ).await?;
    if output.status.success() {
        Ok(Some(String::from_utf8(output.stdout).map_err(internal)?.trim().to_string()))
    } else {
        Ok(None)
    }
}

pub(crate) async fn remove_task_repo(state: &AppState, execution_id: Uuid) -> Result<(), ApiError> {
    let path = task_repo_path(state, execution_id);
    if path.exists() {
        tokio::fs::remove_dir_all(path).await.map_err(internal)?;
    }
    Ok(())
}

async fn install_receive_hook(repo: &Path, allowed_ref: &str) -> anyhow::Result<()> {
    let hooks = repo.join("hooks");
    tokio::fs::create_dir_all(&hooks).await?;
    let hook = hooks.join("pre-receive");
    let content = format!(
        "#!/bin/sh\nset -eu\nallowed='{}'\nwhile read old new ref; do\n  if [ \"$ref\" != \"$allowed\" ]; then\n    echo \"LazyTeam broker: push denied for $ref\" >&2\n    exit 1\n  fi\ndone\n",
        allowed_ref.replace("'", "")
    );
    tokio::fs::write(&hook, content).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).await?;
    }
    Ok(())
}

async fn task_git(
    AxumPath((execution_id, path)): AxumPath<(Uuid, String)>,
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response<Body>, ApiError> {
    let row = sqlx::query(
        "SELECT e.worker_id,e.lease_capability_hash FROM executions e WHERE e.id=? AND e.state IN ('assigned','running') AND e.lease_until>=? AND e.lease_capability_hash IS NOT NULL",
    )
    .bind(execution_id.to_string())
    .bind(chrono::Utc::now().to_rfc3339())
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?
    .ok_or((StatusCode::NOT_FOUND, "Git execution endpoint is not active".into()))?;
    let worker_id: String = row.try_get("worker_id").map_err(internal)?;
    let capability_hash: String = row.try_get("lease_capability_hash").map_err(internal)?;
    api::require_worker(&state.db, Uuid::parse_str(&worker_id).map_err(internal)?, request.headers()).await?;
    api::require_lease_capability(request.headers(), &capability_hash)?;
    serve_git(state, execution_id, path, request, true).await
}

async fn review_git(
    AxumPath((review_id, path)): AxumPath<(Uuid, String)>,
    State(state): State<Arc<AppState>>,
    request: Request,
) -> Result<Response<Body>, ApiError> {
    let row = sqlx::query(
        "SELECT reviewer_worker_id,execution_id,lease_capability_hash FROM reviews WHERE id=? AND state IN ('assigned','running') AND lease_until>=? AND lease_capability_hash IS NOT NULL",
    )
    .bind(review_id.to_string())
    .bind(chrono::Utc::now().to_rfc3339())
    .fetch_optional(&state.db)
    .await
    .map_err(internal)?
    .ok_or((StatusCode::NOT_FOUND, "Git review endpoint is not active".into()))?;
    let worker_id: String = row.try_get("reviewer_worker_id").map_err(internal)?;
    let execution_id: String = row.try_get("execution_id").map_err(internal)?;
    let capability_hash: String = row.try_get("lease_capability_hash").map_err(internal)?;
    api::require_worker(&state.db, Uuid::parse_str(&worker_id).map_err(internal)?, request.headers()).await?;
    api::require_lease_capability(request.headers(), &capability_hash)?;
    serve_git(
        state,
        Uuid::parse_str(&execution_id).map_err(internal)?,
        path,
        request,
        false,
    ).await
}

async fn serve_git(
    state: Arc<AppState>,
    execution_id: Uuid,
    path: String,
    request: Request,
    writable: bool,
) -> Result<Response<Body>, ApiError> {
    let query = request.uri().query().unwrap_or("").to_string();
    let method = request.method().clone();
    let content_type = request.headers().get(header::CONTENT_TYPE).cloned();
    let wants_receive_pack = path.ends_with("git-receive-pack")
        || query.split('&').any(|part| part == "service=git-receive-pack");
    if wants_receive_pack && !writable {
        return Err((StatusCode::FORBIDDEN, "review Git endpoint is read-only".into()));
    }

    let body = to_bytes(request.into_body(), MAX_GIT_BODY)
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, format!("read Git request body: {error}")))?;

    let mut command = Command::new("git");
    command
        .arg("http-backend")
        .env("GIT_PROJECT_ROOT", tasks_root(&state))
        .env("GIT_HTTP_EXPORT_ALL", "1")
        .env("PATH_INFO", format!("/{execution_id}.git/{path}"))
        .env("QUERY_STRING", query)
        .env("REQUEST_METHOD", method.as_str())
        .env("CONTENT_LENGTH", body.len().to_string())
        .env("REMOTE_USER", "lazyteam-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(value) = content_type.and_then(|value| value.to_str().ok().map(str::to_owned)) {
        command.env("CONTENT_TYPE", value);
    }

    let mut child = command.spawn().map_err(internal)?;
    if !body.is_empty() {
        let mut stdin = child.stdin.take().ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Git backend stdin unavailable".into()))?;
        stdin.write_all(&body).await.map_err(internal)?;
    }
    let output = child.wait_with_output().await.map_err(internal)?;
    if !output.status.success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("Git backend failed: {}", String::from_utf8_lossy(&output.stderr).trim()),
        ));
    }
    cgi_response(&output.stdout)
}

fn cgi_response(raw: &[u8]) -> Result<Response<Body>, ApiError> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| (index, 4))
        .or_else(|| raw.windows(2).position(|window| window == b"\n\n").map(|index| (index, 2)))
        .ok_or((StatusCode::BAD_GATEWAY, "Git backend returned malformed CGI headers".into()))?;
    let header_text = String::from_utf8_lossy(&raw[..split.0]);
    let mut status = StatusCode::OK;
    let mut builder = Response::builder();
    for line in header_text.lines() {
        let Some((name, value)) = line.split_once(':') else { continue };
        if name.eq_ignore_ascii_case("status") {
            let code = value.trim().split_whitespace().next().unwrap_or("200");
            status = StatusCode::from_u16(code.parse().map_err(internal)?).map_err(internal)?;
            continue;
        }
        let name = HeaderName::from_bytes(name.trim().as_bytes()).map_err(internal)?;
        let value = HeaderValue::from_str(value.trim()).map_err(internal)?;
        builder = builder.header(name, value);
    }
    builder
        .status(status)
        .body(Body::from(raw[split.0 + split.1..].to_vec()))
        .map_err(internal)
}

fn upstream_repo_url(repo_url: &str, credential: &GitCredential) -> anyhow::Result<String> {
    if !matches!(credential, GitCredential::HttpsBasic { .. }) {
        return Ok(repo_url.to_string());
    }
    if repo_url.starts_with("https://") || repo_url.starts_with("http://") {
        return Ok(repo_url.to_string());
    }
    if let Some(rest) = repo_url.strip_prefix("git@") {
        let (host, path) = rest
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("Host HTTPS Git auth cannot rewrite malformed git@ repository URL"))?;
        if host.is_empty() || path.trim_matches('/').is_empty() {
            anyhow::bail!("Host HTTPS Git auth cannot rewrite malformed git@ repository URL");
        }
        return Ok(format!("https://{host}/{}", path.trim_start_matches('/')));
    }
    if let Some(rest) = repo_url.strip_prefix("ssh://") {
        let (authority, path) = rest
            .split_once('/')
            .ok_or_else(|| anyhow::anyhow!("Host HTTPS Git auth cannot rewrite malformed ssh:// repository URL"))?;
        let host_port = authority.rsplit_once('@').map(|(_, host)| host).unwrap_or(authority);
        let host = match host_port.rsplit_once(':') {
            Some((host, "22")) => host,
            Some((_host, _port)) => anyhow::bail!("Host HTTPS Git auth cannot safely rewrite a non-default SSH port"),
            None => host_port,
        };
        if host.is_empty() || path.trim_matches('/').is_empty() {
            anyhow::bail!("Host HTTPS Git auth cannot rewrite malformed ssh:// repository URL");
        }
        return Ok(format!("https://{host}/{}", path.trim_start_matches('/')));
    }
    anyhow::bail!("Host HTTPS Git auth requires an HTTPS URL or a standard SSH URL that can be rewritten safely")
}

fn projects_root(state: &AppState) -> PathBuf {
    state.git_root.join("projects")
}

fn tasks_root(state: &AppState) -> PathBuf {
    state.git_root.join("tasks")
}

fn project_mirror(state: &AppState, project_id: Uuid) -> PathBuf {
    projects_root(state).join(format!("{project_id}.git"))
}

fn task_repo_path(state: &AppState, execution_id: Uuid) -> PathBuf {
    tasks_root(state).join(format!("{execution_id}.git"))
}

struct HostGitAuth {
    env: Vec<(String, String)>,
    key_path: Option<PathBuf>,
}

impl HostGitAuth {
    fn none() -> Self {
        Self { env: vec![("GIT_TERMINAL_PROMPT".into(), "0".into())], key_path: None }
    }

    async fn prepare(state: &AppState, credential: &GitCredential) -> anyhow::Result<Self> {
        let mut auth = Self::none();
        match credential {
            GitCredential::Host => {}
            GitCredential::HttpsBasic { username, secret } => {
                let encoded = STANDARD.encode(format!("{username}:{secret}"));
                // Explicit project credentials must not be combined with ambient Host
                // authentication. Empty multi-value entries reset inherited Git config
                // before the project-scoped Authorization header is added.
                auth.env.extend([
                    ("GIT_CONFIG_COUNT".into(), "3".into()),
                    ("GIT_CONFIG_KEY_0".into(), "http.extraHeader".into()),
                    ("GIT_CONFIG_VALUE_0".into(), String::new()),
                    ("GIT_CONFIG_KEY_1".into(), "credential.helper".into()),
                    ("GIT_CONFIG_VALUE_1".into(), String::new()),
                    ("GIT_CONFIG_KEY_2".into(), "http.extraHeader".into()),
                    ("GIT_CONFIG_VALUE_2".into(), format!("Authorization: Basic {encoded}")),
                ]);
            }
            GitCredential::SshKey { private_key } => {
                let dir = state.git_root.join("credentials");
                tokio::fs::create_dir_all(&dir).await?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).await?;
                }
                let path = dir.join(format!("{}.key", Uuid::new_v4()));
                tokio::fs::write(&path, private_key).await?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
                }
                let quoted = shell_quote(&path)?;
                auth.env.push((
                    "GIT_SSH_COMMAND".into(),
                    format!("ssh -i {quoted} -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes"),
                ));
                auth.key_path = Some(path);
            }
        }
        Ok(auth)
    }

    fn apply(&self, command: &mut Command) {
        for (key, value) in &self.env {
            command.env(key, value);
        }
    }

    async fn cleanup(&self) {
        if let Some(path) = &self.key_path {
            let _ = tokio::fs::remove_file(path).await;
        }
    }
}

async fn git_ok(auth: &HostGitAuth, command: &mut Command) -> Result<(), ApiError> {
    let output = git_run(auth, command).await?;
    if !output.status.success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("host Git command failed: {}", String::from_utf8_lossy(&output.stderr).trim()),
        ));
    }
    Ok(())
}

async fn git_push_ok(auth: &HostGitAuth, command: &mut Command) -> Result<(), ApiError> {
    match git_ok(auth, command).await {
        Err((status, message)) if message.contains("403") || message.contains("denied to") => Err((
            status,
            format!("{message}. Host credential authenticated but upstream rejected write access; run Project Git Probe and compare the credential revision."),
        )),
        other => other,
    }
}

async fn git_output(auth: &HostGitAuth, command: &mut Command) -> Result<String, ApiError> {
    let output = git_run(auth, command).await?;
    if !output.status.success() {
        return Err((
            StatusCode::BAD_GATEWAY,
            format!("host Git command failed: {}", String::from_utf8_lossy(&output.stderr).trim()),
        ));
    }
    String::from_utf8(output.stdout).map_err(internal)
}

async fn git_run(auth: &HostGitAuth, command: &mut Command) -> Result<std::process::Output, ApiError> {
    auth.apply(command);
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .kill_on_drop(true)
        .output()
        .await
        .map_err(internal)
}

fn shell_quote(path: &Path) -> anyhow::Result<String> {
    let raw = path.to_str().ok_or_else(|| anyhow::anyhow!("non-utf8 Git credential path"))?;
    Ok(format!("'{}'", raw.replace("'", "'\"'\"'")))
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Retry continuity: a task with an earlier completed candidate whose
    /// later attempt failed, manually republished via `retry_task`, must
    /// seed the fresh execution repository with the prior candidate so the
    /// next worker attempt starts with that delta available to amend.
    /// A task with no prior candidate still starts fresh, and candidates
    /// never leak across tasks.
    #[tokio::test]
    async fn manual_retry_seeds_prior_candidate_into_fresh_execution_repo() {
        use sqlx::sqlite::SqlitePoolOptions;

        let root = std::env::temp_dir().join(format!("lazyteam-retry-seed-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let no_auth = HostGitAuth::none();
        let run = |repo: &Path, args: &[&str]| {
            let repo = repo.to_path_buf();
            let args = args.iter().map(|arg| (*arg).to_string()).collect::<Vec<_>>();
            async move {
                git_ok(&HostGitAuth::none(), Command::new("git").arg("-C").arg(&repo).args(&args)).await
            }
        };

        // Upstream with a single commit on `main`.
        let upstream = root.join("upstream.git");
        git_ok(&no_auth, Command::new("git").args(["init", "--bare"]).arg(&upstream)).await.unwrap();
        let seed_work = root.join("seed-work");
        git_ok(&no_auth, Command::new("git").args(["init"]).arg(&seed_work)).await.unwrap();
        run(&seed_work, &["config", "user.name", "LazyTeam Test"]).await.unwrap();
        run(&seed_work, &["config", "user.email", "test@lazyteam.local"]).await.unwrap();
        tokio::fs::write(seed_work.join("base.txt"), "base\n").await.unwrap();
        run(&seed_work, &["add", "base.txt"]).await.unwrap();
        run(&seed_work, &["commit", "-m", "base"]).await.unwrap();
        run(&seed_work, &["branch", "-M", "main"]).await.unwrap();
        let upstream_url = upstream.to_string_lossy().to_string();
        run(&seed_work, &["push", &upstream_url, "refs/heads/main:refs/heads/main"]).await.unwrap();
        let base_sha = git_output(
            &no_auth,
            Command::new("git").arg("-C").arg(&upstream).args(["rev-parse", "refs/heads/main"]),
        ).await.unwrap();

        let db = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let git_root = root.join("git");
        let state = Arc::new(crate::AppState {
            db,
            public_url: None,
            oauth_password: None,
            git_credential_key: None,
            git_root: git_root.clone(),
            agent_auth_updates: Default::default(),
            model_refresh_requests: Default::default(), oauth_login_states: Default::default(),
        });
        let now = chrono::Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(project_id.to_string()).bind("seed-proj").bind("Seed").bind(&upstream_url).bind("main").bind(&now).bind(&now)
            .execute(&state.db).await.unwrap();
        sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(worker_id.to_string()).bind("worker").bind("worker").bind("idle").bind("linux").bind("x86_64")
            .bind(crate::api::PROTOCOL_VERSION as i64).bind("test").bind(&now).bind(&now)
            .execute(&state.db).await.unwrap();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,review_feedback,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(project_id.to_string()).bind("seeded task").bind("").bind("").bind("failed")
            .bind("").bind(&now).bind(&now)
            .execute(&state.db).await.unwrap();
        let project = Project {
            id: project_id,
            slug: "seed-proj".into(),
            name: "Seed".into(),
            repo_url: upstream_url.clone(),
            default_branch: "main".into(),
            contributor: Default::default(),
            required_worker_tags: Default::default(),
            default_task_tags: Default::default(),
            git_auth: Default::default(),
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let branch = format!("lazyteam/task-{}", task_id.simple());
        let allowed_ref = format!("refs/heads/{branch}");

        // Attempt 1: completed with a real candidate pushed to its task repo.
        let exec1 = Uuid::new_v4();
        prepare_task_repo(&state, &project, task_id, exec1, &GitCredential::Host).await.unwrap();
        let old_repo = git_root.join("tasks").join(format!("{exec1}.git"));
        let candidate_work = root.join("candidate-work");
        git_ok(
            &no_auth,
            Command::new("git").args(["clone", &old_repo.to_string_lossy(), &candidate_work.to_string_lossy()]),
        ).await.unwrap();
        run(&candidate_work, &["config", "user.name", "LazyTeam Test"]).await.unwrap();
        run(&candidate_work, &["config", "user.email", "test@lazyteam.local"]).await.unwrap();
        run(&candidate_work, &["checkout", "-b", &branch]).await.unwrap();
        tokio::fs::write(candidate_work.join("fix.txt"), "prior candidate\n").await.unwrap();
        run(&candidate_work, &["add", "fix.txt"]).await.unwrap();
        run(&candidate_work, &["commit", "-m", "lazyteam: seeded task"]).await.unwrap();
        run(&candidate_work, &["push", "origin", &format!("HEAD:{allowed_ref}")]).await.unwrap();
        let candidate_sha = git_output(
            &no_auth,
            Command::new("git").arg("-C").arg(&candidate_work).args(["rev-parse", "HEAD"]),
        ).await.unwrap();
        let result = lazyteam_core::ExecutionResult {
            status: "completed".into(),
            summary: "prior candidate".into(),
            commit_sha: Some(candidate_sha.trim().to_string()),
            base_sha: Some(base_sha.trim().to_string()),
            patch: None,
            patch_truncated: false,
            workspace_clean: Some(true),
            review_ref: Some(branch.clone()),
            changed_files: vec!["fix.txt".into()],
            validation: vec![],
            warnings: vec![],
            artifacts: vec![],
            integration: None,
        };
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,result) VALUES(?,?,?,?,?,?,?,?)")
            .bind(exec1.to_string()).bind(task_id.to_string()).bind(worker_id.to_string()).bind(1_i64)
            .bind("completed").bind(&now).bind(&now).bind(serde_json::to_string(&result).unwrap())
            .execute(&state.db).await.unwrap();
        // Attempt 2: later failure with no candidate; task is failed.
        let exec2 = Uuid::new_v4();
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at) VALUES(?,?,?,?,?,?,?)")
            .bind(exec2.to_string()).bind(task_id.to_string()).bind(worker_id.to_string()).bind(2_i64)
            .bind("failed").bind(&now).bind(&now)
            .execute(&state.db).await.unwrap();

        // Manual re-publish asks to amend the prior candidate.
        let transition = crate::review::retry_task(&state, task_id, Some("manual retry: amend prior candidate")).await.unwrap();
        assert_eq!(transition.state, "queued");

        // The next attempt's fresh execution repository must carry the
        // prior candidate delta.
        let exec3 = Uuid::new_v4();
        prepare_task_repo(&state, &project, task_id, exec3, &GitCredential::Host).await.unwrap();
        let new_repo = git_root.join("tasks").join(format!("{exec3}.git"));
        let seeded = git_output(
            &no_auth,
            Command::new("git").arg("-C").arg(&new_repo).args(["rev-parse", "--verify", &allowed_ref]),
        ).await.unwrap();
        assert_eq!(seeded.trim(), candidate_sha.trim());
        let content = git_output(
            &no_auth,
            Command::new("git").arg("-C").arg(&new_repo).args(["show", &format!("{}:fix.txt", candidate_sha.trim())]),
        ).await.unwrap();
        assert_eq!(content.trim(), "prior candidate");
        // The default branch still tracks current upstream main.
        let new_base = git_output(
            &no_auth,
            Command::new("git").arg("-C").arg(&new_repo).args(["rev-parse", "--verify", "refs/heads/main"]),
        ).await.unwrap();
        assert_eq!(new_base.trim(), base_sha.trim());

        // No cross-task leak and no phantom candidate for a fresh task.
        let other_task = Uuid::new_v4();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,review_feedback,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(other_task.to_string()).bind(project_id.to_string()).bind("fresh task").bind("").bind("").bind("queued")
            .bind("").bind(&now).bind(&now)
            .execute(&state.db).await.unwrap();
        let other_exec = Uuid::new_v4();
        prepare_task_repo(&state, &project, other_task, other_exec, &GitCredential::Host).await.unwrap();
        let other_repo = git_root.join("tasks").join(format!("{other_exec}.git"));
        let other_ref = format!("refs/heads/lazyteam/task-{}", other_task.simple());
        let missing = git_run(
            &HostGitAuth::none(),
            Command::new("git").arg("-C").arg(&other_repo).args(["rev-parse", "--verify", &other_ref]),
        ).await.unwrap();
        assert!(!missing.status.success(), "fresh task must not inherit another task's candidate");
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    struct SeedFixture {
        root: PathBuf,
        state: Arc<crate::AppState>,
        project: Project,
        task_id: Uuid,
        worker_id: Uuid,
        now: String,
        base_sha: String,
        branch: String,
        allowed_ref: String,
    }

    async fn seed_fixture() -> SeedFixture {
        use sqlx::sqlite::SqlitePoolOptions;
        let root = std::env::temp_dir().join(format!("lazyteam-retry-seed-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let no_auth = HostGitAuth::none();
        let upstream = root.join("upstream.git");
        git_ok(&no_auth, Command::new("git").args(["init", "--bare"]).arg(&upstream)).await.unwrap();
        let seed_work = root.join("seed-work");
        git_ok(&no_auth, Command::new("git").args(["init"]).arg(&seed_work)).await.unwrap();
        for args in [["config", "user.name", "LazyTeam Test"], ["config", "user.email", "test@lazyteam.local"]] {
            git_ok(&no_auth, Command::new("git").arg("-C").arg(&seed_work).args(args)).await.unwrap();
        }
        tokio::fs::write(seed_work.join("base.txt"), "base\n").await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&seed_work).args(["add", "base.txt"])).await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&seed_work).args(["commit", "-m", "base"])).await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&seed_work).args(["branch", "-M", "main"])).await.unwrap();
        let upstream_url = upstream.to_string_lossy().to_string();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&seed_work).args(["push", &upstream_url, "refs/heads/main:refs/heads/main"])).await.unwrap();
        let base_sha = git_output(
            &no_auth,
            Command::new("git").arg("-C").arg(&upstream).args(["rev-parse", "refs/heads/main"]),
        ).await.unwrap();
        let db = SqlitePoolOptions::new().max_connections(1).connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!().run(&db).await.unwrap();
        let state = Arc::new(crate::AppState {
            db,
            public_url: None,
            oauth_password: None,
            git_credential_key: None,
            git_root: root.join("git"),
            agent_auth_updates: Default::default(),
            model_refresh_requests: Default::default(), oauth_login_states: Default::default(),
        });
        let now = chrono::Utc::now().to_rfc3339();
        let project_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        let worker_id = Uuid::new_v4();
        sqlx::query("INSERT INTO projects(id,slug,name,repo_url,default_branch,created_at,updated_at) VALUES(?,?,?,?,?,?,?)")
            .bind(project_id.to_string()).bind("seed-proj").bind("Seed").bind(&upstream_url).bind("main").bind(&now).bind(&now)
            .execute(&state.db).await.unwrap();
        sqlx::query("INSERT INTO workers(id,name,role,state,os,arch,protocol_version,worker_version,last_heartbeat_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)")
            .bind(worker_id.to_string()).bind("worker").bind("worker").bind("idle").bind("linux").bind("x86_64")
            .bind(crate::api::PROTOCOL_VERSION as i64).bind("test").bind(&now).bind(&now)
            .execute(&state.db).await.unwrap();
        sqlx::query("INSERT INTO tasks(id,project_id,title,description,expected_outcome,state,review_feedback,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)")
            .bind(task_id.to_string()).bind(project_id.to_string()).bind("seeded task").bind("").bind("").bind("failed")
            .bind("").bind(&now).bind(&now)
            .execute(&state.db).await.unwrap();
        let branch = format!("lazyteam/task-{}", task_id.simple());
        let project = Project {
            id: project_id,
            slug: "seed-proj".into(),
            name: "Seed".into(),
            repo_url: upstream_url,
            default_branch: "main".into(),
            contributor: Default::default(),
            required_worker_tags: Default::default(),
            default_task_tags: Default::default(),
            git_auth: Default::default(),
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        SeedFixture {
            root,
            allowed_ref: format!("refs/heads/{branch}"),
            state, project, task_id, worker_id, now,
            base_sha: base_sha.trim().to_string(),
            branch,
        }
    }

    /// Push a real candidate commit for `execution_id` into its task repo and
    /// record the completed execution row. Returns the candidate SHA.
    async fn record_completed_candidate(fixture: &SeedFixture, execution_id: Uuid, attempt: i64, file: &str, content: &str) -> String {
        let no_auth = HostGitAuth::none();
        prepare_task_repo(&fixture.state, &fixture.project, fixture.task_id, execution_id, &GitCredential::Host).await.unwrap();
        let repo = fixture.state.git_root.join("tasks").join(format!("{execution_id}.git"));
        let work = fixture.root.join(format!("candidate-{execution_id}"));
        git_ok(&no_auth, Command::new("git").args(["clone", &repo.to_string_lossy(), &work.to_string_lossy()])).await.unwrap();
        for args in [["config", "user.name", "LazyTeam Test"], ["config", "user.email", "test@lazyteam.local"]] {
            git_ok(&no_auth, Command::new("git").arg("-C").arg(&work).args(args)).await.unwrap();
        }
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&work).args(["checkout", "-b", &fixture.branch])).await.unwrap();
        tokio::fs::write(work.join(file), content).await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&work).args(["add", file])).await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&work).args(["commit", "-m", "lazyteam: candidate"])).await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&work).args(["push", "origin", &format!("HEAD:{}", fixture.allowed_ref)])).await.unwrap();
        let sha = git_output(&no_auth, Command::new("git").arg("-C").arg(&work).args(["rev-parse", "HEAD"])).await.unwrap();
        let result = lazyteam_core::ExecutionResult {
            status: "completed".into(),
            summary: "candidate".into(),
            commit_sha: Some(sha.trim().to_string()),
            base_sha: Some(fixture.base_sha.clone()),
            patch: None,
            patch_truncated: false,
            workspace_clean: Some(true),
            review_ref: Some(fixture.branch.clone()),
            changed_files: vec![file.into()],
            validation: vec![],
            warnings: vec![],
            artifacts: vec![],
            integration: None,
        };
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,result) VALUES(?,?,?,?,?,?,?,?)")
            .bind(execution_id.to_string()).bind(fixture.task_id.to_string()).bind(fixture.worker_id.to_string()).bind(attempt)
            .bind("completed").bind(&fixture.now).bind(&fixture.now).bind(serde_json::to_string(&result).unwrap())
            .execute(&fixture.state.db).await.unwrap();
        sha.trim().to_string()
    }

    async fn execution_result(fixture: &SeedFixture, execution_id: Uuid) -> lazyteam_core::ExecutionResult {
        let raw: String = sqlx::query_scalar("SELECT result FROM executions WHERE id=?")
            .bind(execution_id.to_string()).fetch_one(&fixture.state.db).await.unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    async fn advance_upstream(fixture: &SeedFixture, file: &str, content: &str) -> String {
        let no_auth = HostGitAuth::none();
        let work = fixture.root.join(format!("upstream-advance-{}", Uuid::new_v4()));
        git_ok(&no_auth, Command::new("git").args(["clone", "--branch", "main", &fixture.project.repo_url, &work.to_string_lossy()])).await.unwrap();
        for args in [["config", "user.name", "LazyTeam Test"], ["config", "user.email", "test@lazyteam.local"]] {
            git_ok(&no_auth, Command::new("git").arg("-C").arg(&work).args(args)).await.unwrap();
        }
        tokio::fs::write(work.join(file), content).await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&work).args(["add", file])).await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&work).args(["commit", "-m", "advance upstream"])).await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&work).args(["push", "origin", "HEAD:refs/heads/main"])).await.unwrap();
        git_output(&no_auth, Command::new("git").arg("-C").arg(&work).args(["rev-parse", "HEAD"])).await.unwrap().trim().to_string()
    }

    #[tokio::test]
    async fn integration_snapshot_same_upstream_is_candidate() {
        let fixture = seed_fixture().await;
        let execution_id = Uuid::new_v4();
        let candidate = record_completed_candidate(&fixture, execution_id, 1, "fix.txt", "candidate\n").await;
        let result = execution_result(&fixture, execution_id).await;
        let snapshot = prepare_integration_snapshot(&fixture.state, &fixture.project, execution_id, &result).await.unwrap();
        assert!(snapshot.is_clean());
        assert_eq!(snapshot.upstream_sha, fixture.base_sha);
        assert_eq!(snapshot.integration_sha.as_deref(), Some(candidate.as_str()));
        assert!(snapshot.effective_diff_hash.is_some());
        assert!(snapshot.conflict.is_none());
        let repo = fixture.state.git_root.join("tasks").join(format!("{execution_id}.git"));
        let pinned = git_output(&HostGitAuth::none(), Command::new("git").arg("-C").arg(&repo).args(["rev-parse", &format!("refs/lazyteam/integration/{candidate}")])).await.unwrap();
        assert_eq!(pinned.trim(), candidate);
        let _ = tokio::fs::remove_dir_all(&fixture.root).await;
    }

    #[tokio::test]
    async fn integration_snapshot_cleanly_merges_advanced_upstream() {
        let fixture = seed_fixture().await;
        let execution_id = Uuid::new_v4();
        let candidate = record_completed_candidate(&fixture, execution_id, 1, "fix.txt", "candidate\n").await;
        let upstream = advance_upstream(&fixture, "unrelated.txt", "upstream\n").await;
        let result = execution_result(&fixture, execution_id).await;
        let snapshot = prepare_integration_snapshot(&fixture.state, &fixture.project, execution_id, &result).await.unwrap();
        assert!(snapshot.is_clean());
        assert_eq!(snapshot.upstream_sha, upstream);
        let integrated = snapshot.integration_sha.as_deref().unwrap();
        assert_ne!(integrated, candidate);
        let repo = fixture.state.git_root.join("tasks").join(format!("{execution_id}.git"));
        let fix = git_output(&HostGitAuth::none(), Command::new("git").arg("-C").arg(&repo).args(["show", &format!("{integrated}:fix.txt")])).await.unwrap();
        let unrelated = git_output(&HostGitAuth::none(), Command::new("git").arg("-C").arg(&repo).args(["show", &format!("{integrated}:unrelated.txt")])).await.unwrap();
        assert_eq!(fix.trim(), "candidate");
        assert_eq!(unrelated.trim(), "upstream");
        let _ = tokio::fs::remove_dir_all(&fixture.root).await;
    }

    #[tokio::test]
    async fn integration_snapshot_reports_real_conflict_against_current_upstream() {
        let fixture = seed_fixture().await;
        let execution_id = Uuid::new_v4();
        let candidate = record_completed_candidate(&fixture, execution_id, 1, "base.txt", "candidate\n").await;
        let upstream = advance_upstream(&fixture, "base.txt", "upstream\n").await;
        let result = execution_result(&fixture, execution_id).await;
        let snapshot = prepare_integration_snapshot(&fixture.state, &fixture.project, execution_id, &result).await.unwrap();
        assert!(!snapshot.is_clean());
        assert_eq!(snapshot.candidate_sha, candidate);
        assert_eq!(snapshot.upstream_sha, upstream);
        assert!(snapshot.integration_sha.is_none());
        let conflict = snapshot.conflict.expect("same-file edits must conflict");
        assert_eq!(conflict.files.len(), 1);
        assert_eq!(conflict.files[0].path, "base.txt");
        assert_eq!(conflict.files[0].status, "UU");
        assert_eq!(conflict.files[0].kind, "both_modified");
        assert!(conflict.files[0].excerpt.as_deref().is_some_and(|text| text.contains("<<<<<<<")));
        let _ = tokio::fs::remove_dir_all(&fixture.root).await;
    }

    async fn seeded_ref(state: &Arc<crate::AppState>, execution_id: Uuid, allowed_ref: &str) -> Option<String> {
        let repo = state.git_root.join("tasks").join(format!("{execution_id}.git"));
        git_output(
            &HostGitAuth::none(),
            Command::new("git").arg("-C").arg(&repo).args(["rev-parse", "--verify", allowed_ref]),
        ).await.ok().map(|sha| sha.trim().to_string())
    }

    /// Fail-closed: a plausible candidate whose execution repository is gone
    /// (or corrupt) must fail preparation instead of silently restarting
    /// from base and reproducing the no-change failure.
    #[tokio::test]
    async fn retry_seed_failure_is_fail_closed_when_candidate_unrecoverable() {
        let fixture = seed_fixture().await;
        let exec1 = Uuid::new_v4();
        record_completed_candidate(&fixture, exec1, 1, "fix.txt", "prior candidate\n").await;
        // Lose the prior execution repository: the DB still records a valid
        // candidate, but it can no longer be reconstructed.
        tokio::fs::remove_dir_all(fixture.state.git_root.join("tasks").join(format!("{exec1}.git"))).await.unwrap();
        let error = prepare_task_repo(&fixture.state, &fixture.project, fixture.task_id, Uuid::new_v4(), &GitCredential::Host)
            .await
            .expect_err("unrecoverable candidate must fail closed");
        assert!(error.1.contains("could not be reconstructed"), "unexpected error: {}", error.1);
        let _ = tokio::fs::remove_dir_all(&fixture.root).await;
    }

    /// Validity filtering: rows with a mismatched review ref, a missing
    /// base, a non-ancestor base, or an unknown commit are skipped (never
    /// selected), while an older valid candidate is still seeded.
    #[tokio::test]
    async fn retry_seed_skips_invalid_candidates_and_seeds_older_valid() {
        let fixture = seed_fixture().await;
        let exec1 = Uuid::new_v4();
        let valid_sha = record_completed_candidate(&fixture, exec1, 1, "fix.txt", "prior candidate\n").await;
        let no_auth = HostGitAuth::none();

        // Attempt 2: completed row pointing at another task's branch.
        let exec2 = Uuid::new_v4();
        prepare_task_repo(&fixture.state, &fixture.project, fixture.task_id, exec2, &GitCredential::Host).await.unwrap();
        let other_branch = format!("lazyteam/task-{}", Uuid::new_v4().simple());
        let cross_result = serde_json::json!({
            "status": "completed", "summary": "cross",
            "commit_sha": valid_sha, "base_sha": fixture.base_sha,
            "review_ref": other_branch, "changed_files": []
        });
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,result) VALUES(?,?,?,?,?,?,?,?)")
            .bind(exec2.to_string()).bind(fixture.task_id.to_string()).bind(fixture.worker_id.to_string()).bind(2_i64)
            .bind("completed").bind(&fixture.now).bind(&fixture.now).bind(cross_result.to_string())
            .execute(&fixture.state.db).await.unwrap();

        // Attempt 3: completed row with no recorded base (legacy/unverifiable).
        let exec3 = Uuid::new_v4();
        let nobase_result = serde_json::json!({
            "status": "completed", "summary": "nobase",
            "commit_sha": valid_sha,
            "review_ref": fixture.branch, "changed_files": []
        });
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,result) VALUES(?,?,?,?,?,?,?,?)")
            .bind(exec3.to_string()).bind(fixture.task_id.to_string()).bind(fixture.worker_id.to_string()).bind(3_i64)
            .bind("completed").bind(&fixture.now).bind(&fixture.now).bind(nobase_result.to_string())
            .execute(&fixture.state.db).await.unwrap();

        // Attempt 4: plausible row whose recorded base is not an ancestor of
        // the recorded candidate (stale/cross-history). Its own repo exists.
        let exec4 = Uuid::new_v4();
        prepare_task_repo(&fixture.state, &fixture.project, fixture.task_id, exec4, &GitCredential::Host).await.unwrap();
        let repo4 = fixture.state.git_root.join("tasks").join(format!("{exec4}.git"));
        // Advance upstream so the recorded "base" postdates the candidate.
        let advance = fixture.root.join("advance");
        git_ok(&no_auth, Command::new("git").args(["clone", "--branch", "main", &fixture.project.repo_url, &advance.to_string_lossy()])).await.unwrap();
        for args in [["config", "user.name", "LazyTeam Test"], ["config", "user.email", "test@lazyteam.local"]] {
            git_ok(&no_auth, Command::new("git").arg("-C").arg(&advance).args(args)).await.unwrap();
        }
        tokio::fs::write(advance.join("later.txt"), "later\n").await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&advance).args(["add", "later.txt"])).await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&advance).args(["commit", "-m", "later"])).await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&advance).args(["push", "origin", "HEAD:refs/heads/main"])).await.unwrap();
        let later_base = git_output(&no_auth, Command::new("git").arg("-C").arg(&advance).args(["rev-parse", "HEAD"])).await.unwrap();
        // Point the task branch at the old valid candidate inside repo4 so
        // the ref is stable but the recorded base is wrong.
        let old_repo = fixture.state.git_root.join("tasks").join(format!("{exec1}.git"));
        git_ok(
            &no_auth,
            Command::new("git").arg("-C").arg(&repo4).args(["fetch", "--no-tags", &old_repo.to_string_lossy(), &format!("{}:{}", fixture.allowed_ref, fixture.allowed_ref)]),
        ).await.unwrap();
        let stale_result = serde_json::json!({
            "status": "completed", "summary": "stale",
            "commit_sha": valid_sha, "base_sha": later_base.trim(),
            "review_ref": fixture.branch, "changed_files": []
        });
        sqlx::query("INSERT INTO executions(id,task_id,worker_id,attempt,state,lease_until,created_at,result) VALUES(?,?,?,?,?,?,?,?)")
            .bind(exec4.to_string()).bind(fixture.task_id.to_string()).bind(fixture.worker_id.to_string()).bind(4_i64)
            .bind("completed").bind(&fixture.now).bind(&fixture.now).bind(stale_result.to_string())
            .execute(&fixture.state.db).await.unwrap();

        // The fresh execution repo must carry the older valid candidate,
        // never the cross-task, baseless, or stale rows.
        let exec5 = Uuid::new_v4();
        prepare_task_repo(&fixture.state, &fixture.project, fixture.task_id, exec5, &GitCredential::Host).await.unwrap();
        assert_eq!(seeded_ref(&fixture.state, exec5, &fixture.allowed_ref).await.as_deref(), Some(valid_sha.as_str()));
        let _ = tokio::fs::remove_dir_all(&fixture.root).await;
    }

    #[tokio::test]
    async fn dry_run_write_probe_does_not_mutate_upstream_ref() {
        let root = std::env::temp_dir().join(format!("lazyteam-git-probe-{}", Uuid::new_v4()));
        let source = root.join("source");
        let upstream = root.join("upstream.git");
        let probe = root.join("probe.git");
        tokio::fs::create_dir_all(&root).await.unwrap();
        let no_auth = HostGitAuth::none();

        git_ok(&no_auth, Command::new("git").args(["init", "--bare"]).arg(&upstream)).await.unwrap();
        git_ok(&no_auth, Command::new("git").args(["init"]).arg(&source)).await.unwrap();
        tokio::fs::write(source.join("README.md"), "probe\n").await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&source).args(["add", "README.md"])).await.unwrap();
        git_ok(
            &no_auth,
            Command::new("git")
                .arg("-C").arg(&source)
                .args(["-c", "user.name=LazyTeam Probe", "-c", "user.email=probe@lazyteam.local", "commit", "-m", "probe"]),
        ).await.unwrap();
        git_ok(&no_auth, Command::new("git").arg("-C").arg(&source).args(["branch", "-M", "main"])).await.unwrap();
        let upstream_url = upstream.to_string_lossy().to_string();
        git_ok(
            &no_auth,
            Command::new("git").arg("-C").arg(&source).args(["push", &upstream_url, "refs/heads/main:refs/heads/main"]),
        ).await.unwrap();
        let before = git_output(
            &no_auth,
            Command::new("git").arg("-C").arg(&upstream).args(["rev-parse", "refs/heads/main"]),
        ).await.unwrap();

        git_ok(&no_auth, Command::new("git").args(["init", "--bare"]).arg(&probe)).await.unwrap();
        let refspec = "refs/heads/main:refs/heads/main";
        let mut fetch = Command::new("git");
        fetch.arg("-C").arg(&probe).args(["fetch", "--no-tags", &upstream_url, refspec]);
        probe_git_command(&no_auth, &mut fetch, "read test upstream").await.unwrap();
        let mut push = Command::new("git");
        push.arg("-C").arg(&probe).args(["push", "--dry-run", &upstream_url, refspec]);
        probe_git_command(&no_auth, &mut push, "dry-run test upstream write").await.unwrap();

        let after = git_output(
            &no_auth,
            Command::new("git").arg("-C").arg(&upstream).args(["rev-parse", "refs/heads/main"]),
        ).await.unwrap();
        assert_eq!(before.trim(), after.trim());
        let _ = tokio::fs::remove_dir_all(root).await;
    }
}
