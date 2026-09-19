use std::{path::{Path, PathBuf}, process::Stdio, sync::Arc};

use axum::{
    body::{to_bytes, Body},
    extract::{Path as AxumPath, Request, State},
    http::{header, HeaderName, HeaderValue, Response, StatusCode},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use lazyteam_core::{GitCredential, Project};
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
    Ok(())
}

pub(crate) async fn publish_reviewed_task(
    state: &AppState,
    evidence: &api::ReviewEvidence,
) -> Result<String, ApiError> {
    let review_ref = evidence.checkout.review_ref.as_deref().ok_or((
        StatusCode::CONFLICT,
        "reviewed execution has no candidate ref".into(),
    ))?;
    let candidate_sha = evidence.checkout.commit_sha.as_deref().ok_or((
        StatusCode::CONFLICT,
        "reviewed execution has no candidate commit".into(),
    ))?;
    let base_sha = evidence.checkout.base_sha.as_deref().ok_or((
        StatusCode::CONFLICT,
        "reviewed execution has no pinned base commit".into(),
    ))?;
    let project_row = sqlx::query("SELECT * FROM projects WHERE id=?")
        .bind(evidence.project.id.to_string())
        .fetch_one(&state.db)
        .await
        .map_err(internal)?;
    let credential = api::git_credential_from_row(state, &project_row)?;
    let upstream_url = upstream_repo_url(&evidence.project.repo_url, &credential).map_err(internal)?;
    let auth = HostGitAuth::prepare(state, &credential).await.map_err(internal)?;
    let result = publish_reviewed_task_inner(state, evidence, review_ref, candidate_sha, base_sha, &upstream_url, &auth).await;
    auth.cleanup().await;
    result
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
            GitCredential::Worker => {}
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
