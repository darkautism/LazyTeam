use std::{collections::{BTreeMap, BTreeSet}, path::{Path, PathBuf}, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use clap::Parser;
use lazyteam_core::{AgentCapabilities, AgentConfig, AgentRole, Assignment, ExecutionResult, GitCredential, ReviewAssignment, ReviewVerdict};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::Deserialize;
use serde_json::json;
use tokio::{process::Command, time::{sleep, Instant}};
use tracing::{error, info, warn};
use uuid::Uuid;

mod runtime;
use runtime::{AgentRuntime, PiRuntime};

const WORKER_CREDENTIAL_HEADER: &str = "x-lazyteam-worker-credential";
const MAX_REVIEW_PATCH_BYTES: usize = 256 * 1024;

#[derive(Parser, Debug)]
struct Args {
    /// Explicit control-plane URL. Usually unnecessary when --join-code is used or
    /// after the endpoint has been persisted from a successful enrollment.
    #[arg(long, env = "LAZYTEAM_SERVER")]
    server: Option<String>,
    /// Short-lived signed bootstrap code issued by the LazyTeam admin UI. It contains
    /// the remote control-plane endpoint and is also the first-enrollment credential.
    #[arg(long, env = "LAZYTEAM_WORKER_JOIN_CODE")]
    join_code: Option<String>,
    /// Legacy shared enrollment secret. Use with --server when no join code is available.
    #[arg(long, env = "LAZYTEAM_WORKER_TOKEN")]
    worker_token: Option<String>,
    #[arg(long, env = "LAZYTEAM_WORKER_NAME", default_value = "worker")]
    name: String,
    #[arg(long = "tag", value_parser = parse_tag)]
    tags: Vec<(String, String)>,
    #[arg(long = "project")]
    allowed_projects: Vec<String>,
    #[arg(long, default_value_t = 1)]
    slots: u32,
    #[arg(long, env = "LAZYTEAM_WORKER_STATE_DIR", default_value = ".lazyteam-worker")]
    state_dir: PathBuf,
    #[arg(long, env = "LAZYTEAM_WORKSPACE_DIR", default_value = "lazyteam-workspaces")]
    workspace_dir: PathBuf,
    #[arg(long, env = "LAZYTEAM_PI_BIN", default_value = "pi")]
    pi_bin: String,
    #[arg(long, env = "LAZYTEAM_PI_PROVIDER")]
    pi_provider: Option<String>,
    #[arg(long, env = "LAZYTEAM_PI_MODEL")]
    pi_model: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WorkerJoinPayload {
    server: String,
}

#[derive(Debug, Deserialize)]
struct WorkerRuntimeConfig {
    role: AgentRole,
    agent: AgentConfig,
}

#[derive(Debug, Deserialize)]
struct WorkerCleanup {
    task_id: Uuid,
    project_slug: String,
    review_ref: String,
    git_credential: GitCredential,
}

struct GitAuthContext {
    env: Vec<(String, String)>,
    key_path: Option<PathBuf>,
}

impl GitAuthContext {
    async fn prepare(state_dir: &Path, task_id: Uuid, nonce: Uuid, credential: &GitCredential) -> anyhow::Result<Self> {
        let mut env = vec![("GIT_TERMINAL_PROMPT".into(), "0".into())];
        let mut key_path = None;
        match credential {
            GitCredential::Worker => {}
            GitCredential::HttpsBasic { username, secret } => {
                if username.trim().is_empty() || secret.is_empty() {
                    bail!("server-managed HTTPS Git credential is incomplete");
                }
                let value = STANDARD.encode(format!("{username}:{secret}"));
                env.push(("GIT_CONFIG_COUNT".into(), "1".into()));
                env.push(("GIT_CONFIG_KEY_0".into(), "http.extraHeader".into()));
                env.push(("GIT_CONFIG_VALUE_0".into(), format!("Authorization: Basic {value}")));
            }
            GitCredential::SshKey { private_key } => {
                if private_key.trim().is_empty() {
                    bail!("server-managed SSH private key is empty");
                }
                let dir = state_dir.join("git-auth");
                tokio::fs::create_dir_all(&dir).await?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).await?;
                }
                let path = dir.join(format!("{}-{}.key", task_id.simple(), nonce.simple()));
                tokio::fs::write(&path, private_key.as_bytes()).await?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
                }
                let quoted = shell_quote(&path)?;
                env.push(("GIT_SSH_COMMAND".into(), format!("ssh -i {quoted} -o IdentitiesOnly=yes -o BatchMode=yes")));
                key_path = Some(path);
            }
        }
        Ok(Self { env, key_path })
    }

    fn apply(&self, command: &mut Command) {
        for (key, value) in &self.env {
            command.env(key, value);
        }
    }

    async fn cleanup(&self) {
        if let Some(path) = &self.key_path {
            if let Err(error) = tokio::fs::remove_file(path).await {
                if error.kind() != std::io::ErrorKind::NotFound {
                    warn!(%error, "failed to remove ephemeral Git SSH key");
                }
            }
        }
    }
}

fn shell_quote(path: &Path) -> anyhow::Result<String> {
    let raw = path.to_str().context("non-utf8 Git credential path")?;
    Ok(format!("'{}'", raw.replace('\'', "'\"'\"'")))
}

async fn clear_stale_git_auth(state_dir: &Path) -> anyhow::Result<()> {
    let dir = state_dir.join("git-auth");
    match tokio::fs::remove_dir_all(&dir).await {
        Ok(()) => info!(path = %dir.display(), "removed stale ephemeral Git credential files"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("remove stale Git credential files"),
    }
    Ok(())
}

fn parse_join_code_server(raw: &str) -> anyhow::Result<String> {
    let mut parts = raw.split('.');
    if parts.next() != Some("ltj1") {
        bail!("invalid worker join code prefix");
    }
    let payload = parts.next().context("worker join code payload is missing")?;
    let signature = parts.next().context("worker join code signature is missing")?;
    if signature.is_empty() || parts.next().is_some() {
        bail!("invalid worker join code format");
    }
    let payload = URL_SAFE_NO_PAD.decode(payload).context("decode worker join code payload")?;
    let payload: WorkerJoinPayload = serde_json::from_slice(&payload).context("parse worker join code payload")?;
    normalize_server(&payload.server)
}

fn normalize_server(raw: &str) -> anyhow::Result<String> {
    let raw = raw.trim().trim_end_matches('/');
    let url = reqwest::Url::parse(raw).context("parse LazyTeam server URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        bail!("LazyTeam server URL must be an absolute http:// or https:// URL");
    }
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        bail!("LazyTeam server URL must not contain credentials, query, or fragment");
    }
    if url.path() != "/" && !url.path().is_empty() {
        bail!("LazyTeam server URL must not contain a path");
    }
    Ok(raw.to_string())
}

fn resolve_worker_path(startup_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() { path.to_path_buf() } else { startup_dir.join(path) }
}

fn parse_tag(raw: &str) -> Result<(String, String), String> {
    let (key, value) = raw.split_once('=').ok_or_else(|| "tag must be key=value".to_string())?;
    if key.is_empty() || value.is_empty() { return Err("tag key/value must not be empty".into()); }
    Ok((key.to_string(), value.to_string()))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let mut args = Args::parse();
    let startup_dir = std::env::current_dir().context("read worker startup directory")?;
    args.state_dir = resolve_worker_path(&startup_dir, &args.state_dir);
    args.workspace_dir = resolve_worker_path(&startup_dir, &args.workspace_dir);
    tokio::fs::create_dir_all(&args.state_dir).await?;
    clear_stale_git_auth(&args.state_dir).await?;
    tokio::fs::create_dir_all(&args.workspace_dir).await?;
    let worker_id = load_or_create_worker_id(&args.state_dir).await?;
    let join_server = args.join_code.as_deref().map(parse_join_code_server).transpose()?;
    let explicit_server = args.server.as_deref().map(normalize_server).transpose()?;
    if let (Some(join), Some(explicit)) = (&join_server, &explicit_server) {
        if join != explicit {
            bail!("--server does not match the endpoint embedded in --join-code");
        }
    }
    let persisted_server = load_server_url(&args.state_dir).await?;
    let server = join_server
        .or(explicit_server)
        .or(persisted_server)
        .context("worker endpoint unknown; provide --join-code (recommended) or --server for first enrollment")?;
    let enrollment_credential = args.join_code.as_deref().or(args.worker_token.as_deref());
    let client = Client::builder().timeout(Duration::from_secs(30)).build()?;
    let pi_bin = args.pi_bin.clone();
    let legacy_provider = args.pi_provider.clone();
    let legacy_model = args.pi_model.clone();
    let probe_runtime = PiRuntime { binary: pi_bin.clone(), provider: None, model: None, session_dir: None };
    let mut agent_capabilities = probe_runtime.capabilities().await;
    let tags: BTreeMap<String, String> = args.tags.into_iter().collect();
    let projects: BTreeSet<String> = args.allowed_projects.into_iter().collect();

    let mut worker_credential = match load_worker_credential(&args.state_dir).await? {
        Some(credential) => credential,
        None => {
            let enrollment = enrollment_credential.context(
                "first enrollment requires --join-code (recommended) or LAZYTEAM_WORKER_TOKEN with an explicit --server",
            )?;
            let credential = register(
                &client,
                &server,
                enrollment,
                worker_id,
                &args.name,
                tags.clone(),
                projects.clone(),
                args.slots,
                agent_capabilities.clone(),
            ).await?;
            persist_worker_credential(&args.state_dir, &credential).await?;
            persist_server_url(&args.state_dir, &server).await?;
            info!(%worker_id, server = %server, "worker enrolled; endpoint and credential persisted");
            credential
        }
    };

    // A server database restore/replacement may invalidate the persisted credential.
    // Re-enroll only when a join code or legacy enrollment secret was intentionally supplied.
    if heartbeat(&client, &server, &worker_credential, worker_id).await.is_err() {
        let enrollment = enrollment_credential.context(
            "persisted worker credential was rejected; provide a fresh --join-code or LAZYTEAM_WORKER_TOKEN for recovery",
        )?;
        worker_credential = register(
            &client,
            &server,
            enrollment,
            worker_id,
            &args.name,
            tags,
            projects,
            args.slots,
            agent_capabilities.clone(),
        ).await?;
        persist_worker_credential(&args.state_dir, &worker_credential).await?;
        persist_server_url(&args.state_dir, &server).await?;
        info!(%worker_id, server = %server, "worker re-enrolled after credential rejection");
    } else {
        persist_server_url(&args.state_dir, &server).await?;
    }

    if let Err(error) = report_capabilities(&client, &server, &worker_credential, worker_id, &agent_capabilities).await {
        warn!(%error, "initial agent capability report failed");
    }
    let mut runtime_config = fetch_runtime_config(&client, &server, &worker_credential, worker_id).await?;
    let mut next_capability_probe = Instant::now() + Duration::from_secs(60);

    loop {
        if let Err(error) = heartbeat(&client, &server, &worker_credential, worker_id).await {
            warn!(%error, "heartbeat failed");
            sleep(Duration::from_secs(5)).await;
            continue;
        }
        if let Err(error) = process_cleanup(&client, &server, &worker_credential, worker_id, &args.workspace_dir, &args.state_dir).await {
            warn!(%error, "post-merge cleanup poll failed");
        }
        if Instant::now() >= next_capability_probe {
            agent_capabilities = probe_runtime.capabilities().await;
            if let Err(error) = report_capabilities(&client, &server, &worker_credential, worker_id, &agent_capabilities).await {
                warn!(%error, "agent capability refresh failed");
            }
            next_capability_probe = Instant::now() + Duration::from_secs(60);
        }
        match fetch_runtime_config(&client, &server, &worker_credential, worker_id).await {
            Ok(config) => runtime_config = config,
            Err(error) => warn!(%error, "worker runtime config refresh failed; using last known config"),
        }
        match runtime_config.role {
            AgentRole::Worker => match claim(&client, &server, &worker_credential, worker_id).await {
                Ok(Some(assignment)) => {
                    info!(task = %assignment.task.id, execution = %assignment.execution.id, project = %assignment.project.slug, "claimed implementation task");
                    let session_dir = args.state_dir.join("sessions").join(assignment.task.id.to_string());
                    let runtime = match runtime_for_config(&runtime_config.agent, &pi_bin, legacy_provider.as_deref(), legacy_model.as_deref(), session_dir) {
                        Ok(runtime) => runtime,
                        Err(error) => { error!(%error, "invalid agent configuration"); sleep(Duration::from_secs(3)).await; continue; }
                    };
                    info!(role = "worker", agent = runtime.kind(), provider = ?runtime_config.agent.provider, model = ?runtime_config.agent.model, "starting agent runtime");
                    if let Err(error) = execute_assignment(
                        &client,
                        &server,
                        &worker_credential,
                        &args.workspace_dir,
                        &args.state_dir,
                        runtime,
                        &runtime_config.agent.initial_prompt,
                        assignment,
                    ).await {
                        error!(%error, "assignment execution failed");
                    }
                }
                Ok(None) => sleep(Duration::from_secs(3)).await,
                Err(error) => { warn!(%error, "implementation claim failed"); sleep(Duration::from_secs(5)).await; }
            },
            AgentRole::Reviewer => match claim_review(&client, &server, &worker_credential, worker_id).await {
                Ok(Some(assignment)) => {
                    info!(task = %assignment.task.id, review = %assignment.review.id, project = %assignment.project.slug, "claimed review");
                    let session_dir = args.state_dir.join("review-sessions").join(assignment.review.id.to_string());
                    let runtime = match runtime_for_config(&runtime_config.agent, &pi_bin, legacy_provider.as_deref(), legacy_model.as_deref(), session_dir.clone()) {
                        Ok(runtime) => runtime,
                        Err(error) => { error!(%error, "invalid reviewer agent configuration"); sleep(Duration::from_secs(3)).await; continue; }
                    };
                    info!(role = "reviewer", agent = runtime.kind(), provider = ?runtime_config.agent.provider, model = ?runtime_config.agent.model, "starting reviewer runtime");
                    if let Err(error) = execute_review_assignment(
                        &client,
                        &server,
                        &worker_credential,
                        &args.workspace_dir,
                        &args.state_dir,
                        runtime,
                        &runtime_config.agent.initial_prompt,
                        assignment,
                    ).await {
                        error!(%error, "review execution failed");
                    }
                    if session_dir.exists() { let _ = tokio::fs::remove_dir_all(session_dir).await; }
                }
                Ok(None) => sleep(Duration::from_secs(3)).await,
                Err(error) => { warn!(%error, "review claim failed"); sleep(Duration::from_secs(5)).await; }
            },
        }
    }
}

fn enrollment_auth(request: RequestBuilder, token: &str) -> RequestBuilder {
    request.bearer_auth(token)
}

fn worker_auth(request: RequestBuilder, credential: &str) -> RequestBuilder {
    request.header(WORKER_CREDENTIAL_HEADER, credential)
}

async fn register(
    client: &Client,
    server: &str,
    enrollment_token: &str,
    id: Uuid,
    name: &str,
    tags: BTreeMap<String, String>,
    allowed_projects: BTreeSet<String>,
    slots: u32,
    agent_capabilities: AgentCapabilities,
) -> anyhow::Result<String> {
    let response = enrollment_auth(client.post(format!("{server}/api/workers/register")), enrollment_token).json(&json!({
        "id": id,
        "name": name,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "tags": tags,
        "allowed_projects": allowed_projects,
        "slots": slots,
        "worker_version": env!("CARGO_PKG_VERSION"),
        "protocol_version": 3,
        "agent_type": "pi",
        "agent_capabilities": agent_capabilities
    })).send().await?;
    let response = ensure_success(response).await?;
    let credential = response
        .headers()
        .get(WORKER_CREDENTIAL_HEADER)
        .and_then(|v| v.to_str().ok())
        .context("server did not return a worker-specific credential")?
        .to_string();
    Ok(credential)
}

async fn report_capabilities(client: &Client, server: &str, credential: &str, worker_id: Uuid, capabilities: &AgentCapabilities) -> anyhow::Result<()> {
    let response = worker_auth(client.post(format!("{server}/api/workers/{worker_id}/capabilities")), credential)
        .header("x-lazyteam-worker-protocol-version", "3")
        .header("x-lazyteam-worker-version", env!("CARGO_PKG_VERSION"))
        .json(capabilities).send().await?;
    ensure_success(response).await?;
    Ok(())
}

async fn fetch_runtime_config(client: &Client, server: &str, credential: &str, worker_id: Uuid) -> anyhow::Result<WorkerRuntimeConfig> {
    let response = worker_auth(client.get(format!("{server}/api/workers/{worker_id}/config")), credential).send().await?;
    Ok(ensure_success(response).await?.json().await?)
}

fn runtime_for_config(agent: &AgentConfig, pi_bin: &str, legacy_provider: Option<&str>, legacy_model: Option<&str>, session_dir: PathBuf) -> anyhow::Result<Arc<dyn AgentRuntime>> {
    if agent.agent_type != "pi" { bail!("unsupported agent type {}", agent.agent_type); }
    Ok(Arc::new(PiRuntime {
        binary: pi_bin.to_string(),
        provider: agent.provider.clone().or_else(|| legacy_provider.map(str::to_string)),
        model: agent.model.clone().or_else(|| legacy_model.map(str::to_string)),
        session_dir: Some(session_dir),
    }))
}

async fn process_cleanup(client: &Client, server: &str, credential: &str, worker_id: Uuid, workspace_root: &Path, state_dir: &Path) -> anyhow::Result<()> {
    let response = worker_auth(client.get(format!("{server}/api/workers/{worker_id}/cleanup")), credential).send().await?;
    let items: Vec<WorkerCleanup> = ensure_success(response).await?.json().await?;
    for item in items {
        let workspace = workspace_root.join(&item.project_slug).join(item.task_id.to_string());
        if workspace.exists() {
            match GitAuthContext::prepare(state_dir, item.task_id, Uuid::new_v4(), &item.git_credential).await {
                Ok(auth) => {
                    if let Err(error) = command_ok_with_auth(&workspace, "git", &["push", "origin", "--delete", &item.review_ref], &auth).await {
                        warn!(%error, task = %item.task_id, "review branch cleanup skipped or already deleted");
                    }
                    auth.cleanup().await;
                }
                Err(error) => warn!(%error, task = %item.task_id, "review branch cleanup credential setup failed"),
            }
            tokio::fs::remove_dir_all(&workspace).await?;
        }
        let session_dir = state_dir.join("sessions").join(item.task_id.to_string());
        if session_dir.exists() { tokio::fs::remove_dir_all(&session_dir).await?; }
        let response = worker_auth(client.post(format!("{server}/api/workers/{worker_id}/cleanup/{}", item.task_id)), credential).send().await?;
        ensure_success(response).await?;
        info!(task = %item.task_id, "merged task workspace and agent session cleaned up");
    }
    Ok(())
}

async fn heartbeat(client: &Client, server: &str, credential: &str, worker_id: Uuid) -> anyhow::Result<()> {
    let response = worker_auth(client.post(format!("{server}/api/workers/{worker_id}/heartbeat")), credential).send().await?;
    ensure_success(response).await?;
    Ok(())
}

async fn claim(client: &Client, server: &str, credential: &str, worker_id: Uuid) -> anyhow::Result<Option<Assignment>> {
    let response = worker_auth(client.post(format!("{server}/api/workers/{worker_id}/claim")), credential).send().await?;
    if response.status() == StatusCode::NO_CONTENT { return Ok(None); }
    let response = ensure_success(response).await?;
    Ok(Some(response.json().await?))
}

async fn claim_review(client: &Client, server: &str, credential: &str, worker_id: Uuid) -> anyhow::Result<Option<ReviewAssignment>> {
    let response = worker_auth(client.post(format!("{server}/api/workers/{worker_id}/review-claim")), credential).send().await?;
    if response.status() == StatusCode::NO_CONTENT { return Ok(None); }
    let response = ensure_success(response).await?;
    Ok(Some(response.json().await?))
}

async fn execute_review_assignment(
    client: &Client,
    server: &str,
    worker_credential: &str,
    workspace_root: &Path,
    state_dir: &Path,
    runtime: Arc<dyn AgentRuntime>,
    initial_prompt: &str,
    assignment: ReviewAssignment,
) -> anyhow::Result<()> {
    let review_id = assignment.review.id;
    let renew_client = client.clone();
    let renew_server = server.to_string();
    let renew_credential = worker_credential.to_string();
    let renew = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            match worker_auth(
                renew_client.post(format!("{renew_server}/api/reviews/{review_id}/renew")),
                &renew_credential,
            ).send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => warn!(status = %response.status(), %review_id, "review lease renew rejected"),
                Err(error) => warn!(%error, %review_id, "review lease renew failed"),
            }
        }
    });

    let workspace = workspace_root
        .join(".reviews")
        .join(&assignment.project.slug)
        .join(review_id.to_string());
    let outcome = match GitAuthContext::prepare(state_dir, assignment.task.id, review_id, &assignment.git_credential).await {
        Ok(auth) => {
            let prepared = prepare_review_workspace(&workspace, &assignment, &auth).await;
            auth.cleanup().await;
            match prepared {
                Ok(()) => {
                    let prompt = build_review_prompt(initial_prompt, &assignment)?;
                    match runtime.run(&workspace, &prompt, &review_id.to_string()).await {
                        Ok(agent) => {
                            let dirty = git_output(&workspace, &["status", "--porcelain"]).await.unwrap_or_default();
                            if !dirty.is_empty() {
                                Err(anyhow::anyhow!("reviewer modified the pinned checkout; review discarded"))
                            } else {
                                parse_review_verdict(&agent.summary)
                            }
                        }
                        Err(error) => Err(error),
                    }
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    };
    renew.abort();

    let body = match outcome {
        Ok(verdict) => json!({"status":"completed","verdict":verdict}),
        Err(error) => json!({"status":"failed","error":error.to_string()}),
    };
    let response = worker_auth(
        client.post(format!("{server}/api/reviews/{review_id}/finish")),
        worker_credential,
    ).json(&body).send().await?;
    ensure_success(response).await?;
    if workspace.exists() { let _ = tokio::fs::remove_dir_all(&workspace).await; }
    Ok(())
}

async fn prepare_review_workspace(path: &Path, assignment: &ReviewAssignment, git_auth: &GitAuthContext) -> anyhow::Result<()> {
    if path.exists() { tokio::fs::remove_dir_all(path).await?; }
    if let Some(parent) = path.parent() { tokio::fs::create_dir_all(parent).await?; }
    command_ok_with_auth(
        Path::new("."),
        "git",
        &["clone", "--branch", &assignment.project.default_branch, "--single-branch", &assignment.checkout.repo_url, path.to_str().context("non-utf8 review workspace path")?],
        git_auth,
    ).await?;
    let review_ref = format!("refs/heads/{}", assignment.checkout.review_ref);
    command_ok_with_auth(path, "git", &["fetch", "origin", &review_ref], git_auth).await?;
    let fetched = git_output(path, &["rev-parse", "FETCH_HEAD"]).await?;
    if fetched != assignment.checkout.commit_sha {
        bail!("review ref moved: expected {}, fetched {}", assignment.checkout.commit_sha, fetched);
    }
    command_ok(path, "git", &["checkout", "--detach", &assignment.checkout.commit_sha]).await?;
    install_workspace_excludes(path).await?;
    command_ok(path, "git", &["remote", "set-url", "--push", "origin", "disabled://lazyteam-reviewer"]).await?;
    Ok(())
}

fn build_review_prompt(initial_prompt: &str, assignment: &ReviewAssignment) -> anyhow::Result<String> {
    let criteria = assignment.task.acceptance_criteria.iter().map(|v| format!("- {v}")).collect::<Vec<_>>().join("\n");
    let result = serde_json::to_string_pretty(&assignment.execution.result).context("serialize implementation evidence")?;
    Ok(format!(
        "{initial_prompt}\n\nProject-specific review policy:\n{}\n\nPinned review target:\nRepository: {}\nDefault branch: {}\nReview ref: {}\nCandidate commit: {}\nBase commit: {}\nImplementation worker: {} ({}/{})\n\nTask contract:\nTitle: {}\n\nDescription:\n{}\n\nExpected outcome:\n{}\n\nAcceptance criteria:\n{}\n\nImplementation evidence:\n{}\n\nReview the checkout at the exact candidate commit. You may inspect files and run validation, but do not edit, commit, push, or merge. Return only the required JSON verdict object.\n",
        assignment.project.reviewer.initial_prompt,
        assignment.checkout.repo_url,
        assignment.checkout.default_branch,
        assignment.checkout.review_ref,
        assignment.checkout.commit_sha,
        assignment.checkout.base_sha.as_deref().unwrap_or("unknown"),
        assignment.implementation_worker.name,
        assignment.implementation_worker.os,
        assignment.implementation_worker.arch,
        assignment.task.title,
        assignment.task.description,
        assignment.task.expected_outcome,
        criteria,
        result,
    ))
}

fn parse_review_verdict(raw: &str) -> anyhow::Result<ReviewVerdict> {
    let trimmed = raw.trim();
    if let Ok(verdict) = serde_json::from_str::<ReviewVerdict>(trimmed) {
        if verdict.reason.trim().is_empty() { bail!("review verdict reason is empty"); }
        return Ok(verdict);
    }
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if start <= end {
            let candidate = &trimmed[start..=end];
            if let Ok(verdict) = serde_json::from_str::<ReviewVerdict>(candidate) {
                if verdict.reason.trim().is_empty() { bail!("review verdict reason is empty"); }
                return Ok(verdict);
            }
        }
    }
    bail!("reviewer did not return the required JSON verdict")
}

async fn execute_assignment(
    client: &Client,
    server: &str,
    worker_credential: &str,
    workspace_root: &Path,
    state_dir: &Path,
    runtime: Arc<dyn AgentRuntime>,
    initial_prompt: &str,
    assignment: Assignment,
) -> anyhow::Result<()> {
    let execution_id = assignment.execution.id;
    let renew_client = client.clone();
    let renew_server = server.to_string();
    let renew_credential = worker_credential.to_string();
    let renew = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            match worker_auth(
                renew_client.post(format!("{renew_server}/api/executions/{execution_id}/renew")),
                &renew_credential,
            ).send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => warn!(status = %response.status(), %execution_id, "lease renew rejected"),
                Err(error) => warn!(%error, %execution_id, "lease renew failed"),
            }
        }
    });

    let outcome = match GitAuthContext::prepare(state_dir, assignment.task.id, assignment.execution.id, &assignment.git_credential).await {
        Ok(auth) => {
            let result = run_task(workspace_root, runtime, initial_prompt, &assignment, &auth).await;
            auth.cleanup().await;
            result
        }
        Err(error) => Err(error),
    };
    renew.abort();

    let result = match outcome {
        Ok(result) => result,
        Err(error) => ExecutionResult {
            status: "failed".into(),
            summary: error.to_string(),
            commit_sha: None,
            base_sha: None,
            patch: None,
            patch_truncated: false,
            workspace_clean: None,
            review_ref: None,
            changed_files: vec![],
            validation: vec![],
            warnings: vec!["worker execution failed before successful completion".into()],
            artifacts: vec![],
        },
    };
    let response = worker_auth(
        client.post(format!("{server}/api/executions/{}/finish", assignment.execution.id)),
        worker_credential,
    )
        .json(&json!({"result": result}))
        .send().await?;
    ensure_success(response).await?;
    Ok(())
}

async fn run_task(workspace_root: &Path, runtime: Arc<dyn AgentRuntime>, initial_prompt: &str, assignment: &Assignment, git_auth: &GitAuthContext) -> anyhow::Result<ExecutionResult> {
    let workspace = workspace_root
        .join(&assignment.project.slug)
        .join(assignment.task.id.to_string());
    let base_sha = prepare_workspace(&workspace, assignment, git_auth).await?;
    let prompt = build_prompt(initial_prompt, assignment);
    let session_name = assignment.task.id.to_string();
    let agent = runtime.run(&workspace, &prompt, &session_name).await?;
    auto_commit(&workspace, assignment).await?;
    let head_sha = git_output(&workspace, &["rev-parse", "HEAD"]).await?;
    if head_sha == base_sha {
        bail!("agent completed without producing any tracked change");
    }
    let commit_sha = Some(head_sha);
    let review_ref = task_branch(assignment);
    command_ok_with_auth(&workspace, "git", &["push", "origin", &format!("HEAD:refs/heads/{review_ref}")], git_auth).await?;
    let changed_files = git_output(&workspace, &["diff", "--name-only", &base_sha])
        .await.unwrap_or_default().lines().filter(|s| !s.is_empty()).map(str::to_string).collect();
    let raw_patch = git_output(&workspace, &["diff", "--no-ext-diff", "--unified=40", &base_sha]).await.unwrap_or_default();
    let (patch, patch_truncated) = bounded_review_patch(raw_patch, MAX_REVIEW_PATCH_BYTES);
    let workspace_clean = git_output(&workspace, &["status", "--porcelain"]).await.map(|v| v.is_empty()).ok();
    Ok(ExecutionResult {
        status: "completed".into(),
        summary: agent.summary,
        commit_sha,
        base_sha: Some(base_sha),
        patch: if patch.is_empty() { None } else { Some(patch) },
        patch_truncated,
        workspace_clean,
        review_ref: Some(review_ref),
        changed_files,
        validation: vec![],
        warnings: vec![],
        artifacts: vec![],
    })
}

fn build_prompt(initial_prompt: &str, assignment: &Assignment) -> String {
    let feedback = assignment.task.review_feedback.trim();
    if assignment.execution.attempt > 1 && !feedback.is_empty() {
        return format!(
            "{}\n\nContinue the existing task session and repository workspace. Do not restart from a reconstructed task contract; rely on the conversation and working tree you already have. The task branch may already be published: preserve its existing commit history. Never amend, rebase, reset, rewrite, or force-push previously published task commits; apply review corrections as new commits on top.\n\nReview feedback from the previous attempt:\n{}\n",
            initial_prompt,
            feedback,
        );
    }

    let criteria = assignment.task.acceptance_criteria.iter().map(|v| format!("- {v}")).collect::<Vec<_>>().join("\n");
    format!(
        "{}\n\nTask contract:\nProject: {}\nRepository: {}\nBase branch: {}\nTask: {}\n\nDescription:\n{}\n\nExpected outcome:\n{}\n\nAcceptance criteria:\n{}\n",
        initial_prompt,
        assignment.project.name,
        assignment.project.repo_url,
        assignment.project.default_branch,
        assignment.task.title,
        assignment.task.description,
        assignment.task.expected_outcome,
        criteria,
    )
}

fn bounded_review_patch(mut patch: String, max_bytes: usize) -> (String, bool) {
    if patch.len() <= max_bytes { return (patch, false); }
    let mut end = max_bytes.min(patch.len());
    while !patch.is_char_boundary(end) { end -= 1; }
    patch.truncate(end);
    patch.push_str("\n\n[LazyTeam review patch truncated]\n");
    (patch, true)
}

fn task_branch(assignment: &Assignment) -> String {
    format!("lazyteam/task-{}", assignment.task.id.simple())
}

async fn prepare_workspace(path: &Path, assignment: &Assignment, git_auth: &GitAuthContext) -> anyhow::Result<String> {
    let branch = task_branch(assignment);
    if path.exists() {
        let inside = git_output(path, &["rev-parse", "--is-inside-work-tree"]).await?;
        if inside != "true" { bail!("existing task workspace is not a git repository"); }
        install_workspace_excludes(path).await?;
        command_ok(path, "git", &["checkout", &branch]).await?;
        return git_output(path, &["rev-parse", &format!("refs/heads/{}", assignment.project.default_branch)]).await;
    }
    if let Some(parent) = path.parent() { tokio::fs::create_dir_all(parent).await?; }
    command_ok_with_auth(
        Path::new("."),
        "git",
        &["clone", "--branch", &assignment.project.default_branch, "--single-branch", &assignment.project.repo_url, path.to_str().context("non-utf8 workspace path")?],
        git_auth,
    ).await?;
    let base = git_output(path, &["rev-parse", "HEAD"]).await?;
    install_workspace_excludes(path).await?;
    command_ok(path, "git", &["checkout", "-b", &branch]).await?;
    Ok(base)
}

async fn install_workspace_excludes(path: &Path) -> anyhow::Result<()> {
    let git_dir = git_output(path, &["rev-parse", "--git-dir"]).await?;
    let git_dir = if Path::new(&git_dir).is_absolute() { PathBuf::from(git_dir) } else { path.join(git_dir) };
    let exclude = git_dir.join("info").join("exclude");
    if let Some(parent) = exclude.parent() { tokio::fs::create_dir_all(parent).await?; }
    let mut current = tokio::fs::read_to_string(&exclude).await.unwrap_or_default();
    const MARKER: &str = "# LazyTeam local generated artifacts";
    if !current.contains(MARKER) {
        if !current.is_empty() && !current.ends_with('\n') { current.push('\n'); }
        current.push_str(MARKER);
        current.push_str("\ntarget/\nnode_modules/\n__pycache__/\n.pytest_cache/\n.venv/\n*.pyc\n");
        tokio::fs::write(exclude, current).await?;
    }
    Ok(())
}

async fn auto_commit(path: &Path, assignment: &Assignment) -> anyhow::Result<()> {
    command_ok(path, "git", &["reset"]).await?;
    command_ok(path, "git", &["add", "-A"]).await?;
    let status = Command::new("git").args(["diff", "--cached", "--quiet"]).current_dir(path).status().await?;
    if status.success() { return Ok(()); }
    command_ok(path, "git", &[
        "-c", "user.name=LazyTeam Worker",
        "-c", "user.email=lazyteam@local",
        "commit", "-m", &format!("lazyteam: {}", assignment.task.title),
    ]).await
}

async fn git_output(path: &Path, args: &[&str]) -> anyhow::Result<String> {
    let output = Command::new("git").args(args).current_dir(path).output().await?;
    if !output.status.success() { bail!("git {:?} failed: {}", args, String::from_utf8_lossy(&output.stderr)); }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

async fn command_ok(path: &Path, program: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = Command::new(program).args(args).current_dir(path).output().await?;
    if !output.status.success() { bail!("{program} {:?} failed: {}", args, String::from_utf8_lossy(&output.stderr)); }
    Ok(())
}

async fn command_ok_with_auth(path: &Path, program: &str, args: &[&str], git_auth: &GitAuthContext) -> anyhow::Result<()> {
    let mut command = Command::new(program);
    command.args(args).current_dir(path);
    git_auth.apply(&mut command);
    let output = command.output().await?;
    if !output.status.success() { bail!("{program} {:?} failed: {}", args, String::from_utf8_lossy(&output.stderr)); }
    Ok(())
}

async fn ensure_success(response: reqwest::Response) -> anyhow::Result<reqwest::Response> {
    if response.status().is_success() { return Ok(response); }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    bail!("server returned {status}: {body}")
}

async fn load_or_create_worker_id(dir: &Path) -> anyhow::Result<Uuid> {
    let path = dir.join("worker-id");
    if let Ok(raw) = tokio::fs::read_to_string(&path).await {
        return Ok(Uuid::parse_str(raw.trim()).context("invalid persisted worker id")?);
    }
    let id = Uuid::new_v4();
    tokio::fs::write(path, id.to_string()).await?;
    Ok(id)
}

async fn load_server_url(dir: &Path) -> anyhow::Result<Option<String>> {
    let path = dir.join("server-url");
    match tokio::fs::read_to_string(path).await {
        Ok(raw) => Ok(Some(normalize_server(raw.trim())?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn persist_server_url(dir: &Path, server: &str) -> anyhow::Result<()> {
    tokio::fs::write(dir.join("server-url"), normalize_server(server)?).await?;
    Ok(())
}

async fn load_worker_credential(dir: &Path) -> anyhow::Result<Option<String>> {
    let path = dir.join("worker-credential");
    match tokio::fs::read_to_string(path).await {
        Ok(raw) => {
            let credential = raw.trim().to_string();
            if credential.is_empty() { Ok(None) } else { Ok(Some(credential)) }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn persist_worker_credential(dir: &Path, credential: &str) -> anyhow::Result<()> {
    let path = dir.join("worker-credential");
    tokio::fs::write(&path, credential).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_code_supplies_remote_server_endpoint() {
        let payload = URL_SAFE_NO_PAD.encode(br#"{"server":"https://lazyteam.example.test"}"#);
        let code = format!("ltj1.{payload}.signature");
        assert_eq!(parse_join_code_server(&code).unwrap(), "https://lazyteam.example.test");
        assert!(parse_join_code_server("bad.code").is_err());
    }

    #[test]
    fn server_url_rejects_paths_and_credentials() {
        assert!(normalize_server("https://lazyteam.example.test").is_ok());
        assert!(normalize_server("https://lazyteam.example.test/mcp").is_err());
        assert!(normalize_server("https://user@lazyteam.example.test").is_err());
    }

    #[test]
    fn relative_worker_paths_are_anchored_at_worker_startup() {
        let startup = Path::new("/srv/lazyteam");
        assert_eq!(
            resolve_worker_path(startup, Path::new(".lazyteam-worker")),
            PathBuf::from("/srv/lazyteam/.lazyteam-worker")
        );
        assert_eq!(
            resolve_worker_path(startup, Path::new("lazyteam-workspaces")),
            PathBuf::from("/srv/lazyteam/lazyteam-workspaces")
        );
        assert_eq!(
            resolve_worker_path(startup, Path::new("/var/lib/lazyteam")),
            PathBuf::from("/var/lib/lazyteam")
        );
    }

    #[test]
    fn reviewer_verdict_parser_accepts_json_and_rejects_missing_reason() {
        let verdict = parse_review_verdict(r#"{"verdict":"approve","reason":"verified","validation":["cargo test"]}"#).unwrap();
        assert_eq!(verdict.verdict, lazyteam_core::ReviewVerdictKind::Approve);
        assert_eq!(verdict.reason, "verified");
        let wrapped = parse_review_verdict("Result:\n{\"verdict\":\"retry\",\"reason\":\"missing test\",\"validation\":[]}").unwrap();
        assert_eq!(wrapped.verdict, lazyteam_core::ReviewVerdictKind::Retry);
        assert!(parse_review_verdict(r#"{"verdict":"approve","reason":"","validation":[]}"#).is_err());
    }

    #[tokio::test]
    async fn https_git_auth_uses_environment_not_command_arguments() {
        let root = std::env::temp_dir().join(format!("lazyteam-git-auth-{}", Uuid::new_v4()));
        let credential = GitCredential::HttpsBasic {
            username: "alice".into(),
            secret: "example-value".into(),
        };
        let auth = GitAuthContext::prepare(&root, Uuid::new_v4(), Uuid::new_v4(), &credential).await.unwrap();
        assert!(auth.key_path.is_none());
        assert!(auth.env.iter().any(|(key, value)| key == "GIT_CONFIG_KEY_0" && value == "http.extraHeader"));
        let header = auth.env.iter().find(|(key, _)| key == "GIT_CONFIG_VALUE_0").unwrap().1.clone();
        assert!(header.starts_with("Authorization: Basic "));
        assert!(!header.contains("example-value"));
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ssh_git_auth_key_is_ephemeral_and_private() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("lazyteam-git-auth-{}", Uuid::new_v4()));
        let credential = GitCredential::SshKey {
            private_key: "test-private-key\n".into(),
        };
        let auth = GitAuthContext::prepare(&root, Uuid::new_v4(), Uuid::new_v4(), &credential).await.unwrap();
        let key_path = auth.key_path.clone().unwrap();
        assert_eq!(tokio::fs::read_to_string(&key_path).await.unwrap(), "test-private-key\n");
        assert_eq!(tokio::fs::metadata(&key_path).await.unwrap().permissions().mode() & 0o777, 0o600);
        auth.cleanup().await;
        assert!(!key_path.exists());
        let _ = tokio::fs::remove_dir_all(root).await;
    }
}
