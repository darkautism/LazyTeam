use std::{collections::{BTreeMap, BTreeSet}, path::{Path, PathBuf}, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use lazyteam_core::{AgentCapabilities, AgentConfig, AgentRole, Assignment, ExecutionResult, ReviewAssignment, ReviewVerdict, LEASE_CAPABILITY_HEADER};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::Deserialize;
use serde_json::json;
use tokio::{process::Command, task::JoinSet, time::{sleep, Instant}};
use tracing::{error, info, warn};
use uuid::Uuid;

mod runtime;
mod sandbox;
use runtime::{AgentRuntime, PiRuntime};
use sandbox::{AgentSandbox, prepare_agent_workspace, sync_agent_workspace};

const WORKER_CREDENTIAL_HEADER: &str = "x-lazyteam-worker-credential";
const MAX_REVIEW_PATCH_BYTES: usize = 256 * 1024;
const WORKER_PROTOCOL_VERSION: u32 = 6;
const AGENT_ROOTFS_BUILD_SCRIPT: &str = include_str!("../../../scripts/agent-rootfs-build.sh");
const AGENT_ROOTFS_SCHEMA: &str = "intuitive-git-v1";
const AGENT_GIT_BOUNDARY: &str = "LazyTeam sandbox Git: this workspace includes a task-scoped synthetic Git repository for familiar inspection. You may freely use read-oriented commands such as `git status`, `git diff`, `git diff lazyteam-base..HEAD`, `git log`, `git show`, and `git grep`. The synthetic repository contains only task snapshots, has no remotes or credentials, disables hooks and external Git transport, and its `.git` metadata is mounted read-only. Its local commit IDs are sandbox snapshots rather than upstream commit IDs. Edit normal working-tree files; LazyTeam's trusted worker layer ignores sandbox Git metadata and owns the real commit, push, and publication flow.";

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
    /// Verify the embedded Linux agent sandbox and exit without contacting the server.
    #[arg(long)]
    sandbox_diagnose: bool,
    /// Probe Pi providers/models through the real Ubuntu container + inner sandbox and exit.
    #[arg(long)]
    capabilities_diagnose: bool,
}

#[derive(Debug, Deserialize)]
struct WorkerJoinPayload {
    server: String,
}

#[derive(Debug, Deserialize)]
struct WorkerRuntimeConfig {
    role: AgentRole,
    agent: AgentConfig,
    #[serde(default = "default_runtime_slots")]
    slots: u32,
    #[serde(default)]
    managed_capabilities: BTreeSet<String>,
    #[serde(default)]
    installed_capabilities: BTreeSet<String>,
    #[serde(default)]
    paused: bool,
}

fn default_runtime_slots() -> u32 { 1 }

#[derive(Deserialize)]
struct AgentAuthDelivery {
    id: Uuid,
    provider: String,
    api_key: String,
}

#[derive(Debug, Deserialize)]
struct WorkerCleanup {
    task_id: Uuid,
    project_slug: String,
}

struct GitAuthContext {
    env: Vec<(String, String)>,
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl AbortOnDrop {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self { Self(handle) }
    fn abort(&self) { self.0.abort(); }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) { self.0.abort(); }
}

impl GitAuthContext {
    fn broker(worker_credential: &str, lease_capability: &str) -> Self {
        Self {
            env: vec![
                ("GIT_TERMINAL_PROMPT".into(), "0".into()),
                ("GIT_CONFIG_COUNT".into(), "2".into()),
                ("GIT_CONFIG_KEY_0".into(), "http.extraHeader".into()),
                ("GIT_CONFIG_VALUE_0".into(), format!("{WORKER_CREDENTIAL_HEADER}: {worker_credential}")),
                ("GIT_CONFIG_KEY_1".into(), "http.extraHeader".into()),
                ("GIT_CONFIG_VALUE_1".into(), format!("{LEASE_CAPABILITY_HEADER}: {lease_capability}")),
            ],
        }
    }

    fn apply(&self, command: &mut Command) {
        for (key, value) in &self.env {
            command.env(key, value);
        }
    }
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

fn main() -> anyhow::Result<()> {
    // Container workers enter their daemon user namespace before Tokio creates threads.
    // The daemon is uid 0 only inside that namespace; uid 0 maps to the configured
    // unprivileged container identity (normally 10001) outside it.
    sandbox::maybe_enter_daemon_user_namespace()?;

    // The sandbox self-exec path must run before Tokio creates worker threads.  Linux user
    // namespaces reject unshare(CLONE_NEWUSER) from a multithreaded process on some kernels.
    if let Some(result) = sandbox::maybe_handle_entrypoint() {
        return result;
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    eprintln!("LazyTeam worker starting version={} git_sha={}", env!("CARGO_PKG_VERSION"), lazyteam_core::BUILD_GIT_SHA);
    let mut args = Args::parse();
    let startup_dir = std::env::current_dir().context("read worker startup directory")?;
    args.state_dir = resolve_worker_path(&startup_dir, &args.state_dir);
    args.workspace_dir = resolve_worker_path(&startup_dir, &args.workspace_dir);
    tokio::fs::create_dir_all(&args.state_dir).await?;
    tokio::fs::create_dir_all(&args.workspace_dir).await?;
    let mut local_installed_capabilities = load_local_installed_capabilities(&args.state_dir).await?;
    let mut agent_rootfs = build_agent_rootfs(&args.state_dir, &local_installed_capabilities).await?;
    let mut agent_sandbox = AgentSandbox::prepare(&args.state_dir, &args.pi_bin, Some(&agent_rootfs)).await?;
    info!(rootfs = %agent_rootfs.display(), schema = AGENT_ROOTFS_SCHEMA, "agent Ubuntu rootfs + intuitive tooling + sandboxed Git ready");
    if args.sandbox_diagnose {
        println!("LazyTeam agent sandbox {}", agent_sandbox.diagnostic_summary());
        return Ok(());
    }
    if args.capabilities_diagnose {
        let runtime = PiRuntime {
            binary: args.pi_bin.clone(),
            provider: None,
            model: None,
            session_dir: None,
            sandbox: agent_sandbox.clone(),
        };
        let capabilities = runtime.capabilities().await;
        println!("{}", serde_json::to_string_pretty(&capabilities)?);
        if let Some(error) = capabilities.probe_error {
            bail!("Pi capability diagnostic failed: {error}");
        }
        return Ok(());
    }
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
    let mut probe_runtime = PiRuntime { binary: pi_bin.clone(), provider: None, model: None, session_dir: None, sandbox: agent_sandbox.clone() };
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
    match reconcile_managed_capabilities(
        &client, &server, &worker_credential, worker_id, &args.state_dir, &args.pi_bin,
        &mut runtime_config, &mut local_installed_capabilities, &mut agent_rootfs,
        &mut agent_sandbox, &mut probe_runtime,
    ).await {
        Ok(()) => {
            agent_capabilities = probe_runtime.capabilities().await;
            if let Err(error) = report_capabilities(&client, &server, &worker_credential, worker_id, &agent_capabilities).await {
                warn!(%error, "agent capability refresh after rootfs reconciliation failed");
            }
        }
        Err(error) => {
            warn!(%error, "initial managed capability reconciliation failed; worker remains pending and will retry");
            let tail = capability_build_log_tail(&args.state_dir).await;
            let _ = report_capability_build_error(
                &client, &server, &worker_credential, worker_id, &local_installed_capabilities, &error.to_string(), &tail,
            ).await;
        }
    }
    let mut next_capability_probe = Instant::now() + Duration::from_secs(60);
    let mut active_jobs = JoinSet::<anyhow::Result<()>>::new();

    loop {
        while let Some(result) = active_jobs.try_join_next() {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => error!(%error, "slot execution failed"),
                Err(error) => error!(%error, "slot task panicked or was cancelled"),
            }
        }
        if let Err(error) = heartbeat(&client, &server, &worker_credential, worker_id).await {
            warn!(%error, "heartbeat failed");
            sleep(Duration::from_secs(5)).await;
            continue;
        }
        if let Err(error) = process_cleanup(&client, &server, &worker_credential, worker_id, &args.workspace_dir, &args.state_dir).await {
            warn!(%error, "post-merge cleanup poll failed");
        }
        match poll_agent_auth(&client, &server, &worker_credential, worker_id).await {
            Ok(Some(update)) => {
                let provider = update.provider.clone();
                if let Err(error) = agent_sandbox.store_pi_api_key(&update.provider, &update.api_key).await {
                    error!(%error, provider = %provider, credential_update = %update.id, "failed to store provider API key");
                } else {
                    info!(provider = %provider, credential_update = %update.id, "provider API key stored in isolated Pi config");
                    agent_capabilities = probe_runtime.capabilities().await;
                    if let Err(error) = report_capabilities(&client, &server, &worker_credential, worker_id, &agent_capabilities).await {
                        warn!(%error, "agent capability refresh after provider credential update failed");
                    }
                    next_capability_probe = Instant::now() + Duration::from_secs(60);
                }
            }
            Ok(None) => {}
            Err(error) => warn!(%error, "provider credential poll failed"),
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
        if runtime_config.paused {
            if !active_jobs.is_empty() {
                info!(active = active_jobs.len(), "worker stopped by control plane; cancelling active slots");
                active_jobs.abort_all();
            }
            sleep(Duration::from_secs(1)).await;
            continue;
        }
        if let Err(error) = reconcile_managed_capabilities(
            &client, &server, &worker_credential, worker_id, &args.state_dir, &args.pi_bin,
            &mut runtime_config, &mut local_installed_capabilities, &mut agent_rootfs,
            &mut agent_sandbox, &mut probe_runtime,
        ).await {
            error!(%error, "managed capability provisioning failed");
            let tail = capability_build_log_tail(&args.state_dir).await;
            let _ = report_capability_build_error(&client, &server, &worker_credential, worker_id, &local_installed_capabilities, &error.to_string(), &tail).await;
            sleep(Duration::from_secs(5)).await;
            continue;
        }
        if agent_capabilities.models.is_empty() {
            tracing::debug!(active = active_jobs.len(), "worker has no usable Pi models yet; not claiming new work");
            sleep(Duration::from_secs(if active_jobs.is_empty() { 3 } else { 1 })).await;
            continue;
        }

        let max_slots = runtime_config.slots.max(1) as usize;
        while active_jobs.len() < max_slots {
            let claimed = match runtime_config.role {
                AgentRole::Worker => match claim(&client, &server, &worker_credential, worker_id).await {
                    Ok(Some(assignment)) => {
                        let task_id = assignment.task.id;
                        let execution_id = assignment.execution.id;
                        let project_slug = assignment.project.slug.clone();
                        info!(task = %task_id, execution = %execution_id, project = %project_slug, active = active_jobs.len() + 1, slots = max_slots, "claimed implementation slot");
                        let session_dir = args.state_dir.join("sessions").join(task_id.to_string());
                        let runtime = match runtime_for_config(
                            &runtime_config.agent,
                            &pi_bin,
                            legacy_provider.as_deref(),
                            legacy_model.as_deref(),
                            session_dir,
                            agent_sandbox.clone(),
                        ) {
                            Ok(runtime) => runtime,
                            Err(error) => {
                                error!(%error, %execution_id, "invalid agent configuration for claimed slot");
                                break;
                            }
                        };
                        info!(role = "worker", agent = runtime.kind(), provider = ?runtime_config.agent.provider, model = ?runtime_config.agent.model, %execution_id, "starting isolated slot runtime");
                        let slot_client = client.clone();
                        let slot_server = server.clone();
                        let slot_credential = worker_credential.clone();
                        let slot_workspace_root = args.workspace_dir.clone();
                        let slot_sandbox = agent_sandbox.clone();
                        let slot_prompt = runtime_config.agent.initial_prompt.clone();
                        active_jobs.spawn(async move {
                            execute_assignment(
                                &slot_client,
                                &slot_server,
                                &slot_credential,
                                &slot_workspace_root,
                                &slot_sandbox,
                                runtime,
                                &slot_prompt,
                                assignment,
                            ).await.with_context(|| format!("execution {execution_id} task {task_id} project {project_slug}"))
                        });
                        true
                    }
                    Ok(None) => false,
                    Err(error) => {
                        warn!(%error, "implementation claim failed");
                        false
                    }
                },
                AgentRole::Reviewer => match claim_review(&client, &server, &worker_credential, worker_id).await {
                    Ok(Some(assignment)) => {
                        let task_id = assignment.task.id;
                        let review_id = assignment.review.id;
                        let project_slug = assignment.project.slug.clone();
                        info!(task = %task_id, review = %review_id, project = %project_slug, active = active_jobs.len() + 1, slots = max_slots, "claimed review slot");
                        let session_dir = args.state_dir.join("review-sessions").join(review_id.to_string());
                        let runtime = match runtime_for_config(
                            &runtime_config.agent,
                            &pi_bin,
                            legacy_provider.as_deref(),
                            legacy_model.as_deref(),
                            session_dir.clone(),
                            agent_sandbox.clone(),
                        ) {
                            Ok(runtime) => runtime,
                            Err(error) => {
                                error!(%error, %review_id, "invalid reviewer agent configuration for claimed slot");
                                break;
                            }
                        };
                        info!(role = "reviewer", agent = runtime.kind(), provider = ?runtime_config.agent.provider, model = ?runtime_config.agent.model, %review_id, "starting isolated slot runtime");
                        let slot_client = client.clone();
                        let slot_server = server.clone();
                        let slot_credential = worker_credential.clone();
                        let slot_workspace_root = args.workspace_dir.clone();
                        let slot_sandbox = agent_sandbox.clone();
                        let slot_prompt = runtime_config.agent.initial_prompt.clone();
                        active_jobs.spawn(async move {
                            let result = execute_review_assignment(
                                &slot_client,
                                &slot_server,
                                &slot_credential,
                                &slot_workspace_root,
                                &slot_sandbox,
                                runtime,
                                &slot_prompt,
                                assignment,
                            ).await.with_context(|| format!("review {review_id} task {task_id} project {project_slug}"));
                            if session_dir.exists() { let _ = tokio::fs::remove_dir_all(session_dir).await; }
                            result
                        });
                        true
                    }
                    Ok(None) => false,
                    Err(error) => {
                        warn!(%error, "review claim failed");
                        false
                    }
                },
            };
            if !claimed { break; }
        }

        sleep(Duration::from_secs(if active_jobs.is_empty() { 3 } else { 1 })).await;
    }
}

fn enrollment_auth(request: RequestBuilder, token: &str) -> RequestBuilder {
    request.bearer_auth(token)
}

fn worker_auth(request: RequestBuilder, credential: &str) -> RequestBuilder {
    request.header(WORKER_CREDENTIAL_HEADER, credential)
}

fn lease_auth(request: RequestBuilder, worker_credential: &str, lease_capability: &str) -> RequestBuilder {
    worker_auth(request, worker_credential).header(LEASE_CAPABILITY_HEADER, lease_capability)
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
        "protocol_version": WORKER_PROTOCOL_VERSION,
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
        .header("x-lazyteam-worker-protocol-version", WORKER_PROTOCOL_VERSION.to_string())
        .header("x-lazyteam-worker-version", env!("CARGO_PKG_VERSION"))
        .json(capabilities).send().await?;
    ensure_success(response).await?;
    Ok(())
}

async fn load_local_installed_capabilities(state_dir: &Path) -> anyhow::Result<BTreeSet<String>> {
    let path = state_dir.join("agent-rootfs").join("current").join(".lazyteam-capabilities");
    match tokio::fs::read_to_string(path).await {
        Ok(raw) => Ok(raw.lines().map(str::trim).filter(|line| !line.is_empty()).map(str::to_string).collect()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeSet::new()),
        Err(error) => Err(error).context("read local agent rootfs capability manifest"),
    }
}

fn capability_build_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("capability-build.log")
}

async fn capability_build_log_tail(state_dir: &Path) -> String {
    const MAX_CHARS: usize = 16_000;
    let raw = tokio::fs::read_to_string(capability_build_log_path(state_dir)).await.unwrap_or_default();
    let count = raw.chars().count();
    if count <= MAX_CHARS { raw } else { raw.chars().skip(count - MAX_CHARS).collect() }
}

async fn build_agent_rootfs(state_dir: &Path, capabilities: &BTreeSet<String>) -> anyhow::Result<PathBuf> {
    let script_path = state_dir.join("agent-rootfs-build.sh");
    let rewrite = match tokio::fs::read_to_string(&script_path).await {
        Ok(existing) => existing != AGENT_ROOTFS_BUILD_SCRIPT,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => return Err(error).context("read agent rootfs builder"),
    };
    if rewrite {
        tokio::fs::write(&script_path, AGENT_ROOTFS_BUILD_SCRIPT).await.context("write agent rootfs builder")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tokio::fs::set_permissions(&script_path, std::fs::Permissions::from_mode(0o700)).await?;
        }
    }

    let log_path = capability_build_log_path(state_dir);
    tokio::fs::write(&log_path, format!("LazyTeam managed-tool build target: {:?}\n", capabilities)).await
        .context("initialize capability build log")?;
    let stdout_log = std::fs::OpenOptions::new().create(true).append(true).open(&log_path)
        .context("open capability build log stdout")?;
    let stderr_log = stdout_log.try_clone().context("clone capability build log")?;

    let mut command = Command::new("/bin/bash");
    command.env("LAZYTEAM_AGENT_ROOTFS_SCHEMA", AGENT_ROOTFS_SCHEMA);
    command.arg(&script_path).arg(state_dir);
    for capability in capabilities {
        command.arg(capability);
    }
    command.stdin(std::process::Stdio::null());
    command.stdout(std::process::Stdio::from(stdout_log));
    command.stderr(std::process::Stdio::from(stderr_log));
    let status = command.status().await.context("run fixed agent rootfs builder")?;
    if !status.success() {
        let tail = capability_build_log_tail(state_dir).await;
        bail!("agent rootfs build failed; provisioning log tail:\n{tail}");
    }
    let rootfs = state_dir.join("agent-rootfs").join("current");
    tokio::fs::canonicalize(&rootfs).await
        .with_context(|| format!("canonicalize built agent rootfs {}", rootfs.display()))
}

async fn build_agent_rootfs_with_heartbeat(
    client: &Client,
    server: &str,
    credential: &str,
    worker_id: Uuid,
    state_dir: &Path,
    capabilities: &BTreeSet<String>,
    installed_before: &BTreeSet<String>,
) -> anyhow::Result<PathBuf> {
    let build = build_agent_rootfs(state_dir, capabilities);
    tokio::pin!(build);
    let mut heartbeat_tick = tokio::time::interval(Duration::from_secs(10));
    let mut log_tick = tokio::time::interval(Duration::from_secs(2));
    loop {
        tokio::select! {
            result = &mut build => return result,
            _ = heartbeat_tick.tick() => {
                if let Err(error) = heartbeat(client, server, credential, worker_id).await {
                    warn!(%error, "heartbeat failed while rebuilding agent rootfs");
                }
            }
            _ = log_tick.tick() => {
                let tail = capability_build_log_tail(state_dir).await;
                let _ = report_capability_build(client, server, credential, worker_id, installed_before, "building", &tail).await;
            }
        }
    }
}

async fn report_capability_build(
    client: &Client,
    server: &str,
    credential: &str,
    worker_id: Uuid,
    installed: &BTreeSet<String>,
    phase: &str,
    log_tail: &str,
) -> anyhow::Result<()> {
    let response = worker_auth(client.post(format!("{server}/api/workers/{worker_id}/capability-build")), credential)
        .json(&json!({"installed_capabilities": installed, "phase": phase, "log_tail": log_tail})).send().await?;
    ensure_success(response).await?;
    Ok(())
}

async fn report_capability_build_error(
    client: &Client,
    server: &str,
    credential: &str,
    worker_id: Uuid,
    installed: &BTreeSet<String>,
    error: &str,
    log_tail: &str,
) -> anyhow::Result<()> {
    let response = worker_auth(client.post(format!("{server}/api/workers/{worker_id}/capability-build")), credential)
        .json(&json!({"installed_capabilities": installed, "error": error, "phase": "failed", "log_tail": log_tail})).send().await?;
    ensure_success(response).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn reconcile_managed_capabilities(
    client: &Client,
    server: &str,
    credential: &str,
    worker_id: Uuid,
    state_dir: &Path,
    pi_bin: &str,
    runtime_config: &mut WorkerRuntimeConfig,
    local_installed: &mut BTreeSet<String>,
    agent_rootfs: &mut PathBuf,
    agent_sandbox: &mut AgentSandbox,
    probe_runtime: &mut PiRuntime,
) -> anyhow::Result<()> {
    let mut target = local_installed.clone();
    target.extend(runtime_config.installed_capabilities.iter().cloned());
    target.extend(runtime_config.managed_capabilities.iter().cloned());

    if target != *local_installed {
        info!(?target, "rebuilding agent rootfs for added managed capabilities");
        let rootfs = build_agent_rootfs_with_heartbeat(client, server, credential, worker_id, state_dir, &target, local_installed).await?;
        let tail = capability_build_log_tail(state_dir).await;
        let _ = report_capability_build(client, server, credential, worker_id, local_installed, "activating", &tail).await;
        let sandbox = AgentSandbox::prepare(state_dir, pi_bin, Some(&rootfs)).await?;
        *agent_rootfs = rootfs;
        *local_installed = target;
        *agent_sandbox = sandbox.clone();
        *probe_runtime = PiRuntime {
            binary: pi_bin.to_string(),
            provider: None,
            model: None,
            session_dir: None,
            sandbox,
        };
        info!(rootfs = %agent_rootfs.display(), schema = AGENT_ROOTFS_SCHEMA, ?local_installed, "agent rootfs rebuild activated");
    }

    if runtime_config.installed_capabilities != *local_installed
        || !runtime_config.managed_capabilities.is_subset(local_installed)
    {
        let tail = capability_build_log_tail(state_dir).await;
        report_capability_build(client, server, credential, worker_id, local_installed, "ready", &tail).await?;
        runtime_config.installed_capabilities = local_installed.clone();
    }
    Ok(())
}

async fn fetch_runtime_config(client: &Client, server: &str, credential: &str, worker_id: Uuid) -> anyhow::Result<WorkerRuntimeConfig> {
    let response = worker_auth(client.get(format!("{server}/api/workers/{worker_id}/config")), credential).send().await?;
    Ok(ensure_success(response).await?.json().await?)
}

async fn poll_agent_auth(client: &Client, server: &str, credential: &str, worker_id: Uuid) -> anyhow::Result<Option<AgentAuthDelivery>> {
    let response = worker_auth(client.get(format!("{server}/api/workers/{worker_id}/agent-auth")), credential).send().await?;
    if response.status() == StatusCode::NO_CONTENT { return Ok(None); }
    Ok(Some(ensure_success(response).await?.json().await?))
}

fn runtime_for_config(agent: &AgentConfig, pi_bin: &str, legacy_provider: Option<&str>, legacy_model: Option<&str>, session_dir: PathBuf, sandbox: AgentSandbox) -> anyhow::Result<Arc<dyn AgentRuntime>> {
    if agent.agent_type != "pi" { bail!("unsupported agent type {}", agent.agent_type); }
    Ok(Arc::new(PiRuntime {
        binary: pi_bin.to_string(),
        provider: agent.provider.clone().or_else(|| legacy_provider.map(str::to_string)),
        model: agent.model.clone().or_else(|| legacy_model.map(str::to_string)),
        session_dir: Some(session_dir),
        sandbox,
    }))
}

async fn process_cleanup(client: &Client, server: &str, credential: &str, worker_id: Uuid, workspace_root: &Path, state_dir: &Path) -> anyhow::Result<()> {
    let response = worker_auth(client.get(format!("{server}/api/workers/{worker_id}/cleanup")), credential).send().await?;
    let items: Vec<WorkerCleanup> = ensure_success(response).await?.json().await?;
    for item in items {
        let workspace = workspace_root.join(&item.project_slug).join(item.task_id.to_string());
        if workspace.exists() {
            tokio::fs::remove_dir_all(&workspace).await?;
        }
        let session_dir = state_dir.join("sessions").join(item.task_id.to_string());
        if session_dir.exists() { tokio::fs::remove_dir_all(&session_dir).await?; }
        let agent_workspace = state_dir.join("agent-workspaces").join(item.task_id.to_string());
        if agent_workspace.exists() { tokio::fs::remove_dir_all(&agent_workspace).await?; }
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
    sandbox: &AgentSandbox,
    runtime: Arc<dyn AgentRuntime>,
    initial_prompt: &str,
    assignment: ReviewAssignment,
) -> anyhow::Result<()> {
    let review_id = assignment.review.id;
    let renew_client = client.clone();
    let renew_server = server.to_string();
    let renew_credential = worker_credential.to_string();
    let renew_capability = assignment.lease_capability.clone();
    let renew = AbortOnDrop::new(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            match lease_auth(
                renew_client.post(format!("{renew_server}/api/reviews/{review_id}/renew")),
                &renew_credential,
                &renew_capability,
            ).send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => warn!(status = %response.status(), %review_id, "review lease renew rejected"),
                Err(error) => warn!(%error, %review_id, "review lease renew failed"),
            }
        }
    }));

    let workspace = workspace_root
        .join(".reviews")
        .join(&assignment.project.slug)
        .join(review_id.to_string());
    let auth = GitAuthContext::broker(worker_credential, &assignment.lease_capability);
    let outcome = match prepare_review_workspace(&workspace, &assignment, &auth).await {
        Ok(()) => {
            let agent_workspace = sandbox.reviewer_workspace(review_id);
            prepare_agent_workspace(&workspace, &agent_workspace, assignment.checkout.base_sha.as_deref()).await?;
            let prompt = build_review_prompt(initial_prompt, &assignment)?;
            match runtime.run_review(&agent_workspace, &prompt, &review_id.to_string()).await {
                Ok(agent) => {
                    let dirty = git_status_external_worktree(&workspace, &agent_workspace)
                        .await
                        .unwrap_or_else(|error| format!("status-check-error: {error}"));
                    if !dirty.is_empty() {
                        Err(anyhow::anyhow!("reviewer modified the pinned source checkout; review discarded: {dirty}"))
                    } else {
                        parse_review_verdict(&agent.summary)
                    }
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    };
    renew.abort();

    let body = match outcome {
        Ok(verdict) => {
            info!(%review_id, verdict = ?verdict.verdict, "reviewer produced verdict; reporting review finish");
            json!({"status":"completed","verdict":verdict})
        }
        Err(error) => {
            warn!(%review_id, %error, "reviewer failed before verdict; reporting failed review");
            json!({"status":"failed","error":error.to_string()})
        }
    };
    let response = lease_auth(
        client.post(format!("{server}/api/reviews/{review_id}/finish")),
        worker_credential,
        &assignment.lease_capability,
    ).json(&body).send().await?;
    ensure_success(response).await?;
    info!(%review_id, "server accepted review finish");
    if workspace.exists() { let _ = tokio::fs::remove_dir_all(&workspace).await; }
    let agent_workspace = sandbox.reviewer_workspace(review_id);
    if agent_workspace.exists() { let _ = tokio::fs::remove_dir_all(&agent_workspace).await; }
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
    let result = reviewer_evidence_for_prompt(assignment.execution.result.as_ref())?;
    Ok(format!(
        "{initial_prompt}\n\n{AGENT_GIT_BOUNDARY}\n\nPinned local review snapshot:\nProject: {}\nDefault branch context: {}\nCandidate: `HEAD` / `lazyteam-task`\nBase: `lazyteam-base`\nImplementation worker: {} ({}/{})\n\nTask contract:\nTitle: {}\n\nDescription:\n{}\n\nExpected outcome:\n{}\n\nAcceptance criteria:\n{}\n\nImplementation report (untrusted):\n{}\n\nUse the local Git snapshot as the review source of truth. You may inspect files and run validation, but do not edit files. Return only the required JSON verdict object.\n",
        assignment.project.name,
        assignment.checkout.default_branch,
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

fn reviewer_evidence_for_prompt(result: Option<&ExecutionResult>) -> anyhow::Result<String> {
    let value = match result {
        Some(result) => json!({
            "status": result.status,
            "summary": result.summary,
            "workspace_clean": result.workspace_clean,
            "changed_files": result.changed_files,
            "validation": result.validation,
            "warnings": result.warnings,
            "artifacts": result.artifacts,
            "patch_truncated": result.patch_truncated,
        }),
        None => json!(null),
    };
    serde_json::to_string_pretty(&value).context("serialize reviewer implementation report")
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
    sandbox: &AgentSandbox,
    runtime: Arc<dyn AgentRuntime>,
    initial_prompt: &str,
    assignment: Assignment,
) -> anyhow::Result<()> {
    let execution_id = assignment.execution.id;
    let renew_client = client.clone();
    let renew_server = server.to_string();
    let renew_credential = worker_credential.to_string();
    let renew_capability = assignment.lease_capability.clone();
    let renew = AbortOnDrop::new(tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            match lease_auth(
                renew_client.post(format!("{renew_server}/api/executions/{execution_id}/renew")),
                &renew_credential,
                &renew_capability,
            ).send().await {
                Ok(response) if response.status().is_success() => {}
                Ok(response) => warn!(status = %response.status(), %execution_id, "lease renew rejected"),
                Err(error) => warn!(%error, %execution_id, "lease renew failed"),
            }
        }
    }));

    let auth = GitAuthContext::broker(worker_credential, &assignment.lease_capability);
    let outcome = run_task(workspace_root, sandbox, runtime, initial_prompt, &assignment, &auth).await;
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
    let response = lease_auth(
        client.post(format!("{server}/api/executions/{}/finish", assignment.execution.id)),
        worker_credential,
        &assignment.lease_capability,
    )
        .json(&json!({"result": result}))
        .send().await?;
    ensure_success(response).await?;
    Ok(())
}

async fn run_task(workspace_root: &Path, sandbox: &AgentSandbox, runtime: Arc<dyn AgentRuntime>, initial_prompt: &str, assignment: &Assignment, git_auth: &GitAuthContext) -> anyhow::Result<ExecutionResult> {
    let workspace = trusted_task_workspace(workspace_root, &assignment.project.slug, assignment.task.id);
    let base_sha = prepare_workspace(&workspace, assignment, git_auth).await?;
    let agent_workspace = sandbox.agent_workspace(assignment.task.id);
    prepare_agent_workspace(&workspace, &agent_workspace, Some(&base_sha)).await?;
    let prompt = build_prompt(initial_prompt, assignment);
    let session_name = assignment.task.id.to_string();
    let agent = runtime.run(&agent_workspace, &prompt, &session_name).await?;
    sync_agent_workspace(&agent_workspace, &workspace).await?;
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
            "{}\n\n{}\n\nContinue the existing task session and repository workspace. The sandbox Git view has been refreshed from the trusted task workspace; use `git status`, `git diff`, `git log`, or `git show` as useful to understand the current state, then apply the requested correction in normal working-tree files.\n\nReview feedback from the previous attempt:\n{}\n",
            initial_prompt,
            AGENT_GIT_BOUNDARY,
            feedback,
        );
    }

    let criteria = assignment.task.acceptance_criteria.iter().map(|v| format!("- {v}")).collect::<Vec<_>>().join("\n");
    format!(
        "{}\n\n{}\n\nTask contract:\nProject: {}\nBase branch context: {}\nLocal task branch: `lazyteam-task`\nLocal base snapshot: `lazyteam-base`\nTask: {}\n\nDescription:\n{}\n\nExpected outcome:\n{}\n\nAcceptance criteria:\n{}\n",
        initial_prompt,
        AGENT_GIT_BOUNDARY,
        assignment.project.name,
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

fn trusted_task_workspace(workspace_root: &Path, project_slug: &str, task_id: Uuid) -> PathBuf {
    workspace_root.join(project_slug).join(task_id.to_string())
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
        command_ok(path, "git", &["remote", "set-url", "origin", &assignment.project.repo_url]).await?;
        let default_ref = format!("refs/heads/{}", assignment.project.default_branch);
        command_ok_with_auth(path, "git", &["fetch", "origin", &default_ref], git_auth).await?;
        let base = git_output(path, &["rev-parse", "FETCH_HEAD"]).await?;
        command_ok(path, "git", &["update-ref", &default_ref, &base]).await?;
        command_ok(path, "git", &["checkout", &branch]).await?;
        let already_based = trusted_git_command().args(["merge-base", "--is-ancestor", &base, "HEAD"]).current_dir(path).status().await?;
        if !already_based.success() {
            let merge = trusted_git_command()
                .args(["-c", &format!("user.name={}", assignment.project.contributor.name)])
                .args(["-c", &format!("user.email={}", assignment.project.contributor.email)])
                .args(["merge", "--no-edit", &base])
                .current_dir(path)
                .output().await?;
            if !merge.status.success() {
                let conflicts = git_output(path, &["diff", "--name-only", "--diff-filter=U"]).await.unwrap_or_default();
                if conflicts.trim().is_empty() {
                    bail!("merge current base into task branch failed: {}", String::from_utf8_lossy(&merge.stderr));
                }
                warn!(%conflicts, "task retry opened with merge conflicts for the agent to resolve");
            }
        }
        return Ok(base);
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
    let git_dir = git_output(path, &["rev-parse", "--git-dir"]).await?;
    let git_dir = if Path::new(&git_dir).is_absolute() { PathBuf::from(git_dir) } else { path.join(git_dir) };
    if !git_dir.join("MERGE_HEAD").exists() {
        command_ok(path, "git", &["reset"]).await?;
    }
    command_ok(path, "git", &["add", "-A"]).await?;
    let status = trusted_git_command().args(["diff", "--cached", "--quiet"]).current_dir(path).status().await?;
    if status.success() { return Ok(()); }
    command_ok(path, "git", &[
        "-c", &format!("user.name={}", assignment.project.contributor.name),
        "-c", &format!("user.email={}", assignment.project.contributor.email),
        "commit", "-m", &format!("lazyteam: {}", assignment.task.title),
    ]).await
}

async fn git_status_external_worktree(repo: &Path, worktree: &Path) -> anyhow::Result<String> {
    let git_dir = git_output(repo, &["rev-parse", "--git-dir"]).await?;
    let git_dir = if Path::new(&git_dir).is_absolute() { PathBuf::from(git_dir) } else { repo.join(git_dir) };
    let output = trusted_git_command()
        .arg("--git-dir").arg(&git_dir)
        .arg("--work-tree").arg(worktree)
        .args(["status", "--porcelain", "--untracked-files=all", "--", ".", ":(exclude).git"])
        .output().await?;
    if !output.status.success() {
        bail!("git external worktree status failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

fn trusted_git_command() -> Command {
    let mut command = Command::new("git");
    command.args(["-c", "core.hooksPath=/dev/null"]);
    command
}

async fn git_output(path: &Path, args: &[&str]) -> anyhow::Result<String> {
    let output = trusted_git_command().args(args).current_dir(path).output().await?;
    if !output.status.success() { bail!("git {:?} failed: {}", args, String::from_utf8_lossy(&output.stderr)); }
    Ok(String::from_utf8(output.stdout)?.trim().to_string())
}

async fn command_ok(path: &Path, program: &str, args: &[&str]) -> anyhow::Result<()> {
    let mut command = if program == "git" { trusted_git_command() } else { Command::new(program) };
    let output = command.args(args).current_dir(path).output().await?;
    if !output.status.success() { bail!("{program} {:?} failed: {}", args, String::from_utf8_lossy(&output.stderr)); }
    Ok(())
}

async fn command_ok_with_auth(path: &Path, program: &str, args: &[&str], git_auth: &GitAuthContext) -> anyhow::Result<()> {
    let mut command = if program == "git" { trusted_git_command() } else { Command::new(program) };
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
    fn runtime_config_defaults_legacy_server_to_one_slot() {
        let config: WorkerRuntimeConfig = serde_json::from_value(json!({
            "role": "worker",
            "agent": {"agent_type":"pi","provider":null,"model":null,"initial_prompt":"prompt"},
            "managed_capabilities": [],
            "installed_capabilities": []
        })).unwrap();
        assert_eq!(config.slots, 1);
    }

    #[test]
    fn trusted_slot_paths_are_project_and_task_isolated() {
        let root = Path::new("/tmp/lazyteam-workspaces");
        let task_a = Uuid::new_v4();
        let task_b = Uuid::new_v4();
        let workspace_a = trusted_task_workspace(root, "project-a", task_a);
        let workspace_b = trusted_task_workspace(root, "project-b", task_b);
        assert_ne!(workspace_a, workspace_b);
        assert!(workspace_a.ends_with(Path::new("project-a").join(task_a.to_string())));
        assert!(workspace_b.ends_with(Path::new("project-b").join(task_b.to_string())));
        assert_ne!(format!("lazyteam/task-{}", task_a.simple()), format!("lazyteam/task-{}", task_b.simple()));
    }

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
    fn reviewer_prompt_evidence_omits_upstream_git_identity() {
        let result = ExecutionResult {
            status: "completed".into(),
            summary: "done".into(),
            commit_sha: Some("candidate-secret-sha".into()),
            base_sha: Some("base-secret-sha".into()),
            patch: Some("diff containing implementation".into()),
            patch_truncated: false,
            workspace_clean: Some(true),
            review_ref: Some("lazyteam/task-secret-ref".into()),
            changed_files: vec!["src/lib.rs".into()],
            validation: vec!["focused check".into()],
            warnings: vec![],
            artifacts: vec![],
        };
        let evidence = reviewer_evidence_for_prompt(Some(&result)).unwrap();
        assert!(evidence.contains("src/lib.rs"));
        assert!(evidence.contains("focused check"));
        assert!(!evidence.contains("candidate-secret-sha"));
        assert!(!evidence.contains("base-secret-sha"));
        assert!(!evidence.contains("task-secret-ref"));
        assert!(!evidence.contains("diff containing implementation"));
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

    #[test]
    fn broker_git_auth_uses_worker_and_lease_capability_headers_only() {
        let auth = GitAuthContext::broker("worker-secret", "lease-secret");
        assert_eq!(auth.env.iter().find(|(key, _)| key == "GIT_CONFIG_COUNT").unwrap().1, "2");
        let worker_header = auth.env.iter().find(|(key, _)| key == "GIT_CONFIG_VALUE_0").unwrap().1.clone();
        let lease_header = auth.env.iter().find(|(key, _)| key == "GIT_CONFIG_VALUE_1").unwrap().1.clone();
        assert_eq!(worker_header, "x-lazyteam-worker-credential: worker-secret");
        assert_eq!(lease_header, "x-lazyteam-lease-capability: lease-secret");
        assert!(!worker_header.contains("Authorization:"));
        assert!(!lease_header.contains("Authorization:"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn trusted_git_commands_disable_repository_hooks() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("lazyteam-git-hooks-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        command_ok(&root, "git", &["init"]).await.unwrap();
        command_ok(&root, "git", &["config", "user.name", "LazyTeam Test"]).await.unwrap();
        command_ok(&root, "git", &["config", "user.email", "lazyteam-test@local"]).await.unwrap();
        tokio::fs::write(root.join("tracked.txt"), b"safe\n").await.unwrap();
        command_ok(&root, "git", &["add", "tracked.txt"]).await.unwrap();

        let hook = root.join(".git").join("hooks").join("pre-commit");
        tokio::fs::write(&hook, b"#!/bin/sh\ntouch \"$PWD/hook-ran\"\nexit 73\n").await.unwrap();
        let mut permissions = tokio::fs::metadata(&hook).await.unwrap().permissions();
        permissions.set_mode(0o755);
        tokio::fs::set_permissions(&hook, permissions).await.unwrap();

        command_ok(&root, "git", &["commit", "-m", "hook must stay disabled"]).await.unwrap();
        assert!(!root.join("hook-ran").exists());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[tokio::test]
    async fn auto_commit_uses_project_contributor_identity() {
        let root = std::env::temp_dir().join(format!("lazyteam-contributor-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        command_ok(&root, "git", &["init"]).await.unwrap();
        tokio::fs::write(root.join("contribution.txt"), b"project contribution\n").await.unwrap();

        let project_id = Uuid::new_v4();
        let task_id = Uuid::new_v4();
        let assignment: Assignment = serde_json::from_value(json!({
            "project": {
                "id": project_id,
                "slug": "test-project",
                "name": "Test Project",
                "repo_url": "https://example.invalid/repo.git",
                "default_branch": "main",
                "contributor": {"name": "Project Contributor", "email": "project@example.test"},
                "required_worker_tags": {},
                "default_task_tags": {},
                "git_auth": {"mode": "worker", "credential_configured": false},
                "enabled": true,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            },
            "task": {
                "id": task_id,
                "project_id": project_id,
                "title": "Use contributor identity",
                "description": "",
                "expected_outcome": "",
                "acceptance_criteria": [],
                "required_tags": {},
                "preferred_tags": {},
                "dependencies": [],
                "review_feedback": "",
                "priority": 0,
                "state": "running",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            },
            "execution": {
                "id": Uuid::new_v4(),
                "task_id": task_id,
                "worker_id": Uuid::new_v4(),
                "attempt": 1,
                "state": "running",
                "lease_until": "2026-01-01T00:02:00Z",
                "started_at": "2026-01-01T00:00:00Z",
                "finished_at": null,
                "result": null
            },
            "lease_capability": "test-lease-capability"
        })).unwrap();

        auto_commit(&root, &assignment).await.unwrap();
        let author = git_output(&root, &["log", "-1", "--format=%an <%ae>"]).await.unwrap();
        assert_eq!(author, "Project Contributor <project@example.test>");
        let _ = tokio::fs::remove_dir_all(root).await;
    }

}
