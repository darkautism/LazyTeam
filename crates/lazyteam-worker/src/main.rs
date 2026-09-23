use std::{collections::{BTreeMap, BTreeSet}, path::{Path, PathBuf}, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use lazyteam_core::{can_claim_work, host_agent_selection_ready, redact_oauth_secret_text, AgentCapabilities, AgentConfig, AgentRole, Assignment, ExecutionResult, ReviewAssignment, ReviewVerdict, LEASE_CAPABILITY_HEADER};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::{io::{AsyncBufReadExt, AsyncWriteExt, BufReader}, process::Command, task::JoinSet, time::{sleep, Instant}};
use tracing::{error, info, warn};
use uuid::Uuid;

mod review_mcp;
mod runtime;
mod session;
use review_mcp::ReviewSlot;
use runtime::{AgentRunResult, AgentRuntime, PiRuntime};
use lazyteam_sandbox::{AgentSandbox, prepare_agent_workspace, sync_agent_workspace};
use session::{AgentSession, SessionLock, SessionManager, SessionRole};

const WORKER_CREDENTIAL_HEADER: &str = "x-lazyteam-worker-credential";
const MAX_REVIEW_PATCH_BYTES: usize = 256 * 1024;
const WORKER_PROTOCOL_VERSION: u32 = 6;
const AGENT_ROOTFS_BUILD_SCRIPT: &str = include_str!("../../../scripts/agent-rootfs-build.sh");
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
    #[serde(default)]
    model_refresh: Option<AgentModelRefreshDelivery>,
}

fn default_runtime_slots() -> u32 { 1 }

#[derive(Deserialize)]
struct AgentAuthDelivery {
    id: Uuid,
    provider: String,
    api_key: String,
}

#[derive(Debug, Deserialize)]
struct AgentModelRefreshDelivery {
    id: Uuid,
    provider: String,
}

#[derive(Debug, Deserialize)]
struct AgentOAuthClaim { id: Uuid, provider: String }

#[derive(Debug, Clone, Serialize)]
struct AgentOAuthEventReport {
    kind: String,
    #[serde(skip_serializing_if = "Option::is_none")] message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] verification_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] user_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] authorization_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] paste_prompt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")] paste_placeholder: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PiOAuthWireEvent {
    kind: String,
    #[serde(default)] event: Option<serde_json::Value>,
    #[serde(default)] message: Option<String>,
    #[serde(default)] prompt: Option<serde_json::Value>,
    #[serde(default)] selection: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct AgentOAuthInputDelivery { id: Uuid, input: String }

#[derive(Debug, Deserialize)]
struct WorkerCleanup {
    task_id: Uuid,
    project_slug: String,
    #[serde(default)]
    role: SessionRole,
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
    lazyteam_sandbox::maybe_enter_daemon_user_namespace()?;

    // The sandbox self-exec path must run before Tokio creates worker threads.  Linux user
    // namespaces reject unshare(CLONE_NEWUSER) from a multithreaded process on some kernels.
    if let Some(result) = lazyteam_sandbox::maybe_handle_entrypoint() {
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
    if local_installed_capabilities.contains("rust") {
        let installed = agent_sandbox.probe_managed_rust_toolchain().await?;
        info!(toolchain = %installed.replace('\n', "; "), "managed Rust toolchain verified through agent sandbox");
    }
    info!(rootfs = %agent_rootfs.display(), "agent Ubuntu rootfs + intuitive tooling + sandboxed Git ready");
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

    if let Err(error) = reset_stale_oauth_login(&client, &server, &worker_credential, worker_id).await {
        warn!(%error, "failed to reset stale OAuth login state during worker startup");
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
            // A previous worker process may have left the Host in degraded state
            // after a provisioning/sandbox failure. Successful startup proves the
            // persisted rootfs is usable again even when the installed capability
            // set itself did not change, so explicitly recover the control-plane
            // state before attempting claims.
            let tail = capability_build_log_tail(&args.state_dir).await;
            if let Err(error) = report_capability_build(
                &client,
                &server,
                &worker_credential,
                worker_id,
                &local_installed_capabilities,
                "ready",
                &tail,
            ).await {
                warn!(%error, "startup capability-ready recovery report failed");
            }
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
    if let Some(refresh) = runtime_config.model_refresh.take() {
        let provider = refresh.provider.clone();
        info!(provider = %provider, refresh_request = %refresh.id, "forced model catalog refresh requested during startup");
        match probe_runtime.force_refresh_models(&provider).await {
            Ok(()) => {
                agent_capabilities = probe_runtime.capabilities().await;
                if let Err(error) = report_capabilities(&client, &server, &worker_credential, worker_id, &agent_capabilities).await {
                    warn!(%error, "agent capability report after startup model refresh failed");
                }
            }
            Err(error) => {
                warn!(%error, provider = %provider, "startup model catalog refresh failed");
                agent_capabilities.probe_error = Some(format!("model catalog refresh for {provider} failed: {error:#}"));
                let _ = report_capabilities(&client, &server, &worker_credential, worker_id, &agent_capabilities).await;
            }
        }
        if let Err(error) = ack_model_refresh(&client, &server, &worker_credential, worker_id, refresh.id).await {
            warn!(%error, provider = %provider, refresh_request = %refresh.id, "model refresh ACK failed; request will be retried");
        }
    }
    let mut next_capability_probe = Instant::now() + Duration::from_secs(60);
    let mut active_jobs = JoinSet::<anyhow::Result<()>>::new();
    let mut oauth_job: Option<tokio::task::JoinHandle<anyhow::Result<()>>> = None;
    let session_manager = SessionManager::new(&args.state_dir);

    loop {
        while let Some(result) = active_jobs.try_join_next() {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => error!(%error, "slot execution failed"),
                Err(error) => error!(%error, "slot task panicked or was cancelled"),
            }
        }
        if oauth_job.as_ref().is_some_and(|job| job.is_finished()) {
            let job = oauth_job.take().expect("OAuth job was checked above");
            match job.await {
                Ok(Ok(())) => info!("Pi OAuth login completed"),
                Ok(Err(error)) => warn!(%error, "Pi OAuth login failed"),
                Err(error) => warn!(%error, "Pi OAuth login task panicked or was cancelled"),
            }
            agent_capabilities = probe_runtime.capabilities().await;
            let _ = report_capabilities(&client, &server, &worker_credential, worker_id, &agent_capabilities).await;
            next_capability_probe = Instant::now() + Duration::from_secs(60);
        }
        if oauth_job.is_none() {
            match claim_oauth_login(&client, &server, &worker_credential, worker_id).await {
                Ok(Some(claim)) => {
                    let oauth_client = client.clone();
                    let oauth_server = server.clone();
                    let oauth_credential = worker_credential.clone();
                    let oauth_runtime = probe_runtime.clone();
                    let oauth_request = claim.id;
                    info!(provider = %claim.provider, oauth_request = %oauth_request, "claimed Pi OAuth login request");
                    oauth_job = Some(tokio::spawn(async move {
                        let result = execute_oauth_login(
                            &oauth_client,
                            &oauth_server,
                            &oauth_credential,
                            worker_id,
                            oauth_runtime,
                            claim,
                        ).await;
                        if let Err(error) = &result {
                            let report = AgentOAuthEventReport {
                                kind: "failed".into(), message: Some(error.to_string()), verification_uri: None, user_code: None, authorization_url: None, paste_prompt: None, paste_placeholder: None,
                            };
                            let _ = report_oauth_event(
                                &oauth_client, &oauth_server, &oauth_credential, worker_id, oauth_request, &report,
                            ).await;
                        }
                        result
                    }));
                }
                Ok(None) => {}
                Err(error) => warn!(%error, "Pi OAuth login poll failed"),
            }
        }
        if let Err(error) = heartbeat(&client, &server, &worker_credential, worker_id).await {
            warn!(%error, "heartbeat failed");
            sleep(Duration::from_secs(5)).await;
            continue;
        }
        if let Err(error) = process_cleanup(&client, &server, &worker_credential, worker_id, &args.workspace_dir, &args.state_dir, &session_manager).await {
            warn!(%error, "post-merge cleanup poll failed");
        }
        match poll_agent_auth(&client, &server, &worker_credential, worker_id).await {
            Ok(Some(update)) => {
                let provider = update.provider.clone();
                if let Err(error) = probe_runtime.store_api_key(&update.provider, &update.api_key).await {
                    error!(%error, provider = %provider, credential_update = %update.id, "failed to store provider API key");
                } else {
                    info!(provider = %provider, credential_update = %update.id, "provider API key stored in isolated Pi config");
                    if let Err(error) = ack_agent_auth(
                        &client,
                        &server,
                        &worker_credential,
                        worker_id,
                        update.id,
                    ).await {
                        warn!(%error, provider = %provider, credential_update = %update.id, "provider credential ACK failed; delivery will be retried");
                    }
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
        if let Some(refresh) = runtime_config.model_refresh.take() {
            let provider = refresh.provider.clone();
            info!(provider = %provider, refresh_request = %refresh.id, "forced model catalog refresh requested");
            match probe_runtime.force_refresh_models(&provider).await {
                Ok(()) => {
                    agent_capabilities = probe_runtime.capabilities().await;
                    if let Err(error) = report_capabilities(&client, &server, &worker_credential, worker_id, &agent_capabilities).await {
                        warn!(%error, "agent capability report after forced model refresh failed");
                    }
                }
                Err(error) => {
                    warn!(%error, provider = %provider, "forced model catalog refresh failed");
                    agent_capabilities.probe_error = Some(format!("model catalog refresh for {provider} failed: {error:#}"));
                    let _ = report_capabilities(&client, &server, &worker_credential, worker_id, &agent_capabilities).await;
                }
            }
            if let Err(error) = ack_model_refresh(&client, &server, &worker_credential, worker_id, refresh.id).await {
                warn!(%error, provider = %provider, refresh_request = %refresh.id, "model refresh ACK failed; request will be retried");
            }
            next_capability_probe = Instant::now() + Duration::from_secs(60);
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
        if !can_claim_work(&runtime_config.agent, &agent_capabilities) {
            if agent_capabilities.models.is_empty() {
                tracing::debug!(active = active_jobs.len(), "worker has no usable Pi models yet; not claiming new work");
            } else if !host_agent_selection_ready(&runtime_config.agent) {
                tracing::debug!(active = active_jobs.len(), "worker has no Host provider/model selection yet; not claiming new work");
            } else {
                tracing::debug!(active = active_jobs.len(), provider = ?runtime_config.agent.provider, model = ?runtime_config.agent.model, "Host provider/model selection unavailable in Pi catalog; not claiming new work");
            }
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
                        let session = match session_manager.acquire(task_id, SessionRole::Implementation, &runtime_config.agent.agent_type).await {
                            Ok(session) => session,
                            Err(error) => {
                                error!(%error, %execution_id, %task_id, "failed to acquire implementation agent session");
                                break;
                            }
                        };
                        let runtime = match runtime_for_config(
                            &runtime_config.agent,
                            &pi_bin,
                            session.data_dir.clone(),
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
                        let slot_session = session.clone();
                        let slot_session_manager = session_manager.clone();
                        active_jobs.spawn(async move {
                            execute_assignment(
                                &slot_client,
                                &slot_server,
                                &slot_credential,
                                &slot_workspace_root,
                                &slot_sandbox,
                                runtime,
                                &slot_prompt,
                                slot_session,
                                &slot_session_manager,
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
                        let session = match session_manager.acquire(task_id, SessionRole::Review, &runtime_config.agent.agent_type).await {
                            Ok(session) => session,
                            Err(error) => {
                                error!(%error, %review_id, %task_id, "failed to acquire reviewer agent session");
                                break;
                            }
                        };
                        let runtime = match runtime_for_config(
                            &runtime_config.agent,
                            &pi_bin,
                            session.data_dir.clone(),
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
                        let slot_session = session.clone();
                        let slot_session_manager = session_manager.clone();
                        active_jobs.spawn(async move {
                            execute_review_assignment(
                                &slot_client,
                                &slot_server,
                                &slot_credential,
                                &slot_workspace_root,
                                &slot_sandbox,
                                runtime,
                                &slot_prompt,
                                slot_session,
                                &slot_session_manager,
                                assignment,
                            ).await.with_context(|| format!("review {review_id} task {task_id} project {project_slug}"))
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

async fn reset_stale_oauth_login(
    client: &Client,
    server: &str,
    credential: &str,
    worker_id: Uuid,
) -> anyhow::Result<()> {
    let response = worker_auth(
        client.post(format!("{server}/api/workers/{worker_id}/oauth-login/reset-stale")),
        credential,
    ).send().await?;
    ensure_success(response).await?;
    Ok(())
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
        if target.contains("rust") {
            let installed = sandbox.probe_managed_rust_toolchain().await?;
            info!(toolchain = %installed.replace('\n', "; "), "managed Rust toolchain verified before rootfs activation");
        }
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
        info!(rootfs = %agent_rootfs.display(), ?local_installed, "agent rootfs rebuild activated");
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

async fn ack_agent_auth(
    client: &Client,
    server: &str,
    credential: &str,
    worker_id: Uuid,
    request_id: Uuid,
) -> anyhow::Result<()> {
    let response = worker_auth(
        client.post(format!("{server}/api/workers/{worker_id}/agent-auth/{request_id}/ack")),
        credential,
    ).send().await?;
    ensure_success(response).await?;
    Ok(())
}

async fn ack_model_refresh(
    client: &Client,
    server: &str,
    credential: &str,
    worker_id: Uuid,
    request_id: Uuid,
) -> anyhow::Result<()> {
    let response = worker_auth(
        client.post(format!("{server}/api/workers/{worker_id}/models/refresh/{request_id}/ack")),
        credential,
    ).send().await?;
    ensure_success(response).await?;
    Ok(())
}

async fn claim_oauth_login(client: &Client, server: &str, credential: &str, worker_id: Uuid) -> anyhow::Result<Option<AgentOAuthClaim>> {
    let response = worker_auth(client.get(format!("{server}/api/workers/{worker_id}/oauth-login/claim")), credential).send().await?;
    if response.status() == StatusCode::NO_CONTENT { return Ok(None); }
    Ok(Some(ensure_success(response).await?.json().await?))
}

async fn report_oauth_event(
    client: &Client,
    server: &str,
    credential: &str,
    worker_id: Uuid,
    request_id: Uuid,
    event: &AgentOAuthEventReport,
) -> anyhow::Result<()> {
    // Single choke point for every worker→Host OAuth report. Pi's upstream
    // errors can embed raw token-response JSON (its parsers include the
    // response body when fields are missing), so the diagnostic is redacted
    // for credential-shaped values here; the Host re-applies the same
    // redaction before storing. Raw helper text never crosses the boundary.
    let mut sanitized = AgentOAuthEventReport {
        kind: event.kind.clone(),
        message: None,
        verification_uri: event.verification_uri.clone(),
        user_code: event.user_code.clone(),
        authorization_url: event.authorization_url.clone(),
        paste_prompt: event.paste_prompt.clone(),
        paste_placeholder: event.paste_placeholder.clone(),
    };
    if let Some(message) = event.message.as_deref() {
        sanitized.message = Some(redact_oauth_secret_text(message));
    }
    let response = worker_auth(
        client.post(format!("{server}/api/workers/{worker_id}/oauth-login/{request_id}/event")),
        credential,
    ).json(&sanitized).send().await?;
    ensure_success(response).await?;
    Ok(())
}

/// Poll the Host for a relayed localhost-callback paste (the user-pasted
/// final redirect URL or authorization code). Returns `None` on timeout.
/// Only lengths are logged: the pasted single-use code is auth material
/// that must never appear in logs, prompts, or Host durable state.
async fn poll_oauth_callback_input(
    client: Client,
    server: String,
    credential: String,
    worker_id: Uuid,
    request_id: Uuid,
    timeout: Duration,
) -> Option<AgentOAuthInputDelivery> {
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline { return None; }
        match worker_auth(
            client.get(format!("{server}/api/workers/{worker_id}/oauth-login/{request_id}/input")),
            &credential,
        ).send().await {
            Ok(response) if response.status() == StatusCode::OK => {
                match response.json::<AgentOAuthInputDelivery>().await {
                    Ok(delivery) if !delivery.input.trim().is_empty() => {
                        info!(oauth_request = %request_id, input_delivery = %delivery.id, input_chars = delivery.input.chars().count(), "received Host-relayed OAuth callback paste");
                        return Some(delivery);
                    }
                    Ok(_) => {}
                    Err(error) => warn!(%error, "failed to parse relayed OAuth callback input"),
                }
            }
            Ok(_) => {}
            Err(error) => warn!(%error, "OAuth callback input poll failed"),
        }
        sleep(Duration::from_secs(2)).await;
    }
}

async fn ack_oauth_callback_input(
    client: &Client,
    server: &str,
    credential: &str,
    worker_id: Uuid,
    request_id: Uuid,
    input_id: Uuid,
) -> anyhow::Result<()> {
    let response = worker_auth(
        client.post(format!(
            "{server}/api/workers/{worker_id}/oauth-login/{request_id}/input/{input_id}/ack"
        )),
        credential,
    ).send().await?;
    ensure_success(response).await?;
    Ok(())
}

/// Paste waiter injected into the Pi OAuth helper script (plain JS, single
/// braces). Kept as a named constant so unit tests can assert the abort
/// wiring without spawning Node: Pi aborts the concurrent `manual_code`
/// prompt when its worker-local localhost callback wins, and the waiter must
/// honor `signal`, close the readline interface, and reject so Pi proceeds
/// with the callback code instead of hanging the helper forever.
const OAUTH_READ_PASTED_LINE_JS: &str = r#"function readPastedLine(signal) {
  return new Promise((resolve,reject)=>{
    const rl=createInterface({input:process.stdin});
    let settled=false;
    const settle=(fn,value)=>{ if (settled) return; settled=true; try{rl.close();}catch{} fn(value); };
    if (signal) {
      if (signal.aborted) { settle(reject,new Error("Login cancelled")); return; }
      signal.addEventListener("abort",()=>settle(reject,new Error("Login cancelled")),{once:true});
    }
    rl.on("line",(line)=>settle(resolve,line));
    rl.on("close",()=>settle(reject,new Error("OAuth paste channel closed")));
  });
}"#;

/// Outcome of driving one Pi OAuth helper process to its terminal wire line.
struct OAuthDriverOutcome {
    completed: bool,
    failed_reported: bool,
}

/// Drive the Pi OAuth helper wire protocol: `select!` over helper stdout and
/// at most one pending Host-relayed paste poll.
///
/// A locally-won localhost callback (`complete` line) or a cancellation
/// (`failed` line) therefore never strands the driver inside the paste poll:
/// the pending poll task is aborted and the loop exits promptly. The pending
/// poll is likewise aborted on helper-stdout EOF and when a second prompt
/// replaces the first. Paste-poll timeout closes helper stdin (releasing
/// Pi's `manual_code` prompt, which then fails through Pi's own cancel path)
/// after reporting; stdin write failures are tolerated because the helper
/// may already have moved on via its local callback. Pasted values are only
/// ever written to helper stdin; only their lengths reach logs.
async fn drive_oauth_wire_loop<R, W, F, Fut, S, A, AFut>(
    reader: R,
    mut stdin: W,
    report: F,
    start_poll: S,
    ack_input: A,
) -> OAuthDriverOutcome
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
    F: Fn(AgentOAuthEventReport) -> Fut,
    Fut: std::future::Future<Output = ()>,
    S: Fn() -> tokio::task::JoinHandle<Option<AgentOAuthInputDelivery>>,
    A: Fn(Uuid) -> AFut,
    AFut: std::future::Future<Output = ()>,
{
    enum Step {
        Line(Option<String>),
        Input(Option<AgentOAuthInputDelivery>),
    }
    let mut lines = BufReader::new(reader).lines();
    let mut pending: Option<tokio::task::JoinHandle<Option<AgentOAuthInputDelivery>>> = None;
    let mut completed = false;
    let mut failed_reported = false;
    loop {
        let step = {
            let poll_wait = async {
                match pending.as_mut() {
                    Some(handle) => handle.await.ok().flatten(),
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                line = lines.next_line() => Step::Line(line.unwrap_or(None)),
                input = poll_wait => Step::Input(input),
            }
        };
        match step {
            Step::Line(None) => break,
            Step::Line(Some(line)) => {
                let Ok(wire) = serde_json::from_str::<PiOAuthWireEvent>(&line) else {
                    tracing::debug!(raw = %line, "ignoring non-json Pi OAuth helper output");
                    continue;
                };
                match wire.kind.as_str() {
                    "selected" => {
                        report(AgentOAuthEventReport {
                            kind: "info".into(),
                            message: Some(format!("Pi login method '{}' started on the worker; waiting for the authorization URL.", wire.selection.as_deref().unwrap_or("unknown"))),
                            verification_uri: None,
                            user_code: None,
                            authorization_url: None,
                            paste_prompt: None,
                            paste_placeholder: None,
                        }).await;
                    }
                    "prompt" => {
                        // A second prompt replaces the first: abort the stale
                        // poll before starting a fresh one.
                        if let Some(handle) = pending.take() {
                            handle.abort();
                        }
                        // Pi's `manual_code` prompt: its localhost callback
                        // cannot be reached from a remote browser, so the Host
                        // UI must collect the pasted final redirect URL/code
                        // and relay it here.
                        let prompt = wire.prompt.as_ref();
                        report(AgentOAuthEventReport {
                            kind: "awaiting_input".into(),
                            message: prompt.and_then(|p| p.get("message").and_then(serde_json::Value::as_str)).map(str::to_string),
                            verification_uri: None,
                            user_code: None,
                            authorization_url: None,
                            paste_prompt: prompt.and_then(|p| p.get("message").and_then(serde_json::Value::as_str)).map(str::to_string),
                            paste_placeholder: prompt.and_then(|p| p.get("placeholder").and_then(serde_json::Value::as_str)).map(str::to_string),
                        }).await;
                        pending = Some(start_poll());
                    }
                    "event" => {
                        let Some(event) = wire.event.as_ref() else { continue; };
                        let reported = match event.get("type").and_then(serde_json::Value::as_str) {
                            Some("device_code") => AgentOAuthEventReport {
                                kind: "device_code".into(),
                                message: Some("Waiting for authorization: open the verification page and enter the device code.".into()),
                                verification_uri: event.get("verificationUri").and_then(serde_json::Value::as_str).map(str::to_string),
                                user_code: event.get("userCode").and_then(serde_json::Value::as_str).map(str::to_string),
                                authorization_url: None,
                                paste_prompt: None,
                                paste_placeholder: None,
                            },
                            Some("progress") | Some("info") => AgentOAuthEventReport {
                                kind: event.get("type").and_then(serde_json::Value::as_str).unwrap_or("info").to_string(),
                                message: event.get("message").and_then(serde_json::Value::as_str).map(str::to_string),
                                verification_uri: None,
                                user_code: None,
                                authorization_url: None,
                                paste_prompt: None,
                                paste_placeholder: None,
                            },
                            Some("auth_url") => AgentOAuthEventReport {
                                kind: "auth_url".into(),
                                message: event.get("instructions").and_then(serde_json::Value::as_str).map(str::to_string),
                                verification_uri: None,
                                user_code: None,
                                authorization_url: event.get("url").and_then(serde_json::Value::as_str).map(str::to_string),
                                paste_prompt: None,
                                paste_placeholder: None,
                            },
                            _ => continue,
                        };
                        report(reported).await;
                    }
                    "complete" => {
                        completed = true;
                        report(AgentOAuthEventReport {
                            kind: "complete".into(),
                            message: Some("Pi stored the OAuth credential in this worker's isolated auth store.".into()),
                            verification_uri: None,
                            user_code: None,
                            authorization_url: None,
                            paste_prompt: None,
                            paste_placeholder: None,
                        }).await;
                        break;
                    }
                    "failed" => {
                        failed_reported = true;
                        report(AgentOAuthEventReport { kind: "failed".into(), message: wire.message, verification_uri: None, user_code: None, authorization_url: None, paste_prompt: None, paste_placeholder: None }).await;
                        break;
                    }
                    _ => {}
                }
            }
            Step::Input(input) => {
                pending = None;
                match input {
                    Some(delivery) => {
                        if let Err(error) = write_oauth_paste(&mut stdin, &delivery.input).await {
                            warn!(%error, input_delivery = %delivery.id, paste_chars = delivery.input.chars().count(), "failed to forward relayed OAuth paste to Pi helper");
                        } else {
                            ack_input(delivery.id).await;
                        }
                    }
                    None => {
                        report(AgentOAuthEventReport {
                            kind: "failed".into(),
                            message: Some("Timed out waiting for the pasted redirect URL/code; no input arrived from the Host.".into()),
                            verification_uri: None,
                            user_code: None,
                            authorization_url: None,
                            paste_prompt: None,
                            paste_placeholder: None,
                        }).await;
                        failed_reported = true;
                        // Release Pi's `manual_code` prompt so the helper
                        // terminates through Pi's own cancel path instead of
                        // hanging on a readline that will never resolve.
                        let _ = tokio::io::AsyncWriteExt::shutdown(&mut stdin).await;
                    }
                }
            }
        }
    }
    if let Some(handle) = pending.take() {
        handle.abort();
    }
    OAuthDriverOutcome { completed, failed_reported }
}

/// Forward one Host-relayed paste line to the helper's stdin (its
/// `readPastedLine` resolves one prompt per line).
async fn write_oauth_paste(
    stdin: &mut (impl tokio::io::AsyncWrite + Unpin),
    pasted: &str,
) -> anyhow::Result<()> {
    stdin.write_all(pasted.as_bytes()).await.context("forward relayed OAuth paste to Pi helper")?;
    stdin.write_all(b"\n").await.context("forward relayed OAuth paste to Pi helper")?;
    stdin.flush().await.context("forward relayed OAuth paste to Pi helper")?;
    Ok(())
}

async fn best_effort_after_oauth_complete<F>(operation: F)
where
    F: std::future::Future<Output = anyhow::Result<()>>,
{
    if let Err(error) = operation.await {
        warn!(%error, "OAuth credential is stored, but post-login model/capability refresh failed");
    }
}

async fn execute_oauth_login(
    client: &Client,
    server: &str,
    credential: &str,
    worker_id: Uuid,
    runtime: PiRuntime,
    claim: AgentOAuthClaim,
) -> anyhow::Result<()> {
    let index = runtime.pi_module_index()?;
    let import_url = serde_json::to_string(&format!("file://{}", index.display()))?;
    let provider_json = serde_json::to_string(&claim.provider)?;
    let script = format!(r#"import {{ ModelRuntime }} from {import_url};
import {{ createInterface }} from "node:readline";
const dir=process.env.PI_CODING_AGENT_DIR;
const provider={provider_json};
const rt=await ModelRuntime.create({{
  authPath:dir+"/auth.json",
  modelsPath:dir+"/models.json",
  modelsStorePath:dir+"/models-store.json",
  allowModelNetwork:false,
  refreshOnCreate:false
}});
// Pi aborts the concurrent `manual_code` prompt when its worker-local
// localhost callback wins the race, so the paste waiter must respect
// `prompt.signal`: on abort the readline interface is closed and the waiter
// rejects, letting Pi proceed with the callback code instead of hanging the
// helper (and Rust, which waits for stdout EOF) forever.
{read_pasted}
const interaction={{
  prompt: async (prompt) => {{
    if (prompt.type === "select") {{
      const options=prompt.options||[];
      // Prefer Pi's browser login so the Host UI can surface the real
      // authorization URL; it completes remotely via the paste-back relay.
      // Fall back to device-code login, which is remote-friendly natively.
      const option=options.find((item)=>/browser/i.test(item.id||"")||/browser/i.test(item.label||""))
        || options.find((item)=>item.id==="device_code")
        || options[0];
      if (!option) throw new Error("OAuth provider offered an empty selection prompt");
      console.log(JSON.stringify({{kind:"selected",selection:option.id}}));
      return option.id;
    }}
    if (prompt.type === "manual_code" || prompt.type === "text" || prompt.type === "secret") {{
      console.log(JSON.stringify({{kind:"prompt",prompt:{{type:prompt.type,message:prompt.message||"",placeholder:prompt.placeholder||""}}}}));
      const pasted=await readPastedLine(prompt.signal);
      if (!pasted.trim()) throw new Error("Login cancelled");
      return pasted.trim();
    }}
    throw new Error(`remote OAuth prompt ${{prompt.type}} is unsupported for this provider`);
  }},
  notify: (event) => console.log(JSON.stringify({{kind:"event",event}}))
}};
try {{
  await rt.login(provider,"oauth",interaction);
  console.log(JSON.stringify({{kind:"complete"}}));
}} catch (error) {{
  console.log(JSON.stringify({{kind:"failed",message:error instanceof Error?error.message:String(error)}}));
  process.exitCode=1;
}}
"#, read_pasted = OAUTH_READ_PASTED_LINE_JS);

    let mut command = runtime.sandbox.command("node", runtime.sandbox.probe_workspace(), None)?;
    command.arg("--input-type=module").arg("--eval").arg(script);
    command.stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
    let mut child = command.spawn().context("start Pi OAuth helper")?;
    let stdout = child.stdout.take().context("Pi OAuth helper stdout missing")?;
    let stdin = child.stdin.take().context("Pi OAuth helper stdin missing")?;
    // Owned clones for the 'static poll task spawned per `manual_code` prompt.
    let report_client = client.clone();
    let report_server = server.to_string();
    let report_credential = credential.to_string();
    let poll_client = client.clone();
    let poll_server = server.to_string();
    let poll_credential = credential.to_string();
    let ack_client = client.clone();
    let ack_server = server.to_string();
    let ack_credential = credential.to_string();
    let OAuthDriverOutcome { completed, failed_reported } = drive_oauth_wire_loop(
        stdout,
        stdin,
        |event: AgentOAuthEventReport| {
            let report_client = report_client.clone();
            let report_server = report_server.clone();
            let report_credential = report_credential.clone();
            async move {
                let _ = report_oauth_event(
                    &report_client,
                    &report_server,
                    &report_credential,
                    worker_id,
                    claim.id,
                    &event,
                )
                .await;
            }
        },
        || {
            tokio::spawn(poll_oauth_callback_input(
                poll_client.clone(),
                poll_server.clone(),
                poll_credential.clone(),
                worker_id,
                claim.id,
                Duration::from_secs(600),
            ))
        },
        |input_id| {
            let ack_client = ack_client.clone();
            let ack_server = ack_server.clone();
            let ack_credential = ack_credential.clone();
            async move {
                if let Err(error) = ack_oauth_callback_input(
                    &ack_client,
                    &ack_server,
                    &ack_credential,
                    worker_id,
                    claim.id,
                    input_id,
                ).await {
                    warn!(%error, oauth_request = %claim.id, input_delivery = %input_id, "OAuth callback input ACK failed; delivery may be retried");
                }
            }
        },
    )
    .await;
    let status = child.wait().await.context("wait for Pi OAuth helper")?;
    if !status.success() && !failed_reported {
        let report = AgentOAuthEventReport {
            kind: "failed".into(), message: Some(format!("Pi OAuth helper exited with {status}")), verification_uri: None, user_code: None, authorization_url: None, paste_prompt: None, paste_placeholder: None,
        };
        let _ = report_oauth_event(client, server, credential, worker_id, claim.id, &report).await;
    }
    if !completed { anyhow::bail!("Pi OAuth login did not complete successfully"); }
    // Pi's complete event is the credential commit point. Anything below is
    // cache/control-plane follow-up and must never downgrade that successful
    // login to failed.
    best_effort_after_oauth_complete(async {
        runtime.force_refresh_models(&claim.provider).await?;
        let capabilities = runtime.capabilities().await;
        report_capabilities(client, server, credential, worker_id, &capabilities).await?;
        Ok(())
    }).await;
    Ok(())
}

/// Build the slot runtime exclusively from the Host-owned agent selection.
/// Worker-local overrides are intentionally unsupported: provider/model may only
/// be set, preserved, or explicitly cleared through the Host worker registry.
fn runtime_for_config(agent: &AgentConfig, pi_bin: &str, session_dir: PathBuf, sandbox: AgentSandbox) -> anyhow::Result<Arc<PiRuntime>> {
    if agent.agent_type != "pi" { bail!("unsupported agent type {}", agent.agent_type); }
    Ok(Arc::new(PiRuntime {
        binary: pi_bin.to_string(),
        provider: agent.provider.clone(),
        model: agent.model.clone(),
        session_dir: Some(session_dir),
        sandbox,
    }))
}

/// Persist an opaque backend session ID returned by a runtime without
/// interpreting it. Scheduler code stays backend-neutral: the ID is treated
/// as an opaque string scoped to the logical (task, role, backend) session.
/// The caller must hold the session lock so the bind cannot race a
/// concurrent acquire or bind. Failures are propagated: continuing with an
/// unpersisted binding would silently abandon session resumption on retry.
async fn persist_backend_session_binding(
    session_manager: &SessionManager,
    session_lock: &SessionLock,
    session: &AgentSession,
    result: &AgentRunResult,
) -> anyhow::Result<()> {
    let Some(new_id) = result.backend_session_id.as_deref() else { return Ok(()); };
    if session.backend_session_id.as_deref() == Some(new_id) { return Ok(()); }
    session_manager.bind_with(
        session_lock,
        session.task_id,
        session.role,
        &session.backend,
        new_id,
    ).await.with_context(|| format!(
        "persist {} backend session binding for task {}",
        session.backend,
        session.task_id,
    ))?;
    Ok(())
}

async fn process_cleanup(client: &Client, server: &str, credential: &str, worker_id: Uuid, workspace_root: &Path, state_dir: &Path, session_manager: &SessionManager) -> anyhow::Result<()> {
    let response = worker_auth(client.get(format!("{server}/api/workers/{worker_id}/cleanup")), credential).send().await?;
    let items: Vec<WorkerCleanup> = ensure_success(response).await?.json().await?;
    for item in items {
        match item.role {
            SessionRole::Implementation => {
                let workspace = workspace_root.join(&item.project_slug).join(item.task_id.to_string());
                if workspace.exists() { tokio::fs::remove_dir_all(&workspace).await?; }
                let agent_workspace = state_dir.join("agent-workspaces").join(item.task_id.to_string());
                if agent_workspace.exists() { tokio::fs::remove_dir_all(&agent_workspace).await?; }
            }
            SessionRole::Review => {
                let agent_workspace = state_dir.join("agent-review-workspaces").join(item.task_id.to_string());
                if agent_workspace.exists() { tokio::fs::remove_dir_all(&agent_workspace).await?; }
            }
        }
        session_manager.release(item.task_id, item.role).await?;
        let response = worker_auth(
            client.post(format!("{server}/api/workers/{worker_id}/cleanup/{}/{}", item.task_id, item.role.as_str())),
            credential,
        ).send().await?;
        if response.status() == StatusCode::NOT_FOUND && item.role == SessionRole::Implementation {
            let legacy = worker_auth(
                client.post(format!("{server}/api/workers/{worker_id}/cleanup/{}", item.task_id)),
                credential,
            ).send().await?;
            ensure_success(legacy).await?;
        } else {
            ensure_success(response).await?;
        }
        info!(task = %item.task_id, role = item.role.as_str(), "merged task logical agent session cleaned up");
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
    session: AgentSession,
    session_manager: &SessionManager,
    assignment: ReviewAssignment,
) -> anyhow::Result<()> {
    let review_id = assignment.review.id;
    let slot = match ReviewSlot::start(review_id, assignment.execution.id).await {
        Ok(slot) => slot,
        Err(error) => {
            warn!(%review_id, %error, "reviewer MCP slot failed to start; reporting failed review");
            let body = json!({"status":"failed","error":format!("reviewer MCP slot startup failed: {error}")});
            let response = lease_auth(
                client.post(format!("{server}/api/reviews/{review_id}/finish")),
                worker_credential,
                &assignment.lease_capability,
            ).json(&body).send().await?;
            ensure_success(response).await?;
            return Ok(());
        }
    };
    let renew_slot = slot.clone();
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
                Ok(response) => {
                    let status = response.status();
                    warn!(%status, %review_id, "review lease renew rejected; cancelling reviewer slot");
                    renew_slot.cancel(format!("review lease renew rejected with {status}"));
                    break;
                }
                Err(error) => warn!(%error, %review_id, "review lease renew failed"),
            }
        }
    }));

    let task_id = assignment.task.id;
    let workspace = workspace_root
        .join(".reviews")
        .join(&assignment.project.slug)
        .join(review_id.to_string());
    let auth = GitAuthContext::broker(worker_credential, &assignment.lease_capability);
    // From this point onward the Host already owns an active review lease.
    // Capture every local/runtime error into `outcome`; never `?` out of this
    // function before POSTing /finish, or the Host can only observe a lost lease.
    let outcome: anyhow::Result<ReviewVerdict> = async {
        if !runtime.supports_reviewer_mcp() {
            bail!("{} runtime cannot attach the required reviewer MCP terminal", runtime.kind());
        }
        // Serialize concurrent retries for the same logical session: the guard is
        // held across refresh → run → bind so a second arrival waits, then resumes
        // the bound session instead of orphaning a duplicate backend session.
        let session_lock = session_manager.lock_session(session.task_id, session.role).await;
        let session = session_manager
            .acquire_with(&session_lock, session.task_id, session.role, &session.backend)
            .await?;
        prepare_review_workspace(&workspace, &assignment, &auth).await?;
        let agent_workspace = sandbox.reviewer_workspace(task_id);
        let review_base = assignment.checkout.upstream_sha.as_deref().or(assignment.checkout.base_sha.as_deref());
        prepare_agent_workspace(&workspace, &agent_workspace, review_base).await?;
        let prompt = build_review_prompt(initial_prompt, &assignment)?;
        let review_run = runtime.run_review_with_mcp(
            &agent_workspace,
            &prompt,
            session.backend_session_id.as_deref(),
            slot.endpoint(),
        );
        tokio::pin!(review_run);
        let verdict = tokio::select! {
            verdict = slot.wait() => verdict,
            run = &mut review_run => {
                let agent = run?;
                persist_backend_session_binding(session_manager, &session_lock, &session, &agent).await?;
                match tokio::time::timeout(Duration::from_secs(2), slot.wait()).await {
                    Ok(verdict) => verdict,
                    Err(_) => Err(anyhow::anyhow!("reviewer ended without calling submit_review MCP tool")),
                }
            }
        }?;
        let dirty = git_status_external_worktree(&workspace, &agent_workspace)
            .await
            .unwrap_or_else(|error| format!("status-check-error: {error}"));
        if !dirty.is_empty() {
            bail!("reviewer modified the pinned source checkout; review discarded: {dirty}");
        }
        Ok(verdict)
    }.await;
    renew.abort();

    let diagnostics = slot.diagnostics();
    let body = match outcome {
        Ok(verdict) => {
            info!(%review_id, verdict = ?verdict.verdict, diagnostics = %diagnostics, "reviewer produced verdict; reporting review finish");
            json!({"status":"completed","verdict":verdict})
        }
        Err(error) => {
            let error = format!("{error}; reviewer_mcp={diagnostics}");
            warn!(%review_id, %error, "reviewer failed before verdict; reporting failed review");
            json!({"status":"failed","error":error})
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
    let agent_workspace = sandbox.reviewer_workspace(task_id);
    if agent_workspace.exists() { let _ = tokio::fs::remove_dir_all(&agent_workspace).await; }
    // The backend session itself is retained by SessionManager until merged.
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
    let review_head = match (assignment.checkout.upstream_sha.as_deref(), assignment.checkout.integration_sha.as_deref()) {
        (Some(upstream_sha), Some(integration_sha)) => {
            let upstream_ref = format!("refs/lazyteam/upstream/{upstream_sha}");
            command_ok_with_auth(path, "git", &["fetch", "origin", &upstream_ref], git_auth).await?;
            let fetched_upstream = git_output(path, &["rev-parse", "FETCH_HEAD"]).await?;
            if fetched_upstream != upstream_sha { bail!("review upstream ref moved: expected {upstream_sha}, fetched {fetched_upstream}"); }
            let integration_ref = format!("refs/lazyteam/integration/{integration_sha}");
            command_ok_with_auth(path, "git", &["fetch", "origin", &integration_ref], git_auth).await?;
            let fetched_integration = git_output(path, &["rev-parse", "FETCH_HEAD"]).await?;
            if fetched_integration != integration_sha { bail!("review integration ref moved: expected {integration_sha}, fetched {fetched_integration}"); }
            integration_sha
        }
        _ => assignment.checkout.commit_sha.as_str(),
    };
    command_ok(path, "git", &["checkout", "--detach", review_head]).await?;
    install_workspace_excludes(path).await?;
    command_ok(path, "git", &["remote", "set-url", "--push", "origin", "disabled://lazyteam-reviewer"]).await?;
    Ok(())
}

fn build_review_prompt(initial_prompt: &str, assignment: &ReviewAssignment) -> anyhow::Result<String> {
    let criteria = assignment.task.acceptance_criteria.iter().map(|v| format!("- {v}")).collect::<Vec<_>>().join("\n");
    let result = reviewer_evidence_for_prompt(assignment.execution.result.as_ref())?;
    Ok(format!(
        "{initial_prompt}\n\n{AGENT_GIT_BOUNDARY}\n\nPinned integration review snapshot:\nProject: {}\nDefault branch: {}\nOriginal candidate SHA: {}\nOriginal candidate base SHA: {}\nCurrent upstream SHA reviewed: {}\nIntegrated result SHA: {}\nLocal `HEAD` / `lazyteam-task`: integrated result that would be published.\nLocal `lazyteam-base`: current upstream snapshot, not the stale original base.\n\nReview the effective `lazyteam-base..HEAD` change against the task contract. When upstream advanced after implementation, preserve upstream changes and do not attribute upstream-only code to the candidate. If this candidate previously resolved a conflict, explicitly verify the resolution retained both current upstream behavior and the task intent.\n\nImplementation worker: {} ({}/{})\n\nTask contract:\nTitle: {}\n\nDescription:\n{}\n\nExpected outcome:\n{}\n\nAcceptance criteria:\n{}\n\nImplementation report (untrusted):\n{}\n\nUse the local Git snapshot as the review source of truth. You may inspect files and run validation, but do not edit files. Finish by calling the `submit_review` MCP tool; do not return a verdict as prose or JSON.\n",
        assignment.project.name,
        assignment.checkout.default_branch,
        assignment.checkout.commit_sha,
        assignment.checkout.base_sha.as_deref().unwrap_or("unknown"),
        assignment.checkout.upstream_sha.as_deref().unwrap_or_else(|| assignment.checkout.base_sha.as_deref().unwrap_or("unknown")),
        assignment.checkout.integration_sha.as_deref().unwrap_or(&assignment.checkout.commit_sha),
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
            "integration": result.integration,
        }),
        None => json!(null),
    };
    serde_json::to_string_pretty(&value).context("serialize reviewer implementation report")
}

async fn execute_assignment(
    client: &Client,
    server: &str,
    worker_credential: &str,
    workspace_root: &Path,
    sandbox: &AgentSandbox,
    runtime: Arc<dyn AgentRuntime>,
    initial_prompt: &str,
    session: AgentSession,
    session_manager: &SessionManager,
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
    // Serialize concurrent retries for the same logical session: the guard is
    // held across refresh → run → bind so a second arrival waits, then
    // resumes the bound session instead of creating a duplicate backend
    // session that would orphan one of them.
    let session_lock = session_manager.lock_session(session.task_id, session.role).await;
    let session = session_manager.acquire_with(&session_lock, session.task_id, session.role, &session.backend).await?;
    let outcome = run_task(workspace_root, sandbox, runtime, initial_prompt, &session, session_manager, &session_lock, &assignment, &auth).await;
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
            integration: None,
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

async fn run_task(workspace_root: &Path, sandbox: &AgentSandbox, runtime: Arc<dyn AgentRuntime>, initial_prompt: &str, session: &AgentSession, session_manager: &SessionManager, session_lock: &SessionLock, assignment: &Assignment, git_auth: &GitAuthContext) -> anyhow::Result<ExecutionResult> {
    let workspace = trusted_task_workspace(workspace_root, &assignment.project.slug, assignment.task.id);
    let (base_sha, preserved) = prepare_workspace(&workspace, assignment, git_auth).await?;
    let agent_workspace = sandbox.agent_workspace(assignment.task.id);
    prepare_agent_workspace(&workspace, &agent_workspace, Some(&base_sha)).await?;
    // The sandbox is rebuilt from the trusted worktree with its Git metadata
    // stripped, so a preserved backup ref alone would be invisible to the
    // resumed agent. Carry the preservation record in the attempt prompt:
    // the prompt travels with this execution (and its resumed session) on
    // whichever worker claimed it, while the backup branch persists in the
    // claiming worker's trusted workspace for session reuse.
    let mut prompt = build_prompt(initial_prompt, assignment);
    if let Some(preserved) = &preserved {
        prompt = with_preserved_attempt_context(prompt, preserved);
    }
    let agent = runtime.run(&agent_workspace, &prompt, session.backend_session_id.as_deref()).await?;
    persist_backend_session_binding(session_manager, session_lock, session, &agent).await?;
    sync_agent_workspace(&agent_workspace, &workspace).await?;
    auto_commit(&workspace, assignment).await?;
    let head_sha = git_output(&workspace, &["rev-parse", "HEAD"]).await?;
    // Compare tree content, not commit SHAs: an empty or equivalent-tree
    // commit on top of the base is still a genuinely unchanged attempt.
    let head_tree = git_output(&workspace, &["rev-parse", "HEAD^{tree}"]).await?;
    let base_tree = git_output(&workspace, &["rev-parse", &format!("{base_sha}^{{tree}}")]).await?;
    ensure_tracked_change(&head_tree, &base_tree)?;
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
        integration: None,
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

/// Zero-change guard: compares tracked tree content, not commit SHAs, so an
/// empty or equivalent-tree commit still counts as a genuinely unchanged
/// attempt. A retry that restored the prior candidate ends at the candidate
/// tree instead, so amending-by-keeping still passes while a genuinely
/// unchanged fresh task still fails.
fn ensure_tracked_change(head_tree: &str, base_tree: &str) -> anyhow::Result<()> {
    if head_tree.trim() == base_tree.trim() {
        bail!("agent completed without producing any tracked change");
    }
    Ok(())
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

/// Agent-visible record of failed-attempt state preserved while restoring
/// the last valid candidate. The backup branch alone would be invisible: the
/// sandbox is rebuilt from the trusted worktree with Git metadata stripped,
/// so this record travels in the attempt prompt instead, which the resumed
/// agent (and its session) always receives on the claiming worker.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PreservedAttempt {
    backup_branch: String,
    files: Vec<String>,
    stat: String,
    diff: String,
}

/// Max bytes of the preserved unified diff carried in the attempt prompt.
const PRESERVED_DIFF_MAX_BYTES: usize = 8 * 1024;

async fn prepare_workspace(
    path: &Path,
    assignment: &Assignment,
    git_auth: &GitAuthContext,
) -> anyhow::Result<(String, Option<PreservedAttempt>)> {
    let branch = task_branch(assignment);
    let branch_ref = format!("refs/heads/{branch}");
    if path.exists() {
        let inside = git_output(path, &["rev-parse", "--is-inside-work-tree"]).await?;
        if inside != "true" { bail!("existing task workspace is not a git repository"); }
        install_workspace_excludes(path).await?;
        command_ok(path, "git", &["remote", "set-url", "origin", &assignment.project.repo_url]).await?;
        let default_ref = format!("refs/heads/{}", assignment.project.default_branch);
        command_ok_with_auth(path, "git", &["fetch", "origin", &default_ref], git_auth).await?;
        let base = git_output(path, &["rev-parse", "FETCH_HEAD"]).await?;
        command_ok(path, "git", &["update-ref", &default_ref, &base]).await?;
        // A fresh execution broker repository carries the latest prior
        // candidate for this task when one exists. Fetch it fail-closed so a
        // reused workspace that lost the local branch (or never saw the
        // candidate) still starts with the prior delta available.
        let seed = fetch_seeded_candidate(path, &branch_ref, git_auth).await?;
        checkout_task_branch(path, &branch).await?;
        let preserved = if seed == SeedFetch::Present {
            restore_seeded_candidate_tree(path, assignment).await?
        } else {
            None
        };
        merge_ref_into_head(path, assignment, &base).await?;
        return Ok((base, preserved));
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
    // A manually retried task seeds its prior candidate into the fresh
    // execution repository. Check it out when present so the next attempt
    // starts with the candidate delta available; a genuinely fresh task has
    // no such ref and still starts from the current base.
    match fetch_seeded_candidate(path, &branch_ref, git_auth).await? {
        SeedFetch::Present => {
            command_ok(path, "git", &["checkout", "-b", &branch, SEEDED_CANDIDATE_REF]).await?;
            merge_ref_into_head(path, assignment, &base).await?;
        }
        SeedFetch::Absent => {
            command_ok(path, "git", &["checkout", "-b", &branch]).await?;
        }
    }
    Ok((base, None))
}

/// Append the preservation record to the attempt prompt so the resumed agent
/// sees what a previous attempt changed relative to the restored candidate.
/// The worktree the agent receives is the last valid candidate; the record
/// below lets it salvage useful exploration without blindly reapplying
/// whatever reverted or broke the previous attempt.
fn with_preserved_attempt_context(prompt: String, preserved: &PreservedAttempt) -> String {
    let files = if preserved.files.is_empty() {
        "(no content differences)".to_string()
    } else {
        preserved.files.iter().map(|file| format!("- {file}")).collect::<Vec<_>>().join("\n")
    };
    format!(
        "{prompt}\n\nPrior attempt context (preserved retry state):\nThe workspace diverged from the last valid implementation candidate (unpushed or uncommitted work from a failed attempt). That state was preserved on local branch `{}` and the worktree was restored to the last valid candidate, which is what you see now. Salvage anything useful, but do not blindly reapply it: it may contain the revert or breakage that failed.\n\nChanged files versus the restored candidate:\n{files}\n\nDiffstat versus the restored candidate:\n{}\n\nUnified diff versus the restored candidate (truncated):\n{}",
        preserved.backup_branch, preserved.stat, preserved.diff,
    )
}

/// Stable local ref holding a prior candidate fetched from the current
/// execution broker repository. Only ever sourced from `origin` (this
/// execution's task repository, which the server seeds solely from completed
/// executions of the same task); reviewer checkouts are never fetched here.
const SEEDED_CANDIDATE_REF: &str = "refs/lazyteam/seeded-candidate";

/// Fetch outcome for the server-seeded prior candidate branch.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum SeedFetch {
    Present,
    Absent,
}

/// Fetch of the task branch seeded by the server into the fresh execution
/// repository. Fail-closed: when origin advertises the branch but the fetch
/// fails (or the fetch cannot even confirm absence), the error propagates so
/// the attempt fails instead of silently restarting from base and
/// reproducing the no-tracked-change failure. Only a confirmed-absent ref
/// (genuinely fresh task) proceeds as [`SeedFetch::Absent`].
async fn fetch_seeded_candidate(path: &Path, branch_ref: &str, git_auth: &GitAuthContext) -> anyhow::Result<SeedFetch> {
    let mut command = trusted_git_command();
    command.args(["fetch", "origin", &format!("+{branch_ref}:{SEEDED_CANDIDATE_REF}")]).current_dir(path);
    git_auth.apply(&mut command);
    let fetch = command.output().await?;
    if fetch.status.success() && seeded_candidate_present(path).await {
        let sha = git_output(path, &["rev-parse", "--verify", SEEDED_CANDIDATE_REF]).await?;
        if !sha.trim().is_empty() {
            return Ok(SeedFetch::Present);
        }
    }
    if origin_advertises_branch(path, branch_ref, git_auth).await? {
        bail!(
            "prior candidate branch {branch_ref} exists on the execution repository but could not be fetched: {}",
            String::from_utf8_lossy(&fetch.stderr).trim()
        );
    }
    Ok(SeedFetch::Absent)
}

/// Confirm via the execution repository whether the seeded branch exists.
/// Errors propagate (fail closed): an unreachable origin must not be
/// mistaken for a genuinely fresh task.
async fn origin_advertises_branch(path: &Path, branch_ref: &str, git_auth: &GitAuthContext) -> anyhow::Result<bool> {
    let mut command = trusted_git_command();
    command.args(["ls-remote", "origin", branch_ref]).current_dir(path);
    git_auth.apply(&mut command);
    let output = command.output().await?;
    if !output.status.success() {
        bail!(
            "cannot verify whether a prior candidate exists on the execution repository: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(!String::from_utf8(output.stdout).context("decode ls-remote output")?.trim().is_empty())
}

/// Restore the trusted worktree to the last valid (server-seeded) candidate
/// tree. A failed attempt can leave the reused branch at a descendant commit
/// (e.g. an unpushed revert/overwrite, committed before the failed push) or
/// a dirty worktree (staged, uncommitted, or untracked changes, or an
/// unfinished conflicted merge); ancestry merging would then keep the revert
/// and hide the prior delta from the agent.
///
/// Nothing is discarded: dirty worktree state is committed first so staged,
/// uncommitted, and untracked failed-attempt work is preserved, and the
/// pre-reset HEAD is kept on a verified backup branch. Backup creation is
/// fail-closed, and no `clean` is used, so candidate-related changes cannot
/// be silently lost.
///
/// Returns the agent-visible preservation record when a restore ran, so the
/// resumed agent can see what the failed attempt changed relative to the
/// restored candidate. Returns `None` when the workspace already matches
/// the candidate and no restore was needed.
async fn restore_seeded_candidate_tree(
    path: &Path,
    assignment: &Assignment,
) -> anyhow::Result<Option<PreservedAttempt>> {
    let seeded = git_output(path, &["rev-parse", "--verify", SEEDED_CANDIDATE_REF]).await?;
    let mut head = git_output(path, &["rev-parse", "HEAD"]).await?;
    // A failed attempt can also leave an uncommitted revert/overwrite or an
    // unfinished conflicted merge on top of the right commit, which would
    // likewise hide the prior delta from the agent.
    let dirty = !git_output(path, &["status", "--porcelain"]).await?.trim().is_empty()
        || git_output(path, &["rev-parse", "--verify", "MERGE_HEAD"]).await.is_ok();
    if head == seeded && !dirty {
        return Ok(None);
    }
    if dirty {
        // Commit staged, uncommitted, and untracked (`-A`) worktree state
        // before resetting, so failed-attempt work survives on the backup
        // branch instead of being discarded by the reset.
        command_ok(path, "git", &["add", "-A"]).await?;
        let commit = trusted_git_command()
            .args([
                "-c",
                &format!("user.name={}", assignment.project.contributor.name),
                "-c",
                &format!("user.email={}", assignment.project.contributor.email),
                "commit",
                "-m",
                "lazyteam: preserve pre-retry worktree",
            ])
            .current_dir(path)
            .output()
            .await?;
        if !commit.status.success() {
            let still_dirty = !git_output(path, &["status", "--porcelain"]).await?.trim().is_empty()
                || git_output(path, &["rev-parse", "--verify", "MERGE_HEAD"]).await.is_ok();
            if still_dirty {
                bail!(
                    "cannot preserve pre-retry worktree changes: {}",
                    String::from_utf8_lossy(&commit.stderr).trim()
                );
            }
        }
        head = git_output(path, &["rev-parse", "HEAD"]).await?;
    }
    // The worktree is committed now, so the reset cannot discard uncommitted
    // state; the backup branch keeps the failed-attempt HEAD reachable.
    let backup = format!("lazyteam/retry-backup-{}", head.chars().take(12).collect::<String>());
    if trusted_git_command()
        .args(["branch", "--no-track", &backup, &head])
        .current_dir(path)
        .status()
        .await?
        .success()
    {
        let created = git_output(path, &["rev-parse", "--verify", &format!("refs/heads/{backup}")]).await?;
        if created != head {
            bail!("retry backup branch {backup} verification failed");
        }
    } else {
        // A rerun may race an identical backup name; tolerate it only when it
        // already points at exactly this HEAD, and fail otherwise.
        let existing = git_output(path, &["rev-parse", "--verify", &format!("refs/heads/{backup}")]).await?;
        if existing != head {
            bail!("retry backup branch {backup} already exists for a different commit");
        }
    }
    command_ok(path, "git", &["reset", "--hard", SEEDED_CANDIDATE_REF]).await?;
    Ok(Some(summarize_preserved_attempt(path, &backup, &seeded).await?))
}

/// Build the agent-visible record of what the preserved pre-reset HEAD
/// changed relative to the restored candidate: changed files, diffstat, and
/// a bounded unified diff. All reads come from committed objects, so the
/// record is exact.
async fn summarize_preserved_attempt(path: &Path, backup: &str, seeded: &str) -> anyhow::Result<PreservedAttempt> {
    let files = git_output(path, &["diff", "--no-ext-diff", "--name-only", seeded, backup, "--"])
        .await
        .unwrap_or_default()
        .lines()
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    let stat = git_output(path, &["diff", "--no-ext-diff", "--stat", seeded, backup, "--"])
        .await
        .unwrap_or_default();
    let raw_diff = git_output(path, &["diff", "--no-ext-diff", "--unified=3", seeded, backup, "--"])
        .await
        .unwrap_or_default();
    let (diff, truncated) = truncate_text(raw_diff, PRESERVED_DIFF_MAX_BYTES);
    let diff = if truncated {
        format!("{diff}\n\n[LazyTeam preserved-attempt diff truncated]")
    } else if diff.is_empty() {
        "(no content differences)".to_string()
    } else {
        diff
    };
    Ok(PreservedAttempt {
        backup_branch: backup.to_string(),
        files,
        stat: if stat.trim().is_empty() { "(no content differences)".to_string() } else { stat },
        diff,
    })
}

/// Truncate text to at most `max_bytes` on a character boundary.
fn truncate_text(mut text: String, max_bytes: usize) -> (String, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }
    let mut end = max_bytes.min(text.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    (text, true)
}

async fn seeded_candidate_present(path: &Path) -> bool {
    trusted_git_command()
        .args(["rev-parse", "--verify", SEEDED_CANDIDATE_REF])
        .current_dir(path)
        .output()
        .await
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Check out the task branch, falling back to the seeded prior candidate (or
/// a fresh branch from the current HEAD) when the local branch is missing.
async fn checkout_task_branch(path: &Path, branch: &str) -> anyhow::Result<()> {
    if trusted_git_command().args(["checkout", branch]).current_dir(path).status().await?.success() {
        return Ok(());
    }
    if seeded_candidate_present(path).await {
        command_ok(path, "git", &["checkout", "-b", branch, SEEDED_CANDIDATE_REF]).await
    } else {
        command_ok(path, "git", &["checkout", "-b", branch]).await
    }
}

/// Merge `revision` (a base SHA or the seeded candidate ref) into the task
/// branch using the existing task-branch rules: fast-forward/no-op when
/// already contained, real merge otherwise, and merge conflicts left in the
/// worktree for the agent to resolve instead of silently dropping changes.
async fn merge_ref_into_head(path: &Path, assignment: &Assignment, revision: &str) -> anyhow::Result<()> {
    if revision == SEEDED_CANDIDATE_REF && !seeded_candidate_present(path).await {
        return Ok(());
    }
    let already_based = trusted_git_command().args(["merge-base", "--is-ancestor", revision, "HEAD"]).current_dir(path).status().await?;
    if !already_based.success() {
        let merge = trusted_git_command()
            .args(["-c", &format!("user.name={}", assignment.project.contributor.name)])
            .args(["-c", &format!("user.email={}", assignment.project.contributor.email)])
            .args(["merge", "--no-edit", revision])
            .current_dir(path)
            .output().await?;
        if !merge.status.success() {
            let conflicts = git_output(path, &["diff", "--name-only", "--diff-filter=U"]).await.unwrap_or_default();
            if conflicts.trim().is_empty() {
                bail!("merge {} into task branch failed: {}", revision, String::from_utf8_lossy(&merge.stderr));
            }
            warn!(%conflicts, "task retry opened with merge conflicts for the agent to resolve");
        }
    }
    Ok(())
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
    use lazyteam_core::{host_selection_available, AgentModel};

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
    fn legacy_pi_selection_flags_are_removed() {
        use clap::Parser;
        assert!(Args::try_parse_from(["lazyteam-worker", "--pi-provider", "legacy"]).is_err());
        assert!(Args::try_parse_from(["lazyteam-worker", "--pi-model", "legacy"]).is_err());
        let args = Args::try_parse_from(["lazyteam-worker"]).unwrap();
        assert_eq!(args.pi_bin, "pi");
    }

    #[tokio::test]
    async fn slot_runtime_uses_only_host_owned_agent_selection() {
        let root = std::env::temp_dir().join(format!("lazyteam-runtime-selection-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let sandbox = AgentSandbox::prepare(&root, "pi", None).await.unwrap();
        let hosted = AgentConfig {
            agent_type: "pi".into(),
            provider: Some("host-provider".into()),
            model: Some("host-model".into()),
            initial_prompt: "prompt".into(),
        };
        let runtime = runtime_for_config(&hosted, "pi", root.join("session-a"), sandbox.clone()).unwrap();
        assert_eq!(runtime.provider.as_deref(), Some("host-provider"));
        assert_eq!(runtime.model.as_deref(), Some("host-model"));
        let unset = AgentConfig {
            agent_type: "pi".into(),
            provider: None,
            model: None,
            initial_prompt: "prompt".into(),
        };
        let runtime = runtime_for_config(&unset, "pi", root.join("session-b"), sandbox).unwrap();
        assert_eq!(runtime.provider, None);
        assert_eq!(runtime.model, None);
        let _ = tokio::fs::remove_dir_all(&root).await;
    }

    fn catalog_with(provider: &str, id: &str) -> AgentCapabilities {
        AgentCapabilities {
            models: vec![AgentModel {
                provider: provider.into(),
                id: id.into(),
                name: None,
                context_window: None,
                reasoning: false,
                cost: None,
            }],
            ..Default::default()
        }
    }

    fn nonempty_catalog() -> AgentCapabilities {
        catalog_with("host-provider", "host-model")
    }

    #[test]
    fn worker_stays_idle_without_host_agent_selection() {
        let catalog = nonempty_catalog();
        let unselected = AgentConfig {
            agent_type: "pi".into(),
            provider: None,
            model: None,
            initial_prompt: "prompt".into(),
        };
        // Nonempty Pi catalog with null Host selection must not become eligible.
        assert!(!can_claim_work(&unselected, &catalog));
        assert!(!can_claim_work(&unselected, &AgentCapabilities::default()));
        let half_selected = AgentConfig {
            agent_type: "pi".into(),
            provider: Some("host-provider".into()),
            model: None,
            initial_prompt: "prompt".into(),
        };
        assert!(!can_claim_work(&half_selected, &catalog));
        let selected = AgentConfig {
            agent_type: "pi".into(),
            provider: Some("host-provider".into()),
            model: Some("host-model".into()),
            initial_prompt: "prompt".into(),
        };
        assert!(can_claim_work(&selected, &catalog));
        assert!(!can_claim_work(&selected, &AgentCapabilities::default()));
    }

    #[test]
    fn worker_stays_idle_when_host_selection_absent_from_catalog() {
        let selected = AgentConfig {
            agent_type: "pi".into(),
            provider: Some("host-provider".into()),
            model: Some("host-model".into()),
            initial_prompt: "prompt".into(),
        };
        // Refreshed probe reports only unrelated models: the Host selection is
        // preserved (never cleared, never substituted) but unavailable, so the
        // worker cannot claim implementation or review work.
        let unrelated = catalog_with("other-provider", "other-model");
        assert!(!can_claim_work(&selected, &unrelated));
        assert!(!host_selection_available(&selected, &unrelated));
        assert_eq!(selected.provider.as_deref(), Some("host-provider"));
        assert_eq!(selected.model.as_deref(), Some("host-model"));
        assert!(host_selection_available(&selected, &nonempty_catalog()));
        assert!(can_claim_work(&selected, &nonempty_catalog()));
    }

    #[test]
    fn host_agent_selection_requires_nonblank_provider_and_model() {
        let selected = AgentConfig {
            agent_type: "pi".into(),
            provider: Some("host-provider".into()),
            model: Some("host-model".into()),
            initial_prompt: "prompt".into(),
        };
        assert!(host_agent_selection_ready(&selected));
        for (provider, model) in [
            (None, None),
            (Some("host-provider"), None),
            (None, Some("host-model")),
            (Some(""), Some("host-model")),
            (Some("host-provider"), Some("   ")),
        ] {
            let agent = AgentConfig {
                agent_type: "pi".into(),
                provider: provider.map(str::to_string),
                model: model.map(str::to_string),
                initial_prompt: "prompt".into(),
            };
            assert!(!host_agent_selection_ready(&agent));
        }
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
            integration: None,
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
                "git_auth": {"mode": "host", "credential_configured": false},
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

    fn workspace_test_assignment(repo_url: &str, task_id: Uuid, project_id: Uuid, attempt: u32) -> Assignment {
        serde_json::from_value(json!({
            "project": {
                "id": project_id,
                "slug": "test-project",
                "name": "Test Project",
                "repo_url": repo_url,
                "default_branch": "main",
                "contributor": {"name": "Project Contributor", "email": "project@example.test"},
                "required_worker_tags": {},
                "default_task_tags": {},
                "git_auth": {"mode": "host", "credential_configured": false},
                "enabled": true,
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            },
            "task": {
                "id": task_id,
                "project_id": project_id,
                "title": "Amend prior candidate",
                "description": "",
                "expected_outcome": "",
                "acceptance_criteria": [],
                "required_tags": {},
                "preferred_tags": {},
                "dependencies": [],
                "review_feedback": "manual retry: amend prior candidate",
                "priority": 0,
                "state": "running",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z"
            },
            "execution": {
                "id": Uuid::new_v4(),
                "task_id": task_id,
                "worker_id": Uuid::new_v4(),
                "attempt": attempt,
                "state": "assigned",
                "lease_until": "2026-01-01T00:02:00Z",
                "started_at": null,
                "finished_at": null,
                "result": null
            },
            "lease_capability": "test-lease-capability"
        })).unwrap()
    }

    async fn git_commit_file(workdir: &Path, name: &str, content: &str, message: &str) {
        tokio::fs::write(workdir.join(name), content).await.unwrap();
        command_ok(workdir, "git", &["add", name]).await.unwrap();
        command_ok(workdir, "git", &["commit", "-m", message]).await.unwrap();
    }

    async fn init_broker_with_base(root: &Path) -> (PathBuf, PathBuf, String) {
        let broker = root.join("broker.git");
        command_ok(root, "git", &["init", "--bare", broker.to_str().unwrap()]).await.unwrap();
        let work = root.join("seed");
        command_ok(root, "git", &["clone", broker.to_str().unwrap(), work.to_str().unwrap()]).await.unwrap();
        command_ok(&work, "git", &["config", "user.name", "LazyTeam Test"]).await.unwrap();
        command_ok(&work, "git", &["config", "user.email", "lazyteam-test@local"]).await.unwrap();
        git_commit_file(&work, "base.txt", "base\n", "base").await;
        command_ok(&work, "git", &["branch", "-M", "main"]).await.unwrap();
        command_ok(&work, "git", &["push", "origin", "refs/heads/main:refs/heads/main"]).await.unwrap();
        let base = git_output(&work, &["rev-parse", "HEAD"]).await.unwrap();
        (broker, work, base)
    }

    /// Manual retry into a fresh workspace must start with the seeded prior
    /// candidate checked out, merged with the current base when main
    /// advanced. Pre-fix this started from a bare base with no candidate
    /// delta, so an agent that (correctly) made no new change hit
    /// `agent completed without producing any tracked change`.
    #[tokio::test]
    async fn prepare_workspace_restores_seeded_candidate_and_merges_advanced_base() {
        let root = std::env::temp_dir().join(format!("lazyteam-ws-seed-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let (broker, work, _) = init_broker_with_base(&root).await;
        let task_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let branch = format!("lazyteam/task-{}", task_id.simple());
        // Server-seeded prior candidate on the execution broker repository.
        command_ok(&work, "git", &["checkout", "-b", &branch]).await.unwrap();
        git_commit_file(&work, "fix.txt", "prior candidate\n", "lazyteam: amend prior candidate").await;
        command_ok(&work, "git", &["push", "origin", &format!("HEAD:refs/heads/{branch}")]).await.unwrap();
        // Main advances after the candidate was produced.
        command_ok(&work, "git", &["checkout", "main"]).await.unwrap();
        git_commit_file(&work, "base2.txt", "advanced\n", "upstream advance").await;
        command_ok(&work, "git", &["push", "origin", "refs/heads/main:refs/heads/main"]).await.unwrap();
        let new_base = git_output(&work, &["rev-parse", "refs/heads/main"]).await.unwrap();

        let workspace = root.join("workspace");
        let assignment = workspace_test_assignment(broker.to_str().unwrap(), task_id, project_id, 3);
        let auth = GitAuthContext::broker("worker-secret", "lease-secret");
        let (base, _) = prepare_workspace(&workspace, &assignment, &auth).await.unwrap();
        assert_eq!(base, new_base);
        assert_eq!(tokio::fs::read_to_string(workspace.join("fix.txt")).await.unwrap(), "prior candidate\n");
        assert_eq!(tokio::fs::read_to_string(workspace.join("base2.txt")).await.unwrap(), "advanced\n");
        assert_eq!(git_output(&workspace, &["rev-parse", "--abbrev-ref", "HEAD"]).await.unwrap(), branch);
        assert!(trusted_git_command().args(["merge-base", "--is-ancestor", &base, "HEAD"]).current_dir(&workspace).status().await.unwrap().success());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    /// A reused workspace whose local branch lost the candidate (stale local
    /// state on another worker) must still pick up the seeded prior
    /// candidate from the fresh execution repository.
    #[tokio::test]
    async fn prepare_workspace_reused_stale_workspace_picks_up_seeded_candidate() {
        let root = std::env::temp_dir().join(format!("lazyteam-ws-stale-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let (broker, work, _) = init_broker_with_base(&root).await;
        let task_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let branch = format!("lazyteam/task-{}", task_id.simple());
        // Stale local workspace: task branch exists but has no candidate.
        let workspace = root.join("workspace");
        command_ok(root.as_path(), "git", &["clone", "--branch", "main", "--single-branch", broker.to_str().unwrap(), workspace.to_str().unwrap()]).await.unwrap();
        command_ok(&workspace, "git", &["checkout", "-b", &branch]).await.unwrap();
        // Server-seeded prior candidate appears on the fresh broker repo.
        command_ok(&work, "git", &["checkout", "-b", &branch]).await.unwrap();
        git_commit_file(&work, "fix.txt", "prior candidate\n", "lazyteam: amend prior candidate").await;
        command_ok(&work, "git", &["push", "origin", &format!("HEAD:refs/heads/{branch}")]).await.unwrap();

        let assignment = workspace_test_assignment(broker.to_str().unwrap(), task_id, project_id, 3);
        let auth = GitAuthContext::broker("worker-secret", "lease-secret");
        prepare_workspace(&workspace, &assignment, &auth).await.unwrap();
        assert_eq!(tokio::fs::read_to_string(workspace.join("fix.txt")).await.unwrap(), "prior candidate\n");
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    /// A failed attempt can leave the reused branch at a descendant commit
    /// (e.g. a committed revert of the candidate, auto-committed before the
    /// failed push). Ancestry merging would keep the revert and hide the
    /// prior delta; the candidate tree must be restored instead.
    #[tokio::test]
    async fn prepare_workspace_descendant_revert_restores_candidate_tree() {
        let root = std::env::temp_dir().join(format!("lazyteam-ws-descendant-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let (broker, work, _) = init_broker_with_base(&root).await;
        let task_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let branch = format!("lazyteam/task-{}", task_id.simple());
        command_ok(&work, "git", &["checkout", "-b", &branch]).await.unwrap();
        git_commit_file(&work, "fix.txt", "prior candidate\n", "lazyteam: amend prior candidate").await;
        command_ok(&work, "git", &["push", "origin", &format!("HEAD:refs/heads/{branch}")]).await.unwrap();
        let seeded = git_output(&work, &["rev-parse", "HEAD"]).await.unwrap();
        // Reused workspace at a descendant that reverts the candidate.
        let workspace = root.join("workspace");
        command_ok(root.as_path(), "git", &["clone", broker.to_str().unwrap(), workspace.to_str().unwrap()]).await.unwrap();
        command_ok(&workspace, "git", &["checkout", &branch]).await.unwrap();
        command_ok(&workspace, "git", &["config", "user.name", "LazyTeam Test"]).await.unwrap();
        command_ok(&workspace, "git", &["config", "user.email", "lazyteam-test@local"]).await.unwrap();
        command_ok(&workspace, "git", &["revert", "--no-edit", "HEAD"]).await.unwrap();
        assert!(!workspace.join("fix.txt").exists());

        let assignment = workspace_test_assignment(broker.to_str().unwrap(), task_id, project_id, 3);
        let auth = GitAuthContext::broker("worker-secret", "lease-secret");
        let (base, preserved) = prepare_workspace(&workspace, &assignment, &auth).await.unwrap();
        assert_eq!(tokio::fs::read_to_string(workspace.join("fix.txt")).await.unwrap(), "prior candidate\n");
        assert_eq!(git_output(&workspace, &["rev-parse", "HEAD"]).await.unwrap(), seeded);
        // The preservation record is agent-visible: the reverted content is
        // described relative to the restored candidate.
        let preserved = preserved.expect("descendant restore must yield a preservation record");
        assert!(preserved.files.iter().any(|file| file == "fix.txt"));
        assert!(preserved.diff.contains("prior candidate"), "unexpected diff: {}", preserved.diff);
        // The sandbox the agent actually receives carries the restored
        // candidate tree.
        let agent = root.join("agent");
        prepare_agent_workspace(&workspace, &agent, Some(&base)).await.unwrap();
        assert_eq!(tokio::fs::read_to_string(agent.join("fix.txt")).await.unwrap(), "prior candidate\n");
        // The attempt prompt surfaces the record to the resumed agent.
        let prompt = with_preserved_attempt_context("base prompt".to_string(), &preserved);
        assert!(prompt.contains(&preserved.backup_branch));
        assert!(prompt.contains("prior candidate"));
        // The pre-reset descendant is preserved for forensics, not dropped.
        assert!(!git_output(&workspace, &["for-each-ref", "refs/heads/lazyteam/retry-backup-*"]).await.unwrap().is_empty());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    /// A failed attempt can also leave an uncommitted revert/overwrite on an
    /// otherwise current branch; the candidate tree must still be restored
    /// so the agent sees the prior delta.
    #[tokio::test]
    async fn prepare_workspace_dirty_revert_restores_candidate_tree() {
        let root = std::env::temp_dir().join(format!("lazyteam-ws-dirty-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let (broker, work, _) = init_broker_with_base(&root).await;
        let task_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let branch = format!("lazyteam/task-{}", task_id.simple());
        command_ok(&work, "git", &["checkout", "-b", &branch]).await.unwrap();
        git_commit_file(&work, "fix.txt", "prior candidate\n", "lazyteam: amend prior candidate").await;
        command_ok(&work, "git", &["push", "origin", &format!("HEAD:refs/heads/{branch}")]).await.unwrap();
        let workspace = root.join("workspace");
        command_ok(root.as_path(), "git", &["clone", broker.to_str().unwrap(), workspace.to_str().unwrap()]).await.unwrap();
        command_ok(&workspace, "git", &["checkout", &branch]).await.unwrap();
        tokio::fs::write(workspace.join("fix.txt"), "tampered\n").await.unwrap();

        let assignment = workspace_test_assignment(broker.to_str().unwrap(), task_id, project_id, 3);
        let auth = GitAuthContext::broker("worker-secret", "lease-secret");
        let (base, preserved) = prepare_workspace(&workspace, &assignment, &auth).await.unwrap();
        assert_eq!(tokio::fs::read_to_string(workspace.join("fix.txt")).await.unwrap(), "prior candidate\n");
        // The preservation record is agent-visible: it describes the
        // tampered content versus the restored candidate.
        let preserved = preserved.expect("dirty restore must yield a preservation record");
        assert!(preserved.files.iter().any(|file| file == "fix.txt"));
        assert!(preserved.diff.contains("tampered"), "unexpected diff: {}", preserved.diff);
        // The sandbox the agent actually receives carries the restored
        // candidate tree.
        let agent = root.join("agent");
        prepare_agent_workspace(&workspace, &agent, Some(&base)).await.unwrap();
        assert_eq!(tokio::fs::read_to_string(agent.join("fix.txt")).await.unwrap(), "prior candidate\n");
        // The attempt prompt surfaces the record to the resumed agent.
        let prompt = with_preserved_attempt_context("base prompt".to_string(), &preserved);
        assert!(prompt.contains(&preserved.backup_branch));
        assert!(prompt.contains("tampered"));
        // The tampered uncommitted work is preserved on the backup branch,
        // not discarded: nothing staged, uncommitted, or untracked is lost.
        let backup = git_output(&workspace, &["for-each-ref", "--format=%(refname:short)", "refs/heads/lazyteam/retry-backup-*"])
            .await
            .unwrap();
        assert!(!backup.trim().is_empty());
        let preserved = git_output(&workspace, &["show", &format!("{}:fix.txt", backup.lines().next().unwrap().trim())])
            .await
            .unwrap();
        assert_eq!(preserved, "tampered");
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    /// Fail-closed fetch: when the execution repository advertises the task
    /// branch but its objects cannot be fetched, preparation must error
    /// instead of silently restarting from base.
    #[tokio::test]
    async fn prepare_workspace_seed_fetch_failure_is_fail_closed() {
        let root = std::env::temp_dir().join(format!("lazyteam-ws-fetchfail-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let (broker, _, _) = init_broker_with_base(&root).await;
        let task_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        // Advertise a task branch whose objects are missing: ls-remote sees
        // the ref, but fetching it fails. Written directly because
        // update-ref refuses a nonexistent object.
        let ref_path = broker.join("refs").join("heads").join("lazyteam").join(format!("task-{}", task_id.simple()));
        tokio::fs::create_dir_all(ref_path.parent().unwrap()).await.unwrap();
        tokio::fs::write(&ref_path, format!("{}\n", "a".repeat(40))).await.unwrap();
        let workspace = root.join("workspace");
        let assignment = workspace_test_assignment(broker.to_str().unwrap(), task_id, project_id, 3);
        let auth = GitAuthContext::broker("worker-secret", "lease-secret");
        let error = prepare_workspace(&workspace, &assignment, &auth).await.expect_err("unfetchable candidate must fail closed");
        assert!(error.to_string().contains("could not be fetched"), "unexpected error: {error}");
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[test]
    fn tracked_change_guard_compares_trees_not_commit_shas() {
        // Identical trees fail even with distinct commit SHAs, so the
        // zero-change completion error is preserved.
        assert!(ensure_tracked_change("tree-abc", "tree-abc").is_err());
        let error = ensure_tracked_change("tree-abc", "tree-abc").unwrap_err();
        assert!(error.to_string().contains("without producing any tracked change"));
        // Retry that restored the prior candidate ends at the candidate
        // tree: amending-by-keeping passes the guard.
        assert!(ensure_tracked_change("candidate-tree", "base-tree").is_ok());
    }

    /// An empty (or equivalent-tree) commit on top of the base resolves to
    /// the same tree and must still trip the zero-change guard, while a
    /// real content change passes it.
    #[tokio::test]
    async fn tracked_change_guard_rejects_empty_commit_with_identical_tree() {
        let root = std::env::temp_dir().join(format!("lazyteam-guard-tree-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let repo = root.join("repo");
        command_ok(&root, "git", &["init", repo.to_str().unwrap()]).await.unwrap();
        command_ok(&repo, "git", &["config", "user.name", "LazyTeam Test"]).await.unwrap();
        command_ok(&repo, "git", &["config", "user.email", "lazyteam-test@local"]).await.unwrap();
        git_commit_file(&repo, "base.txt", "base\n", "base").await;
        let base_tree = git_output(&repo, &["rev-parse", "HEAD^{tree}"]).await.unwrap();
        // Empty commit: new SHA, identical tree. SHA comparison would pass
        // this; tree comparison must reject it.
        let head = git_output(&repo, &["rev-parse", "HEAD"]).await.unwrap();
        command_ok(&repo, "git", &["commit", "--allow-empty", "-m", "empty"]).await.unwrap();
        let empty_head = git_output(&repo, &["rev-parse", "HEAD"]).await.unwrap();
        assert_ne!(head, empty_head, "empty commit must mint a new SHA for this test to be meaningful");
        let empty_tree = git_output(&repo, &["rev-parse", "HEAD^{tree}"]).await.unwrap();
        assert_eq!(empty_tree, base_tree);
        let error = ensure_tracked_change(&empty_tree, &base_tree).unwrap_err();
        assert!(error.to_string().contains("without producing any tracked change"));
        // Real content change passes.
        git_commit_file(&repo, "fix.txt", "fix\n", "real change").await;
        let changed_tree = git_output(&repo, &["rev-parse", "HEAD^{tree}"]).await.unwrap();
        assert!(ensure_tracked_change(&changed_tree, &base_tree).is_ok());
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    /// A genuinely fresh task (no seeded candidate) still starts from the
    /// current base with HEAD == base, so the existing no-tracked-change
    /// guard keeps applying when the agent produces nothing.
    #[tokio::test]
    async fn prepare_workspace_fresh_task_starts_from_base_without_candidate() {
        let root = std::env::temp_dir().join(format!("lazyteam-ws-fresh-{}", Uuid::new_v4()));
        tokio::fs::create_dir_all(&root).await.unwrap();
        let (broker, _, base) = init_broker_with_base(&root).await;
        let task_id = Uuid::new_v4();
        let project_id = Uuid::new_v4();
        let workspace = root.join("workspace");
        let assignment = workspace_test_assignment(broker.to_str().unwrap(), task_id, project_id, 1);
        let auth = GitAuthContext::broker("worker-secret", "lease-secret");
        let (returned_base, preserved) = prepare_workspace(&workspace, &assignment, &auth).await.unwrap();
        assert!(preserved.is_none(), "fresh task must not produce a preservation record");
        assert_eq!(returned_base, base);
        let head = git_output(&workspace, &["rev-parse", "HEAD"]).await.unwrap();
        assert_eq!(head, base, "fresh task must start with no tracked delta so the no-change guard still applies");
        assert!(!seeded_candidate_present(&workspace).await);
        let _ = tokio::fs::remove_dir_all(root).await;
    }

    #[test]
    fn oauth_paste_waiter_honors_prompt_abort_signal() {
        // Pi aborts the concurrent `manual_code` prompt when its
        // worker-local localhost callback wins the race. The injected
        // waiter must observe `prompt.signal`, pre-reject when already
        // aborted, subscribe for later aborts, and always close the
        // readline interface so neither Node nor the Rust driver hangs.
        assert!(OAUTH_READ_PASTED_LINE_JS.contains("readPastedLine(signal)"));
        assert!(OAUTH_READ_PASTED_LINE_JS.contains("signal.aborted"));
        assert!(OAUTH_READ_PASTED_LINE_JS.contains("addEventListener(\"abort\""));
        assert!(OAUTH_READ_PASTED_LINE_JS.contains("rl.close()"));
        assert!(OAUTH_READ_PASTED_LINE_JS.contains("Login cancelled"));
    }

    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct AbortFlag(Arc<AtomicBool>);

    impl Drop for AbortFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    /// Deterministic driver harness: wire lines are fed through a duplex the
    /// test controls (no EOF races), and the Host poll resolves only when the
    /// test sends through a oneshot. Every step is observed with timeouts, so
    /// scheduling races cannot decide the outcome.
    struct GatedDriver {
        feed: tokio::io::DuplexStream,
        stdin_view: tokio::io::DuplexStream,
        reports: Arc<tokio::sync::Mutex<Vec<AgentOAuthEventReport>>>,
        poll_aborted: Arc<AtomicBool>,
        input_tx: Option<tokio::sync::oneshot::Sender<Option<AgentOAuthInputDelivery>>>,
        acked: Arc<tokio::sync::Mutex<Vec<Uuid>>>,
        outcome: tokio::task::JoinHandle<OAuthDriverOutcome>,
    }

    impl GatedDriver {
        fn spawn() -> Self {
            let (feed_read, feed) = tokio::io::duplex(4096);
            let (helper_stdin, stdin_view) = tokio::io::duplex(4096);
            let reports = Arc::new(tokio::sync::Mutex::new(Vec::new()));
            let poll_aborted = Arc::new(AtomicBool::new(false));
            let (input_tx, input_rx) = tokio::sync::oneshot::channel::<Option<AgentOAuthInputDelivery>>();
            let input_cell = Arc::new(tokio::sync::Mutex::new(Some(input_rx)));
            let acked = Arc::new(tokio::sync::Mutex::new(Vec::new()));
            let worker_reports = reports.clone();
            let worker_aborted = poll_aborted.clone();
            let worker_acked = acked.clone();
            let outcome = tokio::spawn(drive_oauth_wire_loop(
                feed_read,
                helper_stdin,
                move |event: AgentOAuthEventReport| {
                    let worker_reports = worker_reports.clone();
                    async move {
                        worker_reports.lock().await.push(event);
                    }
                },
                move || {
                    let input_cell = input_cell.clone();
                    let worker_aborted = worker_aborted.clone();
                    tokio::spawn(async move {
                        // Drop guard proves the task is reclaimed on abort.
                        // The driver always pends on helper stdout after
                        // spawning the poll, so the scheduler runs the poll
                        // task (constructing the guard) before any abort that
                        // the test can subsequently trigger.
                        let _guard = AbortFlag(worker_aborted);
                        match input_cell.lock().await.take() {
                            Some(rx) => rx.await.unwrap_or(None),
                            None => std::future::pending().await,
                        }
                    })
                },
                move |input_id| {
                    let worker_acked = worker_acked.clone();
                    async move {
                        worker_acked.lock().await.push(input_id);
                    }
                },
            ));
            Self {
                feed,
                stdin_view,
                reports,
                poll_aborted,
                input_tx: Some(input_tx),
                acked,
                outcome,
            }
        }

        async fn feed_line(&mut self, line: &str) {
            use tokio::io::AsyncWriteExt;
            let mut wire = line.as_bytes().to_vec();
            wire.push(b'\n');
            self.feed.write_all(&wire).await.expect("feed wire line");
        }

        async fn wait_for_reports(&self, count: usize) {
            let _ = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if self.reports.lock().await.len() >= count {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("reports must arrive");
        }

        fn answer_poll(&mut self, value: Option<String>) -> Option<Uuid> {
            let id = value.as_ref().map(|_| Uuid::new_v4());
            let delivery = value.map(|input| AgentOAuthInputDelivery {
                id: id.expect("delivery id exists for pasted input"),
                input,
            });
            self.input_tx
                .take()
                .expect("single manual_code prompt per login")
                .send(delivery)
                .expect("poll task must be waiting");
            id
        }

        async fn wait_for_ack(&self, expected: Uuid) {
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if self.acked.lock().await.contains(&expected) {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("input delivery ACK must arrive");
        }

        async fn read_stdin_bytes(&mut self, count: usize) -> Vec<u8> {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; count];
            tokio::time::timeout(Duration::from_secs(10), self.stdin_view.read_exact(&mut buf))
                .await
                .expect("helper stdin bytes must arrive")
                .expect("helper stdin must stay open");
            buf
        }

        /// stdin FIN: the driver shut the write half down (poll timeout path).
        async fn expect_stdin_closed(&mut self) {
            use tokio::io::AsyncReadExt;
            let mut one = [0u8; 1];
            let n = tokio::time::timeout(Duration::from_secs(10), self.stdin_view.read(&mut one))
                .await
                .expect("stdin close must be observable");
            assert_eq!(n.expect("stdin read must succeed"), 0, "helper stdin must be shut down");
        }

        async fn finish(self) -> (OAuthDriverOutcome, Vec<String>, Vec<AgentOAuthEventReport>, Arc<AtomicBool>) {
            let Self { feed, outcome, reports, poll_aborted, .. } = self;
            drop(feed);
            let outcome = tokio::time::timeout(Duration::from_secs(15), outcome)
                .await
                .expect("driver must terminate")
                .expect("driver task must not panic");
            let guarded = reports.lock().await;
            let kinds = guarded.iter().map(|report| report.kind.clone()).collect();
            let messages = guarded.clone();
            drop(guarded);
            (outcome, kinds, messages, poll_aborted)
        }
    }

    async fn wait_poll_aborted(poll_aborted: &Arc<AtomicBool>) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while !poll_aborted.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pending Host poll must be aborted");
    }

    fn wire_prompt() -> String {
        serde_json::json!({"kind": "prompt", "prompt": {"type": "manual_code", "message": "paste it", "placeholder": "http://localhost:1455/auth/callback"}}).to_string()
    }

    #[tokio::test]
    async fn oauth_callback_win_aborts_pending_paste_poll() {
        // Same-machine win: the helper's localhost callback fires while the
        // paste poll is pending, so Pi aborts `manual_code` and the helper
        // prints `complete` without ever reading stdin. The driver must exit
        // promptly with success and abort the stranded poll task.
        let mut driver = GatedDriver::spawn();
        driver.feed_line(&wire_prompt()).await;
        driver.wait_for_reports(1).await;
        driver.feed_line(&serde_json::json!({"kind": "complete"}).to_string()).await;
        let (outcome, kinds, _, poll_aborted) = driver.finish().await;
        assert!(outcome.completed);
        assert!(!outcome.failed_reported);
        assert_eq!(kinds, vec!["awaiting_input", "complete"]);
        wait_poll_aborted(&poll_aborted).await;
    }

    #[tokio::test]
    async fn oauth_cancel_reports_failure_and_aborts_pending_poll() {
        let mut driver = GatedDriver::spawn();
        driver.feed_line(&wire_prompt()).await;
        driver.wait_for_reports(1).await;
        driver
            .feed_line(&serde_json::json!({"kind": "failed", "message": "Login cancelled"}).to_string())
            .await;
        let (outcome, kinds, _, poll_aborted) = driver.finish().await;
        assert!(!outcome.completed);
        assert!(outcome.failed_reported);
        assert_eq!(kinds, vec!["awaiting_input", "failed"]);
        wait_poll_aborted(&poll_aborted).await;
    }

    #[tokio::test]
    async fn oauth_relayed_paste_reaches_helper_stdin() {
        let paste = "http://localhost:1455/auth/callback?code=paste-1&state=s";
        let mut driver = GatedDriver::spawn();
        driver.feed_line(&wire_prompt()).await;
        driver.wait_for_reports(1).await;
        let delivery_id = driver.answer_poll(Some(paste.to_string())).expect("paste delivery id");
        let stdin_bytes = driver.read_stdin_bytes(paste.len() + 1).await;
        assert_eq!(stdin_bytes, format!("{paste}\n").into_bytes());
        driver.wait_for_ack(delivery_id).await;
        let (outcome, kinds, _, _) = driver.finish().await;
        assert!(!outcome.completed);
        assert!(!outcome.failed_reported);
        assert_eq!(kinds, vec!["awaiting_input"]);
    }

    #[tokio::test]
    async fn oauth_post_complete_refresh_failure_is_nonfatal() {
        best_effort_after_oauth_complete(async {
            anyhow::bail!("synthetic post-login refresh failure");
        }).await;
    }

    #[tokio::test]
    async fn oauth_poll_timeout_closes_helper_stdin_and_reports() {
        // No Host input within the poll window: the driver reports failure
        // and shuts down helper stdin so Pi's prompt rejects through its own
        // cancel path instead of waiting forever.
        let mut driver = GatedDriver::spawn();
        driver.feed_line(&wire_prompt()).await;
        driver.wait_for_reports(1).await;
        driver.answer_poll(None);
        driver.wait_for_reports(2).await;
        driver.expect_stdin_closed().await;
        let (outcome, kinds, messages, _) = driver.finish().await;
        assert!(!outcome.completed);
        assert!(outcome.failed_reported);
        assert_eq!(kinds, vec!["awaiting_input", "failed"]);
        assert!(
            messages.iter().any(|report| report.message.as_deref().unwrap_or_default().contains("Timed out waiting")),
            "timeout must be actionable, not a bare failure"
        );
    }
}
