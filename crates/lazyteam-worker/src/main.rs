use std::{collections::{BTreeMap, BTreeSet}, path::{Path, PathBuf}, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use clap::Parser;
use lazyteam_core::{AgentCapabilities, AgentConfig, Assignment, ExecutionResult};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::Deserialize;
use serde_json::json;
use tokio::{process::Command, time::{sleep, Instant}};
use tracing::{error, info, warn};
use uuid::Uuid;

mod runtime;
use runtime::{AgentRuntime, PiRuntime};

const WORKER_CREDENTIAL_HEADER: &str = "x-lazyteam-worker-credential";

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
    agent: AgentConfig,
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
    let args = Args::parse();
    tokio::fs::create_dir_all(&args.state_dir).await?;
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
    let probe_runtime = PiRuntime { binary: pi_bin.clone(), provider: None, model: None };
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
        match claim(&client, &server, &worker_credential, worker_id).await {
            Ok(Some(assignment)) => {
                info!(task = %assignment.task.id, execution = %assignment.execution.id, project = %assignment.project.slug, "claimed task");
                let runtime = match runtime_for_config(&runtime_config.agent, &pi_bin, legacy_provider.as_deref(), legacy_model.as_deref()) {
                    Ok(runtime) => runtime,
                    Err(error) => { error!(%error, "invalid agent configuration"); sleep(Duration::from_secs(3)).await; continue; }
                };
                info!(agent = runtime.kind(), provider = ?runtime_config.agent.provider, model = ?runtime_config.agent.model, "starting agent runtime");
                if let Err(error) = execute_assignment(
                    &client,
                    &server,
                    &worker_credential,
                    &args.workspace_dir,
                    runtime,
                    &runtime_config.agent.initial_prompt,
                    assignment,
                ).await {
                    error!(%error, "assignment execution failed");
                }
            }
            Ok(None) => sleep(Duration::from_secs(3)).await,
            Err(error) => {
                warn!(%error, "claim failed");
                sleep(Duration::from_secs(5)).await;
            }
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
        "protocol_version": 1,
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
        .json(capabilities).send().await?;
    ensure_success(response).await?;
    Ok(())
}

async fn fetch_runtime_config(client: &Client, server: &str, credential: &str, worker_id: Uuid) -> anyhow::Result<WorkerRuntimeConfig> {
    let response = worker_auth(client.get(format!("{server}/api/workers/{worker_id}/config")), credential).send().await?;
    Ok(ensure_success(response).await?.json().await?)
}

fn runtime_for_config(agent: &AgentConfig, pi_bin: &str, legacy_provider: Option<&str>, legacy_model: Option<&str>) -> anyhow::Result<Arc<dyn AgentRuntime>> {
    if agent.agent_type != "pi" { bail!("unsupported agent type {}", agent.agent_type); }
    Ok(Arc::new(PiRuntime {
        binary: pi_bin.to_string(),
        provider: agent.provider.clone().or_else(|| legacy_provider.map(str::to_string)),
        model: agent.model.clone().or_else(|| legacy_model.map(str::to_string)),
    }))
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

async fn execute_assignment(
    client: &Client,
    server: &str,
    worker_credential: &str,
    workspace_root: &Path,
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

    let outcome = run_task(workspace_root, runtime, initial_prompt, &assignment).await;
    renew.abort();

    let result = match outcome {
        Ok(result) => result,
        Err(error) => ExecutionResult {
            status: "failed".into(),
            summary: error.to_string(),
            commit_sha: None,
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

async fn run_task(workspace_root: &Path, runtime: Arc<dyn AgentRuntime>, initial_prompt: &str, assignment: &Assignment) -> anyhow::Result<ExecutionResult> {
    let workspace = workspace_root
        .join(&assignment.project.slug)
        .join(assignment.execution.id.to_string());
    let base_sha = prepare_workspace(&workspace, assignment).await?;
    let prompt = build_prompt(initial_prompt, assignment);
    let session_name = format!("lazyteam-{}-a{}", assignment.task.id, assignment.execution.attempt);
    let agent = runtime.run(&workspace, &prompt, &session_name).await?;
    let mut warnings = vec![];
    if let Err(error) = auto_commit(&workspace, assignment).await {
        warnings.push(format!("auto-commit failed: {error}"));
    }
    let commit_sha = git_output(&workspace, &["rev-parse", "HEAD"]).await.ok();
    let changed_files = git_output(&workspace, &["diff", "--name-only", &format!("{base_sha}..HEAD")])
        .await.unwrap_or_default().lines().filter(|s| !s.is_empty()).map(str::to_string).collect();
    Ok(ExecutionResult {
        status: "completed".into(),
        summary: agent.summary,
        commit_sha,
        changed_files,
        validation: vec![],
        warnings,
        artifacts: vec![],
    })
}

fn build_prompt(initial_prompt: &str, assignment: &Assignment) -> String {
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

async fn prepare_workspace(path: &Path, assignment: &Assignment) -> anyhow::Result<String> {
    if path.exists() { tokio::fs::remove_dir_all(path).await?; }
    if let Some(parent) = path.parent() { tokio::fs::create_dir_all(parent).await?; }
    command_ok(
        Path::new("."),
        "git",
        &["clone", "--branch", &assignment.project.default_branch, "--single-branch", &assignment.project.repo_url, path.to_str().context("non-utf8 workspace path")?],
    ).await?;
    let base = git_output(path, &["rev-parse", "HEAD"]).await?;
    let branch = format!("lazyteam/task-{}-a{}", assignment.task.id.simple(), assignment.execution.attempt);
    command_ok(path, "git", &["checkout", "-b", &branch]).await?;
    Ok(base)
}

async fn auto_commit(path: &Path, assignment: &Assignment) -> anyhow::Result<()> {
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
}
