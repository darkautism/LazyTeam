use std::{collections::{BTreeMap, BTreeSet}, path::{Path, PathBuf}, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use clap::Parser;
use lazyteam_core::{Assignment, ExecutionResult};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde_json::json;
use tokio::{process::Command, time::sleep};
use tracing::{error, info, warn};
use uuid::Uuid;

mod runtime;
use runtime::{AgentRuntime, PiRuntime};

const WORKER_CREDENTIAL_HEADER: &str = "x-lazyteam-worker-credential";

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, env = "LAZYTEAM_SERVER", default_value = "http://127.0.0.1:8787")]
    server: String,
    /// Shared enrollment secret. Required only for first enrollment or recovery when
    /// the persisted worker-specific credential is no longer accepted by the server.
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
    let server = args.server.trim_end_matches('/').to_string();
    let client = Client::builder().timeout(Duration::from_secs(30)).build()?;
    let tags: BTreeMap<String, String> = args.tags.into_iter().collect();
    let projects: BTreeSet<String> = args.allowed_projects.into_iter().collect();

    let mut worker_credential = match load_worker_credential(&args.state_dir).await? {
        Some(credential) => credential,
        None => {
            let enrollment = args.worker_token.as_deref().context(
                "LAZYTEAM_WORKER_TOKEN is required for first enrollment; after enrollment the worker credential is persisted",
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
            ).await?;
            persist_worker_credential(&args.state_dir, &credential).await?;
            info!(%worker_id, server = %server, "worker enrolled and credential persisted");
            credential
        }
    };

    // A server database restore/replacement may invalidate the persisted credential.
    // Re-enroll only when an enrollment secret was intentionally supplied for recovery.
    if heartbeat(&client, &server, &worker_credential, worker_id).await.is_err() {
        let enrollment = args.worker_token.as_deref().context(
            "persisted worker credential was rejected and no enrollment secret was supplied for recovery",
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
        ).await?;
        persist_worker_credential(&args.state_dir, &worker_credential).await?;
        info!(%worker_id, "worker re-enrolled after credential rejection");
    }

    let runtime: Arc<dyn AgentRuntime> = Arc::new(PiRuntime {
        binary: args.pi_bin,
        provider: args.pi_provider,
        model: args.pi_model,
    });

    loop {
        if let Err(error) = heartbeat(&client, &server, &worker_credential, worker_id).await {
            warn!(%error, "heartbeat failed");
            sleep(Duration::from_secs(5)).await;
            continue;
        }
        match claim(&client, &server, &worker_credential, worker_id).await {
            Ok(Some(assignment)) => {
                info!(task = %assignment.task.id, execution = %assignment.execution.id, project = %assignment.project.slug, "claimed task");
                if let Err(error) = execute_assignment(
                    &client,
                    &server,
                    &worker_credential,
                    &args.workspace_dir,
                    runtime.clone(),
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
        "protocol_version": 1
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

    let outcome = run_task(workspace_root, runtime, &assignment).await;
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

async fn run_task(workspace_root: &Path, runtime: Arc<dyn AgentRuntime>, assignment: &Assignment) -> anyhow::Result<ExecutionResult> {
    let workspace = workspace_root
        .join(&assignment.project.slug)
        .join(assignment.execution.id.to_string());
    let base_sha = prepare_workspace(&workspace, assignment).await?;
    let prompt = build_prompt(assignment);
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

fn build_prompt(assignment: &Assignment) -> String {
    let criteria = assignment.task.acceptance_criteria.iter().map(|v| format!("- {v}")).collect::<Vec<_>>().join("\n");
    format!(
        "You are a LazyTeam worker executing one unattended coding task.\n\nProject: {}\nRepository: {}\nBase branch: {}\nTask: {}\n\nDescription:\n{}\n\nExpected outcome:\n{}\n\nAcceptance criteria:\n{}\n\nRules:\n- Work only in the current workspace.\n- Inspect the repository before editing.\n- Implement the requested task, run appropriate validation, and do not wait for human interaction.\n- Do not broaden the task beyond its contract.\n- Commit your changes if practical.\n- End with a concise summary of changes and validation.\n",
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
