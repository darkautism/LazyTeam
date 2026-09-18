use std::{path::{Path, PathBuf}, process::Stdio};

use anyhow::{bail, Context};
use async_trait::async_trait;
use lazyteam_core::{AgentCapabilities, AgentLoginMode, AgentModel};
use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::Command,
};

#[derive(Debug)]
pub struct AgentRunResult {
    pub summary: String,
}

#[async_trait]
pub trait AgentRuntime: Send + Sync {
    fn kind(&self) -> &'static str;
    async fn capabilities(&self) -> AgentCapabilities;
    async fn run(&self, workspace: &Path, prompt: &str, session_name: &str) -> anyhow::Result<AgentRunResult>;
}

#[derive(Debug, Clone)]
pub struct PiRuntime {
    pub binary: String,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub session_dir: Option<PathBuf>,
}

impl PiRuntime {
    async fn probe_models(&self) -> anyhow::Result<Vec<AgentModel>> {
        let binary = self.binary.clone();
        tokio::time::timeout(std::time::Duration::from_secs(10), async move {
            let mut child = Command::new(&binary)
                .arg("--mode").arg("rpc").arg("--no-session")
                .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
                .spawn().with_context(|| format!("spawn {binary} for capability probe"))?;
            let mut stdin = child.stdin.take().context("Pi capability probe stdin missing")?;
            let stdout = child.stdout.take().context("Pi capability probe stdout missing")?;
            let request = json!({"id":"lazyteam-models","type":"get_available_models"});
            stdin.write_all(request.to_string().as_bytes()).await?;
            stdin.write_all(b"\n").await?;
            stdin.flush().await?;
            let mut lines = BufReader::new(stdout).lines();
            while let Some(line) = lines.next_line().await? {
                let event: Value = match serde_json::from_str(&line) { Ok(v) => v, Err(_) => continue };
                if event.get("type").and_then(Value::as_str) == Some("response")
                    && event.get("id").and_then(Value::as_str) == Some("lazyteam-models")
                {
                    if event.get("success").and_then(Value::as_bool) != Some(true) {
                        let _ = child.kill().await;
                        bail!("Pi get_available_models failed: {event}");
                    }
                    let models = event.get("data").and_then(|v| v.get("models")).and_then(Value::as_array)
                        .context("Pi get_available_models response omitted data.models")?
                        .iter().filter_map(|model| {
                            Some(AgentModel {
                                provider: model.get("provider")?.as_str()?.to_string(),
                                id: model.get("id")?.as_str()?.to_string(),
                                context_window: model.get("contextWindow").and_then(Value::as_u64),
                                reasoning: model.get("reasoning").and_then(Value::as_bool).unwrap_or(false),
                            })
                        }).collect();
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    return Ok(models);
                }
            }
            let _ = child.kill().await;
            bail!("Pi exited before returning available models")
        }).await.context("Pi capability probe timed out")?
    }
}

#[async_trait]
impl AgentRuntime for PiRuntime {
    fn kind(&self) -> &'static str { "pi" }

    async fn capabilities(&self) -> AgentCapabilities {
        match self.probe_models().await {
            Ok(models) => AgentCapabilities {
                model_discovery: true,
                login_mode: AgentLoginMode::LocalInteractive,
                models,
                probe_error: None,
            },
            Err(error) => AgentCapabilities {
                model_discovery: true,
                login_mode: AgentLoginMode::LocalInteractive,
                models: vec![],
                probe_error: Some(error.to_string()),
            },
        }
    }

    async fn run(&self, workspace: &Path, prompt: &str, session_name: &str) -> anyhow::Result<AgentRunResult> {
        let mut command = Command::new(&self.binary);
        command.arg("--mode").arg("rpc").arg("--name").arg(session_name);
        if let Some(session_dir) = &self.session_dir {
            tokio::fs::create_dir_all(session_dir).await?;
            command.arg("--session-dir").arg(session_dir).arg("--session-id").arg(session_name);
        } else {
            command.arg("--no-session");
        }
        if let Some(provider) = &self.provider { command.arg("--provider").arg(provider); }
        if let Some(model) = &self.model { command.arg("--model").arg(model); }
        command.current_dir(workspace).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = command.spawn().with_context(|| format!("spawn {} --mode rpc", self.binary))?;
        let mut stdin = child.stdin.take().context("Pi RPC stdin missing")?;
        let stdout = child.stdout.take().context("Pi RPC stdout missing")?;
        let stderr = child.stderr.take().context("Pi RPC stderr missing")?;

        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::warn!(target: "pi", "{line}");
            }
        });

        let request = json!({"id":"task-prompt","type":"prompt","message":prompt});
        stdin.write_all(request.to_string().as_bytes()).await?;
        stdin.write_all(b"\n").await?;
        stdin.flush().await?;

        let mut lines = BufReader::new(stdout).lines();
        let mut requested_final = false;
        let mut summary = String::new();

        while let Some(line) = lines.next_line().await? {
            let event: Value = match serde_json::from_str(&line) {
                Ok(event) => event,
                Err(_) => {
                    tracing::debug!(target: "pi", raw = %line, "non-json Pi output");
                    continue;
                }
            };
            match event.get("type").and_then(Value::as_str) {
                Some("message_update") => {
                    if let Some(delta) = event
                        .get("assistantMessageEvent")
                        .and_then(|v| v.get("delta"))
                        .and_then(Value::as_str)
                    {
                        tracing::info!(target: "pi", delta = %delta, "assistant delta");
                    }
                }
                Some("extension_ui_request") => {
                    let _ = child.kill().await;
                    bail!("Pi requested interactive extension UI; worker tasks must be unattended");
                }
                Some("agent_settled") if !requested_final => {
                    requested_final = true;
                    let request = json!({"id":"final-text","type":"get_last_assistant_text"});
                    stdin.write_all(request.to_string().as_bytes()).await?;
                    stdin.write_all(b"\n").await?;
                    stdin.flush().await?;
                }
                Some("response") if event.get("id").and_then(Value::as_str) == Some("final-text") => {
                    if event.get("success").and_then(Value::as_bool) == Some(true) {
                        summary = event
                            .get("data")
                            .and_then(|v| v.get("text"))
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string();
                        break;
                    }
                    let _ = child.kill().await;
                    bail!("Pi failed to return final assistant text: {event}");
                }
                _ => {}
            }
        }

        if !requested_final {
            let status = child.wait().await?;
            bail!("Pi RPC exited before agent_settled: {status}");
        }
        let _ = child.kill().await;
        let _ = child.wait().await;
        Ok(AgentRunResult { summary })
    }
}
