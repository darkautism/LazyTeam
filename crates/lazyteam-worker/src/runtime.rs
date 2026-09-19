use std::{path::{Path, PathBuf}, process::Stdio};

use anyhow::{bail, Context};
use async_trait::async_trait;
use lazyteam_core::{AgentCapabilities, AgentLoginMode, AgentModel, AgentModelCost, AgentProvider};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, Instant};

use crate::sandbox::AgentSandbox;

const DEFAULT_WATCHDOG_PROBE_INTERVAL_SECS: u64 = 120;
const DEFAULT_WATCHDOG_PROBE_GRACE_SECS: u64 = 30;
const DEFAULT_WATCHDOG_MAX_MISSED_PROBES: u32 = 3;
const DEFAULT_WATCHDOG_MAX_INACTIVE_PROBES: u32 = 3;
const DEFAULT_REVIEW_SOFT_TOOL_BUDGET: u64 = 12;
const DEFAULT_REVIEW_HARD_TOOL_BUDGET: u64 = 20;

fn bounded_duration_from_env(name: &str, default_secs: u64, min_secs: u64, max_secs: u64) -> Duration {
    let seconds = std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default_secs)
        .clamp(min_secs, max_secs);
    Duration::from_secs(seconds)
}

fn watchdog_probe_interval() -> Duration {
    bounded_duration_from_env(
        "LAZYTEAM_HARNESS_PROBE_INTERVAL_SECS",
        DEFAULT_WATCHDOG_PROBE_INTERVAL_SECS,
        30,
        600,
    )
}

fn watchdog_probe_grace() -> Duration {
    bounded_duration_from_env(
        "LAZYTEAM_HARNESS_PROBE_GRACE_SECS",
        DEFAULT_WATCHDOG_PROBE_GRACE_SECS,
        5,
        120,
    )
}

fn watchdog_max_missed_probes() -> u32 {
    std::env::var("LAZYTEAM_HARNESS_MAX_MISSED_PROBES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(DEFAULT_WATCHDOG_MAX_MISSED_PROBES)
        .clamp(2, 10)
}

fn watchdog_max_inactive_probes() -> u32 {
    std::env::var("LAZYTEAM_HARNESS_MAX_INACTIVE_PROBES")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(DEFAULT_WATCHDOG_MAX_INACTIVE_PROBES)
        .clamp(2, 10)
}

fn review_tool_budgets() -> (u64, u64) {
    let soft = std::env::var("LAZYTEAM_REVIEW_SOFT_TOOL_BUDGET")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_REVIEW_SOFT_TOOL_BUDGET)
        .clamp(4, 200);
    let hard = std::env::var("LAZYTEAM_REVIEW_HARD_TOOL_BUDGET")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_REVIEW_HARD_TOOL_BUDGET)
        .clamp(soft + 1, 400);
    (soft, hard)
}

fn review_steer_message(completed_tools: u64, soft: u64, hard: u64) -> Option<&'static str> {
    if completed_tools == soft {
        Some("You have completed substantial review inspection. Avoid repeating checks already performed. If the acceptance criteria are now resolved, return the required final JSON verdict; continue using tools only for a concrete unresolved question.")
    } else if completed_tools == hard {
        Some("Conclude the review now unless one specific unresolved acceptance criterion still requires evidence. Do not repeat prior repository inspection. Return the required final JSON verdict as soon as that concrete question is resolved.")
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunPhase {
    Starting,
    ModelStreaming,
    ModelWaiting,
    ToolRunning,
    Compacting,
    ProviderRetry,
    Finalizing,
}

impl RunPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::ModelStreaming => "model_streaming",
            Self::ModelWaiting => "model_waiting",
            Self::ToolRunning => "tool_running",
            Self::Compacting => "compacting",
            Self::ProviderRetry => "provider_retry",
            Self::Finalizing => "finalizing",
        }
    }
}

fn observe_pi_activity(event: &Value, phase: &mut RunPhase, active_tool: &mut Option<String>) -> bool {
    match event.get("type").and_then(Value::as_str) {
        Some("agent_start") | Some("turn_start") | Some("message_start") | Some("message_update") => {
            *phase = RunPhase::ModelStreaming;
            true
        }
        Some("message_end") | Some("turn_end") | Some("agent_end") => {
            *phase = RunPhase::ModelWaiting;
            true
        }
        Some("tool_execution_start") => {
            *active_tool = event.get("toolName").and_then(Value::as_str).map(str::to_string);
            *phase = RunPhase::ToolRunning;
            true
        }
        Some("tool_execution_update") => {
            *phase = RunPhase::ToolRunning;
            true
        }
        Some("tool_execution_end") => {
            *active_tool = None;
            *phase = RunPhase::ModelWaiting;
            true
        }
        Some("compaction_start") => {
            *phase = RunPhase::Compacting;
            true
        }
        Some("compaction_end") => {
            *phase = RunPhase::ModelWaiting;
            true
        }
        Some("auto_retry_start") | Some("summarization_retry_scheduled") | Some("summarization_retry_attempt_start") => {
            *phase = RunPhase::ProviderRetry;
            true
        }
        Some("auto_retry_end") | Some("summarization_retry_finished") => {
            *phase = RunPhase::ModelWaiting;
            true
        }
        Some("agent_settled") => {
            *phase = RunPhase::Finalizing;
            true
        }
        _ => false,
    }
}

fn pi_state_probe_active(event: &Value, phase: RunPhase, active_tool: Option<&str>) -> Option<bool> {
    if event.get("type").and_then(Value::as_str) != Some("response")
        || event.get("command").and_then(Value::as_str) != Some("get_state")
    {
        return None;
    }
    if event.get("success").and_then(Value::as_bool) != Some(true) {
        return Some(false);
    }
    let data = event.get("data")?;
    let streaming = data.get("isStreaming").and_then(Value::as_bool).unwrap_or(false);
    let compacting = data.get("isCompacting").and_then(Value::as_bool).unwrap_or(false);
    let pending = data.get("pendingMessageCount").and_then(Value::as_u64).unwrap_or(0) > 0;
    Some(
        streaming
            || compacting
            || pending
            || active_tool.is_some()
            || matches!(phase, RunPhase::ToolRunning | RunPhase::Compacting | RunPhase::ProviderRetry),
    )
}

async fn abort_pi_run(
    child: &mut tokio::process::Child,
    stdin: &mut tokio::process::ChildStdin,
) {
    let request = json!({"id":"lazyteam-watchdog-abort","type":"abort"});
    if stdin.write_all(request.to_string().as_bytes()).await.is_ok() {
        let _ = stdin.write_all(b"\n").await;
        let _ = stdin.flush().await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let _ = child.kill().await;
    let _ = child.wait().await;
}

#[derive(Debug)]
pub struct AgentRunResult {
    pub summary: String,
    /// Opaque backend-owned session ID created (or rotated) by the runtime
    /// during this run. `None` means the runtime did not create a new
    /// identity (e.g. Pi reuses the caller-chosen logical session ID).
    /// Scheduler code treats this as an opaque string and persists it via
    /// `SessionManager::bind_backend_session` without interpreting it.
    pub backend_session_id: Option<String>,
}

#[async_trait]
pub trait AgentRuntime: Send + Sync {
    fn kind(&self) -> &'static str;
    async fn capabilities(&self) -> AgentCapabilities;
    async fn run(&self, workspace: &Path, prompt: &str, backend_session_id: Option<&str>) -> anyhow::Result<AgentRunResult>;
    async fn run_review(&self, workspace: &Path, prompt: &str, backend_session_id: Option<&str>) -> anyhow::Result<AgentRunResult> {
        self.run(workspace, prompt, backend_session_id).await
    }
}

#[derive(Debug, Clone)]
pub struct PiRuntime {
    pub binary: String,
    pub provider: Option<String>,
    pub model: Option<String>,
    pub session_dir: Option<PathBuf>,
    pub sandbox: AgentSandbox,
}

fn agent_model_from_pi(model: &Value) -> Option<AgentModel> {
    let cost = model.get("cost").and_then(Value::as_object).map(|cost| AgentModelCost {
        input: cost.get("input").and_then(Value::as_f64).unwrap_or(0.0),
        output: cost.get("output").and_then(Value::as_f64).unwrap_or(0.0),
        cache_read: cost.get("cacheRead").and_then(Value::as_f64).unwrap_or(0.0),
        cache_write: cost.get("cacheWrite").and_then(Value::as_f64).unwrap_or(0.0),
    });
    Some(AgentModel {
        provider: model.get("provider")?.as_str()?.to_string(),
        id: model.get("id")?.as_str()?.to_string(),
        name: model.get("name").and_then(Value::as_str).map(str::to_string),
        context_window: model.get("contextWindow").and_then(Value::as_u64),
        reasoning: model.get("reasoning").and_then(Value::as_bool).unwrap_or(false),
        cost,
    })
}

impl PiRuntime {
    async fn run_rpc(
        &self,
        workspace: &Path,
        prompt: &str,
        backend_session_id: Option<&str>,
        review_budgets: Option<(u64, u64)>,
    ) -> anyhow::Result<AgentRunResult> {
        if let Some(session_dir) = &self.session_dir {
            tokio::fs::create_dir_all(session_dir).await?;
        }
        // Pi keeps caller-chosen session IDs: the logical session binding
        // supplies the stable ID. An unbound (`None`) Pi session runs
        // ephemerally without forcing a fabricated ID.
        let session_name = backend_session_id.unwrap_or("lazyteam-ephemeral");
        let mut command = self.sandbox.command(&self.binary, workspace, self.session_dir.as_deref())?;
        command.arg("--mode").arg("rpc").arg("--name").arg(session_name);
        if self.session_dir.is_some() && backend_session_id.is_some() {
            let session_dir = self.session_dir.as_ref().expect("checked above");
            command.arg("--session-dir").arg(session_dir).arg("--session-id").arg(session_name);
        } else {
            command.arg("--no-session");
        }
        if let Some(provider) = &self.provider { command.arg("--provider").arg(provider); }
        if let Some(model) = &self.model { command.arg("--model").arg(model); }
        command.current_dir(workspace).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        command.kill_on_drop(true);

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
        let mut completed_tools = 0u64;
        let probe_interval = watchdog_probe_interval();
        let probe_grace = watchdog_probe_grace();
        let max_missed_probes = watchdog_max_missed_probes();
        let max_inactive_probes = watchdog_max_inactive_probes();
        let mut phase = RunPhase::Starting;
        let mut active_tool: Option<String> = None;
        let mut next_probe_at = Instant::now() + probe_interval;
        let mut probe_deadline: Option<Instant> = None;
        let mut missed_probes = 0u32;
        let mut inactive_probes = 0u32;
        let mut probe_sequence = 0u64;

        loop {
            let wait_until = probe_deadline.unwrap_or(next_probe_at);
            let line = match tokio::time::timeout_at(wait_until, lines.next_line()).await {
                Ok(result) => {
                    let result = result?;
                    let now = Instant::now();
                    next_probe_at = now + probe_interval;
                    probe_deadline = None;
                    missed_probes = 0;
                    result
                }
                Err(_) => {
                    let now = Instant::now();
                    if probe_deadline.take().is_some() {
                        missed_probes += 1;
                        tracing::warn!(
                            session = session_name,
                            phase = phase.as_str(),
                            active_tool = active_tool.as_deref().unwrap_or("none"),
                            missed_probes,
                            max_missed_probes,
                            "Pi harness liveness probe timed out"
                        );
                        if missed_probes >= max_missed_probes {
                            let reason = format!(
                                "Pi harness unresponsive after {missed_probes} liveness probes; phase={} active_tool={}",
                                phase.as_str(),
                                active_tool.as_deref().unwrap_or("none"),
                            );
                            abort_pi_run(&mut child, &mut stdin).await;
                            bail!(reason);
                        }
                    }

                    probe_sequence += 1;
                    let request = json!({
                        "id": format!("lazyteam-liveness-{probe_sequence}"),
                        "type": "get_state"
                    });
                    stdin.write_all(request.to_string().as_bytes()).await?;
                    stdin.write_all(b"\n").await?;
                    stdin.flush().await?;
                    probe_deadline = Some(now + probe_grace);
                    continue;
                }
            };
            let Some(line) = line else { break; };
            let event: Value = match serde_json::from_str(&line) {
                Ok(event) => event,
                Err(_) => {
                    tracing::debug!(target: "pi", raw = %line, "non-json Pi output");
                    continue;
                }
            };

            if observe_pi_activity(&event, &mut phase, &mut active_tool) {
                inactive_probes = 0;
            }
            if let Some(active) = pi_state_probe_active(&event, phase, active_tool.as_deref()) {
                if active {
                    inactive_probes = 0;
                } else {
                    inactive_probes += 1;
                    tracing::warn!(
                        session = session_name,
                        phase = phase.as_str(),
                        inactive_probes,
                        max_inactive_probes,
                        "Pi harness responded but reports no active model, tool, compaction, retry, or queued work"
                    );
                    if inactive_probes >= max_inactive_probes {
                        let reason = format!(
                            "Pi harness stayed inactive for {inactive_probes} consecutive state probes; phase={}",
                            phase.as_str(),
                        );
                        abort_pi_run(&mut child, &mut stdin).await;
                        bail!(reason);
                    }
                }
            }

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
                Some("tool_execution_end") => {
                    if let Some((soft, hard)) = review_budgets {
                        completed_tools += 1;
                        if let Some(message) = review_steer_message(completed_tools, soft, hard) {
                            tracing::warn!(
                                session = session_name,
                                completed_tools,
                                soft,
                                hard,
                                "review tool budget reached; steering reviewer toward a verdict without interrupting running tools"
                            );
                            let request = json!({
                                "id": format!("review-steer-{completed_tools}"),
                                "type": "steer",
                                "message": message,
                            });
                            stdin.write_all(request.to_string().as_bytes()).await?;
                            stdin.write_all(b"\n").await?;
                            stdin.flush().await?;
                        }
                    }
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
        Ok(AgentRunResult { summary, backend_session_id: None })
    }

    fn pi_module_index(&self) -> anyhow::Result<PathBuf> {
        let binary = if Path::new(&self.binary).components().count() > 1 {
            PathBuf::from(&self.binary)
        } else {
            std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
                .map(|dir| dir.join(&self.binary))
                .find(|candidate| candidate.is_file())
                .context("locate Pi executable on PATH")?
        };
        let target = std::fs::canonicalize(&binary)
            .with_context(|| format!("canonicalize Pi executable {}", binary.display()))?;
        let package_root = target.ancestors().nth(3)
            .context("Pi executable layout does not expose package root")?;
        let index = package_root.join("dist").join("index.js");
        if !index.is_file() {
            bail!("Pi public module not found at {}", index.display());
        }
        Ok(index)
    }

    async fn probe_providers(&self) -> anyhow::Result<Vec<AgentProvider>> {
        let index = self.pi_module_index()?;
        let import_url = format!("file://{}", index.display());
        let import_url = serde_json::to_string(&import_url)?;
        let script = format!(
            r#"import {{ ModelRuntime }} from {import_url};
const dir=process.env.PI_CODING_AGENT_DIR;
const rt=await ModelRuntime.create({{
  authPath:dir+"/auth.json",
  modelsPath:dir+"/models.json",
  modelsStorePath:dir+"/models-store.json",
  allowModelNetwork:false,
  refreshOnCreate:false
}});
const stored=new Set((await rt.listCredentials()).map(c=>c.providerId));
const providers=rt.getProviders().map(p=>({{
  id:p.id,
  name:p.name,
  configured:stored.has(p.id)||!!rt.getProviderAuthStatus(p.id)?.configured,
  api_key_label:p.auth?.apiKey?.name??null,
  oauth_label:p.auth?.oauth?.name??null
}}));
console.log(JSON.stringify(providers));"#
        );
        let sandbox = self.sandbox.clone();
        tokio::time::timeout(std::time::Duration::from_secs(10), async move {
            let mut command = sandbox.command("node", sandbox.probe_workspace(), None)?;
            command.arg("--input-type=module").arg("--eval").arg(script);
            command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let output = command.output().await.context("run Pi ModelRuntime provider probe")?;
            if !output.status.success() {
                bail!("Pi provider probe failed: {}", String::from_utf8_lossy(&output.stderr).trim());
            }
            let providers = serde_json::from_slice::<Vec<AgentProvider>>(&output.stdout)
                .context("parse Pi provider probe output")?;
            Ok(providers)
        }).await.context("Pi provider probe timed out")?
    }

    async fn probe_models(&self) -> anyhow::Result<Vec<AgentModel>> {
        let binary = self.binary.clone();
        let sandbox = self.sandbox.clone();
        tokio::time::timeout(std::time::Duration::from_secs(10), async move {
            let mut command = sandbox.command(&binary, sandbox.probe_workspace(), None)?;
            command.arg("--mode").arg("rpc").arg("--no-session");
            command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
            let mut child = command.spawn().with_context(|| format!("spawn sandboxed {binary} for capability probe"))?;
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
                        .iter().filter_map(agent_model_from_pi).collect();
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
        let providers = self.probe_providers().await;
        let models = self.probe_models().await;
        match (providers, models) {
            (Ok(providers), Ok(models)) => AgentCapabilities {
                model_discovery: true,
                login_mode: AgentLoginMode::Remote,
                providers,
                models,
                probe_error: None,
            },
            (providers, models) => {
                let mut errors = Vec::new();
                let providers = match providers {
                    Ok(value) => value,
                    Err(error) => { errors.push(format!("provider catalog: {error:#}")); vec![] }
                };
                let models = match models {
                    Ok(value) => value,
                    Err(error) => { errors.push(format!("model catalog: {error:#}")); vec![] }
                };
                AgentCapabilities {
                    model_discovery: true,
                    login_mode: AgentLoginMode::Remote,
                    providers,
                    models,
                    probe_error: (!errors.is_empty()).then(|| errors.join("; ")),
                }
            }
        }
    }

    async fn run(&self, workspace: &Path, prompt: &str, backend_session_id: Option<&str>) -> anyhow::Result<AgentRunResult> {
        self.run_rpc(workspace, prompt, backend_session_id, None).await
    }

    async fn run_review(&self, workspace: &Path, prompt: &str, backend_session_id: Option<&str>) -> anyhow::Result<AgentRunResult> {
        self.run_rpc(
            workspace,
            prompt,
            backend_session_id,
            Some(review_tool_budgets()),
        ).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewer_convergence_steers_on_completed_tool_budgets_only() {
        assert!(review_steer_message(11, 12, 20).is_none());
        assert!(review_steer_message(12, 12, 20).is_some());
        assert!(review_steer_message(13, 12, 20).is_none());
        assert!(review_steer_message(20, 12, 20).is_some());
        assert!(review_steer_message(21, 12, 20).is_none());
    }

    #[test]
    fn harness_activity_tracks_tool_compaction_and_retry_phases() {
        let mut phase = RunPhase::Starting;
        let mut tool = None;

        assert!(observe_pi_activity(&json!({"type":"message_update"}), &mut phase, &mut tool));
        assert_eq!(phase, RunPhase::ModelStreaming);

        assert!(observe_pi_activity(
            &json!({"type":"tool_execution_start","toolName":"bash"}),
            &mut phase,
            &mut tool,
        ));
        assert_eq!(phase, RunPhase::ToolRunning);
        assert_eq!(tool.as_deref(), Some("bash"));

        assert!(observe_pi_activity(&json!({"type":"tool_execution_update"}), &mut phase, &mut tool));
        assert_eq!(phase, RunPhase::ToolRunning);

        assert!(observe_pi_activity(&json!({"type":"tool_execution_end"}), &mut phase, &mut tool));
        assert_eq!(phase, RunPhase::ModelWaiting);
        assert!(tool.is_none());

        assert!(observe_pi_activity(&json!({"type":"compaction_start"}), &mut phase, &mut tool));
        assert_eq!(phase, RunPhase::Compacting);
        assert!(observe_pi_activity(&json!({"type":"compaction_end"}), &mut phase, &mut tool));
        assert_eq!(phase, RunPhase::ModelWaiting);

        assert!(observe_pi_activity(&json!({"type":"auto_retry_start"}), &mut phase, &mut tool));
        assert_eq!(phase, RunPhase::ProviderRetry);
        assert!(observe_pi_activity(&json!({"type":"auto_retry_end"}), &mut phase, &mut tool));
        assert_eq!(phase, RunPhase::ModelWaiting);
    }

    #[test]
    fn state_probe_keeps_slow_streaming_and_active_tools_alive() {
        let streaming = json!({
            "type":"response",
            "command":"get_state",
            "success":true,
            "data":{"isStreaming":true,"isCompacting":false,"pendingMessageCount":0}
        });
        assert_eq!(
            pi_state_probe_active(&streaming, RunPhase::ModelWaiting, None),
            Some(true),
        );

        let idle = json!({
            "type":"response",
            "command":"get_state",
            "success":true,
            "data":{"isStreaming":false,"isCompacting":false,"pendingMessageCount":0}
        });
        assert_eq!(
            pi_state_probe_active(&idle, RunPhase::ModelWaiting, None),
            Some(false),
        );
        assert_eq!(
            pi_state_probe_active(&idle, RunPhase::ToolRunning, Some("bash")),
            Some(true),
        );
    }

    #[test]
    fn parses_real_pi_model_name_and_cost_metadata() {
        let value = json!({
            "provider": "opencode-go",
            "id": "cheap-real-model",
            "name": "Cheap Real Model",
            "reasoning": true,
            "contextWindow": 1000000,
            "cost": {
                "input": 0.15,
                "output": 0.47,
                "cacheRead": 0.016,
                "cacheWrite": 0.2
            }
        });
        let model = agent_model_from_pi(&value).unwrap();
        assert_eq!(model.provider, "opencode-go");
        assert_eq!(model.id, "cheap-real-model");
        assert_eq!(model.name.as_deref(), Some("Cheap Real Model"));
        assert_eq!(model.context_window, Some(1_000_000));
        assert!(model.reasoning);
        let cost = model.cost.unwrap();
        assert_eq!(cost.input, 0.15);
        assert_eq!(cost.output, 0.47);
        assert_eq!(cost.cache_read, 0.016);
        assert_eq!(cost.cache_write, 0.2);
    }

    struct FakeBackendRuntime {
        created: String,
    }

    #[async_trait]
    impl AgentRuntime for FakeBackendRuntime {
        fn kind(&self) -> &'static str { "fake-backend" }
        async fn capabilities(&self) -> AgentCapabilities { AgentCapabilities::default() }
        async fn run(&self, _workspace: &Path, _prompt: &str, backend_session_id: Option<&str>) -> anyhow::Result<AgentRunResult> {
            // Backend-owned identity: first run creates an opaque ID, later
            // runs resume the bound ID without the scheduler interpreting it.
            match backend_session_id {
                None => Ok(AgentRunResult { summary: "created".into(), backend_session_id: Some(self.created.clone()) }),
                Some(existing) => Ok(AgentRunResult { summary: format!("resumed {existing}"), backend_session_id: None }),
            }
        }
    }

    #[tokio::test]
    async fn backend_owned_identity_is_created_once_then_resumed() {
        let runtime = FakeBackendRuntime { created: "ses_opaque_123".into() };
        let workspace = Path::new("/tmp");
        let first = runtime.run(workspace, "prompt", None).await.unwrap();
        assert_eq!(first.backend_session_id.as_deref(), Some("ses_opaque_123"));
        // Scheduler persists the opaque ID as-is; the next run resumes it and
        // the runtime reports no new identity.
        let second = runtime.run(workspace, "prompt", first.backend_session_id.as_deref()).await.unwrap();
        assert_eq!(second.backend_session_id, Option::<String>::None);
        assert!(second.summary.contains("ses_opaque_123"));
    }

    #[tokio::test]
    async fn pi_style_caller_chosen_session_reports_no_new_identity() {
        // Pi reuses the logical session ID supplied by SessionManager, so a
        // run result carries no new backend identity to persist.
        let runtime = FakeBackendRuntime { created: "ses_opaque_123".into() };
        let workspace = Path::new("/tmp");
        let resumed = runtime.run(workspace, "prompt", Some("task-derived-id")).await.unwrap();
        assert_eq!(resumed.backend_session_id, Option::<String>::None);
    }
}
