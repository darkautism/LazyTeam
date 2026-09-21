use std::{path::{Path, PathBuf}, process::Stdio};

use anyhow::{bail, Context};
use async_trait::async_trait;
use lazyteam_core::{AgentCapabilities, AgentLoginMode, AgentModel, AgentModelCost, AgentProvider};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, Instant};
use uuid::Uuid;

use crate::sandbox::AgentSandbox;

const DEFAULT_WATCHDOG_PROBE_INTERVAL_SECS: u64 = 120;
const DEFAULT_WATCHDOG_PROBE_GRACE_SECS: u64 = 30;
const DEFAULT_WATCHDOG_MAX_MISSED_PROBES: u32 = 3;
const DEFAULT_WATCHDOG_MAX_INACTIVE_PROBES: u32 = 3;
const DEFAULT_WATCHDOG_TOOL_STALL_SECS: u64 = 30 * 60;
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

fn watchdog_tool_stall_window() -> Duration {
    bounded_duration_from_env(
        "LAZYTEAM_HARNESS_TOOL_STALL_SECS",
        DEFAULT_WATCHDOG_TOOL_STALL_SECS,
        30 * 60,
        6 * 60 * 60,
    )
}

fn tool_stalled(last_progress: Instant, now: Instant, window: Duration) -> bool {
    now.saturating_duration_since(last_progress) >= window
}

const MAX_TOOL_NAME_LEN: usize = 32;
const MAX_TOOL_CALL_ID_LEN: usize = 64;
const MAX_PROGRAM_LEN: usize = 32;
const MAX_COMMAND_SUMMARY_LEN: usize = 80;
const MAX_FINGERPRINT_BYTES: usize = 4096;

/// Bounded safe diagnostics for the currently active Pi tool call.
///
/// Only fixed-vocabulary labels, sanitized identifiers, counts, durations,
/// and a stable hash are retained. Raw tool arguments, command payload text,
/// credentials, and transcripts are never stored here or in any durable
/// watchdog message built from this struct.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveToolState {
    name: String,
    call_id: Option<String>,
    started_at: Instant,
    last_progress_at: Instant,
    update_count: u64,
    args_available: bool,
    command_class: String,
    program: Option<String>,
    command_summary: String,
    fingerprint: String,
}

impl ActiveToolState {
    fn name_label(&self) -> &str {
        &self.name
    }
}

fn sanitize_label(raw: &str, max_len: usize) -> String {
    let filtered: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
        .take(max_len)
        .collect();
    if filtered.is_empty() {
        "unknown".to_string()
    } else {
        filtered
    }
}

fn fnv1a64_hex_tool(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn extract_tool_name(event: &Value) -> String {
    let raw = event
        .get("toolName")
        .or_else(|| event.get("tool_name"))
        .or_else(|| event.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    sanitize_label(raw.trim(), MAX_TOOL_NAME_LEN)
}

fn extract_tool_call_id(event: &Value) -> Option<String> {
    const KEYS: &[&str] = &["toolCallId", "tool_call_id", "callId", "call_id", "toolUseId", "tool_use_id"];
    for key in KEYS {
        if let Some(raw) = event.get(*key).and_then(Value::as_str) {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                return Some(sanitize_label(trimmed, MAX_TOOL_CALL_ID_LEN));
            }
        }
    }
    for container in ["toolCall", "tool_call", "toolUse", "tool_use", "data"] {
        if let Some(obj) = event.get(container).and_then(Value::as_object) {
            for key in KEYS {
                if let Some(raw) = obj.get(*key).and_then(Value::as_str) {
                    let trimmed = raw.trim();
                    if !trimmed.is_empty() {
                        return Some(sanitize_label(trimmed, MAX_TOOL_CALL_ID_LEN));
                    }
                }
            }
            if let Some(raw) = obj.get("id").and_then(Value::as_str) {
                let trimmed = raw.trim();
                if !trimmed.is_empty() && container != "data" {
                    return Some(sanitize_label(trimmed, MAX_TOOL_CALL_ID_LEN));
                }
            }
        }
    }
    None
}

/// Locate the tool-argument payload without cloning raw content into durable
/// state. Returns `None` when the Pi RPC event schema exposes no arguments.
fn tool_args_value(event: &Value) -> Option<&Value> {
    const KEYS: &[&str] = &["input", "args", "arguments", "params", "parameters", "toolInput", "tool_input"];
    for key in KEYS {
        if let Some(value) = event.get(*key) {
            if !is_null_like(value) {
                return Some(value);
            }
        }
    }
    for container in ["toolCall", "tool_call", "toolUse", "tool_use", "data"] {
        if let Some(obj) = event.get(container).and_then(Value::as_object) {
            for key in KEYS {
                if let Some(value) = obj.get(*key) {
                    if !is_null_like(value) {
                        return Some(value);
                    }
                }
            }
        }
    }
    // Some schemas inline the command beside the tool name on tool events.
    // Only treated as args for tool execution events (never for get_state
    // responses, which also use a `command` key for the RPC method name).
    if matches!(
        event.get("type").and_then(Value::as_str),
        Some("tool_execution_start") | Some("tool_execution_update")
    ) {
        if let Some(value) = event.get("command") {
            if value.is_string() {
                return Some(value);
            }
        }
    }
    None
}

fn is_null_like(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(s) => s.trim().is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

/// Extract a bounded raw command string for classification only. The returned
/// string is used transiently to derive a redacted class/program/hash and is
/// never persisted itself.
fn raw_command_from_args(args: &Value, event: &Value) -> Option<String> {
    if let Some(s) = args.as_str() {
        return bounded_raw_command(s);
    }
    if let Some(obj) = args.as_object() {
        for key in ["command", "cmd", "script", "code", "text", "input"] {
            if let Some(s) = obj.get(key).and_then(Value::as_str) {
                if let Some(cmd) = bounded_raw_command(s) {
                    return Some(cmd);
                }
            }
        }
    }
    if matches!(
        event.get("type").and_then(Value::as_str),
        Some("tool_execution_start") | Some("tool_execution_update")
    ) {
        if let Some(s) = event.get("command").and_then(Value::as_str) {
            return bounded_raw_command(s);
        }
    }
    None
}

fn bounded_raw_command(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let bounded: String = trimmed.chars().take(MAX_FINGERPRINT_BYTES).collect();
    if bounded.is_empty() { None } else { Some(bounded) }
}

fn first_shell_token(raw: &str) -> Option<String> {
    let mut tokens = raw
        .split([ ' ', '\t', '\n', ';', '&', '|', '(', ')', '\\'])
        .filter(|t| !t.trim().is_empty());
    // Skip common shell wrappers so `sudo cargo test` still reports cargo.
    for _ in 0..3 {
        let Some(token) = tokens.next() else { return None };
        let cleaned = token.trim_matches(|c| c == '"' || c == '\'' || c == '`');
        let lower = cleaned.to_ascii_lowercase();
        if matches!(lower.as_str(), "sudo" | "env" | "time" | "nice" | "stdbuf" | "sh" | "bash") {
            // `env FOO=bar cargo ...` carries assignments as extra wrappers.
            continue;
        }
        if cleaned.contains('=') && !cleaned.contains('/') {
            continue;
        }
        // Basename so `/usr/bin/cargo` still classifies as cargo.
        let base = cleaned.rsplit('/').next().unwrap_or(cleaned);
        if base.is_empty() {
            continue;
        }
        return Some(base.to_string());
    }
    None
}

fn second_shell_token(raw: &str) -> Option<String> {
    let mut parts = raw.split_whitespace();
    let _ = parts.next()?;
    for token in parts {
        let cleaned = token.trim_matches(|c| c == '"' || c == '\'' || c == '`');
        if cleaned.is_empty() || cleaned.starts_with('-') || cleaned.contains('=') {
            // Skip flags/env assignments to find the real subcommand.
            if cleaned.starts_with('-') || cleaned.contains('=') {
                continue;
            }
            continue;
        }
        return Some(cleaned.to_ascii_lowercase());
    }
    None
}

fn classify_bash_command(raw: &str) -> (String, Option<String>, String) {
    let program_raw = first_shell_token(raw).unwrap_or_default();
    let program = if program_raw.is_empty() {
        None
    } else {
        Some(sanitize_label(&program_raw.to_ascii_lowercase(), MAX_PROGRAM_LEN))
    };
    let sub = second_shell_token(raw).unwrap_or_default();
    let program_label = program.as_deref().unwrap_or("unknown");
    let class: &'static str = match (program_label, sub.as_str()) {
        ("cargo", "test") => "cargo-test",
        ("cargo", "check") => "cargo-check",
        ("cargo", "build") => "cargo-build",
        ("cargo", "clippy") => "cargo-clippy",
        ("cargo", "fmt") => "cargo-fmt",
        ("cargo", _) => "cargo",
        ("git", _) => "git",
        ("curl" | "wget", _) => "network-fetch",
        ("ssh" | "scp" | "rsync", _) => "network-ssh",
        ("npm" | "pnpm" | "yarn", _) => "node-build",
        ("docker" | "podman" | "nerdctl", _) => "container",
        ("make" | "just" | "ninja" | "cmake", _) => "build",
        ("cargo-test" | "pytest" | "pytest-3", _) => "python-test",
        ("python" | "python3" | "pip" | "pip3" | "uv", s) if s.contains("test") => "python-test",
        ("python" | "python3" | "pip" | "pip3" | "uv", _) => "python",
        ("go", _) => "go",
        ("rustc", _) => "rustc-build",
        ("sleep", _) => "sleep-wait",
        ("cargo-nextest" | "nextest", _) => "cargo-test",
        ("ls" | "cat" | "echo" | "grep" | "rg" | "fd" | "find" | "head" | "tail" | "sed" | "awk" | "jq", _) => "shell-inspect",
        ("unknown", _) => "generic-shell",
        _ => "generic-shell",
    };
    // Redacted summary carries only the safe program (+ subcommand for
    // well-known dispatchers). All flags, paths, URLs, and payloads stay out.
    let summary = match program.as_deref() {
        Some(p) if matches!(p, "cargo" | "git" | "npm" | "pnpm" | "yarn" | "make" | "just" | "go" | "docker" | "podman") => {
            if sub.is_empty() || sub.starts_with('-') {
                p.to_string()
            } else {
                let safe_sub = sanitize_label(&sub, MAX_PROGRAM_LEN);
                format!("{p} {safe_sub}")
            }
        }
        Some(p) => p.to_string(),
        None => "generic-shell".to_string(),
    };
    let summary = summary.chars().take(MAX_COMMAND_SUMMARY_LEN).collect::<String>();
    (class.to_string(), program, summary)
}

/// Derive the durable bash/non-bash diagnostic from one tool event. Only
/// fixed-vocabulary class labels, sanitized program tokens, lengths, and the
/// stable hash leave this function; raw arguments never do.
fn derive_tool_command(tool_name: &str, event: &Value) -> (bool, String, Option<String>, String, String) {
    let Some(args) = tool_args_value(event) else {
        return (false, "args-unavailable".to_string(), None, "args-unavailable".to_string(), "none".to_string());
    };
    if tool_name == "bash" {
        match raw_command_from_args(args, event) {
            Some(raw) => {
                let fingerprint = fnv1a64_hex_tool(raw.as_bytes());
                let (class, program, summary) = classify_bash_command(&raw);
                (true, class, program, summary, fingerprint)
            }
            None => {
                // Args were exposed but carried no recognizable command string.
                let serialized = serde_json::to_string(args).unwrap_or_default();
                let bounded: String = serialized.chars().take(MAX_FINGERPRINT_BYTES).collect();
                (true, "bash-no-command".to_string(), None, "bash-no-command".to_string(), fnv1a64_hex_tool(bounded.as_bytes()))
            }
        }
    } else {
        let serialized = serde_json::to_string(args).unwrap_or_default();
        let bounded: String = serialized.chars().take(MAX_FINGERPRINT_BYTES).collect();
        (true, "non-bash".to_string(), None, "non-bash".to_string(), fnv1a64_hex_tool(bounded.as_bytes()))
    }
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
        Some("You have completed substantial review inspection. Avoid repeating checks already performed. If the acceptance criteria are now resolved, call submit_review; continue using tools only for a concrete unresolved question.")
    } else if completed_tools == hard {
        Some("Conclude the review now unless one specific unresolved acceptance criterion still requires evidence. Do not repeat prior repository inspection. Call submit_review as soon as that concrete question is resolved.")
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

fn observe_pi_activity(
    event: &Value,
    phase: &mut RunPhase,
    active_tool: &mut Option<ActiveToolState>,
    now: Instant,
) -> bool {
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
            let name = extract_tool_name(event);
            let call_id = extract_tool_call_id(event);
            let (args_available, command_class, program, command_summary, fingerprint) =
                derive_tool_command(&name, event);
            *active_tool = Some(ActiveToolState {
                name,
                call_id,
                started_at: now,
                last_progress_at: now,
                update_count: 0,
                args_available,
                command_class,
                program,
                command_summary,
                fingerprint,
            });
            *phase = RunPhase::ToolRunning;
            true
        }
        Some("tool_execution_update") => {
            match active_tool {
                Some(state) => {
                    // A differently-named update resets the stall clock like a
                    // fresh start; same-tool updates only refresh progress.
                    let name = extract_tool_name(event);
                    if name != "unknown" && name != state.name {
                        let call_id = extract_tool_call_id(event).or_else(|| state.call_id.clone());
                        let (args_available, command_class, program, command_summary, fingerprint) =
                            derive_tool_command(&name, event);
                        let args_available = if event.get("toolName").is_none() && tool_args_value(event).is_none() {
                            state.args_available
                        } else {
                            args_available
                        };
                        *state = ActiveToolState {
                            name,
                            call_id,
                            started_at: now,
                            last_progress_at: now,
                            update_count: 0,
                            args_available,
                            command_class: if args_available { command_class } else { state.command_class.clone() },
                            program: if args_available { program } else { state.program.clone() },
                            command_summary: if args_available { command_summary } else { state.command_summary.clone() },
                            fingerprint: if args_available { fingerprint } else { state.fingerprint.clone() },
                        };
                    } else {
                        state.last_progress_at = now;
                        state.update_count += 1;
                        // An update may be the first event to expose arguments.
                        if !state.args_available {
                            if tool_args_value(event).is_some() {
                                let (args_available, command_class, program, command_summary, fingerprint) =
                                    derive_tool_command(&state.name.clone(), event);
                                state.args_available = args_available;
                                state.command_class = command_class;
                                state.program = program;
                                state.command_summary = command_summary;
                                state.fingerprint = fingerprint;
                            }
                        }
                        if state.call_id.is_none() {
                            state.call_id = extract_tool_call_id(event);
                        }
                    }
                }
                None => {
                    let name = extract_tool_name(event);
                    let call_id = extract_tool_call_id(event);
                    let (args_available, command_class, program, command_summary, fingerprint) =
                        derive_tool_command(&name, event);
                    *active_tool = Some(ActiveToolState {
                        name,
                        call_id,
                        started_at: now,
                        last_progress_at: now,
                        update_count: 1,
                        args_available,
                        command_class,
                        program,
                        command_summary,
                        fingerprint,
                    });
                }
            }
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

fn active_tool_name(state: &Option<ActiveToolState>) -> Option<&str> {
    state.as_ref().map(|s| s.name.as_str())
}

/// Durable stall diagnostic. Emits only bounded sanitized identifiers,
/// fixed-vocabulary class labels, counts, durations, and the stable hash —
/// never raw arguments, command payloads, or transcripts.
fn format_tool_diagnostic(state: &ActiveToolState, now: Instant) -> String {
    let started_ago = now.saturating_duration_since(state.started_at).as_secs();
    let idle_for = now.saturating_duration_since(state.last_progress_at).as_secs();
    let call_id = state.call_id.as_deref().unwrap_or("none");
    let program = state.program.as_deref().unwrap_or("none");
    let args = if state.args_available { "available" } else { "unavailable" };
    format!(
        "tool={} call_id={} updates={} started_ago={}s idle={}s class={} program={} summary='{}' fingerprint={} args={}",
        state.name, call_id, state.update_count, started_ago, idle_for, state.command_class, program, state.command_summary, state.fingerprint, args,
    )
}

fn format_tool_brief(state: &Option<ActiveToolState>, now: Instant) -> String {
    match state {
        Some(s) => format_tool_diagnostic(s, now),
        None => "tool=none".to_string(),
    }
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
    fn supports_reviewer_mcp(&self) -> bool { false }
    async fn run_review_with_mcp(
        &self,
        _workspace: &Path,
        _prompt: &str,
        _backend_session_id: Option<&str>,
        _mcp_endpoint: &str,
    ) -> anyhow::Result<AgentRunResult> {
        bail!("{} runtime does not support reviewer MCP attachment", self.kind())
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

struct TempExtension(PathBuf);
impl Drop for TempExtension {
    fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); }
}

fn pi_reviewer_mcp_bridge_source(endpoint: &str) -> anyhow::Result<String> {
    let endpoint = serde_json::to_string(endpoint)?;
    Ok(format!(r#"const endpoint = {endpoint};
// Dependency-free by design: this file lives in a per-slot session directory,
// outside Pi's package tree. Semantic validation belongs to the Rust MCP slot.
const params = {{
  type: "object",
  additionalProperties: true,
  properties: {{
    verdict: {{ description: "Required: approve or retry" }},
    reason: {{ description: "Required non-empty review reason" }},
    validation: {{ description: "Required array of validation evidence strings" }},
  }},
}};

export default function lazyteamReviewerMcp(pi) {{
  pi.registerTool({{
    name: "submit_review",
    label: "Submit review",
    description: "Submit the terminal LazyTeam review verdict through MCP. If the server rejects arguments, correct them and call again without redoing the review.",
    parameters: params,
    executionMode: "sequential",
    async execute(_toolCallId, input) {{
      const body = {{
        jsonrpc: "2.0",
        id: `review-${{Date.now()}}-${{Math.random()}}`,
        method: "tools/call",
        params: {{
          _meta: {{
            "io.modelcontextprotocol/protocolVersion": "2026-07-28",
            "io.modelcontextprotocol/clientCapabilities": {{}},
          }},
          name: "submit_review",
          arguments: input,
        }},
      }};
      const response = await fetch(endpoint, {{
        method: "POST",
        headers: {{
          "content-type": "application/json",
          "accept": "application/json, text/event-stream",
          "MCP-Protocol-Version": "2026-07-28",
          "Mcp-Method": "tools/call",
          "Mcp-Name": "submit_review",
        }},
        body: JSON.stringify(body),
      }});
      const result = await response.json();
      if (!response.ok || result.error) throw new Error(result.error?.message || `review MCP HTTP ${{response.status}}`);
      const tool = result.result || {{}};
      const text = Array.isArray(tool.content)
        ? tool.content.filter((item) => item?.type === "text").map((item) => item.text).join("\\n")
        : "";
      if (tool.isError) throw new Error(text || "submit_review rejected");
      return {{
        content: Array.isArray(tool.content) ? tool.content : [{{ type: "text", text: "Review verdict accepted" }}],
        details: tool.structuredContent || {{}},
      }};
    }},
  }});

  // Reused reviewer sessions may persist an older active-tool allowlist from
  // before submit_review existed. Repair that session-local state explicitly
  // once the extension runtime is bound.
  pi.on("session_start", () => {{
    if (!pi.getAllTools().some((tool) => tool.name === "submit_review")) {{
      throw new Error("submit_review registered extension tool is unavailable");
    }}
    const active = new Set(pi.getActiveTools());
    active.add("submit_review");
    pi.setActiveTools([...active]);
    if (!pi.getActiveTools().includes("submit_review")) {{
      throw new Error("submit_review could not be activated for reviewer session");
    }}
  }});
}}
"#))
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
        extension: Option<&Path>,
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
        if let Some(extension) = extension {
            // Reviewer verdict transport must be deterministic: load only the
            // explicit slot bridge, not ambient/project extensions.
            command.arg("--no-extensions").arg("--extension").arg(extension);
        }
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
        let mut reviewer_final_nudged = false;
        let mut summary = String::new();
        let mut completed_tools = 0u64;
        let probe_interval = watchdog_probe_interval();
        let probe_grace = watchdog_probe_grace();
        let max_missed_probes = watchdog_max_missed_probes();
        let max_inactive_probes = watchdog_max_inactive_probes();
        let tool_stall_window = watchdog_tool_stall_window();
        let mut phase = RunPhase::Starting;
        let mut active_tool: Option<ActiveToolState> = None;
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
                        let tool_brief = format_tool_brief(&active_tool, Instant::now());
                        tracing::warn!(
                            session = session_name,
                            phase = phase.as_str(),
                            active_tool = active_tool.as_ref().map(|s| s.name_label()).unwrap_or("none"),
                            missed_probes,
                            max_missed_probes,
                            "Pi harness liveness probe timed out"
                        );
                        if missed_probes >= max_missed_probes {
                            let reason = format!(
                                "Pi harness unresponsive after {missed_probes} liveness probes; phase={} {}",
                                phase.as_str(),
                                tool_brief,
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

            let event_type = event.get("type").and_then(Value::as_str);
            // Tool progress is tied strictly to tool execution events.
            // Periodic `get_state` responses refresh liveness only and must
            // never refresh the tool stall clock (see `pi_state_probe_active`).
            if observe_pi_activity(&event, &mut phase, &mut active_tool, Instant::now()) {
                inactive_probes = 0;
            }
            if let Some(active) = pi_state_probe_active(&event, phase, active_tool_name(&active_tool)) {
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
                        let tool_brief = format_tool_brief(&active_tool, Instant::now());
                        let reason = format!(
                            "Pi harness stayed inactive for {inactive_probes} consecutive state probes; phase={} {}",
                            phase.as_str(),
                            tool_brief,
                        );
                        abort_pi_run(&mut child, &mut stdin).await;
                        bail!(reason);
                    }
                }
            }

            if phase == RunPhase::ToolRunning {
                if let Some(state) = active_tool.as_ref() {
                    let now = Instant::now();
                    if tool_stalled(state.last_progress_at, now, tool_stall_window) {
                        let stalled_for = now.saturating_duration_since(state.last_progress_at);
                        let diagnostic = format_tool_diagnostic(state, now);
                        tracing::warn!(
                            session = session_name,
                            active_tool = state.name_label(),
                            stalled_for_secs = stalled_for.as_secs(),
                            stall_limit_secs = tool_stall_window.as_secs(),
                            "Pi tool produced no observable progress; aborting stalled tool run"
                        );
                        let reason = format!(
                            "Pi tool '{}' produced no observable progress for {}s (limit {}s); {}",
                            state.name,
                            stalled_for.as_secs(),
                            tool_stall_window.as_secs(),
                            diagnostic,
                        );
                        abort_pi_run(&mut child, &mut stdin).await;
                        bail!(reason);
                    }
                }
            }

            match event_type {
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
                Some("extension_error") if extension.is_some() => {
                    let _ = child.kill().await;
                    bail!("Pi reviewer MCP bridge failed to load");
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
                    if review_budgets.is_some() && !reviewer_final_nudged {
                        reviewer_final_nudged = true;
                        tracing::warn!(
                            session = session_name,
                            "reviewer settled without terminal verdict; issuing one same-session submit_review nudge"
                        );
                        let request = json!({
                            "id":"review-final-nudge",
                            "type":"prompt",
                            "message":"Your substantive code review is already complete. Do not inspect files or redo the review. Call the submit_review tool now using the verdict, reason, and validation evidence you already decided. Do not answer with prose or JSON."
                        });
                        stdin.write_all(request.to_string().as_bytes()).await?;
                        stdin.write_all(b"\n").await?;
                        stdin.flush().await?;
                    } else {
                        requested_final = true;
                        let request = json!({"id":"final-text","type":"get_last_assistant_text"});
                        stdin.write_all(request.to_string().as_bytes()).await?;
                        stdin.write_all(b"\n").await?;
                        stdin.flush().await?;
                    }
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

    pub async fn force_refresh_models(&self, provider: &str) -> anyhow::Result<()> {
        let index = self.pi_module_index()?;
        let import_url = serde_json::to_string(&format!("file://{}", index.display()))?;
        let provider = serde_json::to_string(provider)?;
        let script = format!(
            r#"import {{ ModelRuntime }} from {import_url};
const dir=process.env.PI_CODING_AGENT_DIR;
const provider={provider};
const controller=new AbortController();
const timeout=setTimeout(()=>controller.abort(),15000);
try {{
  const rt=await ModelRuntime.create({{
    authPath:dir+"/auth.json",
    modelsPath:dir+"/models.json",
    modelsStorePath:dir+"/models-store.json",
    allowModelNetwork:false,
    refreshOnCreate:false
  }});
  const result=await rt.refresh({{allowNetwork:true,force:true,providers:[provider],signal:controller.signal}});
  if(result.aborted) throw new Error("model catalog refresh aborted");
  const error=result.errors.get(provider);
  if(error) throw error;
}} finally {{ clearTimeout(timeout); }}
console.log("ok");"#
        );
        let sandbox = self.sandbox.clone();
        tokio::time::timeout(std::time::Duration::from_secs(20), async move {
            let mut command = sandbox.command("node", sandbox.probe_workspace(), None)?;
            command.arg("--input-type=module").arg("--eval").arg(script);
            command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let output = command.output().await.context("run Pi forced model catalog refresh")?;
            if !output.status.success() {
                bail!("Pi model catalog refresh failed: {}", String::from_utf8_lossy(&output.stderr).trim());
            }
            Ok(())
        }).await.context("Pi model catalog refresh timed out")?
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
        self.run_rpc(workspace, prompt, backend_session_id, None, None).await
    }

    fn supports_reviewer_mcp(&self) -> bool { self.session_dir.is_some() }

    async fn run_review_with_mcp(
        &self,
        workspace: &Path,
        prompt: &str,
        backend_session_id: Option<&str>,
        mcp_endpoint: &str,
    ) -> anyhow::Result<AgentRunResult> {
        let session_dir = self.session_dir.as_ref().context("Pi reviewer MCP requires a session directory")?;
        tokio::fs::create_dir_all(session_dir).await?;
        let path = session_dir.join(format!("review-mcp-{}.ts", Uuid::new_v4().simple()));
        tokio::fs::write(&path, pi_reviewer_mcp_bridge_source(mcp_endpoint)?).await?;
        let extension = TempExtension(path);
        self.run_rpc(
            workspace,
            prompt,
            backend_session_id,
            Some(review_tool_budgets()),
            Some(&extension.0),
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
    fn reviewer_mcp_bridge_is_dependency_free_and_registers_terminal_tool() {
        let source = pi_reviewer_mcp_bridge_source("http://127.0.0.1:12345/mcp/cap").unwrap();
        assert!(!source.contains("import "), "temporary reviewer extension must not depend on node module resolution");
        assert!(source.contains("name: \"submit_review\""));
        assert!(source.contains("method: \"tools/call\""));
        assert!(source.contains("pi.on(\"session_start\""));
        assert!(source.contains("pi.setActiveTools"));
        assert!(source.contains("active.add(\"submit_review\")"));
        assert!(source.contains("http://127.0.0.1:12345/mcp/cap"));
    }

    #[test]
    fn harness_activity_tracks_tool_compaction_and_retry_phases() {
        let mut phase = RunPhase::Starting;
        let mut tool: Option<ActiveToolState> = None;
        let now = Instant::now();

        assert!(observe_pi_activity(&json!({"type":"message_update"}), &mut phase, &mut tool, now));
        assert_eq!(phase, RunPhase::ModelStreaming);

        assert!(observe_pi_activity(
            &json!({"type":"tool_execution_start","toolName":"bash"}),
            &mut phase,
            &mut tool,
            now,
        ));
        assert_eq!(phase, RunPhase::ToolRunning);
        assert_eq!(tool.as_ref().map(|s| s.name.as_str()), Some("bash"));

        assert!(observe_pi_activity(&json!({"type":"tool_execution_update"}), &mut phase, &mut tool, now));
        assert_eq!(phase, RunPhase::ToolRunning);
        assert_eq!(tool.as_ref().map(|s| s.update_count), Some(1));

        assert!(observe_pi_activity(&json!({"type":"tool_execution_end"}), &mut phase, &mut tool, now));
        assert_eq!(phase, RunPhase::ModelWaiting);
        assert!(tool.is_none());

        assert!(observe_pi_activity(&json!({"type":"compaction_start"}), &mut phase, &mut tool, now));
        assert_eq!(phase, RunPhase::Compacting);
        assert!(observe_pi_activity(&json!({"type":"compaction_end"}), &mut phase, &mut tool, now));
        assert_eq!(phase, RunPhase::ModelWaiting);

        assert!(observe_pi_activity(&json!({"type":"auto_retry_start"}), &mut phase, &mut tool, now));
        assert_eq!(phase, RunPhase::ProviderRetry);
        assert!(observe_pi_activity(&json!({"type":"auto_retry_end"}), &mut phase, &mut tool, now));
        assert_eq!(phase, RunPhase::ModelWaiting);
    }

    #[test]
    fn silent_bash_tool_preserves_timing_and_call_identity() {
        let mut phase = RunPhase::Starting;
        let mut tool: Option<ActiveToolState> = None;
        let start = Instant::now();
        assert!(observe_pi_activity(
            &json!({"type":"tool_execution_start","toolName":"bash","toolCallId":"call-silent-1"}),
            &mut phase,
            &mut tool,
            start,
        ));
        let state = tool.as_ref().expect("active bash tool");
        assert_eq!(state.name, "bash");
        assert_eq!(state.call_id.as_deref(), Some("call-silent-1"));
        assert_eq!(state.update_count, 0);
        assert_eq!(state.started_at, start);
        assert_eq!(state.last_progress_at, start);
        // No args exposed by this schema shape: record that explicitly while
        // still preserving timing/update-count/call-id evidence.
        assert!(!state.args_available);
        assert_eq!(state.command_class, "args-unavailable");
        let diagnostic = format_tool_diagnostic(state, start + Duration::from_secs(30 * 60));
        assert!(diagnostic.contains("tool=bash"));
        assert!(diagnostic.contains("call_id=call-silent-1"));
        assert!(diagnostic.contains("updates=0"));
        assert!(diagnostic.contains("args=unavailable"));
        assert!(diagnostic.contains("args-unavailable"));
    }

    #[test]
    fn updating_bash_tool_counts_progress_for_stall_clock() {
        let mut phase = RunPhase::Starting;
        let mut tool: Option<ActiveToolState> = None;
        let start = Instant::now();
        assert!(observe_pi_activity(
            &json!({"type":"tool_execution_start","toolName":"bash","toolCallId":"call-live-1","input":{"command":"cargo test --locked"}}),
            &mut phase,
            &mut tool,
            start,
        ));
        assert_eq!(tool.as_ref().map(|s| s.command_class.as_str()), Some("cargo-test"));
        assert_eq!(tool.as_ref().and_then(|s| s.program.as_deref()), Some("cargo"));
        let later = start + Duration::from_secs(10 * 60);
        assert!(observe_pi_activity(&json!({"type":"tool_execution_update","toolName":"bash"}), &mut phase, &mut tool, later));
        let state = tool.as_ref().expect("active bash tool");
        assert_eq!(state.update_count, 1);
        assert_eq!(state.last_progress_at, later);
        // Periodic progress keeps the stall clock fresh.
        assert!(!tool_stalled(state.last_progress_at, start + Duration::from_secs(35 * 60), Duration::from_secs(30 * 60)));
        // Silence past the window still stalls.
        assert!(tool_stalled(state.last_progress_at, later + Duration::from_secs(31 * 60), Duration::from_secs(30 * 60)));
    }

    #[test]
    fn non_bash_tool_uses_non_bash_class() {
        let mut phase = RunPhase::Starting;
        let mut tool: Option<ActiveToolState> = None;
        let now = Instant::now();
        assert!(observe_pi_activity(
            &json!({"type":"tool_execution_start","toolName":"read","toolCallId":"call-read-1","input":{"path":"src/main.rs"}}),
            &mut phase,
            &mut tool,
            now,
        ));
        let state = tool.as_ref().expect("active tool");
        assert_eq!(state.name, "read");
        assert_eq!(state.command_class, "non-bash");
        assert!(state.args_available);
        let diagnostic = format_tool_diagnostic(state, now);
        assert!(diagnostic.contains("class=non-bash"));
        assert!(!diagnostic.contains("src/main.rs"));
    }

    #[test]
    fn secret_bearing_bash_args_never_appear_in_durable_diagnostic() {
        let secret = "ghp_super_secret_token_abc123";
        let password = "s3cr3t-p4ssw0rd-value";
        let mut phase = RunPhase::Starting;
        let mut tool: Option<ActiveToolState> = None;
        let now = Instant::now();
        assert!(observe_pi_activity(
            &json!({"type":"tool_execution_start","toolName":"bash","toolCallId":"call-secret-1","input":{"command": format!("cargo test --token {secret} --password {password}")}}),
            &mut phase,
            &mut tool,
            now,
        ));
        let state = tool.as_ref().expect("active bash tool");
        assert_eq!(state.command_class, "cargo-test");
        assert_eq!(state.program.as_deref(), Some("cargo"));
        let diagnostic = format_tool_diagnostic(state, now);
        assert!(diagnostic.contains("cargo-test"));
        assert!(!diagnostic.contains(secret));
        assert!(!diagnostic.contains(password));
        // Stable fingerprint lets operators correlate without raw content.
        assert!(diagnostic.contains(&state.fingerprint));
        assert_eq!(state.fingerprint.len(), 16);
        // Same command always yields the same fingerprint.
        let (_, _, _, _, again) = derive_tool_command("bash", &json!({"input": {"command": format!("cargo test --token {secret} --password {password}")}}));
        assert_eq!(again, state.fingerprint);
    }

    #[test]
    fn bash_command_classes_cover_expected_families() {
        let (class, program, summary) = classify_bash_command("cargo check --locked");
        assert_eq!(class, "cargo-check");
        assert_eq!(program.as_deref(), Some("cargo"));
        assert_eq!(summary, "cargo check");
        let (class, _, _) = classify_bash_command("git fetch origin main");
        assert_eq!(class, "git");
        let (class, _, _) = classify_bash_command("curl https://example.com/pkg.tar.gz");
        assert_eq!(class, "network-fetch");
        let (class, _, _) = classify_bash_command("sleep 900");
        assert_eq!(class, "sleep-wait");
        // Redacted summaries never carry URLs, flags, or payloads.
        let (_, _, summary) = classify_bash_command("curl https://example.com/secret?token=abc --retry 5");
        assert_eq!(summary, "curl");
        assert!(!summary.contains("example.com"));
    }

    #[test]
    fn state_probe_responses_are_not_tool_progress() {
        let mut phase = RunPhase::Starting;
        let mut tool: Option<ActiveToolState> = None;
        let start = Instant::now();
        assert!(observe_pi_activity(
            &json!({"type":"tool_execution_start","toolName":"bash","toolCallId":"call-probe-1","input":{"command":"cargo test"}}),
            &mut phase,
            &mut tool,
            start,
        ));
        let progress_before = tool.as_ref().expect("active tool").last_progress_at;
        let updates_before = tool.as_ref().expect("active tool").update_count;
        let probe = json!({
            "type":"response",
            "command":"get_state",
            "success":true,
            "data":{"isStreaming":false,"isCompacting":false,"pendingMessageCount":0}
        });
        assert!(!observe_pi_activity(&probe, &mut phase, &mut tool, start + Duration::from_secs(60)));
        let state = tool.as_ref().expect("active tool still tracked");
        assert_eq!(state.last_progress_at, progress_before);
        assert_eq!(state.update_count, updates_before);
        // The probe still reports the tool as active for liveness purposes.
        assert_eq!(pi_state_probe_active(&probe, phase, active_tool_name(&tool)), Some(true));
    }

    #[test]
    fn tool_stall_clock_allows_periodic_progress() {
        let start = Instant::now();
        let window = Duration::from_secs(30 * 60);
        let refreshed = start + Duration::from_secs(20 * 60);
        let now = start + Duration::from_secs(40 * 60);
        assert!(!tool_stalled(refreshed, now, window));
    }

    #[test]
    fn tool_stall_clock_terminates_no_progress_past_window() {
        let start = Instant::now();
        let window = Duration::from_secs(30 * 60);
        assert!(tool_stalled(start, start + Duration::from_secs(31 * 60), window));
    }

    #[test]
    fn switching_tools_resets_tool_stall_clock() {
        let start = Instant::now();
        let window = Duration::from_secs(30 * 60);
        let second_tool_started = start + Duration::from_secs(29 * 60);
        let now = start + Duration::from_secs(45 * 60);
        assert!(!tool_stalled(second_tool_started, now, window));
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
