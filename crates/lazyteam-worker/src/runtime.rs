use std::{collections::BTreeMap, path::{Path, PathBuf}, process::Stdio};

use anyhow::{bail, Context};
use async_trait::async_trait;
use lazyteam_core::{AgentCapabilities, AgentLoginMode, AgentModel, AgentModelCost, AgentProvider};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, Instant};
use uuid::Uuid;

use lazyteam_sandbox::AgentSandbox;

const DEFAULT_WATCHDOG_PROBE_INTERVAL_SECS: u64 = 120;
const DEFAULT_WATCHDOG_PROBE_GRACE_SECS: u64 = 30;
const DEFAULT_WATCHDOG_MAX_MISSED_PROBES: u32 = 3;
const DEFAULT_WATCHDOG_MAX_INACTIVE_PROBES: u32 = 3;
const DEFAULT_WATCHDOG_TOOL_STALL_SECS: u64 = 10 * 60;
const DEFAULT_WATCHDOG_TOOL_HARD_LIMIT_SECS: u64 = 25 * 60;
const DEFAULT_WATCHDOG_MODEL_STALL_SECS: u64 = 6 * 60;
const TOOL_TIMEOUT_GRACE_SECS: u64 = 15;
const DEFAULT_REVIEW_SOFT_TOOL_BUDGET: u64 = 12;
const DEFAULT_REVIEW_HARD_TOOL_BUDGET: u64 = 20;
const REVIEW_TERMINAL_PROMPT: &str = "LAZYTEAM_REVIEW_TERMINAL_ONLY: The substantive review is complete. Do not inspect files, run commands, or redo the review. Use only submit_review now, with the verdict, reason, and validation evidence you already decided.";

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
        60,
        DEFAULT_WATCHDOG_TOOL_HARD_LIMIT_SECS,
    )
}

fn watchdog_tool_hard_limit() -> Duration {
    bounded_duration_from_env(
        "LAZYTEAM_HARNESS_TOOL_HARD_LIMIT_SECS",
        DEFAULT_WATCHDOG_TOOL_HARD_LIMIT_SECS,
        60,
        DEFAULT_WATCHDOG_TOOL_HARD_LIMIT_SECS,
    )
}

fn watchdog_model_stall_window() -> Duration {
    bounded_duration_from_env(
        "LAZYTEAM_HARNESS_MODEL_STALL_SECS",
        DEFAULT_WATCHDOG_MODEL_STALL_SECS,
        60,
        15 * 60,
    )
}

fn non_tool_phase_stalled(last_progress: Instant, now: Instant, window: Duration, has_active_tool: bool) -> bool {
    !has_active_tool && now.saturating_duration_since(last_progress) >= window
}

fn tool_stalled(last_progress: Instant, now: Instant, window: Duration) -> bool {
    now.saturating_duration_since(last_progress) >= window
}

const MAX_TOOL_NAME_LEN: usize = 32;
const MAX_TOOL_CALL_ID_LEN: usize = 64;
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
    requested_timeout_secs: Option<u64>,
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
fn requested_tool_timeout_secs(tool_name: &str, event: &Value) -> Option<u64> {
    if tool_name != "bash" {
        return None;
    }
    let args = tool_args_value(event)?;
    let timeout = args.as_object()?.get("timeout")?;
    let seconds = match timeout {
        Value::Number(number) => number.as_f64()?,
        Value::String(raw) => raw.trim().parse::<f64>().ok()?,
        _ => return None,
    };
    if !seconds.is_finite() || seconds <= 0.0 {
        return None;
    }
    Some(seconds.ceil().min(DEFAULT_WATCHDOG_TOOL_HARD_LIMIT_SECS as f64) as u64)
}

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

/// Closed vocabulary of executable basenames that may appear in durable
/// diagnostics. The program token is emitted only on exact membership, so an
/// attacker-controlled or secret-bearing argv[0] (a token, a path, or a
/// script name) can never be echoed back. Unknown programs still get a stable
/// fingerprint for correlation, but no name.
const KNOWN_PROGRAMS: &[&str] = &[
    "cargo", "rustc", "gcc", "g++", "cc", "c++", "clang", "clang++", "ld",
    "git", "gh", "glab",
    "curl", "wget", "aria2c",
    "ssh", "scp", "rsync", "sftp",
    "npm", "pnpm", "yarn", "bun", "deno", "node",
    "make", "just", "ninja", "cmake",
    "docker", "podman", "nerdctl",
    "kubectl", "helm", "terraform", "ansible", "ansible-playbook",
    "python", "python3", "pip", "pip3", "uv", "pytest", "pytest-3",
    "nextest", "cargo-nextest",
    "go", "java", "mvn", "gradle", "dotnet", "ruby", "bundle",
    "php", "composer", "perl", "lua", "rscript", "julia",
    "sqlite3", "psql", "mysql", "redis-cli",
    "tar", "zip", "unzip", "7z",
    "ls", "cat", "echo", "grep", "rg", "fd", "find", "head", "tail",
    "sed", "awk", "jq", "yq", "cut", "sort", "uniq", "wc", "diff",
    "less", "more", "file", "stat", "du", "df", "tee", "xargs",
    "chmod", "mkdir", "rm", "cp", "mv", "ln", "touch",
    "sleep", "systemctl", "journalctl",
    "apt", "apt-get", "dpkg", "yum", "dnf", "apk", "pacman", "brew",
];

/// Programs whose redacted summary may include an allowlisted subcommand.
/// Every other program is summarized by its bare name alone.
const SUMMARY_WITH_SUBCOMMAND: &[&str] = &[
    "cargo", "git", "npm", "pnpm", "yarn", "bun", "make", "just", "go",
    "docker", "podman", "kubectl",
];

const SHELL_PROGRAMS: &[&str] = &["sh", "bash", "dash", "zsh", "fish", "ksh"];

/// Wrapper flags that consume a following value while peeling. Best-effort
/// only and applied solely to leading wrapper arguments; unknown flags are
/// skipped singly without a value.
const WRAPPER_VALUE_FLAGS: &[&str] = &[
    "-u", "--user", "-g", "--group", "-s", "--signal", "--kill-after",
    "-n", "-o", "-e", "-i", "--unset", "-C", "--directory",
];

/// Quote-aware shell word splitter. Quoted spans stay one token (quote
/// characters removed); `;`, `&`, `|`, `(`, `)` terminate words so only the
/// leading command is considered.
fn split_shell_words(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    let mut chars = raw.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == '\\' {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
                in_word = true;
                continue;
            }
            if c == q {
                quote = None;
                continue;
            }
            cur.push(c);
            in_word = true;
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                in_word = true;
            }
            '\\' => {
                if let Some(n) = chars.next() {
                    cur.push(n);
                }
                in_word = true;
            }
            c if c.is_whitespace() | matches!(c, ';' | '&' | '|' | '(' | ')') => {
                if in_word {
                    out.push(std::mem::take(&mut cur));
                    in_word = false;
                }
            }
            _ => {
                cur.push(c);
                in_word = true;
            }
        }
    }
    if in_word {
        out.push(cur);
    }
    out
}

fn strip_outer_quotes(token: &str) -> &str {
    let bytes = token.as_bytes();
    if bytes.len() >= 2
        && (bytes[0] == b'"' || bytes[0] == b'\'')
        && bytes[bytes.len() - 1] == bytes[0]
    {
        &token[1..token.len() - 1]
    } else {
        token
    }
}

/// Lowercase basename: `/usr/bin/cargo` and `cargo` are the same program.
/// Basename is taken before any wrapper comparison so absolute wrapper
/// paths (`/usr/bin/env`, `/usr/bin/sudo`) still peel correctly.
fn exe_basename(token: &str) -> String {
    strip_outer_quotes(token.trim())
        .rsplit('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn is_flag(token: &str) -> bool {
    token.len() > 1 && token.starts_with('-')
}

/// `FOO=bar` assignments (value may itself contain `/`, `$`, etc.).
fn is_env_assignment(token: &str) -> bool {
    if token.starts_with('-') {
        return false;
    }
    let Some((key, _)) = token.split_once('=') else {
        return false;
    };
    let mut chars = key.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn is_bare_number(token: &str) -> bool {
    !token.is_empty() && token.chars().all(|c| c.is_ascii_digit())
}

/// `-c`/`-lc`/`-exc` style shell flags (not `--long` forms).
fn is_shell_c_flag(token: &str) -> bool {
    token.len() > 1
        && token.starts_with('-')
        && !token.starts_with("--")
        && token.contains('c')
}

/// Skip leading wrapper flags (and their values) plus env assignments.
/// Stops at the first real operand; everything from there is kept verbatim.
fn skip_wrapper_lead(tokens: &[String], extra_values: bool) -> Vec<String> {
    let mut rest = tokens;
    loop {
        let Some(first) = rest.first() else {
            break;
        };
        if is_flag(first) {
            let take_value = WRAPPER_VALUE_FLAGS.contains(&first.as_str());
            rest = &rest[1.min(rest.len())..];
            if take_value && !rest.is_empty() {
                rest = &rest[1.min(rest.len())..];
            }
            continue;
        }
        if is_env_assignment(first) {
            rest = &rest[1.min(rest.len())..];
            continue;
        }
        if extra_values {
            if is_bare_number(first) {
                rest = &rest[1.min(rest.len())..];
                continue;
            }
        }
        break;
    }
    rest.to_vec()
}

/// Peel shell wrappers to the effective command tokens, so `bash -lc`,
/// `sudo`, `env FOO=x`, and `timeout 300` prefixes still identify the
/// underlying program. Bounded depth; returns whatever remains.
fn peel_shell_tokens(raw: &str) -> Vec<String> {
    let mut tokens = split_shell_words(raw);
    for _ in 0..6 {
        if tokens.is_empty() {
            break;
        }
        let base = exe_basename(&tokens[0]);
        if SHELL_PROGRAMS.contains(&base.as_str()) {
            if let Some(pos) = tokens.iter().position(|t| is_shell_c_flag(t)) {
                let rest = tokens[pos + 1..].join(" ");
                let rest = strip_outer_quotes(rest.trim());
                if rest.is_empty() {
                    tokens.clear();
                    break;
                }
                let next = split_shell_words(rest);
                if next == tokens {
                    break;
                }
                tokens = next;
                continue;
            }
            // `bash script.sh ...`: drop the shell and its flags. The script
            // path itself is untrusted and gated by KNOWN_PROGRAMS below.
            let next: Vec<String> = tokens.into_iter().skip(1).filter(|t| !is_flag(t)).collect();
            tokens = next;
            continue;
        }
        if matches!(base.as_str(), "sudo" | "doas" | "su" | "runuser") {
            tokens = skip_wrapper_lead(&tokens[1..], false);
            continue;
        }
        if base == "env" {
            tokens = skip_wrapper_lead(&tokens[1..], false);
            continue;
        }
        if matches!(base.as_str(), "time" | "nice" | "stdbuf") {
            tokens = skip_wrapper_lead(&tokens[1..], false);
            continue;
        }
        if base == "timeout" {
            tokens = skip_wrapper_lead(&tokens[1..], true);
            continue;
        }
        if is_env_assignment(&tokens[0]) {
            tokens = skip_wrapper_lead(&tokens, false);
            continue;
        }
        break;
    }
    tokens
}

/// First operand that could be a subcommand. Flags, assignments, paths,
/// expansions, and quoted payloads are never candidates, so a secret-bearing
/// path such as `/tmp/ghp_...` can never become one. Membership in the
/// per-program allowlist below is still required before emission.
fn subcommand_candidate(tokens: &[String]) -> Option<String> {
    tokens.iter().skip(1).find_map(|token| {
        let cleaned = strip_outer_quotes(token.trim());
        if cleaned.is_empty()
            || cleaned.starts_with('-')
            || cleaned.chars().any(|c| matches!(c, '=' | '/' | '$' | '\\'))
        {
            return None;
        }
        Some(cleaned.to_ascii_lowercase())
    })
}

/// Closed per-program subcommand vocabulary. Only an exact member may be
/// emitted into durable summaries; everything else degrades to the bare
/// program name.
fn allowed_subcommand(program: &str, sub: &str) -> bool {
    let list: &[&str] = match program {
        "cargo" => &[
            "test", "check", "build", "clippy", "fmt", "run", "doc", "bench",
            "clean", "update", "install", "publish", "tree", "audit", "metadata",
        ],
        "git" => &[
            "fetch", "pull", "push", "status", "diff", "log", "show", "checkout",
            "switch", "clone", "add", "commit", "reset", "rebase", "merge",
            "stash", "branch", "tag", "remote", "submodule", "worktree",
            "rev-parse", "ls-files", "blame", "bisect", "init", "config",
            "clean", "mv", "rm", "grep",
        ],
        "npm" | "pnpm" | "yarn" | "bun" => &[
            "test", "run", "build", "install", "ci", "lint", "check", "start",
            "exec", "audit", "publish",
        ],
        "deno" => &["test", "run", "lint", "fmt", "check"],
        "docker" | "podman" | "nerdctl" => &[
            "build", "run", "pull", "push", "images", "ps", "exec", "logs",
            "compose", "login", "tag", "rm", "rmi",
        ],
        "kubectl" => &[
            "get", "describe", "apply", "delete", "logs", "exec", "create",
            "config", "top", "rollout", "drain",
        ],
        "helm" => &["install", "upgrade", "list", "status", "lint", "template"],
        "terraform" => &["plan", "apply", "init", "validate", "fmt", "show", "destroy"],
        "ansible" | "ansible-playbook" => &["playbook", "ping", "lint"],
        "make" | "just" => &["test", "check", "build", "lint", "clean", "install", "all", "fmt", "vet"],
        "go" => &["test", "build", "vet", "run", "mod", "install", "fmt", "generate"],
        "cargo-nextest" | "nextest" | "pytest" | "pytest-3" => &[],
        "python" | "python3" => &["pytest", "unittest"],
        "uv" | "pip" | "pip3" => &["install", "test", "run", "sync", "lock", "audit"],
        _ => &[],
    };
    list.contains(&sub)
}

fn classify_tokens(program: &str, sub: Option<&str>) -> &'static str {
    match (program, sub) {
        ("cargo", Some("test")) => "cargo-test",
        ("cargo", Some("check")) => "cargo-check",
        ("cargo", Some("build")) => "cargo-build",
        ("cargo", Some("clippy")) => "cargo-clippy",
        ("cargo", Some("fmt")) => "cargo-fmt",
        ("cargo", _) => "cargo",
        ("git" | "gh" | "glab", _) => "git",
        ("curl" | "wget" | "aria2c", _) => "network-fetch",
        ("ssh" | "scp" | "rsync" | "sftp", _) => "network-ssh",
        ("npm" | "pnpm" | "yarn" | "bun" | "deno", _) => "node-build",
        ("docker" | "podman" | "nerdctl", _) => "container",
        ("kubectl" | "helm" | "terraform" | "ansible" | "ansible-playbook", _) => "deploy",
        ("make" | "just" | "ninja" | "cmake", _) => "build",
        ("pytest" | "pytest-3", _) => "python-test",
        ("nextest" | "cargo-nextest", _) => "cargo-test",
        ("python" | "python3", Some("pytest")) | ("python" | "python3", Some("unittest")) => "python-test",
        ("python" | "python3" | "uv" | "pip" | "pip3", _) => "python",
        ("go", _) => "go",
        ("rustc", _) => "rustc-build",
        ("gcc" | "g++" | "cc" | "c++" | "clang" | "clang++" | "ld", _) => "compiler",
        ("java" | "mvn" | "gradle" | "dotnet", _) => "jvm-build",
        ("sleep", _) => "sleep-wait",
        ("ls" | "cat" | "echo" | "grep" | "rg" | "fd" | "find" | "head" | "tail" | "sed" | "awk" | "jq" | "yq" | "cut" | "sort" | "uniq" | "wc" | "diff" | "less" | "more" | "file" | "stat" | "du" | "df" | "tee", _) => "shell-inspect",
        _ => "generic-shell",
    }
}

fn classify_bash_command(raw: &str) -> (String, Option<String>, String) {
    let tokens = peel_shell_tokens(raw);
    let program = tokens
        .first()
        .map(|t| exe_basename(t))
        .filter(|p| KNOWN_PROGRAMS.contains(&p.as_str()));
    let Some(program) = program else {
        return ("generic-shell".to_string(), None, "generic-shell".to_string());
    };
    // Defense in depth: the candidate already excludes flags, assignments,
    // paths, and expansions, and only an allowlisted subcommand is emitted.
    let sub = subcommand_candidate(&tokens).filter(|s| allowed_subcommand(&program, s));
    let class = classify_tokens(&program, sub.as_deref());
    let summary = if SUMMARY_WITH_SUBCOMMAND.contains(&program.as_str()) {
        match sub {
            Some(s) => format!("{program} {s}"),
            None => program.clone(),
        }
    } else {
        program.clone()
    };
    let summary = summary.chars().take(MAX_COMMAND_SUMMARY_LEN).collect::<String>();
    (class.to_string(), Some(program), summary)
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

/// Pi executes tool calls in parallel (`executeToolCallsParallel` in the Pi
/// bundle), so the watchdog tracks every in-flight call keyed by its
/// tool-call id instead of a single "active tool". Updates are routed by id
/// (never by bare tool name across calls); a completion removes only its own
/// call. Events without an id fall back to stalest same-name matching or a
/// bounded anonymous slot, so a missing id degrades one entry, never the
/// whole table.
#[derive(Debug, Default)]
struct ActiveTools {
    calls: BTreeMap<String, ActiveToolState>,
    anon_seq: u64,
}

/// Upper bound on tracked in-flight calls; the stalest entry is evicted past
/// it so a pathological event stream cannot grow memory without bound.
const MAX_ACTIVE_TOOLS: usize = 32;
/// Upper bound on per-call entries rendered into one durable brief.
const MAX_BRIEF_TOOLS: usize = 4;

impl ActiveTools {
    fn new() -> Self {
        Self::default()
    }

    fn any(&self) -> bool {
        !self.calls.is_empty()
    }

    fn is_empty(&self) -> bool {
        self.calls.is_empty()
    }

    fn len(&self) -> usize {
        self.calls.len()
    }

    /// Short label for log fields: distinct tool names, bounded.
    fn label(&self) -> String {
        if self.calls.is_empty() {
            return "none".to_string();
        }
        let mut names: Vec<&str> = self.calls.values().map(|s| s.name.as_str()).collect();
        names.sort();
        names.dedup();
        let extra = names.len().saturating_sub(3);
        let mut label = names.into_iter().take(3).collect::<Vec<_>>().join("+");
        if extra > 0 {
            label.push_str(&format!("+{extra}"));
        }
        label
    }

    /// The stalest in-flight call past the stall window, if any. Only the
    /// earliest `last_progress_at` can stall first, so one entry determines
    /// the watchdog decision while the brief still lists the rest.
    fn stalest_stalled(&self, now: Instant, window: Duration) -> Option<&ActiveToolState> {
        // A bash call with an explicit timeout is allowed to be completely
        // quiet (for example `cargo test | tail`). Its requested timeout is a
        // stronger contract than stdout activity, so the hard-runtime check
        // governs it instead of misclassifying buffered output as a stall.
        let stalest = self.calls
            .values()
            .filter(|state| state.requested_timeout_secs.is_none())
            .min_by_key(|state| state.last_progress_at)?;
        if tool_stalled(stalest.last_progress_at, now, window) {
            Some(stalest)
        } else {
            None
        }
    }

    fn first_hard_limit_exceeded(&self, now: Instant, hard_limit: Duration) -> Option<&ActiveToolState> {
        self.calls
            .values()
            .filter(|state| now.saturating_duration_since(state.started_at) >= active_tool_hard_limit(state, hard_limit))
            .min_by_key(|state| state.started_at)
    }

    /// Bounded multi-call brief for durable failure evidence. Earliest idle
    /// first, capped at MAX_BRIEF_TOOLS entries plus a remainder count.
    fn brief(&self, now: Instant) -> String {
        if self.calls.is_empty() {
            return "tool=none".to_string();
        }
        let mut ordered: Vec<&ActiveToolState> = self.calls.values().collect();
        ordered.sort_by_key(|s| s.last_progress_at);
        let mut out = format!("tools={}", self.calls.len());
        for state in ordered.into_iter().take(MAX_BRIEF_TOOLS) {
            out.push_str(" [");
            out.push_str(&format_tool_diagnostic(state, now));
            out.push(']');
        }
        if self.calls.len() > MAX_BRIEF_TOOLS {
            out.push_str(&format!(" +{} more", self.calls.len() - MAX_BRIEF_TOOLS));
        }
        out
    }

    fn stalest_key(&self) -> Option<String> {
        self.calls
            .iter()
            .min_by_key(|(_, s)| s.last_progress_at)
            .map(|(k, _)| k.clone())
    }

    fn insert_state(&mut self, key: String, state: ActiveToolState) {
        if self.calls.len() >= MAX_ACTIVE_TOOLS && !self.calls.contains_key(&key) {
            if let Some(old) = self.stalest_key() {
                self.calls.remove(&old);
            }
        }
        self.calls.insert(key, state);
    }

    fn on_start(&mut self, event: &Value, name: String, now: Instant) {
        let call_id = extract_tool_call_id(event);
        let (args_available, command_class, program, command_summary, fingerprint) =
            derive_tool_command(&name, event);
        let requested_timeout_secs = requested_tool_timeout_secs(&name, event);
        let key = match &call_id {
            Some(id) => format!("id:{id}"),
            None => {
                self.anon_seq = self.anon_seq.wrapping_add(1);
                format!("anon:{}:{}", name, self.anon_seq)
            }
        };
        self.insert_state(
            key,
            ActiveToolState {
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
                requested_timeout_secs,
            },
        );
    }

    /// Adopt freshly exposed arguments on a later update (the start may have
    /// carried none). Only upgrades `args-unavailable` entries and only from
    /// the event routed to this same call.
    fn adopt_args(state: &mut ActiveToolState, event: &Value) {
        if state.args_available || tool_args_value(event).is_none() {
            return;
        }
        let name = state.name.clone();
        let (args_available, command_class, program, command_summary, fingerprint) =
            derive_tool_command(&name, event);
        state.args_available = args_available;
        state.command_class = command_class;
        state.program = program;
        state.command_summary = command_summary;
        state.fingerprint = fingerprint;
        if state.requested_timeout_secs.is_none() {
            state.requested_timeout_secs = requested_tool_timeout_secs(&name, event);
        }
    }

    fn on_update(&mut self, event: &Value, name: String, now: Instant) {
        if let Some(id) = extract_tool_call_id(event) {
            let key = format!("id:{id}");
            if let Some(state) = self.calls.get_mut(&key) {
                state.last_progress_at = now;
                state.update_count += 1;
                if state.call_id.is_none() {
                    state.call_id = Some(id);
                }
                Self::adopt_args(state, event);
                return;
            }
            // Update for an unknown id (e.g. a missed start): track it so
            // its stall timing is still observed, counting this as progress.
            self.on_start(event, name, now);
            if let Some(state) = self.calls.get_mut(&key) {
                state.update_count = 1;
            }
            return;
        }
        // Single in-flight call with an unattributed update: no siblings to
        // confuse, so refresh it (preserves legacy single-tool behavior).
        if name == "unknown" && self.calls.len() == 1 {
            if let Some(state) = self.calls.values_mut().next() {
                state.last_progress_at = now;
                state.update_count += 1;
                Self::adopt_args(state, event);
            }
            return;
        }
        // No id: route to the stalest same-name call, else an anonymous slot.
        let routed = self
            .calls
            .iter()
            .filter(|(_, s)| s.name == name)
            .min_by_key(|(_, s)| s.last_progress_at)
            .map(|(k, _)| k.clone());
        match routed {
            Some(key) => {
                if let Some(state) = self.calls.get_mut(&key) {
                    state.last_progress_at = now;
                    state.update_count += 1;
                    Self::adopt_args(state, event);
                }
            }
            None => self.on_start(event, name, now),
        }
    }

    fn on_end(&mut self, event: &Value, name: &str) {
        if let Some(id) = extract_tool_call_id(event) {
            self.calls.remove(&format!("id:{id}"));
            return;
        }
        // Single in-flight call with an unattributed end: unambiguous.
        if name == "unknown" && self.calls.len() == 1 {
            if let Some(key) = self.calls.keys().next().cloned() {
                self.calls.remove(&key);
            }
            return;
        }
        // No id: drop only the stalest same-name call, never its siblings.
        // (Real Pi end events always carry the id; this is a fallback.)
        let routed = self
            .calls
            .iter()
            .filter(|(_, s)| s.name == name)
            .min_by_key(|(_, s)| s.last_progress_at)
            .map(|(k, _)| k.clone());
        if let Some(key) = routed {
            self.calls.remove(&key);
        }
    }

    #[cfg(test)]
    fn single(&self) -> Option<&ActiveToolState> {
        if self.calls.len() == 1 {
            self.calls.values().next()
        } else {
            None
        }
    }

    #[cfg(test)]
    fn get(&self, call_id: &str) -> Option<&ActiveToolState> {
        self.calls.get(&format!("id:{call_id}"))
    }
}

fn active_tool_hard_limit(state: &ActiveToolState, global_hard_limit: Duration) -> Duration {
    match state.requested_timeout_secs {
        Some(seconds) => Duration::from_secs(seconds.saturating_add(TOOL_TIMEOUT_GRACE_SECS)).min(global_hard_limit),
        None => global_hard_limit,
    }
}

fn observe_pi_activity(
    event: &Value,
    phase: &mut RunPhase,
    active: &mut ActiveTools,
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
            active.on_start(event, name, now);
            *phase = RunPhase::ToolRunning;
            true
        }
        Some("tool_execution_update") => {
            let name = extract_tool_name(event);
            active.on_update(event, name, now);
            *phase = RunPhase::ToolRunning;
            true
        }
        Some("tool_execution_end") => {
            let name = extract_tool_name(event);
            active.on_end(event, &name);
            // A completion clears only its own call: siblings stay tracked
            // and the phase stays ToolRunning until the last one ends.
            *phase = if active.is_empty() {
                RunPhase::ModelWaiting
            } else {
                RunPhase::ToolRunning
            };
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

fn pi_state_probe_active(event: &Value, phase: RunPhase, has_active_tool: bool) -> Option<bool> {
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
            || has_active_tool
            || matches!(phase, RunPhase::ToolRunning | RunPhase::Compacting | RunPhase::ProviderRetry),
    )
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
    let timeout = state.requested_timeout_secs
        .map(|seconds| format!("{seconds}s"))
        .unwrap_or_else(|| "none".to_string());
    format!(
        "tool={} call_id={} updates={} started_ago={}s idle={}s class={} program={} summary='{}' fingerprint={} args={} timeout={}",
        state.name, call_id, state.update_count, started_ago, idle_for, state.command_class, program, state.command_summary, state.fingerprint, args, timeout,
    )
}

async fn terminate_pi_child(child: &mut tokio::process::Child) -> anyhow::Result<()> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    child.start_kill().context("signal Pi RPC child")?;
    tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .context("Pi RPC child did not exit within 5s after termination signal")??;
    Ok(())
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
    if let Err(error) = terminate_pi_child(child).await {
        tracing::warn!(%error, "failed to terminate Pi RPC child during watchdog abort");
    }
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
    let terminal_prompt = serde_json::to_string(REVIEW_TERMINAL_PROMPT)?;
    Ok(format!(r#"const endpoint = {endpoint};
const terminalPrompt = {terminal_prompt};
// Dependency-free by design: this file lives in a per-slot session directory,
// outside Pi's package tree. Semantic validation belongs to the Rust MCP slot.
const params = {{
  type: "object",
  additionalProperties: true,
  required: ["verdict", "reason"],
  properties: {{
    verdict: {{ type: "string", enum: ["approve", "retry"], description: "approve or retry" }},
    reason: {{ type: "string", minLength: 1, description: "Non-empty review reason" }},
    validation: {{
      description: "Optional validation evidence. Prefer an array of strings; one string is also accepted.",
      anyOf: [
        {{ type: "array", items: {{ type: "string" }}, maxItems: 32 }},
        {{ type: "string" }},
      ],
    }},
  }},
}};

export default function lazyteamReviewerMcp(pi) {{
  let terminalOnly = false;
  let terminalPreviousTools = null;

  function restoreTerminalTools() {{
    if (terminalOnly && Array.isArray(terminalPreviousTools) && terminalPreviousTools.length > 0) {{
      pi.setActiveTools(terminalPreviousTools);
    }}
    terminalOnly = false;
    terminalPreviousTools = null;
  }}

  function keepTerminalOnly() {{
    pi.setActiveTools(["submit_review"]);
  }}

  function forceSubmitReviewChoice(payload) {{
    if (!terminalOnly || !payload || typeof payload !== "object") return payload;
    const tools = Array.isArray(payload.tools) ? payload.tools : [];
    const openaiChat = tools.find((tool) => tool?.function?.name === "submit_review");
    if (openaiChat) {{
      return {{ ...payload, tool_choice: {{ type: "function", function: {{ name: "submit_review" }} }} }};
    }}
    const named = tools.find((tool) => tool?.name === "submit_review");
    if (named) {{
      const choice = Object.prototype.hasOwnProperty.call(named, "input_schema")
        ? {{ type: "tool", name: "submit_review" }}
        : {{ type: "function", name: "submit_review" }};
      return {{ ...payload, tool_choice: choice }};
    }}
    return payload;
  }}

  pi.registerTool({{
    name: "submit_review",
    label: "Submit review",
    description: "Submit the terminal LazyTeam review verdict through MCP. If the server rejects arguments, correct them and call again without redoing the review.",
    parameters: params,
    executionMode: "sequential",
    async execute(_toolCallId, input) {{
      // Restore normal reviewer tools before the MCP request can wake the
      // Rust slot and terminate this Pi process. Re-enter terminal-only on a
      // rejected/failed submit so the correction turn cannot wander.
      const terminalSubmit = terminalOnly && Array.isArray(terminalPreviousTools);
      if (terminalSubmit) pi.setActiveTools(terminalPreviousTools);
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
      try {{
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
        terminalOnly = false;
        terminalPreviousTools = null;
        return {{
          content: Array.isArray(tool.content) ? tool.content : [{{ type: "text", text: "Review verdict accepted" }}],
          details: tool.structuredContent || {{}},
        }};
      }} catch (error) {{
        if (terminalSubmit) keepTerminalOnly();
        throw error;
      }}
    }},
  }});

  // A second turn after substantive review is deliberately terminal-only.
  // Hide repository/tooling affordances from the model instead of merely
  // asking it not to use them; this prevents cheap reviewers from restarting
  // inspection and burning the review tool budget after they already decided.
  pi.on("before_agent_start", (event) => {{
    if (event.prompt !== terminalPrompt) return;
    terminalPreviousTools = pi.getActiveTools();
    if (!terminalPreviousTools.includes("submit_review")) {{
      terminalPreviousTools = [...terminalPreviousTools, "submit_review"];
    }}
    terminalOnly = true;
    keepTerminalOnly();
    return {{
      systemPrompt: "You are submitting the terminal verdict for a review you already completed. The only available tool is submit_review. Use it now. Do not inspect the repository, run commands, or answer with prose or JSON.",
    }};
  }});

  // Active-tools hides every other tool from the terminal turn. For provider
  // payloads that expose an explicit tool choice, require submit_review so a
  // weak reviewer cannot end the terminal turn with prose and zero MCP calls.
  pi.on("before_provider_request", (event) => forceSubmitReviewChoice(event.payload));

  // Providers without a forceable tool-choice shape retain the existing
  // bounded failure behavior.
  pi.on("agent_settled", () => restoreTerminalTools());
  pi.on("session_shutdown", () => restoreTerminalTools());

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
        let tool_hard_limit = watchdog_tool_hard_limit();
        let model_stall_window = watchdog_model_stall_window();
        let mut phase = RunPhase::Starting;
        let mut active_tools = ActiveTools::new();
        let mut next_probe_at = Instant::now() + probe_interval;
        let mut probe_deadline: Option<Instant> = None;
        let mut missed_probes = 0u32;
        let mut inactive_probes = 0u32;
        let mut probe_sequence = 0u64;
        let mut last_meaningful_progress = Instant::now();

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
                        let tool_brief = active_tools.brief(now);
                        let tool_label = active_tools.label();
                        tracing::warn!(
                            session = session_name,
                            phase = phase.as_str(),
                            active_tool = tool_label.as_str(),
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
            let now = Instant::now();
            if observe_pi_activity(&event, &mut phase, &mut active_tools, now) {
                inactive_probes = 0;
                last_meaningful_progress = now;
            }
            if let Some(active) = pi_state_probe_active(&event, phase, active_tools.any()) {
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
                        let tool_brief = active_tools.brief(Instant::now());
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

            let now = Instant::now();
            if non_tool_phase_stalled(
                last_meaningful_progress,
                now,
                model_stall_window,
                active_tools.any(),
            ) {
                let stalled_for = now.saturating_duration_since(last_meaningful_progress);
                tracing::warn!(
                    session = session_name,
                    phase = phase.as_str(),
                    stalled_for_secs = stalled_for.as_secs(),
                    stall_limit_secs = model_stall_window.as_secs(),
                    "Pi model/provider phase produced no meaningful progress; aborting run"
                );
                let reason = format!(
                    "Pi model/provider phase '{}' produced no meaningful progress for {}s (limit {}s)",
                    phase.as_str(),
                    stalled_for.as_secs(),
                    model_stall_window.as_secs(),
                );
                abort_pi_run(&mut child, &mut stdin).await;
                bail!(reason);
            }

            if phase == RunPhase::ToolRunning {
                let now = Instant::now();
                if let Some(expired) = active_tools.first_hard_limit_exceeded(now, tool_hard_limit) {
                    let elapsed = now.saturating_duration_since(expired.started_at);
                    let effective_limit = active_tool_hard_limit(expired, tool_hard_limit);
                    let diagnostic = format_tool_diagnostic(expired, now);
                    tracing::warn!(
                        session = session_name,
                        active_tool = expired.name_label(),
                        elapsed_secs = elapsed.as_secs(),
                        hard_limit_secs = effective_limit.as_secs(),
                        "Pi tool exceeded hard runtime limit; aborting run"
                    );
                    let reason = format!(
                        "Pi tool '{}' exceeded its hard runtime limit after {}s (limit {}s); {}",
                        expired.name,
                        elapsed.as_secs(),
                        effective_limit.as_secs(),
                        diagnostic,
                    );
                    abort_pi_run(&mut child, &mut stdin).await;
                    bail!(reason);
                }
                if let Some(stalled) = active_tools.stalest_stalled(now, tool_stall_window) {
                    let stalled_for = now.saturating_duration_since(stalled.last_progress_at);
                    let diagnostic = format_tool_diagnostic(stalled, now);
                    let tool_count = active_tools.len();
                    tracing::warn!(
                        session = session_name,
                        active_tool = stalled.name_label(),
                        stalled_for_secs = stalled_for.as_secs(),
                        stall_limit_secs = tool_stall_window.as_secs(),
                        active_tools = tool_count,
                        "Pi tool produced no observable progress; aborting stalled tool run"
                    );
                    let reason = format!(
                        "Pi tool '{}' produced no observable progress for {}s (limit {}s); active_tools={} {}",
                        stalled.name,
                        stalled_for.as_secs(),
                        tool_stall_window.as_secs(),
                        tool_count,
                        diagnostic,
                    );
                    abort_pi_run(&mut child, &mut stdin).await;
                    bail!(reason);
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
                    terminate_pi_child(&mut child).await?;
                    bail!("Pi requested interactive extension UI; worker tasks must be unattended");
                }
                Some("extension_error") if extension.is_some() => {
                    terminate_pi_child(&mut child).await?;
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
                            "reviewer settled without terminal verdict; starting one same-session terminal-only submit_review turn"
                        );
                        let request = json!({
                            "id":"review-final-nudge",
                            "type":"prompt",
                            "message":REVIEW_TERMINAL_PROMPT
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
                    terminate_pi_child(&mut child).await?;
                    bail!("Pi failed to return final assistant text: {event}");
                }
                _ => {}
            }
        }

        if !requested_final {
            let status = child.wait().await?;
            bail!("Pi RPC exited before agent_settled: {status}");
        }
        terminate_pi_child(&mut child)
            .await
            .context("terminate settled Pi RPC child")?;
        Ok(AgentRunResult { summary, backend_session_id: None })
    }

    pub(crate) fn pi_module_index(&self) -> anyhow::Result<PathBuf> {
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

    pub async fn store_api_key(&self, provider: &str, api_key: &str) -> anyhow::Result<()> {
        let provider = provider.trim();
        if provider.is_empty() || api_key.trim().is_empty() {
            bail!("provider and API key are required");
        }
        let index = self.pi_module_index()?;
        let dist = index.parent().context("Pi public module missing dist parent")?;
        let auth_storage_url = serde_json::to_string(&format!(
            "file://{}",
            dist.join("core").join("auth-storage.js").display()
        ))?;
        let script = format!(
            r#"import {{ AuthStorage }} from {auth_storage_url};
let input="";
for await (const chunk of process.stdin) input+=chunk;
const {{provider,key}}=JSON.parse(input);
const dir=process.env.PI_CODING_AGENT_DIR;
const auth=AuthStorage.create(dir+"/auth.json");
await auth.modify(provider,async()=>({{type:"api_key",key}}));
console.log("ok");"#
        );
        let payload = serde_json::to_vec(&json!({"provider": provider, "key": api_key}))?;
        let sandbox = self.sandbox.clone();
        // Pi's proper-lockfile backend can legitimately wait up to 30s
        // for an existing credential writer. Stay above that window, but make
        // timeout cancellation kill the helper so a failed delivery cannot
        // perform a delayed credential write after the worker starts retrying.
        tokio::time::timeout(std::time::Duration::from_secs(35), async move {
            let mut command = sandbox.command("node", sandbox.probe_workspace(), None)?;
            command.arg("--input-type=module").arg("--eval").arg(script);
            command.kill_on_drop(true);
            command.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let mut child = command.spawn().context("spawn Pi credential store helper")?;
            let mut stdin = child.stdin.take().context("Pi credential store helper stdin missing")?;
            stdin.write_all(&payload).await?;
            stdin.shutdown().await?;
            drop(stdin);
            let output = child.wait_with_output().await.context("wait for Pi credential store helper")?;
            if !output.status.success() {
                bail!("Pi credential store helper failed: {}", String::from_utf8_lossy(&output.stderr).trim());
            }
            Ok::<(), anyhow::Error>(())
        }).await.context("Pi credential store helper timed out")??;
        self.sandbox.repair_pi_state_permissions().await?;
        Ok(())
    }

    async fn probe_providers(&self) -> anyhow::Result<Vec<AgentProvider>> {
        let index = self.pi_module_index()?;
        let dist = index.parent().context("Pi public module missing dist parent")?;
        let import_url = serde_json::to_string(&format!("file://{}", index.display()))?;
        let auth_storage_url = serde_json::to_string(&format!(
            "file://{}",
            dist.join("core").join("auth-storage.js").display()
        ))?;
        let models_store_url = serde_json::to_string(&format!(
            "file://{}",
            dist.join("core").join("models-store.js").display()
        ))?;
        let script = format!(
            r#"import {{ ModelRuntime }} from {import_url};
import {{ ReadOnlyAuthStorage }} from {auth_storage_url};
import {{ InMemoryCodingAgentModelsStore }} from {models_store_url};
const dir=process.env.PI_CODING_AGENT_DIR;
const rt=await ModelRuntime.create({{
  credentials:new ReadOnlyAuthStorage(dir+"/auth.json"),
  modelsPath:dir+"/models.json",
  modelsStore:new InMemoryCodingAgentModelsStore(),
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
            command.kill_on_drop(true);
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
        let dist = index.parent().context("Pi public module missing dist parent")?;
        let import_url = serde_json::to_string(&format!("file://{}", index.display()))?;
        let auth_storage_url = serde_json::to_string(&format!(
            "file://{}",
            dist.join("core").join("auth-storage.js").display()
        ))?;
        let provider = serde_json::to_string(provider)?;
        let script = model_refresh_script(&import_url, &auth_storage_url, &provider);
        let sandbox = self.sandbox.clone();
        let refresh_result = match tokio::time::timeout(std::time::Duration::from_secs(20), async move {
            let mut command = sandbox.command("node", sandbox.probe_workspace(), None)?;
            command.arg("--input-type=module").arg("--eval").arg(script);
            command.kill_on_drop(true);
            command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let output = command.output().await.context("run Pi forced model catalog refresh")?;
            if !output.status.success() {
                bail!("Pi model catalog refresh failed: {}", String::from_utf8_lossy(&output.stderr).trim());
            }
            Ok(())
        }).await {
            Ok(result) => result,
            Err(error) => Err(anyhow::Error::new(error).context("Pi model catalog refresh timed out")),
        };
        let permissions_result = self.sandbox.repair_pi_state_permissions().await;
        match (refresh_result, permissions_result) {
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error),
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    async fn probe_models(&self) -> anyhow::Result<Vec<AgentModel>> {
        let index = self.pi_module_index()?;
        let dist = index.parent().context("Pi public module missing dist parent")?;
        let import_url = serde_json::to_string(&format!("file://{}", index.display()))?;
        let auth_storage_url = serde_json::to_string(&format!(
            "file://{}",
            dist.join("core").join("auth-storage.js").display()
        ))?;
        let models_store_url = serde_json::to_string(&format!(
            "file://{}",
            dist.join("core").join("models-store.js").display()
        ))?;
        let script = format!(
            r#"import {{ ModelRuntime }} from {import_url};
import {{ ReadOnlyAuthStorage }} from {auth_storage_url};
import {{ InMemoryCodingAgentModelsStore }} from {models_store_url};
const dir=process.env.PI_CODING_AGENT_DIR;
const rt=await ModelRuntime.create({{
  credentials:new ReadOnlyAuthStorage(dir+"/auth.json"),
  modelsPath:dir+"/models.json",
  modelsStore:new InMemoryCodingAgentModelsStore(),
  allowModelNetwork:false,
  refreshOnCreate:false
}});
const models=await rt.getAvailable();
console.log(JSON.stringify(models));"#
        );
        let sandbox = self.sandbox.clone();
        tokio::time::timeout(std::time::Duration::from_secs(10), async move {
            let mut command = sandbox.command("node", sandbox.probe_workspace(), None)?;
            command.arg("--input-type=module").arg("--eval").arg(script);
            command.kill_on_drop(true);
            command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let output = command.output().await.context("run Pi ModelRuntime model probe")?;
            if !output.status.success() {
                bail!("Pi model probe failed: {}", String::from_utf8_lossy(&output.stderr).trim());
            }
            let models = serde_json::from_slice::<Vec<Value>>(&output.stdout)
                .context("parse Pi ModelRuntime model probe output")?
                .iter()
                .filter_map(agent_model_from_pi)
                .collect();
            Ok(models)
        }).await.context("Pi capability probe timed out")?
    }
}

/// Node script executed for a forced provider model-catalog refresh.
///
/// Extracted as a pure builder so the refresh regression test runs the exact
/// production script text against local fake Pi fixtures (no network, no paid
/// model call). The script must keep using the read-only credential store:
/// a writable `AuthStorage` here would let a refresh mutate or truncate the
/// worker-scoped `auth.json`. `import_url`, `auth_storage_url`, and
/// `provider_json` are pre-quoted JSON string literals.
fn model_refresh_script(import_url: &str, auth_storage_url: &str, provider_json: &str) -> String {
    format!(
        r#"import {{ ModelRuntime }} from {import_url};
import {{ ReadOnlyAuthStorage }} from {auth_storage_url};
const dir=process.env.PI_CODING_AGENT_DIR;
const provider={provider_json};
const controller=new AbortController();
const timeout=setTimeout(()=>controller.abort(),15000);
try {{
  const rt=await ModelRuntime.create({{
    credentials:new ReadOnlyAuthStorage(dir+"/auth.json"),
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
    )
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

    #[tokio::test]
    async fn pi_child_termination_is_bounded_and_reaps() {
        let mut child = tokio::process::Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), terminate_pi_child(&mut child))
            .await
            .expect("Pi child termination must be bounded")
            .unwrap();
        assert!(child.try_wait().unwrap().is_some(), "terminated child must be reaped");
    }

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
        assert!(source.contains("required: [\"verdict\", \"reason\"]"));
        assert!(source.contains("enum: [\"approve\", \"retry\"]"));
        assert!(source.contains("Optional validation evidence"));
        assert!(source.contains("method: \"tools/call\""));
        assert!(source.contains("pi.on(\"session_start\""));
        assert!(source.contains("pi.setActiveTools"));
        assert!(source.contains("active.add(\"submit_review\")"));
        assert!(source.contains("pi.on(\"before_agent_start\""));
        assert!(source.contains("event.prompt !== terminalPrompt"));
        assert!(source.contains("pi.setActiveTools([\"submit_review\"])"));
        assert!(source.contains("pi.on(\"before_provider_request\""));
        assert!(source.contains("tool_choice"));
        assert!(source.contains("function: { name: \"submit_review\" }"));
        assert!(source.contains("pi.on(\"agent_settled\""));
        assert!(source.contains("terminalPreviousTools"));
        assert!(source.contains("LAZYTEAM_REVIEW_TERMINAL_ONLY"));
        assert!(source.contains("http://127.0.0.1:12345/mcp/cap"));
    }

    /// Real Pi RPC shapes, per the Pi bundle: parallel tool calls emit
    /// `{type, toolCallId, toolName, args}` with bash args as
    /// `{command, timeout?}`, updates adding `partialResult`, and ends
    /// carrying `{result, isError}`.
    fn pi_bash_start(id: &str, command: &str) -> Value {
        json!({
            "type": "tool_execution_start",
            "toolCallId": id,
            "toolName": "bash",
            "args": {"command": command},
        })
    }

    fn pi_bash_start_with_timeout(id: &str, command: &str, timeout: u64) -> Value {
        json!({
            "type": "tool_execution_start",
            "toolCallId": id,
            "toolName": "bash",
            "args": {"command": command, "timeout": timeout},
        })
    }

    fn pi_bash_update(id: &str, command: &str) -> Value {
        json!({
            "type": "tool_execution_update",
            "toolCallId": id,
            "toolName": "bash",
            "args": {"command": command},
            "partialResult": {"content": []},
        })
    }

    fn pi_tool_end(id: &str, tool: &str) -> Value {
        json!({
            "type": "tool_execution_end",
            "toolCallId": id,
            "toolName": tool,
            "result": {"content": []},
            "isError": false,
        })
    }

    #[test]
    fn harness_activity_tracks_tool_compaction_and_retry_phases() {
        let mut phase = RunPhase::Starting;
        let mut tools = ActiveTools::new();
        let now = Instant::now();

        assert!(observe_pi_activity(&json!({"type":"message_update"}), &mut phase, &mut tools, now));
        assert_eq!(phase, RunPhase::ModelStreaming);

        assert!(observe_pi_activity(
            &pi_bash_start("call-harness-1", "cargo test"),
            &mut phase,
            &mut tools,
            now,
        ));
        assert_eq!(phase, RunPhase::ToolRunning);
        assert_eq!(tools.single().map(|s| s.name.as_str()), Some("bash"));

        assert!(observe_pi_activity(
            &pi_bash_update("call-harness-1", "cargo test"),
            &mut phase,
            &mut tools,
            now,
        ));
        assert_eq!(phase, RunPhase::ToolRunning);
        assert_eq!(tools.single().map(|s| s.update_count), Some(1));

        assert!(observe_pi_activity(&pi_tool_end("call-harness-1", "bash"), &mut phase, &mut tools, now));
        assert_eq!(phase, RunPhase::ModelWaiting);
        assert!(tools.is_empty());

        assert!(observe_pi_activity(&json!({"type":"compaction_start"}), &mut phase, &mut tools, now));
        assert_eq!(phase, RunPhase::Compacting);
        assert!(observe_pi_activity(&json!({"type":"compaction_end"}), &mut phase, &mut tools, now));
        assert_eq!(phase, RunPhase::ModelWaiting);

        assert!(observe_pi_activity(&json!({"type":"auto_retry_start"}), &mut phase, &mut tools, now));
        assert_eq!(phase, RunPhase::ProviderRetry);
        assert!(observe_pi_activity(&json!({"type":"auto_retry_end"}), &mut phase, &mut tools, now));
        assert_eq!(phase, RunPhase::ModelWaiting);
    }

    #[test]
    fn silent_bash_tool_preserves_timing_and_call_identity() {
        let mut phase = RunPhase::Starting;
        let mut tools = ActiveTools::new();
        let start = Instant::now();
        assert!(observe_pi_activity(
            &json!({"type":"tool_execution_start","toolName":"bash","toolCallId":"call-silent-1"}),
            &mut phase,
            &mut tools,
            start,
        ));
        let state = tools.single().expect("active bash tool");
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
    fn bash_requested_timeout_bounds_the_outer_watchdog() {
        let mut phase = RunPhase::Starting;
        let mut tools = ActiveTools::new();
        let start = Instant::now();
        assert!(observe_pi_activity(
            &pi_bash_start_with_timeout("call-timeout-1", "cargo test | tail -n 30", 300),
            &mut phase,
            &mut tools,
            start,
        ));
        let state = tools.single().expect("active bash tool");
        assert_eq!(state.requested_timeout_secs, Some(300));
        assert_eq!(
            active_tool_hard_limit(state, Duration::from_secs(DEFAULT_WATCHDOG_TOOL_HARD_LIMIT_SECS)),
            Duration::from_secs(300 + TOOL_TIMEOUT_GRACE_SECS),
        );
        // Buffered pipelines are not treated as dead merely because Pi sees
        // no stdout updates before the command's own timeout.
        assert!(tools
            .stalest_stalled(start + Duration::from_secs(300), Duration::from_secs(60))
            .is_none());
        assert!(tools
            .first_hard_limit_exceeded(start + Duration::from_secs(314), Duration::from_secs(1500))
            .is_none());
        assert!(tools
            .first_hard_limit_exceeded(start + Duration::from_secs(315), Duration::from_secs(1500))
            .is_some());
    }

    #[test]
    fn bounded_requested_timeout_is_capped_by_global_hard_limit() {
        let now = Instant::now();
        let state = ActiveToolState {
            name: "bash".to_string(),
            call_id: Some("call-timeout-cap-1".to_string()),
            started_at: now,
            last_progress_at: now,
            update_count: 0,
            args_available: true,
            command_class: "cargo-test".to_string(),
            program: Some("cargo".to_string()),
            command_summary: "cargo test".to_string(),
            fingerprint: "0123456789abcdef".to_string(),
            requested_timeout_secs: Some(DEFAULT_WATCHDOG_TOOL_HARD_LIMIT_SECS),
        };
        // Requested timeout plus grace must never exceed the global hard limit.
        assert_eq!(
            active_tool_hard_limit(&state, Duration::from_secs(DEFAULT_WATCHDOG_TOOL_HARD_LIMIT_SECS)),
            Duration::from_secs(DEFAULT_WATCHDOG_TOOL_HARD_LIMIT_SECS),
        );
    }

    #[test]
    fn updating_bash_tool_counts_progress_for_stall_clock() {
        let mut phase = RunPhase::Starting;
        let mut tools = ActiveTools::new();
        let start = Instant::now();
        assert!(observe_pi_activity(
            &pi_bash_start("call-live-1", "cargo test --locked"),
            &mut phase,
            &mut tools,
            start,
        ));
        assert_eq!(tools.single().map(|s| s.command_class.as_str()), Some("cargo-test"));
        assert_eq!(tools.single().and_then(|s| s.program.as_deref()), Some("cargo"));
        let later = start + Duration::from_secs(10 * 60);
        assert!(observe_pi_activity(
            &pi_bash_update("call-live-1", "cargo test --locked"),
            &mut phase,
            &mut tools,
            later,
        ));
        let state = tools.single().expect("active bash tool");
        assert_eq!(state.update_count, 1);
        assert_eq!(state.last_progress_at, later);
        // `partialResult` payloads are progress signals, never diagnostics:
        // the stored summary stays redacted and the fingerprint stable.
        assert_eq!(state.command_summary, "cargo test");
        // Periodic progress keeps the stall clock fresh.
        assert!(!tool_stalled(state.last_progress_at, start + Duration::from_secs(35 * 60), Duration::from_secs(30 * 60)));
        // Silence past the window still stalls.
        assert!(tool_stalled(state.last_progress_at, later + Duration::from_secs(31 * 60), Duration::from_secs(30 * 60)));
    }

    #[test]
    fn parallel_tool_calls_track_by_call_id_not_name() {
        let mut phase = RunPhase::Starting;
        let mut tools = ActiveTools::new();
        let start = Instant::now();
        assert!(observe_pi_activity(&pi_bash_start("call-a", "cargo test"), &mut phase, &mut tools, start));
        let mid = start + Duration::from_secs(60);
        assert!(observe_pi_activity(&pi_bash_start("call-b", "git fetch origin"), &mut phase, &mut tools, mid));
        // A later parallel start must not overwrite the earlier call.
        assert_eq!(tools.len(), 2);
        assert_eq!(tools.get("call-a").map(|s| s.command_class.as_str()), Some("cargo-test"));
        assert_eq!(tools.get("call-b").map(|s| s.command_class.as_str()), Some("git"));
        // An update for call-b is routed by id and leaves call-a's clock alone.
        let later = start + Duration::from_secs(120);
        assert!(observe_pi_activity(&pi_bash_update("call-b", "git fetch origin"), &mut phase, &mut tools, later));
        assert_eq!(tools.get("call-a").map(|s| s.last_progress_at), Some(start));
        assert_eq!(tools.get("call-a").map(|s| s.update_count), Some(0));
        assert_eq!(tools.get("call-b").map(|s| s.last_progress_at), Some(later));
        assert_eq!(tools.get("call-b").map(|s| s.update_count), Some(1));
        // Completing call-a removes only call-a; the phase stays ToolRunning.
        assert!(observe_pi_activity(&pi_tool_end("call-a", "bash"), &mut phase, &mut tools, later));
        assert_eq!(phase, RunPhase::ToolRunning);
        assert!(tools.get("call-a").is_none());
        assert!(tools.get("call-b").is_some());
        // The stall decision observes the remaining call, not the cleared one.
        let window = Duration::from_secs(30 * 60);
        let stall_at = later + Duration::from_secs(31 * 60);
        let stalled = tools.stalest_stalled(stall_at, window).expect("call-b stalls");
        assert_eq!(stalled.call_id.as_deref(), Some("call-b"));
        assert_eq!(stalled.command_class, "git");
        // Draining the last call returns to ModelWaiting with an empty table.
        assert!(observe_pi_activity(&pi_tool_end("call-b", "bash"), &mut phase, &mut tools, stall_at));
        assert_eq!(phase, RunPhase::ModelWaiting);
        assert!(tools.is_empty());
    }

    #[test]
    fn id_less_events_route_to_stalest_same_name_call() {
        let mut phase = RunPhase::Starting;
        let mut tools = ActiveTools::new();
        let first = Instant::now();
        assert!(observe_pi_activity(
            &json!({"type":"tool_execution_start","toolName":"bash","args":{"command":"cargo test"}}),
            &mut phase,
            &mut tools,
            first,
        ));
        let second = first + Duration::from_secs(60);
        assert!(observe_pi_activity(
            &json!({"type":"tool_execution_start","toolName":"bash","args":{"command":"git fetch"}}),
            &mut phase,
            &mut tools,
            second,
        ));
        assert_eq!(tools.len(), 2);
        // An id-less update refreshes only the stalest same-name entry.
        let later = first + Duration::from_secs(120);
        assert!(observe_pi_activity(
            &json!({"type":"tool_execution_update","toolName":"bash"}),
            &mut phase,
            &mut tools,
            later,
        ));
        let progressed: Vec<_> = tools.calls.values().filter(|s| s.last_progress_at == later).collect();
        assert_eq!(progressed.len(), 1);
        assert_eq!(progressed[0].command_class, "cargo-test");
        // An id-less end drops only one same-name entry, not its sibling.
        // (The update above refreshed the cargo entry, so the untouched git
        // entry is now the stalest and goes first.)
        assert!(observe_pi_activity(
            &json!({"type":"tool_execution_end","toolName":"bash"}),
            &mut phase,
            &mut tools,
            later,
        ));
        assert_eq!(phase, RunPhase::ToolRunning);
        let remaining = tools.single().expect("one sibling remains");
        assert_eq!(remaining.command_class, "cargo-test");
        assert_eq!(remaining.update_count, 1);
        assert_eq!(remaining.last_progress_at, later);
    }

    #[test]
    fn non_bash_tool_uses_non_bash_class() {
        let mut phase = RunPhase::Starting;
        let mut tools = ActiveTools::new();
        let now = Instant::now();
        assert!(observe_pi_activity(
            &json!({"type":"tool_execution_start","toolName":"read","toolCallId":"call-read-1","args":{"path":"src/main.rs"}}),
            &mut phase,
            &mut tools,
            now,
        ));
        let state = tools.single().expect("active tool");
        assert_eq!(state.name, "read");
        assert_eq!(state.command_class, "non-bash");
        assert!(state.args_available);
        let diagnostic = format_tool_diagnostic(state, now);
        assert!(diagnostic.contains("class=non-bash"));
        assert!(!diagnostic.contains("src/main.rs"));
    }

    #[test]
    fn secret_bearing_bash_args_never_appear_in_durable_diagnostic() {
        let token = "ghp_super_secret_token_abc123";
        let password = "s3cr3t-p4ssw0rd-value";
        let path_secret = "ghp_path_secret_xyz789";
        // Exact Pi RPC shape (`args.command`) including the wrapper and
        // secret-path forms that previously leaked through the subcommand.
        let cases = [
            (format!("cargo test --token {token} --password {password}"), "cargo-test", "cargo test"),
            (format!("git -C /tmp/{path_secret} fetch"), "git", "git fetch"),
            (format!("bash -lc \"cargo test --token {token}\""), "cargo-test", "cargo test"),
            (format!("sudo curl https://example.com/?token={token}"), "network-fetch", "curl"),
            (format!("env API_KEY={password} cargo test"), "cargo-test", "cargo test"),
        ];
        let mut phase = RunPhase::Starting;
        let mut tools = ActiveTools::new();
        let now = Instant::now();
        for (i, (command, _, _)) in cases.iter().enumerate() {
            let id = format!("call-secret-{i}");
            assert!(observe_pi_activity(&pi_bash_start(&id, command), &mut phase, &mut tools, now));
        }
        assert_eq!(phase, RunPhase::ToolRunning);
        // The durable multi-call brief carries every entry: no secret may
        // appear anywhere in it, in any form (raw, path, or query string).
        let brief = tools.brief(now);
        assert!(brief.contains("tools=5"));
        for secret in [token, password, path_secret] {
            assert!(!brief.contains(secret), "durable brief leaks a secret");
        }
        for (i, (command, class, summary)) in cases.iter().enumerate() {
            let id = format!("call-secret-{i}");
            let state = tools.get(&id).expect("tracked call");
            assert_eq!(&state.command_class, class, "class for {command:?}");
            assert_eq!(&state.command_summary, summary, "summary for {command:?}");
            assert!(state.args_available);
            let diagnostic = format_tool_diagnostic(state, now);
            for secret in [token, password, path_secret] {
                assert!(!diagnostic.contains(secret), "diagnostic leaks a secret for {command:?}");
            }
        }
        // Stable fingerprint lets operators correlate without raw content.
        let first = tools.get("call-secret-0").expect("tracked call");
        assert_eq!(first.fingerprint.len(), 16);
        // Same command always yields the same fingerprint.
        let (_, _, _, _, again) = derive_tool_command(
            "bash",
            &json!({"args": {"command": format!("cargo test --token {token} --password {password}") }}),
        );
        assert_eq!(again, first.fingerprint);
    }

    #[test]
    fn unknown_program_names_stay_out_of_durable_output() {
        // A secret-bearing argv[0] (script path or bare token-like binary)
        // must never be echoed: closed program vocabulary degrades to
        // generic-shell while the fingerprint still correlates.
        for command in [
            "/tmp/ghp_runner_secret_abc123.sh --token xyz",
            "ghp_binary_secret_abc123 run --yes",
            "bash /tmp/deploy_secret_abc123.sh",
        ] {
            let (class, program, summary) = classify_bash_command(command);
            assert_eq!(class, "generic-shell", "class for {command:?}");
            assert!(program.is_none(), "program for {command:?}");
            assert_eq!(summary, "generic-shell", "summary for {command:?}");
            assert!(!summary.contains("secret"), "summary for {command:?}");
        }
    }

    #[test]
    fn bash_command_classes_cover_expected_families() {
        let (class, program, summary) = classify_bash_command("cargo check --locked");
        assert_eq!(class, "cargo-check");
        assert_eq!(program.as_deref(), Some("cargo"));
        assert_eq!(summary, "cargo check");
        let (class, _, summary) = classify_bash_command("git fetch origin main");
        assert_eq!(class, "git");
        assert_eq!(summary, "git fetch");
        let (class, _, _) = classify_bash_command("curl https://example.com/pkg.tar.gz");
        assert_eq!(class, "network-fetch");
        let (class, program, summary) = classify_bash_command("sleep 900");
        assert_eq!(class, "sleep-wait");
        assert_eq!(program.as_deref(), Some("sleep"));
        assert_eq!(summary, "sleep");
        // Redacted summaries never carry URLs, flags, or payloads.
        let (_, _, summary) = classify_bash_command("curl https://example.com/secret?token=abc --retry 5");
        assert_eq!(summary, "curl");
        assert!(!summary.contains("example.com"));
    }

    #[test]
    fn bash_wrapper_forms_identify_the_underlying_program() {
        let cases = [
            ("bash -lc \"cargo test --locked\"", "cargo-test", Some("cargo"), "cargo test"),
            ("bash -c 'git fetch origin'", "git", Some("git"), "git fetch"),
            ("bash -lc 'sleep 900'", "sleep-wait", Some("sleep"), "sleep"),
            ("sudo cargo test", "cargo-test", Some("cargo"), "cargo test"),
            ("sudo -u worker cargo test", "cargo-test", Some("cargo"), "cargo test"),
            ("env FOO=x cargo test", "cargo-test", Some("cargo"), "cargo test"),
            ("FOO=x cargo test --locked", "cargo-test", Some("cargo"), "cargo test"),
            ("/usr/bin/cargo test", "cargo-test", Some("cargo"), "cargo test"),
            ("/usr/bin/sudo cargo check", "cargo-check", Some("cargo"), "cargo check"),
            ("/usr/bin/env FOO=x cargo test", "cargo-test", Some("cargo"), "cargo test"),
            ("timeout 300 cargo build", "cargo-build", Some("cargo"), "cargo build"),
            ("kubectl get pods", "deploy", Some("kubectl"), "kubectl get"),
            ("gcc -O2 -o app main.c", "compiler", Some("gcc"), "gcc"),
        ];
        for (command, class, program, summary) in cases {
            let (got_class, got_program, got_summary) = classify_bash_command(command);
            assert_eq!(got_class, class, "class for {command:?}");
            assert_eq!(got_program.as_deref(), program, "program for {command:?}");
            assert_eq!(got_summary, summary, "summary for {command:?}");
        }
    }

    #[test]
    fn state_probe_responses_are_not_tool_progress() {
        let mut phase = RunPhase::Starting;
        let mut tools = ActiveTools::new();
        let start = Instant::now();
        assert!(observe_pi_activity(
            &pi_bash_start("call-probe-1", "cargo test"),
            &mut phase,
            &mut tools,
            start,
        ));
        let progress_before = tools.single().expect("active tool").last_progress_at;
        let updates_before = tools.single().expect("active tool").update_count;
        let probe = json!({
            "type":"response",
            "command":"get_state",
            "success":true,
            "data":{"isStreaming":false,"isCompacting":false,"pendingMessageCount":0}
        });
        assert!(!observe_pi_activity(&probe, &mut phase, &mut tools, start + Duration::from_secs(60)));
        let state = tools.single().expect("active tool still tracked");
        assert_eq!(state.last_progress_at, progress_before);
        assert_eq!(state.update_count, updates_before);
        // The probe still reports the tool as active for liveness purposes.
        assert_eq!(pi_state_probe_active(&probe, phase, tools.any()), Some(true));
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
    fn streaming_state_probe_does_not_mask_model_stall() {
        let start = Instant::now();
        let window = Duration::from_secs(DEFAULT_WATCHDOG_MODEL_STALL_SECS);
        let probe = json!({
            "type":"response",
            "command":"get_state",
            "success":true,
            "data":{"isStreaming":true,"isCompacting":false,"pendingMessageCount":0}
        });
        assert_eq!(pi_state_probe_active(&probe, RunPhase::ModelStreaming, false), Some(true));
        assert!(non_tool_phase_stalled(
            start,
            start + window,
            window,
            false,
        ), "liveness responses must not keep a provider stream alive forever");
        assert!(!non_tool_phase_stalled(
            start,
            start + window,
            window,
            true,
        ), "active tools use their own stall/hard-limit clocks");
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
            pi_state_probe_active(&streaming, RunPhase::ModelWaiting, false),
            Some(true),
        );

        let idle = json!({
            "type":"response",
            "command":"get_state",
            "success":true,
            "data":{"isStreaming":false,"isCompacting":false,"pendingMessageCount":0}
        });
        assert_eq!(
            pi_state_probe_active(&idle, RunPhase::ModelWaiting, false),
            Some(false),
        );
        assert_eq!(
            pi_state_probe_active(&idle, RunPhase::ToolRunning, true),
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

    /// Model-refresh round-trip regression (worker side).
    ///
    /// Runs the exact production refresh script (`model_refresh_script`) with
    /// plain `node` against local fake Pi fixtures: no network, no paid model
    /// call. The refresh must use the read-only credential store, leave
    /// `auth.json` byte-identical, and target the file-backed models store
    /// whose permissions the worker repairs after every refresh.
    #[tokio::test]
    async fn model_refresh_uses_read_only_auth_and_preserves_credentials() {
        let root = std::env::temp_dir().join(format!("lazyteam-refresh-regression-{}", Uuid::new_v4()));
        let dist = root.join("pkg").join("dist");
        let core = dist.join("core");
        let pi_dir = root.join("pi-agent");
        std::fs::create_dir_all(&core).unwrap();
        std::fs::create_dir_all(&pi_dir).unwrap();

        // Fake auth-storage module: the read-only store the refresh must use,
        // plus the writable store production must never touch (tripwire).
        std::fs::write(
            core.join("auth-storage.js"),
            r#"import fs from "node:fs";
export class ReadOnlyAuthStorage {
  constructor(path) { this.path = path; }
  async modify() { throw new Error("ReadOnlyAuthStorage must not write during refresh"); }
}
export class AuthStorage {
  constructor() {
    fs.writeFileSync(process.env.LAZYTEAM_REFRESH_TRIPWIRE, "writable-store-used");
    throw new Error("writable AuthStorage must not be used during refresh");
  }
}
"#,
        ).unwrap();
        // Fake ModelRuntime: validates the read-only wiring, asserts the
        // refresh arguments, and simulates Pi rewriting models-store.json
        // with fresh (wrong) permissions like a real catalog refresh does.
        std::fs::write(
            dist.join("index.js"),
            r#"import fs from "node:fs";
import path from "node:path";
export class ModelRuntime {
  static async create(opts) {
    if (opts.credentials?.constructor?.name !== "ReadOnlyAuthStorage") {
      throw new Error("refresh must use ReadOnlyAuthStorage, got " + opts.credentials?.constructor?.name);
    }
    if (opts.allowModelNetwork !== false) throw new Error("refresh must set allowModelNetwork:false");
    if (opts.refreshOnCreate !== false) throw new Error("refresh must set refreshOnCreate:false");
    if (typeof opts.modelsStorePath !== "string" || !opts.modelsStorePath.endsWith("models-store.json")) {
      throw new Error("refresh must use the file-backed modelsStorePath");
    }
    const dir = process.env.PI_CODING_AGENT_DIR;
    return {
      async refresh(args) {
        if (args.allowNetwork !== true) throw new Error("refresh must set allowNetwork:true");
        if (args.force !== true) throw new Error("refresh must set force:true");
        const want = [process.env.LAZYTEAM_REFRESH_PROVIDER];
        if (JSON.stringify(args.providers) !== JSON.stringify(want)) {
          throw new Error("refresh scoped to wrong providers: " + JSON.stringify(args.providers));
        }
        const storePath = path.join(dir, "models-store.json");
        fs.writeFileSync(storePath, JSON.stringify({ refreshed: true }));
        fs.chmodSync(storePath, 0o644);
        return { aborted: false, errors: new Map() };
      }
    };
  }
}
"#,
        ).unwrap();

        let auth_before = br#"{"test-provider":{"type":"api_key","key":"secret-123"}}"#;
        std::fs::write(pi_dir.join("auth.json"), auth_before).unwrap();
        std::fs::write(pi_dir.join("models.json"), b"{}").unwrap();
        let tripwire = root.join("writable-store-used");

        let import_url = serde_json::to_string(&format!("file://{}", dist.join("index.js").display())).unwrap();
        let auth_storage_url = serde_json::to_string(&format!("file://{}", core.join("auth-storage.js").display())).unwrap();
        let provider_json = serde_json::to_string("test-provider").unwrap();
        let script = model_refresh_script(&import_url, &auth_storage_url, &provider_json);

        // Static shape: the regression fails loudly if refresh is rewired to
        // a writable credential store or stops targeting the repaired file.
        assert!(script.contains("ReadOnlyAuthStorage"), "refresh must use the read-only auth store");
        assert!(!script.contains("new AuthStorage("), "refresh must not construct the writable auth store");
        assert!(!script.contains("auth.modify"), "refresh must not write credentials");
        assert!(script.contains("modelsStorePath"), "refresh must target the repaired models-store file");
        assert!(script.contains("refreshOnCreate:false"), "refresh must not trigger create-time refresh");
        assert!(script.contains("allowModelNetwork:false"), "refresh must not enable background model network");

        let output = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            tokio::process::Command::new("node")
                .arg("--input-type=module")
                .arg("--eval")
                .arg(&script)
                .env("PI_CODING_AGENT_DIR", &pi_dir)
                .env("LAZYTEAM_REFRESH_PROVIDER", "test-provider")
                .env("LAZYTEAM_REFRESH_TRIPWIRE", &tripwire)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output(),
        ).await.expect("model refresh fixture run timed out").expect("spawn node for refresh fixture");
        assert!(output.status.success(), "refresh fixture failed: {}", String::from_utf8_lossy(&output.stderr));
        assert!(String::from_utf8_lossy(&output.stdout).contains("ok"));
        assert!(!tripwire.exists(), "refresh touched the writable credential store");
        let auth_after = std::fs::read(pi_dir.join("auth.json")).unwrap();
        assert_eq!(auth_after, auth_before, "model refresh must not mutate auth credential bytes");
        let store = std::fs::read(pi_dir.join("models-store.json")).unwrap();
        assert!(String::from_utf8_lossy(&store).contains("refreshed"));
        std::fs::remove_dir_all(&root).ok();
    }
}
