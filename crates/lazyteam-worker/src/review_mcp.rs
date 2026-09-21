use std::{
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU8, AtomicU16, Ordering},
    },
};

use anyhow::Context;
use axum::Router;
use lazyteam_core::{ReviewVerdict, ReviewVerdictKind};
use rmcp::{
    ErrorData as McpError, ServerHandler,
    model::{
        CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation, ListToolsResult,
        PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
    },
    transport::streamable_http_server::{
        StreamableHttpServerConfig, StreamableHttpService,
        session::local::LocalSessionManager,
    },
};
use serde_json::{Map, Value, json};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_INVALID_SUBMITS: u8 = 5;
const MAX_REASON_CHARS: usize = 8_000;
const MAX_VALIDATION_ITEMS: usize = 32;
const MAX_VALIDATION_CHARS: usize = 2_000;

struct SlotState {
    review_id: Uuid,
    execution_id: Uuid,
    submit_calls: AtomicU16,
    invalid_submits: AtomicU8,
    last_invalid: Mutex<Option<String>>,
    verdict: Mutex<Option<ReviewVerdict>>,
    failure: Mutex<Option<String>>,
    terminal: AtomicBool,
    changed: Notify,
}

impl SlotState {
    fn new(review_id: Uuid, execution_id: Uuid) -> Self {
        Self {
            review_id,
            execution_id,
            submit_calls: AtomicU16::new(0),
            invalid_submits: AtomicU8::new(0),
            last_invalid: Mutex::new(None),
            verdict: Mutex::new(None),
            failure: Mutex::new(None),
            terminal: AtomicBool::new(false),
            changed: Notify::new(),
        }
    }

    fn invalid(&self, reason: &str) -> CallToolResult {
        *self.last_invalid.lock().expect("review slot last-invalid lock poisoned") = Some(reason.chars().take(160).collect());
        if self.terminal.load(Ordering::Acquire) {
            return CallToolResult::error(vec![ContentBlock::text(
                "This review slot is already closed; submit_review cannot be called again.",
            )]);
        }
        let attempt = self.invalid_submits.fetch_add(1, Ordering::AcqRel).saturating_add(1);
        if attempt >= MAX_INVALID_SUBMITS {
            let message = format!(
                "submit_review arguments were invalid on attempt {attempt}/{MAX_INVALID_SUBMITS}: {reason}. The review lease is now aborted."
            );
            *self.failure.lock().expect("review slot failure lock poisoned") = Some(message.clone());
            self.terminal.store(true, Ordering::Release);
            self.changed.notify_waiters();
            return CallToolResult::error(vec![ContentBlock::text(message)]);
        }
        CallToolResult::error(vec![ContentBlock::text(format!(
            "submit_review arguments invalid ({attempt}/{MAX_INVALID_SUBMITS}): {reason}. Correct the arguments and call submit_review again; do not redo the code review."
        ))])
    }

    fn submit(&self, arguments: Option<Map<String, Value>>) -> CallToolResult {
        if self.terminal.load(Ordering::Acquire) {
            return CallToolResult::error(vec![ContentBlock::text(
                "This review slot already has a terminal outcome; duplicate submit_review calls are rejected.",
            )]);
        }
        let Some(arguments) = arguments else {
            return self.invalid("arguments object is required");
        };
        let verdict = match arguments.get("verdict").and_then(Value::as_str) {
            Some("approve") => ReviewVerdictKind::Approve,
            Some("retry") => ReviewVerdictKind::Retry,
            Some(_) => return self.invalid("verdict must be `approve` or `retry`"),
            None => return self.invalid("verdict string is required"),
        };
        let reason = match arguments.get("reason").and_then(Value::as_str) {
            Some(reason) if !reason.trim().is_empty() && reason.chars().count() <= MAX_REASON_CHARS => reason.trim().to_string(),
            Some(reason) if reason.trim().is_empty() => return self.invalid("reason must be non-empty"),
            Some(_) => return self.invalid("reason is too long"),
            None => return self.invalid("reason string is required"),
        };
        let validation = match arguments.get("validation") {
            Some(Value::Array(items)) if items.len() <= MAX_VALIDATION_ITEMS => {
                let mut output = Vec::with_capacity(items.len());
                for item in items {
                    let Some(text) = item.as_str() else {
                        return self.invalid("validation must contain only strings");
                    };
                    if text.chars().count() > MAX_VALIDATION_CHARS {
                        return self.invalid("validation entry is too long");
                    }
                    output.push(text.to_string());
                }
                output
            }
            Some(Value::Array(_)) => return self.invalid("validation contains too many entries"),
            Some(Value::String(text)) if text.chars().count() <= MAX_VALIDATION_CHARS => vec![text.to_string()],
            Some(Value::String(_)) => return self.invalid("validation entry is too long"),
            Some(_) => return self.invalid("validation must be a string or an array of strings"),
            None => Vec::new(),
        };

        let verdict = ReviewVerdict { verdict, reason, validation };
        let mut stored = self.verdict.lock().expect("review slot verdict lock poisoned");
        if self.terminal.load(Ordering::Acquire) || stored.is_some() {
            return CallToolResult::error(vec![ContentBlock::text(
                "This review slot already has a terminal outcome; duplicate submit_review calls are rejected.",
            )]);
        }
        *stored = Some(verdict.clone());
        self.terminal.store(true, Ordering::Release);
        drop(stored);
        self.changed.notify_waiters();
        CallToolResult::structured(json!({
            "accepted": true,
            "message": "Review verdict accepted. The reviewer run will now stop.",
        }))
    }

    fn cancel(&self, reason: impl Into<String>) {
        if self.terminal.swap(true, Ordering::AcqRel) {
            return;
        }
        *self.failure.lock().expect("review slot failure lock poisoned") = Some(reason.into());
        self.changed.notify_waiters();
    }

    async fn wait(&self) -> anyhow::Result<ReviewVerdict> {
        loop {
            if let Some(verdict) = self.verdict.lock().expect("review slot verdict lock poisoned").clone() {
                return Ok(verdict);
            }
            if let Some(failure) = self.failure.lock().expect("review slot failure lock poisoned").clone() {
                anyhow::bail!(failure);
            }
            self.changed.notified().await;
        }
    }
}

#[derive(Clone)]
struct ReviewerMcp {
    slot: Weak<SlotState>,
}

impl ReviewerMcp {
    fn tool() -> Tool {
        // Keep transport-level schema permissive so every harness forwards an
        // attempted submission to this Rust-owned slot. Semantic validation
        // below is authoritative and therefore the same 5-attempt budget is
        // enforced for Pi, OpenCode, and future MCP clients alike.
        let schema = json!({
            "type": "object",
            "additionalProperties": true,
            "properties": {
                "verdict": {"description": "Required: approve or retry"},
                "reason": {"description": "Required non-empty review reason"},
                "validation": {"description": "Required array of validation evidence strings"}
            }
        });
        Tool::new(
            "submit_review",
            "Submit the final review verdict. Invalid arguments may be corrected in-place up to five times in this same review lease.",
            Arc::new(schema.as_object().expect("submit_review schema is object").clone()),
        )
    }
}

impl ServerHandler for ReviewerMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_instructions("This MCP server belongs to exactly one active LazyTeam reviewer slot. Use submit_review once the review is complete.".to_string())
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(vec![Self::tool()]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        if request.name.as_ref() != "submit_review" {
            return Err(McpError::invalid_params("unknown reviewer tool", None));
        }
        let Some(slot) = self.slot.upgrade() else {
            return Ok(CallToolResult::error(vec![ContentBlock::text(
                "The owning review slot has ended; this MCP capability is expired.",
            )]).into());
        };
        slot.submit_calls.fetch_add(1, Ordering::AcqRel);
        Ok(slot.submit(request.arguments).into())
    }
}

/// The sole owner of one review verdict capability. Its invalid-submit count,
/// MCP endpoint, cancellation state, and verdict all die with this value.
/// A new review lease necessarily constructs a new ReviewSlot and starts at 0/5.
pub struct ReviewSlot {
    state: Arc<SlotState>,
    endpoint: String,
    server_cancel: CancellationToken,
    server_abort: tokio::task::AbortHandle,
}

impl ReviewSlot {
    pub async fn start(review_id: Uuid, execution_id: Uuid) -> anyhow::Result<Arc<Self>> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .context("bind reviewer MCP loopback listener")?;
        let address = listener.local_addr().context("read reviewer MCP listener address")?;
        let capability = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let path = format!("/mcp/{capability}");
        let endpoint = format!("http://{address}{path}");
        let state = Arc::new(SlotState::new(review_id, execution_id));
        let weak = Arc::downgrade(&state);
        let server_cancel = CancellationToken::new();
        let config = StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true)
            .with_cancellation_token(server_cancel.clone())
            .with_allowed_hosts([
                format!("127.0.0.1:{}", address.port()),
                format!("localhost:{}", address.port()),
            ]);
        let service = StreamableHttpService::new(
            move || Ok(ReviewerMcp { slot: weak.clone() }),
            LocalSessionManager::default().into(),
            config,
        );
        let app = Router::new().route_service(&path, service);
        let task = tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, app).await {
                tracing::warn!(%error, "reviewer MCP loopback server exited");
            }
        });
        let server_abort = task.abort_handle();
        Ok(Arc::new(Self { state, endpoint, server_cancel, server_abort }))
    }

    pub fn endpoint(&self) -> &str { &self.endpoint }
    pub fn diagnostics(&self) -> String {
        let calls = self.state.submit_calls.load(Ordering::Acquire);
        let invalid = self.state.invalid_submits.load(Ordering::Acquire);
        let accepted = self.state.verdict.lock().expect("review slot verdict lock poisoned").is_some();
        let last_invalid = self.state.last_invalid.lock().expect("review slot last-invalid lock poisoned").clone();
        format!(
            "submit_calls={calls} invalid_calls={invalid} accepted={accepted} last_invalid={}",
            last_invalid.as_deref().unwrap_or("none")
        )
    }
    #[cfg(test)]
    pub fn invalid_submits(&self) -> u8 { self.state.invalid_submits.load(Ordering::Acquire) }
    #[cfg(test)]
    pub fn submit_calls(&self) -> u16 { self.state.submit_calls.load(Ordering::Acquire) }
    pub async fn wait(&self) -> anyhow::Result<ReviewVerdict> { self.state.wait().await }
    pub fn cancel(&self, reason: impl Into<String>) { self.state.cancel(reason); }
}

impl Drop for ReviewSlot {
    fn drop(&mut self) {
        tracing::debug!(review_id = %self.state.review_id, execution_id = %self.state.execution_id, "dropping reviewer MCP slot");
        self.state.cancel("review slot ended before a valid submit_review verdict");
        self.server_cancel.cancel();
        self.server_abort.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(verdict: Value, reason: Value, validation: Value) -> Map<String, Value> {
        Map::from_iter([
            ("verdict".to_string(), verdict),
            ("reason".to_string(), reason),
            ("validation".to_string(), validation),
        ])
    }

    async fn mcp_call(endpoint: &str, arguments: Value) -> Value {
        let body = json!({
            "jsonrpc": "2.0",
            "id": Uuid::new_v4().to_string(),
            "method": "tools/call",
            "params": {
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {}
                },
                "name": "submit_review",
                "arguments": arguments
            }
        });
        let response = reqwest::Client::new()
            .post(endpoint)
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", "submit_review")
            .header(reqwest::header::ACCEPT, "application/json, text/event-stream")
            .json(&body)
            .send().await.unwrap();
        assert!(response.status().is_success(), "unexpected MCP HTTP status {}", response.status());
        response.json().await.unwrap()
    }

    #[tokio::test]
    async fn invalid_counter_is_per_slot_and_new_lease_resets_to_zero() {
        let a = ReviewSlot::start(Uuid::new_v4(), Uuid::new_v4()).await.unwrap();
        for _ in 0..4 {
            let result = a.state.submit(Some(args(json!("wat"), json!("x"), json!([]))));
            assert_eq!(result.is_error, Some(true));
        }
        assert_eq!(a.invalid_submits(), 4);
        drop(a);

        let b = ReviewSlot::start(Uuid::new_v4(), Uuid::new_v4()).await.unwrap();
        assert_eq!(b.invalid_submits(), 0);
        let result = b.state.submit(Some(args(json!("wat"), json!("x"), json!([]))));
        assert_eq!(result.is_error, Some(true));
        assert_eq!(b.invalid_submits(), 1);
    }

    #[tokio::test]
    async fn four_invalid_then_valid_keeps_same_lease_alive() {
        let slot = ReviewSlot::start(Uuid::new_v4(), Uuid::new_v4()).await.unwrap();
        for _ in 0..4 {
            assert_eq!(slot.state.submit(Some(args(json!("nope"), json!("x"), json!([])))).is_error, Some(true));
        }
        let ok = slot.state.submit(Some(args(json!("approve"), json!("verified"), json!(["cargo test"]))));
        assert_ne!(ok.is_error, Some(true));
        let verdict = slot.wait().await.unwrap();
        assert_eq!(verdict.verdict, ReviewVerdictKind::Approve);
        assert_eq!(slot.invalid_submits(), 4);
    }

    #[tokio::test]
    async fn fifth_invalid_aborts_only_that_slot() {
        let bad = ReviewSlot::start(Uuid::new_v4(), Uuid::new_v4()).await.unwrap();
        let good = ReviewSlot::start(Uuid::new_v4(), Uuid::new_v4()).await.unwrap();
        for _ in 0..5 {
            bad.state.submit(Some(args(json!("bad"), json!("x"), json!([]))));
        }
        assert!(bad.wait().await.unwrap_err().to_string().contains("5/5"));
        good.state.submit(Some(args(json!("retry"), json!("needs fix"), json!([]))));
        assert_eq!(good.wait().await.unwrap().verdict, ReviewVerdictKind::Retry);
        assert_eq!(good.invalid_submits(), 0);
    }

    #[tokio::test]
    async fn first_valid_wins_and_duplicate_is_rejected() {
        let slot = ReviewSlot::start(Uuid::new_v4(), Uuid::new_v4()).await.unwrap();
        assert_ne!(slot.state.submit(Some(args(json!("approve"), json!("ok"), json!([])))).is_error, Some(true));
        assert_eq!(slot.state.submit(Some(args(json!("retry"), json!("late"), json!([])))).is_error, Some(true));
        assert_eq!(slot.wait().await.unwrap().verdict, ReviewVerdictKind::Approve);
    }

    #[tokio::test]
    async fn real_mcp_transport_counts_invalid_then_accepts_valid() {
        let slot = ReviewSlot::start(Uuid::new_v4(), Uuid::new_v4()).await.unwrap();
        let invalid = mcp_call(slot.endpoint(), json!({"verdict":"wat","reason":"x","validation":[]})).await;
        assert_eq!(invalid.pointer("/result/isError").and_then(Value::as_bool), Some(true));
        assert_eq!(slot.invalid_submits(), 1);
        let valid = mcp_call(slot.endpoint(), json!({"verdict":"approve","reason":"verified","validation":["focused test"]})).await;
        assert_ne!(valid.pointer("/result/isError").and_then(Value::as_bool), Some(true));
        let verdict = slot.wait().await.unwrap();
        assert_eq!(verdict.verdict, ReviewVerdictKind::Approve);
        assert_eq!(verdict.reason, "verified");
        assert_eq!(slot.submit_calls(), 2);
        assert!(slot.diagnostics().contains("submit_calls=2 invalid_calls=1 accepted=true"));
    }

    #[tokio::test]
    async fn common_dumb_validation_shapes_are_normalized() {
        let string_slot = ReviewSlot::start(Uuid::new_v4(), Uuid::new_v4()).await.unwrap();
        let string_response = mcp_call(string_slot.endpoint(), json!({
            "verdict":"approve",
            "reason":"verified",
            "validation":"cargo test -p lazyteam-worker",
            "extra_note":"ignored protocol noise"
        })).await;
        assert_ne!(string_response.pointer("/result/isError").and_then(Value::as_bool), Some(true));
        let string_verdict = string_slot.wait().await.unwrap();
        assert_eq!(string_verdict.validation, vec!["cargo test -p lazyteam-worker"]);
        assert_eq!(string_slot.invalid_submits(), 0);

        let missing_slot = ReviewSlot::start(Uuid::new_v4(), Uuid::new_v4()).await.unwrap();
        let missing_response = mcp_call(missing_slot.endpoint(), json!({
            "verdict":"retry",
            "reason":"one blocker remains"
        })).await;
        assert_ne!(missing_response.pointer("/result/isError").and_then(Value::as_bool), Some(true));
        let missing_verdict = missing_slot.wait().await.unwrap();
        assert!(missing_verdict.validation.is_empty());
        assert_eq!(missing_slot.invalid_submits(), 0);
    }

    #[tokio::test]
    async fn eight_concurrent_mcp_slots_never_cross_wire() {
        let mut slots = Vec::new();
        let mut sends = Vec::new();
        for index in 0..8 {
            let slot = ReviewSlot::start(Uuid::new_v4(), Uuid::new_v4()).await.unwrap();
            let endpoint = slot.endpoint().to_string();
            sends.push(tokio::spawn(async move {
                mcp_call(&endpoint, json!({
                    "verdict": if index % 2 == 0 { "approve" } else { "retry" },
                    "reason": format!("slot-{index}"),
                    "validation": []
                })).await
            }));
            slots.push(slot);
        }
        for send in sends.into_iter().rev() {
            let response = send.await.unwrap();
            assert_ne!(response.pointer("/result/isError").and_then(Value::as_bool), Some(true));
        }
        for (index, slot) in slots.iter().enumerate() {
            let verdict = slot.wait().await.unwrap();
            assert_eq!(verdict.reason, format!("slot-{index}"));
            let expected = if index % 2 == 0 { ReviewVerdictKind::Approve } else { ReviewVerdictKind::Retry };
            assert_eq!(verdict.verdict, expected);
            assert_eq!(slot.invalid_submits(), 0);
        }
    }
}

