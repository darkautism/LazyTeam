use std::sync::Arc;

use axum::{response::Html, routing::get, Router};

use crate::AppState;

pub(crate) fn router() -> Router<Arc<AppState>> {
    Router::new().route("/ui", get(index))
}

async fn index() -> Html<&'static str> {
    Html(INDEX)
}

const INDEX: &str = include_str!("ui.html");

#[cfg(test)]
mod tests {
    use super::INDEX;

    #[test]
    fn management_ui_has_compact_tabs_and_admin_workflows() {
        assert!(INDEX.contains(r#"data-page="home""#));
        assert!(INDEX.contains(r#"data-page="projects""#));
        assert!(INDEX.contains(r#"data-page="workers""#));
        assert!(INDEX.contains("localStorage.setItem(TOKEN_KEY,token)"));
        assert!(INDEX.contains("sessionStorage.removeItem(TOKEN_KEY)"));
        assert!(INDEX.contains("Connected"));
        assert!(!INDEX.contains("Admin token stored for this browser session"));
        assert!(INDEX.contains("/api/task-board"));
        assert!(INDEX.contains("/api/worker-join"));
        assert!(INDEX.contains("New project"));
        assert!(INDEX.contains("New worker"));
        assert!(INDEX.contains("Registration token"));
        assert!(INDEX.contains("Configure worker"));
        assert!(INDEX.contains("Initial prompt"));
        assert!(INDEX.contains("worker-config-provider"));
        assert!(INDEX.contains("worker-config-model"));
        assert!(INDEX.contains("Real Pi catalog from this worker"));
        assert!(INDEX.contains("Pi-reported metadata"));
        assert!(INDEX.contains("Choose provider"));
        assert!(INDEX.contains("No available models yet"));
        assert!(INDEX.contains("worker-provider-api-key"));
        assert!(INDEX.contains("/provider-key"));
        assert!(INDEX.contains("API keys are write-only"));
        assert!(INDEX.contains("modelCostLabel"));
        assert!(INDEX.contains("Unclaimed"));
        assert!(INDEX.contains("Working"));
        assert!(INDEX.contains("Review"));
        assert!(INDEX.contains("MergePending"));
        assert!(INDEX.contains("#queue-cards"));
        assert!(INDEX.contains("#working-cards"));
        assert!(INDEX.contains("#review-cards"));
        assert!(INDEX.contains("#merge-cards"));
        // Compact task cards: single title + 3-line clamped summary, no lifecycle pills.
        assert!(INDEX.contains("cardSummary"));
        assert!(INDEX.contains("compactCard"));
        assert!(INDEX.contains("x.result?.summary||t.expected_outcome||t.description"));
        assert!(INDEX.contains("-webkit-line-clamp:3"));
        assert!(INDEX.contains("-webkit-box-orient:vertical"));
        assert!(INDEX.contains("text-overflow:ellipsis"));
        assert!(INDEX.contains("overflow-wrap:anywhere"));
        assert!(INDEX.contains(".lane{"));
        assert!(INDEX.contains("min-width:0;overflow:hidden"));
        assert!(INDEX.contains(".card{"));
        assert!(INDEX.contains("max-width:100%;overflow:hidden"));
        // Plain-text summary cleanup: strip Markdown markers and collapse whitespace
        // at render time only; stored result data is untouched.
        assert!(INDEX.contains("plainSummary"));
        assert!(INDEX.contains("esc(plainSummary(summary))"));
        assert!(INDEX.contains("/\\s+/g"));
        // Configure worker: compact sectioned layout with preserved field IDs/behavior.
        assert!(INDEX.contains("config-section"));
        assert!(INDEX.contains("config-section-title"));
        assert!(INDEX.contains("aria-label=\"Identity\""));
        assert!(INDEX.contains("aria-label=\"Scope\""));
        assert!(INDEX.contains("aria-label=\"Agent runtime\""));
        assert!(INDEX.contains("aria-label=\"Prompt\""));
        assert!(INDEX.contains(">Identity<"));
        assert!(INDEX.contains(">Scope<"));
        assert!(INDEX.contains(">Agent runtime<"));
        assert!(INDEX.contains(">Prompt<"));
        assert!(INDEX.contains("identity-grid"));
        assert!(INDEX.contains("scope-grid"));
        assert!(INDEX.contains("runtime-grid"));
        assert!(INDEX.contains("worker-config-prompt-details"));
        assert!(INDEX.contains("config-prompt"));
        assert!(INDEX.contains("worker-config-name"));
        assert!(INDEX.contains("worker-config-role"));
        assert!(INDEX.contains("worker-config-slots"));
        assert!(INDEX.contains("identity-help"));
        assert!(INDEX.contains("align-items:start"));
        assert!(INDEX.contains("Slots are concurrent isolated assignments on this worker"));
        assert!(INDEX.contains("each slot gets its own container, workspace, execution ID, and task branch"));
        assert!(INDEX.contains("worker-config-projects"));
        assert!(INDEX.contains("Comma-separated project slugs; spaces are optional"));
        assert!(INDEX.contains("parseProjectInput"));
        assert!(INDEX.contains("worker-config-tags"));
        assert!(!INDEX.contains("worker-system-tags"));
        assert!(!INDEX.contains(">System tags<"));
        assert!(INDEX.contains("worker-managed-capabilities"));
        assert!(INDEX.contains("worker-capability-status"));
        assert!(!INDEX.contains("worker-capability-log-details"));
        assert!(INDEX.contains("worker-log-dialog"));
        assert!(INDEX.contains("worker-log-content"));
        assert!(INDEX.contains("WORKER_LOG_PAGE_LINES=100"));
        assert!(INDEX.contains("openWorkerLog"));
        assert!(INDEX.contains("changeWorkerLogPage"));
        assert!(INDEX.contains("aria-label=\"Configure worker\""));
        assert!(INDEX.contains("aria-label=\"Worker log\""));
        assert!(INDEX.contains("w.capability_phase"));
        assert!(INDEX.contains("w?.capability_log"));
        assert!(INDEX.contains("/api/worker-capabilities"));
        assert!(INDEX.contains("selectedManagedCapabilities"));
        assert!(INDEX.contains("managedCapabilitiesDraft"));
        assert!(INDEX.contains("updateManagedCapabilityDraft(this)"));
        assert!(INDEX.contains("workerConfigCatalogSignature"));
        assert!(INDEX.contains("signature!==workerConfigCatalogSignature"));
        assert!(INDEX.contains("workerListSignature"));
        assert!(INDEX.contains("if(html!==workerListSignature)"));
        assert!(INDEX.contains("signature===workerLogSignature"));
        assert!(!INDEX.contains("if(w){renderManagedCapabilities(w);renderAgentCatalog(w)}"));
        assert!(INDEX.contains("Adding tools rebuilds the agent container"));
        assert!(INDEX.contains("pending and will not claim tasks or reviews"));
        // Protocol v6 only: no legacy protocol<5 managed-tool compatibility branch/message.
        assert!(!INDEX.contains("Update/restart this worker before changing managed tools"));
        assert!(!INDEX.contains("(w.protocol_version||0)<5"));
        assert!(!INDEX.contains("input.disabled=old"));
        assert!(INDEX.contains("worker-config-agent"));
        assert!(INDEX.contains("worker-agent-status"));
        assert!(INDEX.contains("worker-config-prompt"));
        assert!(INDEX.contains("worker-provider-auth"));
        assert!(INDEX.contains("renderProviderAuth"));
        assert!(INDEX.contains("worker-model-refresh"));
        assert!(INDEX.contains("refreshProviderModels"));
        assert!(!INDEX.contains("clear_model:!(provider&&model)"));
        assert!(INDEX.contains("/models/refresh"));
        assert!(INDEX.contains("Configure provider authentication before refreshing models"));
        assert!(INDEX.contains("onWorkerRoleChange"));
        assert!(INDEX.contains("renderWorkerModels"));
        assert!(INDEX.contains("renderAgentCatalog"));
        assert!(INDEX.contains("saveWorkerConfig"));
        assert!(INDEX.contains("card-title"));
        assert!(INDEX.contains("project-pill"));
        assert!(INDEX.contains("projectPill(p)"));
        assert!(INDEX.contains("taskCard(x,pm)"));
        assert!(INDEX.contains("white-space:nowrap"));
        assert!(INDEX.contains("height:calc(1.35em * 3)"));
        assert!(!INDEX.contains("card-actions"));
        assert!(INDEX.contains("worker-pill"));
        assert!(INDEX.contains("reviewer-pill"));
        assert!(INDEX.contains("Working · "));
        assert!(INDEX.contains("Review · "));
        assert!(INDEX.contains("x.reviewer?.name"));
        assert!(!INDEX.contains("p?.reviewer?.mode==='mcp'"));
        assert!(!INDEX.contains("'unclaimed'"));
        assert!(!INDEX.contains("merge_pending</span>"));
        assert!(!INDEX.contains("STATIC_MODELS"));
        assert!(!INDEX.contains("STATIC_PROVIDERS"));
        assert!(!INDEX.contains("project-reviewer-prompt"));
        assert!(!INDEX.contains("Advanced review"));
        assert!(INDEX.contains("project-runner-labels"));
        assert!(INDEX.contains("Runs on"));
        assert!(INDEX.contains("All labels are required (AND)"));
        assert!(INDEX.contains("parseRunnerLabels"));
        assert!(INDEX.contains("formatRunnerLabels"));
        assert!(!INDEX.contains("Advanced tags"));
        assert!(!INDEX.contains("project-worker-tags"));
        assert!(!INDEX.contains("project-task-tags"));
        assert!(INDEX.contains("worker-config-prompt"));
        assert!(!INDEX.contains("· contributor "));
        assert!(!INDEX.contains("review ChatGPT / MCP ·"));
        assert!(INDEX.contains("project-contributor-name"));
        assert!(INDEX.contains("project-contributor-email"));
        assert!(INDEX.contains("contributor:{name:"));
        assert!(!INDEX.contains("ChatGPT / MCP reviewer prompt"));
        assert!(!INDEX.contains("project-git-worker-managed"));
        assert!(INDEX.contains("project-git-auth-mode"));
        assert!(INDEX.contains("<option value=\"host\">Host environment / public repository</option>"));
        assert!(INDEX.contains("Upstream Git access (Host only)"));
        assert!(INDEX.contains("workers never access upstream directly"));
        assert!(INDEX.contains("<option value=\"https_basic\">Host HTTPS username + token/password</option>"));
        assert!(INDEX.contains("project-git-secret"));
        assert!(INDEX.contains("x-access-token"));
        assert!(INDEX.contains("Git credential was not stored; project remains unusable."));
        assert!(INDEX.contains("probe-dot"));
        assert!(INDEX.contains("Git R/W OK"));
        assert!(INDEX.contains("Git read-only"));
        assert!(INDEX.contains("credential revision"));
        assert!(INDEX.contains("Git failed"));
        assert!(INDEX.contains("/git-probe"));
        assert!(INDEX.contains("probeProjectGit"));
        assert!(INDEX.contains("title=\"Edit project\""));
        assert!(INDEX.contains("toggleLabel=p.enabled?'Disable project':'Enable project'"));
        assert!(INDEX.contains("title=\"Delete project\""));
        assert!(INDEX.contains("title=\"Delete task\""));
        assert!(INDEX.contains("merge_pending"));
        assert!(!INDEX.contains(">Approve</button>"));
        assert!(!INDEX.contains(">Retry</button>"));
        // Review-loop signal: durable attempt/review counts on Home cards.
        // Completed reviews keep the "Reviews N" label; runtime failures
        // and lost leases use separate labels and are never folded into it.
        assert!(INDEX.contains("loopCounts"));
        assert!(INDEX.contains("loopMeta"));
        assert!(INDEX.contains("isLoopingCounts"));
        assert!(INDEX.contains("Build "));
        assert!(INDEX.contains("Reviews "));
        assert!(INDEX.contains("Runtime failures "));
        assert!(INDEX.contains("Lost "));
        assert!(INDEX.contains("Returned "));
        assert!(INDEX.contains("Looping"));
        assert!(INDEX.contains("loop-pill"));
        assert!(INDEX.contains("looping-pill"));
        assert!(INDEX.contains("review_rounds"));
        assert!(INDEX.contains("review_runtime_failures"));
        assert!(INDEX.contains("review_lost_leases"));
        assert!(INDEX.contains("reviewer_retries"));
        // Current-cycle vs lifetime retries are tracked separately: the
        // per-cycle limit gates automatic redispatch while lifetime history
        // stays observable. Badges distinguish the two when they differ.
        assert!(INDEX.contains("current_cycle_reviewer_retries"));
        assert!(INDEX.contains("lifetime_reviewer_retries"));
        assert!(INDEX.contains("lifetimeReturned"));
        assert!(INDEX.contains("Lifetime returned "));
        assert!(INDEX.contains("current review cycle"));
        // Compact card layout and 3-line summary behavior are preserved.
        assert!(INDEX.contains("compactCard(t.title,cardSummary(x),"));
        // Looping derives from durable counts only, never review_feedback prose.
        assert!(!INDEX.contains("review_feedback"));
        // Host Insights: durable worker/reviewer/main-gate statistics.
        assert!(INDEX.contains(r#"data-page="insights""#));
        assert!(INDEX.contains("id=\"page-insights\""));
        assert!(INDEX.contains("/api/insights"));
        assert!(INDEX.contains("insights-window"));
        assert!(INDEX.contains("refreshInsights"));
        assert!(INDEX.contains("renderInsights"));
        assert!(INDEX.contains("setInsightsWindow"));
        assert!(INDEX.contains("Reviewer quality vs runtime"));
        assert!(INDEX.contains("Main gate"));
        assert!(INDEX.contains("Completion time"));
        assert!(INDEX.contains("Implementation by worker"));
        assert!(INDEX.contains("Reviewer by worker"));
        assert!(INDEX.contains("Retry and send-back reasons"));
        assert!(INDEX.contains("Lifetime retries"));
        assert!(INDEX.contains("Current-cycle retries"));
        assert!(INDEX.contains("merge-conflict redispatch"));
        assert!(INDEX.contains("never model-quality failures"));
        assert!(INDEX.contains("main_gate_merge_conflict"));
        assert!(INDEX.contains("main_gate_upstream_moved"));
        assert!(INDEX.contains("reviewer_retries_current_cycle"));
        assert!(INDEX.contains("reviews_runtime_failed"));
        assert!(INDEX.contains("/api/tasks/'"));
        assert!(INDEX.contains("Gate outcome"));
        assert!(INDEX.contains("Backend / provider / model"));
        // Task detail exposes durable gate outcomes, never current task state.
        assert!(!INDEX.contains("esc(t.state)"));
        // Evidence drill-down: every task/execution/review/event ID is an
        // action opening the state-independent history bundle, which works
        // for queued retries and cancelled tasks too.
        assert!(INDEX.contains("Evidence drill-down"));
        assert!(INDEX.contains("showInsightEvidence"));
        assert!(INDEX.contains("insightEvidenceLink"));
        assert!(INDEX.contains("/history"));
        assert!(INDEX.contains("insights-evidence"));
        assert!(INDEX.contains("insightVerdictText"));
        // Insights history never filters on mutable task state.
        assert!(!INDEX.contains("state!='cancelled'"));
        // Evidence drill-down surfaces the review-cycle epoch.
        assert!(INDEX.contains("review_cycle"));
        assert!(INDEX.contains("cycle "));
        assert!(!INDEX.contains("/api/tasks/'+esc(r.task_id)+'/review"));
        // Scheduler waiting diagnostics: machine-readable reason + detail on
        // waiting cards only; actively running/reviewing cards stay unspammed.
        assert!(INDEX.contains("waitingMeta"));
        assert!(INDEX.contains("waiting-pill"));
        assert!(INDEX.contains("Waiting · "));
        assert!(INDEX.contains("x.waiting"));
        assert!(INDEX.contains("no_eligible_worker"));
        assert!(INDEX.contains("review_failure_limit"));
        // Insights evidence drill-down renders the same waiting diagnostic.
        assert!(INDEX.contains("h.waiting"));
    }
}
