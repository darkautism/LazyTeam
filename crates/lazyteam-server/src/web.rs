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
        assert!(INDEX.contains("sessionStorage.setItem(TOKEN_KEY,token)"));
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
        assert!(INDEX.contains("Re-dispatch"));
        assert!(INDEX.contains("deleteTask"));
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
        assert!(INDEX.contains("card-title"));
        assert!(INDEX.contains("card-actions"));
        assert!(!INDEX.contains("worker-pill"));
        assert!(!INDEX.contains("ChatGPT / MCP review"));
        assert!(!INDEX.contains("'unclaimed'"));
        assert!(!INDEX.contains("merge_pending</span>"));
        assert!(!INDEX.contains("STATIC_MODELS"));
        assert!(!INDEX.contains("STATIC_PROVIDERS"));
        assert!(INDEX.contains("project-reviewer-prompt"));
        assert!(INDEX.contains("ChatGPT / MCP"));
        assert!(INDEX.contains("project-git-worker-managed"));
        assert!(INDEX.contains("project-git-auth-mode"));
        assert!(INDEX.contains("project-git-secret"));
        assert!(INDEX.contains("I will configure repository credentials on each worker"));
        assert!(INDEX.contains("merge_pending"));
        assert!(!INDEX.contains(">Approve</button>"));
        assert!(!INDEX.contains(">Retry</button>"));
    }
}
