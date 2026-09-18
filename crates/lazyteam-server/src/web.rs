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
        assert!(INDEX.contains("project-reviewer-prompt"));
        assert!(INDEX.contains("ChatGPT / MCP"));
        assert!(INDEX.contains("merge_pending"));
        assert!(!INDEX.contains(">Approve</button>"));
        assert!(!INDEX.contains(">Retry</button>"));
    }
}
