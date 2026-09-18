use std::{
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use anyhow::{ensure, Context};
use axum::{extract::DefaultBodyLimit, middleware, Router};
use clap::Parser;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
use tower_http::trace::TraceLayer;
use tracing::info;
use url::Url;

mod api;
mod cimd;
mod git_credentials;
mod mcp;
mod oauth;
mod review;
mod security;
mod web;

pub(crate) use api::{
    create_project, create_task, delete_task, list_projects, list_tasks, list_workers, review_evidence, ApiError, AppState,
    CreateProject, CreateTask,
};

#[derive(Parser, Debug)]
struct Args {
    #[arg(long, env = "LAZYTEAM_LISTEN", default_value = "0.0.0.0:8787")]
    listen: SocketAddr,
    #[arg(long, env = "LAZYTEAM_DATABASE_URL", default_value = "sqlite://data/lazyteam.db?mode=rwc")]
    database_url: String,
    #[arg(long, env = "LAZYTEAM_PUBLIC_URL")]
    public_url: Option<String>,
    #[arg(long, env = "LAZYTEAM_OAUTH_PASSWORD")]
    oauth_password: Option<String>,
    #[arg(long, env = "LAZYTEAM_PRODUCTION", default_value_t = false)]
    production: bool,
    #[arg(long, env = "LAZYTEAM_ADMIN_TOKEN")]
    admin_token: Option<String>,
    #[arg(long, env = "LAZYTEAM_WORKER_TOKEN")]
    worker_token: Option<String>,
    /// Base64-encoded 32-byte master key used only to encrypt project Git credentials at rest.
    /// It is optional while every project relies on credentials configured directly on workers.
    #[arg(long, env = "LAZYTEAM_GIT_CREDENTIAL_KEY")]
    git_credential_key: Option<String>,
    #[arg(long, env = "LAZYTEAM_ALLOWED_OAUTH_CLIENT_HOSTS", default_value = "")]
    allowed_oauth_client_hosts: String,
    #[arg(long, env = "LAZYTEAM_ALLOWED_REDIRECT_HOSTS", default_value = "")]
    allowed_redirect_hosts: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    eprintln!("LazyTeam server starting version={} git_sha={}", env!("CARGO_PKG_VERSION"), lazyteam_core::BUILD_GIT_SHA);
    let args = Args::parse();
    let public_url = args
        .public_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string());
    let allowed_oauth_client_hosts = parse_hosts(&args.allowed_oauth_client_hosts);
    let allowed_redirect_hosts = parse_hosts(&args.allowed_redirect_hosts);
    let git_credential_key = args
        .git_credential_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(git_credentials::parse_master_key)
        .transpose()
        .context("parse LAZYTEAM_GIT_CREDENTIAL_KEY")?;

    if let Some(public) = public_url.as_deref() {
        validate_public_url(public)?;
    }

    if args.production {
        let public = public_url
            .as_deref()
            .context("LAZYTEAM_PUBLIC_URL is required in production")?;
        let parsed = Url::parse(public).context("parse LAZYTEAM_PUBLIC_URL")?;
        ensure!(
            parsed.scheme() == "https" && parsed.host_str().is_some(),
            "LAZYTEAM_PUBLIC_URL must be an absolute https:// URL in production"
        );
        ensure!(
            args.oauth_password.as_deref().is_some_and(|v| v.len() >= 16),
            "LAZYTEAM_OAUTH_PASSWORD must be at least 16 characters in production"
        );
        ensure!(
            args.admin_token.as_deref().is_some_and(|v| v.len() >= 32),
            "LAZYTEAM_ADMIN_TOKEN must be at least 32 characters in production"
        );
        ensure!(
            args.worker_token.as_deref().is_some_and(|v| v.len() >= 32),
            "LAZYTEAM_WORKER_TOKEN must be at least 32 characters in production"
        );
        ensure!(
            !allowed_oauth_client_hosts.is_empty(),
            "LAZYTEAM_ALLOWED_OAUTH_CLIENT_HOSTS is required in production"
        );
        ensure!(
            !allowed_redirect_hosts.is_empty(),
            "LAZYTEAM_ALLOWED_REDIRECT_HOSTS is required in production"
        );
    }

    security::init(security::SecurityConfig {
        production: args.production,
        public_url: public_url.clone(),
        admin_token: args.admin_token.clone(),
        worker_token: args.worker_token.clone(),
        allowed_oauth_client_hosts,
        allowed_redirect_hosts,
    })?;

    if args.database_url.starts_with("sqlite://data/") {
        tokio::fs::create_dir_all("data").await?;
    }
    let connect_options = SqliteConnectOptions::from_str(&args.database_url)
        .context("parse sqlite URL")?
        .create_if_missing(true)
        .foreign_keys(true)
        .journal_mode(SqliteJournalMode::Wal);
    let db = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(connect_options)
        .await
        .context("connect sqlite")?;
    sqlx::migrate!().run(&db).await.context("run migrations")?;

    let mcp_config = mcp_http_config(public_url.as_deref())?;
    let root_mcp_config = mcp_http_config(public_url.as_deref())?;
    let state = Arc::new(AppState {
        db,
        public_url,
        oauth_password: args.oauth_password,
        git_credential_key,
        agent_auth_updates: Default::default(),
    });

    let mcp_state = state.clone();
    let mcp_service = StreamableHttpService::new(
        move || Ok(mcp::LazyTeamMcp::new(mcp_state.clone())),
        LocalSessionManager::default().into(),
        mcp_config,
    );
    let root_mcp_state = state.clone();
    let root_mcp_service = StreamableHttpService::new(
        move || Ok(mcp::LazyTeamMcp::new(root_mcp_state.clone())),
        LocalSessionManager::default().into(),
        root_mcp_config,
    );
    let mcp_router = Router::<Arc<AppState>>::new()
        .route_service("/", root_mcp_service)
        .route_service("/mcp", mcp_service)
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            oauth::require_mcp_auth,
        ));

    let app = Router::new()
        .merge(web::router())
        .merge(api::router())
        .merge(review::router())
        .merge(oauth::router())
        .merge(mcp_router)
        .layer(DefaultBodyLimit::max(security::MAX_REQUEST_BODY))
        .layer(middleware::from_fn(security::middleware))
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    tokio::spawn(api::reaper(state.clone()));

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    info!(listen = %args.listen, production = args.production, "LazyTeam control plane listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn mcp_http_config(public_url: Option<&str>) -> anyhow::Result<StreamableHttpServerConfig> {
    let mut allowed_hosts = vec![
        "localhost".to_string(),
        "127.0.0.1".to_string(),
        "::1".to_string(),
    ];
    if let Some(public) = public_url {
        let parsed = Url::parse(public).context("parse LAZYTEAM_PUBLIC_URL for MCP host guard")?;
        if let Some(host) = parsed.host_str() {
            let host = host.to_ascii_lowercase();
            if !allowed_hosts.iter().any(|allowed| allowed == &host) {
                allowed_hosts.push(host);
            }
        }
    }
    Ok(StreamableHttpServerConfig::default()
        .with_allowed_hosts(allowed_hosts)
        .with_legacy_session_mode(true)
        .with_json_response(true))
}

fn validate_public_url(public: &str) -> anyhow::Result<()> {
    let parsed = Url::parse(public).context("parse LAZYTEAM_PUBLIC_URL")?;
    let host = parsed
        .host_str()
        .context("LAZYTEAM_PUBLIC_URL must be an absolute URL with a host")?;
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    if !is_loopback {
        ensure!(
            parsed.scheme() == "https",
            "LAZYTEAM_PUBLIC_URL must use https:// for non-loopback hosts"
        );
    } else {
        ensure!(
            matches!(parsed.scheme(), "http" | "https"),
            "LAZYTEAM_PUBLIC_URL loopback development URLs must use http:// or https://"
        );
    }
    Ok(())
}

fn parse_hosts(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header;

    #[test]
    fn mcp_host_guard_allows_public_url_host_and_loopback() {
        let config = mcp_http_config(Some("https://LazyTeam.Example.Test:8443/path")).unwrap();
        assert!(config.allowed_hosts.iter().any(|host| host == "lazyteam.example.test"));
        assert!(config.allowed_hosts.iter().any(|host| host == "localhost"));
        assert!(config.allowed_hosts.iter().any(|host| host == "127.0.0.1"));
        assert!(config.allowed_hosts.iter().any(|host| host == "::1"));
    }

    #[tokio::test]
    async fn public_host_reaches_mcp_discovery() {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_lazy("sqlite::memory:")
            .unwrap();
        let state = Arc::new(AppState {
            db,
            public_url: Some("https://lazyteam.example.test".to_string()),
            oauth_password: None,
            git_credential_key: None,
            agent_auth_updates: Default::default(),
        });
        let mcp_state = state.clone();
        let service = StreamableHttpService::new(
            move || Ok(mcp::LazyTeamMcp::new(mcp_state.clone())),
            LocalSessionManager::default().into(),
            mcp_http_config(state.public_url.as_deref()).unwrap(),
        );
        let app = Router::new().route_service("/mcp", service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let response = reqwest::Client::new()
            .post(format!("http://{addr}/mcp"))
            .header(header::HOST, "lazyteam.example.test")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json, text/event-stream")
            .header("MCP-Protocol-Version", "2026-07-28")
            .header("Mcp-Method", "server/discover")
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": "discover-public-host",
                "method": "server/discover",
                "params": {
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                        "io.modelcontextprotocol/clientInfo": {
                            "name": "lazyteam-public-host-test",
                            "version": "1.0"
                        },
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }
            }))
            .send()
            .await
            .unwrap();
        let status = response.status();
        let body = response.text().await.unwrap();
        server.abort();

        assert_eq!(status, reqwest::StatusCode::OK, "public Host was rejected: {body}");
        assert!(body.contains("2026-07-28"), "discover omitted modern protocol: {body}");
    }
}
