use std::{net::SocketAddr, str::FromStr, sync::Arc};

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
mod mcp;
mod oauth;
mod review;
mod security;
mod web;

pub(crate) use api::{
    create_project, create_task, list_projects, list_tasks, list_workers, ApiError, AppState,
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

    let args = Args::parse();
    let public_url = args
        .public_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.trim_end_matches('/').to_string());
    let allowed_oauth_client_hosts = parse_hosts(&args.allowed_oauth_client_hosts);
    let allowed_redirect_hosts = parse_hosts(&args.allowed_redirect_hosts);

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

    let state = Arc::new(AppState {
        db,
        public_url,
        oauth_password: args.oauth_password,
    });

    let mcp_state = state.clone();
    let mcp_service = StreamableHttpService::new(
        move || Ok(mcp::LazyTeamMcp::new(mcp_state.clone())),
        LocalSessionManager::default().into(),
        StreamableHttpServerConfig::default()
            .with_legacy_session_mode(false)
            .with_json_response(true),
    );
    let mcp_router = Router::<Arc<AppState>>::new()
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

fn parse_hosts(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}
