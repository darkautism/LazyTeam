use std::{net::SocketAddr, sync::Arc};

use anyhow::Context;
use axum::{middleware, Router};
use clap::Parser;
use rmcp::transport::streamable_http_server::{
    session::local::LocalSessionManager, StreamableHttpServerConfig, StreamableHttpService,
};
use sqlx::sqlite::SqlitePoolOptions;
use tower_http::trace::TraceLayer;
use tracing::info;

mod api;
mod cimd;
mod mcp;
mod oauth;
mod review;
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    if args.database_url.starts_with("sqlite://data/") {
        tokio::fs::create_dir_all("data").await?;
    }
    let db = SqlitePoolOptions::new()
        .max_connections(8)
        .connect(&args.database_url)
        .await
        .context("connect sqlite")?;
    sqlx::migrate!().run(&db).await.context("run migrations")?;

    let state = Arc::new(AppState {
        db,
        public_url: args.public_url.map(|s| s.trim_end_matches('/').to_string()),
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
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    tokio::spawn(api::reaper(state.clone()));

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    info!(listen = %args.listen, "LazyTeam control plane listening");
    axum::serve(listener, app).await?;
    Ok(())
}
