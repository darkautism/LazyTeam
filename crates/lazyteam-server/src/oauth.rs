use std::{path::Path, sync::Arc};

use async_trait::async_trait;
use axum::Router;
use ::oauth::{
    ExternalClientResolver, OAuthConfig, OAuthState, RedirectPolicy, ResolvedClient, TokenPrefixes,
};

use crate::{cimd, AppState};

struct LazyTeamClientResolver;

#[async_trait]
impl ExternalClientResolver for LazyTeamClientResolver {
    async fn resolve(&self, client_id: &str) -> Result<Option<ResolvedClient>, String> {
        if !cimd::is_cimd_client_id(client_id) {
            return Ok(None);
        }
        let client = cimd::resolve(client_id).await?;
        Ok(Some(ResolvedClient {
            redirect_uris: client.redirect_uris,
            auth_method: client.token_endpoint_auth_method,
            secret_hash: None,
        }))
    }
}

pub async fn state(
    app: &AppState,
    database_path: impl AsRef<Path>,
) -> Result<Arc<OAuthState>, ::oauth::StorageError> {
    Ok(Arc::new(
        OAuthState::open_migrating_legacy(
            database_path,
            OAuthConfig {
                service_name: "LazyTeam".into(),
                scope: "lazyteam".into(),
                public_url: app.public_url.clone(),
                oauth_password: app.oauth_password.clone(),
                default_host: "127.0.0.1:8787".into(),
                token_prefixes: TokenPrefixes::new("lt"),
                redirect_policy: RedirectPolicy::PublicMcp,
                client_id_metadata_document_supported: true,
            },
            &app.db,
        )
        .await?
        .with_external_client_resolver(Arc::new(LazyTeamClientResolver)),
    ))
}

pub fn router<S>(state: Arc<OAuthState>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    ::oauth::router(state)
}

pub use ::oauth::require_mcp_auth;
