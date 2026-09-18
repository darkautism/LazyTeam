use std::sync::Arc;

use axum::{
    extract::{Form, Query, State},
    http::{header, HeaderMap, StatusCode},
    middleware::Next,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}, Engine};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sqlx::Row;
use url::Url;
use uuid::Uuid;

use crate::{cimd, AppState};

pub const DEFAULT_SCOPE: &str = "lazyteam";
const ACCESS_TTL_SECS: i64 = 3600;
const CODE_TTL_SECS: i64 = 600;
const REFRESH_TTL_SECS: i64 = 30 * 24 * 3600;

#[derive(Debug)]
struct ResolvedClient {
    redirect_uris: Vec<String>,
    auth_method: String,
    secret_hash: Option<String>,
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/.well-known/oauth-protected-resource", get(protected_resource_metadata_root))
        .route("/.well-known/oauth-protected-resource/mcp", get(protected_resource_metadata_mcp))
        .route("/.well-known/oauth-authorization-server", get(authorization_server_metadata))
        .route("/.well-known/openid-configuration", get(authorization_server_metadata))
        .route("/.well-known/oauth-authorization-server/mcp", get(authorization_server_metadata))
        .route("/.well-known/openid-configuration/mcp", get(authorization_server_metadata))
        .route("/mcp/.well-known/oauth-authorization-server", get(authorization_server_metadata))
        .route("/mcp/.well-known/openid-configuration", get(authorization_server_metadata))
        .route("/mcp/oauth/register", post(register_client))
        .route("/mcp/oauth/authorize", get(authorize_get).post(authorize_post))
        .route("/mcp/oauth/token", post(token))
}

fn issuer(state: &AppState, headers: &HeaderMap) -> String {
    if let Some(url) = &state.public_url {
        return url.clone();
    }

    let host = headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:8787");

    // Reverse proxies and tunnels terminate TLS before forwarding to LazyTeam.
    // Keep LAZYTEAM_PUBLIC_URL authoritative when configured, but when it is
    // absent infer only the scheme from standard proxy headers while preserving
    // the actual Host header seen by the request.
    let forwarded_https = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("https"))
        || headers
            .get(header::FORWARDED)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| {
                v.split(';')
                    .chain(v.split(','))
                    .any(|part| part.trim().eq_ignore_ascii_case("proto=https"))
            })
        || headers
            .get("x-forwarded-port")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.trim() == "443");

    let authority_host = host
        .parse::<axum::http::uri::Authority>()
        .ok()
        .map(|a| a.host().to_ascii_lowercase())
        .unwrap_or_else(|| host.to_ascii_lowercase());
    let local = matches!(
        authority_host.as_str(),
        "localhost" | "127.0.0.1" | "::1"
    );

    let scheme = if forwarded_https || !local { "https" } else { "http" };
    format!("{scheme}://{host}")
}

fn resource_url(state: &AppState, headers: &HeaderMap) -> String {
    format!("{}/mcp", issuer(state, headers))
}

async fn protected_resource_metadata_root(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Json<Value> {
    let origin = issuer(&state, &headers);
    protected_resource_metadata_response(format!("{origin}/"), origin)
}

async fn protected_resource_metadata_mcp(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Json<Value> {
    let origin = issuer(&state, &headers);
    protected_resource_metadata_response(format!("{origin}/mcp"), origin)
}

fn protected_resource_metadata_response(resource: String, authorization_server: String) -> Json<Value> {
    Json(json!({
        "resource": resource,
        "authorization_servers": [authorization_server],
        "scopes_supported": [DEFAULT_SCOPE],
        "bearer_methods_supported": ["header"]
    }))
}

async fn authorization_server_metadata(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Json<Value> {
    let origin = issuer(&state, &headers);
    Json(json!({
        "issuer": origin,
        "authorization_endpoint": format!("{origin}/mcp/oauth/authorize"),
        "token_endpoint": format!("{origin}/mcp/oauth/token"),
        "registration_endpoint": format!("{origin}/mcp/oauth/register"),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
        "scopes_supported": [DEFAULT_SCOPE],
        "registration_endpoint_auth_methods_supported": ["none"],
        "client_id_metadata_document_supported": true
    }))
}

#[derive(Debug, Deserialize)]
struct ClientRegistration {
    redirect_uris: Vec<String>,
    #[serde(default)]
    client_name: Option<String>,
    #[serde(default = "default_auth_method")]
    token_endpoint_auth_method: String,
}

fn default_auth_method() -> String {
    "none".into()
}

async fn register_client(
    State(state): State<Arc<AppState>>,
    Json(input): Json<ClientRegistration>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    if input.redirect_uris.is_empty() || input.redirect_uris.iter().any(|u| !valid_redirect_uri(u)) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "invalid redirect_uris",
        ));
    }
    if !matches!(
        input.token_endpoint_auth_method.as_str(),
        "none" | "client_secret_post" | "client_secret_basic"
    ) {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "unsupported token_endpoint_auth_method",
        ));
    }

    let client_id = format!("ltc_{}", Uuid::new_v4().simple());
    let client_secret = (input.token_endpoint_auth_method != "none").then(|| random_token("lts"));
    sqlx::query("INSERT INTO oauth_clients(client_id,client_secret_hash,redirect_uris,token_endpoint_auth_method,client_name,created_at) VALUES(?,?,?,?,?,?)")
        .bind(&client_id)
        .bind(client_secret.as_deref().map(hash))
        .bind(serde_json::to_string(&input.redirect_uris).map_err(internal_oauth)?)
        .bind(&input.token_endpoint_auth_method)
        .bind(&input.client_name)
        .bind(Utc::now().to_rfc3339())
        .execute(&state.db)
        .await
        .map_err(internal_oauth)?;

    let mut out = json!({
        "client_id": client_id,
        "redirect_uris": input.redirect_uris,
        "client_name": input.client_name,
        "token_endpoint_auth_method": input.token_endpoint_auth_method,
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"]
    });
    if let Some(secret) = client_secret {
        out["client_secret"] = Value::String(secret);
        out["client_secret_expires_at"] = Value::from(0);
    }
    Ok((StatusCode::CREATED, Json(out)))
}

fn valid_redirect_uri(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    match url.scheme() {
        "https" => {
            url.host_str().is_some() && url.username().is_empty() && url.password().is_none()
        }
        "http" => matches!(
            url.host_str(),
            Some("127.0.0.1") | Some("localhost") | Some("::1")
        ),
        _ => false,
    }
}

async fn resolve_client(state: &AppState, client_id: &str) -> Result<ResolvedClient, String> {
    let row = sqlx::query("SELECT redirect_uris,token_endpoint_auth_method,client_secret_hash FROM oauth_clients WHERE client_id=?")
        .bind(client_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| format!("read OAuth client: {e}"))?;

    if let Some(row) = row {
        let raw: String = row
            .try_get("redirect_uris")
            .map_err(|e| format!("read redirect_uris: {e}"))?;
        let redirect_uris = serde_json::from_str(&raw)
            .map_err(|e| format!("parse redirect_uris: {e}"))?;
        return Ok(ResolvedClient {
            redirect_uris,
            auth_method: row
                .try_get("token_endpoint_auth_method")
                .map_err(|e| format!("read auth method: {e}"))?,
            secret_hash: row
                .try_get("client_secret_hash")
                .map_err(|e| format!("read client secret: {e}"))?,
        });
    }

    if cimd::is_cimd_client_id(client_id) {
        let client = cimd::resolve(client_id).await?;
        return Ok(ResolvedClient {
            redirect_uris: client.redirect_uris,
            auth_method: client.token_endpoint_auth_method,
            secret_hash: None,
        });
    }

    Err("unknown client".into())
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct AuthorizeParams {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    #[serde(default)]
    code_challenge_method: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

async fn authorize_get(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeParams>,
) -> Result<Html<String>, (StatusCode, String)> {
    validate_authorize(&state, &params).await?;
    let method = params
        .code_challenge_method
        .clone()
        .unwrap_or_else(|| "S256".into());
    let form = format!(
        r#"<!doctype html><meta charset="utf-8"><title>Authorize LazyTeam</title>
<style>body{{font-family:sans-serif;max-width:42rem;margin:4rem auto;padding:0 1rem}}input{{width:100%;padding:.7rem;margin:.4rem 0}}button{{padding:.7rem 1rem}}</style>
<h1>Authorize LazyTeam MCP</h1><p>Client: <code>{}</code></p><form method="post" action="/mcp/oauth/authorize">
<input type="hidden" name="client_id" value="{}"><input type="hidden" name="redirect_uri" value="{}">
<input type="hidden" name="code_challenge" value="{}"><input type="hidden" name="code_challenge_method" value="{}">
<input type="hidden" name="state" value="{}"><input type="hidden" name="resource" value="{}"><input type="hidden" name="scope" value="{}">
<label>LazyTeam password</label><input type="password" name="password" autofocus required><button type="submit">Authorize</button></form>"#,
        esc(&params.client_id),
        esc(&params.client_id),
        esc(&params.redirect_uri),
        esc(&params.code_challenge),
        esc(&method),
        esc(params.state.as_deref().unwrap_or("")),
        esc(params.resource.as_deref().unwrap_or("")),
        esc(params.scope.as_deref().unwrap_or(DEFAULT_SCOPE))
    );
    Ok(Html(form))
}

#[derive(Debug, Deserialize)]
struct AuthorizeForm {
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    #[serde(default)]
    state: String,
    #[serde(default)]
    resource: String,
    #[serde(default)]
    scope: String,
    password: String,
}

async fn authorize_post(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(form): Form<AuthorizeForm>,
) -> Result<Redirect, (StatusCode, String)> {
    let params = AuthorizeParams {
        client_id: form.client_id.clone(),
        redirect_uri: form.redirect_uri.clone(),
        code_challenge: form.code_challenge.clone(),
        code_challenge_method: Some(form.code_challenge_method.clone()),
        state: Some(form.state.clone()),
        resource: (!form.resource.is_empty()).then(|| form.resource.clone()),
        scope: (!form.scope.is_empty()).then(|| form.scope.clone()),
    };
    validate_authorize(&state, &params).await?;

    let expected = state.oauth_password.as_deref().ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "OAuth password is not configured".into(),
    ))?;
    if hash(expected) != hash(&form.password) {
        return Err((StatusCode::UNAUTHORIZED, "invalid password".into()));
    }

    let code = random_token("ltc");
    let resource = params
        .resource
        .unwrap_or_else(|| resource_url(&state, &headers));
    let scope = params.scope.unwrap_or_else(|| DEFAULT_SCOPE.into());
    sqlx::query("INSERT INTO oauth_codes(code_hash,client_id,redirect_uri,code_challenge,resource,scope,expires_at,used) VALUES(?,?,?,?,?,?,?,0)")
        .bind(hash(&code))
        .bind(&form.client_id)
        .bind(&form.redirect_uri)
        .bind(&form.code_challenge)
        .bind(resource)
        .bind(scope)
        .bind((Utc::now() + Duration::seconds(CODE_TTL_SECS)).to_rfc3339())
        .execute(&state.db)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut redirect = Url::parse(&form.redirect_uri)
        .map_err(|_| (StatusCode::BAD_REQUEST, "bad redirect_uri".into()))?;
    redirect.query_pairs_mut().append_pair("code", &code);
    if !form.state.is_empty() {
        redirect.query_pairs_mut().append_pair("state", &form.state);
    }
    Ok(Redirect::to(redirect.as_str()))
}

async fn validate_authorize(
    state: &AppState,
    params: &AuthorizeParams,
) -> Result<(), (StatusCode, String)> {
    if params.client_id.is_empty()
        || params.redirect_uri.is_empty()
        || params.code_challenge.is_empty()
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "missing client_id, redirect_uri, or code_challenge".into(),
        ));
    }
    if params.code_challenge_method.as_deref().unwrap_or("S256") != "S256"
        || params.code_challenge.len() < 43
    {
        return Err((StatusCode::BAD_REQUEST, "PKCE S256 is required".into()));
    }

    let client = resolve_client(state, &params.client_id)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if !client.redirect_uris.iter().any(|u| u == &params.redirect_uri) {
        return Err((
            StatusCode::BAD_REQUEST,
            "redirect_uri is not registered".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct TokenForm {
    grant_type: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    client_secret: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    redirect_uri: String,
    #[serde(default)]
    code_verifier: String,
    #[serde(default)]
    refresh_token: String,
    #[serde(default)]
    resource: String,
}

async fn token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Form(mut form): Form<TokenForm>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if let Some((id, secret)) = parse_basic(&headers) {
        form.client_id = id;
        form.client_secret = secret;
    }
    if form.client_id.is_empty() {
        return Err(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "missing client_id",
        ));
    }
    authenticate_client(&state, &form.client_id, &form.client_secret).await?;
    match form.grant_type.as_str() {
        "authorization_code" => exchange_code(&state, form).await,
        "refresh_token" => exchange_refresh(&state, form).await,
        _ => Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "unsupported grant_type",
        )),
    }
}

async fn authenticate_client(
    state: &AppState,
    client_id: &str,
    supplied_secret: &str,
) -> Result<(), (StatusCode, Json<Value>)> {
    let client = resolve_client(state, client_id)
        .await
        .map_err(|e| oauth_error(StatusCode::UNAUTHORIZED, "invalid_client", &e))?;
    if client.auth_method == "none" {
        return Ok(());
    }

    let supplied_hash = hash(supplied_secret);
    if supplied_secret.is_empty() || client.secret_hash.as_deref() != Some(supplied_hash.as_str()) {
        return Err(oauth_error(
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        ));
    }
    Ok(())
}

async fn exchange_code(
    state: &AppState,
    form: TokenForm,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut tx = state.db.begin().await.map_err(internal_oauth)?;
    let row = sqlx::query("SELECT client_id,redirect_uri,code_challenge,resource,scope,expires_at,used FROM oauth_codes WHERE code_hash=?")
        .bind(hash(&form.code))
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal_oauth)?
        .ok_or_else(|| oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "unknown authorization code"))?;

    let used: i64 = row.try_get("used").map_err(internal_oauth)?;
    let expires: String = row.try_get("expires_at").map_err(internal_oauth)?;
    if used != 0 || parse_time(&expires) <= Utc::now() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code expired or used",
        ));
    }
    let client_id: String = row.try_get("client_id").map_err(internal_oauth)?;
    let redirect_uri: String = row.try_get("redirect_uri").map_err(internal_oauth)?;
    let challenge: String = row.try_get("code_challenge").map_err(internal_oauth)?;
    if client_id != form.client_id
        || redirect_uri != form.redirect_uri
        || pkce_challenge(&form.code_verifier) != challenge
    {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "authorization code validation failed",
        ));
    }

    let stored_resource: String = row.try_get("resource").map_err(internal_oauth)?;
    if !form.resource.is_empty() && form.resource != stored_resource {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "resource mismatch",
        ));
    }
    let resource = if form.resource.is_empty() {
        stored_resource.clone()
    } else {
        form.resource.clone()
    };
    let scope: String = row.try_get("scope").map_err(internal_oauth)?;

    sqlx::query("UPDATE oauth_codes SET used=1 WHERE code_hash=?")
        .bind(hash(&form.code))
        .execute(&mut *tx)
        .await
        .map_err(internal_oauth)?;
    let (access, refresh) = issue_tokens(&mut tx, &form.client_id, &resource, &scope).await?;
    tx.commit().await.map_err(internal_oauth)?;
    Ok(Json(token_response(access, refresh, &scope)))
}

async fn exchange_refresh(
    state: &AppState,
    form: TokenForm,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut tx = state.db.begin().await.map_err(internal_oauth)?;
    let row = sqlx::query("SELECT client_id,resource,scope,expires_at,revoked FROM oauth_refresh_tokens WHERE token_hash=?")
        .bind(hash(&form.refresh_token))
        .fetch_optional(&mut *tx)
        .await
        .map_err(internal_oauth)?
        .ok_or_else(|| oauth_error(StatusCode::BAD_REQUEST, "invalid_grant", "unknown refresh token"))?;

    let client_id: String = row.try_get("client_id").map_err(internal_oauth)?;
    let revoked: i64 = row.try_get("revoked").map_err(internal_oauth)?;
    let expires: String = row.try_get("expires_at").map_err(internal_oauth)?;
    if client_id != form.client_id || revoked != 0 || parse_time(&expires) <= Utc::now() {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "refresh token expired, revoked, or belongs to another client",
        ));
    }
    let stored_resource: String = row.try_get("resource").map_err(internal_oauth)?;
    if !form.resource.is_empty() && form.resource != stored_resource {
        return Err(oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_target",
            "resource mismatch",
        ));
    }
    let scope: String = row.try_get("scope").map_err(internal_oauth)?;

    sqlx::query("UPDATE oauth_refresh_tokens SET revoked=1 WHERE token_hash=?")
        .bind(hash(&form.refresh_token))
        .execute(&mut *tx)
        .await
        .map_err(internal_oauth)?;
    let (access, refresh) = issue_tokens(&mut tx, &form.client_id, &stored_resource, &scope).await?;
    tx.commit().await.map_err(internal_oauth)?;
    Ok(Json(token_response(access, refresh, &scope)))
}

async fn issue_tokens(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    client_id: &str,
    resource: &str,
    scope: &str,
) -> Result<(String, String), (StatusCode, Json<Value>)> {
    let now = Utc::now();
    let access = random_token("lta");
    let refresh = random_token("ltr");
    sqlx::query("INSERT INTO oauth_access_tokens(token_hash,client_id,resource,scope,expires_at,revoked,created_at) VALUES(?,?,?,?,?,0,?)")
        .bind(hash(&access))
        .bind(client_id)
        .bind(resource)
        .bind(scope)
        .bind((now + Duration::seconds(ACCESS_TTL_SECS)).to_rfc3339())
        .bind(now.to_rfc3339())
        .execute(&mut **tx)
        .await
        .map_err(internal_oauth)?;
    sqlx::query("INSERT INTO oauth_refresh_tokens(token_hash,client_id,resource,scope,expires_at,revoked) VALUES(?,?,?,?,?,0)")
        .bind(hash(&refresh))
        .bind(client_id)
        .bind(resource)
        .bind(scope)
        .bind((now + Duration::seconds(REFRESH_TTL_SECS)).to_rfc3339())
        .execute(&mut **tx)
        .await
        .map_err(internal_oauth)?;
    Ok((access, refresh))
}

fn token_response(access: String, refresh: String, scope: &str) -> Value {
    json!({
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": ACCESS_TTL_SECS,
        "refresh_token": refresh,
        "scope": scope
    })
}

pub async fn require_mcp_auth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let origin = issuer(&state, &headers);
    let root_resource = request.uri().path() == "/";
    let resource = if root_resource {
        format!("{origin}/")
    } else {
        format!("{origin}/mcp")
    };
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let valid = match token {
        Some(token) => validate_access_token(&state, token, &resource).await,
        None => false,
    };

    if !valid {
        let metadata = if root_resource {
            format!("{origin}/.well-known/oauth-protected-resource")
        } else {
            format!("{origin}/.well-known/oauth-protected-resource/mcp")
        };
        return (
            StatusCode::UNAUTHORIZED,
            [(
                header::WWW_AUTHENTICATE,
                format!(
                    "Bearer realm=\"lazyteam\", resource_metadata=\"{metadata}\", scope=\"{DEFAULT_SCOPE}\""
                ),
            )],
            "unauthorized",
        )
            .into_response();
    }
    next.run(request).await
}

async fn validate_access_token(state: &AppState, token: &str, resource: &str) -> bool {
    let row = sqlx::query("SELECT resource,expires_at,revoked FROM oauth_access_tokens WHERE token_hash=?")
        .bind(hash(token))
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();
    let Some(row) = row else {
        return false;
    };
    let Ok(stored_resource): Result<String, _> = row.try_get("resource") else {
        return false;
    };
    let Ok(expires): Result<String, _> = row.try_get("expires_at") else {
        return false;
    };
    let Ok(revoked): Result<i64, _> = row.try_get("revoked") else {
        return false;
    };
    revoked == 0 && stored_resource == resource && parse_time(&expires) > Utc::now()
}

fn parse_basic(headers: &HeaderMap) -> Option<(String, String)> {
    let value = headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Basic ")?;
    let decoded = String::from_utf8(STANDARD.decode(value).ok()?).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

fn random_token(prefix: &str) -> String {
    format!(
        "{prefix}_{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    )
}

fn hash(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}

fn pkce_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn parse_time(raw: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(raw)
        .map(|v| v.with_timezone(&Utc))
        .unwrap_or(DateTime::<Utc>::MIN_UTC)
}

fn esc(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn oauth_error(
    status: StatusCode,
    code: &str,
    description: &str,
) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({"error": code, "error_description": description})),
    )
}

fn internal_oauth(error: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    oauth_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "server_error",
        &error.to_string(),
    )
}
