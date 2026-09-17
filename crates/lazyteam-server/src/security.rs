use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::{header, HeaderName, HeaderValue, Method, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};
use tokio::net::lookup_host;
use url::Url;

pub const MAX_REQUEST_BODY: usize = 1024 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const RATE_WINDOW: Duration = Duration::from_secs(60);

#[derive(Clone, Debug)]
pub(crate) struct SecurityConfig {
    pub production: bool,
    pub admin_token: Option<String>,
    pub worker_token: Option<String>,
    pub allowed_oauth_client_hosts: Vec<String>,
    pub allowed_redirect_hosts: Vec<String>,
}

static CONFIG: OnceLock<SecurityConfig> = OnceLock::new();
static RATE: OnceLock<Mutex<HashMap<&'static str, VecDeque<Instant>>>> = OnceLock::new();

pub(crate) fn init(config: SecurityConfig) -> anyhow::Result<()> {
    CONFIG
        .set(config)
        .map_err(|_| anyhow::anyhow!("security configuration already initialized"))
}

fn config() -> &'static SecurityConfig {
    CONFIG.get().expect("security configuration must be initialized")
}

pub(crate) fn production() -> bool {
    config().production
}

pub(crate) fn client_host_allowed(host: &str) -> bool {
    host_allowed(host, &config().allowed_oauth_client_hosts)
}

pub(crate) fn redirect_uri_allowed(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return false;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    match url.scheme() {
        "https" => host_allowed(host, &config().allowed_redirect_hosts),
        "http" if !production() => {
            matches!(host, "127.0.0.1" | "localhost" | "::1")
                && (config().allowed_redirect_hosts.is_empty()
                    || host_allowed(host, &config().allowed_redirect_hosts))
        }
        _ => false,
    }
}

pub(crate) fn cimd_url_allowed(url: &Url) -> bool {
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.host_str().is_some_and(client_host_allowed)
}

pub(crate) async fn resolve_public_endpoint(url: &Url) -> Result<SocketAddr, String> {
    if !cimd_url_allowed(url) {
        return Err("CIMD URL is not allowed by policy".into());
    }
    let host = url.host_str().ok_or_else(|| "CIMD URL has no host".to_string())?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "CIMD URL has no usable port".to_string())?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        if !is_public_ip(ip) {
            return Err("CIMD address is not public".into());
        }
        return Ok(SocketAddr::new(ip, port));
    }

    let addrs = lookup_host((host, port))
        .await
        .map_err(|e| format!("resolve CIMD host: {e}"))?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        return Err("CIMD host resolved to no addresses".into());
    }
    if addrs.iter().any(|addr| !is_public_ip(addr.ip())) {
        return Err("CIMD host resolved to a private or special-use address".into());
    }
    Ok(addrs[0])
}

pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_v4(ip),
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return is_public_v4(v4);
            }
            is_public_v6(ip)
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _d] = ip.octets();
    !(
        a == 0
            || a == 10
            || a == 127
            || (a == 100 && (64..=127).contains(&b))
            || (a == 169 && b == 254)
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 168)
            || (a == 192 && b == 0 && c == 0)
            || (a == 192 && b == 0 && c == 2)
            || (a == 198 && (b == 18 || b == 19))
            || (a == 198 && b == 51 && c == 100)
            || (a == 203 && b == 0 && c == 113)
            || a >= 224
    )
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let s = ip.segments();
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }
    if (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return false;
    }
    // Only global-unicast 2000::/3 is accepted for outbound CIMD fetches.
    (s[0] & 0xe000) == 0x2000
}

fn host_allowed(host: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return !production();
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    allowed.iter().any(|pattern| {
        let pattern = pattern.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(suffix) = pattern.strip_prefix("*.") {
            host != suffix && host.ends_with(&format!(".{suffix}"))
        } else {
            host == pattern
        }
    })
}

pub(crate) async fn middleware(mut request: Request, next: Next) -> Response {
    if let Err(response) = rate_limit_for(&request) {
        return response;
    }

    match guard_oauth_domains(request).await {
        Ok(req) => request = req,
        Err(response) => return response,
    }

    let path = request.uri().path();
    if path == "/" && production() {
        if !bearer_matches(&request, config().admin_token.as_deref()) {
            return unauthorized("admin");
        }
    } else if path.starts_with("/api/") {
        if path == "/api/workers/register" {
            // The shared worker secret is an enrollment credential only. Normal worker
            // traffic is authenticated by the per-worker credential issued at enrollment.
            if production() && !bearer_matches(&request, config().worker_token.as_deref()) {
                return unauthorized("worker-enrollment");
            }
        } else if (path.starts_with("/api/workers/") && path != "/api/workers")
            || path.starts_with("/api/executions/")
        {
            // Per-worker authentication and execution ownership are enforced in the
            // endpoint handlers where the worker/execution ID is available.
        } else if production() && !bearer_matches(&request, config().admin_token.as_deref()) {
            return unauthorized("admin");
        }
    }

    let mut response = match tokio::time::timeout(REQUEST_TIMEOUT, next.run(request)).await {
        Ok(response) => response,
        Err(_) => (StatusCode::REQUEST_TIMEOUT, "request timed out").into_response(),
    };
    add_security_headers(&mut response);
    response
}

async fn guard_oauth_domains(request: Request) -> Result<Request, Response> {
    let path = request.uri().path().to_string();
    if path != "/mcp/oauth/register" && path != "/mcp/oauth/authorize" {
        return Ok(request);
    }
    if !production()
        && config().allowed_oauth_client_hosts.is_empty()
        && config().allowed_redirect_hosts.is_empty()
    {
        return Ok(request);
    }

    if request.method() == Method::GET && path == "/mcp/oauth/authorize" {
        let pairs = request
            .uri()
            .query()
            .map(|q| url::form_urlencoded::parse(q.as_bytes()).into_owned().collect::<HashMap<_, _>>())
            .unwrap_or_default();
        validate_oauth_pairs(&pairs)?;
        return Ok(request);
    }

    if request.method() != Method::POST {
        return Ok(request);
    }

    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, MAX_REQUEST_BODY)
        .await
        .map_err(|_| (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response())?;

    if path == "/mcp/oauth/register" {
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| (StatusCode::BAD_REQUEST, "invalid registration JSON").into_response())?;
        let redirects = value
            .get("redirect_uris")
            .and_then(|v| v.as_array())
            .ok_or_else(|| (StatusCode::BAD_REQUEST, "redirect_uris required").into_response())?;
        if redirects.is_empty()
            || redirects
                .iter()
                .any(|v| v.as_str().is_none_or(|uri| !redirect_uri_allowed(uri)))
        {
            return Err((StatusCode::FORBIDDEN, "OAuth redirect host is not allowed").into_response());
        }
    } else {
        let pairs = url::form_urlencoded::parse(&bytes)
            .into_owned()
            .collect::<HashMap<_, _>>();
        validate_oauth_pairs(&pairs)?;
    }

    Ok(Request::from_parts(parts, Body::from(bytes)))
}

fn validate_oauth_pairs(pairs: &HashMap<String, String>) -> Result<(), Response> {
    let client_id = pairs
        .get("client_id")
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "client_id required").into_response())?;
    if let Ok(url) = Url::parse(client_id) {
        let allowed = url.scheme() == "https"
            && url.host_str().is_some_and(client_host_allowed)
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none();
        if !allowed {
            return Err((StatusCode::FORBIDDEN, "OAuth client host is not allowed").into_response());
        }
    }
    let redirect = pairs
        .get("redirect_uri")
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "redirect_uri required").into_response())?;
    if !redirect_uri_allowed(redirect) {
        return Err((StatusCode::FORBIDDEN, "OAuth redirect host is not allowed").into_response());
    }
    Ok(())
}

fn rate_limit_for(request: &Request) -> Result<(), Response> {
    let path = request.uri().path();
    let (bucket, limit) = if path == "/mcp/oauth/register" {
        ("oauth-register", 60)
    } else if path == "/mcp/oauth/authorize" {
        ("oauth-authorize", 30)
    } else if path == "/mcp/oauth/token" {
        ("oauth-token", 120)
    } else if path == "/api/workers/register" {
        ("worker-register", 60)
    } else if path.ends_with("/claim") && path.starts_with("/api/workers/") {
        ("worker-claim", 600)
    } else {
        return Ok(());
    };

    let now = Instant::now();
    let map = RATE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = map.lock().expect("rate limiter mutex poisoned");
    let hits = map.entry(bucket).or_default();
    while hits.front().is_some_and(|old| now.duration_since(*old) >= RATE_WINDOW) {
        hits.pop_front();
    }
    if hits.len() >= limit {
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response());
    }
    hits.push_back(now);
    Ok(())
}

fn bearer_matches(request: &Request, expected: Option<&str>) -> bool {
    let Some(expected) = expected else {
        return false;
    };
    let supplied = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    supplied.is_some_and(|value| secure_eq(value, expected))
}

fn secure_eq(a: &str, b: &str) -> bool {
    let a = Sha256::digest(a.as_bytes());
    let b = Sha256::digest(b.as_bytes());
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn unauthorized(realm: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, format!("Bearer realm=\"lazyteam-{realm}\""))],
        "unauthorized",
    )
        .into_response()
}

fn add_security_headers(response: &mut Response) {
    let headers = response.headers_mut();
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'"),
    );
    if production() {
        headers.insert(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_private_and_special_ipv4() {
        for raw in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "100.64.0.1",
            "198.18.0.1",
            "224.0.0.1",
        ] {
            assert!(!is_public_ip(raw.parse().unwrap()), "{raw} must be rejected");
        }
        assert!(is_public_ip("1.1.1.1".parse().unwrap()));
    }

    #[test]
    fn rejects_private_and_special_ipv6() {
        for raw in ["::1", "::", "fc00::1", "fd00::1", "fe80::1", "ff02::1", "2001:db8::1"] {
            assert!(!is_public_ip(raw.parse().unwrap()), "{raw} must be rejected");
        }
        assert!(is_public_ip("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn wildcard_hosts_do_not_match_apex() {
        assert!(host_allowed("a.chatgpt.com", &["*.chatgpt.com".into()]));
        assert!(!host_allowed("chatgpt.com", &["*.chatgpt.com".into()]));
        assert!(!host_allowed("evilchatgpt.com", &["*.chatgpt.com".into()]));
    }
}
