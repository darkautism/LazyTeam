use std::time::Duration;

use reqwest::{header::ACCEPT, redirect::Policy};
use serde::Deserialize;
use url::Url;

const MAX_BODY: usize = 1 << 20;
const MAX_REDIRECTS: usize = 8;

#[derive(Debug, Clone)]
pub(crate) struct CimdClient {
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: String,
}

#[derive(Debug, Deserialize)]
struct ClientMetadataDocument {
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    redirect_uris: Vec<String>,
    #[serde(default)]
    token_endpoint_auth_method: String,
    #[serde(default)]
    token_endpoint_auth_methods_supported: Vec<String>,
}

pub(crate) fn is_cimd_client_id(client_id: &str) -> bool {
    if client_id.is_empty() || client_id.len() > 2048 {
        return false;
    }
    let Ok(url) = Url::parse(client_id) else {
        return false;
    };
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

pub(crate) async fn resolve(client_id: &str) -> Result<CimdClient, String> {
    if !is_cimd_client_id(client_id) {
        return Err("client_id is not an HTTPS metadata document URL".into());
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(Policy::custom(|attempt| {
            if attempt.previous().len() >= MAX_REDIRECTS {
                attempt.error("too many CIMD redirects")
            } else if attempt.url().scheme() != "https" {
                attempt.error("CIMD redirects must stay on HTTPS")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|e| format!("build CIMD client: {e}"))?;

    let mut response = client
        .get(client_id)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| format!("fetch CIMD: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("fetch CIMD: HTTP {}", response.status()));
    }
    if response.content_length().is_some_and(|n| n > MAX_BODY as u64) {
        return Err("CIMD document exceeds size limit".into());
    }

    let mut raw = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| format!("read CIMD: {e}"))? {
        if raw.len() + chunk.len() > MAX_BODY {
            return Err("CIMD document exceeds size limit".into());
        }
        raw.extend_from_slice(&chunk);
    }
    let doc: ClientMetadataDocument = serde_json::from_slice(&raw)
        .map_err(|e| format!("parse CIMD: {e}"))?;
    if !doc.client_id.is_empty() && doc.client_id != client_id {
        return Err("CIMD client_id mismatch".into());
    }
    if doc.redirect_uris.is_empty() || doc.redirect_uris.iter().any(|uri| !valid_redirect_uri(uri)) {
        return Err("CIMD contains invalid redirect_uris".into());
    }

    let mut method = doc.token_endpoint_auth_method.trim().to_string();
    if method.is_empty() && doc.token_endpoint_auth_methods_supported.iter().any(|m| m == "none") {
        method = "none".into();
    }
    if method.is_empty() {
        method = "none".into();
    }
    if method != "none" {
        if doc.token_endpoint_auth_methods_supported.iter().any(|m| m == "none") {
            method = "none".into();
        } else {
            return Err(format!("unsupported CIMD token_endpoint_auth_method {method:?}"));
        }
    }

    Ok(CimdClient {
        redirect_uris: doc.redirect_uris,
        token_endpoint_auth_method: method,
    })
}

fn valid_redirect_uri(raw: &str) -> bool {
    let Ok(url) = Url::parse(raw) else {
        return false;
    };
    match url.scheme() {
        "https" => url.host_str().is_some() && url.username().is_empty() && url.password().is_none(),
        "http" => matches!(url.host_str(), Some("127.0.0.1") | Some("localhost") | Some("::1")),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_urls_are_cimd_ids() {
        assert!(is_cimd_client_id("https://chatgpt.com/client-metadata.json"));
        assert!(!is_cimd_client_id("http://chatgpt.com/client-metadata.json"));
        assert!(!is_cimd_client_id("opaque-client-id"));
        assert!(!is_cimd_client_id("https://user@example.com/client.json"));
    }
}
