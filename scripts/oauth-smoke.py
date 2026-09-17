#!/usr/bin/env python3
import base64
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

BASE = os.environ.get("LAZYTEAM_SMOKE_URL", "http://127.0.0.1:8787")
PASSWORD = os.environ.get("LAZYTEAM_OAUTH_PASSWORD", "smoke-secret")
REDIRECT = "http://127.0.0.1:9911/callback"
MCP_VERSION = "2026-07-28"


def request(path, *, method="GET", data=None, headers=None, follow=True):
    body = None
    h = dict(headers or {})
    if data is not None:
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        else:
            body = data
    req = urllib.request.Request(BASE + path, data=body, headers=h, method=method)
    opener = urllib.request.build_opener() if follow else urllib.request.build_opener(NoRedirect())
    try:
        return opener.open(req, timeout=5)
    except urllib.error.HTTPError as exc:
        return exc


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def read_json(resp):
    return json.loads(resp.read().decode())


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def mcp_call(token, method, params=None):
    body = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params or {},
    }).encode()
    return request("/mcp", method="POST", data=body, headers={
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": MCP_VERSION,
        "Mcp-Method": method,
    })


def main():
    health = request("/health")
    expect(health.status == 200 and health.read() == b"ok", "health endpoint failed")

    prm = read_json(request("/.well-known/oauth-protected-resource/mcp"))
    expect(prm["resource"] == BASE + "/mcp", "protected resource URL mismatch")
    expect(prm["authorization_servers"] == [BASE], "authorization server mismatch")

    meta = read_json(request("/.well-known/oauth-authorization-server"))
    expect(meta["issuer"] == BASE, "issuer mismatch")
    expect(meta["registration_endpoint"] == BASE + "/mcp/oauth/register", "DCR endpoint mismatch")
    expect("S256" in meta["code_challenge_methods_supported"], "S256 not advertised")
    expect("refresh_token" in meta["grant_types_supported"], "refresh token not advertised")
    expect(meta.get("client_id_metadata_document_supported") is True, "CIMD support not advertised")

    registration = json.dumps({
        "redirect_uris": [REDIRECT],
        "client_name": "LazyTeam CI",
        "token_endpoint_auth_method": "none",
    }).encode()
    reg = request("/mcp/oauth/register", method="POST", data=registration, headers={"Content-Type": "application/json"})
    expect(reg.status == 201, f"DCR failed with HTTP {reg.status}")
    client = read_json(reg)
    client_id = client["client_id"]

    verifier = "lazyteam-ci-pkce-verifier-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    authorize_query = urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scope": "lazyteam",
        "resource": BASE + "/mcp",
        "state": "ci-state",
    })
    form = request("/mcp/oauth/authorize?" + authorize_query)
    expect(form.status == 200, "authorize GET failed")
    form.read()

    auth = request("/mcp/oauth/authorize", method="POST", data={
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "scope": "lazyteam",
        "resource": BASE + "/mcp",
        "state": "ci-state",
        "password": PASSWORD,
    }, follow=False)
    expect(auth.status in (302, 303), f"authorize POST did not redirect: {auth.status}")
    location = auth.headers["Location"]
    query = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
    expect(query.get("state") == ["ci-state"], "OAuth state was not preserved")
    code = query["code"][0]

    token_resp = request("/mcp/oauth/token", method="POST", data={
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": REDIRECT,
        "code_verifier": verifier,
        "resource": BASE + "/mcp",
    })
    expect(token_resp.status == 200, f"token exchange failed with HTTP {token_resp.status}")
    tokens = read_json(token_resp)
    expect(tokens["token_type"] == "Bearer", "wrong token type")
    expect(tokens.get("refresh_token"), "refresh token missing")

    discover = mcp_call(tokens["access_token"], "server/discover", {
        "_meta": {
            "io.modelcontextprotocol/protocolVersion": MCP_VERSION,
            "io.modelcontextprotocol/clientInfo": {"name": "lazyteam-smoke", "version": "1.0"},
            "io.modelcontextprotocol/clientCapabilities": {},
        }
    })
    expect(discover.status == 200, f"authenticated server/discover failed with HTTP {discover.status}")
    discovered = read_json(discover)
    expect("tools" in discovered.get("result", {}).get("capabilities", {}), "server/discover did not advertise tools")
    expect(MCP_VERSION in discovered.get("result", {}).get("supportedVersions", []), "server/discover omitted requested protocol version")

    tools = mcp_call(tokens["access_token"], "tools/list", {
        "_meta": {"io.modelcontextprotocol/protocolVersion": MCP_VERSION}
    })
    expect(tools.status == 200, f"authenticated tools/list failed with HTTP {tools.status}")
    tool_result = read_json(tools)
    names = {tool.get("name") for tool in tool_result.get("result", {}).get("tools", [])}
    required_tools = {"projects_list", "projects_create", "tasks_list", "tasks_create", "tasks_approve", "tasks_retry", "workers_list"}
    expect(required_tools.issubset(names), f"tools/list missing tools: {sorted(required_tools - names)}")

    refresh_resp = request("/mcp/oauth/token", method="POST", data={
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": tokens["refresh_token"],
        "resource": BASE + "/mcp",
    })
    expect(refresh_resp.status == 200, f"refresh failed with HTTP {refresh_resp.status}")
    refreshed = read_json(refresh_resp)
    expect(refreshed.get("access_token"), "refreshed access token missing")
    expect(refreshed.get("refresh_token") != tokens["refresh_token"], "refresh token did not rotate")

    unauthorized = request("/mcp", method="POST", data=b"{}", headers={"Content-Type": "application/json"})
    expect(unauthorized.status == 401, f"MCP without bearer should be 401, got {unauthorized.status}")
    www = unauthorized.headers.get("WWW-Authenticate", "")
    expect("resource_metadata=" in www, "WWW-Authenticate lacks resource_metadata")

    print("OAuth + MCP smoke test passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"OAuth + MCP smoke test failed: {exc}", file=sys.stderr)
        raise
