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
MCP_LEGACY_VERSION = "2025-11-25"
MCP_MODERN_VERSION = "2026-07-28"


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
    raw = resp.read().decode()
    if "text/event-stream" in resp.headers.get("Content-Type", ""):
        data_lines = [line[5:].lstrip() for line in raw.splitlines() if line.startswith("data:")]
        expect(data_lines, "SSE response contained no data event")
        raw = data_lines[-1]
    return json.loads(raw)


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def mcp_meta(version=MCP_MODERN_VERSION):
    return {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": {"name": "lazyteam-smoke", "version": "1.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def mcp_call(
    token,
    method,
    params=None,
    path="/mcp",
    *,
    version=MCP_MODERN_VERSION,
    session_id=None,
    request_id=1,
    notification=False,
):
    message = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params or {},
    }
    if not notification:
        message["id"] = request_id
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": version,
        "Mcp-Method": method,
    }
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    return request(path, method="POST", data=json.dumps(message).encode(), headers=headers)


EXPECTED_TOOL_ANNOTATIONS = {
    "projects_list": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    "projects_create": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    "tasks_list": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    "tasks_create": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    "reviews_get": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
    "tasks_approve": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
    "tasks_merge": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": True},
    "tasks_retry": {"readOnlyHint": False, "destructiveHint": False, "openWorldHint": False},
    "tasks_delete": {"readOnlyHint": False, "destructiveHint": True, "openWorldHint": False},
    "workers_list": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False},
}


def validate_tool_schemas(tools):
    for tool in tools:
        name = tool.get("name", "<unnamed>")
        schema = tool.get("inputSchema")
        expect(isinstance(schema, dict), f"{name} inputSchema is not an object")
        expect(schema.get("type") == "object", f"{name} inputSchema type is not object")
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        expect(isinstance(properties, dict), f"{name} inputSchema properties is not an object")
        expect(isinstance(required, list), f"{name} inputSchema required is not an array")
        expect(all(isinstance(item, str) for item in required), f"{name} inputSchema required contains non-strings")
        expect(set(required).issubset(properties), f"{name} inputSchema requires unknown properties")
        expect(isinstance(tool.get("title"), str) and tool["title"], f"{name} title is missing")
        annotations = tool.get("annotations")
        expect(isinstance(annotations, dict), f"{name} annotations are missing")
        expected = EXPECTED_TOOL_ANNOTATIONS.get(name)
        expect(expected is not None, f"{name} has no expected annotation contract")
        for key, value in expected.items():
            expect(annotations.get(key) is value, f"{name} {key} mismatch: {annotations.get(key)!r}")
        json.dumps(schema)


def main():
    health = request("/health")
    expect(health.status == 200 and health.read() == b"ok", "health endpoint failed")

    root_prm = read_json(request("/.well-known/oauth-protected-resource"))
    expect(root_prm["resource"] == BASE + "/", "root protected resource URL mismatch")
    expect(root_prm["authorization_servers"] == [BASE], "root authorization server mismatch")

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

    required_tools = {"projects_list", "projects_create", "tasks_list", "tasks_create", "reviews_get", "tasks_approve", "tasks_merge", "tasks_retry", "workers_list"}

    legacy_initialize = mcp_call(tokens["access_token"], "initialize", {
        "protocolVersion": MCP_LEGACY_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "lazyteam-smoke-legacy", "version": "1.0"},
    }, version=MCP_LEGACY_VERSION, request_id=1)
    expect(legacy_initialize.status == 200, f"legacy initialize failed with HTTP {legacy_initialize.status}")
    legacy_session_id = legacy_initialize.headers.get("Mcp-Session-Id")
    expect(legacy_session_id, "legacy initialize did not return Mcp-Session-Id")
    legacy_initialized_body = read_json(legacy_initialize)
    legacy_result = legacy_initialized_body.get("result", {})
    expect(legacy_result.get("protocolVersion") == MCP_LEGACY_VERSION, "legacy initialize negotiated wrong protocolVersion")
    expect("capabilities" in legacy_result, "legacy initialize omitted capabilities")
    expect("serverInfo" in legacy_result, "legacy initialize omitted serverInfo")

    legacy_initialized = mcp_call(
        tokens["access_token"],
        "notifications/initialized",
        version=MCP_LEGACY_VERSION,
        session_id=legacy_session_id,
        notification=True,
    )
    expect(legacy_initialized.status == 202, f"legacy initialized notification failed with HTTP {legacy_initialized.status}")
    legacy_initialized.read()

    legacy_tools_resp = mcp_call(
        tokens["access_token"],
        "tools/list",
        version=MCP_LEGACY_VERSION,
        session_id=legacy_session_id,
        request_id=2,
    )
    expect(legacy_tools_resp.status == 200, f"legacy tools/list failed with HTTP {legacy_tools_resp.status}")
    legacy_tool_result = read_json(legacy_tools_resp)
    legacy_tools = legacy_tool_result.get("result", {}).get("tools", [])
    legacy_names = {tool.get("name") for tool in legacy_tools}
    expect(required_tools.issubset(legacy_names), f"legacy tools/list missing tools: {sorted(required_tools - legacy_names)}")
    validate_tool_schemas(legacy_tools)

    legacy_call = mcp_call(
        tokens["access_token"],
        "tools/call",
        {"name": "projects_list", "arguments": {}},
        version=MCP_LEGACY_VERSION,
        session_id=legacy_session_id,
        request_id=3,
    )
    expect(legacy_call.status == 200, f"legacy tools/call projects_list failed with HTTP {legacy_call.status}")
    legacy_call_result = read_json(legacy_call).get("result", {})
    expect(legacy_call_result.get("isError") is not True, "legacy projects_list returned MCP error result")
    expect(isinstance(legacy_call_result.get("content"), list), "legacy projects_list result omitted content")

    discover = mcp_call(tokens["access_token"], "server/discover", {"_meta": mcp_meta()})
    expect(discover.status == 200, f"authenticated server/discover failed with HTTP {discover.status}")
    discovered = read_json(discover)
    expect("tools" in discovered.get("result", {}).get("capabilities", {}), "server/discover did not advertise tools")
    expect(MCP_MODERN_VERSION in discovered.get("result", {}).get("supportedVersions", []), "server/discover omitted requested protocol version")

    tools = mcp_call(tokens["access_token"], "tools/list", {"_meta": mcp_meta()})
    expect(tools.status == 200, f"authenticated tools/list failed with HTTP {tools.status}")
    tool_result = read_json(tools)
    modern_tools = tool_result.get("result", {}).get("tools", [])
    names = {tool.get("name") for tool in modern_tools}
    expect(required_tools.issubset(names), f"tools/list missing tools: {sorted(required_tools - names)}")
    validate_tool_schemas(modern_tools)

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


    root_verifier = "lazyteam-root-pkce-verifier-0123456789-ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    root_challenge = base64.urlsafe_b64encode(hashlib.sha256(root_verifier.encode()).digest()).rstrip(b"=").decode()
    root_auth = request("/mcp/oauth/authorize", method="POST", data={
        "client_id": client_id,
        "redirect_uri": REDIRECT,
        "code_challenge": root_challenge,
        "code_challenge_method": "S256",
        "scope": "lazyteam",
        "resource": BASE + "/",
        "state": "root-state",
        "password": PASSWORD,
    }, follow=False)
    expect(root_auth.status in (302, 303), f"root authorize POST did not redirect: {root_auth.status}")
    root_location = root_auth.headers["Location"]
    root_query = urllib.parse.parse_qs(urllib.parse.urlparse(root_location).query)
    expect(root_query.get("state") == ["root-state"], "root OAuth state was not preserved")
    root_code = root_query["code"][0]

    root_token_resp = request("/mcp/oauth/token", method="POST", data={
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": root_code,
        "redirect_uri": REDIRECT,
        "code_verifier": root_verifier,
        "resource": BASE + "/",
    })
    expect(root_token_resp.status == 200, f"root token exchange failed with HTTP {root_token_resp.status}")
    root_tokens = read_json(root_token_resp)
    root_tools = mcp_call(root_tokens["access_token"], "tools/list", {"_meta": mcp_meta()}, path="/")
    expect(root_tools.status == 200, f"authenticated root tools/list failed with HTTP {root_tools.status}")

    unauthorized = request("/mcp", method="POST", data=b"{}", headers={"Content-Type": "application/json"})
    expect(unauthorized.status == 401, f"MCP without bearer should be 401, got {unauthorized.status}")
    www = unauthorized.headers.get("WWW-Authenticate", "")
    expect("resource_metadata=" in www, "WWW-Authenticate lacks resource_metadata")
    expect("/.well-known/oauth-protected-resource/mcp" in www, "MCP challenge points to wrong metadata")

    root_unauthorized = request("/", method="POST", data=b"{}", headers={"Content-Type": "application/json"})
    expect(root_unauthorized.status == 401, f"root MCP without bearer should be 401, got {root_unauthorized.status}")
    root_www = root_unauthorized.headers.get("WWW-Authenticate", "")
    expect("resource_metadata=" in root_www, "root WWW-Authenticate lacks resource_metadata")
    expect("/.well-known/oauth-protected-resource" in root_www, "root challenge points to wrong metadata")
    expect("/.well-known/oauth-protected-resource/mcp" not in root_www, "root challenge leaked MCP-path metadata")

    print("OAuth + MCP smoke test passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"OAuth + MCP smoke test failed: {exc}", file=sys.stderr)
        raise
