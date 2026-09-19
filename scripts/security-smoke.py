#!/usr/bin/env python3
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = os.environ.get("LAZYTEAM_SECURITY_SMOKE_URL", "http://127.0.0.1:8788")
ADMIN = os.environ.get("LAZYTEAM_ADMIN_TOKEN", "admin-security-smoke-token-0123456789abcdef")
WORKER = os.environ.get("LAZYTEAM_WORKER_TOKEN", "worker-security-smoke-token-0123456789abcdef")
PUBLIC = os.environ.get("LAZYTEAM_PUBLIC_URL", "https://lazyteam.example.test").rstrip("/")
WORKER_CREDENTIAL_HEADER = "X-LazyTeam-Worker-Credential"
LEASE_CAPABILITY_HEADER = "X-LazyTeam-Lease-Capability"


def request(path, *, method="GET", obj=None, data=None, token=None, headers=None):
    body = data
    h = dict(headers or {})
    if obj is not None:
        body = json.dumps(obj).encode()
        h["Content-Type"] = "application/json"
    if token:
        h["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE + path, data=body, headers=h, method=method)
    try:
        return urllib.request.urlopen(req, timeout=5)
    except urllib.error.HTTPError as exc:
        return exc


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def read_json(resp):
    raw = resp.read()
    return json.loads(raw.decode()) if raw else None


def project_payload(slug, repo_url):
    return {
        "slug": slug,
        "name": "Security Smoke",
        "repo_url": repo_url,
        "default_branch": "main",
    }


def create_local_upstream():
    root = pathlib.Path(tempfile.mkdtemp(prefix="lazyteam-security-upstream-"))
    work = root / "work"
    bare = root / "upstream.git"
    subprocess.run(["git", "init", "-b", "main", str(work)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(work), "config", "user.name", "Security Smoke"], check=True)
    subprocess.run(["git", "-C", str(work), "config", "user.email", "security-smoke@example.invalid"], check=True)
    (work / "README.md").write_text("security smoke\n")
    subprocess.run(["git", "-C", str(work), "add", "README.md"], check=True)
    subprocess.run(["git", "-C", str(work), "commit", "-m", "security smoke base"], check=True, capture_output=True)
    subprocess.run(["git", "clone", "--bare", str(work), str(bare)], check=True, capture_output=True)
    return bare.as_uri()


def worker_payload(worker_id, name="security-smoke-worker"):
    return {
        "id": worker_id,
        "name": name,
        "os": "linux",
        "arch": "x86_64",
        "tags": {"rust": "true"},
        "allowed_projects": ["*"],
        "slots": 1,
        "worker_version": "security-smoke",
        "protocol_version": 6,
    }


def register_worker(worker_id, name):
    response = request(
        "/api/workers/register",
        method="POST",
        obj=worker_payload(worker_id, name),
        token=WORKER,
    )
    expect(response.status == 200, f"worker registration failed: HTTP {response.status}")
    credential = response.headers.get(WORKER_CREDENTIAL_HEADER)
    expect(bool(credential), "worker registration did not issue a worker credential")
    response.read()
    return credential


def worker_headers(credential):
    return {WORKER_CREDENTIAL_HEADER: credential}


def lease_headers(headers, capability):
    return {**headers, LEASE_CAPABILITY_HEADER: capability}


def main():
    health = request("/health")
    expect(health.status == 200 and health.read() == b"ok", "health failed")
    expect(health.headers.get("X-Content-Type-Options") == "nosniff", "nosniff missing")
    expect(health.headers.get("Strict-Transport-Security"), "HSTS missing in production")

    root_mcp = request("/", method="POST", data=b"{}", headers={"Content-Type": "application/json"})
    expect(root_mcp.status == 401, f"production root MCP should challenge with OAuth, got {root_mcp.status}")
    root_www = root_mcp.headers.get("WWW-Authenticate", "")
    expect("resource_metadata=" in root_www, "production root MCP did not expose OAuth resource metadata")
    expect("lazyteam-admin" not in root_www, "production root MCP was intercepted by admin auth")

    slug = "security-" + uuid.uuid4().hex[:8]
    upstream_repo = create_local_upstream()

    anonymous_admin = request("/api/projects", method="POST", obj=project_payload(slug, upstream_repo))
    expect(anonymous_admin.status == 401, f"anonymous admin API should be 401, got {anonymous_admin.status}")

    worker_on_admin = request("/api/projects", method="POST", obj=project_payload(slug, upstream_repo), token=WORKER)
    expect(worker_on_admin.status == 401, f"worker enrollment token reached admin API: {worker_on_admin.status}")

    admin_create = request("/api/projects", method="POST", obj=project_payload(slug, upstream_repo), token=ADMIN)
    expect(admin_create.status == 200, f"admin token could not create project: HTTP {admin_create.status}")
    project = read_json(admin_create)

    anonymous_join = request("/api/worker-join", method="POST", obj={})
    expect(anonymous_join.status == 401, "anonymous client could issue a worker join code")
    worker_join = request("/api/worker-join", method="POST", obj={}, token=WORKER)
    expect(worker_join.status == 401, "worker enrollment secret could issue a worker join code")
    join_response = request("/api/worker-join", method="POST", obj={}, token=ADMIN)
    expect(join_response.status == 200, f"admin could not issue worker join code: HTTP {join_response.status}")
    join = read_json(join_response)
    join_code = join.get("join_code", "")
    expect(join_code.startswith("ltj1."), "worker join code has wrong format")
    expect(join.get("server") == PUBLIC, f"worker join code embedded wrong server: {join.get('server')}")
    expect(bool(join.get("expires_at")), "worker join code omitted expiry")

    join_worker_id = str(uuid.uuid4())
    joined = request(
        "/api/workers/register",
        method="POST",
        obj=worker_payload(join_worker_id, "join-code-worker"),
        token=join_code,
    )
    expect(joined.status == 200, f"worker join-code enrollment failed: HTTP {joined.status}")
    expect(bool(joined.headers.get(WORKER_CREDENTIAL_HEADER)), "join-code enrollment did not issue worker credential")
    joined.read()

    tampered = join_code[:-1] + ("A" if join_code[-1] != "A" else "B")
    rejected_tampered = request(
        "/api/workers/register",
        method="POST",
        obj=worker_payload(str(uuid.uuid4()), "tampered-join-worker"),
        token=tampered,
    )
    expect(rejected_tampered.status == 401, "tampered worker join code was accepted")

    anonymous_tasks = request("/api/tasks")
    expect(anonymous_tasks.status == 401, "anonymous task listing was not rejected")
    worker_tasks = request("/api/tasks", token=WORKER)
    expect(worker_tasks.status == 401, "worker enrollment token reached task listing")
    admin_tasks = request("/api/tasks", token=ADMIN)
    expect(admin_tasks.status == 200, "admin token could not list tasks")

    task = request("/api/tasks", method="POST", token=ADMIN, obj={
        "project_id": project["id"],
        "title": "security smoke task",
        "expected_outcome": "exercise worker role separation",
        "required_tags": {"rust": "true"},
    })
    expect(task.status == 200, f"admin could not create task: HTTP {task.status}")
    task_json = read_json(task)

    worker_id = str(uuid.uuid4())
    anonymous_worker = request("/api/workers/register", method="POST", obj=worker_payload(worker_id))
    expect(anonymous_worker.status == 401, "anonymous worker registration was not rejected")
    admin_worker = request("/api/workers/register", method="POST", obj=worker_payload(worker_id), token=ADMIN)
    expect(admin_worker.status == 401, "admin credential was accepted as worker enrollment credential")

    credential_a = register_worker(worker_id, "worker-a")
    headers_a = worker_headers(credential_a)

    worker_b_id = str(uuid.uuid4())
    credential_b = register_worker(worker_b_id, "worker-b")
    headers_b = worker_headers(credential_b)

    enrollment_only = request(f"/api/workers/{worker_id}/heartbeat", method="POST", token=WORKER)
    expect(enrollment_only.status == 401, "enrollment secret worked as a runtime worker credential")

    wrong_credential = request(
        f"/api/workers/{worker_id}/heartbeat",
        method="POST",
        headers=headers_b,
    )
    expect(wrong_credential.status == 401, "worker B credential impersonated worker A")

    heartbeat = request(
        f"/api/workers/{worker_id}/heartbeat",
        method="POST",
        headers=headers_a,
    )
    expect(heartbeat.status == 204, f"worker-specific heartbeat failed without enrollment secret: {heartbeat.status}")

    # Even a bogus Authorization header must not matter after enrollment; only the
    # worker-specific credential is the runtime identity.
    heartbeat_with_bogus_bearer = request(
        f"/api/workers/{worker_id}/heartbeat",
        method="POST",
        token="not-the-enrollment-token",
        headers=headers_a,
    )
    expect(heartbeat_with_bogus_bearer.status == 204, "runtime worker endpoint still depends on enrollment bearer")

    claim = request(
        f"/api/workers/{worker_id}/claim",
        method="POST",
        headers=headers_a,
    )
    expect(claim.status == 200, f"worker claim failed: {claim.status}")
    assignment = read_json(claim)
    expect(assignment["task"]["id"] == task_json["id"], "worker claimed unexpected task")
    execution_id = assignment["execution"]["id"]
    lease_capability = assignment["lease_capability"]

    cross_worker_renew = request(
        f"/api/executions/{execution_id}/renew",
        method="POST",
        headers=lease_headers(headers_b, lease_capability),
    )
    expect(cross_worker_renew.status == 401, "worker B renewed worker A execution")

    own_renew = request(
        f"/api/executions/{execution_id}/renew",
        method="POST",
        headers=lease_headers(headers_a, lease_capability),
    )
    expect(own_renew.status == 204, f"worker A could not renew its execution: {own_renew.status}")

    approve_with_worker = request(f"/api/tasks/{task_json['id']}/approve", method="POST", obj={}, token=WORKER)
    expect(approve_with_worker.status == 401, "worker enrollment token reached removed approval route")
    approve_with_worker.read()
    approve_with_admin = request(f"/api/tasks/{task_json['id']}/approve", method="POST", obj={}, token=ADMIN)
    expect(approve_with_admin.status == 404, f"manual approval bypass still exists: {approve_with_admin.status}")
    approve_with_admin.read()

    bad_dcr = request("/mcp/oauth/register", method="POST", obj={
        "redirect_uris": ["https://evil.example/callback"],
        "client_name": "blocked",
        "token_endpoint_auth_method": "none",
    })
    expect(bad_dcr.status == 403, f"unapproved OAuth redirect host was accepted: {bad_dcr.status}")

    good_dcr = request("/mcp/oauth/register", method="POST", obj={
        "redirect_uris": ["https://chatgpt.com/connector/oauth/security-smoke"],
        "client_name": "allowed",
        "token_endpoint_auth_method": "none",
    })
    expect(good_dcr.status == 201, f"allowed ChatGPT redirect was rejected: HTTP {good_dcr.status}")
    good_dcr.read()

    bad_cimd_query = urllib.parse.urlencode({
        "client_id": "https://127.0.0.1/client-metadata.json",
        "redirect_uri": "https://chatgpt.com/connector/oauth/security-smoke",
        "response_type": "code",
        "code_challenge": "a" * 43,
        "code_challenge_method": "S256",
    })
    bad_cimd = request("/mcp/oauth/authorize?" + bad_cimd_query)
    expect(bad_cimd.status == 403, f"private CIMD client host was not blocked before fetch: {bad_cimd.status}")

    limited = None
    for _ in range(125):
        limited = request(
            "/mcp/oauth/token",
            method="POST",
            data=urllib.parse.urlencode({
                "grant_type": "authorization_code",
                "client_id": "invalid-client",
                "code": "invalid",
                "redirect_uri": "https://chatgpt.com/connector/oauth/security-smoke",
                "code_verifier": "x" * 43,
            }).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    expect(limited is not None and limited.status == 429, f"OAuth token rate limit did not engage: {getattr(limited, 'status', None)}")

    print("Security smoke test passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Security smoke test failed: {exc}", file=sys.stderr)
        raise
