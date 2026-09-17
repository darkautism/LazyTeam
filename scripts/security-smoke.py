#!/usr/bin/env python3
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

BASE = os.environ.get("LAZYTEAM_SECURITY_SMOKE_URL", "http://127.0.0.1:8788")
ADMIN = os.environ.get("LAZYTEAM_ADMIN_TOKEN", "admin-security-smoke-token-0123456789abcdef")
WORKER = os.environ.get("LAZYTEAM_WORKER_TOKEN", "worker-security-smoke-token-0123456789abcdef")
WORKER_CREDENTIAL_HEADER = "X-LazyTeam-Worker-Credential"


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


def project_payload(slug):
    return {
        "slug": slug,
        "name": "Security Smoke",
        "repo_url": "https://example.invalid/security.git",
        "default_branch": "main",
    }


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
        "protocol_version": 1,
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


def main():
    health = request("/health")
    expect(health.status == 200 and health.read() == b"ok", "health failed")
    expect(health.headers.get("X-Content-Type-Options") == "nosniff", "nosniff missing")
    expect(health.headers.get("Strict-Transport-Security"), "HSTS missing in production")

    slug = "security-" + uuid.uuid4().hex[:8]

    anonymous_admin = request("/api/projects", method="POST", obj=project_payload(slug))
    expect(anonymous_admin.status == 401, f"anonymous admin API should be 401, got {anonymous_admin.status}")

    worker_on_admin = request("/api/projects", method="POST", obj=project_payload(slug), token=WORKER)
    expect(worker_on_admin.status == 401, f"worker enrollment token reached admin API: {worker_on_admin.status}")

    admin_create = request("/api/projects", method="POST", obj=project_payload(slug), token=ADMIN)
    expect(admin_create.status == 200, f"admin token could not create project: HTTP {admin_create.status}")
    project = read_json(admin_create)

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

    cross_worker_renew = request(
        f"/api/executions/{execution_id}/renew",
        method="POST",
        headers=headers_b,
    )
    expect(cross_worker_renew.status == 401, "worker B renewed worker A execution")

    own_renew = request(
        f"/api/executions/{execution_id}/renew",
        method="POST",
        headers=headers_a,
    )
    expect(own_renew.status == 204, f"worker A could not renew its execution: {own_renew.status}")

    approve_with_worker = request(f"/api/tasks/{task_json['id']}/approve", method="POST", obj={}, token=WORKER)
    expect(approve_with_worker.status == 401, "worker enrollment token reached review approval")

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
