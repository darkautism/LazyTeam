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


def worker_payload(worker_id):
    return {
        "id": worker_id,
        "name": "security-smoke-worker",
        "os": "linux",
        "arch": "x86_64",
        "tags": {"rust": "true"},
        "allowed_projects": ["*"],
        "slots": 1,
        "worker_version": "security-smoke",
        "protocol_version": 1,
    }


def main():
    health = request("/health")
    expect(health.status == 200 and health.read() == b"ok", "health failed")
    expect(health.headers.get("X-Content-Type-Options") == "nosniff", "nosniff missing")
    expect(health.headers.get("Strict-Transport-Security"), "HSTS missing in production")

    slug = "security-" + uuid.uuid4().hex[:8]

    anonymous_admin = request("/api/projects", method="POST", obj=project_payload(slug))
    expect(anonymous_admin.status == 401, f"anonymous admin API should be 401, got {anonymous_admin.status}")

    worker_on_admin = request("/api/projects", method="POST", obj=project_payload(slug), token=WORKER)
    expect(worker_on_admin.status == 401, f"worker token reached admin API: {worker_on_admin.status}")

    admin_create = request("/api/projects", method="POST", obj=project_payload(slug), token=ADMIN)
    expect(admin_create.status == 200, f"admin token could not create project: {admin_create.status} {admin_create.read()!r}")
    project = read_json(admin_create)

    anonymous_tasks = request("/api/tasks")
    expect(anonymous_tasks.status == 401, "anonymous task listing was not rejected")
    worker_tasks = request("/api/tasks", token=WORKER)
    expect(worker_tasks.status == 401, "worker token reached task listing")
    admin_tasks = request("/api/tasks", token=ADMIN)
    expect(admin_tasks.status == 200, "admin token could not list tasks")

    task = request("/api/tasks", method="POST", token=ADMIN, obj={
        "project_id": project["id"],
        "title": "security smoke task",
        "expected_outcome": "exercise worker role separation",
        "required_tags": {"rust": "true"},
    })
    expect(task.status == 200, f"admin could not create task: {task.status}")
    task_json = read_json(task)

    worker_id = str(uuid.uuid4())
    anonymous_worker = request("/api/workers/register", method="POST", obj=worker_payload(worker_id))
    expect(anonymous_worker.status == 401, "anonymous worker registration was not rejected")
    admin_worker = request("/api/workers/register", method="POST", obj=worker_payload(worker_id), token=ADMIN)
    expect(admin_worker.status == 401, "admin credential was accepted as worker credential")
    good_worker = request("/api/workers/register", method="POST", obj=worker_payload(worker_id), token=WORKER)
    expect(good_worker.status == 200, f"worker registration failed: {good_worker.status}")

    claim = request(f"/api/workers/{worker_id}/claim", method="POST", token=WORKER)
    expect(claim.status == 200, f"worker claim failed: {claim.status}")
    assignment = read_json(claim)
    expect(assignment["task"]["id"] == task_json["id"], "worker claimed unexpected task")

    approve_with_worker = request(f"/api/tasks/{task_json['id']}/approve", method="POST", obj={}, token=WORKER)
    expect(approve_with_worker.status == 401, "worker token reached review approval")

    bogus_worker = request(f"/api/workers/{worker_id}/heartbeat", method="POST", token="not-the-worker-token")
    expect(bogus_worker.status == 401, "bogus worker token was accepted")
    heartbeat = request(f"/api/workers/{worker_id}/heartbeat", method="POST", token=WORKER)
    expect(heartbeat.status == 204, f"worker heartbeat failed: {heartbeat.status}")

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
    expect(good_dcr.status == 201, f"allowed ChatGPT redirect was rejected: {good_dcr.status} {good_dcr.read()!r}")

    bad_cimd_query = urllib.parse.urlencode({
        "client_id": "https://127.0.0.1/client-metadata.json",
        "redirect_uri": "https://chatgpt.com/connector/oauth/security-smoke",
        "response_type": "code",
        "code_challenge": "a" * 43,
        "code_challenge_method": "S256",
    })
    bad_cimd = request("/mcp/oauth/authorize?" + bad_cimd_query)
    expect(bad_cimd.status == 403, f"private CIMD client host was not blocked before fetch: {bad_cimd.status}")

    # The token endpoint is deliberately rate limited. Invalid requests still consume
    # budget, which prevents cheap brute-force/DoS amplification against the DB.
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
