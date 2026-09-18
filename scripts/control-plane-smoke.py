#!/usr/bin/env python3
import json
import os
import sys
import urllib.error
import urllib.request
import uuid

BASE = os.environ.get("LAZYTEAM_SMOKE_URL", "http://127.0.0.1:8787")
WORKER_CREDENTIAL_HEADER = "X-LazyTeam-Worker-Credential"


def request(path, *, method="GET", obj=None, headers=None):
    data = None
    h = dict(headers or {})
    if obj is not None:
        data = json.dumps(obj).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=h, method=method)
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


def post_json(path, obj, expected=200, headers=None):
    resp = request(path, method="POST", obj=obj, headers=headers)
    expect(resp.status == expected, f"POST {path}: expected {expected}, got {resp.status}")
    return read_json(resp)


def main():
    suffix = uuid.uuid4().hex[:8]
    project_a = post_json("/api/projects", {
        "slug": f"smoke-a-{suffix}",
        "name": "Smoke A",
        "repo_url": "https://example.invalid/a.git",
        "default_branch": "main",
    })
    project_b = post_json("/api/projects", {
        "slug": f"smoke-b-{suffix}",
        "name": "Smoke B",
        "repo_url": "https://example.invalid/b.git",
        "default_branch": "main",
    })

    worker_id = str(uuid.uuid4())
    registration = request("/api/workers/register", method="POST", obj={
        "id": worker_id,
        "name": "smoke-worker",
        "os": "linux",
        "arch": "x86_64",
        "tags": {"rust": "true", "class": "general"},
        "allowed_projects": [project_a["slug"]],
        "slots": 1,
        "worker_version": "smoke",
        "protocol_version": 1,
    })
    expect(registration.status == 200, f"worker registration failed: {registration.status}")
    credential = registration.headers.get(WORKER_CREDENTIAL_HEADER)
    expect(bool(credential), "worker registration did not issue a credential")
    worker = read_json(registration)
    expect(worker["id"] == worker_id, "worker ID mismatch")
    worker_headers = {WORKER_CREDENTIAL_HEADER: credential}

    foreign_task = post_json("/api/tasks", {
        "project_id": project_b["id"],
        "title": "must not run here",
        "expected_outcome": "remain queued",
        "required_tags": {"rust": "true"},
        "priority": 100,
    })
    parent = post_json("/api/tasks", {
        "project_id": project_a["id"],
        "title": "parent",
        "expected_outcome": "complete parent",
        "required_tags": {"rust": "true"},
        "priority": 10,
    })
    child = post_json("/api/tasks", {
        "project_id": project_a["id"],
        "title": "child",
        "expected_outcome": "run only after parent approval",
        "required_tags": {"rust": "true"},
        "dependencies": [parent["id"]],
        "priority": 20,
    })

    claim = request(f"/api/workers/{worker_id}/claim", method="POST", headers=worker_headers)
    expect(claim.status == 200, f"first claim failed: {claim.status}")
    assignment = read_json(claim)
    expect(assignment["task"]["id"] == parent["id"], "scheduler ignored project/dependency matching")
    execution_id = assignment["execution"]["id"]

    renew = request(f"/api/executions/{execution_id}/renew", method="POST", headers=worker_headers)
    expect(renew.status == 204, f"lease renew failed: {renew.status}")

    finish = request(
        f"/api/executions/{execution_id}/finish",
        method="POST",
        obj={"result": {"status": "completed", "summary": "parent done"}},
        headers=worker_headers,
    )
    expect(finish.status == 204, f"finish failed: {finish.status}")

    blocked_claim = request(f"/api/workers/{worker_id}/claim", method="POST", headers=worker_headers)
    expect(blocked_claim.status == 204, "child ran before parent review approval or foreign project was assigned")

    approved = post_json(f"/api/tasks/{parent['id']}/approve", {}, expected=200)
    expect(approved["state"] == "merge_pending", "parent approval did not enter merge_pending")

    still_blocked = request(f"/api/workers/{worker_id}/claim", method="POST", headers=worker_headers)
    expect(still_blocked.status == 204, "child unlocked before the approved parent was actually merged")

    merged = post_json(f"/api/tasks/{parent['id']}/merged", {"merge_commit_sha": "merge-parent"}, expected=200)
    expect(merged["state"] == "done", "merged parent did not mark done")
    cleanup = read_json(request(f"/api/workers/{worker_id}/cleanup", headers=worker_headers))
    expect(any(item["task_id"] == parent["id"] for item in cleanup), "merged parent did not queue cleanup on its worker")
    ack = request(f"/api/workers/{worker_id}/cleanup/{parent['id']}", method="POST", headers=worker_headers)
    expect(ack.status == 204, f"cleanup ack failed: {ack.status}")

    child_claim = request(f"/api/workers/{worker_id}/claim", method="POST", headers=worker_headers)
    expect(child_claim.status == 200, f"child did not unlock after merge: {child_claim.status}")
    child_assignment = read_json(child_claim)
    expect(child_assignment["task"]["id"] == child["id"], "wrong child assignment")

    child_execution = child_assignment["execution"]["id"]
    finish_child = request(
        f"/api/executions/{child_execution}/finish",
        method="POST",
        obj={"result": {"status": "completed", "summary": "child done"}},
        headers=worker_headers,
    )
    expect(finish_child.status == 204, f"child finish failed: {finish_child.status}")
    child_approved = post_json(f"/api/tasks/{child['id']}/approve", {}, expected=200)
    expect(child_approved["state"] == "merge_pending", "child approval did not enter merge_pending")
    post_json(f"/api/tasks/{child['id']}/merged", {"merge_commit_sha": "merge-child"}, expected=200)
    child_cleanup = read_json(request(f"/api/workers/{worker_id}/cleanup", headers=worker_headers))
    expect(any(item["task_id"] == child["id"] for item in child_cleanup), "merged child did not queue cleanup")
    request(f"/api/workers/{worker_id}/cleanup/{child['id']}", method="POST", headers=worker_headers).read()

    tasks = read_json(request("/api/tasks"))
    by_id = {task["id"]: task for task in tasks}
    expect(by_id[parent["id"]]["state"] == "done", "parent final state mismatch")
    expect(by_id[child["id"]]["state"] == "done", "child final state mismatch")
    expect(by_id[foreign_task["id"]]["state"] == "queued", "foreign project task was consumed")

    if os.environ.get("LAZYTEAM_GIT_CREDENTIAL_KEY"):
        credential_value = "example-credential-value"
        managed = post_json("/api/projects", {
            "slug": f"managed-git-{suffix}",
            "name": "Managed Git",
            "repo_url": "https://example.invalid/private.git",
            "default_branch": "main",
            "git_auth": {
                "mode": "https_basic",
                "username": "smoke-user",
                "secret": credential_value,
            },
        })
        expect(managed["git_auth"]["mode"] == "https_basic", "managed Git auth mode missing")
        expect(managed["git_auth"]["username"] == "smoke-user", "managed Git username missing")
        expect(managed["git_auth"]["credential_configured"] is True, "managed Git credential status missing")
        expect(credential_value not in json.dumps(managed), "project create response exposed Git credential")
        project_listing = read_json(request("/api/projects"))
        expect(credential_value not in json.dumps(project_listing), "project list exposed Git credential")

        managed_task = post_json("/api/tasks", {
            "project_id": managed["id"],
            "title": "managed credential task",
            "expected_outcome": "credential is delivered only to protocol 2 worker",
            "priority": 200,
        })

        legacy_id = str(uuid.uuid4())
        legacy_registration = request("/api/workers/register", method="POST", obj={
            "id": legacy_id,
            "name": "legacy-managed-worker",
            "os": "linux",
            "arch": "x86_64",
            "allowed_projects": [managed["slug"]],
            "slots": 1,
            "worker_version": "smoke-v1",
            "protocol_version": 1,
        })
        expect(legacy_registration.status == 200, f"protocol 1 compatibility registration failed: {legacy_registration.status}")
        legacy_headers = {WORKER_CREDENTIAL_HEADER: legacy_registration.headers.get(WORKER_CREDENTIAL_HEADER)}
        legacy_claim = request(f"/api/workers/{legacy_id}/claim", method="POST", headers=legacy_headers)
        expect(legacy_claim.status == 204, "protocol 1 worker received a server-managed Git task")

        managed_worker_id = str(uuid.uuid4())
        managed_registration = request("/api/workers/register", method="POST", obj={
            "id": managed_worker_id,
            "name": "managed-git-worker",
            "os": "linux",
            "arch": "x86_64",
            "allowed_projects": [managed["slug"]],
            "slots": 1,
            "worker_version": "smoke-v2",
            "protocol_version": 2,
        })
        expect(managed_registration.status == 200, f"protocol 2 worker registration failed: {managed_registration.status}")
        managed_headers = {WORKER_CREDENTIAL_HEADER: managed_registration.headers.get(WORKER_CREDENTIAL_HEADER)}
        managed_claim = request(f"/api/workers/{managed_worker_id}/claim", method="POST", headers=managed_headers)
        expect(managed_claim.status == 200, f"protocol 2 worker could not claim managed Git task: {managed_claim.status}")
        managed_assignment = read_json(managed_claim)
        expect(managed_assignment["task"]["id"] == managed_task["id"], "protocol 2 worker claimed wrong managed Git task")
        expect(managed_assignment["git_credential"]["mode"] == "https_basic", "worker assignment omitted Git auth mode")
        expect(managed_assignment["git_credential"]["username"] == "smoke-user", "worker assignment omitted Git username")
        expect(managed_assignment["git_credential"]["secret"] == credential_value, "worker assignment received wrong Git credential")
        managed_execution = managed_assignment["execution"]["id"]
        managed_finish = request(
            f"/api/executions/{managed_execution}/finish",
            method="POST",
            obj={"result": {"status": "completed", "summary": "credential delivery checked"}},
            headers=managed_headers,
        )
        expect(managed_finish.status == 204, f"managed Git smoke finish failed: {managed_finish.status}")

    print("Control-plane smoke test passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Control-plane smoke test failed: {exc}", file=sys.stderr)
        raise
