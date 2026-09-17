#!/usr/bin/env python3
import json
import os
import sys
import urllib.error
import urllib.request
import uuid

BASE = os.environ.get("LAZYTEAM_SMOKE_URL", "http://127.0.0.1:8787")


def request(path, *, method="GET", obj=None):
    data = None
    headers = {}
    if obj is not None:
        data = json.dumps(obj).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
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


def post_json(path, obj, expected=200):
    resp = request(path, method="POST", obj=obj)
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
    worker = post_json("/api/workers/register", {
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
    expect(worker["id"] == worker_id, "worker ID mismatch")

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

    claim = request(f"/api/workers/{worker_id}/claim", method="POST")
    expect(claim.status == 200, f"first claim failed: {claim.status}")
    assignment = read_json(claim)
    expect(assignment["task"]["id"] == parent["id"], "scheduler ignored project/dependency matching")
    execution_id = assignment["execution"]["id"]

    renew = request(f"/api/executions/{execution_id}/renew", method="POST")
    expect(renew.status == 204, f"lease renew failed: {renew.status}")

    finish = request(
        f"/api/executions/{execution_id}/finish",
        method="POST",
        obj={"result": {"status": "completed", "summary": "parent done"}},
    )
    expect(finish.status == 204, f"finish failed: {finish.status}")

    blocked_claim = request(f"/api/workers/{worker_id}/claim", method="POST")
    expect(blocked_claim.status == 204, "child ran before parent review approval or foreign project was assigned")

    approved = post_json(f"/api/tasks/{parent['id']}/approve", {}, expected=200)
    expect(approved["state"] == "done", "parent approval did not mark done")

    child_claim = request(f"/api/workers/{worker_id}/claim", method="POST")
    expect(child_claim.status == 200, f"child did not unlock after approval: {child_claim.status}")
    child_assignment = read_json(child_claim)
    expect(child_assignment["task"]["id"] == child["id"], "wrong child assignment")

    child_execution = child_assignment["execution"]["id"]
    finish_child = request(
        f"/api/executions/{child_execution}/finish",
        method="POST",
        obj={"result": {"status": "completed", "summary": "child done"}},
    )
    expect(finish_child.status == 204, f"child finish failed: {finish_child.status}")
    post_json(f"/api/tasks/{child['id']}/approve", {}, expected=200)

    tasks = read_json(request("/api/tasks"))
    by_id = {task["id"]: task for task in tasks}
    expect(by_id[parent["id"]]["state"] == "done", "parent final state mismatch")
    expect(by_id[child["id"]]["state"] == "done", "child final state mismatch")
    expect(by_id[foreign_task["id"]]["state"] == "queued", "foreign project task was consumed")

    print("Control-plane smoke test passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Control-plane smoke test failed: {exc}", file=sys.stderr)
        raise
