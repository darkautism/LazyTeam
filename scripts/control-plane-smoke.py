#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import uuid

BASE = os.environ.get("LAZYTEAM_SMOKE_URL", "http://127.0.0.1:8787")
WORKER_CREDENTIAL_HEADER = "X-LazyTeam-Worker-Credential"
LEASE_CAPABILITY_HEADER = "X-LazyTeam-Lease-Capability"


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


def lease_headers(worker_headers, capability):
    headers = dict(worker_headers)
    headers[LEASE_CAPABILITY_HEADER] = capability
    return headers


def main():
    suffix = uuid.uuid4().hex[:8]
    git_fixture = tempfile.mkdtemp(prefix="lazyteam-smoke-git-")
    work_repo = os.path.join(git_fixture, "work")
    upstream_repo = os.path.join(git_fixture, "upstream.git")
    subprocess.run(["git", "init", "-b", "main", work_repo], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "-C", work_repo, "config", "user.name", "LazyTeam Smoke"], check=True)
    subprocess.run(["git", "-C", work_repo, "config", "user.email", "smoke@lazyteam.test"], check=True)
    with open(os.path.join(work_repo, "README.md"), "w", encoding="utf-8") as handle:
        handle.write("LazyTeam broker smoke\n")
    subprocess.run(["git", "-C", work_repo, "add", "README.md"], check=True)
    subprocess.run(["git", "-C", work_repo, "commit", "-m", "smoke base"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "-C", work_repo, "checkout", "-b", "secret-branch"], check=True, stdout=subprocess.DEVNULL)
    with open(os.path.join(work_repo, "SECRET.txt"), "w", encoding="utf-8") as handle:
        handle.write("must not be advertised by task broker\n")
    subprocess.run(["git", "-C", work_repo, "add", "SECRET.txt"], check=True)
    subprocess.run(["git", "-C", work_repo, "commit", "-m", "unrelated secret branch"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "-C", work_repo, "checkout", "main"], check=True, stdout=subprocess.DEVNULL)
    subprocess.run(["git", "clone", "--bare", work_repo, upstream_repo], check=True, stdout=subprocess.DEVNULL)

    project_a = post_json("/api/projects", {
        "slug": f"smoke-a-{suffix}",
        "name": "Smoke A",
        "repo_url": upstream_repo,
        "default_branch": "main",
    })
    project_b = post_json("/api/projects", {
        "slug": f"smoke-b-{suffix}",
        "name": "Smoke B",
        "repo_url": upstream_repo,
        "default_branch": "main",
    })
    git_probe = post_json(f"/api/projects/{project_a['id']}/git-probe", {})
    expect(git_probe["ok"] is True, f"Host Git probe failed for valid upstream: {git_probe}")
    expect("refs/heads/main" in git_probe["message"], "Host Git probe did not report the configured default branch")

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
        "protocol_version": 6,
    })
    expect(registration.status == 200, f"worker registration failed: {registration.status}")
    credential = registration.headers.get(WORKER_CREDENTIAL_HEADER)
    expect(bool(credential), "worker registration did not issue a credential")
    worker = read_json(registration)
    expect(worker["id"] == worker_id, "worker ID mismatch")
    worker_headers = {WORKER_CREDENTIAL_HEADER: credential}

    failure_task = post_json("/api/tasks", {
        "project_id": project_a["id"],
        "title": "failure returns unclaimed",
        "expected_outcome": "become unclaimed after a failed execution",
        "required_tags": {"rust": "true"},
        "priority": 200,
    })
    failure_claim = request(f"/api/workers/{worker_id}/claim", method="POST", headers=worker_headers)
    expect(failure_claim.status == 200, f"failure smoke claim failed: {failure_claim.status}")
    failure_assignment = read_json(failure_claim)
    expect(failure_assignment["task"]["id"] == failure_task["id"], "failure smoke task was not claimed")
    failure_capability = failure_assignment["lease_capability"]
    failure_repo_path = failure_assignment["project"]["repo_url"].removeprefix(BASE)
    missing_capability = request(f"{failure_repo_path}/info/refs?service=git-upload-pack", headers=worker_headers)
    expect(missing_capability.status == 401, "broker accepted worker credential without lease capability")
    wrong_capability = request(f"{failure_repo_path}/info/refs?service=git-upload-pack", headers=lease_headers(worker_headers, "ltc_wrong"))
    expect(wrong_capability.status == 401, "broker accepted a wrong lease capability")
    valid_capability = request(f"{failure_repo_path}/info/refs?service=git-upload-pack", headers=lease_headers(worker_headers, failure_capability))
    expect(valid_capability.status == 200, f"broker rejected the active lease capability: {valid_capability.status}")
    git_env = dict(os.environ)
    git_env.update({
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": "http.extraHeader",
        "GIT_CONFIG_VALUE_0": f"{WORKER_CREDENTIAL_HEADER}: {credential}",
        "GIT_CONFIG_KEY_1": "http.extraHeader",
        "GIT_CONFIG_VALUE_1": f"{LEASE_CAPABILITY_HEADER}: {failure_capability}",
    })
    git_probe = subprocess.run(["git", "ls-remote", failure_assignment["project"]["repo_url"]], env=git_env, capture_output=True, text=True)
    expect(git_probe.returncode == 0, f"real Git smart-HTTP broker probe failed: {git_probe.stderr.strip()}")
    expect("refs/heads/main" in git_probe.stdout, "task broker omitted the default branch")
    expect("refs/heads/secret-branch" not in git_probe.stdout, "task broker exposed an unrelated upstream branch")
    failure_finish = request(
        f"/api/executions/{failure_assignment['execution']['id']}/finish",
        method="POST",
        obj={"result": {"status": "failed", "summary": "intentional smoke failure"}},
        headers=lease_headers(worker_headers, failure_capability),
    )
    expect(failure_finish.status == 204, f"failure smoke finish failed: {failure_finish.status}")
    revoked_capability = request(f"{failure_repo_path}/info/refs?service=git-upload-pack", headers=lease_headers(worker_headers, failure_capability))
    expect(revoked_capability.status == 404, "finished execution retained broker access")
    board = read_json(request("/api/task-board"))
    failure_board = next(item for item in board if item["task"]["id"] == failure_task["id"])
    expect(failure_board["task"]["state"] == "failed", "failed execution did not move task to failed")
    expect(failure_board["worker"] is None, "failed task still exposed its previous worker")
    redispatched = post_json(f"/api/tasks/{failure_task['id']}/retry", {}, expected=200)
    expect(redispatched["state"] == "queued", "failed task did not re-dispatch to queued")
    deleted = request(f"/api/tasks/{failure_task['id']}", method="DELETE")
    expect(deleted.status == 204, f"task delete failed: {deleted.status}")
    visible_tasks = read_json(request("/api/tasks"))
    expect(all(task["id"] != failure_task["id"] for task in visible_tasks), "deleted task remained visible")
    cleanup = read_json(request(f"/api/workers/{worker_id}/cleanup", headers=worker_headers))
    expect(any(item["task_id"] == failure_task["id"] for item in cleanup), "deleted task did not queue worker cleanup")
    ack = request(f"/api/workers/{worker_id}/cleanup/{failure_task['id']}", method="POST", headers=worker_headers)
    expect(ack.status == 204, f"deleted task cleanup ack failed: {ack.status}")

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
    assignment_capability = assignment["lease_capability"]

    wrong_renew = request(f"/api/executions/{execution_id}/renew", method="POST", headers=lease_headers(worker_headers, "ltc_wrong"))
    expect(wrong_renew.status == 401, "execution renew accepted wrong lease capability")
    renew = request(f"/api/executions/{execution_id}/renew", method="POST", headers=lease_headers(worker_headers, assignment_capability))
    expect(renew.status == 204, f"lease renew failed: {renew.status}")

    parent_ref = f"lazyteam/task-{parent['id'].replace('-', '')}"
    finish = request(
        f"/api/executions/{execution_id}/finish",
        method="POST",
        obj={"result": {"status": "completed", "summary": "parent done", "commit_sha": "parent-candidate", "base_sha": "parent-base", "review_ref": parent_ref}},
        headers=lease_headers(worker_headers, assignment_capability),
    )
    expect(finish.status == 204, f"finish failed: {finish.status}")

    blocked_claim = request(f"/api/workers/{worker_id}/claim", method="POST", headers=worker_headers)
    expect(blocked_claim.status == 204, "child ran before parent review approval or foreign project was assigned")

    removed_approve = request(f"/api/tasks/{parent['id']}/approve", method="POST", obj={})
    expect(removed_approve.status == 404, f"manual approval bypass still exists: {removed_approve.status}")
    removed_approve.read()

    dep_reviewer_id = str(uuid.uuid4())
    dep_reviewer_registration = request("/api/workers/register", method="POST", obj={
        "id": dep_reviewer_id,
        "name": "smoke-dep-reviewer",
        "os": "linux",
        "arch": "x86_64",
        "allowed_projects": [project_a["slug"]],
        "slots": 1,
        "worker_version": "smoke-dep-reviewer",
        "protocol_version": 6,
    })
    expect(dep_reviewer_registration.status == 200, f"dependency reviewer registration failed: {dep_reviewer_registration.status}")
    dep_reviewer_headers = {WORKER_CREDENTIAL_HEADER: dep_reviewer_registration.headers.get(WORKER_CREDENTIAL_HEADER)}
    dep_reviewer_update = request(f"/api/workers/{dep_reviewer_id}", method="PATCH", obj={
        "role": "reviewer",
        "initial_prompt": "Dependency reviewer smoke prompt",
    })
    expect(dep_reviewer_update.status == 200, f"dependency reviewer role update failed: {dep_reviewer_update.status}")
    dep_reviewer_update.read()

    parent_review_claim = request(f"/api/workers/{dep_reviewer_id}/review-claim", method="POST", headers=dep_reviewer_headers)
    expect(parent_review_claim.status == 200, f"reviewer could not claim parent review: {parent_review_claim.status}")
    parent_review_assignment = read_json(parent_review_claim)
    expect(parent_review_assignment["task"]["id"] == parent["id"], "reviewer claimed wrong parent task")
    parent_review_done = request(
        f"/api/reviews/{parent_review_assignment['review']['id']}/finish",
        method="POST",
        obj={"status": "completed", "verdict": {"verdict": "approve", "reason": "parent independently verified", "validation": []}},
        headers=lease_headers(dep_reviewer_headers, parent_review_assignment["lease_capability"]),
    )
    expect(parent_review_done.status == 204, f"parent reviewer finish failed: {parent_review_done.status}")
    parent_state = next(task for task in read_json(request("/api/tasks")) if task["id"] == parent["id"])
    expect(parent_state["state"] == "merge_pending", "reviewer approval did not move parent to merge_pending")

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
    child_capability = child_assignment["lease_capability"]
    child_ref = f"lazyteam/task-{child['id'].replace('-', '')}"
    finish_child = request(
        f"/api/executions/{child_execution}/finish",
        method="POST",
        obj={"result": {"status": "completed", "summary": "child done", "commit_sha": "child-candidate", "base_sha": "child-base", "review_ref": child_ref}},
        headers=lease_headers(worker_headers, child_capability),
    )
    expect(finish_child.status == 204, f"child finish failed: {finish_child.status}")
    child_review_claim = request(f"/api/workers/{dep_reviewer_id}/review-claim", method="POST", headers=dep_reviewer_headers)
    expect(child_review_claim.status == 200, f"reviewer could not claim child review: {child_review_claim.status}")
    child_review_assignment = read_json(child_review_claim)
    expect(child_review_assignment["task"]["id"] == child["id"], "reviewer claimed wrong child task")
    child_review_done = request(
        f"/api/reviews/{child_review_assignment['review']['id']}/finish",
        method="POST",
        obj={"status": "completed", "verdict": {"verdict": "approve", "reason": "child independently verified", "validation": []}},
        headers=lease_headers(dep_reviewer_headers, child_review_assignment["lease_capability"]),
    )
    expect(child_review_done.status == 204, f"child reviewer finish failed: {child_review_done.status}")
    child_state = next(task for task in read_json(request("/api/tasks")) if task["id"] == child["id"])
    expect(child_state["state"] == "merge_pending", "reviewer approval did not move child to merge_pending")
    post_json(f"/api/tasks/{child['id']}/merged", {"merge_commit_sha": "merge-child"}, expected=200)
    child_cleanup = read_json(request(f"/api/workers/{worker_id}/cleanup", headers=worker_headers))
    expect(any(item["task_id"] == child["id"] for item in child_cleanup), "merged child did not queue cleanup")
    request(f"/api/workers/{worker_id}/cleanup/{child['id']}", method="POST", headers=worker_headers).read()

    tasks = read_json(request("/api/tasks"))
    by_id = {task["id"]: task for task in tasks}
    expect(by_id[parent["id"]]["state"] == "done", "parent final state mismatch")
    expect(by_id[child["id"]]["state"] == "done", "child final state mismatch")
    expect(by_id[foreign_task["id"]]["state"] == "queued", "foreign project task was consumed")

    review_task = post_json("/api/tasks", {
        "project_id": project_a["id"],
        "title": "reviewer role smoke",
        "expected_outcome": "reviewer worker approves a pinned candidate",
        "required_tags": {"rust": "true"},
        "priority": 150,
    })
    review_impl_claim = request(f"/api/workers/{worker_id}/claim", method="POST", headers=worker_headers)
    expect(review_impl_claim.status == 200, f"review implementation claim failed: {review_impl_claim.status}")
    review_impl_assignment = read_json(review_impl_claim)
    expect(review_impl_assignment["task"]["id"] == review_task["id"], "wrong review implementation task claimed")
    review_execution = review_impl_assignment["execution"]["id"]
    review_impl_capability = review_impl_assignment["lease_capability"]
    review_finish = request(
        f"/api/executions/{review_execution}/finish",
        method="POST",
        obj={"result": {
            "status": "completed",
            "summary": "candidate ready",
            "commit_sha": "candidate-sha",
            "base_sha": "base-sha",
            "review_ref": f"lazyteam/task-{review_task['id'].replace('-', '')}",
        }},
        headers=lease_headers(worker_headers, review_impl_capability),
    )
    expect(review_finish.status == 204, f"review implementation finish failed: {review_finish.status}")

    reviewer_id = str(uuid.uuid4())
    reviewer_registration = request("/api/workers/register", method="POST", obj={
        "id": reviewer_id,
        "name": "smoke-reviewer",
        "os": "linux",
        "arch": "x86_64",
        "allowed_projects": [project_a["slug"]],
        "slots": 1,
        "worker_version": "smoke-reviewer",
        "protocol_version": 6,
    })
    expect(reviewer_registration.status == 200, f"reviewer registration failed: {reviewer_registration.status}")
    reviewer_headers = {WORKER_CREDENTIAL_HEADER: reviewer_registration.headers.get(WORKER_CREDENTIAL_HEADER)}
    reviewer_update = request(f"/api/workers/{reviewer_id}", method="PATCH", obj={
        "role": "reviewer",
        "initial_prompt": "Independent reviewer smoke prompt",
    })
    expect(reviewer_update.status == 200, f"reviewer role update failed: {reviewer_update.status}")
    reviewer_worker = read_json(reviewer_update)
    expect(reviewer_worker["role"] == "reviewer", "reviewer role was not persisted")

    wrong_claim = request(f"/api/workers/{reviewer_id}/claim", method="POST", headers=reviewer_headers)
    expect(wrong_claim.status == 204, "reviewer worker claimed an implementation task")

    review_claim = request(f"/api/workers/{reviewer_id}/review-claim", method="POST", headers=reviewer_headers)
    expect(review_claim.status == 200, f"reviewer could not claim review: {review_claim.status}")
    review_assignment = read_json(review_claim)
    expect(review_assignment["task"]["id"] == review_task["id"], "reviewer claimed wrong task")
    expect(review_assignment["review"]["execution_id"] == review_execution, "review was not pinned to implementation execution")
    expect(review_assignment["checkout"]["commit_sha"] == "candidate-sha", "review checkout was not pinned to candidate SHA")
    expect(review_assignment["implementation_worker"]["id"] == worker_id, "review assignment lost implementation worker identity")

    raced_main = request(f"/api/tasks/{review_task['id']}/approve", method="POST", obj={})
    expect(raced_main.status == 404, f"manual approval bypass still exists: {raced_main.status}")
    raced_main.read()

    review_id = review_assignment["review"]["id"]
    review_capability = review_assignment["lease_capability"]
    wrong_review_renew = request(f"/api/reviews/{review_id}/renew", method="POST", headers=lease_headers(reviewer_headers, "ltc_wrong"))
    expect(wrong_review_renew.status == 401, "review renew accepted wrong lease capability")
    review_repo_path = review_assignment["checkout"]["repo_url"].removeprefix(BASE)
    valid_review_read = request(f"{review_repo_path}/info/refs?service=git-upload-pack", headers=lease_headers(reviewer_headers, review_capability))
    expect(valid_review_read.status == 200, f"active reviewer could not read broker checkout: {valid_review_read.status}")
    reviewer_write = request(f"{review_repo_path}/info/refs?service=git-receive-pack", headers=lease_headers(reviewer_headers, review_capability))
    expect(reviewer_write.status == 403, "reviewer broker endpoint exposed receive-pack write access")
    review_done = request(
        f"/api/reviews/{review_id}/finish",
        method="POST",
        obj={"status": "completed", "verdict": {
            "verdict": "approve",
            "reason": "candidate independently verified",
            "validation": ["smoke validation"],
        }},
        headers=lease_headers(reviewer_headers, review_capability),
    )
    expect(review_done.status == 204, f"reviewer finish failed: {review_done.status}")
    revoked_review_read = request(f"{review_repo_path}/info/refs?service=git-upload-pack", headers=lease_headers(reviewer_headers, review_capability))
    expect(revoked_review_read.status == 404, "review finish did not revoke broker access immediately")
    review_state = next(task for task in read_json(request("/api/tasks")) if task["id"] == review_task["id"])
    expect(review_state["state"] == "merge_pending", "reviewer approval did not move task to merge_pending")

    credential_value = "example-credential-value"
    managed = post_json("/api/projects", {
        "slug": f"managed-git-{suffix}",
        "name": "Managed Git",
        "repo_url": upstream_repo,
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

    # Same worker, different slots: the worker identity is shared, but lease authority is not.
    slot_project = post_json("/api/projects", {
        "slug": f"slot-isolation-{suffix}",
        "name": "Slot isolation",
        "repo_url": upstream_repo,
        "default_branch": "main",
    })
    slot_task_a = post_json("/api/tasks", {
        "project_id": slot_project["id"],
        "title": "slot A",
        "expected_outcome": "hold an isolated execution lease",
        "priority": 20,
    })
    slot_task_b = post_json("/api/tasks", {
        "project_id": slot_project["id"],
        "title": "slot B",
        "expected_outcome": "hold a different isolated execution lease",
        "priority": 10,
    })
    slot_worker_id = str(uuid.uuid4())
    slot_registration = request("/api/workers/register", method="POST", obj={
        "id": slot_worker_id,
        "name": "two-slot-worker",
        "os": "linux",
        "arch": "x86_64",
        "allowed_projects": [slot_project["slug"]],
        "slots": 2,
        "worker_version": "smoke-v6",
        "protocol_version": 6,
    })
    expect(slot_registration.status == 200, f"two-slot worker registration failed: {slot_registration.status}")
    slot_headers = {WORKER_CREDENTIAL_HEADER: slot_registration.headers.get(WORKER_CREDENTIAL_HEADER)}
    slot_claim_a = request(f"/api/workers/{slot_worker_id}/claim", method="POST", headers=slot_headers)
    slot_claim_b = request(f"/api/workers/{slot_worker_id}/claim", method="POST", headers=slot_headers)
    expect(slot_claim_a.status == 200 and slot_claim_b.status == 200, "two-slot worker did not receive two concurrent leases")
    slot_a = read_json(slot_claim_a)
    slot_b = read_json(slot_claim_b)
    cap_a = slot_a["lease_capability"]
    cap_b = slot_b["lease_capability"]
    expect(cap_a != cap_b, "different slots received the same lease capability")
    exec_a = slot_a["execution"]["id"]
    exec_b = slot_b["execution"]["id"]
    cross_renew = request(f"/api/executions/{exec_b}/renew", method="POST", headers=lease_headers(slot_headers, cap_a))
    expect(cross_renew.status == 401, "slot A capability renewed slot B execution")
    slot_b_repo = slot_b["project"]["repo_url"].removeprefix(BASE)
    cross_git = request(f"{slot_b_repo}/info/refs?service=git-upload-pack", headers=lease_headers(slot_headers, cap_a))
    expect(cross_git.status == 401, "slot A capability read slot B repository")
    own_git = request(f"{slot_b_repo}/info/refs?service=git-upload-pack", headers=lease_headers(slot_headers, cap_b))
    expect(own_git.status == 200, f"slot B capability could not read its own repository: {own_git.status}")
    finish_slot_a = request(
        f"/api/executions/{exec_a}/finish",
        method="POST",
        obj={"result": {"status": "failed", "summary": "slot isolation checked"}},
        headers=lease_headers(slot_headers, cap_a),
    )
    expect(finish_slot_a.status == 204, f"slot A finish failed: {finish_slot_a.status}")
    revoke_worker_auth = request(
        f"/api/workers/{slot_worker_id}",
        method="PATCH",
        obj={"allowed_projects": []},
    )
    expect(revoke_worker_auth.status == 200, f"worker authorization update failed: {revoke_worker_auth.status}")
    revoked_slot_git = request(f"{slot_b_repo}/info/refs?service=git-upload-pack", headers=lease_headers(slot_headers, cap_b))
    expect(revoked_slot_git.status == 404, "worker allowed-project change did not revoke active slot broker access")
    revoked_slot_renew = request(f"/api/executions/{exec_b}/renew", method="POST", headers=lease_headers(slot_headers, cap_b))
    expect(revoked_slot_renew.status == 409, "worker allowed-project change did not revoke active slot lease")

    # Reviewer cache affinity: prefer the previous live reviewer, but mint a fresh capability.
    affinity_task = post_json("/api/tasks", {
        "project_id": project_a["id"],
        "title": "reviewer affinity",
        "expected_outcome": "prefer prior reviewer without retaining prior authority",
        "required_tags": {"rust": "true"},
        "priority": 250,
    })
    affinity_impl_claim = request(f"/api/workers/{worker_id}/claim", method="POST", headers=worker_headers)
    expect(affinity_impl_claim.status == 200, f"affinity implementation claim failed: {affinity_impl_claim.status}")
    affinity_impl = read_json(affinity_impl_claim)
    affinity_exec = affinity_impl["execution"]["id"]
    affinity_ref = f"lazyteam/task-{affinity_task['id'].replace('-', '')}"
    affinity_finish = request(
        f"/api/executions/{affinity_exec}/finish",
        method="POST",
        obj={"result": {"status": "completed", "summary": "affinity candidate one", "commit_sha": "affinity-one", "base_sha": "base-one", "review_ref": affinity_ref}},
        headers=lease_headers(worker_headers, affinity_impl["lease_capability"]),
    )
    expect(affinity_finish.status == 204, f"affinity implementation finish failed: {affinity_finish.status}")
    first_affinity_claim = request(f"/api/workers/{reviewer_id}/review-claim", method="POST", headers=reviewer_headers)
    expect(first_affinity_claim.status == 200, f"preferred reviewer could not claim first affinity review: {first_affinity_claim.status}")
    first_affinity = read_json(first_affinity_claim)
    first_review_cap = first_affinity["lease_capability"]
    first_review_id = first_affinity["review"]["id"]
    first_retry = request(
        f"/api/reviews/{first_review_id}/finish",
        method="POST",
        obj={"status": "completed", "verdict": {"verdict": "retry", "reason": "exercise reviewer affinity", "validation": []}},
        headers=lease_headers(reviewer_headers, first_review_cap),
    )
    expect(first_retry.status == 204, f"first affinity review retry failed: {first_retry.status}")
    stale_review_cap = request(f"/api/reviews/{first_review_id}/renew", method="POST", headers=lease_headers(reviewer_headers, first_review_cap))
    expect(stale_review_cap.status == 409, "finished review capability remained renewable")

    affinity_retry_claim = request(f"/api/workers/{worker_id}/claim", method="POST", headers=worker_headers)
    expect(affinity_retry_claim.status == 200, f"sticky implementation retry was not reclaimed: {affinity_retry_claim.status}")
    affinity_retry = read_json(affinity_retry_claim)
    affinity_retry_finish = request(
        f"/api/executions/{affinity_retry['execution']['id']}/finish",
        method="POST",
        obj={"result": {"status": "completed", "summary": "affinity candidate two", "commit_sha": "affinity-two", "base_sha": "base-two", "review_ref": affinity_ref}},
        headers=lease_headers(worker_headers, affinity_retry["lease_capability"]),
    )
    expect(affinity_retry_finish.status == 204, f"affinity retry implementation finish failed: {affinity_retry_finish.status}")

    reviewer_b_id = str(uuid.uuid4())
    reviewer_b_registration = request("/api/workers/register", method="POST", obj={
        "id": reviewer_b_id,
        "name": "smoke-reviewer-b",
        "os": "linux",
        "arch": "x86_64",
        "allowed_projects": [project_a["slug"]],
        "slots": 1,
        "worker_version": "smoke-reviewer-b",
        "protocol_version": 6,
    })
    expect(reviewer_b_registration.status == 200, "second reviewer registration failed")
    reviewer_b_headers = {WORKER_CREDENTIAL_HEADER: reviewer_b_registration.headers.get(WORKER_CREDENTIAL_HEADER)}
    reviewer_b_update = request(f"/api/workers/{reviewer_b_id}", method="PATCH", obj={"role": "reviewer", "initial_prompt": "Second reviewer"})
    expect(reviewer_b_update.status == 200, "second reviewer role update failed")
    heartbeat_a = request(f"/api/workers/{reviewer_id}/heartbeat", method="POST", headers=reviewer_headers)
    expect(heartbeat_a.status == 204, "preferred reviewer heartbeat failed")
    nonpreferred_claim = request(f"/api/workers/{reviewer_b_id}/review-claim", method="POST", headers=reviewer_b_headers)
    expect(nonpreferred_claim.status == 204, "non-preferred reviewer stole a review while preferred reviewer was live and idle")
    preferred_claim = request(f"/api/workers/{reviewer_id}/review-claim", method="POST", headers=reviewer_headers)
    expect(preferred_claim.status == 200, f"preferred reviewer did not reclaim review: {preferred_claim.status}")
    second_affinity = read_json(preferred_claim)
    expect(second_affinity["lease_capability"] != first_review_cap, "reviewer affinity reused an old lease capability")
    second_affinity_done = request(
        f"/api/reviews/{second_affinity['review']['id']}/finish",
        method="POST",
        obj={"status": "completed", "verdict": {"verdict": "approve", "reason": "affinity verified", "validation": []}},
        headers=lease_headers(reviewer_headers, second_affinity["lease_capability"]),
    )
    expect(second_affinity_done.status == 204, f"preferred reviewer finish failed: {second_affinity_done.status}")

    # Project disable is an authority change: live capabilities are invalidated atomically.
    disable_project = post_json("/api/projects", {
        "slug": f"disable-auth-{suffix}",
        "name": "Disable authority",
        "repo_url": upstream_repo,
        "default_branch": "main",
    })
    disable_task = post_json("/api/tasks", {
        "project_id": disable_project["id"],
        "title": "disable revokes lease",
        "expected_outcome": "lose broker authority when project is disabled",
        "priority": 10,
    })
    disable_worker_id = str(uuid.uuid4())
    disable_registration = request("/api/workers/register", method="POST", obj={
        "id": disable_worker_id,
        "name": "disable-worker",
        "os": "linux",
        "arch": "x86_64",
        "allowed_projects": [disable_project["slug"]],
        "slots": 1,
        "worker_version": "smoke-v6",
        "protocol_version": 6,
    })
    expect(disable_registration.status == 200, "disable worker registration failed")
    disable_headers = {WORKER_CREDENTIAL_HEADER: disable_registration.headers.get(WORKER_CREDENTIAL_HEADER)}
    disable_claim = request(f"/api/workers/{disable_worker_id}/claim", method="POST", headers=disable_headers)
    expect(disable_claim.status == 200, "disable test task was not claimed")
    disable_assignment = read_json(disable_claim)
    disable_cap = disable_assignment["lease_capability"]
    disable_exec = disable_assignment["execution"]["id"]
    disable_repo = disable_assignment["project"]["repo_url"].removeprefix(BASE)
    project_disabled = request(f"/api/projects/{disable_project['id']}", method="PATCH", obj={"enabled": False})
    expect(project_disabled.status == 200, f"project disable failed: {project_disabled.status}")
    disabled_git = request(f"{disable_repo}/info/refs?service=git-upload-pack", headers=lease_headers(disable_headers, disable_cap))
    expect(disabled_git.status == 404, "project disable did not revoke broker capability immediately")
    disabled_renew = request(f"/api/executions/{disable_exec}/renew", method="POST", headers=lease_headers(disable_headers, disable_cap))
    expect(disabled_renew.status == 409, "project disable did not revoke execution lease immediately")

    # Deleting a task while a reviewer holds it must revoke that reviewer immediately.
    delete_review_task = post_json("/api/tasks", {
        "project_id": project_a["id"],
        "title": "delete active review",
        "expected_outcome": "revoke active reviewer on delete",
        "required_tags": {"rust": "true"},
        "priority": 300,
    })
    delete_impl_claim = request(f"/api/workers/{worker_id}/claim", method="POST", headers=worker_headers)
    expect(delete_impl_claim.status == 200, "delete-review implementation claim failed")
    delete_impl = read_json(delete_impl_claim)
    delete_ref = f"lazyteam/task-{delete_review_task['id'].replace('-', '')}"
    delete_impl_finish = request(
        f"/api/executions/{delete_impl['execution']['id']}/finish",
        method="POST",
        obj={"result": {"status": "completed", "summary": "delete review candidate", "commit_sha": "delete-review", "base_sha": "delete-base", "review_ref": delete_ref}},
        headers=lease_headers(worker_headers, delete_impl["lease_capability"]),
    )
    expect(delete_impl_finish.status == 204, "delete-review implementation finish failed")
    delete_reviewer_id = str(uuid.uuid4())
    delete_reviewer_registration = request("/api/workers/register", method="POST", obj={
        "id": delete_reviewer_id,
        "name": "delete-reviewer",
        "os": "linux",
        "arch": "x86_64",
        "allowed_projects": [project_a["slug"]],
        "slots": 1,
        "worker_version": "smoke-reviewer-delete",
        "protocol_version": 6,
    })
    expect(delete_reviewer_registration.status == 200, "delete reviewer registration failed")
    delete_reviewer_headers = {WORKER_CREDENTIAL_HEADER: delete_reviewer_registration.headers.get(WORKER_CREDENTIAL_HEADER)}
    delete_reviewer_update = request(f"/api/workers/{delete_reviewer_id}", method="PATCH", obj={"role": "reviewer", "initial_prompt": "Delete reviewer"})
    expect(delete_reviewer_update.status == 200, "delete reviewer role update failed")
    delete_review_claim = request(f"/api/workers/{delete_reviewer_id}/review-claim", method="POST", headers=delete_reviewer_headers)
    expect(delete_review_claim.status == 200, "delete reviewer did not claim active review")
    delete_review_assignment = read_json(delete_review_claim)
    delete_review_cap = delete_review_assignment["lease_capability"]
    delete_review_id = delete_review_assignment["review"]["id"]
    delete_review_repo = delete_review_assignment["checkout"]["repo_url"].removeprefix(BASE)
    delete_active_task = request(f"/api/tasks/{delete_review_task['id']}", method="DELETE")
    expect(delete_active_task.status == 204, f"deleting active review task failed: {delete_active_task.status}")
    deleted_review_git = request(f"{delete_review_repo}/info/refs?service=git-upload-pack", headers=lease_headers(delete_reviewer_headers, delete_review_cap))
    expect(deleted_review_git.status == 404, "task delete did not revoke reviewer broker access")
    deleted_review_renew = request(f"/api/reviews/{delete_review_id}/renew", method="POST", headers=lease_headers(delete_reviewer_headers, delete_review_cap))
    expect(deleted_review_renew.status == 409, "task delete did not revoke reviewer lease")

    print("Control-plane smoke test passed")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Control-plane smoke test failed: {exc}", file=sys.stderr)
        raise
