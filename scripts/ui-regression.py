#!/usr/bin/env python3
"""Management UI regression test: reviewer role selector and MergePending lane.

Statically verifies that crates/lazyteam-server/src/ui.html implements the
role/prompt/merge-pending contract against lazyteam_core defaults without
requiring a running server.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "crates" / "lazyteam-server" / "src" / "ui.html"
CORE = ROOT / "crates" / "lazyteam-core" / "src" / "lib.rs"


def expect(condition, message):
    if not condition:
        raise AssertionError(message)


def rust_const(name):
    text = CORE.read_text()
    m = re.search(r'pub const ' + name + r': &str = "(.*?)"\s*;', text, re.S)
    expect(m, f"core constant {name} not found")
    return m.group(1).encode().decode("unicode_escape")


def js_const(name):
    text = UI.read_text()
    m = re.search(r'const ' + name + r"='(.*?)';", text, re.S)
    expect(m, f"UI constant {name} not found")
    raw = m.group(1)
    # Unescape JS single-quote escapes used for "worker's".
    return raw.replace("\\'", "'")


def main():
    ui = UI.read_text()

    # 1. Both role default prompts must exactly match the core constants.
    for name in ("DEFAULT_WORKER_PROMPT", "DEFAULT_REVIEWER_PROMPT"):
        expect(js_const(name) == rust_const(name), f"UI {name} does not match lazyteam_core::{name}")

    # 2. Role selector with Worker and Reviewer options.
    expect('id="worker-config-role"' in ui, "worker-config-role selector missing")
    expect(re.search(r'<select[^>]*id="worker-config-role"[^>]*onchange="onWorkerRoleChange\(\)"', ui),
           "role selector must call onWorkerRoleChange()")
    expect('<option value="worker">Worker</option>' in ui, "Worker role option missing")
    expect('<option value="reviewer">Reviewer</option>' in ui, "Reviewer role option missing")
    expect(re.search(r"Changing role replaces Initial prompt.*customized prompt.*overwrite confirmation", ui, re.I | re.S),
           "role selector must show a hint that changing role replaces the prompt and customized prompts need overwrite confirmation")

    # 3. Role change replaces the prompt with the role default.
    expect("function defaultPromptForRole(role)" in ui, "defaultPromptForRole helper missing")
    expect("defaultPromptForRole(nextRole)" in ui or "promptEl.value=nextDefault" in ui,
           "role change must replace the Initial prompt with the new role default")
    expect("configuringWorkerRole" in ui, "prior-role tracking missing")

    # 4. Customized prompt triggers an explicit overwrite confirmation;
    #    cancel restores the prior role and keeps the prompt unchanged.
    m = re.search(r"function onWorkerRoleChange\(\)\{([^\n]*)\n", ui)
    expect(m, "onWorkerRoleChange logic missing")
    logic = m.group(1)
    expect("confirm(" in logic, "role change must ask for confirmation")
    expect(re.search(r"overwrite.*customized prompt", logic, re.I),
           "confirmation must warn that the customized prompt will be overwritten")
    expect("select.value=prevRole" in logic.replace(" ", ""),
           "cancel must restore the prior role selection")
    cancel_branch = logic.split("confirm(")[1]
    expect("return" in cancel_branch.split("}")[0] or "return" in logic,
           "cancel must keep the prompt unchanged")

    # 5. Saving worker config PATCHes role together with the prompt.
    m = re.search(r"async function saveWorkerConfig\(\)\{([^\n]*)\n", ui)
    expect(m, "saveWorkerConfig missing")
    save_logic = m.group(1)
    expect("role:" in save_logic.replace(" ", "") or 'role=$' in save_logic or
           '"role"' in save_logic or "'role'" in save_logic or "role:$('#worker-config-role').value" in save_logic,
           "saveWorkerConfig must PATCH role")
    expect("initial_prompt" in save_logic, "saveWorkerConfig must PATCH the chosen prompt")

    # 6. Worker list visibly distinguishes Worker vs Reviewer.
    m = re.search(r"function workerRow\(w\)\{(.*?)\}", ui, re.S)
    expect(m, "workerRow missing")
    expect("w.role" in m.group(1), "worker list must render the worker role")

    # 7. Home board has exactly four lanes; merge_pending is not mixed into Review.
    for lane in ("Unclaimed", "Working", "Review", "MergePending"):
        expect(f"<span>{lane}</span>" in ui, f"{lane} lane missing")
    expect('id="merge-cards"' in ui and 'id="merge-count"' in ui, "MergePending lane containers missing")
    expect("repeat(4," in ui, "board must use four columns")
    expect("x.task.state==='review'" in ui.replace(" ", ""),
           "Review lane must contain only task.state=review")
    expect("x.task.state==='merge_pending'" in ui.replace(" ", ""),
           "MergePending lane must contain only task.state=merge_pending")
    expect("['review','merge_pending']" not in ui.replace(" ", "").replace('"', "'"),
           "merge_pending tasks must not be mixed into the Review lane")

    # 8. MergePending has no Approve/Retry UI and indicates main-agent merge handoff.
    expect(">Approve<" not in ui and ">Retry<" not in ui,
           "board must not contain manual Approve/Retry buttons")
    expect(re.search(r"onclick=\"[^\"]*[Aa]pprove", ui) is None, "board must not wire Approve actions")
    m = re.search(r"function mergeCard\(\s*x\s*,\s*pm\s*\)\{([^}]*)\}", ui, re.S)
    expect(m, "mergeCard renderer missing")
    expect("<button" not in m.group(1), "MergePending cards must have no action buttons")
    expect(re.search(r"main agent.*merge|merge.*main agent", ui, re.I),
           "MergePending must indicate the main-agent merge handoff")
    expect("Working · " in ui and "worker-pill" in ui,
           "Working cards must identify the assigned worker")
    expect("Review · " in ui and "reviewer-pill" in ui,
           "Review cards must identify the configured or active reviewer")

    # 9. Fresh-worker provider auth uses Pi-reported capability data and a write-only API-key handoff.
    expect('id="worker-provider-api-key"' in ui, "provider API-key input missing")
    expect("caps.providers||[]" in ui, "provider picker must use worker/Pi-reported provider metadata")
    expect("/provider-key" in ui, "provider API key must be sent through the dedicated write-only endpoint")
    expect("API keys are write-only" in ui, "UI must explain provider key write-only semantics")
    expect("STATIC_PROVIDERS" not in ui and "STATIC_MODELS" not in ui,
           "UI must not contain mock/static provider or model catalogs")

    # 10. Backend review scheduling/runtime files must be untouched by UI work
    #     (guarded by task contract; informational only here).
    print("Management UI regression test passed")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(f"Management UI regression test failed: {exc}", file=sys.stderr)
        sys.exit(1)
