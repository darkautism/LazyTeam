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
    expect("project-pill" in ui and "projectPill(p)" in ui,
           "every task-card renderer must include a compact project pill")

    # 9. Worker/project routing UI uses human-readable comma-separated selectors.
    expect('id="worker-config-projects"' in ui, "Allowed projects input missing")
    expect("Comma-separated project slugs" in ui and "parseProjectInput" in ui,
           "Allowed projects must document and parse comma-separated slugs")
    expect("worker-system-tags" not in ui and ">System tags<" not in ui,
           "read-only system tags must not consume worker configuration space")
    expect('id="project-runner-labels"' in ui, "Project Runs on input missing")
    expect("All labels are required (AND)" in ui and "parseRunnerLabels" in ui,
           "Project Runs on must use AND-style human-readable runner labels")
    expect("Advanced tags" not in ui and "project-worker-tags" not in ui and "project-task-tags" not in ui,
           "JSON Advanced tags UI must be removed")

    # 10. Project Git credential source is explicit; server-managed tokens cannot be silently ignored.
    expect('id="project-git-auth-mode"' in ui, "project Git auth selector missing")
    expect('project-git-worker-managed' not in ui,
           "ambiguous worker-managed Git checkbox must not coexist with server credential fields")
    expect('<option value="host">No stored credential</option>' in ui and
           '<option value="https_basic">HTTPS username + token/password</option>' in ui,
           "project Git auth selector must distinguish no stored credential from stored HTTPS auth")
    expect('Upstream Git access (Host only)' in ui and 'workers never access upstream directly' in ui,
           "project Git UI must state that upstream credentials stay on the Host")
    expect('Advanced review' not in ui and 'project-reviewer-prompt' not in ui,
           "Project must not expose a redundant reviewer prompt; reviewer workers own Initial prompt")
    expect('x-access-token' in ui and "github\\.com[:/]" in ui,
           "GitHub token mode should supply a usable default username")
    expect('Git credential was not stored; project remains unusable.' in ui,
           "project save must fail visibly if a selected server-managed credential was not persisted")

    # 11. Worker logs are separate from settings, paginated, and polling avoids rebuilding unchanged DOM.
    expect('id="worker-log-dialog"' in ui and 'id="worker-log-content"' in ui,
           "worker provisioning log must live in its own dialog")
    expect('worker-capability-log-details' not in ui,
           "worker provisioning log must not be embedded in Configure worker")
    expect('aria-label="Configure worker"' in ui and 'aria-label="Worker log"' in ui,
           "worker row must expose separate settings/log icon actions")
    expect('WORKER_LOG_PAGE_LINES=100' in ui and 'changeWorkerLogPage' in ui,
           "worker log must provide 100-line pagination")
    expect('workerListSignature' in ui and 'if(html!==workerListSignature)' in ui,
           "worker list polling must not replace unchanged DOM")
    expect('signature===workerLogSignature' in ui and 'workerConfigCatalogSignature' in ui,
           "log/config polling must skip unchanged content to prevent flicker")

    # 12. Fresh-worker provider auth uses Pi-reported capability data and a write-only API-key handoff.
    expect('id="worker-provider-api-key"' in ui, "provider API-key input missing")
    expect("caps.providers||[]" in ui, "provider picker must use worker/Pi-reported provider metadata")
    expect("/provider-key" in ui, "provider API key must be sent through the dedicated write-only endpoint")
    expect("API keys are write-only" in ui, "UI must explain provider key write-only semantics")
    expect("STATIC_PROVIDERS" not in ui and "STATIC_MODELS" not in ui,
           "UI must not contain mock/static provider or model catalogs")

    # 13. OAuth sign-in must pre-open a tab in the click gesture and navigate
    #     it to the worker-reported authorization URL (pi-web behavior).
    expect("window.open('about:blank','_blank')" in ui,
           "Sign in must pre-open a blank tab synchronously to avoid popup blocking")
    expect("oauthAuthTabNavigated" in ui and "navigateOAuthTab" in ui,
           "sign-in tab must navigate exactly once when authorization_url arrives")
    expect("oauthAuthTab.location.href=" in ui,
           "sign-in tab must navigate to the reported authorization URL")
    expect("unreachable localhost page" in ui,
           "paste-back guidance must tell the user to copy the final localhost address-bar URL")

    # 14. Settings polling uses an edit generation plus a refresh/save epoch:
    #     only the latest refresh whose generation is current and whose draft
    #     is clean may write the inputs; Save invalidates in-flight
    #     refreshes both when it starts and when it completes, so a refresh
    #     started before or during the PATCH can never overwrite just-saved
    #     values with a stale GET.
    expect("settingsGen" in ui and "settingsRefreshSeq" in ui,
           "settings polling must track an edit generation and a refresh/save epoch")
    expect("seq=++settingsRefreshSeq" in ui and "seq!==settingsRefreshSeq" in ui,
           "only the latest eligible refresh may write the settings inputs")
    expect("gen!==settingsGen" in ui and "writeSettingsInputs" in ui,
           "stale refresh/save responses must not overwrite newer drafts")

    # 15. Backend review scheduling/runtime files must be untouched by UI work
    #     (guarded by task contract; informational only here).
    print("Management UI regression test passed")


if __name__ == "__main__":
    try:
        main()
    except AssertionError as exc:
        print(f"Management UI regression test failed: {exc}", file=sys.stderr)
        sys.exit(1)
