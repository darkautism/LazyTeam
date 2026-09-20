-- Minimal durable main-gate event log for Host Insights statistics.
--
-- Existing executions/reviews rows already capture implementation and reviewer
-- quality. The merge gate (merge_pending -> done via tasks_merge /
-- tasks_confirm_merge, merge_pending -> queued via tasks_retry, and Host merge
-- conflicts that redispatch to implementation) previously left no durable
-- per-outcome history, so Insights could only infer gate outcomes from current
-- task state. This table records one row per gate outcome only; it is not a
-- generic outcome/blocker framework.
CREATE TABLE IF NOT EXISTS main_gate_events (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    execution_id TEXT REFERENCES executions(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('merged','sent_back','merge_conflict')),
    reason TEXT NOT NULL DEFAULT '',
    merge_commit_sha TEXT,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_main_gate_task ON main_gate_events(task_id, created_at);
CREATE INDEX IF NOT EXISTS idx_main_gate_kind ON main_gate_events(kind, created_at);
