CREATE TABLE agent_session_cleanup (
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    role TEXT NOT NULL CHECK(role IN ('implementation','review')),
    created_at TEXT NOT NULL,
    PRIMARY KEY(task_id, worker_id, role)
);

-- Carry forward implementation cleanups that were queued before session roles
-- existed. The legacy table remains for compatibility with already-running
-- older workers during rollout.
INSERT OR IGNORE INTO agent_session_cleanup(task_id,worker_id,role,created_at)
SELECT task_id,worker_id,'implementation',created_at FROM task_cleanup;
