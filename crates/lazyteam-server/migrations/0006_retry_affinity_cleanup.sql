ALTER TABLE tasks ADD COLUMN sticky_worker_id TEXT;
ALTER TABLE tasks ADD COLUMN merge_commit_sha TEXT;
UPDATE projects SET reviewer_mode='mcp' WHERE reviewer_mode='manual';
CREATE TABLE task_cleanup (
    task_id TEXT PRIMARY KEY REFERENCES tasks(id) ON DELETE CASCADE,
    worker_id TEXT NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);
