ALTER TABLE workers ADD COLUMN role TEXT NOT NULL DEFAULT 'worker';

CREATE TABLE reviews (
    id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
    execution_id TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    reviewer_worker_id TEXT NOT NULL REFERENCES workers(id) ON DELETE CASCADE,
    state TEXT NOT NULL,
    lease_until TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT,
    verdict TEXT,
    created_at TEXT NOT NULL
);

CREATE UNIQUE INDEX idx_reviews_active_task
ON reviews(task_id)
WHERE state IN ('assigned', 'running');

CREATE INDEX idx_reviews_worker_state
ON reviews(reviewer_worker_id, state);
