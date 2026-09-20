CREATE TABLE IF NOT EXISTS host_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    review_retry_limit INTEGER NOT NULL DEFAULT 3,
    review_failure_limit INTEGER NOT NULL DEFAULT 3,
    updated_at TEXT NOT NULL
);

INSERT OR IGNORE INTO host_settings(id, review_retry_limit, review_failure_limit, updated_at)
VALUES(1, 3, 3, CURRENT_TIMESTAMP);
