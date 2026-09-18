ALTER TABLE projects ADD COLUMN reviewer_mode TEXT NOT NULL DEFAULT 'manual';
ALTER TABLE projects ADD COLUMN reviewer_prompt TEXT NOT NULL DEFAULT '';
ALTER TABLE tasks ADD COLUMN review_feedback TEXT NOT NULL DEFAULT '';
