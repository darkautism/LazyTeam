ALTER TABLE projects ADD COLUMN git_auth_mode TEXT NOT NULL DEFAULT 'worker';
ALTER TABLE projects ADD COLUMN git_auth_username TEXT;
ALTER TABLE projects ADD COLUMN git_auth_secret TEXT;
