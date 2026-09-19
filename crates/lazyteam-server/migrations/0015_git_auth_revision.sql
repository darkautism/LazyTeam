ALTER TABLE projects ADD COLUMN git_auth_revision TEXT;
UPDATE projects
SET git_auth_revision = lower(hex(randomblob(16)))
WHERE git_auth_secret IS NOT NULL;
