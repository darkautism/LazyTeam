ALTER TABLE projects ADD COLUMN contributor_name TEXT NOT NULL DEFAULT 'LazyTeam Worker';
ALTER TABLE projects ADD COLUMN contributor_email TEXT NOT NULL DEFAULT 'lazyteam@local';
