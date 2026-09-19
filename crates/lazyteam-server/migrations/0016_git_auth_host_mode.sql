-- Forward migration for the renamed Host Git auth mode. Older databases store
-- git_auth_mode='worker' for projects that use ambient Host Git / anonymous
-- public repository access. The Worker-named mode never granted upstream
-- credentials to workers; rename the stored value to the Host-owned name.
UPDATE projects SET git_auth_mode = 'host' WHERE git_auth_mode = 'worker';
