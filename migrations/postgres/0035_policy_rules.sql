CREATE TABLE IF NOT EXISTS policy_rules (
    id          TEXT PRIMARY KEY,
    scope       TEXT NOT NULL,
    name        TEXT NOT NULL,
    rule_json   TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    created_by  TEXT,
    local_gen   BIGINT NOT NULL DEFAULT 0,
    UNIQUE(scope, name)
);
