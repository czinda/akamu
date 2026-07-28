CREATE TABLE IF NOT EXISTS policy_rules (
    id          VARCHAR(36) PRIMARY KEY,
    scope       VARCHAR(64) NOT NULL,
    name        VARCHAR(255) NOT NULL,
    rule_json   TEXT NOT NULL,
    enabled     TINYINT(1) NOT NULL DEFAULT 1,
    created_at  VARCHAR(30) NOT NULL,
    updated_at  VARCHAR(30) NOT NULL,
    created_by  VARCHAR(255),
    local_gen   BIGINT NOT NULL DEFAULT 0,
    UNIQUE(scope, name)
);
