-- Replace the table-level UNIQUE(scope, name) which covers tombstoned rows
-- with a partial unique index that only constrains live (non-tombstoned) rows.
-- Without this, re-creating a rule after soft-delete fails with a constraint
-- violation.
--
-- SQLite cannot drop inline UNIQUE constraints, so we recreate the table.
-- WARNING: The CREATE TABLE AS / DROP / RENAME pattern drops ALL indexes on the
-- original table.  Any index added between migrations 0033 and 0035 MUST be
-- re-created below after the RENAME.

CREATE TABLE policy_rules_new (
    id          TEXT PRIMARY KEY,
    scope       TEXT NOT NULL,
    name        TEXT NOT NULL,
    rule_json   TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL,
    created_by  TEXT,
    local_gen   INTEGER NOT NULL DEFAULT 0,
    tombstone   INTEGER NOT NULL DEFAULT 0,
    tombstone_at INTEGER,
    CHECK ((tombstone = 0 AND tombstone_at IS NULL) OR (tombstone = 1 AND tombstone_at IS NOT NULL))
);

INSERT INTO policy_rules_new
    SELECT id, scope, name, rule_json, enabled, created_at, updated_at,
           created_by, local_gen, tombstone, tombstone_at
    FROM policy_rules;

DROP TABLE policy_rules;
ALTER TABLE policy_rules_new RENAME TO policy_rules;

CREATE UNIQUE INDEX uq_policy_rules_scope_name_live
    ON policy_rules (scope, name)
    WHERE tombstone = 0;

-- Covering index for list_by_scope (WHERE scope = ? AND tombstone = 0).
CREATE INDEX idx_policy_rules_scope
    ON policy_rules (scope)
    WHERE tombstone = 0;
