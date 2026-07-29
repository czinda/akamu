-- Replace the table-level UNIQUE(scope, name) which covers tombstoned rows
-- with a partial unique index that only constrains live (non-tombstoned) rows.
-- Without this, re-creating a rule after soft-delete fails with a constraint
-- violation.

ALTER TABLE policy_rules DROP CONSTRAINT IF EXISTS policy_rules_scope_name_key;

CREATE UNIQUE INDEX uq_policy_rules_scope_name_live
    ON policy_rules (scope, name)
    WHERE tombstone = 0;

-- Covering index for list_by_scope (WHERE scope = ? AND tombstone = 0).
CREATE INDEX idx_policy_rules_scope
    ON policy_rules (scope)
    WHERE tombstone = 0;
