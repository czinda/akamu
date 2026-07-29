-- Replace the table-level UNIQUE(scope, name) which covers tombstoned rows.
-- MariaDB does not support partial indexes, so we use a generated column
-- that is NULL for tombstoned rows.  UNIQUE indexes in MariaDB ignore NULLs,
-- so only live rows participate in the uniqueness check.

ALTER TABLE policy_rules DROP INDEX `scope`;

ALTER TABLE policy_rules
    ADD COLUMN name_live VARCHAR(255) AS (CASE WHEN tombstone = 0 THEN name ELSE NULL END) STORED;

CREATE UNIQUE INDEX uq_policy_rules_scope_name_live
    ON policy_rules (scope, name_live);

-- Covering index for list_by_scope (WHERE scope = ? AND tombstone = 0).
CREATE INDEX idx_policy_rules_scope
    ON policy_rules (scope, tombstone);
