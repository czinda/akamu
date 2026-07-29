ALTER TABLE policy_rules ADD COLUMN tombstone INTEGER NOT NULL DEFAULT 0;
ALTER TABLE policy_rules ADD COLUMN tombstone_at INTEGER;
-- Note: SQLite cannot add CHECK constraints via ALTER TABLE ADD COLUMN.
-- PostgreSQL and MariaDB enforce ck_policy_tombstone_consistency:
--   (tombstone = 0 AND tombstone_at IS NULL) OR (tombstone = 1 AND tombstone_at IS NOT NULL)
-- Application-level enforcement in src/db/policy_rules.rs covers this invariant.
