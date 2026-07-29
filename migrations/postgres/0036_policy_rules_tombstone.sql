ALTER TABLE policy_rules ADD COLUMN tombstone INTEGER NOT NULL DEFAULT 0;
ALTER TABLE policy_rules ADD COLUMN tombstone_at BIGINT;
ALTER TABLE policy_rules ADD CONSTRAINT ck_policy_tombstone_consistency CHECK (
    (tombstone = 0 AND tombstone_at IS NULL) OR
    (tombstone = 1 AND tombstone_at IS NOT NULL)
);
