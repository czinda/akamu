-- FIA_AFL.1: per-operator authentication lockout after repeated failures.
ALTER TABLE operators ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operators ADD COLUMN locked_until TEXT;
