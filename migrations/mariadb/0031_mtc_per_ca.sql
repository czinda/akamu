-- Add ca_id to MTC tables for per-CA transparency logs.
-- Existing rows default to 'default' (the legacy single-CA configuration).

ALTER TABLE mtc_checkpoints ADD COLUMN ca_id VARCHAR(64) NOT NULL DEFAULT 'default';
ALTER TABLE mtc_landmarks ADD COLUMN ca_id VARCHAR(64) NOT NULL DEFAULT 'default';
ALTER TABLE mtc_cosignatures ADD COLUMN ca_id VARCHAR(64) NOT NULL DEFAULT 'default';

-- Replace the original single-column UNIQUE constraints with composites.
ALTER TABLE mtc_checkpoints DROP INDEX tree_size, ADD UNIQUE INDEX mtc_checkpoints_ca_tree (ca_id, tree_size);
ALTER TABLE mtc_landmarks DROP INDEX sequence_no, ADD UNIQUE INDEX mtc_landmarks_ca_seq (ca_id, sequence_no);
ALTER TABLE mtc_landmarks DROP INDEX tree_size, ADD UNIQUE INDEX mtc_landmarks_ca_tree (ca_id, tree_size);
