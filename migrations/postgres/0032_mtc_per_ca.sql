-- Add ca_id to MTC tables for per-CA transparency logs.
-- Existing rows default to 'default' (the legacy single-CA configuration).

ALTER TABLE mtc_checkpoints ADD COLUMN ca_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE mtc_landmarks ADD COLUMN ca_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE mtc_cosignatures ADD COLUMN ca_id TEXT NOT NULL DEFAULT 'default';

-- Replace the original single-column UNIQUE constraints with composites.
ALTER TABLE mtc_checkpoints DROP CONSTRAINT IF EXISTS mtc_checkpoints_tree_size_key;
ALTER TABLE mtc_checkpoints ADD CONSTRAINT mtc_checkpoints_ca_tree UNIQUE (ca_id, tree_size);

ALTER TABLE mtc_landmarks DROP CONSTRAINT IF EXISTS mtc_landmarks_sequence_no_key;
ALTER TABLE mtc_landmarks DROP CONSTRAINT IF EXISTS mtc_landmarks_tree_size_key;
ALTER TABLE mtc_landmarks ADD CONSTRAINT mtc_landmarks_ca_seq UNIQUE (ca_id, sequence_no);
ALTER TABLE mtc_landmarks ADD CONSTRAINT mtc_landmarks_ca_tree UNIQUE (ca_id, tree_size);
