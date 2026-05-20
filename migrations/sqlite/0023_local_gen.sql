-- Add local_gen column to all CRDT-tracked tables so the node can resume
-- delta gossip after a restart without re-broadcasting unchanged entries.
ALTER TABLE accounts         ADD COLUMN local_gen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE orders           ADD COLUMN local_gen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE authorizations   ADD COLUMN local_gen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE challenges       ADD COLUMN local_gen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE certificates     ADD COLUMN local_gen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE eab_keys         ADD COLUMN local_gen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE operators        ADD COLUMN local_gen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE delegations      ADD COLUMN local_gen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mtc_checkpoints  ADD COLUMN local_gen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE mtc_cosignatures ADD COLUMN local_gen INTEGER NOT NULL DEFAULT 0;
ALTER TABLE audit_events     ADD COLUMN local_gen INTEGER NOT NULL DEFAULT 0;
