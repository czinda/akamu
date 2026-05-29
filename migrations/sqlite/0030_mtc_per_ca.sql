-- Add ca_id to MTC tables for per-CA transparency logs.
-- SQLite cannot DROP CONSTRAINT, so we recreate each table to replace the
-- single-column UNIQUE constraints with composite (ca_id, ...) ones.
-- Existing rows are preserved with ca_id = 'default'.

-- ── mtc_checkpoints ─────────────────────────────────────────────────────────
CREATE TABLE mtc_checkpoints_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id       TEXT    NOT NULL DEFAULT 'default',
    tree_size   INTEGER NOT NULL,
    root_hex    TEXT    NOT NULL,
    signature   BLOB    NOT NULL,
    created     INTEGER NOT NULL,
    local_gen   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(ca_id, tree_size)
);
INSERT INTO mtc_checkpoints_new (id, ca_id, tree_size, root_hex, signature, created, local_gen)
    SELECT id, 'default', tree_size, root_hex, signature, created, local_gen
    FROM mtc_checkpoints;
DROP TABLE mtc_checkpoints;
ALTER TABLE mtc_checkpoints_new RENAME TO mtc_checkpoints;

-- ── mtc_landmarks ───────────────────────────────────────────────────────────
CREATE TABLE mtc_landmarks_new (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id       TEXT    NOT NULL DEFAULT 'default',
    sequence_no INTEGER NOT NULL,
    tree_size   INTEGER NOT NULL,
    cert_der    BLOB,
    created     INTEGER NOT NULL,
    UNIQUE(ca_id, sequence_no),
    UNIQUE(ca_id, tree_size)
);
INSERT INTO mtc_landmarks_new (id, ca_id, sequence_no, tree_size, cert_der, created)
    SELECT id, 'default', sequence_no, tree_size, cert_der, created
    FROM mtc_landmarks;
DROP TABLE mtc_landmarks;
ALTER TABLE mtc_landmarks_new RENAME TO mtc_landmarks;

-- ── mtc_cosignatures ────────────────────────────────────────────────────────
CREATE TABLE mtc_cosignatures_new (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id           TEXT    NOT NULL DEFAULT 'default',
    checkpoint_id   INTEGER NOT NULL REFERENCES mtc_checkpoints(id) ON DELETE CASCADE,
    cosigner_url    TEXT    NOT NULL,
    signature_der   BLOB    NOT NULL,
    created         INTEGER NOT NULL,
    local_gen       INTEGER NOT NULL DEFAULT 0,
    UNIQUE(checkpoint_id, cosigner_url)
);
INSERT INTO mtc_cosignatures_new (id, ca_id, checkpoint_id, cosigner_url, signature_der, created, local_gen)
    SELECT id, 'default', checkpoint_id, cosigner_url, signature_der, created, local_gen
    FROM mtc_cosignatures;
DROP TABLE mtc_cosignatures;
ALTER TABLE mtc_cosignatures_new RENAME TO mtc_cosignatures;
CREATE INDEX IF NOT EXISTS idx_mtc_cosignatures_checkpoint ON mtc_cosignatures(checkpoint_id);
