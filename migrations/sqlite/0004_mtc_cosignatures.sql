CREATE TABLE IF NOT EXISTS mtc_cosignatures (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    checkpoint_id   INTEGER NOT NULL REFERENCES mtc_checkpoints(id),
    cosigner_url    TEXT    NOT NULL,
    signature_der   BLOB    NOT NULL,
    created         INTEGER NOT NULL,
    UNIQUE(checkpoint_id, cosigner_url)
);
CREATE INDEX IF NOT EXISTS idx_mtc_cosignatures_checkpoint ON mtc_cosignatures(checkpoint_id);
