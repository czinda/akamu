-- MTC issuance-log checkpoints produced by the CA signing key.
-- Each row captures the Merkle tree state at a specific tree size and stores
-- the CA's DER-encoded signature over the DER-encoded Checkpoint structure.
CREATE TABLE IF NOT EXISTS mtc_checkpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tree_size   INTEGER NOT NULL UNIQUE,   -- log leaf count when checkpoint was produced
    root_hex    TEXT    NOT NULL,          -- lowercase hex Merkle root
    signature   BLOB    NOT NULL,          -- MTC signing key signature over DER Checkpoint
    created     INTEGER NOT NULL           -- Unix epoch seconds
);
CREATE INDEX IF NOT EXISTS idx_mtc_checkpoints_tree_size ON mtc_checkpoints(tree_size DESC);
