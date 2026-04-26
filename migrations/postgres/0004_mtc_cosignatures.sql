CREATE TABLE IF NOT EXISTS mtc_cosignatures (
    id              BIGSERIAL   PRIMARY KEY,
    checkpoint_id   BIGINT      NOT NULL REFERENCES mtc_checkpoints(id) ON DELETE CASCADE,
    cosigner_url    TEXT        NOT NULL,
    signature_der   BYTEA       NOT NULL,
    created         BIGINT      NOT NULL,
    UNIQUE(checkpoint_id, cosigner_url)
);
CREATE INDEX IF NOT EXISTS idx_mtc_cosignatures_checkpoint ON mtc_cosignatures(checkpoint_id);
