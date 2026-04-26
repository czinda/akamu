CREATE TABLE IF NOT EXISTS mtc_cosignatures (
    id              BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    checkpoint_id   BIGINT      NOT NULL REFERENCES mtc_checkpoints(id) ON DELETE CASCADE,
    cosigner_url    VARCHAR(2048) NOT NULL,
    signature_der   MEDIUMBLOB  NOT NULL,
    created         BIGINT      NOT NULL,
    UNIQUE(checkpoint_id, cosigner_url(512))
);
CREATE INDEX idx_mtc_cosignatures_checkpoint ON mtc_cosignatures(checkpoint_id);
