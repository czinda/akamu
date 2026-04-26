-- MTC issuance-log checkpoints produced by the MTC signing key.
CREATE TABLE IF NOT EXISTS mtc_checkpoints (
    id          BIGSERIAL   PRIMARY KEY,
    tree_size   BIGINT      NOT NULL UNIQUE,
    root_hex    TEXT        NOT NULL,
    signature   BYTEA       NOT NULL,
    created     BIGINT      NOT NULL
);
