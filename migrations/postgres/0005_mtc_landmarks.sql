CREATE TABLE IF NOT EXISTS mtc_landmarks (
    id          BIGSERIAL   PRIMARY KEY,
    sequence_no BIGINT      NOT NULL UNIQUE,
    tree_size   BIGINT      NOT NULL UNIQUE,
    cert_der    BYTEA,
    created     BIGINT      NOT NULL
);
