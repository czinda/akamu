-- Node identity keys: ML-KEM-768 key pair + ECDSA P-256 signing key pair.
-- Generated locally on first start; never replicated via gossip.
CREATE TABLE IF NOT EXISTS node_keys (
    node_id                  TEXT    PRIMARY KEY,
    kem_private_key_der      BYTEA   NOT NULL,
    kem_public_key_der       BYTEA   NOT NULL,
    signing_private_key_der  BYTEA   NOT NULL,
    signing_public_key_der   BYTEA   NOT NULL,
    signing_certificate_der  BYTEA   NOT NULL,
    created_at               BIGINT  NOT NULL
);
