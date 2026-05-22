-- RFC 9447 tkauth-01: extra challenge fields and JTI replay-prevention cache.

ALTER TABLE challenges ADD COLUMN tkauth_type TEXT;
ALTER TABLE challenges ADD COLUMN token_authority TEXT;

CREATE TABLE tkauth_jti_cache (
    jti      TEXT    PRIMARY KEY,
    authz_id TEXT    NOT NULL,
    expires  BIGINT  NOT NULL,
    created  BIGINT  NOT NULL
);

CREATE INDEX tkauth_jti_expires_idx ON tkauth_jti_cache (expires);
