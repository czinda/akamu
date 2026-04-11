-- RFC 8555 §7.3.4 External Account Binding key store.
-- kid         — the external account key identifier, unique
-- hmac_key_b64u — base64url-encoded raw HMAC key bytes
-- created     — Unix timestamp when the key was provisioned
-- used_at     — Unix timestamp when the key was consumed (NULL = unused)
CREATE TABLE eab_keys (
    kid           TEXT    PRIMARY KEY,
    hmac_key_b64u TEXT    NOT NULL,
    created       INTEGER NOT NULL,
    used_at       INTEGER
);
