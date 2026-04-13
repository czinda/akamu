-- Anti-replay nonces; consumed on first use.
-- In-memory NonceBucket is the primary store on the hot path; this table
-- exists for startup cleanup of nonces written by previous process versions.
CREATE TABLE nonces (
    nonce   TEXT    PRIMARY KEY,
    created BIGINT  NOT NULL  -- Unix epoch seconds
);

-- ACME accounts
CREATE TABLE accounts (
    id             TEXT    PRIMARY KEY,      -- UUID
    status         TEXT    NOT NULL DEFAULT 'valid',  -- valid|deactivated|revoked
    contact        TEXT,                     -- JSON array of mailto: URIs
    public_key     BYTEA   NOT NULL,         -- DER-encoded SubjectPublicKeyInfo
    jwk_thumbprint TEXT    NOT NULL UNIQUE,  -- base64url SHA-256 JWK thumbprint
    created        BIGINT  NOT NULL,         -- Unix epoch seconds
    updated        BIGINT  NOT NULL
);

-- ACME orders
CREATE TABLE orders (
    id                         TEXT    PRIMARY KEY,
    account_id                 TEXT    NOT NULL REFERENCES accounts(id),
    status                     TEXT    NOT NULL DEFAULT 'pending', -- pending|ready|processing|valid|invalid
    expires                    BIGINT,                   -- Unix epoch; NULL = no expiry
    identifiers                TEXT    NOT NULL,         -- JSON [{type,value}]
    not_before                 BIGINT,                   -- Unix epoch; NULL = not set
    not_after                  BIGINT,                   -- Unix epoch; NULL = not set
    error                      TEXT,                     -- problem+json string if invalid
    certificate_id             TEXT,                     -- FK to certificates.id when valid
    replaces                   TEXT,                     -- RFC 9773 ARI: cert_id of predecessor
    created                    BIGINT  NOT NULL,
    updated                    BIGINT  NOT NULL,
    -- RFC 8739 STAR auto-renewal fields
    star_start_date            BIGINT,                   -- Unix timestamp, optional
    star_end_date              BIGINT,                   -- Unix timestamp, required for STAR
    star_lifetime_secs         BIGINT,                   -- lifetime of each cert, seconds
    star_lifetime_adjust_secs  BIGINT  NOT NULL DEFAULT 0,
    star_allow_cert_get        SMALLINT NOT NULL DEFAULT 0,
    star_canceled_at           BIGINT,                   -- set on cancellation
    star_csr_der               BYTEA,                    -- stored CSR DER for reissuance
    -- draft-aaron-acme-profiles-01
    profile                    TEXT
);
CREATE INDEX idx_orders_account  ON orders(account_id);
CREATE INDEX idx_orders_status   ON orders(status);
CREATE INDEX idx_orders_replaces ON orders(replaces) WHERE replaces IS NOT NULL;
CREATE INDEX idx_orders_star     ON orders(star_end_date) WHERE star_end_date IS NOT NULL;

-- ACME authorizations
CREATE TABLE authorizations (
    id                     TEXT    PRIMARY KEY,
    order_id               TEXT    NOT NULL REFERENCES orders(id),
    account_id             TEXT    NOT NULL REFERENCES accounts(id),
    status                 TEXT    NOT NULL DEFAULT 'pending', -- pending|valid|invalid|deactivated|expired|revoked
    identifier             TEXT    NOT NULL,             -- JSON {"type":"dns","value":"example.com"}
    expires                BIGINT,                       -- Unix epoch
    wildcard               SMALLINT NOT NULL DEFAULT 0,
    subdomain_auth_allowed SMALLINT NOT NULL DEFAULT 0, -- RFC 9444
    created                BIGINT  NOT NULL,
    updated                BIGINT  NOT NULL
);
CREATE INDEX idx_authz_order   ON authorizations(order_id);
CREATE INDEX idx_authz_account ON authorizations(account_id);

-- ACME challenges
CREATE TABLE challenges (
    id        TEXT    PRIMARY KEY,
    authz_id  TEXT    NOT NULL REFERENCES authorizations(id),
    type      TEXT    NOT NULL,              -- http-01|dns-01|tls-alpn-01
    status    TEXT    NOT NULL DEFAULT 'pending', -- pending|processing|valid|invalid
    token     TEXT    NOT NULL,              -- random URL-safe base64url string
    validated BIGINT,                        -- Unix epoch when validated
    error     TEXT,                          -- problem+json string if invalid
    created   BIGINT  NOT NULL,
    updated   BIGINT  NOT NULL
);
CREATE INDEX idx_chall_authz ON challenges(authz_id);

-- Issued X.509 certificates
CREATE TABLE certificates (
    id                    TEXT    PRIMARY KEY,   -- UUID used in the cert URL path
    order_id              TEXT    NOT NULL REFERENCES orders(id),
    account_id            TEXT    NOT NULL REFERENCES accounts(id),
    serial_number         TEXT    NOT NULL UNIQUE,  -- hex-encoded serial
    status                TEXT    NOT NULL DEFAULT 'valid', -- valid|revoked
    der                   BYTEA   NOT NULL,      -- full chain DER (leaf + CA)
    pem                   TEXT    NOT NULL,      -- PEM bundle for download
    not_before            BIGINT  NOT NULL,      -- Unix epoch
    not_after             BIGINT  NOT NULL,      -- Unix epoch
    revoked_at            BIGINT,                -- Unix epoch
    revocation_reason     BIGINT,                -- CRL reason code or NULL
    mtc_log_index         BIGINT,                -- MTC transparency log leaf index
    created               BIGINT  NOT NULL,
    -- RFC 9773 ARI suggested renewal window
    suggested_window_start BIGINT,              -- Unix epoch
    suggested_window_end   BIGINT,              -- Unix epoch
    replaced_by           TEXT                  -- RFC 9773: order_id that replaced this cert
);
CREATE INDEX idx_certs_account              ON certificates(account_id);
CREATE INDEX idx_certs_serial               ON certificates(serial_number);
CREATE INDEX idx_certs_order                ON certificates(order_id);
CREATE INDEX idx_certs_status               ON certificates(status);
CREATE INDEX idx_certs_account_status_not_after ON certificates(account_id, status, not_after);
CREATE INDEX idx_certs_replaced_by          ON certificates(replaced_by)
    WHERE replaced_by IS NOT NULL;
CREATE INDEX idx_nonces_created             ON nonces(created);

-- RFC 8555 §7.3.4 External Account Binding key store
CREATE TABLE eab_keys (
    kid           TEXT    PRIMARY KEY,
    hmac_key_b64u TEXT    NOT NULL,
    created       BIGINT  NOT NULL,
    used_at       BIGINT
);
