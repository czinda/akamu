-- Enable WAL mode and foreign key enforcement
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Anti-replay nonces; consumed on first use
CREATE TABLE nonces (
    nonce   TEXT    PRIMARY KEY,
    created INTEGER NOT NULL  -- Unix epoch seconds
);

-- ACME accounts
CREATE TABLE accounts (
    id             TEXT    PRIMARY KEY,      -- UUID
    status         TEXT    NOT NULL DEFAULT 'valid',  -- valid|deactivated|revoked
    contact        TEXT,                     -- JSON array of mailto: URIs
    public_key     BLOB    NOT NULL,         -- DER-encoded SubjectPublicKeyInfo
    jwk_thumbprint TEXT    NOT NULL UNIQUE,  -- base64url SHA-256 JWK thumbprint
    created        INTEGER NOT NULL,         -- Unix epoch seconds
    updated        INTEGER NOT NULL
);

-- ACME orders
CREATE TABLE orders (
    id             TEXT    PRIMARY KEY,
    account_id     TEXT    NOT NULL REFERENCES accounts(id),
    status         TEXT    NOT NULL DEFAULT 'pending', -- pending|ready|processing|valid|invalid
    expires        INTEGER,                  -- Unix epoch; NULL = no expiry
    identifiers    TEXT    NOT NULL,         -- JSON [{type,value}]
    not_before     INTEGER,                  -- Unix epoch; NULL = not set
    not_after      INTEGER,                  -- Unix epoch; NULL = not set
    error          TEXT,                     -- problem+json string if invalid
    certificate_id TEXT,                     -- FK to certificates.id when valid
    created        INTEGER NOT NULL,
    updated        INTEGER NOT NULL
);
CREATE INDEX idx_orders_account ON orders(account_id);
CREATE INDEX idx_orders_status  ON orders(status);

-- ACME authorizations
CREATE TABLE authorizations (
    id         TEXT    PRIMARY KEY,
    order_id   TEXT    NOT NULL REFERENCES orders(id),
    account_id TEXT    NOT NULL REFERENCES accounts(id),
    status     TEXT    NOT NULL DEFAULT 'pending', -- pending|valid|invalid|deactivated|expired|revoked
    identifier TEXT    NOT NULL,             -- JSON {"type":"dns","value":"example.com"}
    expires    INTEGER,                      -- Unix epoch
    wildcard   INTEGER NOT NULL DEFAULT 0,   -- 0=false, 1=true
    created    INTEGER NOT NULL,
    updated    INTEGER NOT NULL
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
    validated INTEGER,                       -- Unix epoch when validated
    error     TEXT,                          -- problem+json string if invalid
    created   INTEGER NOT NULL,
    updated   INTEGER NOT NULL
);
CREATE INDEX idx_chall_authz ON challenges(authz_id);

-- Issued X.509 certificates
CREATE TABLE certificates (
    id                TEXT    PRIMARY KEY,   -- UUID used in the cert URL path
    order_id          TEXT    NOT NULL REFERENCES orders(id),
    account_id        TEXT    NOT NULL REFERENCES accounts(id),
    serial_number     TEXT    NOT NULL UNIQUE,  -- hex-encoded serial
    status            TEXT    NOT NULL DEFAULT 'valid', -- valid|revoked
    der               BLOB    NOT NULL,      -- full chain DER (leaf + CA)
    pem               TEXT    NOT NULL,      -- PEM bundle for download
    not_before        INTEGER NOT NULL,      -- Unix epoch
    not_after         INTEGER NOT NULL,      -- Unix epoch
    revoked_at        INTEGER,               -- Unix epoch
    revocation_reason INTEGER,               -- CRL reason code or NULL
    mtc_log_index     INTEGER,               -- MTC transparency log leaf index
    created           INTEGER NOT NULL
);
CREATE INDEX idx_certs_account ON certificates(account_id);
CREATE INDEX idx_certs_serial  ON certificates(serial_number);
CREATE INDEX idx_certs_order   ON certificates(order_id);
