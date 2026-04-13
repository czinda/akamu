-- Anti-replay nonces; consumed on first use.
-- In-memory NonceBucket is the primary store on the hot path; this table
-- exists for startup cleanup of nonces written by previous process versions.
CREATE TABLE nonces (
    nonce   VARCHAR(255) PRIMARY KEY,
    created BIGINT       NOT NULL  -- Unix epoch seconds
);

-- ACME accounts
CREATE TABLE accounts (
    id             VARCHAR(64)  PRIMARY KEY,      -- UUID
    status         VARCHAR(20)  NOT NULL DEFAULT 'valid',  -- valid|deactivated|revoked
    contact        TEXT,                           -- JSON array of mailto: URIs
    public_key     MEDIUMBLOB   NOT NULL,          -- DER-encoded SubjectPublicKeyInfo
    jwk_thumbprint VARCHAR(255) NOT NULL UNIQUE,   -- base64url SHA-256 JWK thumbprint
    created        BIGINT       NOT NULL,           -- Unix epoch seconds
    updated        BIGINT       NOT NULL
);

-- ACME orders
CREATE TABLE orders (
    id                         VARCHAR(64)  PRIMARY KEY,
    account_id                 VARCHAR(64)  NOT NULL REFERENCES accounts(id),
    status                     VARCHAR(20)  NOT NULL DEFAULT 'pending',
    expires                    BIGINT,
    identifiers                TEXT         NOT NULL,
    not_before                 BIGINT,
    not_after                  BIGINT,
    error                      TEXT,
    certificate_id             VARCHAR(64),
    replaces                   VARCHAR(255),
    created                    BIGINT       NOT NULL,
    updated                    BIGINT       NOT NULL,
    -- RFC 8739 STAR auto-renewal fields
    star_start_date            BIGINT,
    star_end_date              BIGINT,
    star_lifetime_secs         BIGINT,
    star_lifetime_adjust_secs  BIGINT       NOT NULL DEFAULT 0,
    star_allow_cert_get        TINYINT(1)   NOT NULL DEFAULT 0,
    star_canceled_at           BIGINT,
    star_csr_der               MEDIUMBLOB,
    -- draft-aaron-acme-profiles-01
    profile                    VARCHAR(255)
);
CREATE INDEX idx_orders_account  ON orders(account_id);
CREATE INDEX idx_orders_status   ON orders(status);
-- MariaDB does not support partial indexes (WHERE clause); use a full index instead.
CREATE INDEX idx_orders_replaces ON orders(replaces);
CREATE INDEX idx_orders_star     ON orders(star_end_date);

-- ACME authorizations
CREATE TABLE authorizations (
    id                     VARCHAR(64)  PRIMARY KEY,
    order_id               VARCHAR(64)  NOT NULL REFERENCES orders(id),
    account_id             VARCHAR(64)  NOT NULL REFERENCES accounts(id),
    status                 VARCHAR(20)  NOT NULL DEFAULT 'pending',
    identifier             TEXT         NOT NULL,
    expires                BIGINT,
    wildcard               TINYINT(1)   NOT NULL DEFAULT 0,
    subdomain_auth_allowed TINYINT(1)   NOT NULL DEFAULT 0,
    created                BIGINT       NOT NULL,
    updated                BIGINT       NOT NULL
);
CREATE INDEX idx_authz_order   ON authorizations(order_id);
CREATE INDEX idx_authz_account ON authorizations(account_id);

-- ACME challenges
CREATE TABLE challenges (
    id        VARCHAR(64)  PRIMARY KEY,
    authz_id  VARCHAR(64)  NOT NULL REFERENCES authorizations(id),
    type      VARCHAR(30)  NOT NULL,
    status    VARCHAR(20)  NOT NULL DEFAULT 'pending',
    token     VARCHAR(255) NOT NULL,
    validated BIGINT,
    error     TEXT,
    created   BIGINT       NOT NULL,
    updated   BIGINT       NOT NULL
);
CREATE INDEX idx_chall_authz ON challenges(authz_id);

-- Issued X.509 certificates
CREATE TABLE certificates (
    id                     VARCHAR(64)  PRIMARY KEY,
    order_id               VARCHAR(64)  NOT NULL REFERENCES orders(id),
    account_id             VARCHAR(64)  NOT NULL REFERENCES accounts(id),
    serial_number          VARCHAR(255) NOT NULL UNIQUE,
    status                 VARCHAR(20)  NOT NULL DEFAULT 'valid',
    der                    MEDIUMBLOB   NOT NULL,
    pem                    MEDIUMTEXT   NOT NULL,
    not_before             BIGINT       NOT NULL,
    not_after              BIGINT       NOT NULL,
    revoked_at             BIGINT,
    revocation_reason      BIGINT,
    mtc_log_index          BIGINT,
    created                BIGINT       NOT NULL,
    -- RFC 9773 ARI suggested renewal window
    suggested_window_start BIGINT,
    suggested_window_end   BIGINT,
    replaced_by            VARCHAR(64)
);
CREATE INDEX idx_certs_account              ON certificates(account_id);
CREATE INDEX idx_certs_serial               ON certificates(serial_number);
CREATE INDEX idx_certs_order                ON certificates(order_id);
CREATE INDEX idx_certs_status               ON certificates(status);
CREATE INDEX idx_certs_account_status_not_after ON certificates(account_id, status, not_after);
-- MariaDB does not support partial indexes; use a full index.
CREATE INDEX idx_certs_replaced_by          ON certificates(replaced_by);
CREATE INDEX idx_nonces_created             ON nonces(created);

-- RFC 8555 §7.3.4 External Account Binding key store
CREATE TABLE eab_keys (
    kid           VARCHAR(255) PRIMARY KEY,
    hmac_key_b64u TEXT         NOT NULL,
    created       BIGINT       NOT NULL,
    used_at       BIGINT
);
