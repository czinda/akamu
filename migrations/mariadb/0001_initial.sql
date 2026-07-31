-- ACME accounts
CREATE TABLE accounts (
    id                 VARCHAR(64)  PRIMARY KEY,      -- UUID
    status             VARCHAR(20)  NOT NULL DEFAULT 'valid',  -- valid|deactivated|revoked
    contact            TEXT,                           -- JSON array of mailto: URIs
    public_key         MEDIUMBLOB   NOT NULL,          -- DER-encoded SubjectPublicKeyInfo
    jwk_thumbprint     VARCHAR(255) NOT NULL UNIQUE,   -- base64url SHA-256 JWK thumbprint
    created            BIGINT       NOT NULL,           -- Unix epoch seconds
    updated            BIGINT       NOT NULL,
    profile_grants     TEXT,
    ca_id              VARCHAR(64)  NOT NULL DEFAULT '',
    local_gen          BIGINT       NOT NULL DEFAULT 0,
    kerberos_principal TEXT,
    -- MariaDB 10.2.1+ enforces CHECK constraints
    CHECK(status IN ('valid','deactivated','revoked'))
);
CREATE INDEX idx_accounts_ca_id ON accounts(ca_id);

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
    profile                    VARCHAR(255),
    -- Multi-CA (ca_id) and RFC 9115 delegation fields.
    -- delegation_id's FK (fk_orders_delegation) is added below, once the
    -- delegations table exists.
    ca_id                      VARCHAR(64)  NOT NULL DEFAULT 'default',
    delegation_id              VARCHAR(64),
    allow_cert_get             TINYINT(1)   NOT NULL DEFAULT 0,
    upstream_order_url         TEXT,
    upstream_cert_url          TEXT,
    local_gen                  BIGINT       NOT NULL DEFAULT 0,
    CHECK(status IN ('pending','ready','processing','valid','invalid','canceled'))
);
CREATE INDEX idx_orders_account  ON orders(account_id);
CREATE INDEX idx_orders_status   ON orders(status);
-- MariaDB does not support partial indexes (WHERE clause); use a full index instead.
CREATE INDEX idx_orders_replaces ON orders(replaces);
CREATE INDEX idx_orders_star     ON orders(star_end_date);
CREATE INDEX idx_orders_ca_id ON orders(ca_id);
CREATE INDEX idx_orders_ca_account ON orders(ca_id, account_id);
-- MariaDB does not support partial indexes; full index on delegation_id.
CREATE INDEX idx_orders_delegation ON orders(delegation_id);
CREATE INDEX idx_orders_delegation_status ON orders(delegation_id, status);

-- ACME authorizations
CREATE TABLE authorizations (
    id                     VARCHAR(64)  PRIMARY KEY,
    order_id               VARCHAR(64)  REFERENCES orders(id), -- NULL for RFC 8555 §7.4.1 standalone pre-authorizations
    account_id             VARCHAR(64)  NOT NULL REFERENCES accounts(id),
    status                 VARCHAR(20)  NOT NULL DEFAULT 'pending',
    identifier             TEXT         NOT NULL,
    expires                BIGINT,
    wildcard               TINYINT(1)   NOT NULL DEFAULT 0,
    subdomain_auth_allowed TINYINT(1)   NOT NULL DEFAULT 0,
    created                BIGINT       NOT NULL,
    updated                BIGINT       NOT NULL,
    ca_id                  VARCHAR(64)  NOT NULL DEFAULT 'default',
    local_gen              BIGINT       NOT NULL DEFAULT 0,
    CHECK(status IN ('pending','valid','invalid','deactivated','expired','revoked'))
);
CREATE INDEX idx_authz_order   ON authorizations(order_id);
CREATE INDEX idx_authz_account ON authorizations(account_id);
CREATE INDEX idx_authzs_ca_id  ON authorizations(ca_id);
-- Hot-path index (see original 0022_hot_indexes.sql); the partial-index
-- equivalent (idx_authz_order_nonvalid in postgres) is skipped since
-- MariaDB has no WHERE-clause partial indexes and a full index here would
-- just duplicate idx_authz_order.
CREATE INDEX idx_authz_acct_ident ON authorizations(account_id, identifier);

-- ACME challenges
CREATE TABLE challenges (
    id                VARCHAR(64)  PRIMARY KEY,
    authz_id          VARCHAR(64)  NOT NULL REFERENCES authorizations(id),
    type              VARCHAR(30)  NOT NULL,
    status            VARCHAR(20)  NOT NULL DEFAULT 'pending',
    token             VARCHAR(255) NOT NULL,
    validated         BIGINT,
    error             TEXT,
    created           BIGINT       NOT NULL,
    updated           BIGINT       NOT NULL,
    -- RFC 8823 email-reply-00 challenge state
    email_token_part1 TEXT,
    email_message_id  TEXT,
    local_gen         BIGINT       NOT NULL DEFAULT 0,
    -- RFC 9447 tkauth-01 fields
    tkauth_type       TEXT,
    token_authority   TEXT,
    CHECK(status IN ('pending','processing','valid','invalid'))
);
CREATE INDEX idx_chall_authz ON challenges(authz_id);
-- Unique index on email_message_id; duplicate webhook deliveries for the same
-- Message-ID are caught at the storage layer. InnoDB unique indexes permit
-- multiple NULL values (NULL != NULL semantics), so no partial-index syntax
-- is needed. Prefix length 255 is required for TEXT columns in all InnoDB
-- row formats.
CREATE UNIQUE INDEX idx_chall_email_message_id
    ON challenges(email_message_id(255));

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
    replaced_by            VARCHAR(64),
    mtc_standalone_der     MEDIUMBLOB,
    subject_dn             TEXT,
    ca_id                  VARCHAR(64)  NOT NULL DEFAULT 'default',
    local_gen              BIGINT       NOT NULL DEFAULT 0,
    CHECK(status IN ('valid','revoked'))
);
CREATE INDEX idx_certs_account              ON certificates(account_id);
CREATE INDEX idx_certs_serial               ON certificates(serial_number);
CREATE INDEX idx_certs_order                ON certificates(order_id);
CREATE INDEX idx_certs_status               ON certificates(status);
CREATE INDEX idx_certs_account_status_not_after ON certificates(account_id, status, not_after);
-- MariaDB does not support partial indexes; use a full index.
CREATE INDEX idx_certs_replaced_by          ON certificates(replaced_by);
CREATE INDEX idx_certs_mtc_log_index        ON certificates(mtc_log_index);
CREATE INDEX idx_certs_subject_dn           ON certificates(subject_dn);
CREATE INDEX idx_certs_ca_id                ON certificates(ca_id);
-- Composite index for CRL generation; MariaDB does not support partial
-- indexes, so this full composite index replaces the WHERE status='revoked' form.
CREATE INDEX idx_certs_ca_id_status ON certificates(ca_id, status);

-- Anti-replay nonces; consumed on first use.
-- In-memory NonceBucket is the primary store on the hot path; this table
-- exists for startup cleanup of nonces written by previous process versions.
CREATE TABLE nonces (
    nonce   VARCHAR(255) PRIMARY KEY,
    created BIGINT       NOT NULL  -- Unix epoch seconds
);
CREATE INDEX idx_nonces_created ON nonces(created);

-- RFC 8555 §7.3.4 External Account Binding key store.
-- created_by_operator_id's FK to operators.id is added below
-- (fk_eab_keys_operator), once the operators table exists.
CREATE TABLE eab_keys (
    kid                    VARCHAR(255) PRIMARY KEY,
    hmac_key_b64u          TEXT         NOT NULL,
    created                BIGINT       NOT NULL,
    used_at                BIGINT,
    profile_grants         TEXT,
    created_by_operator_id BIGINT,
    bound_principal        TEXT,
    alg                    TEXT         NOT NULL DEFAULT 'sha256',  -- sha256|sha384|sha512
    local_gen              BIGINT       NOT NULL DEFAULT 0,
    -- MariaDB 10.2.1+ enforces CHECK constraints
    CONSTRAINT chk_eab_alg CHECK (alg IN ('sha256', 'sha384', 'sha512'))
);

-- PP CA v2.1 FMT: operator accounts with role-based access control.
--
-- Each operator is identified by a client certificate fingerprint, a
-- Kerberos principal, or both.  At least one must be non-NULL (enforced by
-- the CHECK constraint).
CREATE TABLE operators (
    id               BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name             VARCHAR(255) NOT NULL UNIQUE,
    role             VARCHAR(32)  NOT NULL,     -- administrator|ca_operations|ca_ra|auditor
    cert_fingerprint VARCHAR(128) UNIQUE,       -- SHA-256 hex; NULL = no cert auth
    gssapi_principal VARCHAR(255) UNIQUE,       -- Kerberos principal; NULL = no GSSAPI auth
    created_at       VARCHAR(40)  NOT NULL,     -- RFC 3339
    last_seen_at     VARCHAR(40),               -- RFC 3339
    active           BIGINT       NOT NULL DEFAULT 1,
    failed_attempts  INTEGER      NOT NULL DEFAULT 0,  -- FIA_AFL.1 lockout counter
    locked_until     TEXT,                      -- RFC 3339; NULL = not locked
    ca_id            VARCHAR(64)  NOT NULL DEFAULT '', -- '' = server-wide; else scoped to one CA
    local_gen        BIGINT       NOT NULL DEFAULT 0,
    -- MariaDB 10.2.1+ enforces CHECK constraints
    CHECK(role IN ('administrator','ca_operations','ca_ra','auditor')),
    CHECK(active IN (0, 1)),
    CHECK(cert_fingerprint IS NOT NULL OR gssapi_principal IS NOT NULL)
);

-- Deferred FK: eab_keys.created_by_operator_id -> operators.id.
-- Declared here (rather than inline on eab_keys) because eab_keys is created
-- earlier in this file, before the operators table exists.
ALTER TABLE eab_keys
    ADD CONSTRAINT fk_eab_keys_operator
    FOREIGN KEY (created_by_operator_id)
    REFERENCES operators(id)
    ON DELETE SET NULL;

-- Cross-certificates: CA certificates issued by one akamu CA for another CA's
-- public key (same-server CA or an external CA supplied by PEM).
--
-- Used to construct alternative trust chains when multiple CAs are deployed
-- (e.g. an RSA CA cross-signing an ML-DSA CA's public key so relying parties
-- with only RSA trust anchors can still verify ML-DSA end-entity certificates).
--
-- Rows are insert-only (never mutated after creation), so no `updated` timestamp.
CREATE TABLE cross_certs (
    id              VARCHAR(36)   NOT NULL PRIMARY KEY,  -- UUID
    issuer_ca_id    VARCHAR(64)   NOT NULL,              -- CA that signed the cross-cert
    subject_ca_id   VARCHAR(64)   DEFAULT NULL,          -- akamu CA ID if same-server, NULL if external
    subject_dn      TEXT          NOT NULL,              -- RFC 4514 subject DN string
    subject_spki    MEDIUMBLOB    NOT NULL,              -- DER SubjectPublicKeyInfo of subject CA key
    cross_cert_der  MEDIUMBLOB    NOT NULL,              -- DER of the issued cross-certificate
    cross_cert_pem  MEDIUMTEXT    NOT NULL,              -- PEM for download
    not_before      BIGINT        NOT NULL,              -- Unix epoch
    not_after       BIGINT        NOT NULL,              -- Unix epoch
    serial_number   VARCHAR(255)  NOT NULL,              -- hex-encoded serial (matches certificates table)
    created         BIGINT        NOT NULL,              -- Unix epoch
    UNIQUE (issuer_ca_id, serial_number)                 -- RFC 5280: unique within issuing CA
);
CREATE INDEX idx_cross_certs_issuer  ON cross_certs(issuer_ca_id);
-- MariaDB does not support partial indexes; full index on subject_ca_id.
CREATE INDEX idx_cross_certs_subject ON cross_certs(subject_ca_id);

-- RFC 9115 ACME profile for delegated certificates.
--
-- Delegation objects represent a pre-configured delegation from an Identifier Owner (IdO)
-- to a Name Delegation Consumer (NDC).  Each delegation carries a CSR template that the
-- NDC must satisfy when submitting finalize requests, and an optional CNAME map.
CREATE TABLE delegations (
    id           VARCHAR(64)  PRIMARY KEY,
    account_id   VARCHAR(64)  NOT NULL,
    csr_template MEDIUMTEXT   NOT NULL,  -- JSON per RFC 9115 §4 / Appendix A
    cname_map    MEDIUMTEXT,             -- JSON {fqdn: fqdn} or NULL
    created      BIGINT       NOT NULL,
    updated      BIGINT       NOT NULL,
    local_gen    BIGINT       NOT NULL DEFAULT 0,
    ca_id        VARCHAR(64)  NOT NULL DEFAULT '',
    FOREIGN KEY (account_id) REFERENCES accounts(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_delegations_account ON delegations(account_id);

-- Deferred FK: orders.delegation_id -> delegations.id.
-- Declared here (rather than inline on orders) because orders is created
-- earlier in this file, before the delegations table exists.
ALTER TABLE orders
    ADD CONSTRAINT fk_orders_delegation FOREIGN KEY (delegation_id) REFERENCES delegations(id);

-- Node identity keys: ML-KEM-768 key pair + ECDSA P-256 signing key pair.
-- Generated locally on first start; never replicated via gossip.
CREATE TABLE node_keys (
    node_id                  VARCHAR(255) PRIMARY KEY,
    kem_private_key_der      MEDIUMBLOB   NOT NULL,
    kem_public_key_der       MEDIUMBLOB   NOT NULL,
    signing_private_key_der  MEDIUMBLOB   NOT NULL,
    signing_public_key_der   MEDIUMBLOB   NOT NULL,
    signing_certificate_der  MEDIUMBLOB   NOT NULL,
    created_at               BIGINT       NOT NULL
);

-- Cluster node registry: replicated via gossip, mirroring AkaCrdt.cluster_nodes.
CREATE TABLE crdt_cluster_nodes (
    node_id                  VARCHAR(255) PRIMARY KEY,
    gossip_url               TEXT         NOT NULL,
    kem_public_key_der       MEDIUMBLOB   NOT NULL,
    signing_public_key_der   MEDIUMBLOB   NOT NULL,
    signing_certificate_der  MEDIUMBLOB   NOT NULL,
    ca_ids                   TEXT         NOT NULL DEFAULT '[]', -- JSON array of CA IDs
    registered_at            BIGINT       NOT NULL,
    tombstone                TINYINT      NOT NULL DEFAULT 0,
    tombstone_at             BIGINT,
    local_gen                BIGINT       NOT NULL DEFAULT 0,
    CONSTRAINT ck_tombstone_consistency CHECK (
        (tombstone = 0 AND tombstone_at IS NULL) OR
        (tombstone = 1 AND tombstone_at IS NOT NULL)
    )
);

-- Gossip-consensus order ownership: one row per order that has a live claim.
-- Ownership lapses when claimed_at + ownership_ttl_secs < now.
CREATE TABLE crdt_order_owners (
    order_id    VARCHAR(64)  PRIMARY KEY,
    node_id     VARCHAR(255) NOT NULL,
    claimed_at  BIGINT       NOT NULL,
    local_gen   BIGINT       NOT NULL DEFAULT 0
);

-- MTC writer election: at most one row (application always uses id = 'singleton').
CREATE TABLE crdt_mtc_writer (
    id          VARCHAR(32)  PRIMARY KEY,
    node_id     VARCHAR(255) NOT NULL,
    claimed_at  BIGINT       NOT NULL,
    local_gen   BIGINT       NOT NULL DEFAULT 0
);

-- RFC 9447 tkauth-01: JTI replay-prevention cache.
CREATE TABLE tkauth_jti_cache (
    jti      VARCHAR(512) PRIMARY KEY,
    authz_id VARCHAR(64)  NOT NULL,
    expires  BIGINT       NOT NULL,
    created  BIGINT       NOT NULL,
    tkvalue  TEXT,                      -- JWTClaimConstraints DER for encoder-backed identifiers
    ca_flag  TINYINT(1)   NOT NULL DEFAULT 0  -- atc.ca boolean from the authority token
);
CREATE INDEX tkauth_jti_expires_idx  ON tkauth_jti_cache (expires);
CREATE INDEX tkauth_jti_authzid_idx  ON tkauth_jti_cache (authz_id, expires);

-- MTC issuance-log checkpoints produced by the MTC signing key.
CREATE TABLE mtc_checkpoints (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ca_id       VARCHAR(64)  NOT NULL DEFAULT 'default',
    tree_size   BIGINT       NOT NULL,
    root_hex    TEXT         NOT NULL,
    signature   MEDIUMBLOB   NOT NULL,
    created     BIGINT       NOT NULL,
    local_gen   BIGINT       NOT NULL DEFAULT 0,
    UNIQUE KEY mtc_checkpoints_ca_tree (ca_id, tree_size)
);

-- MTC landmark certificates issued at fixed tree-size intervals.
CREATE TABLE mtc_landmarks (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ca_id       VARCHAR(64)  NOT NULL DEFAULT 'default',
    sequence_no BIGINT       NOT NULL,
    tree_size   BIGINT       NOT NULL,
    cert_der    MEDIUMBLOB,
    created     BIGINT       NOT NULL,
    UNIQUE KEY mtc_landmarks_ca_seq (ca_id, sequence_no),
    UNIQUE KEY mtc_landmarks_ca_tree (ca_id, tree_size)
);

-- Third-party cosignatures over MTC checkpoints.
CREATE TABLE mtc_cosignatures (
    id              BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    ca_id           VARCHAR(64)   NOT NULL DEFAULT 'default',
    checkpoint_id   BIGINT        NOT NULL REFERENCES mtc_checkpoints(id) ON DELETE CASCADE,
    cosigner_url    VARCHAR(2048) NOT NULL,
    signature_der   MEDIUMBLOB    NOT NULL,
    created         BIGINT        NOT NULL,
    local_gen       BIGINT        NOT NULL DEFAULT 0,
    UNIQUE(checkpoint_id, cosigner_url(512))
);
CREATE INDEX idx_mtc_cosignatures_checkpoint ON mtc_cosignatures(checkpoint_id);

-- MTC revoked ranges: marks ranges of log entry indices as revoked (§5.6).
CREATE TABLE mtc_revoked_ranges (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    ca_id       VARCHAR(255) NOT NULL,
    range_start BIGINT       NOT NULL,
    range_end   BIGINT       NOT NULL,
    created     BIGINT       NOT NULL,
    UNIQUE(ca_id, range_start, range_end),
    CHECK(range_start <= range_end)
);

-- Policy engine rules (soft-deletable via tombstone).
-- name_live is a generated column used only to build a partial-unique-index
-- equivalent (MariaDB has no WHERE-clause partial indexes, but UNIQUE
-- indexes ignore NULLs, so tombstoned rows drop out of the uniqueness check).
CREATE TABLE policy_rules (
    id           VARCHAR(36)  PRIMARY KEY,
    scope        VARCHAR(64)  NOT NULL,
    name         VARCHAR(255) NOT NULL,
    rule_json    TEXT         NOT NULL,
    enabled      TINYINT(1)   NOT NULL DEFAULT 1,
    created_at   VARCHAR(30)  NOT NULL,
    updated_at   VARCHAR(30)  NOT NULL,
    created_by   VARCHAR(255),
    local_gen    BIGINT       NOT NULL DEFAULT 0,
    tombstone    INTEGER      NOT NULL DEFAULT 0,
    tombstone_at BIGINT,
    name_live    VARCHAR(255) AS (CASE WHEN tombstone = 0 THEN name ELSE NULL END) STORED,
    CONSTRAINT ck_policy_tombstone_consistency CHECK (
        (tombstone = 0 AND tombstone_at IS NULL) OR
        (tombstone = 1 AND tombstone_at IS NOT NULL)
    )
);
CREATE UNIQUE INDEX uq_policy_rules_scope_name_live
    ON policy_rules (scope, name_live);
-- Covering index for list_by_scope (WHERE scope = ? AND tombstone = 0).
CREATE INDEX idx_policy_rules_scope
    ON policy_rules (scope, tombstone);
