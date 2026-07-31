-- ACME accounts
CREATE TABLE accounts (
    id                  TEXT    PRIMARY KEY,      -- UUID
    status              TEXT    NOT NULL DEFAULT 'valid'
                                 CHECK(status IN ('valid','deactivated','revoked')),  -- valid|deactivated|revoked
    contact             TEXT,                     -- JSON array of mailto: URIs
    public_key          BYTEA   NOT NULL,         -- DER-encoded SubjectPublicKeyInfo
    jwk_thumbprint      TEXT    NOT NULL UNIQUE,  -- base64url SHA-256 JWK thumbprint
    created             BIGINT  NOT NULL,         -- Unix epoch seconds
    updated             BIGINT  NOT NULL,
    profile_grants      TEXT,                     -- JSON array of allowed profile IDs; NULL = no restriction
    ca_id               TEXT    NOT NULL DEFAULT '', -- '' = server-wide scope (account may use any CA)
    local_gen           BIGINT  NOT NULL DEFAULT 0,  -- CRDT delta-gossip generation counter
    kerberos_principal  TEXT                      -- set when account created via GSSAPI-authenticated EAB
);
CREATE INDEX idx_accounts_ca_id ON accounts(ca_id);

-- ACME orders
CREATE TABLE orders (
    id                         TEXT    PRIMARY KEY,
    account_id                 TEXT    NOT NULL REFERENCES accounts(id),
    status                     TEXT    NOT NULL DEFAULT 'pending'
                                       CHECK(status IN ('pending','ready','processing','valid','invalid','canceled')), -- pending|ready|processing|valid|invalid|canceled
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
    profile                    TEXT,
    -- Multi-CA (ca_id) and RFC 9115 delegation fields.
    -- delegation_id's FK to delegations(id) is added below (fk_orders_delegation),
    -- once the delegations table exists.
    ca_id                      TEXT    NOT NULL DEFAULT 'default',
    delegation_id              TEXT,                     -- NULL for non-delegation orders
    allow_cert_get             SMALLINT NOT NULL DEFAULT 0,  -- RFC 9115 §2.3.5 top-level flag
    upstream_order_url         TEXT,                     -- Order2 URL on the upstream CA; NULL until submitted
    upstream_cert_url          TEXT,                     -- cert/star-cert URL from the upstream CA; NULL until valid
    local_gen                  BIGINT  NOT NULL DEFAULT 0
);
CREATE INDEX idx_orders_account  ON orders(account_id);
CREATE INDEX idx_orders_status   ON orders(status);
CREATE INDEX idx_orders_replaces ON orders(replaces) WHERE replaces IS NOT NULL;
CREATE INDEX idx_orders_star     ON orders(star_end_date) WHERE star_end_date IS NOT NULL;
CREATE INDEX idx_orders_ca_id    ON orders(ca_id);
CREATE INDEX idx_orders_ca_account ON orders(ca_id, account_id);
CREATE INDEX idx_orders_delegation ON orders(delegation_id) WHERE delegation_id IS NOT NULL;
CREATE INDEX idx_orders_delegation_status
    ON orders(delegation_id, status)
    WHERE delegation_id IS NOT NULL AND status = 'processing';

-- ACME authorizations
CREATE TABLE authorizations (
    id                     TEXT    PRIMARY KEY,
    order_id               TEXT    REFERENCES orders(id), -- NULL for RFC 8555 §7.4.1 standalone pre-authorizations
    account_id             TEXT    NOT NULL REFERENCES accounts(id),
    status                 TEXT    NOT NULL DEFAULT 'pending'
                                   CHECK(status IN ('pending','valid','invalid','deactivated','expired','revoked')), -- pending|valid|invalid|deactivated|expired|revoked
    identifier             TEXT    NOT NULL,             -- JSON {"type":"dns","value":"example.com"}
    expires                BIGINT,                       -- Unix epoch
    wildcard               SMALLINT NOT NULL DEFAULT 0,
    subdomain_auth_allowed SMALLINT NOT NULL DEFAULT 0, -- RFC 9444
    created                BIGINT  NOT NULL,
    updated                BIGINT  NOT NULL,
    ca_id                  TEXT    NOT NULL DEFAULT 'default',
    local_gen              BIGINT  NOT NULL DEFAULT 0
);
CREATE INDEX idx_authz_order   ON authorizations(order_id);
CREATE INDEX idx_authz_account ON authorizations(account_id);
CREATE INDEX idx_authzs_ca_id  ON authorizations(ca_id);
-- Hot-path indexes (see original 0018_hot_indexes.sql for the online-migration
-- rationale; a plain CREATE INDEX is used here since this is the initial,
-- one-shot schema for an empty database, so CONCURRENTLY has no benefit).
--
-- Partial index for the on_valid NOT EXISTS check.
CREATE INDEX idx_authz_order_nonvalid
    ON authorizations(order_id)
    WHERE status != 'valid';
-- Compound index for find_valid_by_account_and_identifier.
CREATE INDEX idx_authz_acct_ident
    ON authorizations(account_id, identifier);

-- ACME challenges
CREATE TABLE challenges (
    id                TEXT    PRIMARY KEY,
    authz_id          TEXT    NOT NULL REFERENCES authorizations(id),
    type              TEXT    NOT NULL,              -- http-01|dns-01|tls-alpn-01
    status            TEXT    NOT NULL DEFAULT 'pending'
                               CHECK(status IN ('pending','processing','valid','invalid')), -- pending|processing|valid|invalid
    token             TEXT    NOT NULL,              -- random URL-safe base64url string
    validated         BIGINT,                        -- Unix epoch when validated
    error             TEXT,                          -- problem+json string if invalid
    created           BIGINT  NOT NULL,
    updated           BIGINT  NOT NULL,
    -- RFC 8823 email-reply-00 challenge state
    email_token_part1 TEXT,
    email_message_id  TEXT,
    local_gen         BIGINT  NOT NULL DEFAULT 0,
    -- RFC 9447 tkauth-01 fields
    tkauth_type       TEXT,
    token_authority   TEXT
);
CREATE INDEX idx_chall_authz ON challenges(authz_id);
-- Unique on email_message_id; duplicate webhook deliveries for the same
-- Message-ID are caught at the storage layer. NULL values are not indexed
-- (PostgreSQL NULL != NULL semantics), so a partial index keeps it sparse.
CREATE UNIQUE INDEX idx_chall_email_message_id
    ON challenges(email_message_id)
    WHERE email_message_id IS NOT NULL;

-- Issued X.509 certificates
CREATE TABLE certificates (
    id                     TEXT    PRIMARY KEY,   -- UUID used in the cert URL path
    order_id               TEXT    NOT NULL REFERENCES orders(id),
    account_id             TEXT    NOT NULL REFERENCES accounts(id),
    serial_number          TEXT    NOT NULL UNIQUE,  -- hex-encoded serial
    status                 TEXT    NOT NULL DEFAULT 'valid'
                                   CHECK(status IN ('valid','revoked')), -- valid|revoked
    der                    BYTEA   NOT NULL,      -- full chain DER (leaf + CA)
    pem                    TEXT    NOT NULL,      -- PEM bundle for download
    not_before             BIGINT  NOT NULL,      -- Unix epoch
    not_after              BIGINT  NOT NULL,      -- Unix epoch
    revoked_at             BIGINT,                -- Unix epoch
    revocation_reason      BIGINT,                -- CRL reason code or NULL
    mtc_log_index          BIGINT,                -- MTC transparency log leaf index
    created                BIGINT  NOT NULL,
    -- RFC 9773 ARI suggested renewal window
    suggested_window_start BIGINT,              -- Unix epoch
    suggested_window_end   BIGINT,              -- Unix epoch
    replaced_by            TEXT,                 -- RFC 9773: order_id that replaced this cert
    mtc_standalone_der     BYTEA,                -- standalone-form MTC certificate DER
    subject_dn             TEXT,                 -- FAU_SCR_EXT.1 searchable subject DN
    ca_id                  TEXT    NOT NULL DEFAULT 'default',
    local_gen              BIGINT  NOT NULL DEFAULT 0
);
CREATE INDEX idx_certs_account              ON certificates(account_id);
CREATE INDEX idx_certs_serial               ON certificates(serial_number);
CREATE INDEX idx_certs_order                ON certificates(order_id);
CREATE INDEX idx_certs_status               ON certificates(status);
CREATE INDEX idx_certs_account_status_not_after ON certificates(account_id, status, not_after);
CREATE INDEX idx_certs_replaced_by          ON certificates(replaced_by)
    WHERE replaced_by IS NOT NULL;
CREATE INDEX idx_certs_mtc_log_index
    ON certificates(mtc_log_index)
    WHERE mtc_log_index IS NOT NULL;
CREATE INDEX idx_certs_subject_dn           ON certificates(subject_dn);
CREATE INDEX idx_certs_ca_id                ON certificates(ca_id);
-- Partial index for CRL generation: WHERE status = 'revoked' AND ca_id = ?
CREATE INDEX idx_certs_ca_id_revoked ON certificates(ca_id) WHERE status = 'revoked';

-- Anti-replay nonces; consumed on first use.
-- In-memory NonceBucket is the primary store on the hot path; this table
-- exists for startup cleanup of nonces written by previous process versions.
CREATE TABLE nonces (
    nonce   TEXT    PRIMARY KEY,
    created BIGINT  NOT NULL  -- Unix epoch seconds
);
CREATE INDEX idx_nonces_created ON nonces(created);

-- RFC 8555 §7.3.4 External Account Binding key store.
-- created_by_operator_id's FK to operators(id) is added below
-- (fk_eab_keys_operator), once the operators table exists.
CREATE TABLE eab_keys (
    kid                    TEXT    PRIMARY KEY,
    hmac_key_b64u          TEXT    NOT NULL,
    created                BIGINT  NOT NULL,
    used_at                BIGINT,
    profile_grants         TEXT,     -- JSON array of profile IDs copied to the account at creation
    created_by_operator_id BIGINT,   -- provisioning operator; NULL = config file / pre-migration
    bound_principal        TEXT,     -- Kerberos principal that derived this key via /acme/eab
    alg                    TEXT    NOT NULL DEFAULT 'sha256'  -- HMAC algorithm: sha256|sha384|sha512
                                    CONSTRAINT chk_eab_alg CHECK (alg IN ('sha256', 'sha384', 'sha512')),
    local_gen              BIGINT  NOT NULL DEFAULT 0
);

-- PP CA v2.1 FMT: operator accounts with role-based access control.
--
-- Each operator is identified by a client certificate fingerprint, a
-- Kerberos principal, or both.  At least one must be non-NULL (enforced by
-- the CHECK constraint).
CREATE TABLE operators (
    id               BIGSERIAL   PRIMARY KEY,
    name             TEXT        NOT NULL UNIQUE,
    role             TEXT        NOT NULL
                                 CHECK(role IN ('administrator','ca_operations','ca_ra','auditor')),
    cert_fingerprint TEXT        UNIQUE,       -- SHA-256 hex; NULL = no cert auth
    gssapi_principal TEXT        UNIQUE,       -- Kerberos principal; NULL = no GSSAPI auth
    created_at       TEXT        NOT NULL,     -- RFC 3339
    last_seen_at     TEXT,                     -- RFC 3339
    active           BIGINT      NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    failed_attempts  INTEGER     NOT NULL DEFAULT 0,  -- FIA_AFL.1 lockout counter
    locked_until     TEXT,                     -- RFC 3339; NULL = not locked
    ca_id            TEXT        NOT NULL DEFAULT '', -- '' = server-wide; else scoped to one CA
    local_gen        BIGINT      NOT NULL DEFAULT 0,
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
    id              TEXT    PRIMARY KEY,          -- UUID
    issuer_ca_id    TEXT    NOT NULL,             -- CA that signed the cross-cert
    subject_ca_id   TEXT,                         -- akamu CA ID if same-server target, NULL if external
    subject_dn      TEXT    NOT NULL,             -- RFC 4514 subject DN string
    subject_spki    BYTEA   NOT NULL,             -- DER SubjectPublicKeyInfo of subject CA key
    cross_cert_der  BYTEA   NOT NULL,             -- DER of the issued cross-certificate
    cross_cert_pem  TEXT    NOT NULL,             -- PEM for download
    not_before      BIGINT  NOT NULL,             -- Unix epoch
    not_after       BIGINT  NOT NULL,             -- Unix epoch
    serial_number   TEXT    NOT NULL,             -- hex-encoded serial (same format as certificates)
    created         BIGINT  NOT NULL,             -- Unix epoch
    UNIQUE (issuer_ca_id, serial_number)          -- RFC 5280: unique within issuing CA
);
CREATE INDEX idx_cross_certs_issuer  ON cross_certs(issuer_ca_id);
-- Partial index: queries always filter on a concrete non-NULL subject_ca_id
CREATE INDEX idx_cross_certs_subject ON cross_certs(subject_ca_id)
    WHERE subject_ca_id IS NOT NULL;

-- RFC 9115 ACME profile for delegated certificates.
--
-- Delegation objects represent a pre-configured delegation from an Identifier Owner (IdO)
-- to a Name Delegation Consumer (NDC).  Each delegation carries a CSR template that the
-- NDC must satisfy when submitting finalize requests, and an optional CNAME map.
CREATE TABLE delegations (
    id           TEXT    PRIMARY KEY,
    account_id   TEXT    NOT NULL REFERENCES accounts(id),
    csr_template TEXT    NOT NULL,  -- JSON per RFC 9115 §4 / Appendix A
    cname_map    TEXT,              -- JSON {fqdn: fqdn} or NULL
    created      BIGINT  NOT NULL,
    updated      BIGINT  NOT NULL,
    local_gen    BIGINT  NOT NULL DEFAULT 0,
    ca_id        TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_delegations_account ON delegations(account_id);

-- Deferred FK: orders.delegation_id -> delegations.id.
-- Declared here (rather than inline on orders) because orders is created
-- earlier in this file, before the delegations table exists.
ALTER TABLE orders
    ADD CONSTRAINT fk_orders_delegation
    FOREIGN KEY (delegation_id)
    REFERENCES delegations(id);

-- Node identity keys: ML-KEM-768 key pair + ECDSA P-256 signing key pair.
-- Generated locally on first start; never replicated via gossip.
CREATE TABLE node_keys (
    node_id                  TEXT    PRIMARY KEY,
    kem_private_key_der      BYTEA   NOT NULL,
    kem_public_key_der       BYTEA   NOT NULL,
    signing_private_key_der  BYTEA   NOT NULL,
    signing_public_key_der   BYTEA   NOT NULL,
    signing_certificate_der  BYTEA   NOT NULL,
    created_at               BIGINT  NOT NULL
);

-- Cluster node registry: replicated via gossip, mirroring AkaCrdt.cluster_nodes.
CREATE TABLE crdt_cluster_nodes (
    node_id                  TEXT    PRIMARY KEY,
    gossip_url               TEXT    NOT NULL,
    kem_public_key_der       BYTEA   NOT NULL,
    signing_public_key_der   BYTEA   NOT NULL,
    signing_certificate_der  BYTEA   NOT NULL,
    ca_ids                   TEXT    NOT NULL DEFAULT '[]', -- JSON array of CA IDs
    registered_at            BIGINT  NOT NULL,
    tombstone                SMALLINT NOT NULL DEFAULT 0,
    tombstone_at             BIGINT,
    local_gen                BIGINT  NOT NULL DEFAULT 0,
    CONSTRAINT ck_tombstone_consistency CHECK (
        (tombstone = 0 AND tombstone_at IS NULL) OR
        (tombstone = 1 AND tombstone_at IS NOT NULL)
    )
);

-- Gossip-consensus order ownership: one row per order that has a live claim.
-- Ownership lapses when claimed_at + ownership_ttl_secs < now.
CREATE TABLE crdt_order_owners (
    order_id    TEXT    PRIMARY KEY,
    node_id     TEXT    NOT NULL,
    claimed_at  BIGINT  NOT NULL,
    local_gen   BIGINT  NOT NULL DEFAULT 0
);

-- MTC writer election: at most one row (application always uses id = 'singleton').
CREATE TABLE crdt_mtc_writer (
    id          TEXT    PRIMARY KEY,
    node_id     TEXT    NOT NULL,
    claimed_at  BIGINT  NOT NULL,
    local_gen   BIGINT  NOT NULL DEFAULT 0
);

-- RFC 9447 tkauth-01: JTI replay-prevention cache.
CREATE TABLE tkauth_jti_cache (
    jti      TEXT    PRIMARY KEY,
    authz_id TEXT    NOT NULL,
    expires  BIGINT  NOT NULL,
    created  BIGINT  NOT NULL,
    tkvalue  TEXT,                            -- JWTClaimConstraints DER for encoder-backed identifiers
    ca_flag  BOOLEAN NOT NULL DEFAULT FALSE   -- atc.ca boolean from the authority token
);
CREATE INDEX tkauth_jti_expires_idx  ON tkauth_jti_cache (expires);
CREATE INDEX tkauth_jti_authzid_idx  ON tkauth_jti_cache (authz_id, expires);

-- MTC issuance-log checkpoints produced by the MTC signing key.
CREATE TABLE mtc_checkpoints (
    id          BIGSERIAL   PRIMARY KEY,
    ca_id       TEXT        NOT NULL DEFAULT 'default',
    tree_size   BIGINT      NOT NULL,
    root_hex    TEXT        NOT NULL,
    signature   BYTEA       NOT NULL,
    created     BIGINT      NOT NULL,
    local_gen   BIGINT      NOT NULL DEFAULT 0,
    CONSTRAINT mtc_checkpoints_ca_tree UNIQUE (ca_id, tree_size)
);

-- MTC landmark certificates issued at fixed tree-size intervals.
CREATE TABLE mtc_landmarks (
    id          BIGSERIAL   PRIMARY KEY,
    ca_id       TEXT        NOT NULL DEFAULT 'default',
    sequence_no BIGINT      NOT NULL,
    tree_size   BIGINT      NOT NULL,
    cert_der    BYTEA,
    created     BIGINT      NOT NULL,
    CONSTRAINT mtc_landmarks_ca_seq UNIQUE (ca_id, sequence_no),
    CONSTRAINT mtc_landmarks_ca_tree UNIQUE (ca_id, tree_size)
);

-- Third-party cosignatures over MTC checkpoints.
CREATE TABLE mtc_cosignatures (
    id              BIGSERIAL   PRIMARY KEY,
    ca_id           TEXT        NOT NULL DEFAULT 'default',
    checkpoint_id   BIGINT      NOT NULL REFERENCES mtc_checkpoints(id) ON DELETE CASCADE,
    cosigner_url    TEXT        NOT NULL,
    signature_der   BYTEA       NOT NULL,
    created         BIGINT      NOT NULL,
    local_gen       BIGINT      NOT NULL DEFAULT 0,
    UNIQUE(checkpoint_id, cosigner_url)
);
CREATE INDEX idx_mtc_cosignatures_checkpoint ON mtc_cosignatures(checkpoint_id);

-- MTC revoked ranges: marks ranges of log entry indices as revoked (§5.6).
CREATE TABLE mtc_revoked_ranges (
    id          BIGSERIAL PRIMARY KEY,
    ca_id       TEXT    NOT NULL,
    range_start BIGINT  NOT NULL,
    range_end   BIGINT  NOT NULL,
    created     BIGINT  NOT NULL,
    UNIQUE(ca_id, range_start, range_end),
    CHECK(range_start <= range_end)
);

-- Policy engine rules (soft-deletable via tombstone).
CREATE TABLE policy_rules (
    id           TEXT PRIMARY KEY,
    scope        TEXT NOT NULL,
    name         TEXT NOT NULL,
    rule_json    TEXT NOT NULL,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    created_by   TEXT,
    local_gen    BIGINT NOT NULL DEFAULT 0,
    tombstone    INTEGER NOT NULL DEFAULT 0,
    tombstone_at BIGINT,
    CONSTRAINT ck_policy_tombstone_consistency CHECK (
        (tombstone = 0 AND tombstone_at IS NULL) OR
        (tombstone = 1 AND tombstone_at IS NOT NULL)
    )
);
-- Partial unique index: only live (non-tombstoned) rows participate in the
-- uniqueness check, so a rule can be re-created after soft-delete.
CREATE UNIQUE INDEX uq_policy_rules_scope_name_live
    ON policy_rules (scope, name)
    WHERE tombstone = 0;
-- Covering index for list_by_scope (WHERE scope = ? AND tombstone = 0).
CREATE INDEX idx_policy_rules_scope
    ON policy_rules (scope)
    WHERE tombstone = 0;
