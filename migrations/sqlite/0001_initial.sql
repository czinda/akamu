-- ACME accounts
CREATE TABLE accounts (
    id                  TEXT    PRIMARY KEY,      -- UUID
    status              TEXT    NOT NULL DEFAULT 'valid'
                                 CHECK(status IN ('valid','deactivated','revoked')),  -- valid|deactivated|revoked
    contact             TEXT,                     -- JSON array of mailto: URIs
    public_key          BLOB    NOT NULL,         -- DER-encoded SubjectPublicKeyInfo
    jwk_thumbprint      TEXT    NOT NULL UNIQUE,  -- base64url SHA-256 JWK thumbprint
    created             INTEGER NOT NULL,         -- Unix epoch seconds
    updated             INTEGER NOT NULL,
    profile_grants      TEXT,                     -- JSON array of allowed profile IDs; NULL = no restriction
    ca_id               TEXT    NOT NULL DEFAULT '', -- '' = server-wide scope (account may use any CA)
    local_gen           INTEGER NOT NULL DEFAULT 0,  -- CRDT delta-gossip generation counter
    kerberos_principal  TEXT                      -- set when account created via GSSAPI-authenticated EAB
);
CREATE INDEX idx_accounts_ca_id ON accounts(ca_id);

-- ACME orders
CREATE TABLE orders (
    id                         TEXT    PRIMARY KEY,
    account_id                 TEXT    NOT NULL REFERENCES accounts(id),
    status                     TEXT    NOT NULL DEFAULT 'pending'
                                       CHECK(status IN ('pending','ready','processing','valid','invalid','canceled')), -- pending|ready|processing|valid|invalid|canceled
    expires                    INTEGER,                  -- Unix epoch; NULL = no expiry
    identifiers                TEXT    NOT NULL,         -- JSON [{type,value}]
    not_before                 INTEGER,                  -- Unix epoch; NULL = not set
    not_after                  INTEGER,                  -- Unix epoch; NULL = not set
    error                      TEXT,                     -- problem+json string if invalid
    certificate_id             TEXT,                     -- FK to certificates.id when valid
    replaces                   TEXT,                     -- RFC 9773 ARI: cert_id of predecessor
    created                    INTEGER NOT NULL,
    updated                    INTEGER NOT NULL,
    -- RFC 8739 STAR auto-renewal fields
    star_start_date            INTEGER,                  -- Unix timestamp, optional
    star_end_date              INTEGER,                  -- Unix timestamp, required for STAR
    star_lifetime_secs         INTEGER,                  -- lifetime of each cert, seconds
    star_lifetime_adjust_secs  INTEGER NOT NULL DEFAULT 0,
    star_allow_cert_get        INTEGER NOT NULL DEFAULT 0,
    star_canceled_at           INTEGER,                  -- set on cancellation
    star_csr_der               BLOB,                     -- stored CSR DER for reissuance
    -- draft-aaron-acme-profiles-01
    profile                    TEXT,
    -- Multi-CA (ca_id) and RFC 9115 delegation fields
    ca_id                      TEXT    NOT NULL DEFAULT 'default',
    delegation_id              TEXT    REFERENCES delegations(id), -- NULL for non-delegation orders
    allow_cert_get             INTEGER NOT NULL DEFAULT 0,         -- RFC 9115 §2.3.5 top-level flag
    upstream_order_url         TEXT,                     -- Order2 URL on the upstream CA; NULL until submitted
    upstream_cert_url          TEXT,                     -- cert/star-cert URL from the upstream CA; NULL until valid
    local_gen                  INTEGER NOT NULL DEFAULT 0
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
    expires                INTEGER,                      -- Unix epoch
    wildcard               INTEGER NOT NULL DEFAULT 0,
    subdomain_auth_allowed INTEGER NOT NULL DEFAULT 0,     -- RFC 9444
    created                INTEGER NOT NULL,
    updated                INTEGER NOT NULL,
    ca_id                  TEXT    NOT NULL DEFAULT 'default',
    local_gen              INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX idx_authz_order   ON authorizations(order_id);
CREATE INDEX idx_authz_account ON authorizations(account_id);
CREATE INDEX idx_authzs_ca_id  ON authorizations(ca_id);

-- ACME challenges
CREATE TABLE challenges (
    id                TEXT    PRIMARY KEY,
    authz_id          TEXT    NOT NULL REFERENCES authorizations(id),
    type              TEXT    NOT NULL,              -- http-01|dns-01|tls-alpn-01
    status            TEXT    NOT NULL DEFAULT 'pending'
                               CHECK(status IN ('pending','processing','valid','invalid')), -- pending|processing|valid|invalid
    token             TEXT    NOT NULL,              -- random URL-safe base64url string
    validated         INTEGER,                       -- Unix epoch when validated
    error             TEXT,                          -- problem+json string if invalid
    created           INTEGER NOT NULL,
    updated           INTEGER NOT NULL,
    -- RFC 8823 email-reply-00 challenge state
    email_token_part1 TEXT,
    email_message_id  TEXT,
    local_gen         INTEGER NOT NULL DEFAULT 0,
    -- RFC 9447 tkauth-01 fields
    tkauth_type       TEXT,
    token_authority   TEXT
);
CREATE INDEX idx_chall_authz ON challenges(authz_id);
-- Unique on email_message_id; duplicate webhook deliveries for the same
-- Message-ID are caught at the storage layer. Partial form keeps the index
-- sparse: only rows with a non-NULL message ID are indexed.
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
    der                    BLOB    NOT NULL,      -- full chain DER (leaf + CA)
    pem                    TEXT    NOT NULL,      -- PEM bundle for download
    not_before             INTEGER NOT NULL,      -- Unix epoch
    not_after              INTEGER NOT NULL,      -- Unix epoch
    revoked_at             INTEGER,               -- Unix epoch
    revocation_reason      INTEGER,               -- CRL reason code or NULL
    mtc_log_index          INTEGER,               -- MTC transparency log leaf index
    created                INTEGER NOT NULL,
    -- RFC 9773 ARI suggested renewal window
    suggested_window_start INTEGER,             -- Unix epoch
    suggested_window_end   INTEGER,             -- Unix epoch
    replaced_by            TEXT,                 -- RFC 9773: order_id that replaced this cert
    mtc_standalone_der     BLOB,                 -- standalone-form MTC certificate DER
    subject_dn             TEXT,                 -- FAU_SCR_EXT.1 searchable subject DN
    ca_id                  TEXT    NOT NULL DEFAULT 'default',
    local_gen              INTEGER NOT NULL DEFAULT 0
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
-- Composite index for CRL generation: WHERE status = 'revoked' AND ca_id = ?
CREATE INDEX idx_certs_ca_id_revoked ON certificates(ca_id) WHERE status = 'revoked';

-- Anti-replay nonces; consumed on first use.
-- In-memory NonceBucket is the primary store on the hot path; this table
-- exists for startup cleanup of nonces written by previous process versions.
CREATE TABLE nonces (
    nonce   TEXT    PRIMARY KEY,
    created INTEGER NOT NULL  -- Unix epoch seconds
);
CREATE INDEX idx_nonces_created ON nonces(created);

-- RFC 8555 §7.3.4 External Account Binding key store
CREATE TABLE eab_keys (
    kid                    TEXT    PRIMARY KEY,
    hmac_key_b64u          TEXT    NOT NULL,
    created                INTEGER NOT NULL,
    used_at                INTEGER,
    profile_grants         TEXT,     -- JSON array of profile IDs copied to the account at creation
    created_by_operator_id INTEGER,  -- provisioning operator; NULL = config file / pre-migration
    bound_principal        TEXT,     -- Kerberos principal that derived this key via /acme/eab
    alg                    TEXT    NOT NULL DEFAULT 'sha256', -- HMAC algorithm: sha256|sha384|sha512
    local_gen              INTEGER NOT NULL DEFAULT 0
);

-- PP CA v2.1 FMT: operator accounts with role-based access control.
--
-- Each operator is identified by a client certificate fingerprint, a
-- Kerberos principal, or both.  At least one must be non-NULL (enforced by
-- the CHECK constraint).
CREATE TABLE operators (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL UNIQUE,
    role             TEXT    NOT NULL
                             CHECK(role IN ('administrator','ca_operations','ca_ra','auditor')),
    cert_fingerprint TEXT    UNIQUE,   -- SHA-256 hex of DER leaf cert; NULL = no cert auth
    gssapi_principal TEXT    UNIQUE,   -- Kerberos principal e.g. alice@REALM; NULL = no GSSAPI auth
    created_at       TEXT    NOT NULL, -- RFC 3339
    last_seen_at     TEXT,             -- RFC 3339; updated on each successful authentication
    active           INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    failed_attempts  INTEGER NOT NULL DEFAULT 0,  -- FIA_AFL.1 lockout counter
    locked_until     TEXT,             -- RFC 3339; NULL = not locked
    ca_id            TEXT    NOT NULL DEFAULT '', -- '' = server-wide; else scoped to one CA
    local_gen        INTEGER NOT NULL DEFAULT 0,
    CHECK(cert_fingerprint IS NOT NULL OR gssapi_principal IS NOT NULL)
);

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
    subject_spki    BLOB    NOT NULL,             -- DER SubjectPublicKeyInfo of subject CA key
    cross_cert_der  BLOB    NOT NULL,             -- DER of the issued cross-certificate
    cross_cert_pem  TEXT    NOT NULL,             -- PEM for download
    not_before      INTEGER NOT NULL,             -- Unix epoch
    not_after       INTEGER NOT NULL,             -- Unix epoch
    serial_number   TEXT    NOT NULL,             -- hex-encoded serial (same format as certificates)
    created         INTEGER NOT NULL,             -- Unix epoch
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
    created      INTEGER NOT NULL,
    updated      INTEGER NOT NULL,
    local_gen    INTEGER NOT NULL DEFAULT 0,
    ca_id        TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX idx_delegations_account ON delegations(account_id);

-- Node identity keys: ML-KEM-768 key pair + ECDSA P-256 signing key pair.
-- Generated locally on first start; never replicated via gossip.
CREATE TABLE node_keys (
    node_id                  TEXT    PRIMARY KEY,
    kem_private_key_der      BLOB    NOT NULL,
    kem_public_key_der       BLOB    NOT NULL,
    signing_private_key_der  BLOB    NOT NULL,
    signing_public_key_der   BLOB    NOT NULL,
    signing_certificate_der  BLOB    NOT NULL,
    created_at               INTEGER NOT NULL
);

-- Cluster node registry: replicated via gossip, mirroring AkaCrdt.cluster_nodes.
CREATE TABLE crdt_cluster_nodes (
    node_id                  TEXT    PRIMARY KEY,
    gossip_url               TEXT    NOT NULL,
    kem_public_key_der       BLOB    NOT NULL,
    signing_public_key_der   BLOB    NOT NULL,
    signing_certificate_der  BLOB    NOT NULL,
    ca_ids                   TEXT    NOT NULL DEFAULT '[]', -- JSON array of CA IDs
    registered_at            INTEGER NOT NULL,
    tombstone                INTEGER NOT NULL DEFAULT 0,
    tombstone_at             INTEGER,
    local_gen                INTEGER NOT NULL DEFAULT 0,
    -- Writer of this entry, for CRDT merge tiebreak; distinct from the
    -- `node_id` column above, which is the entry's subject (the node this
    -- row describes), not who wrote it.
    writer_node_id           TEXT    NOT NULL DEFAULT '',
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
    claimed_at  INTEGER NOT NULL,
    local_gen   INTEGER NOT NULL DEFAULT 0
);

-- One row per CA with a live or historical MTC writer election claim.
CREATE TABLE crdt_mtc_writer (
    ca_id       TEXT    PRIMARY KEY,
    node_id     TEXT    NOT NULL,
    claimed_at  INTEGER NOT NULL,
    local_gen   INTEGER NOT NULL DEFAULT 0
);

-- RFC 9447 tkauth-01: JTI replay-prevention cache.
CREATE TABLE tkauth_jti_cache (
    jti      TEXT    PRIMARY KEY,
    authz_id TEXT    NOT NULL,
    expires  INTEGER NOT NULL,
    created  INTEGER NOT NULL,
    tkvalue  TEXT,                       -- JWTClaimConstraints DER for encoder-backed identifiers
    ca_flag  INTEGER NOT NULL DEFAULT 0  -- atc.ca boolean from the authority token
);
CREATE INDEX tkauth_jti_expires_idx  ON tkauth_jti_cache (expires);
CREATE INDEX tkauth_jti_authzid_idx  ON tkauth_jti_cache (authz_id, expires);

-- MTC issuance-log checkpoints produced by the CA signing key.
-- Each row captures the Merkle tree state at a specific tree size and stores
-- the CA's DER-encoded signature over the DER-encoded Checkpoint structure.
CREATE TABLE mtc_checkpoints (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id       TEXT    NOT NULL DEFAULT 'default',
    tree_size   INTEGER NOT NULL,       -- log leaf count when checkpoint was produced
    root_hex    TEXT    NOT NULL,       -- lowercase hex Merkle root
    signature   BLOB    NOT NULL,       -- MTC signing key signature over DER Checkpoint
    created     INTEGER NOT NULL,       -- Unix epoch seconds
    local_gen   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(ca_id, tree_size)
);

-- MTC landmark certificates issued at fixed tree-size intervals.
CREATE TABLE mtc_landmarks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id       TEXT    NOT NULL DEFAULT 'default',
    sequence_no INTEGER NOT NULL,
    tree_size   INTEGER NOT NULL,
    cert_der    BLOB,           -- DER-encoded LandmarkCertificate; NULL until built
    created     INTEGER NOT NULL,
    UNIQUE(ca_id, sequence_no),
    UNIQUE(ca_id, tree_size)
);

-- Third-party cosignatures over MTC checkpoints.
CREATE TABLE mtc_cosignatures (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id           TEXT    NOT NULL DEFAULT 'default',
    checkpoint_id   INTEGER NOT NULL REFERENCES mtc_checkpoints(id) ON DELETE CASCADE,
    cosigner_url    TEXT    NOT NULL,
    signature_der   BLOB    NOT NULL,
    created         INTEGER NOT NULL,
    local_gen       INTEGER NOT NULL DEFAULT 0,
    UNIQUE(checkpoint_id, cosigner_url)
);
CREATE INDEX idx_mtc_cosignatures_checkpoint ON mtc_cosignatures(checkpoint_id);

-- MTC revoked ranges: marks ranges of log entry indices as revoked (§5.6).
CREATE TABLE mtc_revoked_ranges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id       TEXT    NOT NULL,
    range_start INTEGER NOT NULL,
    range_end   INTEGER NOT NULL,
    created     INTEGER NOT NULL,
    UNIQUE(ca_id, range_start, range_end),
    CHECK(range_start <= range_end)
);

-- Idempotency cache for leaf-appends forwarded to this node's MTC writer
-- election (see gossip::mtc_forward). append_leaf has no natural
-- idempotency (each call assigns the next sequential index regardless of
-- whether it's a retry), so a retried forward must be answered from here
-- instead of appending the same certificate's leaf twice.
CREATE TABLE mtc_forwarded_appends (
    ca_id         TEXT    NOT NULL,
    serial_number TEXT    NOT NULL,
    leaf_index    INTEGER NOT NULL,
    tree_size     INTEGER NOT NULL,
    proof_cbor    BLOB    NOT NULL,
    created       INTEGER NOT NULL,
    PRIMARY KEY (ca_id, serial_number)
);

-- Policy engine rules (soft-deletable via tombstone).
CREATE TABLE policy_rules (
    id             TEXT PRIMARY KEY,
    scope          TEXT NOT NULL,
    name           TEXT NOT NULL,
    rule_json      TEXT NOT NULL,
    enabled        INTEGER NOT NULL DEFAULT 1,
    created_at     TEXT NOT NULL,
    updated_at     TEXT NOT NULL,
    created_by     TEXT,
    local_gen      INTEGER NOT NULL DEFAULT 0,
    tombstone      INTEGER NOT NULL DEFAULT 0,
    tombstone_at   INTEGER,
    -- Writer of this entry, for CRDT merge tiebreak (see crdt_cluster_nodes).
    writer_node_id TEXT NOT NULL DEFAULT '',
    CHECK ((tombstone = 0 AND tombstone_at IS NULL) OR (tombstone = 1 AND tombstone_at IS NOT NULL))
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
