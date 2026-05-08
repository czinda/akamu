-- RFC 9115 ACME profile for delegated certificates.
--
-- Delegation objects represent a pre-configured delegation from an Identifier Owner (IdO)
-- to a Name Delegation Consumer (NDC).  Each delegation carries a CSR template that the
-- NDC must satisfy when submitting finalize requests, and an optional CNAME map.
CREATE TABLE IF NOT EXISTS delegations (
    id           VARCHAR(64)  PRIMARY KEY,
    account_id   VARCHAR(64)  NOT NULL,
    csr_template MEDIUMTEXT   NOT NULL,  -- JSON per RFC 9115 §4 / Appendix A
    cname_map    MEDIUMTEXT,             -- JSON {fqdn: fqdn} or NULL
    created      BIGINT       NOT NULL,
    updated      BIGINT       NOT NULL,
    FOREIGN KEY (account_id) REFERENCES accounts(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
CREATE INDEX idx_delegations_account ON delegations(account_id);

-- Orders: delegation reference and non-STAR unauthenticated-GET flag.
-- delegation_id: FK into delegations(id); NULL for non-delegation orders.
-- allow_cert_get: top-level allow-certificate-get flag (RFC 9115 §2.3.5).
--   Distinct from star_allow_cert_get which lives inside the auto-renewal subobject.
-- upstream_order_url: Order2 URL on the upstream CA (IdO→CA leg); NULL until submitted.
-- upstream_cert_url:  cert/star-cert URL returned by the upstream CA; NULL until valid.
ALTER TABLE orders ADD COLUMN IF NOT EXISTS delegation_id       VARCHAR(64), ALGORITHM=INSTANT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS allow_cert_get      TINYINT(1)  NOT NULL DEFAULT 0, ALGORITHM=INSTANT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS upstream_order_url  TEXT, ALGORITHM=INSTANT;
ALTER TABLE orders ADD COLUMN IF NOT EXISTS upstream_cert_url   TEXT, ALGORITHM=INSTANT;

-- FK constraint is added separately; InnoDB does not permit ALGORITHM=INSTANT for FK additions.
ALTER TABLE orders
    ADD CONSTRAINT fk_orders_delegation FOREIGN KEY (delegation_id) REFERENCES delegations(id);

-- MariaDB does not support partial indexes; full index on delegation_id.
-- (SQLite and PostgreSQL use a WHERE clause to create a sparse index on non-NULL rows only.)
CREATE INDEX IF NOT EXISTS idx_orders_delegation ON orders(delegation_id) ALGORITHM=INPLACE LOCK=NONE;

-- Composite index for list_pending_delegation_orders (no partial index support in MariaDB).
CREATE INDEX IF NOT EXISTS idx_orders_delegation_status ON orders(delegation_id, status) ALGORITHM=INPLACE LOCK=NONE;
