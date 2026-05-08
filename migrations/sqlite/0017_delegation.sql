-- RFC 9115 ACME profile for delegated certificates.
--
-- Delegation objects represent a pre-configured delegation from an Identifier Owner (IdO)
-- to a Name Delegation Consumer (NDC).  Each delegation carries a CSR template that the
-- NDC must satisfy when submitting finalize requests, and an optional CNAME map.
CREATE TABLE IF NOT EXISTS delegations (
    id           TEXT    PRIMARY KEY,
    account_id   TEXT    NOT NULL REFERENCES accounts(id),
    csr_template TEXT    NOT NULL,  -- JSON per RFC 9115 §4 / Appendix A
    cname_map    TEXT,              -- JSON {fqdn: fqdn} or NULL
    created      INTEGER NOT NULL,
    updated      INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_delegations_account ON delegations(account_id);

-- Orders: delegation reference and non-STAR unauthenticated-GET flag.
-- delegation_id: FK into delegations(id); NULL for non-delegation orders.
-- allow_cert_get: top-level allow-certificate-get flag (RFC 9115 §2.3.5).
--   Distinct from star_allow_cert_get which lives inside the auto-renewal subobject.
-- upstream_order_url: Order2 URL on the upstream CA (IdO→CA leg); NULL until submitted.
-- upstream_cert_url:  cert/star-cert URL returned by the upstream CA; NULL until valid.
ALTER TABLE orders ADD COLUMN delegation_id       TEXT REFERENCES delegations(id);
ALTER TABLE orders ADD COLUMN allow_cert_get      INTEGER NOT NULL DEFAULT 0;
ALTER TABLE orders ADD COLUMN upstream_order_url  TEXT;
ALTER TABLE orders ADD COLUMN upstream_cert_url   TEXT;

CREATE INDEX IF NOT EXISTS idx_orders_delegation ON orders(delegation_id) WHERE delegation_id IS NOT NULL;

-- Composite index to accelerate list_pending_delegation_orders (status='processing' filter).
CREATE INDEX IF NOT EXISTS idx_orders_delegation_status
    ON orders(delegation_id, status)
    WHERE delegation_id IS NOT NULL AND status = 'processing';
