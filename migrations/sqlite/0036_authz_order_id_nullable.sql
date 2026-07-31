-- Make authorizations.order_id nullable: RFC 8555 §7.4.1 standalone
-- pre-authorizations (POST /acme/new-authz) are not linked to any order, but
-- the original schema declared order_id NOT NULL, so every pre-authorization
-- request failed with a NOT NULL constraint violation. SQLite cannot DROP
-- NOT NULL via ALTER TABLE, so the table is recreated.
CREATE TABLE authorizations_new (
    id                     TEXT    PRIMARY KEY,
    order_id               TEXT    REFERENCES orders(id),
    account_id             TEXT    NOT NULL REFERENCES accounts(id),
    status                 TEXT    NOT NULL DEFAULT 'pending',
    identifier             TEXT    NOT NULL,
    expires                INTEGER,
    wildcard               INTEGER NOT NULL DEFAULT 0,
    subdomain_auth_allowed INTEGER NOT NULL DEFAULT 0,
    created                INTEGER NOT NULL,
    updated                INTEGER NOT NULL,
    ca_id                  TEXT    NOT NULL DEFAULT 'default',
    local_gen              INTEGER NOT NULL DEFAULT 0
);
INSERT INTO authorizations_new
    (id, order_id, account_id, status, identifier, expires, wildcard,
     subdomain_auth_allowed, created, updated, ca_id, local_gen)
    SELECT id, order_id, account_id, status, identifier, expires, wildcard,
           subdomain_auth_allowed, created, updated, ca_id, local_gen
    FROM authorizations;
DROP TABLE authorizations;
ALTER TABLE authorizations_new RENAME TO authorizations;

CREATE INDEX idx_authz_order   ON authorizations(order_id);
CREATE INDEX idx_authz_account ON authorizations(account_id);
CREATE INDEX idx_authzs_ca_id  ON authorizations(ca_id);
