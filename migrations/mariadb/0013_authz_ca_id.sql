-- Add ca_id to authorizations so that per-CA namespace isolation can be
-- enforced for both order-linked authzs and standalone pre-authorizations.
--
-- Backfill: authzs linked to an order inherit the order's ca_id.
-- Standalone pre-authzs (order_id IS NULL) keep ca_id = 'default' — correct
-- for deployments that had only one CA before the multi-CA migration.
--
-- ALGORITHM=INSTANT: metadata-only ADD COLUMN on MariaDB 10.3+.

ALTER TABLE authorizations
    ADD COLUMN ca_id VARCHAR(64) NOT NULL DEFAULT 'default',
    ALGORITHM=INSTANT;

UPDATE authorizations a
  INNER JOIN orders o ON o.id = a.order_id
   SET a.ca_id = o.ca_id
 WHERE a.order_id IS NOT NULL AND a.order_id != '';

-- Composite index for admin API queries that filter by both CA and account.
CREATE INDEX idx_orders_ca_account ON orders(ca_id, account_id);
CREATE INDEX idx_authzs_ca_id ON authorizations(ca_id);
