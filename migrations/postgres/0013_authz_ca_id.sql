-- no-transaction
-- Add ca_id to authorizations so that per-CA namespace isolation can be
-- enforced for both order-linked authzs and standalone pre-authorizations.
--
-- Backfill: authzs linked to an order inherit the order's ca_id.
-- Standalone pre-authzs (order_id IS NULL) keep ca_id = 'default' — correct
-- for deployments that had only one CA before the multi-CA migration.
--
-- Run outside a transaction so that CREATE INDEX CONCURRENTLY can proceed
-- without a lock.  The UPDATE backfill is idempotent: if the migration is
-- interrupted and re-run, rows already set correctly are updated to the same
-- value (no-op).

ALTER TABLE authorizations ADD COLUMN IF NOT EXISTS ca_id TEXT NOT NULL DEFAULT 'default';

UPDATE authorizations
   SET ca_id = orders.ca_id
  FROM orders
 WHERE orders.id = authorizations.order_id
   AND authorizations.order_id IS NOT NULL
   AND authorizations.order_id != '';

-- Composite index for admin API queries that filter by both CA and account.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_ca_account ON orders(ca_id, account_id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_authzs_ca_id ON authorizations(ca_id);
