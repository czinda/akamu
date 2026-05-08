-- no-transaction
-- Concurrent indexes for delegation tables — must run outside a transaction.
-- Separated from 0016_delegation.sql so the transactional DDL can be atomic.

-- Partial index: only delegation orders are indexed (sparse; keeps the index tiny).
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_delegations_account ON delegations(account_id);

-- Sparse index on orders.delegation_id.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_delegation
    ON orders(delegation_id)
    WHERE delegation_id IS NOT NULL;

-- Composite partial index to accelerate list_pending_delegation_orders.
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_orders_delegation_status
    ON orders(delegation_id, status)
    WHERE delegation_id IS NOT NULL AND status = 'processing';
