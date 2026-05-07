-- Hot-path index additions for PostgreSQL.
--
-- 1. Partial index for the on_valid NOT EXISTS check.
--    Every successful challenge fires:
--      NOT EXISTS (SELECT 1 FROM authorizations WHERE order_id = ? AND status != 'valid')
--    A partial index covering only non-valid rows is tiny in steady state and
--    makes this subquery an index-only scan with near-zero cost.
CREATE INDEX IF NOT EXISTS idx_authz_order_nonvalid
    ON authorizations(order_id)
    WHERE status != 'valid';

-- 2. Compound index for find_valid_by_account_and_identifier.
--    The query filters by account_id AND identifier; without this index
--    PostgreSQL must fetch every authorization row for the account then
--    filter by identifier in a seq scan of the result set.
CREATE INDEX IF NOT EXISTS idx_authz_acct_ident
    ON authorizations(account_id, identifier);
