-- Hot-path index additions for MariaDB.
-- Equivalent to postgres/0018_hot_indexes.sql (minus the partial index — MariaDB does not
-- support WHERE-clause partial indexes).
--
-- Compound index for find_valid_by_account_and_identifier.
-- The query filters by account_id AND identifier; without this index MariaDB must
-- fetch every authorization row for the account then filter by identifier in memory.
CREATE INDEX IF NOT EXISTS idx_authz_acct_ident
    ON authorizations(account_id, identifier) ALGORITHM=INPLACE LOCK=NONE;
