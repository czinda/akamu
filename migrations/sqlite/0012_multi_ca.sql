-- Multi-CA support: record which CA issued each order and certificate,
-- and which CA an account is scoped to.
--
-- Sentinel conventions (two intentionally different values):
--   accounts.ca_id = '' (empty string) means "server-wide scope — account may use any CA".
--     '' is not a valid CA ID (config validator requires ^[a-zA-Z0-9]), so no collision.
--   orders.ca_id = 'default' backfills pre-migration rows to the canonical single-CA name.
--   certificates.ca_id = 'default' — same.
--     'default' is the auto-assigned ID for single-CA compatibility mode.

ALTER TABLE accounts     ADD COLUMN ca_id TEXT NOT NULL DEFAULT '';
ALTER TABLE orders       ADD COLUMN ca_id TEXT NOT NULL DEFAULT 'default';
ALTER TABLE certificates ADD COLUMN ca_id TEXT NOT NULL DEFAULT 'default';

CREATE INDEX idx_accounts_ca_id ON accounts(ca_id);
CREATE INDEX idx_orders_ca_id ON orders(ca_id);
CREATE INDEX idx_certs_ca_id  ON certificates(ca_id);
-- Composite index for CRL generation: WHERE status = 'revoked' AND ca_id = ?
CREATE INDEX idx_certs_ca_id_revoked ON certificates(ca_id) WHERE status = 'revoked';
