-- RFC 9773 §5: replaces/replaced-by linkage for ACME Renewal Information (ARI)
ALTER TABLE orders ADD COLUMN replaces TEXT;
ALTER TABLE certificates ADD COLUMN replaced_by TEXT;
CREATE INDEX IF NOT EXISTS idx_orders_replaces ON orders(replaces) WHERE replaces IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_certs_replaced_by ON certificates(replaced_by)
    WHERE replaced_by IS NOT NULL;
