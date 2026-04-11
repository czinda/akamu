-- RFC 8739 ACME STAR: auto-renewal fields on orders
ALTER TABLE orders ADD COLUMN star_start_date INTEGER;           -- Unix timestamp, optional
ALTER TABLE orders ADD COLUMN star_end_date INTEGER;             -- Unix timestamp, required for STAR
ALTER TABLE orders ADD COLUMN star_lifetime_secs INTEGER;        -- lifetime of each cert, seconds
ALTER TABLE orders ADD COLUMN star_lifetime_adjust_secs INTEGER NOT NULL DEFAULT 0;
ALTER TABLE orders ADD COLUMN star_allow_cert_get INTEGER NOT NULL DEFAULT 0;
ALTER TABLE orders ADD COLUMN star_canceled_at INTEGER;          -- set on cancellation
ALTER TABLE orders ADD COLUMN star_csr_der BLOB;                 -- stored CSR DER for reissuance

-- Index for efficient background STAR renewal task queries
CREATE INDEX IF NOT EXISTS idx_orders_star ON orders(star_end_date) WHERE star_end_date IS NOT NULL;
