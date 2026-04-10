-- RFC 9773: ACME Renewal Information (ARI) extension
-- Adds suggested renewal window columns to certificates
ALTER TABLE certificates ADD COLUMN suggested_window_start INTEGER;  -- Unix epoch
ALTER TABLE certificates ADD COLUMN suggested_window_end   INTEGER;  -- Unix epoch
