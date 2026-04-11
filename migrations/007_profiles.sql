-- draft-aaron-acme-profiles-01: add profile column to orders table.
-- NULL means the order was placed without a profile (server applies its default).
ALTER TABLE orders ADD COLUMN profile TEXT;
