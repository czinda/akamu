-- HMAC algorithm the EAB key was issued with (e.g. "sha256", "sha384", "sha512").
-- Defaults to sha256 for keys created before this migration.
ALTER TABLE eab_keys ADD COLUMN alg TEXT NOT NULL DEFAULT 'sha256';
