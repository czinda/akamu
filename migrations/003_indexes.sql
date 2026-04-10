-- Performance indexes identified as missing in the initial schema.

-- certificates.status is queried heavily by list_revoked (CRL generation)
-- and filtered alongside account_id + not_after by list_valid_for_account.
CREATE INDEX IF NOT EXISTS idx_certs_status
    ON certificates(status);

CREATE INDEX IF NOT EXISTS idx_certs_account_status_not_after
    ON certificates(account_id, status, not_after);

-- nonces.created is used by sweep_expired (DELETE WHERE created < ?).
CREATE INDEX IF NOT EXISTS idx_nonces_created
    ON nonces(created);
