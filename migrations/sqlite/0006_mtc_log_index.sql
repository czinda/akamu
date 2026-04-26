CREATE INDEX IF NOT EXISTS idx_certs_mtc_log_index
    ON certificates(mtc_log_index)
    WHERE mtc_log_index IS NOT NULL;
