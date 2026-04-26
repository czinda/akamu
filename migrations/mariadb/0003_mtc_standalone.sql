ALTER TABLE certificates ADD COLUMN mtc_standalone_der MEDIUMBLOB;
CREATE INDEX idx_certs_mtc_log_index ON certificates(mtc_log_index);
