-- FAU_SCR_EXT.1: add searchable subject DN column to certificates.
ALTER TABLE certificates ADD COLUMN subject_dn TEXT;
CREATE INDEX idx_certs_subject_dn ON certificates(subject_dn);
