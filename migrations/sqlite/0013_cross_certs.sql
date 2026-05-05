-- Cross-certificates: CA certificates issued by one akamu CA for another CA's
-- public key (same-server CA or an external CA supplied by PEM).
--
-- Used to construct alternative trust chains when multiple CAs are deployed
-- (e.g. an RSA CA cross-signing an ML-DSA CA's public key so relying parties
-- with only RSA trust anchors can still verify ML-DSA end-entity certificates).
--
-- Rows are insert-only (never mutated after creation), so no `updated` timestamp.

CREATE TABLE cross_certs (
    id              TEXT    PRIMARY KEY,          -- UUID
    issuer_ca_id    TEXT    NOT NULL,             -- CA that signed the cross-cert
    subject_ca_id   TEXT,                         -- akamu CA ID if same-server target, NULL if external
    subject_dn      TEXT    NOT NULL,             -- RFC 4514 subject DN string
    subject_spki    BLOB    NOT NULL,             -- DER SubjectPublicKeyInfo of subject CA key
    cross_cert_der  BLOB    NOT NULL,             -- DER of the issued cross-certificate
    cross_cert_pem  TEXT    NOT NULL,             -- PEM for download
    not_before      INTEGER NOT NULL,             -- Unix epoch
    not_after       INTEGER NOT NULL,             -- Unix epoch
    serial_number   TEXT    NOT NULL,             -- hex-encoded serial (same format as certificates)
    created         INTEGER NOT NULL,             -- Unix epoch
    UNIQUE (issuer_ca_id, serial_number)          -- RFC 5280: unique within issuing CA
);

CREATE INDEX idx_cross_certs_issuer  ON cross_certs(issuer_ca_id);
-- Partial index: queries always filter on a concrete non-NULL subject_ca_id
CREATE INDEX idx_cross_certs_subject ON cross_certs(subject_ca_id)
    WHERE subject_ca_id IS NOT NULL;
