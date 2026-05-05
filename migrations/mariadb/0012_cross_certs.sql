-- Cross-certificates: CA certificates issued by one akamu CA for another CA's
-- public key (same-server CA or an external CA supplied by PEM).
--
-- Used to construct alternative trust chains when multiple CAs are deployed
-- (e.g. an RSA CA cross-signing an ML-DSA CA's public key so relying parties
-- with only RSA trust anchors can still verify ML-DSA end-entity certificates).
--
-- Rows are insert-only (never mutated after creation), so no `updated` timestamp.

CREATE TABLE cross_certs (
    id              VARCHAR(36)   NOT NULL PRIMARY KEY,  -- UUID
    issuer_ca_id    VARCHAR(64)   NOT NULL,              -- CA that signed the cross-cert
    subject_ca_id   VARCHAR(64)   DEFAULT NULL,          -- akamu CA ID if same-server, NULL if external
    subject_dn      TEXT          NOT NULL,              -- RFC 4514 subject DN string
    subject_spki    MEDIUMBLOB    NOT NULL,              -- DER SubjectPublicKeyInfo of subject CA key
    cross_cert_der  MEDIUMBLOB    NOT NULL,              -- DER of the issued cross-certificate
    cross_cert_pem  MEDIUMTEXT    NOT NULL,              -- PEM for download
    not_before      BIGINT        NOT NULL,              -- Unix epoch
    not_after       BIGINT        NOT NULL,              -- Unix epoch
    serial_number   VARCHAR(255)  NOT NULL,              -- hex-encoded serial (matches certificates table)
    created         BIGINT        NOT NULL,              -- Unix epoch
    UNIQUE (issuer_ca_id, serial_number)                 -- RFC 5280: unique within issuing CA
);

CREATE INDEX idx_cross_certs_issuer  ON cross_certs(issuer_ca_id);
-- MariaDB does not support partial indexes; full index on subject_ca_id.
CREATE INDEX idx_cross_certs_subject ON cross_certs(subject_ca_id);
