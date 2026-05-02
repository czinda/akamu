-- PP CA v2.1 FMT: operator accounts with role-based access control.
CREATE TABLE operators (
    id               BIGSERIAL   PRIMARY KEY,
    name             TEXT        NOT NULL UNIQUE,
    role             TEXT        NOT NULL
                                 CHECK(role IN ('administrator','ca_operations','ca_ra','auditor')),
    cert_fingerprint TEXT        UNIQUE,       -- SHA-256 hex; NULL = no cert auth
    gssapi_principal TEXT        UNIQUE,       -- Kerberos principal; NULL = no GSSAPI auth
    created_at       TEXT        NOT NULL,     -- RFC 3339
    last_seen_at     TEXT,                     -- RFC 3339
    active           SMALLINT    NOT NULL DEFAULT 1,
    CHECK(cert_fingerprint IS NOT NULL OR gssapi_principal IS NOT NULL)
);
