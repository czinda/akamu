-- PP CA v2.1 FMT: operator accounts with role-based access control.
CREATE TABLE operators (
    id               BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    name             VARCHAR(255) NOT NULL UNIQUE,
    role             VARCHAR(32)  NOT NULL,     -- administrator|ca_operations|ca_ra|auditor
    cert_fingerprint VARCHAR(128) UNIQUE,       -- SHA-256 hex; NULL = no cert auth
    gssapi_principal VARCHAR(255) UNIQUE,       -- Kerberos principal; NULL = no GSSAPI auth
    created_at       VARCHAR(40)  NOT NULL,     -- RFC 3339
    last_seen_at     VARCHAR(40),               -- RFC 3339
    active           BIGINT       NOT NULL DEFAULT 1,
    -- MariaDB 10.2.1+ enforces CHECK constraints
    CHECK(role IN ('administrator','ca_operations','ca_ra','auditor')),
    CHECK(active IN (0, 1)),
    CHECK(cert_fingerprint IS NOT NULL OR gssapi_principal IS NOT NULL)
);
