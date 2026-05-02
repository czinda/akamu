-- PP CA v2.1 FMT: operator accounts with role-based access control.
--
-- Each operator is identified by a client certificate fingerprint, a
-- Kerberos principal, or both.  At least one must be non-NULL (enforced by
-- the CHECK constraint).
CREATE TABLE operators (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL,
    role             TEXT    NOT NULL
                             CHECK(role IN ('administrator','ca_operations','ca_ra','auditor')),
    cert_fingerprint TEXT    UNIQUE,   -- SHA-256 hex of DER leaf cert; NULL = no cert auth
    gssapi_principal TEXT    UNIQUE,   -- Kerberos principal e.g. alice@REALM; NULL = no GSSAPI auth
    created_at       TEXT    NOT NULL, -- RFC 3339
    last_seen_at     TEXT,             -- RFC 3339; updated on each successful authentication
    active           INTEGER NOT NULL DEFAULT 1,
    CHECK(cert_fingerprint IS NOT NULL OR gssapi_principal IS NOT NULL)
);
