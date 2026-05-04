-- PP CA v2.1 FMT: operator accounts with role-based access control.
--
-- NOTE: This is migration 0009 for SQLite but 0008 for Postgres and MariaDB.
-- The offset exists because SQLite has an extra migration (0006_mtc_log_index.sql)
-- for WAL-mode index tuning that is not applicable to Postgres/MariaDB.
-- All future migrations must use the next number per backend:
--   SQLite: 0010+, Postgres/MariaDB: 0009+.
--
-- Each operator is identified by a client certificate fingerprint, a
-- Kerberos principal, or both.  At least one must be non-NULL (enforced by
-- the CHECK constraint).
CREATE TABLE operators (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    name             TEXT    NOT NULL UNIQUE,
    role             TEXT    NOT NULL
                             CHECK(role IN ('administrator','ca_operations','ca_ra','auditor')),
    cert_fingerprint TEXT    UNIQUE,   -- SHA-256 hex of DER leaf cert; NULL = no cert auth
    gssapi_principal TEXT    UNIQUE,   -- Kerberos principal e.g. alice@REALM; NULL = no GSSAPI auth
    created_at       TEXT    NOT NULL, -- RFC 3339
    last_seen_at     TEXT,             -- RFC 3339; updated on each successful authentication
    active           INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
    CHECK(cert_fingerprint IS NOT NULL OR gssapi_principal IS NOT NULL)
);
