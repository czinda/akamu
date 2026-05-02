-- PP CA v2.1 FAU: structured audit trail.
--
-- Records are append-only: the application never issues UPDATE or DELETE on
-- this table (FAU_STG.1(1) write-protection model).  Overflow is handled at
-- the application level via the audit_overflow / audit_max_rows config keys.
CREATE TABLE audit_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    occurred_at TEXT    NOT NULL,          -- RFC 3339 timestamp
    event_type  TEXT    NOT NULL,          -- taxonomy: see src/audit.rs AuditEventType
    subject     TEXT,                      -- JWK thumbprint, account UUID, cert serial, etc.
    principal   TEXT,                      -- operator name or "acme:<jwk_thumbprint>"
    outcome     TEXT    NOT NULL CHECK(outcome IN ('success','failure')),
    detail      TEXT                       -- JSON object with event-specific fields
);
CREATE INDEX audit_idx_type ON audit_events(event_type);
CREATE INDEX audit_idx_subj ON audit_events(subject);
CREATE INDEX audit_idx_time ON audit_events(occurred_at);
