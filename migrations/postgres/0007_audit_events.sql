-- PP CA v2.1 FAU: structured audit trail.
--
-- Records are append-only at the application level (FAU_STG.1(1)).
CREATE TABLE audit_events (
    id          BIGSERIAL   PRIMARY KEY,
    occurred_at TEXT        NOT NULL,          -- RFC 3339 timestamp
    event_type  TEXT        NOT NULL,
    subject     TEXT,                          -- JWK thumbprint, account UUID, cert serial
    principal   TEXT,                          -- operator name or "acme:<jwk_thumbprint>"
    outcome     TEXT        NOT NULL CHECK(outcome IN ('success','failure')),
    detail      TEXT                           -- JSON object with event-specific fields
);
CREATE INDEX audit_idx_type ON audit_events(event_type);
CREATE INDEX audit_idx_subj ON audit_events(subject);
CREATE INDEX audit_idx_time ON audit_events(occurred_at);
