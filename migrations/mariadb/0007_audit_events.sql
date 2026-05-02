-- PP CA v2.1 FAU: structured audit trail.
--
-- Records are append-only at the application level (FAU_STG.1(1)).
CREATE TABLE audit_events (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    occurred_at VARCHAR(40)  NOT NULL,          -- RFC 3339 timestamp
    event_type  VARCHAR(64)  NOT NULL,
    subject     VARCHAR(255),                   -- JWK thumbprint, account UUID, cert serial
    principal   VARCHAR(255),                   -- operator name or "acme:<jwk_thumbprint>"
    outcome     VARCHAR(8)   NOT NULL CHECK(outcome IN ('success','failure')),  -- 'success' | 'failure'
    detail      TEXT                            -- JSON object with event-specific fields
);
CREATE INDEX audit_idx_type ON audit_events(event_type);
CREATE INDEX audit_idx_subj ON audit_events(subject);
CREATE INDEX audit_idx_time ON audit_events(occurred_at);
