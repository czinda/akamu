-- MTC revoked ranges: marks ranges of log entry indices as revoked (§5.6).
CREATE TABLE IF NOT EXISTS mtc_revoked_ranges (
    id          BIGSERIAL PRIMARY KEY,
    ca_id       TEXT    NOT NULL,
    range_start BIGINT  NOT NULL,
    range_end   BIGINT  NOT NULL,
    created     BIGINT  NOT NULL,
    UNIQUE(ca_id, range_start, range_end),
    CHECK(range_start <= range_end)
);
