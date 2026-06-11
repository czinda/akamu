-- MTC revoked ranges: marks ranges of log entry indices as revoked (§5.6).
CREATE TABLE IF NOT EXISTS mtc_revoked_ranges (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ca_id       TEXT    NOT NULL,
    range_start INTEGER NOT NULL,
    range_end   INTEGER NOT NULL,
    created     INTEGER NOT NULL,
    UNIQUE(ca_id, range_start, range_end),
    CHECK(range_start <= range_end)
);
