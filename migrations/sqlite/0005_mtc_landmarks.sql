CREATE TABLE IF NOT EXISTS mtc_landmarks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sequence_no INTEGER NOT NULL UNIQUE,
    tree_size   INTEGER NOT NULL UNIQUE,
    cert_der    BLOB,           -- DER-encoded LandmarkCertificate; NULL until built
    created     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mtc_landmarks_seq ON mtc_landmarks(sequence_no DESC);
