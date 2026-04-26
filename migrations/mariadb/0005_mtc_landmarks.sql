CREATE TABLE IF NOT EXISTS mtc_landmarks (
    id          BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    sequence_no BIGINT      NOT NULL UNIQUE,
    tree_size   BIGINT      NOT NULL UNIQUE,
    cert_der    MEDIUMBLOB,
    created     BIGINT      NOT NULL
);
CREATE INDEX idx_mtc_landmarks_seq ON mtc_landmarks(sequence_no DESC);
