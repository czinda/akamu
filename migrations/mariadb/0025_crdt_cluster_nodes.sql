-- Cluster node registry: replicated via gossip, mirroring AkaCrdt.cluster_nodes.
CREATE TABLE IF NOT EXISTS crdt_cluster_nodes (
    node_id                  VARCHAR(255) PRIMARY KEY,
    gossip_url               TEXT         NOT NULL,
    kem_public_key_der       MEDIUMBLOB   NOT NULL,
    signing_public_key_der   MEDIUMBLOB   NOT NULL,
    signing_certificate_der  MEDIUMBLOB   NOT NULL,
    ca_ids                   TEXT         NOT NULL DEFAULT '[]',
    registered_at            BIGINT       NOT NULL,
    tombstone                TINYINT      NOT NULL DEFAULT 0,
    tombstone_at             BIGINT,
    local_gen                BIGINT       NOT NULL DEFAULT 0,
    CONSTRAINT ck_tombstone_consistency CHECK (
        (tombstone = 0 AND tombstone_at IS NULL) OR
        (tombstone = 1 AND tombstone_at IS NOT NULL)
    )
);

-- Gossip-consensus order ownership: one row per order that has a live claim.
-- Ownership lapses when claimed_at + ownership_ttl_secs < now.
CREATE TABLE IF NOT EXISTS crdt_order_owners (
    order_id    VARCHAR(64)  PRIMARY KEY,
    node_id     VARCHAR(255) NOT NULL,
    claimed_at  BIGINT       NOT NULL,
    local_gen   BIGINT       NOT NULL DEFAULT 0
);

-- MTC writer election: at most one row (application always uses id = 'singleton').
CREATE TABLE IF NOT EXISTS crdt_mtc_writer (
    id          VARCHAR(32)  PRIMARY KEY,
    node_id     VARCHAR(255) NOT NULL,
    claimed_at  BIGINT       NOT NULL,
    local_gen   BIGINT       NOT NULL DEFAULT 0
);
