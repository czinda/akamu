-- Cluster node registry: replicated via gossip, mirroring AkaCrdt.cluster_nodes.
CREATE TABLE IF NOT EXISTS crdt_cluster_nodes (
    node_id                  TEXT    PRIMARY KEY,
    gossip_url               TEXT    NOT NULL,
    kem_public_key_der       BYTEA   NOT NULL,
    signing_public_key_der   BYTEA   NOT NULL,
    signing_certificate_der  BYTEA   NOT NULL,
    ca_ids                   TEXT    NOT NULL DEFAULT '[]', -- JSON array of CA IDs
    registered_at            BIGINT  NOT NULL,
    tombstone                SMALLINT NOT NULL DEFAULT 0,
    tombstone_at             BIGINT,
    local_gen                BIGINT  NOT NULL DEFAULT 0
);

-- Gossip-consensus order ownership: one row per order that has a live claim.
-- Ownership lapses when claimed_at + ownership_ttl_secs < now.
CREATE TABLE IF NOT EXISTS crdt_order_owners (
    order_id    TEXT    PRIMARY KEY,
    node_id     TEXT    NOT NULL,
    claimed_at  BIGINT  NOT NULL,
    local_gen   BIGINT  NOT NULL DEFAULT 0
);

-- MTC writer election: at most one row (application always uses id = 'singleton').
CREATE TABLE IF NOT EXISTS crdt_mtc_writer (
    id          TEXT    PRIMARY KEY,
    node_id     TEXT    NOT NULL,
    claimed_at  BIGINT  NOT NULL,
    local_gen   BIGINT  NOT NULL DEFAULT 0
);
