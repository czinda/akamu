-- Cluster node registry: replicated via gossip, mirroring AkaCrdt.cluster_nodes.
CREATE TABLE IF NOT EXISTS crdt_cluster_nodes (
    node_id                  TEXT    PRIMARY KEY,
    gossip_url               TEXT    NOT NULL,
    kem_public_key_der       BLOB    NOT NULL,
    signing_public_key_der   BLOB    NOT NULL,
    signing_certificate_der  BLOB    NOT NULL,
    ca_ids                   TEXT    NOT NULL DEFAULT '[]', -- JSON array of CA IDs
    registered_at            INTEGER NOT NULL,
    tombstone                INTEGER NOT NULL DEFAULT 0,
    tombstone_at             INTEGER,
    local_gen                INTEGER NOT NULL DEFAULT 0
);

-- Gossip-consensus order ownership: one row per order that has a live claim.
-- Ownership lapses when claimed_at + ownership_ttl_secs < now.
CREATE TABLE IF NOT EXISTS crdt_order_owners (
    order_id    TEXT    PRIMARY KEY,
    node_id     TEXT    NOT NULL,
    claimed_at  INTEGER NOT NULL,
    local_gen   INTEGER NOT NULL DEFAULT 0
);

-- MTC writer election: at most one row (application always uses id = 'singleton').
CREATE TABLE IF NOT EXISTS crdt_mtc_writer (
    id          TEXT    PRIMARY KEY,
    node_id     TEXT    NOT NULL,
    claimed_at  INTEGER NOT NULL,
    local_gen   INTEGER NOT NULL DEFAULT 0
);
