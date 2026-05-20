# Cluster Setup and Gossip Replication

Akamu supports multi-node deployments through CRDT-based gossip replication.  Each node
maintains its own local SQLite (or PostgreSQL/MariaDB) database and replicates state to
peers over an authenticated, encrypted gossip channel.

## Prerequisites

- **Separate database per node.** Each node holds its own database; there is no shared
  database in a cluster.  Provision one SQLite/PostgreSQL/MariaDB instance per node.
- **CA private keys on every node.** CA keys are never replicated.  Copy the CA PEM files
  to every node before starting it.
- **Network reachability.** Each node must be able to reach every peer's gossip URL
  (typically the admin socket or a dedicated internal port).
- **Firewall rules.** Gossip traffic goes to the admin interface.  Keep it off the public
  ACME listener.

## Configuration

Add a `[gossip]` section to each node's `akamu.toml`:

```toml
[gossip]
# URLs of all other cluster nodes (admin base URL, not the ACME URL).
peers = [
    "http://node2.acme.internal:8081",
    "http://node3.acme.internal:8081",
]

# How often to run a gossip round (seconds).  Default: 15.
interval_secs = 15

# How long to keep tombstoned entries before GC (seconds).  Default: 604800 = 7 days.
tombstone_ttl_secs = 604800

# How long a node may claim exclusive ownership of an order/MTC write slot
# before another node may take over.  Default: 150 seconds.
ownership_ttl_secs = 150
```

Omitting the `[gossip]` section entirely puts the node in single-node mode: no replication,
no gossip background task.

## Startup Sequence

On first start a new node:

1. Generates an ML-KEM-768 key pair and an ECDSA P-256 gossip signing key pair.
2. Stores both key pairs in the local database (`node_keys` table).
3. Registers itself in the in-memory CRDT cluster node map.
4. Starts the gossip background loop.

On the first successful gossip round with each peer the node logs:

```
INFO gossip: first-contact merge complete  peer="http://node2.acme.internal:8081"
    accounts=142 orders=891 certificates=734 authorizations=1023 cluster_nodes=2
```

After this log line the node has full knowledge of all existing ACME state and is ready to
serve requests.

## Adding a Node to a Running Cluster

1. Provision the new node's database and CA key files.
2. Add the new node's gossip URL to every existing node's `peers` list and reload their
   configuration (SIGHUP or restart).
3. Start the new node with a `[gossip]` section listing at least one existing peer.
4. Wait for the "first-contact merge complete" log line.  The new node is now in sync.

## Troubleshooting

### `gossip: no KEM key for peer, skipping`

The peer is not yet in the cluster node map.  This is normal for 1–2 rounds after a new
node starts.  If it persists after 3 rounds, check that:

- The peer node started successfully and its gossip loop is running.
- The peer's gossip URL is reachable from this node.
- Both nodes list each other in their `peers` configuration.

### `gossip: verify_and_open response failed`

The response could not be authenticated.  Possible causes:

- Clock skew between nodes (default tolerance is `tombstone_ttl_secs`; a node whose clock
  is wildly ahead will produce envelopes that look stale to peers).
- A misconfigured or corrupted `node_keys` table.

### `X-Akamu-Node-Id` header rejected by peer

The responding peer's handler rejected the sender's node ID because the sender is not yet
in the peer's `cluster_nodes` CRDT.  This resolves automatically after the first successful
full-state exchange.  If it does not resolve, verify that gossip traffic is not blocked by a
firewall between the nodes.

### Gossip stalls entirely

Check that the `[gossip]` section is present in `akamu.toml` and that `peers` is non-empty.
A node with no configured peers (or no `[gossip]` section) logs
`gossip: no peers configured — loop disabled` and exits the gossip loop immediately.
