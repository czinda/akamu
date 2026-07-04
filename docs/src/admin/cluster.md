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
- **NTP synchronisation.** All cluster nodes must run NTP or an equivalent time-sync
  daemon.  Clock skew between nodes must stay below `clock_skew_tolerance_secs` (default
  30 seconds).  Exceeding this threshold causes gossip envelopes to be rejected as
  future-dated or stale.

## Cluster Sizing

### Minimum nodes

A single node with a `[gossip]` section and an empty `peers` list runs in single-node
mode (the gossip loop logs `gossip: no peers configured — loop disabled` and exits).  A
two-node cluster is the minimum for replication and provides basic redundancy; however,
there is no quorum concept — each node operates independently, so a two-node cluster
continues to serve requests when one node is down.

### Recommended configurations

| Cluster size | Use case | Notes |
|---|---|---|
| 1 node | Development, low-volume production | No replication; simplest operation |
| 2–3 nodes | Typical production HA | Full mesh gossip (`fan_out = 0`); every node contacts every peer each round |
| 4–7 nodes | High-availability production | Full mesh still practical; consider `fan_out = 3` at 5+ nodes |
| 8+ nodes | Large-scale or multi-region | Set `fan_out = 3–5` to bound O(N^2) gossip overhead; convergence in ceil(N/fan_out) rounds |

### Resource requirements per node

Gossip adds moderate overhead to a standalone Akamu deployment:

- **Memory:** The full CRDT is held in memory on every node (accounts, orders,
  authorizations, challenges, certificates, EAB keys, operators, delegations, MTC data).
  For a cluster with 100,000 certificates and associated state, expect approximately
  100–300 MiB of additional RSS per node beyond the base process footprint.
- **CPU:** Each gossip round involves CBOR serialisation, zstd compression, ML-KEM-768
  encapsulation, AES-256-GCM encryption, and ECDSA P-256 signing.  This is negligible at
  the default 15-second interval but becomes measurable if `interval_secs` is set below 5
  or `fan_out` is large.
- **Disk:** The CRDT database (`crdt_db_url`) is persisted every 30 seconds.  Size is
  proportional to the ACME state (roughly 1–2x the main database).
- **Network:** Each gossip round transfers a delta (typically a few KiB) or, on first
  contact, the full CRDT (proportional to total ACME state).  Bandwidth is bounded by
  `fan_out * delta_size * (1 / interval_secs)` per node.

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

## Full Gossip Configuration Reference

All keys in the `[gossip]` TOML section:

### `peers`

**Optional. Default: `[]`.**

List of peer gossip URLs to push CRDT state to.  Each entry must be the base URL of a
peer Akamu node's admin interface (scheme, host, and optional port; no trailing path).
The gossip loop also discovers peers dynamically from the CRDT's `cluster_nodes` map, so
a new node only needs to list one existing peer to bootstrap into the cluster; the
remaining peers will be discovered automatically after the first successful gossip round.

```toml
peers = ["https://node2.acme.internal:8443", "https://node3.acme.internal:8443"]
```

### `interval_secs`

**Optional. Default: `15`.**

How often (in seconds) the background gossip loop fires and pushes CRDT deltas to peers.
Lower values reduce replication lag at the cost of more network traffic and CPU.  The
minimum effective value is 1 second; values below 1 are clamped to 1.

In addition to this periodic timer, the gossip loop wakes immediately on local CRDT
writes (with a 20 ms sliding debounce window, capped at 150 ms, and a 500 ms minimum
interval between write-triggered rounds).  This means writes propagate within roughly 500
ms even when `interval_secs` is set high.

```toml
interval_secs = 15
```

### `tombstone_ttl_secs`

**Optional. Default: `604800` (7 days).**

How long tombstone (deletion) records are retained in the CRDT before garbage collection
removes them.  Tombstones must be retained long enough to ensure every peer in the cluster
has received the deletion before the record is purged.  If a node is offline for longer
than this period, it may re-introduce deleted entries when it rejoins the cluster.

Tombstone GC runs hourly under a write lock.

```toml
tombstone_ttl_secs = 604800
```

### `ownership_ttl_secs`

**Optional. Default: `150`.**

Lease duration in seconds for exclusive write-ownership of ACME orders and MTC log writer
elections.  When a node claims ownership of an order (to process finalization) or the MTC
writer role, the claim is valid for this many seconds.  If the owning node crashes or
becomes unreachable, another node can take over after the TTL expires.

The default of 150 seconds is intentionally longer than a typical HTTP timeout (30–60 s)
so that transient gossip failures do not cause ownership to flap.  With a 15-second gossip
interval, a claim survives at least nine missed rounds.

```toml
ownership_ttl_secs = 150
```

### `gossip_envelope_max_age_secs`

**Optional. Default: `300` (5 minutes).**

Maximum age in seconds of an accepted gossip envelope.  Envelopes with an `issued_at`
timestamp older than `now - gossip_envelope_max_age_secs` are rejected as stale.  This
provides replay protection: even if an attacker captures a valid signed envelope, it
becomes unusable after this window expires.

```toml
gossip_envelope_max_age_secs = 300
```

### `clock_skew_tolerance_secs`

**Optional. Default: `30`.**

Maximum acceptable clock difference between cluster nodes, in seconds.  Gossip envelopes
with an `issued_at` timestamp more than this many seconds *in the future* relative to the
receiver's clock are rejected.  Ensure NTP synchronisation across all cluster members
keeps skew well below this threshold.

If you observe `gossip/sync: rejecting future-dated envelope` log messages, check NTP
synchronisation on both the sender and receiver nodes.

```toml
clock_skew_tolerance_secs = 30
```

### `fan_out`

**Optional. Default: `0` (contact all peers).**

Maximum number of peers contacted per gossip round.  When set to a positive integer, the
gossip loop selects a rotating window of that many peers each round (indexed by
`CRDT_GENERATION % peer_count`), so every peer is reached within ceil(N / fan_out) rounds.

In small clusters (2–4 nodes), leave this at 0 to contact all peers every round.  In
larger clusters (5+ nodes), set this to 3–5 to reduce O(N^2) gossip overhead while
maintaining convergence in O(log_k(N)) rounds via transitive propagation.

```toml
fan_out = 3   # recommended for clusters of 5+ nodes
```

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

## Removing a Node from a Running Cluster

There is no explicit "decommission" command.  To safely remove a node:

1. **Stop the node** you want to remove.  This is safe because no quorum is required;
   remaining nodes continue to operate independently.
2. **Remove the stopped node's gossip URL** from every remaining node's `peers` list in
   `akamu.toml`, then restart or SIGHUP those nodes.  If you skip this step, the remaining
   nodes will log warnings each round (`gossip: request failed`) until the URL is removed,
   but replication between the remaining nodes is unaffected.
3. **Optionally clean up the CRDT.** The removed node's entry in `cluster_nodes` will
   remain in the CRDT as a live entry.  It is harmless (the node simply never responds to
   gossip) and can be ignored.  There is currently no admin endpoint to explicitly remove a
   cluster node entry from the CRDT.

**Important:** ensure that any ACME orders owned by the departing node have either
completed or that `ownership_ttl_secs` (default 150 s) has elapsed before relying on
another node to take over processing.  After the TTL expires, any remaining node will
automatically claim and process pending orders.

## Network Partition Behavior

Akamu uses CRDT (Conflict-free Replicated Data Type) merge semantics, which guarantee
convergence after a network partition heals without requiring consensus or coordination.

### During a partition

- Each partition continues to operate independently.  Nodes within each partition
  replicate among themselves normally.
- New ACME accounts, orders, authorizations, challenges, and certificates created on
  either side of the partition accumulate locally and in the in-partition peers.
- Nodes on the unreachable side of the partition are logged as `gossip: request failed`
  each round (at `warn` level) and skipped.  The gossip loop continues with reachable
  peers.
- Order ownership claims (`order_owners` LWW map) and MTC writer elections
  (`mtc_writer` LWW register) may diverge: both partitions could claim ownership of the
  same order or the MTC writer role.

### After partition healing

When network connectivity is restored, the gossip loop automatically exchanges full or
delta CRDTs with the previously unreachable peers.  Merge proceeds according to CRDT
rules:

| CRDT type | Merge rule | Potential conflict |
|---|---|---|
| `OrMap` (accounts, orders, certs, etc.) | Tombstone always wins; live-vs-live: higher timestamp wins | A deletion on one side and an update on the other: the deletion wins unconditionally |
| `LwwMap` (challenges, EAB keys, ownership) | Higher timestamp wins; equal timestamps: lexicographically greater `node_id` wins | Both partitions update the same challenge status: the later write wins |
| `LwwRegister` (MTC writer) | Higher timestamp wins; tie-break by `node_id` | Both partitions elect an MTC writer: the one with the later claim wins |

**What may diverge:**

- **Duplicate certificate issuance.** If the same order is finalized on both sides of a
  partition (because the ownership TTL expired and a second node claimed it), two
  certificates may be issued for the same order.  After merge, both certificates exist in
  the CRDT.  This is safe but potentially surprising; monitor for it via the admin API.
- **Challenge state.** If a challenge is validated on one side and marked invalid on the
  other, the later timestamp wins.
- **Order ownership.** The LWW map converges to the most recent claim.  The losing node
  will notice on its next gossip round and stop processing the order.

**No manual intervention is required** after a partition heals.  The CRDT merge is fully
automatic and deterministic.

## Rolling Upgrades

Akamu supports rolling upgrades of cluster nodes.  The CRDT wire format is
forward-compatible: CBOR-encoded fields use compact string keys, and unknown fields are
silently ignored by older nodes during deserialization.

### Procedure

1. **Verify compatibility.**  Read the release notes for the target version to confirm
   there are no breaking CRDT schema changes.  Breaking changes are called out explicitly
   in the changelog.
2. **Upgrade one node at a time.**  For each node:
   a. Stop the node.
   b. Replace the `akamu` binary (or update the package).
   c. Start the node.
   d. Wait for the `gossip: first-contact merge complete` or `gossip: merge complete` log
      line confirming the node has re-synced with the cluster.
   e. Verify the node is healthy (see [Monitoring](#monitoring) below).
   f. Proceed to the next node.
3. **Do not upgrade all nodes simultaneously.**  While the CRDT is resilient to brief
   unavailability, upgrading all nodes at once creates a window where no node is serving
   requests.
4. **Rollback.** If a node fails to start after upgrade, restore the previous binary and
   restart.  The CRDT will re-sync automatically.  If the new version introduced CRDT
   schema fields that the old version does not understand, those fields are silently
   dropped during merge on the rolled-back node; this is safe but means the new fields
   will not replicate to the rolled-back node until it is re-upgraded.

### Version skew tolerance

Nodes running different versions can coexist in the same cluster as long as the CRDT wire
format is compatible.  The gossip envelope's cryptographic layer (ML-KEM-768 + ECDSA P-256
+ CMS) is version-independent.  Aim to complete the rolling upgrade within one
`tombstone_ttl_secs` window (default 7 days) to avoid edge cases where a tombstone is
garbage-collected on an upgraded node but still live on an old node.

## Monitoring

### `GET /admin/gossip/status`

The primary health-check endpoint.  Requires at least `auditor` role.  Returns a JSON
object with the current gossip state:

```json
{
  "node_id": "abc123...",
  "crdt_generation": 42,
  "kem_enrolled": true,
  "gossip_signing_enrolled": true,
  "peers": ["https://node2.acme.internal:8443"],
  "counts": {
    "cluster_nodes": 3,
    "accounts": 142,
    "orders": 891,
    "authorizations": 1023,
    "challenges": 500,
    "certificates": 734,
    "eab_keys": 10,
    "operators": 2,
    "delegations": 0,
    "mtc_checkpoints": 0,
    "mtc_cosignatures": 0
  }
}
```

**Health indicators:**

- `kem_enrolled` and `gossip_signing_enrolled` should both be `true`.  If either is
  `false`, the node's keys have not been registered -- run `POST /admin/gossip/register`.
- `crdt_generation` should increase over time.  If it is static across multiple checks,
  the gossip loop may be stalled or no writes are occurring.
- `counts.cluster_nodes` should match the expected cluster size.
- Compare `counts` across nodes: significant divergence in entry counts (e.g. one node has
  100 fewer certificates) indicates a replication problem.

### Log messages to watch

The gossip subsystem emits structured log messages at various levels.  Configure your log
aggregation to alert on `warn` and `error` messages with the `gossip:` or `gossip/sync:`
prefix.

#### Healthy operation

| Log message | Level | Meaning |
|---|---|---|
| `gossip: loop started` | `info` | Gossip loop has started with configured peers and interval |
| `gossip: first-contact merge complete` | `info` | Initial state sync with a peer succeeded; the node is now in sync |
| `gossip: merge complete` | `debug` | A routine gossip round completed successfully |
| `gossip: unchanged, skipping` | `debug` | No local changes since the last sync with this peer; round skipped |
| `gossip: tombstone GC applied in-memory` | `info` | Hourly tombstone garbage collection ran |

#### Warning signs

| Log message | Level | Meaning | Action |
|---|---|---|---|
| `gossip: request failed` | `warn` | HTTP POST to a peer failed (network error, timeout, DNS) | Check network connectivity and peer status |
| `gossip: peer returned error` | `warn` | Peer responded with a non-2xx HTTP status | Check the peer's logs for the cause |
| `gossip: verify_and_open response failed` | `warn` | Response could not be cryptographically verified | Check for clock skew, key mismatch, or corrupted `node_keys` |
| `gossip: peer not in cluster_nodes` | `warn` | Peer URL is in `peers` config but has no registered keys | Run `POST /admin/gossip/register` on the peer |
| `gossip: peer missing KEM or signing key` | `warn` | Peer is registered but key data is empty | Re-register the peer via `POST /admin/gossip/register` |
| `gossip: rejecting future-dated envelope` | `warn` | Peer's clock is ahead by more than `clock_skew_tolerance_secs` | Synchronise NTP on both nodes |
| `gossip: rejecting stale envelope` | `warn` | Envelope is older than `gossip_envelope_max_age_secs` | Check for network delays or clock drift |
| `gossip: peer URL uses plaintext HTTP` | `warn` | Gossip traffic is unencrypted in transit (logged once per peer) | Use HTTPS for gossip URLs in production |
| `gossip: periodic CRDT cluster persist failed` | `warn` | Failed to write CRDT cluster state to disk | Check disk space and database connectivity |
| `gossip: periodic ACME persist failed` | `warn` | Failed to write ACME state to disk | Check disk space and database connectivity |

#### Receiver-side warnings

| Log message | Level | Meaning | Action |
|---|---|---|---|
| `gossip/sync: missing x-akamu-node-id header` | `warn` | Inbound request lacks the required node ID header | Verify sender configuration |
| `gossip/sync: verify_and_open failed` | `warn` | Inbound request failed cryptographic verification | Check key enrollment and clock sync |
| `gossip/sync: rejecting future-dated envelope` | `warn` | Sender's clock is ahead | Sync NTP |
| `gossip/sync: rejecting stale envelope` | `warn` | Envelope too old | Check network latency or sender clock |
| `gossip/sync: duplicate nonce -- rejecting replay` | `warn` | Replay attempt or duplicate delivery | Usually benign; investigate if persistent |
| `gossip/sync: nonce cache full` | `warn` | Nonce dedup cache hit 10,000 entries | Indicates excessive gossip traffic; returns 429 |
| `gossip/sync: CBOR decode CRDT failed` | `warn` | Peer sent malformed CRDT data | Check for version incompatibility |

### Monitoring checklist

For production clusters, set up monitoring for:

1. **Alerting on `warn`/`error` gossip log messages** -- any persistent warning indicates a
   replication problem.
2. **Periodic `GET /admin/gossip/status` polling** -- compare `crdt_generation` and
   `counts` across nodes.  If `crdt_generation` on one node stops increasing while others
   advance, that node is not receiving gossip updates.
3. **Entry count divergence** -- if the `certificates` count on one node is more than one
   gossip interval behind the others, investigate network connectivity.
4. **Clock skew** -- monitor NTP offset on all nodes; alert if skew exceeds 10 seconds
   (well before the 30-second default tolerance).

## Troubleshooting

### `gossip: no peers configured — loop disabled`

The `[gossip]` section is absent from `akamu.toml`, or the `peers` list is empty.  The
node operates in single-node mode with no replication.  If clustering is intended, add at
least one peer URL to the `peers` list and restart.

### `gossip: peer not in cluster_nodes`

The peer URL is listed in the `peers` configuration but the peer's keys have not been
registered in the CRDT.  This is expected for the first 1–3 rounds after a new peer is
added.  If it persists:

- Verify the peer node started successfully and its gossip loop is running (look for
  `gossip: loop started` in the peer's logs).
- Verify the peer's gossip URL is reachable from this node (`curl -v <peer-url>/gossip/sync`
  should return a response, even if it is an error).
- Run `POST /admin/gossip/register` on this node to register the peer's keys, or on the
  peer to register this node's keys.  Both nodes must have each other's keys registered
  before gossip can proceed.

### `gossip: peer missing KEM or signing key`

The peer is registered in `cluster_nodes` but its key fields are empty.  This can happen
if `POST /admin/gossip/register` was called with empty key values or if the CRDT entry was
corrupted.  Re-register the peer with correct key values.

### `gossip: verify_and_open response failed`

The response from a peer could not be cryptographically verified.  Possible causes:

- **Clock skew** between nodes.  The default tolerance is 30 seconds
  (`clock_skew_tolerance_secs`); if one node's clock is ahead by more than this, its
  envelopes will be rejected as future-dated.  Ensure NTP is running on all nodes.
- **Key mismatch.**  The signing key registered for the peer does not match the key the
  peer is actually using.  This can happen if a peer's database was recreated (generating
  new keys) without re-registering the new keys on other nodes.  Re-run
  `POST /admin/gossip/register` with the peer's current keys.
- **Corrupted `node_keys` table.**  If the peer's key pair in its local database is
  corrupted, delete the `node_keys` table entries and restart the peer to regenerate keys.
  Then re-register the new keys on all other nodes.

### `gossip/sync: rejecting future-dated envelope`

The sender's `issued_at` timestamp is more than `clock_skew_tolerance_secs` in the future.
This almost always indicates an NTP synchronisation problem.  Check `timedatectl status`
or equivalent on both the sender and receiver.

### `gossip/sync: rejecting stale envelope`

The envelope's `issued_at` timestamp is older than `gossip_envelope_max_age_secs` (default
300 seconds).  Possible causes:

- **Network latency.**  If the gossip HTTP request took more than 5 minutes to deliver
  (extremely unusual), the envelope may have expired in transit.
- **Clock drift.**  The receiver's clock may be ahead of the sender's.
- **Stuck sender.**  The sender's gossip loop may be blocked (e.g. by a deadlocked write
  lock).  Check the sender's logs and process state.

### `gossip/sync: duplicate nonce — rejecting replay`

The same gossip envelope was received twice.  This is usually harmless (e.g. due to a
retry at the HTTP layer) but if it occurs persistently, investigate whether a network
middlebox is duplicating traffic or an attacker is replaying captured envelopes.

### `gossip/sync: nonce cache full`

The nonce deduplication cache has reached its maximum of 10,000 entries.  This indicates
that the node is receiving an unusually high volume of gossip requests.  The node returns
HTTP 429 until some nonce cache entries expire (after `gossip_envelope_max_age_secs`).
Possible causes:

- Too many nodes gossipping at a high frequency -- increase `interval_secs` or set
  `fan_out` to limit concurrent inbound gossip.
- A misconfigured load balancer sending duplicate gossip traffic.

### `gossip: request failed`

The HTTP POST to a peer failed.  Common causes:

- The peer is down or restarting.  This is normal during rolling upgrades.
- DNS resolution failed for the peer URL.
- A firewall is blocking the gossip port.
- The peer's TLS certificate is invalid or expired (when using HTTPS gossip URLs).

The gossip loop will retry on the next round.  Persistent failures for a single peer do
not affect replication with other peers.

### `gossip: peer returned error`

The peer responded with a non-2xx HTTP status.  Check the peer's logs for the
corresponding `gossip/sync:` warning to determine the cause.  Common statuses:

- **401 Unauthorized** -- the sender's node ID is not recognized by the peer.  Register
  the sender's keys on the peer.
- **400 Bad Request** -- the envelope failed validation (timestamp, nonce, or CBOR decode).
- **429 Too Many Requests** -- the peer's nonce cache is full.

### `X-Akamu-Node-Id` header rejected by peer

The responding peer's handler rejected the sender's node ID because the sender is not yet
in the peer's `cluster_nodes` CRDT.  This resolves automatically after the first successful
full-state exchange.  If it does not resolve, verify that gossip traffic is not blocked by a
firewall between the nodes.

### `gossip: periodic CRDT cluster persist failed` / `gossip: periodic ACME persist failed`

The CRDT state could not be persisted to the database.  The in-memory CRDT is unaffected
and replication continues normally, but if the node crashes before a successful persist,
it will lose state received since the last persist.

Check:
- Database disk space.
- Database connectivity (especially for PostgreSQL/MariaDB backends).
- Database lock contention (for SQLite, ensure `max_connections = 1`).

### Data appears on some nodes but not others

If data is present on some nodes but missing on others and gossip is running without
errors:

1. Check `GET /admin/gossip/status` on each node and compare `crdt_generation` values.
2. If one node's generation is significantly behind, check its logs for gossip warnings.
3. Ensure all nodes are listed in each other's `peers` configuration (or use dynamic peer
   discovery via `cluster_nodes`).
4. If a node was offline for longer than `tombstone_ttl_secs`, deleted entries may
   reappear on that node after it rejoins.  This resolves on the next gossip round as the
   tombstones are re-propagated.

## Protocol Internals

For a detailed description of the gossip protocol, CRDT data model, wire format,
cryptographic layer, and concurrency design, see the developer documentation:
[Gossip Replication Protocol](../developer/gossip-replication.md).
