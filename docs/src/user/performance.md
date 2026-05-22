# Performance

This chapter covers issuance throughput and latency characteristics of Akāmu
under load, with guidance on key type selection, cluster sizing, and capacity
planning.

All numbers were collected on a single host — AMD Ryzen 9 3900X (24 cores,
63 GB RAM, Fedora Linux 6.19, OpenSSL 3.5.5) — using the `acme-bench` tool in
**process mode** (`--spawn process`):

```
cargo build --release
cargo bench --bench acme_bench -- --spawn process [OPTIONS]
```

Process mode starts each node as a separate `akamu` OS process with its own
Tokio runtime, memory allocator, and SQLite in-memory database.  This matches
how a real cluster deployment behaves: nodes share only the network interface
and no process state.  All measurements use SQLite `:memory:` unless otherwise
noted.

The benchmark runs full ACME workflows (new-order → authz → challenge validate
→ finalize → certificate download) against N nodes, distributing requests
round-robin across nodes.  Latency is end-to-end wall time from `new-order`
through certificate download; account creation is amortised and excluded.
Default configuration uses ec:P-256 client keys, http-01 challenge, direct
topology, and 100 concurrent clients.

---

## Scale-out

With ec:P-256 certificates, http-01 validation, and 100 concurrent clients,
issuance throughput scales near-linearly from 1 to 5 nodes and remains strong
through 10 nodes.

| Nodes | Throughput (iss/s) | Mean (ms) | p99 (ms) | new_order | authz | challenge | finalize | download |
|------:|-------------------:|----------:|---------:|----------:|------:|----------:|---------:|---------:|
|  1    |    467             |   182     |   194    |  47.5     | 21.8  |  43.6     |  69.2    |  0.2     |
|  2    |    724             |   112     |   128    |  31.3     | 10.0  |  31.8     |  38.3    |  0.2     |
|  3    |    957             |    79     |   102    |  22.5     |  6.7  |  22.0     |  27.3    |  0.3     |
|  5    |  1,270             |    59     |    79    |  16.3     |  4.9  |  16.6     |  20.3    |  0.4     |
|  7    |  1,653             |    43     |    58    |  12.5     |  3.6  |  12.6     |  14.3    |  0.3     |
| 10    |  2,016             |    35     |    51    |   9.5     |  3.0  |  10.1     |  11.5    |  0.4     |

Phase columns show mean milliseconds per ACME step.

Five nodes deliver **3.3× throughput** at 59 ms mean latency versus a single
node — a good operating point.  Ten nodes reach 4.3× with diminishing
per-node efficiency (202 iss/s/node vs 467 at n=1) as scheduler contention on
the shared host grows.

The finalize phase dominates at all node counts and benefits most from
parallelism: 69 ms at n=1 compresses to 12 ms at n=10 as certificate signing
is distributed across independent processes.  All five phases compress
proportionally; the download phase remains sub-millisecond throughout.

---

## Concurrency

At a fixed number of nodes, throughput peaks between 25 and 50 concurrent
clients.  Higher concurrency raises queue depth, increasing mean latency
without proportional throughput gains.

| Clients | n=1 (iss/s) | n=1 mean (ms) | n=1 p99 (ms) | n=5 (iss/s) | n=5 mean (ms) | n=5 p99 (ms) |
|--------:|------------:|--------------:|-------------:|------------:|--------------:|-------------:|
|  10     |   540        |    18.4       |   20.9       |  1,400       |     6.9       |    8.8       |
|  25     |   552        |    45.0       |   47.7       |  1,609       |    14.4       |   28.2       |
|  50     |   531        |    91.4       |   96.1       |  1,427       |    30.0       |   40.0       |
| 100     |   465        |   183.5       |  192.4       |  1,382       |    54.5       |   69.4       |

At c=10 the server is under-utilised: **6.9 ms mean latency** at n=5 reflects
near-zero queueing.  Throughput peaks at c=25 for both node counts; beyond
that, queue depth grows faster than concurrency gains.

For high-concurrency deployments, adding nodes is more effective than raising
concurrency per node: n=5 at c=25 (1,609 iss/s) outperforms n=1 at any
concurrency level.

---

## Client key type

The client key type is the largest single determinant of per-issuance latency.
EC and Ed25519 keys complete in sub-200 ms at n=1; RSA key generation is
CPU-bound in the client worker and barely benefits from adding server nodes.

| CSR key type | n=1 mean (ms) | n=5 mean (ms) | Speedup | n=1 p99 (ms) | n=5 p99 (ms) | n=1 tput (iss/s) |
|:-------------|:-------------:|:-------------:|:-------:|:------------:|:------------:|:----------------:|
| ec:P-256     |   179         |    54         |  3.3×   |   194        |    69        |   474            |
| ed25519      |   187         |    57         |  3.3×   |   201        |    85        |   457            |
| ec:P-384     |   237         |    66         |  3.6×   |   253        |    89        |   363            |
| rsa2048      |   347         |   282         |  1.2×   |   526        |   470        |   237            |
| rsa4096      | 2,797         | 2,307         |  1.2×   | 3,889        | 3,249        |    24            |

EC P-256 and Ed25519 are equivalent for practical purposes (~180–187 ms at
n=1, ~54–57 ms at n=5).  EC P-384 adds ~58 ms to the finalize phase.  Both
scale linearly with node count: 3.3–3.6× speedup at n=5.

RSA 2048 improves to 282 ms at n=5 (1.2× speedup from 347 ms at n=1) because
RSA key generation runs in the bench client worker, not the server, and cannot
be parallelised by adding server nodes.  RSA 4096 is effectively CPU-wall-limited
at all node counts: 2,797 ms at n=1 shrinks only to 2,307 ms at n=5.  The
challenge and finalize phases each exceed one second.

**RSA 4096 is strongly discouraged for ACME clients in multi-client
deployments.**

---

## CA key type

Unlike client-side key generation, CA signing is server-side and parallelises
well across nodes.  An RSA 4096 CA at n=5 is 4.3× faster than at n=1,
matching the speedup ratio of ec:P-256.

| CA key     | n=1 mean (ms) | n=5 mean (ms) | Speedup | n=1 finalize (ms) | n=5 finalize (ms) |
|:-----------|:-------------:|:-------------:|:-------:|:-----------------:|:-----------------:|
| ec:P-256   |   182         |    56         |  3.2×   |    68.7           |    18.1           |
| rsa2048    |   229         |    62         |  3.7×   |    91.6           |    21.6           |
| ec:P-384   |   268         |    72         |  3.7×   |   110.0           |    26.4           |
| rsa4096 ¹  |   442         |   104         |  4.3×   |   225.5           |    52.9           |

¹ rsa4096 runs used 100 issuances due to practical time constraints.

EC P-256 is the fastest CA key type and the recommended default.  RSA 4096 as
CA adds 157 ms to finalize at n=1 and reduces single-node throughput from 469
to 154 iss/s (3× penalty).  At n=5 the gap narrows to 104 ms total mean vs
56 ms — multi-node deployments can absorb larger RSA CA keys without severe
degradation because each node signs independently.

---

## Post-quantum chain

Akāmu supports ML-DSA (FIPS 204 / RFC 9881) CA keys at three NIST security
levels.  The table measures a post-quantum CA with ec:P-256 client keys and
compares to an ec:P-256 CA baseline at 100 concurrent clients.

| CA chain    | NIST cat. | n=1 mean (ms) | n=5 mean (ms) | Speedup | vs P-256 n=1 | Alloc/issuance |
|:------------|:---------:|:-------------:|:-------------:|:-------:|:------------:|:--------------:|
| ec:P-256    |     —     |   182         |    56         |  3.2×   |     —        |   147 KB       |
| ML-DSA-44   |     2     |   268         |    70         |  3.8×   |   +47%       |   215 KB       |
| ML-DSA-65   |     3     |   337         |    82         |  4.1×   |   +85%       |   266 KB       |
| ML-DSA-87   |     5     |   394         |    91         |  4.3×   |  +116%       |   316 KB       |

All ML-DSA variants scale well: 3.8–4.3× speedup at n=5, comparable to
classical keys.  At n=5, ML-DSA-44 is only 25% slower than ec:P-256 (70 ms vs
56 ms), versus 47% slower at n=1.  Allocation pressure rises with key size:
ML-DSA-87 uses 316 KB per issuance vs 147 KB for ec:P-256, reflecting the
larger certificate and signature structures.

ML-DSA requires OpenSSL 3.5 or later.  Akāmu will report a startup error if
the requested key type is unavailable on the installed OpenSSL version.

---

## Challenge type

| Challenge      | Nodes | Throughput (iss/s) | Mean (ms) | p99 (ms) | Challenge phase (ms) |
|:---------------|------:|-------------------:|----------:|---------:|---------------------:|
| http-01        |   1   |    471             |   180     |   199    |  47.1                |
| dns-persist-01 |   1   |    419             |   203     |   224    |  66.9                |
| http-01        |   5   |  1,405             |    53     |    71    |  15.1                |
| dns-persist-01 |   5   |  1,240             |    61     |    83    |  22.5                |

`dns-persist-01` adds approximately 20 ms to the challenge phase at n=1 and
7 ms at n=5.  The absolute gap shrinks with scale as parallel nodes service
challenge poll loops concurrently.  Both challenge types deliver zero errors
across all runs.

Deployments using dns-persist-01 in process mode must configure
`dns_resolver_addr` in each node's `[server]` section to point at a DNS
resolver that can see the validation TXT records.

---

## Topology

| Topology | Nodes | Throughput (iss/s) | Mean (ms) | p99 (ms) | Download (ms) |
|:---------|------:|-------------------:|----------:|---------:|--------------:|
| direct   |   5   |  1,354             |    56     |    68    |    0.3        |
| proxy    |   5   |    579             |    95     |   452    |   81.7        |
| direct   |  10   |  2,046             |    35     |    52    |    0.4        |
| proxy    |  10   |    241             |   209     | 1,030    |  200.0        |

Direct topology routes clients to individual nodes round-robin.  Proxy
topology fronts the cluster with a single akamu node that nonce-routes each
request to the backend that issued the corresponding nonce.

**Proxy mode introduces severe tail latency.**  At n=10, p99 reaches 1,030 ms
vs 52 ms for direct — a 20× gap.  The proxy must serialise certificate
downloads through a single forwarding path, causing the download phase alone to
account for 200 ms.  Memory overhead reflects full response body buffering:
721 KB per issuance (proxy n=10) vs 187 KB (direct n=10).

For performance-sensitive deployments, direct topology is strongly preferred.
Use proxy topology only when a single entry point is required for network
routing, and limit the cluster to n≤5 to contain nonce serialisation overhead.

---

## Gossip overhead

Gossip synchronisation (CRDT state exchange across cluster nodes) imposes
negligible overhead:

| Gossip | Nodes | Throughput (iss/s) | Mean (ms) | p99 (ms) |
|:-------|------:|-------------------:|----------:|---------:|
| on     |   5   |  1,416             |    53.0   |   68.4   |
| off    |   5   |  1,420             |    51.3   |   67.5   |
| on     |  10   |  2,012             |    35.6   |   53.7   |
| off    |  10   |  2,056             |    34.6   |   51.9   |

The difference is within measurement noise at both node counts.  Gossip
fan-out at 1-second intervals generates sub-millisecond background traffic and
does not block the ACME request path.  Enable gossip in all multi-node
deployments.

---

## Key type recommendations

| Scenario | Recommended type |
|:---------|:-----------------|
| General purpose, broad client compatibility | `ec:P-256` |
| Smallest footprint, fastest validation | `ed25519` |
| Higher security margin, still classical | `ec:P-384` |
| Post-quantum resistant, FIPS 204 category 2 | `ml-dsa-44` |
| Post-quantum resistant, FIPS 204 category 3 | `ml-dsa-65` |
| Post-quantum resistant, FIPS 204 category 5 | `ml-dsa-87` |
| Interoperability with RSA-only clients | `rsa:2048` (avoid RSA 4096 under load) |

---

## Cluster sizing guidance

| Target throughput | Nodes | Expected mean latency | Notes |
|:-----------------:|:-----:|:---------------------:|:------|
| ≤500 iss/s        |  1    | ~180 ms               | SQLite `:memory:` adequate |
| ≤1,000 iss/s      | 2–3   | 79–112 ms             | |
| ≤1,500 iss/s      |  5    |  ~59 ms               | Good efficiency–latency balance |
| ≤2,000 iss/s      | 7–10  | 35–43 ms              | Diminishing per-node efficiency |

Figures assume ec:P-256 keys, http-01, direct topology, and 100 concurrent
clients.  RSA or ML-DSA keys lower per-node throughput proportionally.

For the database backend: SQLite `:memory:` suits nodes with no persistent
state requirement (accounts, orders, and certificates are lost on restart).
For persistent deployments, PostgreSQL is recommended; use a connection pool
of 20–25 (`[database] pool_connections = 25`) and accept that
`synchronous_commit = off` is appropriate for the new-order, authz, and
challenge transactions (finalize retains full durability).

---

## Memory

The benchmark instruments heap allocation using a custom `GlobalAlloc` wrapper.
Per-issuance allocation pressure — bytes requested from the system allocator
per certificate, including memory subsequently freed — varies by configuration:

| Configuration                               | Per-issuance alloc |
|:--------------------------------------------|:------------------:|
| ec:P-256 CA + ec:P-256 client, n=1          | 147 KB             |
| ec:P-256 CA + ec:P-256 client, n=5          | 176 KB             |
| ec:P-256 CA + ec:P-256 client, n=10         | 183 KB             |
| ec:P-256 CA + rsa4096 client, n=1           | 229 KB             |
| ML-DSA-44 CA + ec:P-256 client, n=5         | 265 KB             |
| ML-DSA-65 CA + ec:P-256 client, n=5         | 313 KB             |
| ML-DSA-87 CA + ec:P-256 client, n=5         | 364 KB             |
| proxy topology, n=10                        | 721 KB             |

Server overhead per process-mode node is approximately 0.15–1.4 MB RSS,
growing with node count as gossip peer state and nonce caches accumulate.
Per-issuance live heap growth is 1–2 KB per concurrent worker — the footprint
is bounded by the number of in-flight requests, not the total issuance count.

### JSON output

The `"memory"` key is present when `--output json` is used:

```json
{
  "memory": {
    "start_live_bytes":           102400,
    "server_ready_live_bytes":    204800,
    "after_bench_live_bytes":     614400,
    "peak_live_bytes":           1572864,
    "server_overhead_bytes":      512000,
    "issuance_growth_bytes":      409600,
    "per_issuance_growth_bytes":    1900,
    "issuance_alloc_bytes":     87523328,
    "per_issuance_alloc_bytes":   150120,
    "total_alloc_count":         319099
  }
}
```

| Field | Meaning |
|:------|:--------|
| `*_live_bytes` | Heap footprint at each milestone |
| `peak_live_bytes` | Highest live bytes seen during the issuance window |
| `server_overhead_bytes` | Live growth from start to server-ready |
| `issuance_growth_bytes` | Live growth from server-ready to end of bench |
| `per_issuance_growth_bytes` | Per-issuance share of issuance growth |
| `issuance_alloc_bytes` | Total bytes requested during the issuance window |
| `per_issuance_alloc_bytes` | Per-issuance allocation pressure |
| `total_alloc_count` | Total number of `alloc` calls in the whole process |

---

## Running the benchmark

Process mode requires the release binary to be built first:

```bash
cargo build --release
cargo bench --bench acme_bench -- --spawn process [OPTIONS]
```

Common invocations:

```bash
# Scale-out sweep
for n in 1 2 3 5 7 10; do
  cargo bench --bench acme_bench -- \
    --spawn process --nodes $n --clients 100 --requests 500 --warmup 50
done

# Key type comparison at n=5
for kt in ec:P-256 ec:P-384 ed25519 rsa:2048; do
  cargo bench --bench acme_bench -- \
    --spawn process --nodes 5 --key-type $kt --clients 100 --requests 500 --warmup 50
done

# CA key type comparison at n=5
cargo bench --bench acme_bench -- \
  --spawn process --nodes 5 --ca-key-type rsa:4096 --clients 100 --requests 100

# Post-quantum chain (ML-DSA-44 CA, ec:P-256 client)
cargo bench --bench acme_bench -- \
  --spawn process --nodes 5 --ca-key-type ml-dsa-44 --clients 100 --requests 500

# dns-persist-01 challenge
cargo bench --bench acme_bench -- \
  --spawn process --nodes 5 --challenge dns-persist-01 --clients 100 --requests 500

# Proxy topology
cargo bench --bench acme_bench -- \
  --spawn process --nodes 5 --topology proxy --clients 100 --requests 500

# Gossip on vs off
cargo bench --bench acme_bench -- \
  --spawn process --nodes 5 --clients 100 --requests 500
cargo bench --bench acme_bench -- \
  --spawn process --nodes 5 --no-gossip --clients 100 --requests 500

# Concurrency sweep at n=5
for c in 10 25 50 100; do
  cargo bench --bench acme_bench -- \
    --spawn process --nodes 5 --clients $c --requests 500 --warmup 50
done

# JSON output for scripting
cargo bench --bench acme_bench -- \
  --spawn process --nodes 5 --clients 100 --requests 500 --output json | jq .summary
```

### Available options

| Option | Default | Description |
|:-------|:--------|:------------|
| `--spawn MODE` | `inprocess` | `inprocess` or `process`; use `process` for representative measurements |
| `--nodes N` | 1 | Number of akamu nodes in the cluster |
| `--clients N` | 10 | Concurrent worker tasks |
| `--requests N` | 100 | Issuances to measure (warmup not counted) |
| `--warmup N` | 10 | Warmup issuances discarded before measurement |
| `--challenge TYPE` | `http-01` | `http-01` or `dns-persist-01` |
| `--key-type TYPE` | `ec:P-256` | CSR key type (see table above) |
| `--ca-key-type TYPE` | `ec:P-256` | CA key type (same syntax) |
| `--topology MODE` | `direct` | `direct` (round-robin) or `proxy` (single-node proxy) |
| `--no-gossip` | off | Disable gossip in multi-node runs |
| `--db PATH` | `:memory:` | SQLite URL; ignored in process mode (always `:memory:`) |
| `--pool-connections N` | `1` | Connection pool size (process mode: always 1) |
| `--wildcard` | off | Issue `*.bench-N.acme-bench.test` (dns-persist-01 only) |
| `--output FORMAT` | `text` | `text` or `json` |
| `--verify-cert` | off | Parse and verify the SAN of every issued certificate |
