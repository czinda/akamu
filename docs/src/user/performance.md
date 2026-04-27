# Performance

This chapter covers issuance throughput and latency characteristics of Akāmu
under load, with guidance on key type selection and capacity planning.

All numbers were collected on a single host using the `acme-bench` tool shipped
in the repository:

```
cargo bench --bench acme_bench -- [OPTIONS]
```

The benchmark runs full ACME flows (account → new-order → challenge validate →
finalize → certificate download) against a real in-process server over the
loopback interface using an in-memory SQLite database.  Reported latency is
end-to-end wall time from the start of `new-order` through certificate download;
account creation is excluded because it is amortised across all orders from a
given client.

> **Note — single-connection database pool.**  Both in-memory (`:memory:`) and
> file-backed databases use a single-connection pool.  In-memory databases require
> this because every SQLite in-memory connection opens its own private, empty
> database.  File-backed databases use it to avoid `SQLITE_BUSY_SNAPSHOT` (error 517),
> a WAL-mode contention error that bypasses the busy handler and cannot be retried.
> Approximately 24 SQL round-trips are needed per issuance (reduced from ~55 by moving
> anti-replay nonces to an in-memory store and using JOIN queries to collapse read pairs
> into single round-trips); throughput peaks at ≈ 1350–1480 iss/s around 10 concurrent
> clients and remains stable at 25–50 clients (≈ 1170–1380 iss/s), determined by how
> fast the single database connection can process queries rather than by crypto, network,
> or storage speed.  See the [Database scalability](#database-scalability) section for
> guidance on exceeding this ceiling.

---

## Concurrency scaling

With EC P-256 certificates and an EC P-256 CA, throughput scales up to ~10
concurrent clients and then plateaus as the single-connection pool becomes
the bottleneck:

| Concurrent clients | Throughput (iss/s) | Mean latency (ms) | p95 (ms) |
|-------------------:|-------------------:|------------------:|---------:|
|  1                 |   219              |  4.6              |  5.5     |
|  5                 |  1111              |  4.5              |  5.3     |
| 10                 |  1476              |  6.7              |  7.7     |
| 25                 |  1176              | 17.5              | 18.2     |
| 50                 |  1170              | 35.7              | 42.3     |

Throughput peaks around 10 concurrent clients at ~1480 iss/s and remains
stable at 25–50 clients (≈ 1170–1180 iss/s); latency grows roughly linearly with
client count, consistent with a single serialised resource.  The practical
bottleneck is the in-memory SQLite single connection; crypto and network are not
limiting factors at these rates.

---

## Key type comparison

The table below compares issuance performance for different CSR key types at
25 concurrent clients with an EC P-256 CA.

| CSR key type | Throughput (iss/s) | Mean latency (ms) | p95 (ms) | Finalize phase (ms) |
|:-------------|-------------------:|------------------:|---------:|--------------------:|
| ec:P-256     |  1150              | 17.9              | 23.5     |   4.0               |
| ed25519      |  1259              | 16.0              | 18.4     |   3.9               |
| ec:P-384     |  1177              | 16.9              | 20.4     |   4.5               |
| ml-dsa-44    |  1086              | 18.6              | 23.4     |   4.8               |
| ml-dsa-65    |  1072              | 18.9              | 24.0     |   5.6               |
| ml-dsa-87    |   840              | 23.9              | 35.5     |   6.8               |
| rsa:2048     |   151              | 122.5             | 245.3    |  97.7               |
| rsa:4096     |    11              | 1323              | 2249     | 1191                |

All classical and post-quantum key types cluster around 840–1260 iss/s because
throughput is bounded by the single-connection database pool, not by crypto.
Finalize-phase latency (CSR verification + certificate issuance) still reflects
relative signing cost: EC and Ed25519 are fastest, ML-DSA adds ~1–3 ms, and RSA
adds tens to hundreds of milliseconds.

RSA is the outlier: RSA 2048 adds ~98 ms to finalize, and RSA 4096 adds ~1191 ms.

### RSA 4096 saturation

| Clients | Throughput (iss/s) | Finalize mean (ms) | p99 (ms) |
|--------:|-------------------:|-------------------:|---------:|
|  1      |    3               |   375              |  1027    |
| 10      |   12               |   785              |  3214    |
| 25      |   14               |  1103              |  4065    |
| 50      |   15               |  1496              |  5483    |

Throughput is limited by RSA 4096 key generation time.  At 50 clients the
additional queuing raises both finalize latency and p99 dramatically — from 1027 ms
at 1 client to 5483 ms at 50 clients.  Avoid RSA 4096 in any configuration where
more than a handful of concurrent ACME clients are expected.

---

## Post-quantum cryptography

Akāmu supports ML-DSA (FIPS 204 / RFC 9881) for both CA keys and certificate
keys.  Three security levels are available.  The table uses a full post-quantum
chain (ML-DSA CA + ML-DSA leaf, with `--verify-cert`) at 25 concurrent clients:

| Parameter set | NIST category | Throughput (iss/s) | Alloc pressure (MiB/iss) |
|:--------------|:-------------:|-------------------:|-------------------------:|
| ML-DSA-44     | 2             |  1160              | 0.60                     |
| ML-DSA-65     | 3             |  1031              | 0.69                     |
| ML-DSA-87     | 5             |   957              | 0.84                     |
| EC P-256      | —             |  1233              | 0.36                     |

ML-DSA allocation pressure is 65–135% higher than EC P-256 per issuance,
reflecting the larger key and signature structures.  Throughput difference between
ML-DSA and EC P-256 varies by parameter set; all are constrained by the
database single-connection bottleneck at 25 clients rather than by crypto cost.
ML-DSA-65 and ML-DSA-87 trail EC P-256 by ~15–22% due to their larger certificate
structures consuming more of the single connection's capacity during signing and
serialisation.

ML-DSA requires OpenSSL 3.5 or later.  Akāmu will report a startup error if the
requested key type is unavailable on the installed OpenSSL version.

### CA key type impact

| CA key    | Throughput (iss/s) | Mean latency (ms) | Finalize (ms) |
|:----------|-------------------:|------------------:|--------------:|
| ec:P-256  |  1046              | 18.8              |  4.0          |
| ec:P-384  |  1120              | 18.0              |  4.8          |
| rsa:2048  |  1285              | 15.6              |  3.9          |
| rsa:3072  |   970              | 20.9              |  7.8          |
| rsa:4096  |   851              | 23.9              | 11.2          |

EC and RSA 2048 CA keys deliver the highest throughput at 25 clients.  Larger RSA
CA keys incur increasing finalize latency — RSA 3072 adds ~8 ms and RSA 4096 adds
~11 ms — reducing aggregate throughput by ~7–19% vs EC P-256.  Avoid RSA 4096 as
a CA key for performance-sensitive deployments.

---

## Challenge type comparison

| Challenge type    | Throughput (iss/s) | Challenge phase (ms) | Alloc pressure (MiB/iss) |
|:------------------|-------------------:|---------------------:|-------------------------:|
| http-01           |  1219              |  6.1                 | 0.37                     |
| dns-persist-01    |  1243              |  6.7                 | 0.40                     |

`http-01` and `dns-persist-01` deliver equivalent throughput on loopback
(difference is within run-to-run noise).  Both challenge phases reflect the
adaptive poll backoff (starts at 1 ms, caps at `--poll-ms`) rather than network
latency; the 6–7 ms figure is dominated by polling overhead and background
validation round-trips.

---

## Key type recommendations

| Scenario | Recommended key type |
|:---------|:---------------------|
| General purpose, broad client compatibility | `ec:P-256` |
| Smallest footprint, fastest validation | `ed25519` |
| Higher security margin, still classical | `ec:P-384` |
| Post-quantum resistant, FIPS 204 category 2 | `ml-dsa-44` |
| Post-quantum resistant, FIPS 204 category 3 | `ml-dsa-65` |
| Post-quantum resistant, FIPS 204 category 5 | `ml-dsa-87` |
| Interoperability with RSA-only clients | `rsa:2048` (avoid RSA 4096 under load) |

---

## Database scalability

Both in-memory (`:memory:`) and file-backed databases use a single-connection
pool, so the throughput ceiling of ≈ 1350–1480 iss/s applies to both.  The ceiling
is set by how fast the SQLite worker thread can process one query at a time —
each query requires a channel round-trip to the background thread, and ~24 such
round-trips are needed per issuance (reduced from ~55 by moving anti-replay nonces
to an in-memory store and using JOIN queries to collapse read pairs).

### Backend comparison (tmpfs vs in-memory)

The table below shows that file-backed SQLite on a RAM-backed filesystem (`tmpfs`
/ `/dev/shm`) produces equivalent throughput to an in-memory database.  WAL
journal mode adds a small amount of write bookkeeping overhead; the difference
is within run-to-run noise.

| Concurrent clients | In-memory (iss/s) | tmpfs WAL (iss/s) |
|-------------------:|------------------:|------------------:|
|  1                 |   231             |   219             |
|  5                 |   967             |  1069             |
| 10                 |  1430             |  1362             |
| 25                 |  1377             |  1278             |
| 50                 |  1243             |  1164             |

Both backends peak around 1350–1430 iss/s at 10 concurrent clients and remain
above 1150 iss/s at 50 clients.  The bottleneck is the database connection
round-trip per query, not storage speed; switching from in-memory to a
tmpfs-backed file provides durability without a significant throughput penalty.

For sustained high-throughput targets consider:

- **In-memory database** for lab, CI, or ephemeral CA use cases.  Fastest
  startup; data is lost on restart.
- **File-backed WAL database** on a fast SSD or RAM-backed filesystem.
  Throughput matches in-memory while providing crash durability.
- **Sharding** — multiple Akāmu instances behind a load balancer, each with its
  own database — for production-scale deployments requiring higher aggregate
  issuance rates above the ≈ 1350–1480 iss/s per-instance ceiling.

### Connection pool size and `BEGIN IMMEDIATE`

`SQLITE_BUSY_SNAPSHOT` (error 517) occurs in WAL mode when a deferred
transaction (`BEGIN`) captures a read snapshot that becomes stale after another
connection commits — even when the two transactions write to completely different
rows.  Unlike `SQLITE_BUSY` (error 5), error 517 bypasses the busy handler
entirely, so `busy_timeout` has no effect on it.

Akāmu resolves this by using `BEGIN IMMEDIATE` for every write transaction.
`BEGIN IMMEDIATE` acquires the write lock at transaction
start, so the snapshot is always current.  Any resulting `SQLITE_BUSY`
contention is handled transparently by the `busy_timeout = 5 s` already
configured on the pool.

The table below shows that after this fix, pool > 1 produces **zero errors**
at every concurrency level.  Write throughput is unchanged because `BEGIN
IMMEDIATE` still serialises writers — only one connection can hold the write
lock at a time — but errors are eliminated.

**Throughput (iss/s) and error count (out of 200 requests) on tmpfs WAL with `BEGIN IMMEDIATE`:**

| Concurrent clients | Pool = 1          | Pool = 2          | Pool = 4          | Pool = 8          |
|-------------------:|------------------:|------------------:|------------------:|------------------:|
|  1                 |  236 / 0 err      |  207 / 0 err      |  202 / 0 err      |  207 / 0 err      |
|  5                 |  941 / 0 err      |  868 / 0 err      |  704 / 0 err      |  611 / 0 err      |
| 10                 | 1331 / 0 err      | 1100 / 0 err      | 1188 / 0 err      |  868 / 0 err      |
| 25                 | 1221 / 0 err      | 1205 / 0 err      |  925 / 0 err      |  956 / 0 err      |
| 50                 |  982 / 0 err      | 1013 / 0 err      |  750 / 0 err      |  956 / 0 err      |

All pool sizes produce **zero errors** — `BEGIN IMMEDIATE` eliminates
`SQLITE_BUSY_SNAPSHOT` regardless of how many connections are in the pool.
Pool = 1 consistently delivers the highest throughput because all requests
share a single serialised connection channel with no lock-acquisition contention.
Pool = 2 and above pay increasingly for BEGIN IMMEDIATE wait time as multiple
connections compete for the WAL write lock; the gap widens at medium concurrency
(5–10 clients) where lock contention is highest relative to available parallelism.

For the single-connection production default (`open`) this has no observable
effect: with one connection there is never a concurrent writer, so `BEGIN
IMMEDIATE` and `BEGIN DEFERRED` behave identically.

The `--pool-connections` benchmark option can be used to measure pool behaviour:

```bash
# Pool comparison on tmpfs with BEGIN IMMEDIATE (zero errors expected)
for p in 1 2 4 8; do
  DB=$(mktemp /dev/shm/bench_pool_XXXXXX.db)
  cargo bench --bench acme_bench -- \
    --db "$DB" --pool-connections "$p" \
    --clients 25 --requests 200 --warmup 20 --poll-ms 5
  rm -f "$DB" "${DB}-wal" "${DB}-shm"
done
```

---

## Running the benchmark

The `acme-bench` binary is built as a Cargo bench target:

```bash
cargo bench --bench acme_bench -- --help
```

Common invocations:

```bash
# Baseline: 25 concurrent clients, 200 issuances, EC P-256, 5 ms poll cap
cargo bench --bench acme_bench -- --clients 25 --requests 200 --warmup 20 --poll-ms 5

# Compare RSA 2048 vs EC P-256
cargo bench --bench acme_bench -- --key-type rsa:2048 --clients 25 --requests 100
cargo bench --bench acme_bench -- --key-type ec:P-256  --clients 25 --requests 100

# Full post-quantum chain (ML-DSA-65 CA + ML-DSA-65 leaf)
cargo bench --bench acme_bench -- \
  --ca-key-type ml-dsa-65 --key-type ml-dsa-65 \
  --clients 25 --requests 100 --verify-cert

# Scalability sweep
for n in 1 5 10 25 50; do
  cargo bench --bench acme_bench -- --clients $n --requests 300 --warmup 20 --poll-ms 5
done

# dns-persist-01 challenge type
cargo bench --bench acme_bench -- --challenge dns-persist-01 --clients 25 --requests 200

# JSON output for scripting
cargo bench --bench acme_bench -- --output json --clients 25 --requests 200 --poll-ms 5 | jq .summary

```

### Available options

| Option | Default | Description |
|:-------|:--------|:------------|
| `--clients N` | 10 | Concurrent worker tasks |
| `--requests N` | 100 | Issuances to measure (warmup not counted) |
| `--warmup N` | 10 | Warmup issuances discarded before measurement |
| `--poll-ms N` | 50 | Poll interval cap in milliseconds; adaptive backoff starts at 1 ms |
| `--challenge TYPE` | `http-01` | `http-01` or `dns-persist-01` |
| `--key-type TYPE` | `ec:P-256` | CSR key type (see table above) |
| `--ca-key-type TYPE` | `ec:P-256` | CA key type (same syntax) |
| `--db PATH` | `:memory:` | SQLite path — `:memory:` or a file path |
| `--pool-connections N` | `1` | SQLite pool size; ignored (clamped to 1) when `--db :memory:`; see [Connection pool size and `BEGIN IMMEDIATE`](#connection-pool-size-and-begin-immediate) |
| `--wildcard` | off | Issue `*.bench-N.acme-bench.test` (dns-persist-01 only) |
| `--output FORMAT` | `text` | `text` or `json` |
| `--verify-cert` | off | Parse and verify the SAN of every issued certificate |

The poll loop uses adaptive exponential backoff: it starts at 1 ms, doubles each
miss, and caps at `--poll-ms`.  This mirrors how production ACME clients behave
and reveals the true validation latency without a fixed artificial floor.

---

## Memory consumption

The benchmark instruments heap allocation using a custom
[`GlobalAlloc`](https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html)
wrapper that records four `AtomicU64` counters.  This reports in-process heap
usage without any external tooling or `/proc` parsing.

Three snapshots are taken:

| Milestone | When |
|:----------|:-----|
| **process start** | Before the server is initialised |
| **server ready** | After the server has bound its port and is accepting connections |
| **after bench** | After all issuances (warmup + measured) have completed |

The peak counter is reset at `server ready` so the high-water mark reflects
only the issuance window, not server startup allocations.

### Text output

```
  Heap (allocator counters):
    process start:        0.1 MiB  live
    server ready:         0.2 MiB  live   (server overhead: +0.5 MiB)
    after  220 iss.:      0.6 MiB  live   (issuance growth: +0.4 MiB, 1.9 KiB/iss.)
    peak live:            1.5 MiB         (high-water mark during issuances)
    alloc pressure:      83.5 MiB  total  (0.379 MiB/iss. requested, incl. freed)
```

**live** — bytes currently held on the heap (footprint).
**alloc pressure** — cumulative bytes requested from the system allocator since
`server ready`, including memory that was allocated and subsequently freed.  A
high pressure-to-footprint ratio indicates short-lived allocations (normal for
per-request work like signature buffers and JSON serialisation).

### JSON output

The `"memory"` key is present in JSON output when `--output json` is used:

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
    "per_issuance_alloc_bytes":   397833,
    "total_alloc_count":         700000
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

### Typical figures

At 25 concurrent clients with 300 measured issuances (EC P-256, `:memory:` DB,
5 ms poll cap):

- Server overhead: ~0.3 MiB live (router tables, DB connection pool, CA state, HTTP client)
- Per-issuance heap growth: ~1–2 KiB (request-scoped state retained by tokio workers)
- Peak during issuances: ~2.5 MiB (25 in-flight requests simultaneously)
- Allocation pressure: ~382 KiB per issuance (JWS buffers, JSON serialisation, cert DER/PEM)

For ML-DSA key types allocation pressure rises to ~507–651 KiB per issuance for
leaf keys (with EC P-256 CA), and to ~610–855 KiB per issuance for a full
post-quantum chain (matching ML-DSA CA + ML-DSA leaf), due to larger key and
certificate structures.

These figures confirm that Akāmu has a stable heap footprint at steady state.
Per-issuance live growth is small and bounded by the number of concurrent workers,
not the total number of issuances.
