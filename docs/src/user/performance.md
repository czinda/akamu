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
> into single round-trips); throughput peaks at ≈ 700–770 iss/s around 10 concurrent
> clients and remains stable at 25–50 clients (≈ 600–650 iss/s), determined by how
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
|  1                 |   108              |  9.3              | 12.7     |
|  5                 |   613              |  8.1              | 10.0     |
| 10                 |   735              | 13.5              | 16.4     |
| 25                 |   651              | 32.8              | 38.2     |
| 50                 |   641              | 66.2              | 73.9     |

Throughput peaks around 10 concurrent clients at ~735 iss/s and remains
stable at 25–50 clients (≈ 640–650 iss/s); latency grows roughly linearly with
client count, consistent with a single serialised resource.  The practical
bottleneck is the in-memory SQLite single connection; crypto and network are not
limiting factors at these rates.

---

## Key type comparison

The table below compares issuance performance for different CSR key types at
25 concurrent clients with an EC P-256 CA.

| CSR key type | Throughput (iss/s) | Mean latency (ms) | p95 (ms) | Finalize phase (ms) |
|:-------------|-------------------:|------------------:|---------:|--------------------:|
| ec:P-256     |   575              | 34.4              | 43.2     |   8.6               |
| ed25519      |   572              | 35.2              | 42.5     |   9.9               |
| ec:P-384     |   512              | 37.4              | 51.7     |  12.3               |
| ml-dsa-44    |   546              | 35.1              | 40.6     |  10.1               |
| ml-dsa-65    |   426              | 44.0              | 53.8     |  12.4               |
| ml-dsa-87    |   473              | 41.7              | 60.0     |  12.5               |
| rsa:2048     |   157              | 124.9             | 255.5    |  97.4               |
| rsa:4096     |    15              | 1048.8            | 1749.7   | 945.4               |

All classical and post-quantum key types cluster around 420–580 iss/s because
throughput is bounded by the single-connection database pool, not by crypto.
Finalize-phase latency (CSR verification + certificate issuance) still reflects
relative signing cost: EC and Ed25519 are fastest (~9–10 ms), ML-DSA adds ~1–3 ms
over EC, and RSA adds tens to hundreds of milliseconds.

RSA is the outlier: RSA 2048 adds ~97 ms to finalize, and RSA 4096 adds ~945 ms.

### RSA 4096 saturation

| Clients | Throughput (iss/s) | Finalize mean (ms) | p99 (ms) |
|--------:|-------------------:|-------------------:|---------:|
|  1      |    3               |   376.7            |  1244.8  |
| 10      |   12               |   672.4            |  1968.6  |
| 25      |   14               |  1070.8            |  3374.8  |
| 50      |   17               |  1359.6            |  3997.8  |

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
| ML-DSA-44     | 2             |   492              | 0.69                     |
| ML-DSA-65     | 3             |   449              | 0.83                     |
| ML-DSA-87     | 5             |   525              | 0.93                     |
| EC P-256      | —             |   595              | 0.46                     |

ML-DSA allocation pressure is 50–100% higher than EC P-256 per issuance,
reflecting the larger key and signature structures.  Throughput difference between
ML-DSA and EC P-256 varies by parameter set; all are constrained by the
database single-connection bottleneck at 25 clients rather than by crypto cost.
ML-DSA-44 through ML-DSA-87 trail EC P-256 by ~12–25% due to their larger certificate
structures consuming more of the single connection's capacity during signing and
serialisation.

ML-DSA requires OpenSSL 3.5 or later.  Akāmu will report a startup error if the
requested key type is unavailable on the installed OpenSSL version.

### CA key type impact

| CA key    | Throughput (iss/s) | Mean latency (ms) | Finalize (ms) |
|:----------|-------------------:|------------------:|--------------:|
| ec:P-256  |   579              | 32.5              |  8.5          |
| ec:P-384  |   487              | 37.8              | 10.8          |
| rsa:2048  |   519              | 37.1              | 12.2          |
| rsa:3072  |   451              | 43.0              | 16.6          |
| rsa:4096  |   366              | 52.2              | 19.7          |

EC P-256 delivers the highest throughput at 25 clients.  Larger RSA CA keys incur
increasing finalize latency — RSA 3072 adds ~8 ms and RSA 4096 adds ~11 ms over
EC P-256 — reducing aggregate throughput by ~16–37%.  Avoid RSA 4096 as a CA key
for performance-sensitive deployments.

---

## Challenge type comparison

| Challenge type    | Throughput (iss/s) | Challenge phase (ms) | Alloc pressure (MiB/iss) |
|:------------------|-------------------:|---------------------:|-------------------------:|
| http-01           |   623              | 12.9                 | 0.45                     |
| dns-persist-01    |   566              | 13.7                 | 0.50                     |

`http-01` and `dns-persist-01` deliver equivalent throughput on loopback
(difference is within run-to-run noise).  Both challenge phases reflect the
adaptive poll backoff (starts at 1 ms, caps at `--poll-ms`) rather than network
latency; the ~13 ms figure is dominated by polling overhead and background
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
pool, so the throughput ceiling of ≈ 640–770 iss/s applies to both.  The ceiling
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
|  1                 |   109             |   104             |
|  5                 |   700             |   639             |
| 10                 |   766             |   634             |
| 25                 |   606             |   599             |
| 50                 |   643             |   548             |

Both backends peak around 640–770 iss/s at 10 concurrent clients and remain
above 540 iss/s at 50 clients.  The bottleneck is the database connection
round-trip per query, not storage speed; switching from in-memory to a
tmpfs-backed file provides durability without a significant throughput penalty.

For sustained high-throughput targets consider:

- **In-memory database** for lab, CI, or ephemeral CA use cases.  Fastest
  startup; data is lost on restart.
- **File-backed WAL database** on a fast SSD or RAM-backed filesystem.
  Throughput matches in-memory while providing crash durability.
- **Sharding** — multiple Akāmu instances behind a load balancer, each with its
  own database — for production-scale deployments requiring higher aggregate
  issuance rates above the ≈ 640–770 iss/s per-instance ceiling.

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
|  1                 |  142 / 0 err      |  110 / 0 err      |   95 / 0 err      |   84 / 0 err      |
|  5                 |  650 / 0 err      |  596 / 0 err      |  344 / 0 err      |  213 / 0 err      |
| 10                 |  672 / 0 err      |  612 / 0 err      |  570 / 0 err      |  529 / 0 err      |
| 25                 |  585 / 0 err      |  517 / 0 err      |  518 / 0 err      |  502 / 0 err      |
| 50                 |  511 / 0 err      |  538 / 0 err      |  491 / 0 err      |  464 / 0 err      |

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
- Allocation pressure: ~451 KiB per issuance (JWS buffers, JSON serialisation, cert DER/PEM)

For ML-DSA key types allocation pressure rises to ~607–723 KiB per issuance for
leaf keys (with EC P-256 CA), and to ~707–953 KiB per issuance for a full
post-quantum chain (matching ML-DSA CA + ML-DSA leaf), due to larger key and
certificate structures.

These figures confirm that Akāmu has a stable heap footprint at steady state.
Per-issuance live growth is small and bounded by the number of concurrent workers,
not the total number of issuances.
