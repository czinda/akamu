# Performance

This chapter covers issuance throughput and latency characteristics of Akāmu
under load, with guidance on key type selection, database backend choice, and
capacity planning.

All numbers were collected on a single host — a Lenovo ThinkPad P1 Gen 5
(12th Gen Intel Core i7-12800H, 14 cores / 20 threads) — using the `acme-bench`
tool shipped in the repository:

```
cargo bench --bench acme_bench -- [OPTIONS]
```

The benchmark runs full ACME flows (account → new-order → challenge validate →
finalize → certificate download) against a real in-process server over the
loopback interface.  Reported latency is end-to-end wall time from the start of
`new-order` through certificate download; account creation is excluded because
it is amortised across all orders from a given client.

Results are shown for two database backends: **SQLite** (tmpfs-backed file on
`/dev/shm`) and **PostgreSQL** (connected via UNIX-domain socket, so no
network cost).

> **Database architecture.**  SQLite uses a single-connection write pool with
> `BEGIN IMMEDIATE` for every write transaction.  `SQLITE_BUSY_SNAPSHOT`
> (error 517) bypasses the busy handler in WAL mode — using `BEGIN IMMEDIATE`
> and a single connection eliminates the error entirely.  The optional
> read-only pool (`?mode=ro`) serves pure-read handlers (`get_order`,
> `get_authz`, `download_cert`) to reduce write-lock contention at high
> concurrency.  Approximately 23 SQL round-trips are needed per issuance
> (reduced from ~55 by moving anti-replay nonces to an in-memory store, using
> JOIN queries to collapse read pairs, consolidating multi-CA scope checks
> inside write transactions, replacing explicit 4-RT transactions with
> conditional-UPDATE autocommit in the challenge handler, and batching finalize
> audit events into a single two-row INSERT).
>
> PostgreSQL uses a standard connection pool (default 20, recommended 25
> connections) and per-connection MVCC; there is no write-lock serialisation.
> State-transition transactions (`new-order`, `new-authz`, `challenge`) use
> `SET LOCAL synchronous_commit = off` to eliminate per-commit WAL flush
> overhead (~1–4 ms on SSD); the certificate issuance transaction (`finalize`)
> retains full durability.

---

## Concurrency scaling

With EC P-256 certificates and an EC P-256 CA, the two backends scale
differently as client count increases.  SQLite saturates near 780 iss/s around
5–10 concurrent clients because the single write connection serialises all
writers regardless of concurrency.  PostgreSQL scales further — the crossover
where PostgreSQL overtakes SQLite occurs between c=10 and c=25 depending on
pool size.

| Clients | SQLite (iss/s) | mean (ms) | p95 (ms) | PG p=20 (iss/s) | mean (ms) | p95 (ms) | PG p=25 (iss/s) | mean (ms) | p95 (ms) |
|--------:|---------------:|----------:|---------:|----------------:|----------:|---------:|----------------:|----------:|---------:|
|  1      |    130         |   7.7     |  11.2    |      39         |  25.7     |  30.0    |      39         |  25.6     |  30.2    |
|  5      |    780         |   6.4     |   7.6    |     208         |  23.9     |  28.9    |     217         |  22.8     |  27.4    |
| 10      |    782         |  12.6     |  14.1    |     511         |  19.0     |  22.0    |     522         |  18.9     |  22.0    |
| 25      |    740         |  29.2     |  31.8    |     725         |  29.3     |  33.3    |     879         |  20.9     |  23.2    |
| 50      |    710         |  57.6     |  72.1    |     780         |  52.9     |  62.0    |     913         |  42.9     |  62.8    |

At c=1 PostgreSQL is ~3× slower than SQLite: each of the ~23 round-trips
requires a kernel context switch across the UNIX socket, whereas SQLite
executes in-process.  At c=5–10 the gap narrows as more requests overlap those
round-trips.  At c≥25 PostgreSQL with pool=25 is 19–28% faster than SQLite
because concurrent transactions execute without the write-lock queue.

---

## Key type comparison

The table below compares issuance performance for different CSR key types at
25 concurrent clients with an EC P-256 CA.

| CSR key type | SQLite (iss/s) | PG (iss/s) | SQLite fin (ms) | PG fin (ms) | p95 SQLite | p95 PG |
|:-------------|---------------:|-----------:|----------------:|------------:|-----------:|-------:|
| ec:P-256     |   552          |   608      |   7.4           |   8.0       |  46.4      |  30.6  |
| ed25519      |   613          |   528      |   7.9           |   8.1       |  41.1      |  52.4  |
| ec:P-384     |   593          |   541      |   8.2           |   8.6       |  49.1      |  53.7  |
| ml-dsa-44    |   552          |   503      |   9.7           |   8.6       |  45.8      |  50.3  |
| ml-dsa-65    |   437          |   521      |  11.9           |   8.9       |  73.2      |  47.4  |
| ml-dsa-87    |   427          |   516      |  12.8           |   9.4       |  80.9      |  55.1  |
| rsa:2048     |   179          |   143      | 80.0            |  90.0       | 207.5      | 183.9  |
| rsa:4096     |    14          |    16      | 785.2           | 766.2       | 1641.8     | 1630.9 |

PG column uses pool=20; pool=25 adds a further ~5–14% on most key types.

At c=25 SQLite's single write connection is the bottleneck for all key types.
Under PostgreSQL the bottleneck shifts to crypto cost: ML-DSA-65 and ML-DSA-87
outperform their SQLite counterparts by ~20% because concurrent signing no
longer queues behind the write lock.  RSA numbers are CPU-bound and nearly
identical across backends.

Classical EC and Ed25519 cluster around 530–610 iss/s across both backends.
Finalize-phase latency (CSR verification + certificate issuance) reflects
signing cost: EC and Ed25519 run at ~7–8 ms, ML-DSA adds 1–4 ms, and RSA
adds tens to hundreds of milliseconds.

RSA is the outlier: RSA 2048 adds ~80–90 ms to finalize, and RSA 4096 adds
~766–785 ms.

### RSA 4096 saturation

| Clients | Throughput (iss/s) | Finalize mean (ms) | p99 (ms) |
|--------:|-------------------:|-------------------:|---------:|
|  1      |    3               |   348              |   787    |
| 10      |   14               |   609              |  1904    |
| 25      |   16               |  1072              |  3235    |
| 50      |   14               |  1861              |  6332    |

Throughput is limited by RSA 4096 key generation time; both backends produce
the same results since the bottleneck is CPU, not IO.  At 50 clients queuing
raises p99 to over 6 seconds.  Avoid RSA 4096 in any configuration where more
than a handful of concurrent ACME clients are expected.

---

## Post-quantum cryptography

Akāmu supports ML-DSA (FIPS 204 / RFC 9881) for both CA keys and certificate
keys.  Three security levels are available.  The table uses a full post-quantum
chain (ML-DSA CA + ML-DSA leaf, with `--verify-cert`) at 25 concurrent clients:

| Parameter set | NIST cat. | SQLite (iss/s) | PG p=20 (iss/s) | PG p=25 (iss/s) | Alloc (MiB/iss) |
|:--------------|:---------:|---------------:|----------------:|----------------:|----------------:|
| ML-DSA-44     | 2         |   501          |   468           |   540           | 0.74            |
| ML-DSA-65     | 3         |   390          |   503           |   540           | 0.86            |
| ML-DSA-87     | 5         |   399          |   424           |   506           | 1.03            |
| EC P-256      | —         |   496          |   512           |   586           | 0.49            |

Alloc figures are for PG p=25; SQLite is ~10–15% lower due to absent protocol
framing overhead.

PostgreSQL removes the write-lock serialisation that suppresses ML-DSA
throughput under SQLite.  ML-DSA-65 and ML-DSA-87 at pool=25 reach 540 and
506 iss/s respectively, matching or exceeding their SQLite figures despite the
larger certificate structures.  ML-DSA allocation pressure is 50–110% higher
than EC P-256 per issuance, reflecting larger key and signature structures.

ML-DSA requires OpenSSL 3.5 or later.  Akāmu will report a startup error if
the requested key type is unavailable on the installed OpenSSL version.

### CA key type impact

The table uses an EC P-256 leaf at 25 concurrent clients, varying the CA key.

| CA key    | SQLite (iss/s) | PG p=20 (iss/s) | PG p=25 (iss/s) | PG p=25 fin (ms) |
|:----------|---------------:|----------------:|----------------:|-----------------:|
| ec:P-256  |   457          |   510           |   616           |   7.2            |
| ec:P-384  |   500          |   477           |   552           |   8.7            |
| rsa:2048  |   519          |   512           |   591           |   8.1            |
| rsa:3072  |   440          |   496           |   528           |   9.9            |
| rsa:4096  |   389          |   433           |   447           |  16.0            |

EC P-256 delivers the highest throughput at 25 clients across all backends.
Larger RSA CA keys incur increasing finalize latency; RSA 4096 as CA costs
~9 ms more than EC P-256 at finalize and reduces throughput by ~27%.  Avoid
RSA 4096 as a CA key for performance-sensitive deployments.

---

## Challenge type comparison

| Challenge type | SQLite (iss/s) | PG p=20 (iss/s) | PG p=25 (iss/s) | Challenge phase (ms) PG p=25 | Alloc (MiB/iss) |
|:---------------|---------------:|----------------:|----------------:|-----------------------------:|----------------:|
| http-01        |   615          |   652           |   785           |   7.8                        | 0.46            |
| dns-persist-01 |   530          |   655           |   712           |   8.7                        | 0.52            |

`http-01` and `dns-persist-01` deliver equivalent throughput across all
backends (difference is within run-to-run noise).  Both challenge phases reflect
the adaptive poll backoff (starts at 1 ms, caps at `--poll-ms`) rather than
network latency.  At pool=25 the challenge phase drops from ~10–12 ms (SQLite)
to ~8–9 ms because concurrent challenge updates no longer serialise behind the
write lock.

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

### Choosing a backend

| Workload | Recommended backend |
|:---------|:--------------------|
| Lab, CI, ephemeral CA | SQLite `:memory:` — fastest startup, no persistence |
| Single-node, ≤10 concurrent clients | SQLite (tmpfs or SSD WAL) — lower per-round-trip cost than PostgreSQL at low concurrency |
| Single-node, ≥25 concurrent clients | PostgreSQL — no write-lock serialisation; scales to 900+ iss/s |
| Production, multi-node | PostgreSQL — standard connection pooling, MVCC, operational tooling |

SQLite is faster than PostgreSQL at low concurrency (c≤10) because each query
is an in-process function call with no kernel IPC.  PostgreSQL pays ~1–2 ms per
round-trip in UNIX-socket context-switch overhead; at c=1 this results in
~3× lower throughput.  The crossover where PostgreSQL overtakes SQLite occurs
at c=25 with pool=20, or at c=10–25 with pool=25.

### SQLite: backend comparison (tmpfs vs persistent file)

The table compares a persistent `/dev/shm` file (accumulated rows from prior
benchmark sections) with a fresh tmpfs file created per benchmark run.

| Concurrent clients | Persistent shm (iss/s) | Fresh tmpfs (iss/s) |
|-------------------:|-----------------------:|--------------------:|
|  1                 |   108                  |   113               |
|  5                 |   691                  |   681               |
| 10                 |   684                  |   809               |
| 25                 |   650                  |   759               |
| 50                 |   658                  |   692               |

At c=10–25 the fresh tmpfs file is 17–18% faster; the persistent file carries
accumulated rows that increase index scan cost.  Both use WAL mode on a
RAM-backed filesystem; storage speed is not a factor.  For sustained production
use, periodic `VACUUM` or WAL checkpointing keeps the persistent file compact.

### SQLite: connection pool and `BEGIN IMMEDIATE`

`SQLITE_BUSY_SNAPSHOT` (error 517) occurs in WAL mode when a deferred
transaction (`BEGIN`) captures a read snapshot that becomes stale after another
connection commits — even when the two transactions write to completely different
rows.  Unlike `SQLITE_BUSY` (error 5), error 517 bypasses the busy handler
entirely, so `busy_timeout` has no effect on it.

Akāmu resolves this by using `BEGIN IMMEDIATE` for every write transaction.
`BEGIN IMMEDIATE` acquires the write lock at transaction start, so the snapshot
is always current.  Any resulting `SQLITE_BUSY` contention is handled
transparently by the `busy_timeout = 5 s` already configured on the pool.

**Throughput (iss/s) on fresh tmpfs WAL with `BEGIN IMMEDIATE`:**

| Concurrent clients | Pool = 1 | Pool = 2 | Pool = 4 | Pool = 8 |
|-------------------:|---------:|---------:|---------:|---------:|
|  1                 |  118     |  115     |  103     |   95     |
|  5                 |  726     |  659     |  402     |  262     |
| 10                 |  778     |  752     |  714     |  614     |
| 25                 |  736     |  666     |  630     |  608     |
| 50                 |  692     |  652     |  639     |  544     |

All pool sizes produce **zero errors** — `BEGIN IMMEDIATE` eliminates
`SQLITE_BUSY_SNAPSHOT` regardless of pool size.  Pool = 1 consistently delivers
the highest throughput because all requests share a single serialised connection
channel with no lock-acquisition contention.  Pool = 2 and above pay
increasingly for `BEGIN IMMEDIATE` wait time as multiple connections compete
for the WAL write lock; the gap widens at medium concurrency (5–10 clients)
where lock contention is highest relative to available parallelism.

For the single-connection production default this has no observable effect:
with one connection there is never a concurrent writer, so `BEGIN IMMEDIATE`
and `BEGIN DEFERRED` behave identically.

### SQLite: read-only pool split

Separating read-heavy handlers onto a dedicated `?mode=ro` pool frees the write
connection from serving pure-read requests.  The benefit grows with concurrency,
where read and write requests are most likely to interleave.

**Throughput (iss/s) on fresh tmpfs WAL — no split vs read-only pool (ro = 4):**

| Concurrent clients | No split (iss/s) | With ro=4 (iss/s) | Gain |
|-------------------:|-----------------:|------------------:|-----:|
|  1                 |  114             |  102              |  −11% |
|  5                 |  775             |  858              |  +11% |
| 10                 |  857             | 1045              |  +22% |
| 25                 |  780             |  871              |  +12% |
| 50                 |  757             |  793              |   +5% |

The split provides negligible benefit at c=1 (no contention) but yields
+11–22% at c=5–25, where write and read handlers compete most heavily for the
single write connection.  At c=50 most contention is again on the write lock
and the gain falls to +5%.

**Throughput (iss/s) sweeping ro-connections at 10 concurrent clients:**

| ro connections | Throughput (iss/s) |
|---------------:|-------------------:|
|  1             |  1010              |
|  2             |  1056              |
|  4             |   990              |
|  8             |   980              |
| 16             |  1007              |

ro=2 saturates the benefit (1056 iss/s); additional connections beyond 2
provide no further improvement because write-connection serialisation becomes
the dominant constraint.

### PostgreSQL: connection pool size

With PostgreSQL the connection pool size directly controls how many concurrent
requests can hold a database connection simultaneously.  With fewer connections
than clients, excess clients queue; with pool ≥ clients all run in parallel.

| Concurrent clients | PG pool=20 (iss/s) | PG pool=25 (iss/s) | Gain |
|-------------------:|-------------------:|-------------------:|-----:|
|  1                 |   39               |   39               |   0% |
|  5                 |  208               |  217               |  +4% |
| 10                 |  511               |  522               |  +2% |
| 25                 |  725               |  879               | +21% |
| 50                 |  780               |  913               | +17% |

At c≤10 pool size has almost no effect because 10 clients rarely saturate a
20-connection pool.  At c=25–50 raising the pool from 20 to 25 eliminates the
5-connection queue that forms at peak concurrency and yields +17–21%.

The recommended default is **25 connections** (`--pool-connections 25`).
Raising the pool beyond 25 has not shown further benefit and can increase
PostgreSQL shared-memory pressure.

---

## Running the benchmark

The `acme-bench` binary is built as a Cargo bench target:

```bash
cargo bench --bench acme_bench -- --help
```

The `contrib/performance/run_benchmarks.sh` script runs the full suite and
writes one JSON object per benchmark to a newline-delimited file:

```bash
# SQLite (tmpfs-backed /dev/shm) — sections 1–9 including pool/RO comparisons
DB=/dev/shm/akamu_bench.db
SQLITE_URL="sqlite://$DB" \
  contrib/performance/run_benchmarks.sh ~/bench_sqlite.ndjson
rm -f "$DB" "$DB-wal" "$DB-shm"

# PostgreSQL — sections 1–6; requires backend-postgres feature and a running server
BENCH_RESET=1 PG_POOL=25 PG_URL="postgres:///akamu_bench" \
  contrib/performance/run_benchmarks.sh ~/bench_pg25.ndjson
```

`BENCH_RESET=1` truncates all ACME tables and issues `CHECKPOINT` before
section 1, ensuring a clean database state across successive runs.

Common individual invocations:

```bash
# Baseline: 25 concurrent clients, 200 issuances, EC P-256, 5 ms poll cap
cargo bench --bench acme_bench -- --clients 25 --requests 200 --warmup 20 --poll-ms 5

# PostgreSQL backend
cargo bench --features backend-postgres --bench acme_bench -- \
  --db postgres:///akamu_bench --pool-connections 25 \
  --clients 25 --requests 200 --warmup 20 --poll-ms 5

# Compare RSA 2048 vs EC P-256
cargo bench --bench acme_bench -- --key-type rsa:2048 --clients 25 --requests 100
cargo bench --bench acme_bench -- --key-type ec:P-256  --clients 25 --requests 100

# Full post-quantum chain (ML-DSA-65 CA + ML-DSA-65 leaf)
cargo bench --bench acme_bench -- \
  --ca-key-type ml-dsa-65 --key-type ml-dsa-65 \
  --clients 25 --requests 100 --verify-cert

# Concurrency sweep
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
| `--db PATH` | `:memory:` | Database URL — SQLite path or `postgres://…` |
| `--pool-connections N` | `1` | Connection pool size; for SQLite, pool > 1 is not recommended (see [Connection pool size](#sqlite-connection-pool-and-begin-immediate)); for PostgreSQL, use 25 |
| `--ro-connections N` | `0` | Read-only pool size (SQLite only); `0` disables the split |
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

At 25 concurrent clients with 300 measured issuances (EC P-256, 5 ms poll cap):

- Server overhead: ~0.3 MiB live (router tables, DB connection pool, CA state, HTTP client)
- Per-issuance heap growth: ~1–2 KiB (request-scoped state retained by tokio workers)
- Peak during issuances: ~2.5 MiB (25 in-flight requests simultaneously)
- Allocation pressure: ~430–470 KiB per issuance (JWS buffers, JSON serialisation, cert DER/PEM); PostgreSQL adds ~30–50 KiB per issuance for protocol framing

For ML-DSA key types allocation pressure rises to ~580–740 KiB per issuance for
leaf keys (with EC P-256 CA), and to ~740–1030 KiB per issuance for a full
post-quantum chain (matching ML-DSA CA + ML-DSA leaf), due to larger key and
certificate structures.

These figures confirm that Akāmu has a stable heap footprint at steady state.
Per-issuance live growth is small and bounded by the number of concurrent workers,
not the total number of issuances.
