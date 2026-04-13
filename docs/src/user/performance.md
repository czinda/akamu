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

> **Note — database layer (sqlx).**  Akāmu uses sqlx 0.8 for SQLite access.
> The in-memory database path (`db = ":memory:"`, the benchmark default) uses a
> single-connection pool (`max_connections = 1`), because every SQLite in-memory
> connection opens its own private, empty database.  All ~20 SQL operations per
> issuance are serialised through this one pool connection.  As a result,
> throughput for the in-memory configuration plateaus at ≈ 850 iss/s regardless
> of concurrent-client count — determined by how fast the single connection can
> process queries, not by crypto or network speed.  File-backed databases use a
> 4-connection WAL-mode pool and do not have this ceiling; see the
> [Database scalability](#database-scalability) section for guidance.

---

## Concurrency scaling

With EC P-256 certificates and an EC P-256 CA, throughput scales up to ~5
concurrent clients and then plateaus as the single-connection pool becomes
the bottleneck:

| Concurrent clients | Throughput (iss/s) | Mean latency (ms) | p95 (ms) |
|-------------------:|-------------------:|------------------:|---------:|
|  1                 |   208              |  4.8              |  5.8     |
|  5                 |   760              |  6.5              |  8.5     |
| 10                 |   880              | 11.2              | 14.9     |
| 25                 |   846              | 26.1              | 29.3     |
| 50                 |   808              | 53.9              | 60.2     |

Throughput peaks around 10 concurrent clients at ~880 iss/s and is stable
thereafter; latency grows roughly linearly with client count, consistent with a
single serialised resource.  The practical bottleneck is the in-memory SQLite
single connection; crypto and network are not limiting factors at these rates.

---

## Key type comparison

The table below compares issuance performance for different CSR key types at
25 concurrent clients with an EC P-256 CA.

| CSR key type | Throughput (iss/s) | Mean latency (ms) | p95 (ms) | Finalize phase (ms) |
|:-------------|-------------------:|------------------:|---------:|--------------------:|
| ec:P-256     |   807              | 24.5              | 32.0     |   5.7               |
| ed25519      |   762              | 26.5              | 38.1     |   5.9               |
| ec:P-384     |   735              | 27.1              | 40.0     |   6.5               |
| ml-dsa-44    |   749              | 26.4              | 31.9     |   6.4               |
| ml-dsa-65    |   769              | 26.1              | 32.7     |   6.7               |
| ml-dsa-87    |   725              | 27.9              | 41.3     |   7.4               |
| rsa:2048     |   167              | 119.9             | 220.3    |  93.2               |
| rsa:4096     |    12              | 1 015             | 2 187    | 868                 |

All classical and post-quantum key types cluster around 725–810 iss/s because
throughput is bounded by the single-connection database pool, not by crypto.
Finalize-phase latency (CSR verification + certificate issuance) still reflects
relative signing cost: EC and Ed25519 are fastest, ML-DSA adds ~1–2 ms, and RSA
adds tens to hundreds of milliseconds.

RSA is the outlier: RSA 2048 adds ~90 ms to finalize, and RSA 4096 adds ~870 ms.

### RSA 4096 saturation

| Clients | Throughput (iss/s) | Finalize mean (ms) | p99 (ms) |
|--------:|-------------------:|-------------------:|---------:|
|  1      |    3               |   381              |   828    |
| 10      |   12               |   712              |  1 158   |
| 25      |   13               |   835              |  1 587   |
| 50      |   19               |   749              |  1 061   |

Throughput is limited by RSA 4096 key generation time regardless of concurrency.
Avoid RSA 4096 in any configuration where more than a handful of concurrent ACME
clients are expected.

---

## Post-quantum cryptography

Akāmu supports ML-DSA (FIPS 204 / RFC 9881) for both CA keys and certificate
keys.  Three security levels are available.  The table uses a full post-quantum
chain (ML-DSA CA + ML-DSA leaf, with `--verify-cert`) at 25 concurrent clients:

| Parameter set | NIST category | Throughput (iss/s) | Alloc pressure (MiB/iss) |
|:--------------|:-------------:|-------------------:|-------------------------:|
| ML-DSA-44     | 2             |   685              | 0.64                     |
| ML-DSA-65     | 3             |   708              | 0.69                     |
| ML-DSA-87     | 5             |   715              | 0.84                     |
| EC P-256      | —             |   807              | 0.38                     |

ML-DSA allocation pressure is 70–120% higher than EC P-256 per issuance,
reflecting the larger key and signature structures.  Throughput difference between
ML-DSA and EC P-256 is small (10–15%) because the database single-connection
bottleneck dominates over crypto cost at 25 clients.

ML-DSA requires OpenSSL 3.5 or later.  Akāmu will report a startup error if the
requested key type is unavailable on the installed OpenSSL version.

### CA key type impact

| CA key    | Throughput (iss/s) | Mean latency (ms) | Finalize (ms) |
|:----------|-------------------:|------------------:|--------------:|
| ec:P-256  |   795              | 25.5              |  5.8          |
| ec:P-384  |   804              | 24.9              |  5.7          |
| rsa:2048  |   685              | 29.6              |  6.7          |
| rsa:4096  |   607              | 31.9              | 12.1          |

EC and Ed25519 CA keys deliver the highest throughput.  RSA 2048 as the CA key
is acceptable (finalize ~6.7 ms).  RSA 4096 as the CA key reduces throughput by
~24% vs EC P-256 due to slower signing; avoid it for performance-sensitive
deployments.

---

## Challenge type comparison

| Challenge type    | Throughput (iss/s) | Challenge phase (ms) | Alloc pressure (MiB/iss) |
|:------------------|-------------------:|---------------------:|-------------------------:|
| http-01           |   790              | 10.1                 | 0.38                     |
| dns-persist-01    |   861              | 10.0                 | 0.41                     |

`http-01` and `dns-persist-01` deliver equivalent throughput on loopback.
Both challenge phases reflect the adaptive poll backoff (starts at 1 ms, caps at
`--poll-ms`) rather than network latency, so the 10 ms figure is dominated by
polling overhead.

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

The benchmark default is an in-memory SQLite database (`:memory:`), which uses a
single pool connection.  A file-backed database on a local SSD with WAL mode
enables a 4-connection pool: readers do not block writers, and multiple reads can
proceed concurrently.  This removes the single-connection ceiling for
read-intensive phases (authz fetch, cert download) while writes remain serialised
by SQLite.

For sustained high-throughput targets consider:

- **File-backed WAL database** on a fast SSD or RAM-backed filesystem (`tmpfs`).
  The 4-connection pool removes the in-memory ceiling while retaining durability.
- **In-memory database** if restart-durability is not required (lab or internal CA
  use cases); throughput is bounded at ≈ 850 iss/s by the single-connection pool.
- **Sharding** — multiple Akāmu instances behind a load balancer, each with its
  own database — for production-scale deployments requiring higher aggregate
  issuance rates.

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

At 25 concurrent clients with 200 measured issuances (EC P-256, `:memory:` DB,
5 ms poll cap):

- Server overhead: ~0.5 MiB live (router tables, DB connection pool, CA state, HTTP client)
- Per-issuance heap growth: ~2 KiB (request-scoped state retained by tokio workers)
- Peak during issuances: ~1.5 MiB (25 in-flight requests simultaneously)
- Allocation pressure: ~380 KiB per issuance (JWS buffers, JSON serialisation, cert DER/PEM)

For ML-DSA key types allocation pressure rises to ~640–840 KiB per issuance
due to larger key and certificate structures.

These figures confirm that Akāmu has a stable heap footprint at steady state.
Per-issuance live growth is small and bounded by the number of concurrent workers,
not the total number of issuances.
