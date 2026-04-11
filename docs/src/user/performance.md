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

---

## Concurrency scaling

With EC P-256 certificates and an EC P-256 CA, throughput scales near-linearly
with the number of concurrent clients up to the SQLite write-serialisation
ceiling:

| Concurrent clients | Throughput (iss/s) | Mean latency (ms) | p95 (ms) |
|-------------------:|-------------------:|------------------:|---------:|
|  1                 |   225              | 4.4               | 5.2      |
|  5                 | 1 114              | 4.5               | 5.1      |
| 10                 | 2 116              | 4.7               | 5.5      |
| 25                 | 2 822              | 7.1               | 8.1      |
| 50                 | 3 256              | 11.6              | 13.8     |

Throughput rises 14× from 1 to 50 clients.  Latency climbs as the SQLite write
lock is increasingly contended above ~10 concurrent clients, but remains in the
single-digit millisecond range through 25 clients.

The practical ceiling is the SQLite write lock and the minimum round-trip time
of the challenge-validation loop.  With in-memory SQLite and fast crypto
(EC P-256, Ed25519, ML-DSA) the bottleneck is network/scheduling jitter rather
than CPU.

---

## Key type comparison

The table below compares issuance performance for different CSR key types at
25 concurrent clients with an EC P-256 CA.

| CSR key type | Throughput (iss/s) | Mean latency (ms) | p95 (ms) | Finalize phase (ms) |
|:-------------|-------------------:|------------------:|---------:|--------------------:|
| ed25519      | 2 914              |  6.6              |  7.6     |  1.6                |
| ec:P-256     | 2 903              |  6.6              |  8.5     |  1.5                |
| ec:P-384     | 2 266              |  8.6              | 10.5     |  3.3                |
| ml-dsa-44    | 2 211              |  8.4              | 10.3     |  2.6                |
| ml-dsa-65    | 2 125              |  8.7              | 10.6     |  3.2                |
| ml-dsa-87    | 1 930              |  9.6              | 11.7     |  4.0                |
| rsa:2048     |   175              | 121.8             | 256.0    | 100.7               |
| rsa:4096     |    16              | 1 298             | 2 521    | 1 094               |

EC P-256 and Ed25519 are the fastest options.  ML-DSA post-quantum key types
(FIPS 204) are 25–35% slower than EC P-256 due to larger CSR and certificate
sizes, but remain well above 1 000 iss/s at 25 clients.

RSA is the outlier: RSA 2048 adds ~100 ms to the finalize phase (key generation
+ CA signing), and RSA 4096 adds ~1 100 ms — a 730× penalty compared with EC
P-256 on the finalize phase.

### RSA 4096 saturation

RSA 4096 key generation is CPU-intensive and happens inside the finalize handler.
Under concurrency the SQLite write lock queues behind the signing time and
throughput stops growing:

| Clients | Throughput (iss/s) | Finalize mean (ms) | p99 (ms) |
|--------:|-------------------:|-------------------:|---------:|
|  1      |   2                |  294               |  630     |
| 10      |  16                | 1 094              | 3 829    |
| 25      |  16                | 1 094              | 3 829    |
| 50      |  13                | 1 960              | 6 480    |

Throughput plateaus at ≈16 iss/s regardless of client count while latency grows
without bound.  Avoid RSA 4096 in any configuration where more than a handful
of concurrent ACME clients are expected.

---

## Post-quantum cryptography

Akāmu supports ML-DSA (FIPS 204 / RFC 9881) for both CA keys and certificate
keys.  Three security levels are available:

| Parameter set | NIST category | Throughput (iss/s) | Alloc pressure (MiB/iss) |
|:--------------|:-------------:|-------------------:|-------------------------:|
| ML-DSA-44     | 2             | 2 211              | 0.43                     |
| ML-DSA-65     | 3             | 2 125              | 0.48                     |
| ML-DSA-87     | 5             | 1 930              | 0.53                     |
| EC P-256      | —             | 2 903              | 0.28                     |

ML-DSA allocation pressure is 50–90% higher than EC P-256 per issuance,
reflecting the larger key and signature structures.  Heap footprint at steady
state remains under 5 MiB for any key type at 25 concurrent clients.

ML-DSA requires OpenSSL 3.5 or later.  Akāmu will report a startup error if the
requested key type is unavailable on the installed OpenSSL version.

### CA key type impact

The CA key controls how fast the server signs each issued certificate.  EC CA
keys are recommended.  RSA 4096 as the CA key limits throughput:

| CA key    | Throughput (iss/s) | Mean latency (ms) | Finalize (ms) |
|:----------|-------------------:|------------------:|--------------:|
| ec:P-256  | 2 386              |  7.0              |  1.5          |
| ec:P-384  | 2 435              |  7.5              |  2.1          |
| rsa:2048  | 2 700              |  7.9              |  2.5          |
| rsa:4096  | 1 085              | 17.7              | 10.8          |

RSA 2048 as the CA key is acceptable (finalize ~2.5 ms).  RSA 4096 as the CA
key reduces throughput by ~55% vs EC P-256 due to slower signing.

A full post-quantum deployment (ML-DSA CA + ML-DSA leaf keys) achieves
>1 500 iss/s at 25 concurrent clients with allocation pressure ~0.5 MiB/iss.

---

## Challenge type comparison

| Challenge type    | Throughput (iss/s) | Challenge phase (ms) | Alloc pressure (MiB/iss) |
|:------------------|-------------------:|---------------------:|-------------------------:|
| http-01           | 2 822              | 3.2                  | 0.28                     |
| dns-persist-01    | 2 768              | 3.7                  | 0.31                     |

`http-01` and `dns-persist-01` deliver equivalent throughput on loopback.
`dns-persist-01` shows slightly higher latency because DNS validation incurs one
extra UDP round-trip compared with the HTTP challenge responder.

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

All benchmarks above use an in-memory SQLite database (`:memory:`).  A
file-backed database on a local SSD introduces a small write-sync overhead but
does not change the throughput ceiling for EC or ML-DSA workloads at typical
client counts.

For sustained high-throughput targets consider:

- Running with an in-memory database if durability across restarts is not
  required (lab or internal CA use cases).
- Placing the SQLite file on a RAM-backed filesystem (`tmpfs`) for a middle
  ground.
- Sharding load across multiple Akāmu instances behind a load balancer, each
  with its own database, for production-scale deployments.

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
    server ready:         0.2 MiB  live   (server overhead: +1.5 MiB)
    after  220 iss.:      1.6 MiB  live   (issuance growth: +1.4 MiB, 6.7 KiB/iss.)
    peak live:            3.9 MiB         (high-water mark during issuances)
    alloc pressure:      61.2 MiB  total  (0.278 MiB/iss. requested, incl. freed)
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
    "after_bench_live_bytes":    1677722,
    "peak_live_bytes":           4089446,
    "server_overhead_bytes":     1572864,
    "issuance_growth_bytes":     1472922,
    "per_issuance_growth_bytes":    6695,
    "issuance_alloc_bytes":     64174080,
    "per_issuance_alloc_bytes":   291700,
    "total_alloc_count":         950000
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

- Server overhead: ~1.5 MiB live (router tables, DB connection, CA state, HTTP client pool)
- Per-issuance heap growth: ~7 KiB (request-scoped state retained by tokio workers)
- Peak during issuances: ~4 MiB (25 in-flight requests simultaneously)
- Allocation pressure: ~280 KiB per issuance (JWS buffers, JSON serialisation, cert DER/PEM)

For ML-DSA key types allocation pressure rises to ~430–530 KiB per issuance
due to larger key and certificate structures.

These figures confirm that Akāmu has a stable heap footprint at steady state.
Per-issuance live growth is small and bounded by the number of concurrent workers,
not the total number of issuances.
