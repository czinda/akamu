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
with the number of concurrent clients:

| Concurrent clients | Throughput (iss/s) | Mean latency (ms) | p95 (ms) |
|-------------------:|-------------------:|------------------:|---------:|
|  1                 |   9                | 108               | 109      |
|  5                 |  46                | 108               | 109      |
| 10                 |  92                | 108               | 110      |
| 25                 | 200                | 111               | 113      |
| 50                 | 346                | 112               | 116      |

End-to-end latency rises by only 4 ms across the full 1–50 client range.  The
flat latency profile exists because the dominant cost is two mandatory async
poll sleeps (one for challenge validation, one for finalize), each capped at
50 ms.  Those waits are CPU-idle and fully concurrent, so adding clients
increases throughput without affecting individual request latency.

The practical ceiling is the SQLite write lock.  With in-memory SQLite and
fast crypto (EC, Ed25519, ML-DSA), the lock is held only during the database
write at finalize and is released quickly enough to keep throughput linear.

---

## Key type comparison

The table below compares issuance performance for different CSR key types at 10
concurrent clients.  The CA uses EC P-256 in all rows.

| CSR key type | Throughput (iss/s) | Mean latency (ms) | p95 (ms) | Finalize phase (ms) |
|:-------------|-------------------:|------------------:|---------:|--------------------:|
| ec:P-256     |  92                | 108               | 110      |  54                 |
| ec:P-384     |  92                | 109               | 111      |  55                 |
| ed25519      |  92                | 108               | 109      |  54                 |
| ml-dsa-44    |  91                | 110               | 111      |  55                 |
| ml-dsa-65    |  92                | 109               | 111      |  55                 |
| ml-dsa-87    |  91                | 110               | 111      |  55                 |
| rsa:2048     |  65                | 148               | 188      |  94                 |
| rsa:4096     |  12                | 767               | 1594     | 713                 |

All EC, Ed25519, and ML-DSA key types deliver equivalent throughput and latency.
RSA is the outlier: RSA 2048 adds roughly 40 ms to the finalize phase (CA
signing time), and RSA 4096 adds 660 ms — a 12× penalty compared with EC.

### RSA 4096 saturation

RSA 4096 key generation is CPU-intensive and is performed inside the finalize
handler while holding the SQLite write lock.  Under concurrency the lock queues
up and throughput stops growing:

| Clients | Throughput (iss/s) | Finalize mean (ms) | p99 (ms) |
|--------:|-------------------:|-------------------:|---------:|
|  1      |   2                | 439                | 1221     |
|  5      |   9                | 489                | 1433     |
| 10      |  12                | 713                | 2045     |
| 25      |  15                | 1278               | 4198     |
| 50      |  13                | 1960               | 6480     |

Throughput plateaus at ≈15 iss/s regardless of client count while latency grows
without bound.  Avoid RSA 4096 in any configuration where more than a handful
of concurrent ACME clients are expected.

---

## Post-quantum cryptography

Akāmu supports ML-DSA (FIPS 204 / RFC 9881) for both CA keys and certificate
keys.  Three security levels are available:

| Parameter set | NIST category | Key generate | Sign (CA) |
|:--------------|:-------------:|:------------:|:---------:|
| ML-DSA-44     | 2             | fast         | fast      |
| ML-DSA-65     | 3             | fast         | fast      |
| ML-DSA-87     | 5             | fast         | fast      |

ML-DSA requires OpenSSL 3.5 or later.  Akāmu will report a startup error if the
requested key type is unavailable on the installed OpenSSL version.

### Scalability with ML-DSA CSR keys

All three ML-DSA security levels show the same concurrency scaling curve as
EC P-256:

| Clients | ML-DSA-44 (iss/s) | ML-DSA-65 (iss/s) | ML-DSA-87 (iss/s) | EC P-256 (iss/s) |
|--------:|------------------:|------------------:|------------------:|-----------------:|
|  1      |  9                |  9                |  9                |  9               |
|  5      | 46                | 46                | 46                | 46               |
| 10      | 91                | 92                | 91                | 92               |
| 25      | 197               | 197               | 196               | 200              |
| 50      | 346               | 337               | 345               | 346              |

There is no measurable cost for moving from classical to post-quantum
cryptography at any security level.

### CA key type impact

Changing the CA key from EC P-256 to any ML-DSA variant has no observable
effect on throughput or latency.  The CA signing operation is not on the
critical path:

| CA key    | Throughput (iss/s) | Mean latency (ms) | Finalize (ms) |
|:----------|-------------------:|------------------:|--------------:|
| ec:P-256  | 92                 | 108               | 54            |
| ml-dsa-44 | 92                 | 108               | 54            |
| ml-dsa-65 | 91                 | 109               | 55            |
| ml-dsa-87 | 92                 | 109               | 55            |

A full post-quantum deployment (ML-DSA CA + ML-DSA leaf keys) is operationally
free compared with a classical EC deployment.

---

## Key type recommendations

| Scenario | Recommended key type |
|:---------|:---------------------|
| General purpose, broad client compatibility | `ec:P-256` |
| Higher security margin, still classical | `ec:P-384` |
| Post-quantum resistant, FIPS 204 category 2 | `ml-dsa-44` |
| Post-quantum resistant, FIPS 204 category 3 | `ml-dsa-65` |
| Post-quantum resistant, FIPS 204 category 5 | `ml-dsa-87` |
| Interoperability with RSA-only clients | `rsa:2048` (avoid RSA 4096 under load) |

---

## Database scalability

All benchmarks above use an in-memory SQLite database (`:memory:`).  A
file-backed database on a local SSD introduces a small write-sync overhead but
does not change the throughput ceiling for EC or ML-DSA workloads, because the
SQLite write lock is released quickly enough that the file I/O is not on the
critical path at these client counts.

For very high throughput targets (hundreds of iss/s sustained) consider:

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
# Baseline: 10 concurrent clients, 100 issuances, EC P-256
cargo bench --bench acme_bench -- --clients 10 --requests 100

# Compare RSA 2048 vs EC P-256
cargo bench --bench acme_bench -- --key-type rsa:2048 --clients 10 --requests 100
cargo bench --bench acme_bench -- --key-type ec:P-256  --clients 10 --requests 100

# Full post-quantum chain (CA + leaf both ML-DSA-65)
cargo bench --bench acme_bench -- \
  --ca-key-type ml-dsa-65 --key-type ml-dsa-65 \
  --clients 10 --requests 100 --verify-cert

# Scalability sweep
for n in 1 5 10 25 50; do
  cargo bench --bench acme_bench -- --clients $n --requests 200 --warmup 20
done

# dns-persist-01 challenge type
cargo bench --bench acme_bench -- --challenge dns-persist-01 --clients 10

# JSON output for scripting
cargo bench --bench acme_bench -- --output json --clients 10 --requests 200 | jq .summary
```

### Available options

| Option | Default | Description |
|:-------|:--------|:------------|
| `--clients N` | 10 | Concurrent worker tasks |
| `--requests N` | 100 | Issuances to measure (warmup not counted) |
| `--warmup N` | 10 | Warmup issuances discarded before measurement |
| `--challenge TYPE` | `http-01` | `http-01` or `dns-persist-01` |
| `--key-type TYPE` | `ec:P-256` | CSR key type (see table above) |
| `--ca-key-type TYPE` | `ec:P-256` | CA key type (same syntax) |
| `--db PATH` | `:memory:` | SQLite path — `:memory:` or a file path |
| `--wildcard` | off | Issue `*.bench-N.acme-bench.test` (dns-persist-01 only) |
| `--output FORMAT` | `text` | `text` or `json` |
| `--verify-cert` | off | Parse and verify the SAN of every issued certificate |

---

## Memory consumption

The benchmark instruments heap allocation using a custom
[`GlobalAlloc`](https://doc.rust-lang.org/std/alloc/trait.GlobalAlloc.html)
wrapper that wraps the system allocator with four `AtomicU64` counters.  This
reports in-process heap usage without any external tooling or `/proc` parsing.

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
    server ready:         0.2 MiB  live   (server overhead: +0.0 MiB)
    after  110 iss.:      0.2 MiB  live   (issuance growth: +0.0 MiB, 2.1 KiB/iss.)
    peak live:            0.5 MiB         (high-water mark during issuances)
    alloc pressure:       3.7 MiB  total  (0.034 MiB/iss. requested, incl. freed)
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
    "after_bench_live_bytes":     204900,
    "peak_live_bytes":            524288,
    "server_overhead_bytes":      102400,
    "issuance_growth_bytes":          100,
    "per_issuance_growth_bytes":        1,
    "issuance_alloc_bytes":       3774873,
    "per_issuance_alloc_bytes":     34317,
    "total_alloc_count":          182035
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

At 10 concurrent clients with 100 measured issuances (EC P-256, `:memory:` DB):

- Server overhead: ~100 KiB live (router tables, DB connection, CA state)
- Issuance growth: effectively zero — the server reaches steady-state after warmup
- Peak during issuances: ~0.5 MiB (10 concurrent in-flight requests)
- Allocation pressure: ~35 KiB per issuance (JWS signing buffers, JSON, TLS frames)

These figures confirm that Akāmu has a stable heap footprint at steady state.
There is no measurable per-issuance memory growth after warmup, which indicates
no request-scoped allocations are leaking into long-lived structures.
