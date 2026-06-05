# Performance

This chapter covers issuance throughput and latency characteristics of Akāmu
under load, with guidance on key type selection, connection pool tuning, and
capacity planning.

All numbers were collected on a single host — Intel Core i7-12800H (14 cores /
20 threads, 63 GB RAM, Fedora Linux 6.15, OpenSSL 3.5.6) — using the
`acme-bench` tool in two modes:

- **Process mode** (`--spawn process`): the server runs as a separate OS
  process with its own Tokio runtime, memory allocator, and SQLite `:memory:`
  database.  This matches how a real deployment behaves.  Heap allocation
  numbers reflect the client side only.
- **Inprocess mode** (default): server and clients share a single process.
  This mode enables SQLite backend, connection pool, and read-only pool split
  benchmarks that require shared-process access to the database layer.  Heap
  allocation numbers include both client and server.

Audit events are written to a JSONL file (`/tmp/akamu-bench-audit.jsonl`) in
both modes.

The benchmark runs full ACME workflows (new-order → authz → challenge validate
→ finalize → certificate download).  Latency is end-to-end wall time from
`new-order` through certificate download; account creation is amortised and
excluded.  Default configuration uses ec:P-256 client keys, ec:P-256 CA key,
and http-01 challenge.

The full benchmark suite can be run with
`contrib/performance/run_benchmarks.sh`, which writes newline-delimited JSON
results to a file for post-processing.  Set `SPAWN_MODE="--spawn process"` to
run the suite in process mode.

---

## Concurrency

With ec:P-256 certificates, http-01 validation, and SQLite `:memory:`,
throughput peaks at 5–10 concurrent clients in both modes and degrades
under higher concurrency as queue depth grows.

### Process mode

| Clients | Throughput (iss/s) | Mean (ms) | p99 (ms) | new_order | authz | challenge | finalize | download |
|--------:|-------------------:|----------:|---------:|----------:|------:|----------:|---------:|---------:|
|   1     |    100             |   10.2    |   13.7   |   1.3     |  1.0  |   4.3     |    3.4   |   0.4    |
|   5     |    975             |    5.0    |    6.3   |   0.6     |  0.4  |   2.6     |    1.2   |   0.2    |
|  10     |  1,098             |    8.7    |   14.7   |   1.6     |  0.6  |   4.0     |    2.2   |   0.3    |
|  25     |  1,208             |   19.0    |   24.3   |   4.6     |  0.5  |   8.2     |    5.4   |   0.3    |
|  50     |  1,015             |   34.5    |   73.7   |   9.2     |  0.5  |  17.7     |    6.9   |   0.2    |

### Inprocess mode

| Clients | Throughput (iss/s) | Mean (ms) | p99 (ms) | new_order | authz | challenge | finalize | download |
|--------:|-------------------:|----------:|---------:|----------:|------:|----------:|---------:|---------:|
|   1     |    107             |    9.4    |   14.9   |   1.2     |  0.9  |   4.0     |    2.9   |   0.3    |
|   5     |    696             |    7.1    |    9.7   |   0.7     |  0.6  |   3.1     |    2.2   |   0.4    |
|  10     |    686             |   14.3    |   20.4   |   1.6     |  1.4  |   5.0     |    5.0   |   1.3    |
|  25     |    676             |   33.1    |   42.4   |   3.8     |  3.4  |   8.3     |   14.2   |   3.3    |
|  50     |    592             |   74.0    |   95.6   |   8.4     |  7.2  |  22.5     |   28.3   |   7.4    |

Phase columns show mean milliseconds per ACME step.

Process mode peaks at c=5–10 (**975–1,098 iss/s**) with sub-9 ms mean
latency, driven by read-only pool separation, crypto caching, and
`spawn_blocking` for certificate signing.  Inprocess mode peaks at c=5–10
(**686–696 iss/s**).  Process mode shows lower download times (0.2 ms vs
1–7 ms) because certificate delivery bypasses the shared-process HTTP stack.
Inprocess mode shows higher authz and download overhead at high concurrency
due to Tokio task contention within the single runtime.

---

## Client key type

The client key type is the largest single determinant of per-issuance latency.
All runs use 25 concurrent clients and ec:P-256 CA.

### Process mode

| CSR key type | Throughput (iss/s) | Mean (ms) | p99 (ms) | Finalize (ms) | Alloc/iss |
|:-------------|-------------------:|----------:|---------:|--------------:|----------:|
| ed25519      |    561             |   33.0    |   69.1   |   14.2        |  166 KB   |
| ec:P-256     |    556             |   33.6    |   57.6   |   15.5        |  164 KB   |
| ML-DSA-44    |    523             |   37.9    |   66.8   |   17.2        |  243 KB   |
| ML-DSA-65    |    511             |   41.1    |   52.2   |   22.4        |  269 KB   |
| ML-DSA-87    |    418             |   45.5    |   88.5   |   23.0        |  313 KB   |
| ec:P-384     |    377             |   53.2    |   71.7   |   28.2        |  175 KB   |
| rsa:2048     |    153             |  124.0    |  266.8   |   88.9        |  166 KB   |
| rsa:4096     |     13             | 1156.6    | 2345.5   |  779.8        |  223 KB   |

### Inprocess mode

| CSR key type | Throughput (iss/s) | Mean (ms) | p99 (ms) | Finalize (ms) | Alloc/iss |
|:-------------|-------------------:|----------:|---------:|--------------:|----------:|
| ec:P-256     |    604             |   30.4    |   55.5   |   12.8        |  467 KB   |
| ML-DSA-44    |    482             |   42.2    |   55.4   |   17.8        |  611 KB   |
| ed25519      |    469             |   40.6    |   64.0   |   17.6        |  440 KB   |
| ML-DSA-65    |    422             |   43.1    |   77.8   |   19.7        |  635 KB   |
| ML-DSA-87    |    414             |   48.0    |   70.6   |   27.0        |  742 KB   |
| ec:P-384     |    354             |   55.8    |   75.3   |   32.0        |  473 KB   |
| rsa:2048     |    129             |  145.0    |  334.3   |  116.2        |  469 KB   |
| rsa:4096     |     11             | 1175.5    | 2187.9   | 1033.3        |  617 KB   |

In process mode ed25519 and ec:P-256 are effectively tied (~33 ms, 556–561
iss/s).  ML-DSA variants perform well: ML-DSA-44 at 523 iss/s is only 6%
slower than ec:P-256.  EC P-384 is consistently slower than ML-DSA-87 in both
modes due to its heavier finalize cost.

RSA 2048 is 3.6–4.7× slower than ec:P-256; RSA 4096 at ~1,160 ms mean is
dominated entirely by key generation.

**RSA 4096 is strongly discouraged for ACME clients in multi-client
deployments.**

---

## RSA 4096 saturation

RSA 4096 key generation is CPU-wall-limited.  Adding concurrency barely
improves throughput while latency grows linearly.

### Process mode

| Clients | Throughput (iss/s) | Mean (ms) | p99 (ms) | Finalize (ms) |
|--------:|-------------------:|----------:|---------:|--------------:|
|   1     |      3             |   375     |  1,215   |    370        |
|  10     |     13             |   691     |  2,292   |    666        |
|  25     |     15             | 1,334     |  3,463   |  1,068        |
|  50     |     15             | 2,417     |  4,831   |  1,283        |

### Inprocess mode

| Clients | Throughput (iss/s) | Mean (ms) | p99 (ms) | Finalize (ms) |
|--------:|-------------------:|----------:|---------:|--------------:|
|   1     |      3             |   407     |  1,341   |    403        |
|  10     |     11             |   695     |  2,033   |    690        |
|  25     |     14             | 1,443     |  3,433   |  1,219        |
|  50     |     14             | 2,623     |  4,730   |  1,601        |

Throughput saturates at ~14–15 iss/s regardless of concurrency or mode.  At
c=50, p99 reaches 4.7–4.8 seconds.  This is entirely client-side key
generation; the server is idle waiting for CSRs.

---

## CA key type

CA signing is server-side.  The CA key type directly affects the finalize
phase; other phases are unaffected.  All runs use 25 concurrent clients and
ec:P-256 client keys.

### Process mode

| CA key     | Throughput (iss/s) | Mean (ms) | p99 (ms) | Finalize (ms) |
|:-----------|-------------------:|----------:|---------:|--------------:|
| ec:P-256   |    624             |   31.0    |   48.5   |   14.9        |
| rsa:2048   |    466             |   42.7    |   61.4   |   25.5        |
| ec:P-384   |    307             |   66.3    |   95.9   |   38.5        |
| rsa:3072   |    266             |   76.0    |   94.1   |   49.2        |
| rsa:4096   |    183             |  116.5    |  165.8   |   89.9        |

### Inprocess mode

| CA key     | Throughput (iss/s) | Mean (ms) | p99 (ms) | Finalize (ms) |
|:-----------|-------------------:|----------:|---------:|--------------:|
| ec:P-256   |    513             |   36.4    |   61.4   |   14.4        |
| ec:P-384   |    344             |   54.5    |   91.1   |   30.4        |
| rsa:2048   |    335             |   55.6    |   81.3   |   29.9        |
| rsa:3072   |    238             |   86.8    |   99.3   |   62.1        |
| rsa:4096   |    154             |  134.0    |  154.9   |  105.8        |

EC P-256 is the fastest CA key type and the recommended default.  In process
mode, RSA 2048 CA (466 iss/s) outperforms EC P-384 CA (307 iss/s) because
OpenSSL's RSA 2048 signing is faster than ECDSA P-384; in inprocess mode the
gap narrows due to shared-runtime contention.  RSA 4096 as CA reduces
throughput to 154–183 iss/s (3.4–3.3× penalty vs ec:P-256).

---

## Post-quantum chain

Akāmu supports ML-DSA (FIPS 204 / RFC 9881) CA keys at three NIST security
levels.  The table measures a full post-quantum chain (matching ML-DSA CA +
ML-DSA client keys, with `--verify-cert`) and compares to an ec:P-256
baseline.  All runs use 25 concurrent clients.

### Process mode

| CA + client  | NIST cat. | Throughput (iss/s) | Mean (ms) | p99 (ms) | Finalize (ms) | vs P-256 | Alloc/iss |
|:-------------|:---------:|-------------------:|----------:|---------:|--------------:|---------:|----------:|
| ec:P-256     |     —     |    526             |   36.7    |   70.0   |   16.0        |    —     |  170 KB   |
| ML-DSA-44    |     2     |    362             |   55.7    |   75.1   |   34.6        |  +52%    |  257 KB   |
| ML-DSA-65    |     3     |    298             |   68.6    |   86.0   |   46.0        |  +87%    |  312 KB   |
| ML-DSA-87    |     5     |    250             |   80.5    |  105.8   |   56.6        | +119%    |  385 KB   |

### Inprocess mode

| CA + client  | NIST cat. | Throughput (iss/s) | Mean (ms) | p99 (ms) | Finalize (ms) | vs P-256 | Alloc/iss |
|:-------------|:---------:|-------------------:|----------:|---------:|--------------:|---------:|----------:|
| ec:P-256     |     —     |    516             |   36.0    |   55.3   |   14.1        |    —     |  464 KB   |
| ML-DSA-44    |     2     |    289             |   67.2    |  118.2   |   35.9        |  +87%    |  714 KB   |
| ML-DSA-65    |     3     |    267             |   74.0    |  110.2   |   46.2        | +106%    |  815 KB   |
| ML-DSA-87    |     5     |    249             |   80.7    |  102.8   |   54.3        | +124%    |  968 KB   |

ML-DSA-44 shows a smaller overhead in process mode (+52% vs +87%) because the
server's larger ML-DSA signature is generated out-of-process without competing
for the client's Tokio runtime.  Allocation pressure in inprocess mode
(714–968 KB) reflects both client and server heap usage; process mode
(257–385 KB) reflects client-side only.

ML-DSA requires OpenSSL 3.5 or later.  Akāmu will report a startup error if
the requested key type is unavailable on the installed OpenSSL version.

---

## Challenge type

All runs use 25 concurrent clients, ec:P-256 keys, SQLite `:memory:`.

### Process mode

| Challenge      | Throughput (iss/s) | Mean (ms) | p99 (ms) | Challenge phase (ms) |
|:---------------|-------------------:|----------:|---------:|---------------------:|
| http-01        |    615             |   31.0    |   71.1   |    9.6               |
| dns-persist-01 |    544             |   37.7    |   62.9   |   14.7               |

### Inprocess mode

| Challenge      | Throughput (iss/s) | Mean (ms) | p99 (ms) | Challenge phase (ms) |
|:---------------|-------------------:|----------:|---------:|---------------------:|
| http-01        |    519             |   36.5    |   83.4   |    9.4               |
| dns-persist-01 |    447             |   47.9    |   55.4   |   17.6               |

`dns-persist-01` adds 5–8 ms to the challenge phase, reducing throughput by
12–14% in both modes.  Both challenge types deliver zero errors across all
runs.

---

## Backend comparison

SQLite `:memory:` versus a tmpfs-backed WAL file (`/dev/shm`), sweeping
concurrency with ec:P-256 keys and http-01.  Inprocess mode only — process
mode always uses `:memory:`.

| Clients | :memory: (iss/s) | :memory: mean (ms) | tmpfs (iss/s) | tmpfs mean (ms) | Overhead |
|--------:|-----------------:|-------------------:|--------------:|----------------:|---------:|
|   1     |    107           |    9.3             |    100        |   10.0          |   −7%    |
|   5     |    651           |    7.6             |    599        |    8.3          |   −8%    |
|  10     |    698           |   14.2             |    682        |   14.5          |   −2%    |
|  25     |    651           |   33.1             |    588        |   37.0          |  −10%    |
|  50     |    597           |   71.5             |    561        |   75.6          |   −6%    |

Tmpfs WAL is within 6–10% of `:memory:` at all concurrency levels.  The
overhead comes from WAL write and fsync, not from read amplification.  Tmpfs
WAL is a viable choice for deployments that need crash-recoverable state
without the complexity of PostgreSQL.

---

## Connection pool

Connection pool sizing affects throughput when multiple concurrent clients
contend for database writes.  Inprocess mode with tmpfs WAL backend — process
mode ignores pool settings.

| Pool | c=1 (iss/s) | c=5 (iss/s) | c=10 (iss/s) | c=25 (iss/s) | c=50 (iss/s) |
|-----:|------------:|------------:|-------------:|-------------:|-------------:|
|    1 |    104      |    561      |     635      |     544      |     499      |
|    2 |    105      |    755      |     799      |     656      |     640      |
|    4 |    102      |    670      |     916      |     731      |     704      |
|    8 |    103      |    587      |     837      |     651      |     676      |

At c=1 pool size is irrelevant.  At c=10, pool=4 delivers the best throughput
(916 iss/s) — a **44% improvement** over pool=1 (635 iss/s).  Pool=2 is the
best all-round choice: it delivers strong gains at every concurrency level
without the p99 tail-latency spikes that appear at pool=8 under moderate load.

Pool sizes above 4 show diminishing returns and increased p99 variance as
SQLite's single-writer constraint causes contention on `BEGIN IMMEDIATE`.

---

## Read-only pool split

Splitting read-only handlers (get_order, get_authz, download_cert, star_cert,
renewal_info, ocsp) onto a separate `?mode=ro` connection pool frees the write
connection for write-path handlers.  Inprocess mode with tmpfs WAL — process
mode ignores pool settings.

| Clients | No split (iss/s) | Split ro=4 (iss/s) | Improvement |
|--------:|-----------------:|-------------------:|------------:|
|   1     |    108           |     111            |     +3%     |
|   5     |    628           |     830            |    +32%     |
|  10     |    606           |     866            |    +43%     |
|  25     |    603           |     723            |    +20%     |
|  50     |    562           |     661            |    +18%     |

The split delivers significant gains at c≥5.  Peak improvement is **+43%** at
c=10 (866 vs 606 iss/s).  Even at c=50 the split adds 18%.

### RO connection sweep at c=10

| ro-connections | Throughput (iss/s) | Mean (ms) | p99 (ms) |
|---------------:|-------------------:|----------:|---------:|
|   1            |    898             |   10.9    |   15.4   |
|   2            |    869             |   11.2    |   15.6   |
|   4            |    872             |   11.3    |   15.3   |
|   8            |    845             |   11.4    |   18.6   |
|  16            |    719             |   13.5    |   17.7   |

At c=10, even a single RO connection (ro=1) captures most of the benefit
(898 iss/s).  Beyond ro=4, connection overhead starts to reduce throughput.
**ro=1 or ro=2 is the recommended setting** for typical deployments.

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

## Capacity planning

Single-node throughput for ec:P-256 keys, http-01, SQLite `:memory:`:

| Target throughput | Configuration | Expected mean latency | Notes |
|:-----------------:|:--------------|:---------------------:|:------|
| ≤100 iss/s        | 1 client, pool=1   | ~10 ms           | Minimal deployment |
| ≤1,000 iss/s      | 5–10 clients       | 5–9 ms           | Sweet spot: low latency, high throughput |
| ≤1,200 iss/s      | 25 clients         | ~19 ms           | Near single-writer ceiling |
| ≤900 iss/s        | 10 clients, pool=4, ro=1 | ~11 ms    | RO split + pool tuning (inprocess) |

Figures assume ec:P-256 keys, http-01 challenge, and SQLite `:memory:`.
RSA or ML-DSA keys lower throughput proportionally.

For the database backend: SQLite `:memory:` suits nodes with no persistent
state requirement (accounts, orders, and certificates are lost on restart).
Tmpfs WAL (`/dev/shm`) provides crash-recoverable state with only 6–10%
overhead.  For persistent deployments, PostgreSQL is recommended; use a
connection pool of 20–25 (`[database] pool_connections = 25`).

---

## Memory

The benchmark instruments heap allocation using a custom `GlobalAlloc` wrapper.
Per-issuance allocation pressure — bytes requested from the system allocator
per certificate, including memory subsequently freed — varies by configuration
and mode.

In process mode, allocation reflects the client side only (server runs in a
separate process); in inprocess mode it includes both client and server.

### Process mode (client-side allocation)

| Configuration                               | Per-issuance alloc |
|:--------------------------------------------|:------------------:|
| ec:P-256 CA + ec:P-256 client, c=1          | 134 KB             |
| ec:P-256 CA + ec:P-256 client, c=5          | 134 KB             |
| ec:P-256 CA + ec:P-256 client, c=10         | 137 KB             |
| ec:P-256 CA + ec:P-256 client, c=50         | 190 KB             |
| ec:P-256 CA + rsa:4096 client, c=25         | 223 KB             |
| ML-DSA-44 CA + ML-DSA-44 client, c=25       | 257 KB             |
| ML-DSA-65 CA + ML-DSA-65 client, c=25       | 312 KB             |
| ML-DSA-87 CA + ML-DSA-87 client, c=25       | 385 KB             |

### Inprocess mode (client + server allocation)

| Configuration                               | Per-issuance alloc |
|:--------------------------------------------|:------------------:|
| ec:P-256 CA + ec:P-256 client, c=1          | 412 KB             |
| ec:P-256 CA + ec:P-256 client, c=5          | 412 KB             |
| ec:P-256 CA + ec:P-256 client, c=10         | 414 KB             |
| ec:P-256 CA + ec:P-256 client, c=50         | 432 KB             |
| ec:P-256 CA + rsa:4096 client, c=25         | 617 KB             |
| ML-DSA-44 CA + ML-DSA-44 client, c=25       | 714 KB             |
| ML-DSA-65 CA + ML-DSA-65 client, c=25       | 815 KB             |
| ML-DSA-87 CA + ML-DSA-87 client, c=25       | 968 KB             |

The difference between modes (e.g. 412 KB − 134 KB = 278 KB for ec:P-256)
represents the server-side allocation per issuance: certificate construction,
DER encoding, audit logging, and database writes.

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

### Full suite

The benchmark suite script runs all configurations and writes
newline-delimited JSON results:

```bash
cargo build --release

# Inprocess mode (default)
contrib/performance/run_benchmarks.sh [OUTPUT_FILE]

# Process mode
SPAWN_MODE="--spawn process" contrib/performance/run_benchmarks.sh [OUTPUT_FILE]
```

Post-processing examples:

```bash
# Print throughput for all runs
jq -r '.label + ": " + (.summary.throughput_per_sec|round|tostring) + " iss/s"' results.ndjson

# Extract concurrency scaling table
jq 'select(.label | startswith("concurrency_"))
    | [.label, .summary.throughput_per_sec,
       .summary.total_latency_ms.mean, .summary.total_latency_ms.p95]' results.ndjson
```

### Individual runs

```bash
cargo build --release

# Concurrency sweep (process mode)
for c in 1 5 10 25 50; do
  cargo bench --bench acme_bench -- --spawn process --clients $c --requests 300 --warmup 20
done

# Key type comparison at c=25
for kt in ec:P-256 ec:P-384 ed25519 rsa:2048 ml-dsa-44; do
  cargo bench --bench acme_bench -- --spawn process --clients 25 --key-type $kt --requests 100
done

# CA key type comparison
for cakt in ec:P-256 ec:P-384 rsa:2048 rsa:4096; do
  cargo bench --bench acme_bench -- --spawn process --clients 25 --ca-key-type $cakt --requests 100
done

# Post-quantum full chain with verification
cargo bench --bench acme_bench -- \
  --spawn process --clients 25 --ca-key-type ml-dsa-44 --key-type ml-dsa-44 --verify-cert

# Challenge type comparison
cargo bench --bench acme_bench -- --spawn process --clients 25 --challenge dns-persist-01

# Backend comparison (inprocess mode, tmpfs WAL)
cargo bench --bench acme_bench -- --clients 10 --db "sqlite:///dev/shm/bench.db" --requests 300

# RO pool split (inprocess mode)
cargo bench --bench acme_bench -- \
  --clients 10 --db "sqlite:///dev/shm/bench.db" --ro-connections 4 --requests 300

# JSON output for scripting
cargo bench --bench acme_bench -- --spawn process --clients 25 --requests 100 --output json | jq .summary
```

### Available options

| Option | Default | Description |
|:-------|:--------|:------------|
| `--spawn MODE` | `inprocess` | `inprocess` or `process`; `process` starts separate OS processes |
| `--nodes N` | 1 | Number of akamu nodes in the cluster |
| `--clients N` | 10 | Concurrent worker tasks |
| `--requests N` | 100 | Issuances to measure (warmup not counted) |
| `--warmup N` | 10 | Warmup issuances discarded before measurement |
| `--challenge TYPE` | `http-01` | `http-01` or `dns-persist-01` |
| `--key-type TYPE` | `ec:P-256` | CSR key type (see table above) |
| `--ca-key-type TYPE` | `ec:P-256` | CA key type (same syntax) |
| `--topology MODE` | `direct` | `direct` (round-robin) or `proxy` (single-node proxy) |
| `--no-gossip` | off | Disable gossip in multi-node runs |
| `--db PATH` | `:memory:` | SQLite URL or PostgreSQL connection string |
| `--pool-connections N` | `1` | Write connection pool size |
| `--ro-connections N` | 0 | Read-only connection pool size (0 = no split) |
| `--wildcard` | off | Issue `*.bench-N.acme-bench.test` (dns-persist-01 only) |
| `--output FORMAT` | `text` | `text` or `json` |
| `--verify-cert` | off | Parse and verify the SAN of every issued certificate |
| `--poll-ms N` | 100 | Challenge poll interval in milliseconds |
