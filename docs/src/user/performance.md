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
|   1     |    120             |    8.3    |   13.1   |   1.1     |  0.8  |   3.7     |    2.4   |   0.3    |
|   5     |    818             |    6.1    |    8.0   |   0.6     |  0.5  |   2.8     |    1.8   |   0.3    |
|  10     |    854             |   11.5    |   13.9   |   1.2     |  1.1  |   4.3     |    4.1   |   0.8    |
|  25     |    889             |   27.5    |   36.3   |   3.2     |  3.2  |   8.1     |   11.1   |   1.9    |
|  50     |    681             |   67.0    |   80.5   |   7.5     |  7.0  |  20.1     |   26.6   |   5.7    |

Phase columns show mean milliseconds per ACME step.

Process mode peaks at c=5–10 (**975–1,098 iss/s**) with sub-9 ms mean
latency, driven by read-only pool separation, crypto caching, and
`spawn_blocking` for certificate signing.  Inprocess mode peaks at c=5–25
(**818–889 iss/s**).  Process mode shows lower download times (0.2 ms vs
1–6 ms) because certificate delivery bypasses the shared-process HTTP stack.
Inprocess mode shows higher authz and download overhead at high concurrency
due to Tokio task contention within the single runtime.

---

## Client key type

The client key type is the largest single determinant of per-issuance latency.
All runs use ec:P-256 CA; process mode uses 25 concurrent clients, inprocess
mode uses 50.

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
| ec:P-256     |    770             |   54.6    |   70.0   |   20.7        |  434 KB   |
| ed25519      |    742             |   54.1    |   72.8   |   20.2        |  432 KB   |
| ML-DSA-44    |    685             |   60.4    |   75.0   |   24.0        |  575 KB   |
| ML-DSA-65    |    589             |   69.9    |   98.8   |   30.0        |  624 KB   |
| ML-DSA-87    |    540             |   77.3    |   99.9   |   34.7        |  696 KB   |
| ec:P-384     |    487             |   85.7    |   97.3   |   46.3        |  438 KB   |
| rsa:2048     |    157             |  279.7    |  554.2   |  165.1        |  454 KB   |
| rsa:4096     |     15             | 2506.9    | 4099.1   | 1496.2        |  531 KB   |

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
|   1     |      3             |   357     |    922   |    353        |
|  10     |     14             |   651     |  2,817   |    647        |
|  25     |     14             | 1,340     |  4,501   |  1,155        |
|  50     |     13             | 2,804     |  4,441   |  1,749        |

Throughput saturates at ~13–15 iss/s regardless of concurrency or mode.  At
c=50, p99 reaches 4.4–4.8 seconds.  This is entirely client-side key
generation; the server is idle waiting for CSRs.

---

## CA key type

CA signing is server-side.  The CA key type directly affects the finalize
phase; other phases are unaffected.  All runs use ec:P-256 client keys;
process mode uses 25 concurrent clients, inprocess mode uses 50.

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
| ec:P-256   |    729             |   58.3    |   68.4   |   22.8        |
| ec:P-384   |    663             |   63.1    |   75.0   |   25.7        |
| rsa:2048   |    643             |   64.5    |   82.7   |   26.9        |
| rsa:3072   |    598             |   69.3    |   81.5   |   31.7        |
| rsa:4096   |    518             |   80.4    |   99.6   |   38.5        |

EC P-256 is the fastest CA key type and the recommended default.  In process
mode, RSA 2048 CA (466 iss/s) outperforms EC P-384 CA (307 iss/s) because
OpenSSL's RSA 2048 signing is faster than ECDSA P-384; in inprocess mode
RSA 2048 and EC P-384 are close (643 vs 663 iss/s).  RSA 4096 as CA reduces
throughput to 183–518 iss/s.

---

## Post-quantum chain

Akāmu supports ML-DSA (FIPS 204 / RFC 9881) CA keys at three NIST security
levels.  The table measures a full post-quantum chain (matching ML-DSA CA +
ML-DSA client keys, with `--verify-cert`) and compares to an ec:P-256
baseline.  Process mode uses 25 concurrent clients, inprocess mode uses 50.

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
| ec:P-256     |     —     |    730             |   56.0    |   68.2   |   21.9        |    —     |  438 KB   |
| ML-DSA-44    |     2     |    637             |   64.1    |   84.3   |   28.4        |  +14%    |  671 KB   |
| ML-DSA-65    |     3     |    551             |   75.6    |   89.5   |   32.3        |  +35%    |  770 KB   |
| ML-DSA-87    |     5     |    508             |   83.8    |   96.9   |   40.3        |  +50%    |  914 KB   |

ML-DSA-44 shows a smaller overhead in process mode (+52% vs +14% inprocess)
because the server's larger ML-DSA signature is generated out-of-process
without competing for the client's Tokio runtime.  Allocation pressure in
inprocess mode (671–914 KB) reflects both client and server heap usage;
process mode (257–385 KB) reflects client-side only.

ML-DSA requires OpenSSL 3.5 or later.  Akāmu will report a startup error if
the requested key type is unavailable on the installed OpenSSL version.

---

## Challenge type

All runs use ec:P-256 keys and SQLite `:memory:`; process mode uses 25
concurrent clients, inprocess mode uses 50.

### Process mode

| Challenge      | Throughput (iss/s) | Mean (ms) | p99 (ms) | Challenge phase (ms) |
|:---------------|-------------------:|----------:|---------:|---------------------:|
| http-01        |    615             |   31.0    |   71.1   |    9.6               |
| dns-persist-01 |    544             |   37.7    |   62.9   |   14.7               |

### Inprocess mode

| Challenge      | Throughput (iss/s) | Mean (ms) | p99 (ms) | Challenge phase (ms) |
|:---------------|-------------------:|----------:|---------:|---------------------:|
| http-01        |    746             |   57.3    |   65.3   |   17.7               |
| dns-persist-01 |    623             |   67.8    |   83.7   |   26.7               |

`dns-persist-01` adds 5–9 ms to the challenge phase, reducing throughput by
12–16% in both modes.  Both challenge types deliver zero errors across all
runs.

---

## Backend comparison

SQLite `:memory:` versus a tmpfs-backed WAL file (`/dev/shm`), sweeping
concurrency with ec:P-256 keys and http-01.  Inprocess mode only — process
mode always uses `:memory:`.  The tmpfs backend uses a write coalescer that
batches concurrent writes through a single connection, eliminating `BEGIN
IMMEDIATE` contention.

| Clients | :memory: (iss/s) | :memory: mean (ms) | tmpfs (iss/s) | tmpfs mean (ms) | Delta |
|--------:|-----------------:|-------------------:|--------------:|----------------:|------:|
|   1     |    114           |    8.7             |    110        |    9.1          |   −4% |
|   5     |    746           |    6.7             |    845        |    5.9          |  +13% |
|  10     |    836           |   11.8             |  1,112        |    8.9          |  +33% |
|  25     |    872           |   28.1             |  1,030        |   23.6          |  +18% |
|  50     |    747           |   60.6             |    910        |   48.7          |  +22% |
|  75     |    681           |   96.8             |    932        |   68.6          |  +37% |

With the write coalescer, tmpfs WAL **outperforms** `:memory:` at c≥5: the
coalescer serialises writes on a dedicated connection, avoiding contention
that `:memory:` still experiences through the pool.  Peak tmpfs throughput is
1,112 iss/s at c=10 versus 872 iss/s for `:memory:` at c=25.  Tmpfs WAL is
the recommended backend for deployments that need crash-recoverable state
without the complexity of PostgreSQL.

---

## Connection pool

Connection pool sizing affects throughput when multiple concurrent clients
contend for database reads.  The write coalescer handles all writes through a
dedicated connection, so the pool primarily serves read operations.  Inprocess
mode with tmpfs WAL backend — process mode ignores pool settings.

| Pool | c=1 (iss/s) | c=5 (iss/s) | c=10 (iss/s) | c=25 (iss/s) | c=50 (iss/s) |
|-----:|------------:|------------:|-------------:|-------------:|-------------:|
|    1 |    129      |    917      |   1,074      |   1,168      |     934      |
|    2 |    134      |    954      |   1,407      |   1,175      |   1,141      |
|    4 |    117      |    970      |   1,075      |   1,588      |   1,295      |
|    8 |    114      |    942      |   1,106      |   1,531      |   1,127      |

At c=1 pool size is irrelevant.  At c=25, pool=4 delivers the best throughput
(**1,588 iss/s**) — a **36% improvement** over pool=1 (1,168 iss/s).  Pool=4
is the recommended choice: it delivers the highest peak throughput while
maintaining reasonable p99 latency (22.8 ms at c=25).

Pool sizes above 4 show diminishing returns; pool=8 at c=25 reaches 1,531
iss/s (−4% vs pool=4) with slightly higher p99 variance.

---

## Read-only pool split

Splitting read-only handlers (get_order, get_authz, download_cert, star_cert,
renewal_info, ocsp) onto a separate `?mode=ro` connection pool frees the
write pool for write-path handlers.  Inprocess mode with tmpfs WAL — process
mode ignores pool settings.

| Clients | No split (iss/s) | Split ro=4 (iss/s) | Improvement |
|--------:|-----------------:|-------------------:|------------:|
|   1     |    113           |     110            |     −3%     |
|   5     |    894           |     990            |    +11%     |
|  10     |  1,253           |   1,154            |     −8%     |
|  25     |  1,197           |   1,548            |    +29%     |
|  50     |  1,009           |   1,430            |    +42%     |

The split delivers significant gains at c≥25 where read contention competes
with the write coalescer.  Peak improvement is **+42%** at c=50 (1,430 vs
1,009 iss/s).  At lower concurrency the overhead of managing a separate pool
can slightly reduce throughput.

### RO connection sweep at c=10

| ro-connections | Throughput (iss/s) | Mean (ms) | p99 (ms) |
|---------------:|-------------------:|----------:|---------:|
|   1            |  1,201             |    8.2    |   12.8   |
|   2            |  1,207             |    8.1    |   13.2   |
|   4            |  1,149             |    8.6    |   14.8   |
|   8            |  1,121             |    8.8    |   15.6   |
|  16            |  1,223             |    8.1    |   14.3   |

At c=10, all RO connection counts perform similarly (1,121–1,223 iss/s).
**ro=1 or ro=2 is the recommended setting** for typical deployments; higher
counts add connection overhead without meaningful throughput gain.

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

Single-node throughput for ec:P-256 keys, http-01:

| Target throughput | Configuration | Expected mean latency | Notes |
|:-----------------:|:--------------|:---------------------:|:------|
| ≤100 iss/s        | 1 client, pool=1   | ~9 ms            | Minimal deployment |
| ≤1,000 iss/s      | 5–10 clients       | 6–12 ms          | Sweet spot: low latency, high throughput |
| ≤1,200 iss/s      | 25 clients         | ~20 ms           | Near `:memory:` ceiling |
| ≤1,600 iss/s      | 25 clients, pool=4, tmpfs WAL | ~14 ms | Coalescer + pool tuning |

Figures assume ec:P-256 keys and http-01 challenge.  RSA or ML-DSA keys
lower throughput proportionally.

For the database backend: SQLite `:memory:` suits nodes with no persistent
state requirement (accounts, orders, and certificates are lost on restart).
Tmpfs WAL (`/dev/shm`) with the write coalescer outperforms `:memory:` under
concurrency (up to 1,588 iss/s vs ~889 iss/s) and provides crash-recoverable
state.  For persistent deployments, PostgreSQL is recommended; use a
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
| ec:P-256 CA + ec:P-256 client, c=1          | 416 KB             |
| ec:P-256 CA + ec:P-256 client, c=5          | 416 KB             |
| ec:P-256 CA + ec:P-256 client, c=10         | 417 KB             |
| ec:P-256 CA + ec:P-256 client, c=50         | 426 KB             |
| ec:P-256 CA + rsa:4096 client, c=50         | 531 KB             |
| ML-DSA-44 CA + ML-DSA-44 client, c=50       | 671 KB             |
| ML-DSA-65 CA + ML-DSA-65 client, c=50       | 770 KB             |
| ML-DSA-87 CA + ML-DSA-87 client, c=50       | 914 KB             |

The difference between modes (e.g. 416 KB − 134 KB = 282 KB for ec:P-256)
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
