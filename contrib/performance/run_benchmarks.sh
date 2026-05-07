#!/usr/bin/env bash
# run_benchmarks.sh — Akāmu full performance benchmark suite
#
# Runs all benchmark configurations documented in docs/src/user/performance.md
# and writes results to a newline-delimited JSON file (one JSON object per line).
#
# Usage:
#   contrib/performance/run_benchmarks.sh [OUTPUT_FILE]
#
# Default output file: /tmp/akamu_bench_$(date +%Y%m%d_%H%M%S).ndjson
#
# Environment variables:
#   BENCH_EXE   Path to a pre-built acme_bench binary.  When set the script
#               runs it directly instead of compiling via `cargo bench`.
#               Useful for running benchmarks on machines without a Rust
#               toolchain, or for comparing two pre-built binaries.
#               Example:
#                 BENCH_EXE=/tmp/acme_bench contrib/performance/run_benchmarks.sh
#
#   PG_URL      PostgreSQL connection URL.  When set every bench run uses this
#               database instead of sqlite::memory:.  Sections 7–9 (SQLite WAL,
#               pool, and RO-split) are skipped because they are SQLite-specific.
#               When using `cargo bench` (no BENCH_EXE), --features backend-postgres
#               is added automatically.
#               Example:
#                 PG_URL=postgres://user:pass@localhost/bench \
#                   contrib/performance/run_benchmarks.sh
#
#   PG_POOL     PostgreSQL connection pool size forwarded as --pool-connections.
#               Defaults to 20.  Ignored when PG_URL is not set.
#
#   SQLITE_URL  SQLite connection URL used for sections 1–6 when PG_URL is not
#               set.  Sections 7–9 always create their own /dev/shm temp files
#               regardless of this setting.  The database file is NOT deleted
#               automatically; callers should remove it after the run.
#               Example:
#                 DB=/dev/shm/akamu_bench.db
#                 SQLITE_URL="sqlite://$DB" \
#                   contrib/performance/run_benchmarks.sh
#                 rm -f "$DB" "$DB-wal" "$DB-shm"
#
#   BENCH_RESET When set to any non-empty value and PG_URL is set, all ACME
#               tables are truncated (RESTART IDENTITY CASCADE) before section 1
#               runs.  This eliminates the row-accumulation artifact that makes
#               later sections appear slower when an old benchmark left rows
#               behind in a persistent database.
#               Example:
#                 BENCH_RESET=1 PG_URL=postgres://user:pass@localhost/bench \
#                   contrib/performance/run_benchmarks.sh
#
# Each result line is a JSON object with the benchmark config merged with the
# full acme_bench JSON output, plus an added "label" field.
#
# Prerequisites:
#   - cargo (Rust toolchain) — not required when BENCH_EXE is set
#   - psql (PostgreSQL client) — required only when BENCH_RESET is set
#   - /dev/shm (tmpfs, available on Linux) for the file-backed DB tests
#     (sections 7–9; skipped when PG_URL is set)
#
# Post-processing (examples):
#   # Print throughput for all runs
#   jq -r '.label + ": " + (.summary.throughput_per_sec|round|tostring) + " iss/s"' results.ndjson
#
#   # Extract a specific table (concurrency scaling)
#   jq 'select(.label | startswith("concurrency_"))
#       | [.label, .summary.throughput_per_sec,
#          .summary.total_latency_ms.mean, .summary.total_latency_ms.p95]' results.ndjson
#
# Notes:
#   - RSA 4096 runs use fewer issuances (30 measured + 5 warmup) to keep
#     the total run time reasonable; all other runs use 100 or 300 issuances.
#   - ML-DSA requires OpenSSL 3.5 or later.  The script aborts with an error
#     if OpenSSL < 3.5 is detected.
#   - The pool/RO-split comparison sections create and delete temporary database
#     files under /dev/shm.
#   - Section 9 measures the WAL read-only pool split: pure-read handlers
#     (get_order, get_authz, download_cert, star_cert, renewal_info, ocsp) are
#     served by a separate ?mode=ro pool, freeing the single write connection
#     for write-path handlers only.

set -euo pipefail

export LANG=C

# ── Configuration ─────────────────────────────────────────────────────────────

# Pre-built benchmark binary.  Empty = compile via cargo bench.
BENCH_EXE="${BENCH_EXE:-}"

# PostgreSQL URL.  Empty = use sqlite::memory:.
PG_URL="${PG_URL:-}"

# Pool size used for every PostgreSQL run (ignored for SQLite).
PG_POOL="${PG_POOL:-20}"

# SQLite URL for sections 1–6.  Empty = binary default (sqlite::memory:).
SQLITE_URL="${SQLITE_URL:-}"

# When non-empty and PG_URL is set, truncate all ACME tables before section 1.
BENCH_RESET="${BENCH_RESET:-}"

# ── Validate ──────────────────────────────────────────────────────────────────

if [[ -n "$BENCH_EXE" ]] && [[ ! -x "$BENCH_EXE" ]]; then
    echo "error: BENCH_EXE='$BENCH_EXE' is not executable" >&2
    exit 1
fi

if [[ -z "$BENCH_EXE" ]] && ! command -v cargo &>/dev/null; then
    echo "error: cargo not found and BENCH_EXE is not set" >&2
    exit 1
fi

# ── Helpers ──────────────────────────────────────────────────────────────────

OUT="${1:-/tmp/akamu_bench_$(date +%Y%m%d_%H%M%S).ndjson}"
> "$OUT"
echo "Writing results to: $OUT" >&2

if [[ -n "$BENCH_EXE" ]]; then
    echo "Using pre-built binary: $BENCH_EXE" >&2
else
    echo "Using: cargo bench" >&2
fi
if [[ -n "$PG_URL" ]]; then
    reset_note=""
    [[ -n "$BENCH_RESET" ]] && reset_note=", reset=yes"
    echo "Database: PostgreSQL (pool=$PG_POOL${reset_note}, sections 7–9 skipped)" >&2
elif [[ -n "$SQLITE_URL" ]]; then
    echo "Database: SQLite $SQLITE_URL (sections 7–9 use own /dev/shm temp files)" >&2
else
    echo "Database: sqlite::memory: (sections 7–9 included)" >&2
fi

# Truncate all ACME transactional tables so each benchmark run starts from a
# known-empty state.  Without this, rows accumulated by a previous run slow
# later sections (larger seq scans, more index pages) and make comparisons
# between runs misleading.
reset_pg_db() {
    echo "Resetting PostgreSQL benchmark database…" >&2
    psql "$PG_URL" -q -c "
        TRUNCATE
            challenges,
            mtc_cosignatures,
            cross_certs,
            mtc_landmarks,
            mtc_checkpoints,
            certificates,
            authorizations,
            orders,
            eab_keys,
            accounts,
            nonces,
            audit_events
        RESTART IDENTITY CASCADE;
    " 2>&1 | sed 's/^/  /' >&2
    # Force a checkpoint immediately so the next automatic checkpoint is pushed
    # 5 minutes into the future from a clean state.  Without this a checkpoint
    # can fire mid-benchmark (during §5–§6) and cause uniform phase slowdowns.
    # Requires the pg_checkpoint role; skipped with a warning if not granted.
    if ! psql "$PG_URL" -q -c "CHECKPOINT;" 2>/dev/null; then
        echo "  (warning: CHECKPOINT skipped — no pg_checkpoint privilege;" >&2
        echo "   run as superuser: GRANT pg_checkpoint TO <bench-user>;)" >&2
    fi
    echo "Database reset complete." >&2
}

check_openssl_version() {
    local ver
    ver=$(openssl version | awk '{print $2}')
    local major minor
    major=$(echo "$ver" | cut -d. -f1)
    minor=$(echo "$ver" | cut -d. -f2)
    if [ "$major" -lt 3 ] || { [ "$major" -eq 3 ] && [ "$minor" -lt 5 ]; }; then
        echo "WARNING: OpenSSL $ver detected — ML-DSA benchmarks require OpenSSL 3.5+." >&2
        echo "         ML-DSA runs will fail; all other sections will still complete." >&2
    fi
}

# Run one benchmark, write result JSON to $OUT, print a summary line to stderr.
#
# When BENCH_EXE is set the binary is invoked directly; otherwise `cargo bench`
# compiles and runs the benchmark.  PG_URL and PG_POOL are injected
# automatically when set.
bench() {
    local label="$1"; shift
    printf "  %-52s" "$label" >&2

    # Extra args injected for the configured database backend.
    # Suppressed when the per-bench call already carries --db (sections 7–9
    # pass their own temp-file path); the bench binary rejects duplicate flags.
    local db_args=()
    local has_db=0
    local a; for a in "$@"; do [[ "$a" == "--db" ]] && has_db=1; done
    if [[ $has_db -eq 0 ]]; then
        if [[ -n "$PG_URL" ]]; then
            db_args=(--db "$PG_URL" --pool-connections "$PG_POOL")
        elif [[ -n "$SQLITE_URL" ]]; then
            db_args=(--db "$SQLITE_URL")
        fi
    fi

    local json
    if [[ -n "$BENCH_EXE" ]]; then
        if ! json=$("$BENCH_EXE" "${db_args[@]}" "$@" --output json 2>/dev/null); then
            echo "  FAILED" >&2
            return
        fi
    else
        local cargo_features=()
        [[ -n "$PG_URL" ]] && cargo_features=(--features backend-postgres)
        if ! json=$(cargo bench "${cargo_features[@]}" --bench acme_bench -- \
                        "${db_args[@]}" "$@" --output json 2>/dev/null); then
            echo "  FAILED" >&2
            return
        fi
    fi

    printf "%s\n" "$json" | jq --arg lbl "$label" '{label: $lbl} + .' >> "$OUT"
    local thr mean p95 fin alloc
    thr=$(printf "%s\n"  "$json" | jq '.summary.throughput_per_sec  | round')
    mean=$(printf "%s\n" "$json" | jq '(.summary.total_latency_ms.mean * 10 | round) / 10')
    p95=$(printf "%s\n"  "$json" | jq '(.summary.total_latency_ms.p95  * 10 | round) / 10')
    fin=$(printf "%s\n"  "$json" | jq '(.phases.finalize_ms           * 10 | round) / 10')
    alloc=$(printf "%s\n" "$json" | jq '(.memory.per_issuance_alloc_bytes / 1024 * 10 | round) / 10')
    printf "thr=%5d  mean=%6.1f ms  p95=%6.1f ms  fin=%5.1f ms  alloc=%6.1f KiB\n" \
        "$thr" "$mean" "$p95" "$fin" "$alloc" >&2
}

POLL=5

check_openssl_version
[[ -n "$BENCH_RESET" && -n "$PG_URL" ]] && reset_pg_db

# ── Section 1: Concurrency scaling ───────────────────────────────────────────
# EC P-256 leaf + CA, http-01, :memory:, 300 measured + 20 warmup

echo "" >&2
echo "=== 1. Concurrency scaling (ec:P-256, http-01, :memory:, 300 req) ===" >&2
for n in 1 5 10 25 50; do
    bench "concurrency_${n}" \
        --clients "$n" --requests 300 --warmup 20 --poll-ms "$POLL"
done

# ── Section 2: Key type comparison ───────────────────────────────────────────
# 25 concurrent clients, EC P-256 CA, :memory:

echo "" >&2
echo "=== 2. Key type comparison (25 clients, ec:P-256 CA, :memory:) ===" >&2
for kt in ec:P-256 ed25519 ec:P-384 ml-dsa-44 ml-dsa-65 ml-dsa-87 rsa:2048; do
    bench "keytype_${kt//:/}" \
        --clients 25 --requests 100 --warmup 10 --poll-ms "$POLL" \
        --key-type "$kt"
done
# rsa:4096 uses fewer issuances — generation time dominates
bench "keytype_rsa4096" \
    --clients 25 --requests 30 --warmup 5 --poll-ms "$POLL" \
    --key-type rsa:4096

# ── Section 3: RSA 4096 saturation ───────────────────────────────────────────
# Sweep concurrency with rsa:4096 leaf + ec:P-256 CA

echo "" >&2
echo "=== 3. RSA 4096 saturation ===" >&2
for n in 1 10 25 50; do
    bench "rsa4096_sat_${n}" \
        --clients "$n" --requests 100 --warmup 10 --poll-ms "$POLL" \
        --key-type rsa:4096
done

# ── Section 4: Post-quantum full chain ───────────────────────────────────────
# Matching ML-DSA CA + ML-DSA leaf, --verify-cert, 25 clients

echo "" >&2
echo "=== 4. Post-quantum full chain (25 clients, verify-cert) ===" >&2
for pq in ml-dsa-44 ml-dsa-65 ml-dsa-87; do
    bench "pq_chain_${pq}" \
        --clients 25 --requests 100 --warmup 10 --poll-ms "$POLL" \
        --ca-key-type "$pq" --key-type "$pq" --verify-cert
done
bench "pq_chain_ec256_baseline" \
    --clients 25 --requests 100 --warmup 10 --poll-ms "$POLL" \
    --ca-key-type ec:P-256 --key-type ec:P-256 --verify-cert

# ── Section 5: CA key type impact ────────────────────────────────────────────
# ec:P-256 leaf, varying CA key type, 25 clients

echo "" >&2
echo "=== 5. CA key type impact (25 clients, ec:P-256 leaf) ===" >&2
for cakt in ec:P-256 ec:P-384 rsa:2048 rsa:3072; do
    bench "ca_keytype_${cakt//:/}" \
        --clients 25 --requests 100 --warmup 10 --poll-ms "$POLL" \
        --ca-key-type "$cakt"
done
bench "ca_keytype_rsa4096" \
    --clients 25 --requests 100 --warmup 10 --poll-ms "$POLL" \
    --ca-key-type rsa:4096

# ── Section 6: Challenge type comparison ─────────────────────────────────────
# 25 clients, ec:P-256, :memory:

echo "" >&2
echo "=== 6. Challenge type comparison (25 clients, ec:P-256, :memory:) ===" >&2
bench "challenge_http01" \
    --clients 25 --requests 200 --warmup 20 --poll-ms "$POLL" \
    --challenge http-01
bench "challenge_dns_persist" \
    --clients 25 --requests 200 --warmup 20 --poll-ms "$POLL" \
    --challenge dns-persist-01

# ── Sections 7–9: SQLite-specific (skipped when PG_URL is set) ───────────────

if [[ -z "$PG_URL" ]]; then

# ── Section 7: Backend comparison (:memory: vs tmpfs WAL) ────────────────────
# EC P-256, sweep concurrency

echo "" >&2
echo "=== 7. Backend comparison (:memory: vs tmpfs WAL) ===" >&2
for n in 1 5 10 25 50; do
    bench "backend_mem_${n}" \
        --clients "$n" --requests 300 --warmup 20 --poll-ms "$POLL"

    TMPDB=$(mktemp /dev/shm/akamu_bench_XXXXXX.db)
    bench "backend_tmpfs_${n}" \
        --clients "$n" --requests 300 --warmup 20 --poll-ms "$POLL" \
        --db "sqlite://$TMPDB"
    rm -f "$TMPDB" "${TMPDB}-wal" "${TMPDB}-shm"
done

# ── Section 8: Pool comparison (BEGIN IMMEDIATE, tmpfs WAL) ──────────────────
# pool-connections 1/2/4/8 × clients 1/5/10/25/50, 200 measured + 20 warmup

echo "" >&2
echo "=== 8. Pool comparison (BEGIN IMMEDIATE, tmpfs WAL) ===" >&2
for p in 1 2 4 8; do
    for n in 1 5 10 25 50; do
        POOLDB=$(mktemp /dev/shm/akamu_bench_pool_XXXXXX.db)
        bench "pool_${p}_clients_${n}" \
            --clients "$n" --requests 200 --warmup 20 --poll-ms "$POLL" \
            --db "sqlite://$POOLDB" --pool-connections "$p"
        rm -f "$POOLDB" "${POOLDB}-wal" "${POOLDB}-shm"
    done
done

# ── Section 9: Read-only pool split (tmpfs WAL) ──────────────────────────────
# Compare tmpfs WAL with and without --ro-connections across concurrency levels,
# then sweep ro-connections count at the peak concurrency to find the sweet spot.

echo "" >&2
echo "=== 9. RO pool split comparison (tmpfs WAL, ec:P-256, 300 req) ===" >&2

echo "  --- 9a. no split vs split (ro=4) across concurrency ---" >&2
for n in 1 5 10 25 50; do
    RODB=$(mktemp /dev/shm/akamu_bench_ro_XXXXXX.db)
    bench "ro_nosplit_${n}" \
        --clients "$n" --requests 300 --warmup 20 --poll-ms "$POLL" \
        --db "sqlite://$RODB"
    rm -f "$RODB" "${RODB}-wal" "${RODB}-shm"

    RODB=$(mktemp /dev/shm/akamu_bench_ro_XXXXXX.db)
    bench "ro_split4_${n}" \
        --clients "$n" --requests 300 --warmup 20 --poll-ms "$POLL" \
        --db "sqlite://$RODB" --ro-connections 4
    rm -f "$RODB" "${RODB}-wal" "${RODB}-shm"
done

echo "  --- 9b. ro-connections sweep at c=10 ---" >&2
for ro in 1 2 4 8 16; do
    RODB=$(mktemp /dev/shm/akamu_bench_ro_XXXXXX.db)
    bench "ro_sweep_ro${ro}" \
        --clients 10 --requests 300 --warmup 20 --poll-ms "$POLL" \
        --db "sqlite://$RODB" --ro-connections "$ro"
    rm -f "$RODB" "${RODB}-wal" "${RODB}-shm"
done

else
    echo "" >&2
    echo "=== 7–9. Skipped (SQLite-only; PG_URL is set) ===" >&2
fi

echo "" >&2
echo "Done. Results written to: $OUT" >&2
echo "" >&2
echo "Quick summary:" >&2
jq -r '.label + ": " + (.summary.throughput_per_sec|round|tostring) + " iss/s"' "$OUT" >&2
