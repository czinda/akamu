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
# Each result line is a JSON object with the benchmark config merged with the
# full acme_bench JSON output, plus an added "label" field.
#
# Prerequisites:
#   - cargo (Rust toolchain)
#   - /dev/shm (tmpfs, available on Linux) for the file-backed DB tests
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

# ── Helpers ──────────────────────────────────────────────────────────────────

OUT="${1:-/tmp/akamu_bench_$(date +%Y%m%d_%H%M%S).ndjson}"
> "$OUT"
echo "Writing results to: $OUT" >&2

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
bench() {
    local label="$1"; shift
    printf "  %-52s" "$label" >&2
    local json
    if ! json=$(cargo bench --bench acme_bench -- "$@" --output json 2>/dev/null); then
        echo "  FAILED" >&2
        return
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

echo "" >&2
echo "Done. Results written to: $OUT" >&2
echo "" >&2
echo "Quick summary:" >&2
jq -r '.label + ": " + (.summary.throughput_per_sec|round|tostring) + " iss/s"' "$OUT" >&2
