#!/usr/bin/env bash
# run_cluster_benchmarks.sh — Akāmu multi-node cluster performance sweep
#
# Measures performance across every clustering axis and writes results to a
# newline-delimited JSON file (one object per run, same format as
# run_benchmarks.sh so the two files can be combined or processed uniformly).
#
# Usage:
#   contrib/performance/run_cluster_benchmarks.sh [OUTPUT_FILE]
#
# Default output: /tmp/akamu_cluster_bench_<timestamp>.ndjson
#
# Environment variables:
#   BENCH_EXE   Path to a pre-built acme_bench binary.  When set the script
#               runs it directly instead of compiling.  The bench binary still
#               needs target/release/akamu alongside it for process-mode runs;
#               set AKAMU_EXE to override that path.
#
#   AKAMU_EXE   Path to a pre-built akamu server binary used by --spawn process.
#               When set the script symlinks or copies it to target/release/akamu
#               before running process-mode sections.
#               Default: target/release/akamu (built by cargo build --release).
#
#   QUICK       Set to any non-empty value for a faster sweep:
#               200 requests / 20 warmup instead of 500 / 50.
#               Useful for spot-checks; not suitable for publication.
#
# Axes covered (10 sections):
#
#   §1  Node scaling         — ec:P-256 / http-01, nodes 1→10, process mode
#   §2  Key type × nodes     — each cert key type at 1 and 5 nodes, process mode
#   §3  CA key type × nodes  — each CA key type at 1 and 5 nodes, process mode
#   §4  PQ full chain        — ML-DSA leaf+CA at 1 and 5 nodes (OpenSSL 3.5+)
#   §5  Spawn mode           — inprocess vs process at nodes 1/5/10
#   §6  Challenge type       — http-01 vs dns-persist-01 at nodes 1/5, process
#   §7  Topology             — direct vs proxy at nodes 5/10, process
#   §8  Gossip overhead      — gossip on vs off at nodes 5/10, process
#   §9  Concurrency × nodes  — client sweep (10/25/50/100) at nodes 1/5, process
#   §10 System metadata      — appended as a final JSON object with host info
#
# Post-processing examples:
#   # Print throughput for all runs
#   jq -r '.label + ": " + (.summary.throughput_per_sec|round|tostring) + " iss/s"' results.ndjson
#
#   # Extract the scaling table
#   jq -r 'select(.label | startswith("scale_")) | [.label,
#     .config.nodes, .summary.throughput_per_sec,
#     .summary.total_latency_ms.mean, .summary.total_latency_ms.p95] | @tsv' results.ndjson
#
# Prerequisites:
#   - cargo (Rust toolchain) — not required when BENCH_EXE + AKAMU_EXE are set
#   - openssl (CLI) — for version detection
#   - python3 or jq — for JSON assembly (python3 preferred, jq as fallback)

set -euo pipefail
export LANG=C

# ── Paths ─────────────────────────────────────────────────────────────────────

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/../.." && pwd)
cd "$REPO_ROOT"

OUT="${1:-/tmp/akamu_cluster_bench_$(date +%Y%m%d_%H%M%S).ndjson}"
> "$OUT"

BENCH_EXE="${BENCH_EXE:-}"
AKAMU_EXE="${AKAMU_EXE:-}"
QUICK="${QUICK:-}"

# ── Request counts ─────────────────────────────────────────────────────────────

if [[ -n "$QUICK" ]]; then
    REQ=200; WARMUP=20; CLIENTS=50
else
    REQ=500; WARMUP=50; CLIENTS=100
fi
RSA4096_REQ=$(( REQ / 5 ))   # RSA-4096 generation is ~5× slower
RSA4096_WARMUP=$(( WARMUP / 5 ))
POLL=5

# ── Helpers ───────────────────────────────────────────────────────────────────

log()  { echo "$*" >&2; }
note() { printf "  %-60s" "$1" >&2; }

# Determine how to run the bench binary.
run_bench_raw() {
    if [[ -n "$BENCH_EXE" ]]; then
        "$BENCH_EXE" "$@"
    else
        cargo bench --bench acme_bench -- "$@"
    fi
}

# Merge JSON with jq or python3.
merge_json() {
    local lbl="$1" extra="$2" json="$3"
    if command -v jq &>/dev/null; then
        printf '%s\n' "$json" | jq --arg lbl "$lbl" --argjson ex "$extra" \
            '{label: $lbl} + $ex + .'
    else
        python3 - <<PYEOF
import json, sys
d = json.loads("""$json""")
ex = $extra
d = {"label": "$lbl", **ex, **d}
print(json.dumps(d))
PYEOF
    fi
}

# Run one benchmark.  Appends a JSON object to $OUT, prints a summary line.
#   bench LABEL [EXTRA_JSON] -- [BENCH_ARGS...]
# EXTRA_JSON is a JSON object string merged into the output (default: {}).
bench() {
    local label="$1"; shift
    local extra="{}"
    if [[ "$1" != "--" ]]; then
        extra="$1"; shift
    fi
    [[ "$1" == "--" ]] && shift

    note "$label"

    local json
    if ! json=$(run_bench_raw "$@" --output json 2>/dev/null); then
        log "  FAILED"
        return
    fi

    local merged
    merged=$(merge_json "$label" "$extra" "$json")
    printf '%s\n' "$merged" >> "$OUT"

    local thr mean p95 fin
    if command -v jq &>/dev/null; then
        thr=$(printf '%s\n'  "$json" | jq '.summary.throughput_per_sec | round')
        mean=$(printf '%s\n' "$json" | jq '(.summary.total_latency_ms.mean * 10 | round) / 10')
        p95=$(printf '%s\n'  "$json" | jq '(.summary.total_latency_ms.p95  * 10 | round) / 10')
        fin=$(printf '%s\n'  "$json" | jq '(.phases.finalize_ms            * 10 | round) / 10')
    else
        thr=$(python3  -c "import json,sys; d=json.loads(sys.stdin.read()); print(round(d['summary']['throughput_per_sec']))" <<< "$json")
        mean=$(python3 -c "import json,sys; d=json.loads(sys.stdin.read()); print(round(d['summary']['total_latency_ms']['mean'],1))" <<< "$json")
        p95=$(python3  -c "import json,sys; d=json.loads(sys.stdin.read()); print(round(d['summary']['total_latency_ms']['p95'],1))" <<< "$json")
        fin=$(python3  -c "import json,sys; d=json.loads(sys.stdin.read()); print(round(d['phases']['finalize_ms'],1))" <<< "$json")
    fi
    printf "thr=%5d  mean=%6.1f ms  p95=%6.1f ms  fin=%5.1f ms\n" \
        "$thr" "$mean" "$p95" "$fin" >&2
}

# ── OpenSSL version check ──────────────────────────────────────────────────────

has_openssl35=0
if command -v openssl &>/dev/null; then
    ossl_ver=$(openssl version | awk '{print $2}')
    ossl_maj=$(echo "$ossl_ver" | cut -d. -f1)
    ossl_min=$(echo "$ossl_ver" | cut -d. -f2)
    if [[ "$ossl_maj" -gt 3 ]] || { [[ "$ossl_maj" -eq 3 ]] && [[ "$ossl_min" -ge 5 ]]; }; then
        has_openssl35=1
    fi
fi

# ── Build ─────────────────────────────────────────────────────────────────────

log ""
log "=== Build ==="

if [[ -n "$AKAMU_EXE" ]]; then
    log "  Using AKAMU_EXE=$AKAMU_EXE"
    mkdir -p target/release
    if [[ "$AKAMU_EXE" != "target/release/akamu" ]]; then
        cp "$AKAMU_EXE" target/release/akamu
        chmod +x target/release/akamu
    fi
elif [[ -z "$BENCH_EXE" ]]; then
    log "  cargo build --release …"
    cargo build --release 2>&1 | grep -E "^(Compiling|Finished|error)" | sed 's/^/    /' >&2
    log "  Release build done."
else
    if [[ ! -x "target/release/akamu" ]]; then
        log "  WARNING: target/release/akamu not found — process-mode sections will be skipped."
        log "  Set AKAMU_EXE or run \`cargo build --release\` to enable them."
    fi
fi

CAN_PROCESS=0
[[ -x "target/release/akamu" ]] && CAN_PROCESS=1

# ── System metadata (written as last record, also printed at start) ────────────

collect_system_info() {
    local cpu cores mem_kb git_commit git_branch ossl_ver_str kernel
    cpu=$(grep -m1 "^model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ //' || echo "unknown")
    cores=$(nproc 2>/dev/null || echo "?")
    mem_kb=$(grep "^MemTotal" /proc/meminfo 2>/dev/null | awk '{print $2}' || echo "0")
    git_commit=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
    git_branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
    ossl_ver_str=$(openssl version 2>/dev/null || echo "unknown")
    kernel=$(uname -r 2>/dev/null || echo "unknown")

    python3 - <<PYEOF
import json
print(json.dumps({
    "label": "_system_metadata",
    "system": {
        "cpu":         "$cpu",
        "cores":       $cores,
        "memory_gb":   round(${mem_kb}.0 / 1048576, 1),
        "kernel":      "$kernel",
        "openssl":     "$ossl_ver_str",
        "has_pq":      $([ $has_openssl35 -eq 1 ] && echo true || echo false),
        "git_commit":  "$git_commit",
        "git_branch":  "$git_branch",
    },
    "bench_params": {
        "clients":  $CLIENTS,
        "requests": $REQ,
        "warmup":   $WARMUP,
        "quick":    $([ -n "$QUICK" ] && echo true || echo false),
    }
}))
PYEOF
}

sys_info=$(collect_system_info)
log ""
log "System:"
if command -v jq &>/dev/null; then
    printf '%s\n' "$sys_info" | jq '.system' >&2
else
    printf '%s\n' "$sys_info" >&2
fi
log "Bench params: clients=$CLIENTS requests=$REQ warmup=$WARMUP$([ -n "$QUICK" ] && echo " (quick)" || true)"
log "Output: $OUT"

# ── §1: Node scaling ──────────────────────────────────────────────────────────

log ""
log "=== §1  Node scaling  (ec:P-256 / http-01 / process mode) ==="
if [[ $CAN_PROCESS -eq 1 ]]; then
    for n in 1 2 3 5 7 10; do
        bench "scale_n${n}" '{"axis":"scale","spawn":"process"}' -- \
            --nodes "$n" --clients "$CLIENTS" --requests "$REQ" --warmup "$WARMUP" \
            --spawn process --poll-ms "$POLL"
    done
else
    log "  SKIPPED (target/release/akamu not found)"
fi

# ── §2: Key type × nodes ──────────────────────────────────────────────────────

log ""
log "=== §2  Key type × nodes  (process mode, ec:P-256 CA) ==="
if [[ $CAN_PROCESS -eq 1 ]]; then
    for kt in ec:P-256 ec:P-384 ed25519 rsa:2048 rsa:4096; do
        tag="${kt//:/}"
        r="$REQ"; w="$WARMUP"
        [[ "$kt" == "rsa:4096" ]] && r="$RSA4096_REQ" && w="$RSA4096_WARMUP"
        for n in 1 5; do
            bench "keytype_${tag}_n${n}" \
                "{\"axis\":\"keytype\",\"key_type\":\"$kt\",\"spawn\":\"process\"}" -- \
                --nodes "$n" --clients "$CLIENTS" --requests "$r" --warmup "$w" \
                --key-type "$kt" --spawn process --poll-ms "$POLL"
        done
    done
else
    log "  SKIPPED"
fi

# ── §3: CA key type × nodes ───────────────────────────────────────────────────

log ""
log "=== §3  CA key type × nodes  (process mode, ec:P-256 leaf) ==="
if [[ $CAN_PROCESS -eq 1 ]]; then
    for cakt in ec:P-256 ec:P-384 rsa:2048 rsa:4096; do
        tag="${cakt//:/}"
        r="$REQ"; w="$WARMUP"
        [[ "$cakt" == "rsa:4096" ]] && r="$RSA4096_REQ" && w="$RSA4096_WARMUP"
        for n in 1 5; do
            bench "ca_keytype_${tag}_n${n}" \
                "{\"axis\":\"ca_keytype\",\"ca_key_type\":\"$cakt\",\"spawn\":\"process\"}" -- \
                --nodes "$n" --clients "$CLIENTS" --requests "$r" --warmup "$w" \
                --ca-key-type "$cakt" --spawn process --poll-ms "$POLL"
        done
    done
else
    log "  SKIPPED"
fi

# ── §4: PQ full chain × nodes ─────────────────────────────────────────────────

log ""
log "=== §4  PQ full chain × nodes  (ML-DSA leaf+CA, process mode) ==="
if [[ $has_openssl35 -eq 1 ]] && [[ $CAN_PROCESS -eq 1 ]]; then
    for pq in ml-dsa-44 ml-dsa-65 ml-dsa-87; do
        tag="${pq//-/_}"
        for n in 1 5; do
            bench "pq_chain_${tag}_n${n}" \
                "{\"axis\":\"pq_chain\",\"key_type\":\"$pq\",\"spawn\":\"process\"}" -- \
                --nodes "$n" --clients "$CLIENTS" --requests "$REQ" --warmup "$WARMUP" \
                --key-type "$pq" --ca-key-type "$pq" --spawn process --poll-ms "$POLL"
        done
    done
else
    [[ $has_openssl35 -eq 0 ]] && log "  SKIPPED (OpenSSL < 3.5)"
    [[ $CAN_PROCESS -eq 0  ]] && log "  SKIPPED (no akamu binary)"
fi

# ── §5: Spawn mode comparison ─────────────────────────────────────────────────

log ""
log "=== §5  Spawn mode: inprocess vs process  (ec:P-256 / http-01) ==="
for n in 1 5 10; do
    bench "spawn_inprocess_n${n}" \
        "{\"axis\":\"spawn_mode\",\"spawn\":\"inprocess\"}" -- \
        --nodes "$n" --clients "$CLIENTS" --requests "$REQ" --warmup "$WARMUP" \
        --spawn inprocess --poll-ms "$POLL"

    if [[ $CAN_PROCESS -eq 1 ]]; then
        bench "spawn_process_n${n}" \
            "{\"axis\":\"spawn_mode\",\"spawn\":\"process\"}" -- \
            --nodes "$n" --clients "$CLIENTS" --requests "$REQ" --warmup "$WARMUP" \
            --spawn process --poll-ms "$POLL"
    fi
done

# ── §6: Challenge type × nodes ────────────────────────────────────────────────

log ""
log "=== §6  Challenge type × nodes  (ec:P-256, process mode) ==="
if [[ $CAN_PROCESS -eq 1 ]]; then
    for ch in http-01 dns-persist-01; do
        tag="${ch//-/_}"
        for n in 1 5; do
            bench "challenge_${tag}_n${n}" \
                "{\"axis\":\"challenge\",\"challenge\":\"$ch\",\"spawn\":\"process\"}" -- \
                --nodes "$n" --clients "$CLIENTS" --requests "$REQ" --warmup "$WARMUP" \
                --challenge "$ch" --spawn process --poll-ms "$POLL"
        done
    done
else
    log "  SKIPPED"
fi

# ── §7: Topology × nodes ──────────────────────────────────────────────────────

log ""
log "=== §7  Topology: direct vs proxy  (ec:P-256 / http-01, process mode) ==="
if [[ $CAN_PROCESS -eq 1 ]]; then
    for topo in direct proxy; do
        for n in 5 10; do
            bench "topology_${topo}_n${n}" \
                "{\"axis\":\"topology\",\"topology\":\"$topo\",\"spawn\":\"process\"}" -- \
                --nodes "$n" --clients "$CLIENTS" --requests "$REQ" --warmup "$WARMUP" \
                --topology "$topo" --spawn process --poll-ms "$POLL"
        done
    done
else
    log "  SKIPPED"
fi

# ── §8: Gossip overhead ───────────────────────────────────────────────────────

log ""
log "=== §8  Gossip overhead  (ec:P-256 / http-01, process mode) ==="
if [[ $CAN_PROCESS -eq 1 ]]; then
    for n in 5 10; do
        bench "gossip_on_n${n}" \
            "{\"axis\":\"gossip\",\"gossip\":true,\"spawn\":\"process\"}" -- \
            --nodes "$n" --clients "$CLIENTS" --requests "$REQ" --warmup "$WARMUP" \
            --spawn process --poll-ms "$POLL"
        bench "gossip_off_n${n}" \
            "{\"axis\":\"gossip\",\"gossip\":false,\"spawn\":\"process\"}" -- \
            --nodes "$n" --clients "$CLIENTS" --requests "$REQ" --warmup "$WARMUP" \
            --spawn process --no-gossip --poll-ms "$POLL"
    done
else
    log "  SKIPPED"
fi

# ── §9: Concurrency × nodes ───────────────────────────────────────────────────

log ""
log "=== §9  Concurrency × nodes  (ec:P-256 / http-01, process mode) ==="
if [[ $CAN_PROCESS -eq 1 ]]; then
    for c in 10 25 50 100; do
        for n in 1 5; do
            bench "concurrency_c${c}_n${n}" \
                "{\"axis\":\"concurrency\",\"spawn\":\"process\"}" -- \
                --nodes "$n" --clients "$c" --requests "$REQ" --warmup "$WARMUP" \
                --spawn process --poll-ms "$POLL"
        done
    done
else
    log "  SKIPPED"
fi

# ── §10: System metadata ──────────────────────────────────────────────────────

log ""
log "=== §10  System metadata ==="
printf '%s\n' "$sys_info" >> "$OUT"
log "  Written."

# ── Summary ───────────────────────────────────────────────────────────────────

total=$(grep -c '"label"' "$OUT" 2>/dev/null || echo "?")
log ""
log "Done.  $total records written to: $OUT"
log ""
log "Quick throughput table:"
if command -v jq &>/dev/null; then
    jq -r 'select(.label != "_system_metadata")
        | .label + ": " + (.summary.throughput_per_sec | round | tostring) + " iss/s"' \
        "$OUT" >&2
else
    python3 - "$OUT" <<'PYEOF'
import json, sys
for line in open(sys.argv[1]):
    d = json.loads(line)
    if d.get("label") == "_system_metadata":
        continue
    thr = round(d["summary"]["throughput_per_sec"])
    print(f"  {d['label']}: {thr} iss/s")
PYEOF
fi
