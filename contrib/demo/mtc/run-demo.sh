#!/usr/bin/env bash
# run-demo.sh — End-to-end Merkle Tree Certificate (MTC) issuance demo
#
# What this script does:
#   1. Builds the akamu server and akamu-cli binaries
#   2. Starts the akamu ACME server with:
#        - ML-DSA-87 CA key (post-quantum)
#        - ML-DSA-44 MTC signing key (distinct from CA key per MTC §5.5)
#        - An issue_as="mtc" certificate profile
#   3. Issues 10 MTC StandaloneCertificates for distinct subdomains
#   4. Shows how the Merkle tree grows with each issuance
#   5. Inspects the first certificate's ASN.1 structure
#   6. Queries the MTC transparency log via `akamu-cli mtc` subcommands
#   7. Verifies all 10 inclusion proofs via `akamu-cli mtc verify`
#   8. Cleans up on exit (Ctrl-C or completion)
#
# The MTC StandaloneCertificate has:
#   signatureAlgorithm = id-alg-mtcProof (OID 1.3.6.1.4.1.44363.47.0)
#   signatureValue     = TLS-encoded MtcProof (Merkle inclusion proof)
#   issuer             = LogID (id-rdna-trustAnchorID)
#   serialNumber       = Merkle tree leaf index
#
# Prerequisites:
#   - openssl 3.5+ (for ML-DSA key generation)
#   - synta-tool (for MTC certificate inspection)
#   - cargo / rust toolchain
#
# Usage:
#   cd /path/to/akamu-rfc9447
#   bash contrib/demo/mtc/run-demo.sh [--interactive]
#
# --interactive: after the certificate is issued, keep the akamu server running
#                and wait for Ctrl-C before cleaning up.  Without this flag the
#                script exits immediately after displaying results.

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DEMO_DIR/../../.." && pwd)"
TESTDIR="${TMPDIR:-/tmp}/akamu-demo-mtc"
AKAMU_PORT=8556                 # Avoids collision with gssapi demo's 8555
HTTP_CHALLENGE_PORT=5002        # Non-privileged port for http-01 challenge
AKAMU_CA_ID="default"
INTERACTIVE=false

# ── cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    echo
    echo "[demo] Cleaning up..."
    [[ -n "${AKAMU_PID:-}" ]] && kill "$AKAMU_PID" 2>/dev/null || true
    wait "$AKAMU_PID" 2>/dev/null || true
    echo "[demo] Done."
}
trap cleanup EXIT INT TERM

# ── helpers ───────────────────────────────────────────────────────────────────

die() { echo "[demo] ERROR: $*" >&2; exit 1; }

require_cmd() {
    command -v "$1" &>/dev/null || die "'$1' not found; install $2"
}

wait_for_port() {
    local host=$1 port=$2 label=$3
    local deadline=$((SECONDS + 20))
    while (( SECONDS < deadline )); do
        if bash -c ">/dev/tcp/$host/$port" 2>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    die "$label did not start within 20 seconds"
}

wait_for_file() {
    local file=$1 label=$2
    local deadline=$((SECONDS + 20))
    while (( SECONDS < deadline )); do
        [[ -f "$file" ]] && return 0
        sleep 0.2
    done
    die "$label file $file not created within 20 seconds"
}

# ── argument parsing ─────────────────────────────────────────────────────────

for arg in "$@"; do
    case "$arg" in
        --interactive) INTERACTIVE=true ;;
        *) die "Unknown argument: $arg" ;;
    esac
done

# ── prerequisite checks ───────────────────────────────────────────────────────

echo "[demo] Checking prerequisites..."
require_cmd openssl "openssl 3.5+"
require_cmd cargo   "rustup / cargo"

echo "[demo] All prerequisites found."

# ── build ─────────────────────────────────────────────────────────────────────

echo "[demo] Building akamu, akamu-cli, and synta-tool (this may take a while)..."
if ! (cd "$REPO_ROOT" && cargo build --all-features --quiet -p akamu -p akamu-cli); then
    die "cargo build failed — see output above"
fi
AKAMU_BIN="$REPO_ROOT/target/debug/akamu"
AKAMU_CLI="$REPO_ROOT/target/debug/akamu-cli"
[[ -x "$AKAMU_BIN" ]] || die "akamu binary not found after build"
[[ -x "$AKAMU_CLI" ]] || die "akamu-cli binary not found after build"

echo "[demo] Installing synta-tools >=0.2.5..."
if ! cargo install --quiet synta-tools --version '>=0.2.5'; then
    die "cargo install synta-tools failed — see output above"
fi
SYNTA_TOOL="$(command -v synta-tool)"
# cargo install may place the binary under ~/.cargo/bin; prefer the newest one.
[[ -x "${HOME}/.cargo/bin/synta-tool" ]] && SYNTA_TOOL="${HOME}/.cargo/bin/synta-tool"
"$SYNTA_TOOL" --version >/dev/null 2>&1 || die "synta-tool not functional; install synta-tools >=0.2.5"
echo "[demo] Build complete."

# ── testdir ───────────────────────────────────────────────────────────────────

[[ "$TESTDIR" == */akamu-demo-mtc ]] || die "TESTDIR sanity check failed: $TESTDIR"
rm -rf "$TESTDIR"
mkdir -p "$TESTDIR"
echo "[demo] Working directory: $TESTDIR"

# ── CA certificate ────────────────────────────────────────────────────────────

CA_KEY="$TESTDIR/ca.key.pem"
CA_CERT="$TESTDIR/ca.cert.pem"

# ── akamu server config ──────────────────────────────────────────────────────
#
# Profile: mtc-tls
#   issue_as = "mtc" — the finalize handler builds a StandaloneCertificate
#   instead of returning a standard X.509 PEM chain.
#
# MTC config:
#   CA key:          ML-DSA-87 (post-quantum)
#   MTC signing key: ML-DSA-44 (must differ from CA key per MTC §5.5)
#   Log:             disk-backed append-only Merkle tree

AKAMU_CFG="$TESTDIR/akamu.toml"
AKAMU_DB="$TESTDIR/acme.db"
cat > "$AKAMU_CFG" <<EOF
listen_addr = "127.0.0.1:${AKAMU_PORT}"
base_url    = "https://127.0.0.1:${AKAMU_PORT}"

[database]
url = "sqlite://${AKAMU_DB}"

[tls]
enabled     = true
cert_file   = "${TESTDIR}/server.pem"
key_file    = "${TESTDIR}/server.key"
server_name = "127.0.0.1"

[tls.client_auth]
required = false
ca_files = ["${CA_CERT}"]

[ca]
key_file          = "${CA_KEY}"
cert_file         = "${CA_CERT}"
key_type          = "ml-dsa-87"
validity_days     = 30
ca_validity_years = 1

[mtc]
log_path                 = "${TESTDIR}/mtc.log"
enabled                  = true
checkpoint_interval_secs = 10

[mtc.signing_key]
key_file = "${TESTDIR}/mtc-signing.key"
key_type = "ml-dsa-44"

[server]
http_validation_port              = ${HTTP_CHALLENGE_PORT}
http_validation_allow_private_ips = true
validate_dnssec                   = false

[profiles]
[profiles.providers.local]
type = "builtin"

[profiles.providers.local.profiles.mtc-tls]
description   = "MTC StandaloneCertificate demo profile"
validity_days = 30
eku           = ["server_auth"]
issue_as      = "mtc"
EOF
echo "[demo] akamu config written to $AKAMU_CFG"

# ── akamu server ──────────────────────────────────────────────────────────────

echo "[demo] Starting akamu ACME server (port ${AKAMU_PORT})..."
"$AKAMU_BIN" "$AKAMU_CFG" \
    > "$TESTDIR/akamu.log" 2>&1 &
AKAMU_PID=$!
wait_for_port 127.0.0.1 "$AKAMU_PORT" "akamu"
wait_for_file "$CA_CERT" "CA certificate"
echo "[demo] akamu ready (pid $AKAMU_PID)"

# ── issue 10 certificates ────────────────────────────────────────────────────

ACCOUNT_KEY="$TESTDIR/account.key.pem"
CERT_COUNT=10
CERT_IDS=()
MTC_ARGS=(--server "https://127.0.0.1:${AKAMU_PORT}" --ca "$AKAMU_CA_ID" --server-ca "$CA_CERT")

echo "[demo] Issuing ${CERT_COUNT} MTC StandaloneCertificates via http-01..."
echo "[demo]   Profile:        mtc-tls (issue_as = mtc)"
echo "[demo]   CA key type:    ML-DSA-87"
echo "[demo]   Cert key type:  ML-DSA-65"
echo "[demo]   MTC key type:   ML-DSA-44"
echo

for i in $(seq -w 1 "$CERT_COUNT"); do
    CERT_SUBDIR="$TESTDIR/cert-$i"
    mkdir -p "$CERT_SUBDIR"
    CERT_DOMAIN="cert-${i}.mtc-demo.localhost"
    CERT_FILE="$CERT_SUBDIR/cert.der"

    echo "[demo] ── Certificate $i/$CERT_COUNT: dns:${CERT_DOMAIN} ──"

    ISSUE_OUTPUT=$("$AKAMU_CLI" issue \
        --server        "https://127.0.0.1:${AKAMU_PORT}" \
        --ca            "$AKAMU_CA_ID" \
        --account-key   "$ACCOUNT_KEY" \
        --out           "$CERT_FILE" \
        --cert-key-type ml-dsa-65 \
        --challenge     http-01 \
        --http-port     "$HTTP_CHALLENGE_PORT" \
        --domain        "$CERT_DOMAIN" \
        --server-ca     "$CA_CERT" \
        --profile       mtc-tls 2>&1)

    CERT_URL=$(echo "$ISSUE_OUTPUT" | grep 'Certificate URL:' | awk '{print $NF}')
    CERT_ID="${CERT_URL##*/}"
    CERT_IDS+=("$CERT_ID")

    echo "[demo]   cert_id:   ${CERT_ID}"
    echo "[demo]   file:      ${CERT_FILE} ($(wc -c < "$CERT_FILE") bytes)"
    echo
done

echo "[demo] ================================================"
echo "[demo] All ${CERT_COUNT} certificates issued."
echo "[demo] ================================================"

# ── inspect first certificate ────────────────────────────────────────────────

echo
echo "[demo] Certificate #01 ASN.1 structure:"
echo
"$SYNTA_TOOL" cert -v "$TESTDIR/cert-01/cert.der"

# ── query MTC transparency log ───────────────────────────────────────────────

echo
echo "[demo] ================================================"
echo "[demo] MTC Transparency Log State (after ${CERT_COUNT} issuances)"
echo "[demo] ================================================"
echo

echo "[demo] akamu-cli mtc tree-size"
"$AKAMU_CLI" mtc tree-size "${MTC_ARGS[@]}"
echo

echo "[demo] akamu-cli mtc root"
"$AKAMU_CLI" mtc root "${MTC_ARGS[@]}"
echo

echo "[demo] akamu-cli mtc checkpoint (C2SP signed-note format)"
"$AKAMU_CLI" mtc checkpoint "${MTC_ARGS[@]}"
echo

echo "[demo] akamu-cli mtc landmarks"
"$AKAMU_CLI" mtc landmarks "${MTC_ARGS[@]}"
echo

# ── verify all inclusion proofs ──────────────────────────────────────────────

echo "[demo] ================================================"
echo "[demo] Verifying all ${CERT_COUNT} inclusion proofs..."
echo "[demo] ================================================"
echo

VERIFY_PASS=0
VERIFY_FAIL=0
for i in $(seq -w 1 "$CERT_COUNT"); do
    idx=$((10#$i - 1))
    CID="${CERT_IDS[$idx]}"
    CFILE="$TESTDIR/cert-$i/cert.der"
    if "$AKAMU_CLI" mtc verify "${MTC_ARGS[@]}" --cert-id "$CID" --cert-file "$CFILE" 2>&1; then
        VERIFY_PASS=$((VERIFY_PASS + 1))
    else
        echo "[demo]   FAIL: cert-$i (cert_id=$CID)"
        VERIFY_FAIL=$((VERIFY_FAIL + 1))
    fi
done

echo
echo "[demo] ================================================"
echo "[demo] Verification: ${VERIFY_PASS} passed, ${VERIFY_FAIL} failed (of ${CERT_COUNT})"
echo "[demo] ================================================"

# ── done ──────────────────────────────────────────────────────────────────────

echo
echo "[demo] Tip: inspect any certificate with:"
echo "[demo]   ${SYNTA_TOOL} cert -v ${TESTDIR}/cert-01/cert.der"
echo
echo "[demo] Tip: query the MTC log while running in --interactive mode:"
echo "[demo]   ${AKAMU_CLI} mtc root ${MTC_ARGS[*]}"
echo "[demo]   ${AKAMU_CLI} mtc verify ${MTC_ARGS[*]} --cert-id <CERT_ID> --cert-file <FILE>"
echo "[demo] ================================================"
echo
if $INTERACTIVE; then
    echo "[demo] Demo complete. Press Ctrl-C to stop the akamu server."
    while true; do sleep 86400; done
else
    echo "[demo] Demo complete."
fi
