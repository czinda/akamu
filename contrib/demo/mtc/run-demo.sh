#!/usr/bin/env bash
# run-demo.sh — End-to-end Merkle Tree Certificate (MTC) issuance demo
#
# What this script does:
#   1. Builds the akamu server and akamu-cli binaries
#   2. Starts the akamu ACME server with:
#        - ML-DSA-87 CA key (post-quantum)
#        - ML-DSA-44 MTC signing key (distinct from CA key per MTC §5.5)
#        - An issue_as="mtc" certificate profile
#   3. Registers an ACME account and requests a certificate via http-01
#   4. The server issues an MTC StandaloneCertificate
#      (draft-ietf-plants-merkle-tree-certs) instead of a standard X.509 PEM chain
#   5. Inspects the standalone certificate ASN.1 structure
#   6. Queries the MTC transparency log HTTP endpoints
#   7. Cleans up on exit (Ctrl-C or completion)
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
#   - curl
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
DOMAIN="mtc-demo.localhost"     # .localhost TLD is reserved (RFC 6761), resolves to 127.0.0.1
AKAMU_PORT=8556                 # Avoids collision with gssapi demo's 8555
HTTP_CHALLENGE_PORT=5002        # Non-privileged port for http-01 challenge
AKAMU_CA_ID="default"
INTERACTIVE=false

# ── cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    echo
    echo "[demo] Cleaning up..."
    [[ -n "${AKAMU_PID:-}" ]] && kill "$AKAMU_PID" 2>/dev/null || true
    sleep 1
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
require_cmd curl    "curl"
require_cmd cargo   "rustup / cargo"

echo "[demo] All prerequisites found."

# ── build ─────────────────────────────────────────────────────────────────────

echo "[demo] Building akamu, akamu-cli, and synta-tool (this may take a while)..."
(cd "$REPO_ROOT" && cargo build --all-features --quiet -p akamu -p akamu-cli 2>&1) | tail -5
AKAMU_BIN="$REPO_ROOT/target/debug/akamu"
AKAMU_CLI="$REPO_ROOT/target/debug/akamu-cli"
[[ -x "$AKAMU_BIN" ]] || die "akamu binary not found after build"
[[ -x "$AKAMU_CLI" ]] || die "akamu-cli binary not found after build"

echo "[demo] Installing synta-tools >=0.2.5..."
cargo install --quiet synta-tools --version '>=0.2.5' 2>&1 | tail -3
SYNTA_TOOL="$(command -v synta-tool)"
# cargo install may place the binary under ~/.cargo/bin; prefer the newest one.
[[ -x "${HOME}/.cargo/bin/synta-tool" ]] && SYNTA_TOOL="${HOME}/.cargo/bin/synta-tool"
"$SYNTA_TOOL" --version | grep -q '0\.2\.' || die "synta-tool >=0.2.5 required"
echo "[demo] Build complete."

# ── testdir ───────────────────────────────────────────────────────────────────

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

# ── ACME request ──────────────────────────────────────────────────────────────

ACCOUNT_KEY="$TESTDIR/account.key.pem"
CERT_OUT="$TESTDIR/demo.cert.der"
ACME_DIR="https://127.0.0.1:${AKAMU_PORT}/acme/${AKAMU_CA_ID}/directory"

echo "[demo] Requesting MTC StandaloneCertificate for dns:${DOMAIN} via http-01..."
echo "[demo]   ACME directory: ${ACME_DIR}"
echo "[demo]   Profile:        mtc-tls (issue_as = mtc)"
echo "[demo]   CA key type:    ML-DSA-87"
echo "[demo]   Cert key type:  ML-DSA-65"
echo "[demo]   MTC key type:   ML-DSA-44"
echo

"$AKAMU_CLI" issue \
    --server        "https://127.0.0.1:${AKAMU_PORT}" \
    --ca            "$AKAMU_CA_ID" \
    --account-key   "$ACCOUNT_KEY" \
    --out           "$CERT_OUT" \
    --cert-key-type ml-dsa-65 \
    --challenge     http-01 \
    --http-port     "$HTTP_CHALLENGE_PORT" \
    --domain        "$DOMAIN" \
    --server-ca     "$CA_CERT" \
    --profile       mtc-tls

# ── display results ──────────────────────────────────────────────────────────

echo
echo "[demo] ================================================"
echo "[demo] MTC StandaloneCertificate issued successfully!"
echo "[demo] Written to: ${CERT_OUT}"
echo "[demo] File size:  $(wc -c < "$CERT_OUT") bytes (raw DER)"
echo "[demo] ================================================"
echo
echo "[demo] Certificate structure:"
echo
"$SYNTA_TOOL" cert -v "$CERT_OUT"

# ── query MTC transparency log endpoints ─────────────────────────────────────

echo
echo "[demo] ================================================"
echo "[demo] MTC Transparency Log State"
echo "[demo] ================================================"
echo

echo "[demo] GET /acme/mtc/tree-size"
curl -s --cacert "$CA_CERT" \
    "https://127.0.0.1:${AKAMU_PORT}/acme/mtc/tree-size"
echo
echo

echo "[demo] GET /acme/mtc/root"
ROOT_JSON=$(curl -s --cacert "$CA_CERT" \
    "https://127.0.0.1:${AKAMU_PORT}/acme/mtc/root")
echo "$ROOT_JSON"
echo
echo

echo "[demo] GET /acme/mtc/tlog/checkpoint (C2SP signed-note format)"
CHECKPOINT=$(curl -s --cacert "$CA_CERT" \
    "https://127.0.0.1:${AKAMU_PORT}/acme/mtc/tlog/checkpoint")
echo "$CHECKPOINT"
echo

echo "[demo] GET /acme/mtc/landmarks"
curl -s --cacert "$CA_CERT" \
    "https://127.0.0.1:${AKAMU_PORT}/acme/mtc/landmarks"
echo
echo

# ── verify MTC inclusion proof ───────────────────────────────────────────────

# Extract the root hash from the JSON response for proof verification.
ROOT_HASH=$(echo "$ROOT_JSON" | grep -oP '"rootHash"\s*:\s*"\K[0-9a-f]+')
if [[ -n "$ROOT_HASH" ]]; then
    echo "[demo] ================================================"
    echo "[demo] Verifying MTC inclusion proof against root hash..."
    echo "[demo]   Root hash: ${ROOT_HASH}"
    echo
    "$SYNTA_TOOL" cert -v --subtree-root "$ROOT_HASH" "$CERT_OUT"
    echo "[demo] ================================================"
    echo
fi

# ── done ──────────────────────────────────────────────────────────────────────

echo "[demo] ================================================"
echo "[demo] Tip: inspect the certificate with:"
echo "[demo]   ${SYNTA_TOOL} cert -v ${CERT_OUT}"
echo "[demo]   ${SYNTA_TOOL} cert -v --subtree-root <root_hash> ${CERT_OUT}"
echo
echo "[demo] Tip: query the MTC log while running in --interactive mode:"
echo "[demo]   curl -s --cacert ${CA_CERT} https://127.0.0.1:${AKAMU_PORT}/acme/mtc/root"
echo "[demo] ================================================"
echo
if $INTERACTIVE; then
    echo "[demo] Demo complete. Press Ctrl-C to stop the akamu server."
    sleep infinity
else
    echo "[demo] Demo complete."
fi
