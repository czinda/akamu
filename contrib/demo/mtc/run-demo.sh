#!/usr/bin/env bash
# run-demo.sh — End-to-end Merkle Tree Certificate (MTC) issuance demo
#
# What this script does:
#   1. Builds the akamu server, akamu-cli, and akamuctl binaries
#   2. Creates an ephemeral Kerberos realm (for GSSAPI + EAB browser login)
#   3. Starts the akamu ACME server with:
#        - ML-DSA-87 CA key (post-quantum)
#        - ML-DSA-44 MTC signing key (distinct from CA key per MTC §5.5)
#        - An issue_as="mtc" certificate profile
#        - A bootstrap administrator with mTLS + GSSAPI principal
#        - GSSAPI/Kerberos admin auth (enables EAB browser login)
#   4. Bootstraps admin access, creates operators, provisions EAB key:
#        - administrator, ca_operations, ca_ra, auditor
#        - EAB key for Web UI browser login (browsers lack ML-DSA mTLS)
#   5. Issues 10 MTC StandaloneCertificates for distinct subdomains
#   6. Shows how the Merkle tree grows with each issuance
#   7. Inspects the first certificate's ASN.1 structure
#   8. Queries the MTC transparency log via `akamu-cli mtc` subcommands
#   9. Uses akamuctl as each operator role to demonstrate RBAC
#  10. Verifies all 10 inclusion proofs via `akamu-cli mtc verify`
#  11. Cleans up on exit (Ctrl-C or completion)
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
#   - Kerberos utilities: krb5kdc, kdb5_util, kadmin.local (krb5-server)
#   - Python 3.9+ (for KDC setup)
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
KDC_PORT=62000                  # KDC port from setup.py
AKAMU_CA_ID="default"
INTERACTIVE=false

# ── cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    echo
    echo "[demo] Cleaning up..."
    [[ -n "${AKAMU_PID:-}" ]]     && kill "$AKAMU_PID"     2>/dev/null || true
    [[ -n "${AKAMU_PID:-}" ]]     && wait "$AKAMU_PID"     2>/dev/null || true
    [[ -n "${KDC_SETUP_PID:-}" ]] && kill "$KDC_SETUP_PID" 2>/dev/null || true
    [[ -n "${KDC_SETUP_PID:-}" ]] && wait "$KDC_SETUP_PID" 2>/dev/null || true
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
require_cmd openssl     "openssl 3.5+"
require_cmd cargo       "rustup / cargo"
require_cmd krb5kdc     "krb5-server"
require_cmd kdb5_util   "krb5-server"
require_cmd kadmin.local "krb5-server"
require_cmd python3     "python3"

echo "[demo] All prerequisites found."

# ── build ─────────────────────────────────────────────────────────────────────

echo "[demo] Building akamu, akamu-cli, akamuctl, and synta-tool (this may take a while)..."
if ! (cd "$REPO_ROOT" && cargo build --all-features --quiet -p akamu -p akamu-cli -p akamuctl); then
    die "cargo build failed — see output above"
fi
AKAMU_BIN="$REPO_ROOT/target/debug/akamu"
AKAMU_CLI="$REPO_ROOT/target/debug/akamu-cli"
AKAMUCTL="$REPO_ROOT/target/debug/akamuctl"
[[ -x "$AKAMU_BIN"  ]] || die "akamu binary not found after build"
[[ -x "$AKAMU_CLI"  ]] || die "akamu-cli binary not found after build"
[[ -x "$AKAMUCTL"   ]] || die "akamuctl binary not found after build"

echo "[demo] Installing synta-tools >=0.2.5..."
if ! cargo install --quiet synta-tools --version '>=0.2.5'; then
    die "cargo install synta-tools failed — see output above"
fi
SYNTA_TOOL="${HOME}/.cargo/bin/synta-tool"
[[ -x "$SYNTA_TOOL" ]] || SYNTA_TOOL="$(command -v synta-tool 2>/dev/null || true)"
[[ -x "$SYNTA_TOOL" ]] || die "synta-tool not found in PATH or ~/.cargo/bin"
"$SYNTA_TOOL" --version >/dev/null 2>&1 || die "synta-tool not functional; install synta-tools >=0.2.5"
echo "[demo] Build complete."

# ── testdir ───────────────────────────────────────────────────────────────────

[[ "$TESTDIR" == */akamu-demo-mtc ]] || die "TESTDIR sanity check failed: $TESTDIR"
rm -rf "$TESTDIR"
mkdir -p "$TESTDIR"
echo "[demo] Working directory: $TESTDIR"

# ── Kerberos realm (for EAB browser login) ───────────────────────────────────
# Reuse the gssapi demo's setup.py to create an ephemeral KDC.  The admin
# operator gets a GSSAPI principal so akamuctl can also log in via Negotiate.
# More importantly, the [admin.gssapi] config enables the EAB session endpoint
# (/admin/session/eab) which the Web UI uses for browser login — browsers
# cannot do ML-DSA mTLS yet.

GSSAPI_DEMO_DIR="$REPO_ROOT/contrib/demo/gssapi"
[[ -f "$GSSAPI_DEMO_DIR/setup.py" ]] || die "gssapi demo setup.py not found at $GSSAPI_DEMO_DIR/setup.py"

echo "[demo] Starting KDC..."
ENV_FILE="$TESTDIR/kdc-env.sh"
python3 "$GSSAPI_DEMO_DIR/setup.py" \
    --testdir "$TESTDIR/kdc" \
    --env-file "$ENV_FILE" &
KDC_SETUP_PID=$!

wait_for_file "$ENV_FILE" "KDC env file"
# shellcheck source=/dev/null
source "$ENV_FILE"
IDP_KEYTAB="$DEMO_IDP_KEYTAB"

wait_for_port 127.0.0.1 "$KDC_PORT" "KDC"
echo "[demo] KDC ready"

# ── CA certificate ────────────────────────────────────────────────────────────

CA_KEY="$TESTDIR/ca.key.pem"
CA_CERT="$TESTDIR/ca.cert.pem"

# ── Operator client CA ───────────────────────────────────────────────────────
# A lightweight EC CA for signing operator client certificates.  The akamu
# ML-DSA-87 CA signs the bootstrap admin cert, but additional operator certs
# need a CA in [tls.client_auth].ca_files so the server's TLS layer accepts
# them.
OP_CA_KEY="$TESTDIR/op-ca.key.pem"
OP_CA_CERT="$TESTDIR/op-ca.cert.pem"
echo "[demo] Generating operator client CA (EC P-256)..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$OP_CA_KEY" -out "$OP_CA_CERT" -days 365 -nodes \
    -subj "/CN=Demo Operator CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign" 2>/dev/null

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
ca_files = ["${CA_CERT}", "${OP_CA_CERT}"]
allow_post_quantum = true

[ca]
key_file          = "${CA_KEY}"
cert_file         = "${CA_CERT}"
key_type          = "ml-dsa-87"
validity_days     = 30
ca_validity_years = 1

[ca.mtc]
log_path                 = "${TESTDIR}/mtc.log"
enabled                  = true
checkpoint_interval_secs = 10
trust_anchor_id          = "1.3.6.1.4.1.44363.47.1"

[ca.mtc.signing_key]
key_file = "${TESTDIR}/mtc-signing.key"
key_type = "ml-dsa-44"

[server]
http_validation_port              = ${HTTP_CHALLENGE_PORT}
http_validation_allow_private_ips = true
validate_dnssec                   = false

[admin]
bootstrap_operator_cert_file = "${TESTDIR}/admin.cert.pem"
bootstrap_operator_key_file  = "${TESTDIR}/admin.key.pem"
bootstrap_operator_gssapi_principal = "user@DEMO.TEST"

[admin.gssapi]
keytab_file  = "${IDP_KEYTAB}"
service_name = "HTTP/127.0.0.1@DEMO.TEST"

[server.webui]
static_dir = "${REPO_ROOT}/webui/dist"

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
"$AKAMU_BIN" serve -c "$AKAMU_CFG" \
    > "$TESTDIR/akamu.log" 2>&1 &
AKAMU_PID=$!
wait_for_port 127.0.0.1 "$AKAMU_PORT" "akamu"
wait_for_file "$CA_CERT" "CA certificate"
echo "[demo] akamu ready (pid $AKAMU_PID)"

# ── bootstrap admin + create operators ──────────────────────────────────────

section() {
    echo
    echo "[demo] ================================================"
    echo "[demo] $*"
    echo "[demo] ================================================"
    echo
}

section "Bootstrapping admin access and creating operators"

wait_for_file "$TESTDIR/admin.cert.pem" "bootstrap admin certificate"
wait_for_file "$TESTDIR/admin.key.pem"  "bootstrap admin key"

akamuctl_admin() {
    "$AKAMUCTL" --server-url "https://127.0.0.1:${AKAMU_PORT}" \
        --ca-cert "$CA_CERT" \
        --cert "$TESTDIR/admin.cert.pem" \
        --key "$TESTDIR/admin.key.pem" \
        "$@"
}

echo "[demo] Logging in as bootstrap administrator..."
akamuctl_admin login

echo "[demo] Current operators:"
akamuctl_admin operator list
echo

# Generate client certificates for each operator role.
# The bootstrap admin cert's CA is the server's CA — we generate self-signed
# certs for the additional operators.  akamuctl only needs the cert fingerprint
# (SHA-256 of the DER) to register an operator.

for OP_ROLE in ca_operations ca_ra auditor; do
    OP_NAME="demo-${OP_ROLE}"
    OP_KEY="$TESTDIR/${OP_NAME}.key.pem"
    OP_CSR="$TESTDIR/${OP_NAME}.csr.pem"
    OP_CERT="$TESTDIR/${OP_NAME}.cert.pem"

    echo "[demo] Generating client certificate for ${OP_NAME} (${OP_ROLE})..."
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
        -keyout "$OP_KEY" -out "$OP_CSR" -nodes \
        -subj "/CN=${OP_NAME}" 2>/dev/null
    openssl x509 -req -in "$OP_CSR" \
        -CA "$OP_CA_CERT" -CAkey "$OP_CA_KEY" -CAcreateserial \
        -out "$OP_CERT" -days 365 \
        -extfile <(printf 'basicConstraints = CA:FALSE\nkeyUsage = critical,digitalSignature\nextendedKeyUsage = clientAuth\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid,issuer\nsubjectAltName = dirName:san_dn\n[san_dn]\nCN = %s' "$OP_NAME") 2>/dev/null

    echo "[demo] Registering operator '${OP_NAME}' with role '${OP_ROLE}'..."
    CA_ID_ARGS=()
    if [[ "$OP_ROLE" = "ca_ra" ]]; then
        CA_ID_ARGS=(--ca-id "$AKAMU_CA_ID")
    fi
    akamuctl_admin operator add \
        --name "$OP_NAME" \
        --role "$OP_ROLE" \
        --cert-file "$OP_CERT" \
        "${CA_ID_ARGS[@]}"
    echo
done

echo "[demo] All operators registered:"
akamuctl_admin operator list
echo

# ── provision EAB key for browser login ─────────────────────────────────────
# Browsers cannot do ML-DSA mTLS, so the Web UI uses EAB kid+HMAC login
# via POST /admin/session/eab.  Provision a key tied to the bootstrap admin.

section "Provisioning EAB key for Web UI browser login"

EAB_JSON=$(akamuctl_admin -o json eab add)
EAB_KID=$(echo "$EAB_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['kid'])")
EAB_HMAC=$(echo "$EAB_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['hmac_key_b64u'])")
echo "[demo] EAB kid:      ${EAB_KID}"
echo "[demo] EAB HMAC key: ${EAB_HMAC}"
echo "[demo] Use these credentials in the Web UI login page."
echo

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
    if [ -z "$CERT_URL" ]; then
        echo "[demo] ERROR: failed to extract Certificate URL from issue output" >&2
        echo "$ISSUE_OUTPUT" >&2
        exit 1
    fi
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

# ── demonstrate RBAC with each operator role ────────────────────────────────

section "Demonstrating RBAC — MTC operations per operator role"

# Helper: run akamuctl as a specific operator
akamuctl_as() {
    local op_name=$1; shift
    "$AKAMUCTL" --server-url "https://127.0.0.1:${AKAMU_PORT}" \
        --ca-cert "$CA_CERT" \
        --cert "$TESTDIR/${op_name}.cert.pem" \
        --key "$TESTDIR/${op_name}.key.pem" \
        "$@"
}

# administrator — full access: can query MTC and force operations
echo "[demo] ── administrator: full MTC access ──"
akamuctl_admin login
echo "[demo]   mtc tree-size:"
akamuctl_admin mtc tree-size
echo "[demo]   mtc root:"
akamuctl_admin mtc root
echo "[demo]   Forcing checkpoint..."
akamuctl_admin mtc force-checkpoint --ca "$AKAMU_CA_ID"
echo "[demo]   Forcing landmark..."
akamuctl_admin mtc force-landmark --ca "$AKAMU_CA_ID"
echo "[demo]   mtc landmarks (after force):"
akamuctl_admin mtc landmarks
echo

# ca_operations — can query MTC and force operations
echo "[demo] ── ca_operations: MTC query + force operations ──"
akamuctl_as demo-ca_operations login
echo "[demo]   mtc tree-size:"
akamuctl_as demo-ca_operations mtc tree-size
echo "[demo]   mtc revoked-ranges:"
akamuctl_as demo-ca_operations mtc revoked-ranges
echo

# auditor — read-only MTC access
echo "[demo] ── auditor: read-only MTC access ──"
akamuctl_as demo-auditor login
echo "[demo]   mtc tree-size:"
akamuctl_as demo-auditor mtc tree-size
echo "[demo]   mtc landmarks:"
akamuctl_as demo-auditor mtc landmarks
echo

# ca_ra — no MTC access (should get 403)
echo "[demo] ── ca_ra: no MTC access (expect 403) ──"
akamuctl_as demo-ca_ra login
echo "[demo]   mtc tree-size (expecting failure):"
if akamuctl_as demo-ca_ra mtc tree-size 2>&1; then
    echo "[demo]   WARNING: ca_ra should not have MTC access"
else
    echo "[demo]   Correctly denied: ca_ra cannot access MTC endpoints"
fi
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
echo
echo "[demo] Operators created (mTLS client certificates in ${TESTDIR}/):"
echo "[demo]   admin              (administrator)   admin.cert.pem / admin.key.pem"
echo "[demo]   demo-ca_operations (ca_operations)   demo-ca_operations.cert.pem / .key.pem"
echo "[demo]   demo-ca_ra         (ca_ra)            demo-ca_ra.cert.pem / .key.pem"
echo "[demo]   demo-auditor       (auditor)          demo-auditor.cert.pem / .key.pem"
echo
echo "[demo] Tip: use akamuctl as any operator:"
echo "[demo]   ${AKAMUCTL} --server-url https://127.0.0.1:${AKAMU_PORT} \\"
echo "[demo]     --ca-cert ${CA_CERT} \\"
echo "[demo]     --cert ${TESTDIR}/demo-auditor.cert.pem \\"
echo "[demo]     --key ${TESTDIR}/demo-auditor.key.pem \\"
echo "[demo]     login"
echo
echo "[demo] Web UI (browser login via EAB — no ML-DSA mTLS needed):"
echo "[demo]   URL:      https://127.0.0.1:${AKAMU_PORT}"
echo "[demo]   EAB kid:  ${EAB_KID}"
echo "[demo]   EAB HMAC: ${EAB_HMAC}"
echo "[demo] ================================================"
echo
if $INTERACTIVE; then
    echo "[demo] Demo complete. Press Ctrl-C to stop the KDC and akamu server."
    while true; do sleep 86400; done
else
    echo "[demo] Demo complete."
fi
