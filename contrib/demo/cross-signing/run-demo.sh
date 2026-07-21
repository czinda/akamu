#!/usr/bin/env bash
# run-demo.sh — End-to-end cross-signing demo with two Akamu instances
#
# What this script does:
#   1. Builds the akamu server, akamu-cli, and akamuctl binaries
#   2. Starts two independent Akamu instances:
#        - Instance A: RSA CA (rsa:4096, port 8560)
#        - Instance B: EC CA  (ec:P-256, port 8561)
#      Each instance has its own database, TLS, and admin API with a
#      bootstrap operator certificate for mTLS authentication.
#   3. Downloads each instance's CA certificate
#   4. Cross-signs: instance A signs instance B's CA, and vice versa
#   5. Lists and downloads the cross-certificates
#   6. Issues end-entity certificates from each CA via ACME (http-01)
#   7. Verifies the cross-signed chains:
#        - EE cert from CA-A verified against CA-B root via cross-cert
#        - EE cert from CA-B verified against CA-A root via cross-cert
#   8. Cleans up on exit (Ctrl-C or completion)
#
# Prerequisites:
#   - openssl
#   - curl
#   - cargo / rust toolchain
#
# Usage:
#   cd /path/to/akamu
#   bash contrib/demo/cross-signing/run-demo.sh [--interactive]
#
# --interactive: after verification, keep both servers running and wait
#                for Ctrl-C before cleaning up.

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DEMO_DIR/../../.." && pwd)"
TESTDIR="${TMPDIR:-/tmp}/akamu-demo-cross-signing"
INTERACTIVE=false

# Instance A — RSA CA
A_PORT=8560
A_ADMIN_PORT=8570
A_HTTP_PORT=5010
A_DOMAIN="cross-a.localhost"

# Instance B — EC CA
B_PORT=8561
B_ADMIN_PORT=8571
B_HTTP_PORT=5011
B_DOMAIN="cross-b.localhost"

# ── cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    echo
    echo "[demo] Cleaning up..."
    [[ -n "${A_PID:-}" ]] && kill "$A_PID" 2>/dev/null || true
    [[ -n "${B_PID:-}" ]] && kill "$B_PID" 2>/dev/null || true
    wait "${A_PID:-}" 2>/dev/null || true
    wait "${B_PID:-}" 2>/dev/null || true
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

section() {
    echo
    echo "[demo] ================================================"
    echo "[demo] $*"
    echo "[demo] ================================================"
    echo
}

# ── argument parsing ─────────────────────────────────────────────────────────

for arg in "$@"; do
    case "$arg" in
        --interactive) INTERACTIVE=true ;;
        *) die "Unknown argument: $arg" ;;
    esac
done

# ── prerequisite checks ──────────────────────────────────────────────────────

echo "[demo] Checking prerequisites..."
require_cmd openssl  "openssl"
require_cmd curl     "curl"
require_cmd cargo    "rustup / cargo"
require_cmd python3  "python3"

echo "[demo] All prerequisites found."

# ── build ────────────────────────────────────────────────────────────────────

echo "[demo] Building akamu, akamu-cli, and akamuctl (this may take a while)..."
if ! (cd "$REPO_ROOT" && cargo build --quiet -p akamu -p akamu-cli -p akamuctl); then
    die "cargo build failed — see output above"
fi
AKAMU_BIN="$REPO_ROOT/target/debug/akamu"
AKAMU_CLI="$REPO_ROOT/target/debug/akamu-cli"
AKAMUCTL="$REPO_ROOT/target/debug/akamuctl"
[[ -x "$AKAMU_BIN"  ]] || die "akamu binary not found after build"
[[ -x "$AKAMU_CLI"  ]] || die "akamu-cli binary not found after build"
[[ -x "$AKAMUCTL"   ]] || die "akamuctl binary not found after build"
echo "[demo] Build complete."

# ── testdir ──────────────────────────────────────────────────────────────────

[[ "$TESTDIR" == */akamu-demo-cross-signing ]] || die "TESTDIR sanity check failed: $TESTDIR"
rm -rf "$TESTDIR"
mkdir -p "$TESTDIR"/{a,b}
echo "[demo] Working directory: $TESTDIR"

# ── Instance A config (RSA CA) ───────────────────────────────────────────────

A_DIR="$TESTDIR/a"
cat > "$A_DIR/akamu.toml" <<EOF
listen_addr = "127.0.0.1:${A_PORT}"
base_url    = "https://127.0.0.1:${A_PORT}"

[database]
url = "sqlite://${A_DIR}/acme.db"

[tls]
enabled     = true
cert_file   = "${A_DIR}/server.pem"
key_file    = "${A_DIR}/server.key"
server_name = "127.0.0.1"

[tls.client_auth]
required = false

[ca]
key_file      = "${A_DIR}/ca.key.pem"
cert_file     = "${A_DIR}/ca.cert.pem"
key_type      = "rsa:4096"
common_name   = "Cross-Sign Demo RSA CA"
organization  = "Akamu Demo"
validity_days = 90

[server]
http_validation_port              = ${A_HTTP_PORT}
http_validation_allow_private_ips = true
validate_dnssec                   = false

[server.webui]
static_dir = "${REPO_ROOT}/webui/dist"

[admin]
bootstrap_operator_pkcs12_file = "${A_DIR}/admin.p12"
EOF

# ── Instance B config (EC CA) ────────────────────────────────────────────────

B_DIR="$TESTDIR/b"
cat > "$B_DIR/akamu.toml" <<EOF
listen_addr = "127.0.0.1:${B_PORT}"
base_url    = "https://127.0.0.1:${B_PORT}"

[database]
url = "sqlite://${B_DIR}/acme.db"

[tls]
enabled     = true
cert_file   = "${B_DIR}/server.pem"
key_file    = "${B_DIR}/server.key"
server_name = "127.0.0.1"

[tls.client_auth]
required = false

[ca]
key_file      = "${B_DIR}/ca.key.pem"
cert_file     = "${B_DIR}/ca.cert.pem"
common_name   = "Cross-Sign Demo EC CA"
organization  = "Akamu Demo"
validity_days = 90

[server]
http_validation_port              = ${B_HTTP_PORT}
http_validation_allow_private_ips = true
validate_dnssec                   = false

[server.webui]
static_dir = "${REPO_ROOT}/webui/dist"

[admin]
bootstrap_operator_pkcs12_file = "${B_DIR}/admin.p12"
EOF

# ── start both instances ─────────────────────────────────────────────────────

section "Starting two Akamu instances"

echo "[demo] Starting instance A (RSA CA, port ${A_PORT})..."
"$AKAMU_BIN" serve -c "$A_DIR/akamu.toml" > "$A_DIR/akamu.log" 2>&1 &
A_PID=$!
wait_for_port 127.0.0.1 "$A_PORT" "instance A"
wait_for_file "$A_DIR/admin.p12" "instance A admin credentials"
echo "[demo] Instance A ready (pid $A_PID)"

echo "[demo] Starting instance B (EC CA, port ${B_PORT})..."
"$AKAMU_BIN" serve -c "$B_DIR/akamu.toml" > "$B_DIR/akamu.log" 2>&1 &
B_PID=$!
wait_for_port 127.0.0.1 "$B_PORT" "instance B"
wait_for_file "$B_DIR/admin.p12" "instance B admin credentials"
echo "[demo] Instance B ready (pid $B_PID)"

# ── display CA certificates ──────────────────────────────────────────────────

section "CA certificates"

echo "[demo] Instance A — RSA CA:"
openssl x509 -in "$A_DIR/ca.cert.pem" -noout -subject -issuer -dates
echo

echo "[demo] Instance B — EC CA:"
openssl x509 -in "$B_DIR/ca.cert.pem" -noout -subject -issuer -dates

# ── authenticate with admin API ──────────────────────────────────────────────

section "Authenticating with admin APIs"

# akamuctl needs to target each instance separately.
# We use --server-url, --ca-cert (server TLS), --cert/--key (mTLS operator).

AKAMUCTL_A=("$AKAMUCTL" --server-url "https://127.0.0.1:${A_PORT}" \
    --ca-cert "$A_DIR/ca.cert.pem" \
    --pkcs12 "$A_DIR/admin.p12")

AKAMUCTL_B=("$AKAMUCTL" --server-url "https://127.0.0.1:${B_PORT}" \
    --ca-cert "$B_DIR/ca.cert.pem" \
    --pkcs12 "$B_DIR/admin.p12")

echo "[demo] Logging into instance A..."
"${AKAMUCTL_A[@]}" login
echo "[demo] Logging into instance B..."
"${AKAMUCTL_B[@]}" login

echo "[demo] Both admin sessions established."

# ── list CAs ─────────────────────────────────────────────────────────────────

section "Listing CAs on each instance"

echo "[demo] Instance A CAs:"
"${AKAMUCTL_A[@]}" ca list
echo

echo "[demo] Instance B CAs:"
"${AKAMUCTL_B[@]}" ca list

# ── cross-sign ───────────────────────────────────────────────────────────────

section "Cross-signing CAs"

# Instance A (RSA) cross-signs Instance B's (EC) CA certificate
echo "[demo] Instance A (RSA) cross-signs Instance B (EC)..."
echo "[demo]   akamuctl ca cross-sign default --subject-cert $B_DIR/ca.cert.pem --validity-years 5"
"${AKAMUCTL_A[@]}" -o json ca cross-sign default \
    --subject-cert "$B_DIR/ca.cert.pem" \
    --validity-years 5
echo

# Instance B (EC) cross-signs Instance A's (RSA) CA certificate
echo "[demo] Instance B (EC) cross-signs Instance A (RSA)..."
echo "[demo]   akamuctl ca cross-sign default --subject-cert $A_DIR/ca.cert.pem --validity-years 5"
"${AKAMUCTL_B[@]}" -o json ca cross-sign default \
    --subject-cert "$A_DIR/ca.cert.pem" \
    --validity-years 5

# ── list and download cross-certificates ─────────────────────────────────────

section "Listing cross-certificates"

echo "[demo] Cross-certificates on instance A:"
"${AKAMUCTL_A[@]}" cross-cert list
echo

echo "[demo] Cross-certificates on instance B:"
"${AKAMUCTL_B[@]}" cross-cert list

# Download cross-certs
echo
echo "[demo] Downloading cross-certificates..."

# A signed B's CA → cross-cert stored on instance A
A_CROSS_ID=$("${AKAMUCTL_A[@]}" -o json cross-cert list | python3 -c "import sys,json; print(json.load(sys.stdin)['cross_certs'][0]['id'])")
[[ -n "$A_CROSS_ID" ]] || die "failed to extract cross-cert ID from instance A"
"${AKAMUCTL_A[@]}" cross-cert download "$A_CROSS_ID" -o "$TESTDIR/a-signs-b.pem"
echo "[demo]   A→B cross-cert: $TESTDIR/a-signs-b.pem"

# B signed A's CA → cross-cert stored on instance B
B_CROSS_ID=$("${AKAMUCTL_B[@]}" -o json cross-cert list | python3 -c "import sys,json; print(json.load(sys.stdin)['cross_certs'][0]['id'])")
[[ -n "$B_CROSS_ID" ]] || die "failed to extract cross-cert ID from instance B"
"${AKAMUCTL_B[@]}" cross-cert download "$B_CROSS_ID" -o "$TESTDIR/b-signs-a.pem"
echo "[demo]   B→A cross-cert: $TESTDIR/b-signs-a.pem"

# ── inspect cross-certificates ───────────────────────────────────────────────

section "Cross-certificate details"

echo "[demo] A→B cross-cert (RSA CA signs EC CA):"
openssl x509 -in "$TESTDIR/a-signs-b.pem" -noout -subject -issuer -dates \
    -ext basicConstraints,keyUsage
echo

echo "[demo] B→A cross-cert (EC CA signs RSA CA):"
openssl x509 -in "$TESTDIR/b-signs-a.pem" -noout -subject -issuer -dates \
    -ext basicConstraints,keyUsage

# ── issue end-entity certificates ────────────────────────────────────────────

section "Issuing end-entity certificates"

echo "[demo] Requesting certificate from instance A for dns:${A_DOMAIN}..."
"$AKAMU_CLI" issue \
    --server     "https://127.0.0.1:${A_PORT}" \
    --ca         default \
    --account-key "$TESTDIR/account-a.key.pem" \
    --out        "$TESTDIR/ee-a.cert.pem" \
    --challenge  http-01 \
    --http-port  "$A_HTTP_PORT" \
    --domain     "$A_DOMAIN" \
    --server-ca  "$A_DIR/ca.cert.pem"

echo "[demo] EE cert from A:"
openssl x509 -in "$TESTDIR/ee-a.cert.pem" -noout -subject -issuer -dates
echo

echo "[demo] Requesting certificate from instance B for dns:${B_DOMAIN}..."
"$AKAMU_CLI" issue \
    --server     "https://127.0.0.1:${B_PORT}" \
    --ca         default \
    --account-key "$TESTDIR/account-b.key.pem" \
    --out        "$TESTDIR/ee-b.cert.pem" \
    --challenge  http-01 \
    --http-port  "$B_HTTP_PORT" \
    --domain     "$B_DOMAIN" \
    --server-ca  "$B_DIR/ca.cert.pem"

echo "[demo] EE cert from B:"
openssl x509 -in "$TESTDIR/ee-b.cert.pem" -noout -subject -issuer -dates

# ── verify direct chains ─────────────────────────────────────────────────────

section "Verifying direct chains (EE → own CA)"

echo "[demo] EE-A → CA-A (direct):"
openssl verify -CAfile "$A_DIR/ca.cert.pem" "$TESTDIR/ee-a.cert.pem"
echo

echo "[demo] EE-B → CA-B (direct):"
openssl verify -CAfile "$B_DIR/ca.cert.pem" "$TESTDIR/ee-b.cert.pem"

# ── verify cross-signed chains ───────────────────────────────────────────────

section "Verifying cross-signed chains"

echo "[demo] Cross-signed chain verification:"
echo "[demo]   EE-A was issued by CA-A."
echo "[demo]   The B→A cross-cert (EC CA signs RSA CA) lets CA-B trust CA-A."
echo "[demo]   So: EE-A → CA-A (intermediate via B→A cross-cert) → CA-B (trusted root)"
echo

# Verify: EE from CA-A, trusted root = CA-B, intermediate = B-signs-A cross-cert
echo "[demo] EE-A → [B→A cross-cert] → CA-B root:"
openssl verify \
    -CAfile "$B_DIR/ca.cert.pem" \
    -untrusted "$TESTDIR/b-signs-a.pem" \
    "$TESTDIR/ee-a.cert.pem"
echo

# Verify: EE from CA-B, trusted root = CA-A, intermediate = A-signs-B cross-cert
echo "[demo] EE-B → [A→B cross-cert] → CA-A root:"
openssl verify \
    -CAfile "$A_DIR/ca.cert.pem" \
    -untrusted "$TESTDIR/a-signs-b.pem" \
    "$TESTDIR/ee-b.cert.pem"

# ── public discovery endpoint note ────────────────────────────────────────────

section "Public cross-certificate discovery"

# The GET /ca/{id}/cross-certs endpoint returns cross-certs where the
# specified CA is the *subject*.  In this demo both cross-signs use
# --subject-cert (external PEM), so subject_ca_id is null and the
# public endpoint returns an empty list.
#
# In a same-server multi-CA deployment (e.g. [[ca]] with id="rsa" and
# id="ec"), using --subject-ca-id would populate subject_ca_id and the
# cross-cert would appear on this unauthenticated endpoint.

echo "[demo] Note: GET /ca/default/cross-certs (public, unauthenticated) returns"
echo "[demo] cross-certs where the local CA is the *subject*.  Since this demo"
echo "[demo] cross-signs external PEM files (not same-server CAs), subject_ca_id"
echo "[demo] is null and the public endpoint returns an empty list."
echo "[demo]"
echo "[demo] The admin-authenticated 'akamuctl cross-cert list' shown above"
echo "[demo] lists all cross-certs regardless of subject_ca_id."

# ── summary ──────────────────────────────────────────────────────────────────

section "Demo complete"

echo "[demo] Summary:"
echo "[demo]   Instance A (RSA CA):  https://127.0.0.1:${A_PORT}"
echo "[demo]   Instance B (EC CA):   https://127.0.0.1:${B_PORT}"
echo "[demo]"
echo "[demo]   Cross-certificates:"
echo "[demo]     A→B: $TESTDIR/a-signs-b.pem  (RSA CA signed EC CA)"
echo "[demo]     B→A: $TESTDIR/b-signs-a.pem  (EC CA signed RSA CA)"
echo "[demo]"
echo "[demo]   End-entity certificates:"
echo "[demo]     EE-A: $TESTDIR/ee-a.cert.pem  (issued by RSA CA for $A_DOMAIN)"
echo "[demo]     EE-B: $TESTDIR/ee-b.cert.pem  (issued by EC CA for $B_DOMAIN)"
echo "[demo]"
echo "[demo]   Verification results:"
echo "[demo]     EE-A verified via CA-B root + B→A cross-cert  ✓"
echo "[demo]     EE-B verified via CA-A root + A→B cross-cert  ✓"
echo "[demo]"
echo "[demo] Working directory: $TESTDIR"
echo

if $INTERACTIVE; then
    echo "[demo] Press Ctrl-C to stop both servers."
    while true; do sleep 86400; done
else
    echo "[demo] Demo complete."
fi
