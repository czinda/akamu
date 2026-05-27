#!/usr/bin/env bash
# run-demo.sh — Full end-to-end tkauth-01 mixed-flow demo with Kerberos + ML-DSA-65
#
# What this script does:
#   1. Builds the akamu server and akamu-cli binaries
#   2. Creates a temporary Kerberos realm (via setup.py)
#   3. Generates a demo CA certificate
#   4. Starts mock_idp.py (ML-DSA-65 JWT issuer, SPNEGO auth)
#   5. Starts the akamu ACME server (tkauth-01 enabled, trusts mock IdP JWKS)
#   6. Registers an ACME account and requests a certificate via tkauth-01
#   7. The issued certificate contains both a DNS SAN and a KRB5PrincipalName
#      OtherName SAN derived from the JWTClaimConstraints token
#   8. Cleans up on exit (Ctrl-C or completion)
#
# Mixed-flow overview:
#   - The order contains a standard dns identifier ("demo.test").
#   - The IdP generates a JWTClaimConstraints blob with:
#       mustInclude:     [sub]          (principal MUST be in the JWT)
#       permittedValues: [dns=demo.test, sub=user@DEMO.TEST]
#   - akamu validates the dns authz via tkauth-01 (replaces http-01/dns-01),
#     stores the JCC blob in the JTI cache, and at finalization time:
#       • DNS SAN "demo.test"          — from the CSR (ordered identifier)
#       • KRB5PrincipalName OtherName  — from JCC permittedValues[sub] via krb5-kpn encoder
#
# Prerequisites:
#   - Kerberos utilities: krb5kdc, kdb5_util, kadmin.local  (krb5-server / krb5-workstation)
#   - Python 3.9+: gssapi, synta  (pip install gssapi synta)
#   - openssl 3.5+ (for ML-DSA-65 key generation by synta)
#   - cargo / rust toolchain
#
# Usage:
#   cd /path/to/akamu-rfc9447
#   bash contrib/demo/gssapi/run-demo.sh [--interactive]
#
# --interactive: after the certificate is issued, keep the KDC, IdP, and akamu
#                server running and wait for Ctrl-C before cleaning up.
#                Without this flag the script exits immediately after the cert
#                is written, which is suitable for automated testing.

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DEMO_DIR/../../.." && pwd)"
TESTDIR="${TMPDIR:-/tmp}/akamu-demo-gssapi"
DOMAIN="demo.test"          # ACME dns identifier the IdP will certify
IDP_PORT=9447
AKAMU_PORT=8555
AKAMU_CA_ID="default"       # akamu uses this as the per-CA URL segment
INTERACTIVE=false

export KRB5_TRACE=/dev/stderr

# ── cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    echo
    echo "[demo] Cleaning up..."
    [[ -n "${IDP_PID:-}"       ]] && kill "$IDP_PID"       2>/dev/null || true
    [[ -n "${AKAMU_PID:-}"     ]] && kill "$AKAMU_PID"     2>/dev/null || true
    # SIGTERM to setup.py — its atexit handler stops krb5kdc
    [[ -n "${KDC_SETUP_PID:-}" ]] && kill "$KDC_SETUP_PID" 2>/dev/null || true
    sleep 1
#    rm -rf "$TESTDIR"
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
require_cmd krb5kdc     "krb5-server"
require_cmd kdb5_util   "krb5-server"
require_cmd kadmin.local "krb5-server"
require_cmd openssl     "openssl"
require_cmd python3     "python3"
require_cmd cargo       "rustup / cargo"

python3 -c "import gssapi"  2>/dev/null || die "Python gssapi missing; pip install gssapi"
python3 -c "import synta"   2>/dev/null || die "Python synta missing; install from workspace"

echo "[demo] All prerequisites found."

# ── build ─────────────────────────────────────────────────────────────────────

echo "[demo] Building akamu and akamu-cli (this may take a while)..."
(cd "$REPO_ROOT" && cargo build --quiet -p akamu -p akamu-cli 2>&1) | tail -5
AKAMU_BIN="$REPO_ROOT/target/debug/akamu"
AKAMU_CLI="$REPO_ROOT/target/debug/akamu-cli"
[[ -x "$AKAMU_BIN"  ]] || die "akamu binary not found after build"
[[ -x "$AKAMU_CLI"  ]] || die "akamu-cli binary not found after build"
echo "[demo] Build complete."

# ── testdir ───────────────────────────────────────────────────────────────────

rm -rf "$TESTDIR"
mkdir -p "$TESTDIR"
echo "[demo] Working directory: $TESTDIR"

# ── Kerberos realm ────────────────────────────────────────────────────────────

echo "[demo] Starting KDC..."
ENV_FILE="$TESTDIR/kdc-env.sh"
python3 "$DEMO_DIR/setup.py" \
    --testdir "$TESTDIR/kdc" \
    --env-file "$ENV_FILE" &
KDC_SETUP_PID=$!

wait_for_file "$ENV_FILE" "KDC env file"
# shellcheck source=/dev/null
source "$ENV_FILE"
USER_KEYTAB="$DEMO_USER_KEYTAB"
IDP_KEYTAB="$DEMO_IDP_KEYTAB"

wait_for_port 127.0.0.1 62000 "KDC"
echo "[demo] KDC ready"

# ── CA certificate ────────────────────────────────────────────────────────────

echo "[demo] Demo certificates will be generated on Akamu start"
CA_KEY="$TESTDIR/ca.key.pem"
CA_CERT="$TESTDIR/ca.cert.pem"

# ── akamu server config ────────────────────────────────────────────────────────
#
# Profile: demo-tkauth
#   trust_jwks_urls   — the mock IdP's JWKS endpoint (kid+JWKS key path)
#
# claim_encoders:
#   dns  → dns-san    — verifies dns:demo.test via JCC permittedValues;
#                       offers tkauth-01 INSTEAD of http-01/dns-01 for dns identifiers
#   sub  → krb5-kpn   — injects permittedValues[sub] as a KRB5PrincipalName OtherName SAN

AKAMU_CFG="$TESTDIR/akamu.toml"
AKAMU_DB="$TESTDIR/acme.db"
cat > "$AKAMU_CFG" <<EOF
listen_addr = "127.0.0.1:${AKAMU_PORT}"
base_url    = "https://127.0.0.1:${AKAMU_PORT}"

[database]
url = "sqlite://${AKAMU_DB}"

[tls]
enabled = true
cert_file     = "${TESTDIR}/server.pem"
key_file      = "${TESTDIR}/server.key"
server_name   = "127.0.0.1"

[tls.client_auth]
required      = false
allow_post_quantum = true
ca_files      = ["${CA_CERT}"]

[ca]
key_file      = "${CA_KEY}"
cert_file     = "${CA_CERT}"
key_type      = "ml-dsa-87"
validity_days = 30
ca_validity_years = 1

[mtc]
log_path = "${TESTDIR}/mtc.log"

[server]
http_validation_allow_private_ips = true
validate_dnssec = false

[tkauth]
enabled = true
trusted_ta_ca_files = ["${CA_CERT}"]

# dns-san encoder: akamu will offer tkauth-01 INSTEAD OF http-01/dns-01 for
# dns identifiers.  The JCC permittedValues[dns] constrains which names are
# allowed; those already in the order are added to the cert via the CSR.
[[tkauth.claim_encoders]]
claim   = "dns"
encoder = "dns-san"

# krb5-kpn encoder: permittedValues[sub] with exactly one value is encoded as
# a KRB5PrincipalName OtherName SAN in the issued certificate.
[[tkauth.claim_encoders]]
claim   = "sub"
encoder = "krb5-kpn"

[profiles]
[profiles.providers.local]
type = "builtin"

[profiles.providers.local.profiles.demo-tkauth]
description     = "Demo tkauth-01 mixed-flow profile"
validity_days   = 30
eku             = ["server_auth"]
trust_jwks_urls = ["http://127.0.0.1:${IDP_PORT}/jwks"]

[admin]
bootstrap_key_type = "ec:P-256"
bootstrap_operator_pkcs12_file     = "${TESTDIR}/admin-bootstrap.p12"
bootstrap_operator_pkcs12_password = "demo"
bootstrap_operator_gssapi_principal = "user@DEMO.TEST"

[admin.gssapi]
keytab_file  = "${IDP_KEYTAB}"
service_name = "HTTP"
EOF
echo "[demo] akamu config written to $AKAMU_CFG"

# ── mock IdP ──────────────────────────────────────────────────────────────────

echo "[demo] Starting mock Token Authority (port ${IDP_PORT})..."
python3 "$DEMO_DIR/mock_idp.py" \
    --port "$IDP_PORT" \
    --domain "$DOMAIN" \
    --idp-keytab "$IDP_KEYTAB" \
    > "$TESTDIR/idp.log" 2>&1 &
IDP_PID=$!

DEADLINE=$((SECONDS + 20))
while (( SECONDS < DEADLINE )); do
    grep -q "READY" "$TESTDIR/idp.log" 2>/dev/null && break
    sleep 0.2
done
grep -q "READY" "$TESTDIR/idp.log" || die "mock_idp.py did not start; see $TESTDIR/idp.log"
echo "[demo] Mock IdP ready (pid $IDP_PID)"

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
CERT_OUT="$TESTDIR/demo.cert.pem"
ACME_DIR="https://127.0.0.1:${AKAMU_PORT}/acme/${AKAMU_CA_ID}/directory"

# Obtain a TGT for the demo user so akamu-cli can acquire GSSAPI credentials.
echo "[demo] Obtaining Kerberos TGT for demo user..."
KRB5_CONFIG="$KRB5_CONFIG" KRB5CCNAME="$KRB5CCNAME" \
    kinit -k -t "$USER_KEYTAB" "user@DEMO.TEST"
echo "[demo] TGT acquired"

echo "[demo] Requesting certificate for dns:${DOMAIN} via tkauth-01 (mixed-flow)..."
echo "[demo]   ACME directory:  ${ACME_DIR}"
echo "[demo]   Token Authority: http://127.0.0.1:${IDP_PORT}/at/account/1/token"
echo "[demo]   User keytab:     ${USER_KEYTAB}"
echo "[demo]   Profile:         demo-tkauth"
echo

# The order uses a standard dns identifier.  Because the akamu server has a
# dns-san claim encoder configured, it offers tkauth-01 instead of http-01.
# akamu-cli fetches a JWTClaimConstraints authority token from the mock IdP
# (SPNEGO-authenticated), then triggers the tkauth-01 challenge.
#
# The IdP generates a JCC blob with:
#   mustInclude:     [sub]                    — principal MUST be in the JWT
#   permittedValues: [dns=demo.test,          — authorises the dns identifier
#                     sub=user@DEMO.TEST]     — constrains the principal value
#
# akamu stores the JCC blob in the JTI cache.  At finalization:
#   DNS SAN "demo.test"           — from the CSR (the ordered dns identifier)
#   KRB5PrincipalName OtherName   — from JCC permittedValues[sub] via krb5-kpn

KRB5_CONFIG="$KRB5_CONFIG" KRB5CCNAME="$KRB5CCNAME" \
"$AKAMU_CLI" issue \
    --server      "https://127.0.0.1:${AKAMU_PORT}" \
    --ca          "$AKAMU_CA_ID" \
    --account-key "$ACCOUNT_KEY" \
    --out         "$CERT_OUT" \
    --challenge   tkauth-01 \
    --domain      "$DOMAIN" \
    --tkauth-url  "http://127.0.0.1:${IDP_PORT}/at/account/1/token" \
    --tkauth-keytab "$USER_KEYTAB" \
    --server-ca   "$CA_CERT" \
    --profile     demo-tkauth

echo
echo "[demo] ================================================"
echo "[demo] Certificate issued successfully!"
echo "[demo] Written to: ${CERT_OUT}"
echo
openssl x509 -in "$CERT_OUT" -noout -text 2>/dev/null \
    | grep -E "Subject:|Issuer:|Not Before:|Not After :|DNS:|URI:|other|Serial|krb5|Algorithm:|CURVE:" || true
echo "[demo] ================================================"
echo
echo "[demo] Tip: inspect the full cert with:"
echo "[demo]   openssl x509 -in ${CERT_OUT} -noout -text"
echo
echo "[demo] Admin bootstrap PKCS#12: ${TESTDIR}/admin-bootstrap.p12"
echo "[demo]   password: demo  (use this when importing into Firefox)"
echo
if $INTERACTIVE; then
    echo "[demo] Demo complete. Press Ctrl-C to stop the KDC, IdP, and akamu server."
    sleep infinity
else
    echo "[demo] Demo complete."
fi
