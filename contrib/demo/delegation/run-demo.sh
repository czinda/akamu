#!/usr/bin/env bash
# run-demo.sh — End-to-end RFC 9115 upstream delegation demo
#
# What this script does:
#   1. Builds the akamu server, akamu-cli, and akamuctl binaries
#   2. Starts a mock DNS server for dns-01 challenge validation
#   3. Starts two Akamu instances in two phases:
#        Phase 1: start without [delegation_upstream] to generate CA certs
#        Phase 2: restart with full config including cross-trust
#      - Instance A: RSA CA (port 8585), upstream → B
#      - Instance B: EC CA  (port 8586), upstream → A
#   4. Creates delegation objects on each server
#   5. NDC issues a cert through Server A with --delegation
#      → A's upstream task drives dns-01 on B → cert issued by B's CA
#   6. Verifies the cert issuer is Server B's CA
#   7. Repeats through Server B → cert issued by A's CA
#   8. Cleans up on exit
#
# Prerequisites:
#   - openssl, curl, cargo/rust, python3
#
# Usage:
#   cd /path/to/akamu
#   bash contrib/demo/delegation/run-demo.sh [--interactive]

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DEMO_DIR/../../.." && pwd)"
TESTDIR="${TMPDIR:-/tmp}/akamu-demo-delegation"
INTERACTIVE=false

# Instance A — RSA CA
readonly A_PORT=8585
readonly A_ADMIN_PORT=8595
readonly A_DOMAIN="deleg-a.example"

# Instance B — EC CA
readonly B_PORT=8586
readonly B_ADMIN_PORT=8596
readonly B_DOMAIN="deleg-b.example"

# Mock DNS
readonly DNS_PORT=5053
DNS_RECORDS_DIR=""

# ── cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    echo
    echo "[demo] Cleaning up..."
    [[ -n "${DNS_PID:-}" ]] && kill "$DNS_PID" 2>/dev/null || true
    [[ -n "${A_PID:-}" ]]   && kill "$A_PID"   2>/dev/null || true
    [[ -n "${B_PID:-}" ]]   && kill "$B_PID"   2>/dev/null || true
    wait "${DNS_PID:-}" 2>/dev/null || true
    wait "${A_PID:-}" 2>/dev/null || true
    wait "${B_PID:-}" 2>/dev/null || true
    echo "[demo] Done."
}
trap cleanup EXIT INT TERM

# ── helpers ───────────────────────────────────────────────────────────────────

die() { echo "[demo] ERROR: $*" >&2; exit 1; }

# Print certificate properties: subject, issuer, validity, SAN, AKI, SKI,
# serial, signature algorithm, and public key type/size.
show_cert() {
    local cert=$1 label=$2
    echo "[demo] ── $label ──"
    echo "[demo]   Subject:    $(openssl x509 -in "$cert" -noout -subject | sed 's/subject=//')"
    echo "[demo]   Issuer:     $(openssl x509 -in "$cert" -noout -issuer  | sed 's/issuer=//')"
    echo "[demo]   Serial:     $(openssl x509 -in "$cert" -noout -serial  | sed 's/serial=//')"
    echo "[demo]   Not Before: $(openssl x509 -in "$cert" -noout -startdate | sed 's/notBefore=//')"
    echo "[demo]   Not After:  $(openssl x509 -in "$cert" -noout -enddate   | sed 's/notAfter=//')"
    echo "[demo]   Sig Alg:    $(openssl x509 -in "$cert" -noout -text \
        | grep 'Signature Algorithm:' | head -1 | sed 's/.*Signature Algorithm: //')"
    echo "[demo]   Pub Key:    $(openssl x509 -in "$cert" -noout -text \
        | grep 'Public Key Algorithm:' | sed 's/.*Public Key Algorithm: //')"
    local san
    san=$(openssl x509 -in "$cert" -noout -ext subjectAltName 2>/dev/null \
        | { grep -v 'X509v3 Subject Alternative Name' || true; } | tr -d ' ')
    [[ -n "$san" ]] && echo "[demo]   SAN:        $san"
    local aki
    aki=$(openssl x509 -in "$cert" -noout -ext authorityKeyIdentifier 2>/dev/null \
        | { grep -v 'X509v3 Authority Key Identifier' || true; } | tr -d ' \n')
    [[ -n "$aki" ]] && echo "[demo]   AKI:        $aki"
    local ski
    ski=$(openssl x509 -in "$cert" -noout -ext subjectKeyIdentifier 2>/dev/null \
        | { grep -v 'X509v3 Subject Key Identifier' || true; } | tr -d ' \n')
    [[ -n "$ski" ]] && echo "[demo]   SKI:        $ski"
}

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

[[ "$TESTDIR" == */akamu-demo-delegation ]] || die "TESTDIR sanity check failed: $TESTDIR"
rm -rf "$TESTDIR"
mkdir -p "$TESTDIR"/{a,b}

DNS_RECORDS_DIR="$TESTDIR/dns-records"
mkdir -p "$DNS_RECORDS_DIR"
echo "[demo] Working directory: $TESTDIR"

# ── mock DNS ─────────────────────────────────────────────────────────────────

section "Starting mock DNS server"

python3 "$DEMO_DIR/mock_dns.py" --port "$DNS_PORT" --record-dir "$DNS_RECORDS_DIR" &
DNS_PID=$!
sleep 0.5
kill -0 "$DNS_PID" 2>/dev/null || die "mock DNS failed to start"
echo "[demo] Mock DNS ready (pid $DNS_PID, port $DNS_PORT)"

# ── dns-01 deploy/cleanup scripts ────────────────────────────────────────────
#
# The delegation_upstream module clears the environment before running these
# scripts, passing only CERTBOT_DOMAIN and CERTBOT_VALIDATION.  We must
# therefore hardcode the records directory path into the scripts.

A_DEPLOY="$TESTDIR/a/dns-deploy.sh"
A_CLEANUP="$TESTDIR/a/dns-cleanup.sh"
B_DEPLOY="$TESTDIR/b/dns-deploy.sh"
B_CLEANUP="$TESTDIR/b/dns-cleanup.sh"

cat > "$A_DEPLOY" <<SCRIPT
#!/usr/bin/env bash
[[ "\$CERTBOT_DOMAIN" == */* || "\$CERTBOT_DOMAIN" == *..* ]] && exit 1
echo "\$CERTBOT_VALIDATION" > "${DNS_RECORDS_DIR}/_acme-challenge.\${CERTBOT_DOMAIN}"
SCRIPT
chmod +x "$A_DEPLOY"

cat > "$A_CLEANUP" <<SCRIPT
#!/usr/bin/env bash
[[ "\$CERTBOT_DOMAIN" == */* || "\$CERTBOT_DOMAIN" == *..* ]] && exit 1
rm -f "${DNS_RECORDS_DIR}/_acme-challenge.\${CERTBOT_DOMAIN}"
SCRIPT
chmod +x "$A_CLEANUP"

cat > "$B_DEPLOY" <<SCRIPT
#!/usr/bin/env bash
[[ "\$CERTBOT_DOMAIN" == */* || "\$CERTBOT_DOMAIN" == *..* ]] && exit 1
echo "\$CERTBOT_VALIDATION" > "${DNS_RECORDS_DIR}/_acme-challenge.\${CERTBOT_DOMAIN}"
SCRIPT
chmod +x "$B_DEPLOY"

cat > "$B_CLEANUP" <<SCRIPT
#!/usr/bin/env bash
[[ "\$CERTBOT_DOMAIN" == */* || "\$CERTBOT_DOMAIN" == *..* ]] && exit 1
rm -f "${DNS_RECORDS_DIR}/_acme-challenge.\${CERTBOT_DOMAIN}"
SCRIPT
chmod +x "$B_CLEANUP"

echo "[demo] Deploy/cleanup scripts created."

# ── upstream account keys ────────────────────────────────────────────────────

section "Generating upstream account keys"

# Generate PKCS#8 EC P-256 keys (the format akamu-client expects).
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$TESTDIR/a/upstream-account.key" 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
    -out "$TESTDIR/b/upstream-account.key" 2>/dev/null
echo "[demo] Upstream account keys generated."

# ── Phase 1: start servers without delegation_upstream ───────────────────────

section "Phase 1: Starting servers to generate CA certificates"

# Instance A — minimal config (no delegation_upstream).
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
common_name   = "Delegation Demo RSA CA"
organization  = "Akamu Demo"
validity_days = 90

[server]
dns_resolver_addr                 = "127.0.0.1:${DNS_PORT}"
http_validation_allow_private_ips = true
validate_dnssec                   = false

[admin]
bootstrap_operator_pkcs12_file = "${A_DIR}/admin.p12"
EOF

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
key_type      = "ec:P-256"
common_name   = "Delegation Demo EC CA"
organization  = "Akamu Demo"
validity_days = 90

[server]
dns_resolver_addr                 = "127.0.0.1:${DNS_PORT}"
http_validation_allow_private_ips = true
validate_dnssec                   = false

[admin]
bootstrap_operator_pkcs12_file = "${B_DIR}/admin.p12"
EOF

echo "[demo] Starting instance A (RSA CA, port ${A_PORT})..."
"$AKAMU_BIN" serve -c "$A_DIR/akamu.toml" > "$A_DIR/akamu.log" 2>&1 &
A_PID=$!
wait_for_port 127.0.0.1 "$A_PORT" "instance A"
wait_for_file "$A_DIR/ca.cert.pem" "instance A CA cert"
echo "[demo] Instance A ready (pid $A_PID)"

echo "[demo] Starting instance B (EC CA, port ${B_PORT})..."
"$AKAMU_BIN" serve -c "$B_DIR/akamu.toml" > "$B_DIR/akamu.log" 2>&1 &
B_PID=$!
wait_for_port 127.0.0.1 "$B_PORT" "instance B"
wait_for_file "$B_DIR/ca.cert.pem" "instance B CA cert"
echo "[demo] Instance B ready (pid $B_PID)"

echo "[demo] Phase 1 complete — CA certificates generated."

# ── Phase 2: restart with delegation_upstream ────────────────────────────────

section "Phase 2: Restarting with delegation_upstream config"

# Stop both servers.
kill "$A_PID" 2>/dev/null; wait "$A_PID" 2>/dev/null || true; unset A_PID
kill "$B_PID" 2>/dev/null; wait "$B_PID" 2>/dev/null || true; unset B_PID
echo "[demo] Both servers stopped."

# Rewrite configs with [delegation_upstream] sections.
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
common_name   = "Delegation Demo RSA CA"
organization  = "Akamu Demo"
validity_days = 90

[server]
dns_resolver_addr                 = "127.0.0.1:${DNS_PORT}"
http_validation_allow_private_ips = true
validate_dnssec                   = false
delegation_enabled                = true

[admin]
bootstrap_operator_pkcs12_file = "${A_DIR}/admin.p12"

[delegation_upstream]
directory_url           = "https://127.0.0.1:${B_PORT}/acme/default/directory"
account_key_file        = "${A_DIR}/upstream-account.key"
challenge_solver        = "dns-01"
challenge_deploy_script = "${A_DEPLOY}"
challenge_cleanup_script = "${A_CLEANUP}"
poll_interval_secs      = 2
ca_cert_file            = "${B_DIR}/ca.cert.pem"
EOF

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
key_type      = "ec:P-256"
common_name   = "Delegation Demo EC CA"
organization  = "Akamu Demo"
validity_days = 90

[server]
dns_resolver_addr                 = "127.0.0.1:${DNS_PORT}"
http_validation_allow_private_ips = true
validate_dnssec                   = false
delegation_enabled                = true

[admin]
bootstrap_operator_pkcs12_file = "${B_DIR}/admin.p12"

[delegation_upstream]
directory_url           = "https://127.0.0.1:${A_PORT}/acme/default/directory"
account_key_file        = "${B_DIR}/upstream-account.key"
challenge_solver        = "dns-01"
challenge_deploy_script = "${B_DEPLOY}"
challenge_cleanup_script = "${B_CLEANUP}"
poll_interval_secs      = 2
ca_cert_file            = "${A_DIR}/ca.cert.pem"
EOF

echo "[demo] Starting instance A with delegation_upstream → B..."
"$AKAMU_BIN" serve -c "$A_DIR/akamu.toml" >> "$A_DIR/akamu.log" 2>&1 &
A_PID=$!
wait_for_port 127.0.0.1 "$A_PORT" "instance A"
echo "[demo] Instance A ready (pid $A_PID)"

echo "[demo] Starting instance B with delegation_upstream → A..."
"$AKAMU_BIN" serve -c "$B_DIR/akamu.toml" >> "$B_DIR/akamu.log" 2>&1 &
B_PID=$!
wait_for_port 127.0.0.1 "$B_PORT" "instance B"
echo "[demo] Instance B ready (pid $B_PID)"

echo "[demo] Phase 2 complete — both servers have delegation upstream."

# ── create delegation objects ────────────────────────────────────────────────

section "Creating delegation objects"

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

# Create a CSR template that allows any DNS name (wildcard pattern).
CSR_TEMPLATE="$TESTDIR/csr-template.json"
cat > "$CSR_TEMPLATE" <<'TMPL'
{
  "keyTypes": [
    {"type": "EC", "curve": "P-256"},
    {"type": "EC", "curve": "P-384"},
    {"type": "RSA", "keySize": 2048},
    {"type": "RSA", "keySize": 4096}
  ],
  "subject": {},
  "extensions": {
    "subjectAltName": {}
  }
}
TMPL

# We need ACME account IDs for the delegations.  akamu-cli issue auto-
# registers the account on first run; we trigger that registration by
# attempting a dummy issue that will fail (no delegation exists yet),
# then extract the account ID from the admin API.

# Pre-register NDC accounts by triggering a dummy issue that will fail
# after registration (delegation doesn't exist yet).  Parse the account
# URL from stdout to get the correct account ID.

echo "[demo] Pre-registering NDC account on instance A..."
NDC_A_REG=$("$AKAMU_CLI" issue \
    --server "https://127.0.0.1:${A_PORT}" --ca default \
    --account-key "$TESTDIR/ndc-a.key.pem" \
    --out "$TESTDIR/dummy-a.pem" --domain dummy.test \
    --server-ca "$A_DIR/ca.cert.pem" \
    --delegation "https://127.0.0.1:${A_PORT}/acme/delegation/nonexistent" \
    2>/dev/null || true)
NDC_A_ACCOUNT_ID=$(echo "$NDC_A_REG" | grep -o 'account/[0-9a-f-]*' | sed 's|account/||')
[[ -n "$NDC_A_ACCOUNT_ID" ]] || die "failed to extract NDC account ID from instance A"
echo "[demo] NDC account on A: $NDC_A_ACCOUNT_ID"

echo "[demo] Pre-registering NDC account on instance B..."
NDC_B_REG=$("$AKAMU_CLI" issue \
    --server "https://127.0.0.1:${B_PORT}" --ca default \
    --account-key "$TESTDIR/ndc-b.key.pem" \
    --out "$TESTDIR/dummy-b.pem" --domain dummy.test \
    --server-ca "$B_DIR/ca.cert.pem" \
    --delegation "https://127.0.0.1:${B_PORT}/acme/delegation/nonexistent" \
    2>/dev/null || true)
NDC_B_ACCOUNT_ID=$(echo "$NDC_B_REG" | grep -o 'account/[0-9a-f-]*' | sed 's|account/||')
[[ -n "$NDC_B_ACCOUNT_ID" ]] || die "failed to extract NDC account ID from instance B"
echo "[demo] NDC account on B: $NDC_B_ACCOUNT_ID"

echo "[demo] Creating delegation on instance A (account $NDC_A_ACCOUNT_ID)..."
DELEG_A_RESP=$("${AKAMUCTL_A[@]}" -o json delegation add \
    --account-id "$NDC_A_ACCOUNT_ID" \
    --csr-template "$CSR_TEMPLATE")
DELEG_A_ID=$(echo "$DELEG_A_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "[demo] Delegation A ID: $DELEG_A_ID"

echo "[demo] Creating delegation on instance B (account $NDC_B_ACCOUNT_ID)..."
DELEG_B_RESP=$("${AKAMUCTL_B[@]}" -o json delegation add \
    --account-id "$NDC_B_ACCOUNT_ID" \
    --csr-template "$CSR_TEMPLATE")
DELEG_B_ID=$(echo "$DELEG_B_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "[demo] Delegation B ID: $DELEG_B_ID"

# Build delegation URLs.
# When ca_id == default_ca_id the ACME prefix omits the CA segment.
DELEG_A_URL="https://127.0.0.1:${A_PORT}/acme/delegation/${DELEG_A_ID}"
DELEG_B_URL="https://127.0.0.1:${B_PORT}/acme/delegation/${DELEG_B_ID}"
echo "[demo] Delegation A URL: $DELEG_A_URL"
echo "[demo] Delegation B URL: $DELEG_B_URL"

# ── issue delegated certificate through Server A ─────────────────────────────

section "Issuing delegated certificate through Server A"

echo "[demo] NDC requests cert for ${A_DOMAIN} through Server A"
echo "[demo] → A's upstream task drives ACME on Server B (dns-01)"
echo "[demo] → cert will be issued by Server B's EC CA"
echo

"$AKAMU_CLI" issue \
    --server     "https://127.0.0.1:${A_PORT}" \
    --ca         default \
    --account-key "$TESTDIR/ndc-a.key.pem" \
    --out        "$TESTDIR/ee-via-a.cert.pem" \
    --domain     "$A_DOMAIN" \
    --server-ca  "$A_DIR/ca.cert.pem" \
    --delegation "$DELEG_A_URL" \
    --poll-timeout 120

echo
show_cert "$TESTDIR/ee-via-a.cert.pem" "EE certificate via Server A"
echo
show_cert "$B_DIR/ca.cert.pem" "Server B CA certificate (expected issuer)"

# Verify issuer is Server B's CA.
ISSUER_A=$(openssl x509 -in "$TESTDIR/ee-via-a.cert.pem" -noout -issuer)
CA_B_SUBJECT=$(openssl x509 -in "$B_DIR/ca.cert.pem" -noout -subject)
ISSUER_A_CN=$(echo "$ISSUER_A" | sed 's/issuer=//')
CA_B_CN=$(echo "$CA_B_SUBJECT" | sed 's/subject=//')
if [[ "$ISSUER_A_CN" == "$CA_B_CN" ]]; then
    echo "[demo] ✓ Issuer matches Server B's CA subject"
else
    echo "[demo] ✗ Unexpected issuer:"
    echo "[demo]   Got:      $ISSUER_A"
    echo "[demo]   Expected: $CA_B_SUBJECT"
    die "delegated cert has wrong issuer"
fi

# Verify AKI of EE cert matches SKI of issuing CA.
EE_A_AKI=$(openssl x509 -in "$TESTDIR/ee-via-a.cert.pem" -noout -ext authorityKeyIdentifier 2>/dev/null \
    | { grep -v 'X509v3 Authority Key Identifier' || true; } | tr -d ' \n' | sed 's/keyid://')
CA_B_SKI=$(openssl x509 -in "$B_DIR/ca.cert.pem" -noout -ext subjectKeyIdentifier 2>/dev/null \
    | { grep -v 'X509v3 Subject Key Identifier' || true; } | tr -d ' \n')
if [[ -n "$EE_A_AKI" && "$EE_A_AKI" == "$CA_B_SKI" ]]; then
    echo "[demo] ✓ EE AKI matches Server B CA SKI"
elif [[ -z "$EE_A_AKI" ]]; then
    echo "[demo] ⚠ EE certificate has no AKI extension (skipping check)"
else
    echo "[demo] ✗ AKI mismatch:"
    echo "[demo]   EE AKI:  $EE_A_AKI"
    echo "[demo]   CA SKI:  $CA_B_SKI"
    die "AKI does not match issuing CA's SKI"
fi

# Verify the EE cert signature chains to Server B's CA.
if openssl verify -CAfile "$B_DIR/ca.cert.pem" "$TESTDIR/ee-via-a.cert.pem" >/dev/null 2>&1; then
    echo "[demo] ✓ Signature verification against Server B's CA succeeded"
else
    die "EE cert via A fails signature verification against Server B's CA"
fi

# ── issue delegated certificate through Server B ─────────────────────────────

section "Issuing delegated certificate through Server B"

echo "[demo] NDC requests cert for ${B_DOMAIN} through Server B"
echo "[demo] → B's upstream task drives ACME on Server A (dns-01)"
echo "[demo] → cert will be issued by Server A's RSA CA"
echo

"$AKAMU_CLI" issue \
    --server     "https://127.0.0.1:${B_PORT}" \
    --ca         default \
    --account-key "$TESTDIR/ndc-b.key.pem" \
    --out        "$TESTDIR/ee-via-b.cert.pem" \
    --domain     "$B_DOMAIN" \
    --server-ca  "$B_DIR/ca.cert.pem" \
    --delegation "$DELEG_B_URL" \
    --poll-timeout 120

echo
show_cert "$TESTDIR/ee-via-b.cert.pem" "EE certificate via Server B"
echo
show_cert "$A_DIR/ca.cert.pem" "Server A CA certificate (expected issuer)"

# Verify issuer is Server A's CA.
ISSUER_B=$(openssl x509 -in "$TESTDIR/ee-via-b.cert.pem" -noout -issuer)
CA_A_SUBJECT=$(openssl x509 -in "$A_DIR/ca.cert.pem" -noout -subject)
ISSUER_B_CN=$(echo "$ISSUER_B" | sed 's/issuer=//')
CA_A_CN=$(echo "$CA_A_SUBJECT" | sed 's/subject=//')
if [[ "$ISSUER_B_CN" == "$CA_A_CN" ]]; then
    echo "[demo] ✓ Issuer matches Server A's CA subject"
else
    echo "[demo] ✗ Unexpected issuer:"
    echo "[demo]   Got:      $ISSUER_B"
    echo "[demo]   Expected: $CA_A_SUBJECT"
    die "delegated cert has wrong issuer"
fi

# Verify AKI of EE cert matches SKI of issuing CA.
EE_B_AKI=$(openssl x509 -in "$TESTDIR/ee-via-b.cert.pem" -noout -ext authorityKeyIdentifier 2>/dev/null \
    | { grep -v 'X509v3 Authority Key Identifier' || true; } | tr -d ' \n' | sed 's/keyid://')
CA_A_SKI=$(openssl x509 -in "$A_DIR/ca.cert.pem" -noout -ext subjectKeyIdentifier 2>/dev/null \
    | { grep -v 'X509v3 Subject Key Identifier' || true; } | tr -d ' \n')
if [[ -n "$EE_B_AKI" && "$EE_B_AKI" == "$CA_A_SKI" ]]; then
    echo "[demo] ✓ EE AKI matches Server A CA SKI"
elif [[ -z "$EE_B_AKI" ]]; then
    echo "[demo] ⚠ EE certificate has no AKI extension (skipping check)"
else
    echo "[demo] ✗ AKI mismatch:"
    echo "[demo]   EE AKI:  $EE_B_AKI"
    echo "[demo]   CA SKI:  $CA_A_SKI"
    die "AKI does not match issuing CA's SKI"
fi

# Verify the EE cert signature chains to Server A's CA.
if openssl verify -CAfile "$A_DIR/ca.cert.pem" "$TESTDIR/ee-via-b.cert.pem" >/dev/null 2>&1; then
    echo "[demo] ✓ Signature verification against Server A's CA succeeded"
else
    die "EE cert via B fails signature verification against Server A's CA"
fi

# ── summary ──────────────────────────────────────────────────────────────────

section "Demo complete"

echo "[demo] Summary:"
echo "[demo]   Instance A (RSA CA): https://127.0.0.1:${A_PORT}"
echo "[demo]     delegation_upstream → Instance B"
echo "[demo]   Instance B (EC CA):  https://127.0.0.1:${B_PORT}"
echo "[demo]     delegation_upstream → Instance A"
echo "[demo]"
echo "[demo]   Delegated certificates:"
echo "[demo]     via A: $TESTDIR/ee-via-a.cert.pem"
echo "[demo]       Subject: ${A_DOMAIN}, Issuer: B's EC CA  ✓"
echo "[demo]     via B: $TESTDIR/ee-via-b.cert.pem"
echo "[demo]       Subject: ${B_DOMAIN}, Issuer: A's RSA CA  ✓"
echo "[demo]"
echo "[demo] Working directory: $TESTDIR"
echo

if $INTERACTIVE; then
    echo "[demo] Press Ctrl-C to stop both servers."
    while true; do sleep 86400; done
else
    echo "[demo] Demo complete."
fi
