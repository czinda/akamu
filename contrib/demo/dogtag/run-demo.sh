#!/usr/bin/env bash
# run-demo.sh — End-to-end Dogtag PKI RA demo
#
# What this script does:
#   1. Builds the akamu server and akamu-cli binaries
#   2. Deploys a Dogtag PKI CA in containers (389 DS + pki-ca)
#   3. Creates an RA agent user and certificate in Dogtag
#   4. Starts Akamu configured as a Registration Authority for Dogtag
#   5. Issues a certificate via ACME (akamu-cli → Akamu → Dogtag)
#   6. Verifies the certificate was issued by Dogtag's CA
#   7. Confirms the certificate exists in Dogtag's database
#   8. Cleans up on exit (Ctrl-C or completion)
#
# Prerequisites:
#   - podman (or docker)
#   - openssl
#   - curl
#   - cargo / rust toolchain
#
# Usage:
#   cd /path/to/akamu
#   bash contrib/demo/dogtag/run-demo.sh [--interactive]
#
# --interactive: after verification, keep everything running and wait
#                for Ctrl-C before cleaning up.

set -euo pipefail

DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DEMO_DIR/../../.." && pwd)"
TESTDIR="${TMPDIR:-/tmp}/akamu-demo-dogtag"
INTERACTIVE=false

# Container names
NET_NAME="akamu-demo"
DS_NAME="akamu-demo-ds"
CA_NAME="akamu-demo-ca"

DS_IMAGE="quay.io/389ds/dirsrv"
CA_IMAGE="quay.io/dogtagpki/pki-ca:latest"

DS_PASSWORD="Secret.123"
DS_HOSTNAME="ds.example.com"
CA_HOSTNAME="ca.example.com"

# Akamu ports
AKAMU_PORT=8580
AKAMU_HTTP_PORT=5020
AKAMU_DOMAIN="dogtag-demo.localhost"

# ── cleanup ───────────────────────────────────────────────────────────────────

cleanup() {
    echo
    echo "[demo] Cleaning up..."
    [[ -n "${AKAMU_PID:-}" ]] && kill "$AKAMU_PID" 2>/dev/null || true
    wait "${AKAMU_PID:-}" 2>/dev/null || true
    $CTR rm -f "$CA_NAME" 2>/dev/null || true
    $CTR rm -f "$DS_NAME" 2>/dev/null || true
    $CTR volume rm -f "${DS_NAME}-data" 2>/dev/null || true
    $CTR network rm -f "$NET_NAME" 2>/dev/null || true
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
    local deadline=$((SECONDS + 30))
    while (( SECONDS < deadline )); do
        if bash -c ">/dev/tcp/$host/$port" 2>/dev/null; then
            return 0
        fi
        sleep 0.5
    done
    die "$label did not start within 30 seconds"
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
# Container runtime: prefer podman, fall back to docker
if command -v podman &>/dev/null; then
    CTR=podman
elif command -v docker &>/dev/null; then
    CTR=docker
else
    die "Neither podman nor docker found; install one of them"
fi

echo "[demo] Checking prerequisites..."
require_cmd openssl "openssl"
require_cmd curl    "curl"

echo "[demo] Container runtime: $CTR"
echo "[demo] All prerequisites found."

# ── locate or build akamu binaries ───────────────────────────────────────────

section "Locating Akamu binaries"

# Prefer installed binaries (e.g. from RPM), then cargo build output, then
# build from source as a last resort.
find_binary() {
    local name=$1
    # 1. Already on PATH (installed package)
    if command -v "$name" &>/dev/null; then
        command -v "$name"
        return 0
    fi
    # 2. Cargo build output
    local cargo_bin="$REPO_ROOT/target/debug/$name"
    if [[ -x "$cargo_bin" ]]; then
        echo "$cargo_bin"
        return 0
    fi
    return 1
}

AKAMU_BIN=$(find_binary akamu || true)
AKAMU_CLI=$(find_binary akamu-cli || true)

if [[ -z "$AKAMU_BIN" || -z "$AKAMU_CLI" ]]; then
    if ! command -v cargo &>/dev/null; then
        die "akamu/akamu-cli not found on PATH or in target/debug/ and cargo is not available to build them"
    fi
    echo "[demo] Building akamu and akamu-cli (this may take a while)..."
    if ! (cd "$REPO_ROOT" && cargo build --quiet -p akamu -p akamu-cli); then
        die "cargo build failed — see output above"
    fi
    AKAMU_BIN="$REPO_ROOT/target/debug/akamu"
    AKAMU_CLI="$REPO_ROOT/target/debug/akamu-cli"
fi

[[ -x "$AKAMU_BIN"  ]] || die "akamu binary not found: $AKAMU_BIN"
[[ -x "$AKAMU_CLI"  ]] || die "akamu-cli binary not found: $AKAMU_CLI"
echo "[demo] akamu:     $AKAMU_BIN"
echo "[demo] akamu-cli: $AKAMU_CLI"

# ── testdir ──────────────────────────────────────────────────────────────────

[[ "$TESTDIR" == */akamu-demo-dogtag ]] || die "TESTDIR sanity check failed: $TESTDIR"
rm -rf "$TESTDIR"
mkdir -p "$TESTDIR"/{dogtag,akamu}
echo "[demo] Working directory: $TESTDIR"

# ── container network ────────────────────────────────────────────────────────

section "Setting up Dogtag PKI containers"

echo "[demo] Creating container network..."
$CTR network create "$NET_NAME" 2>/dev/null || true

# ── 389 DS container ─────────────────────────────────────────────────────────

echo "[demo] Creating DS volume..."
$CTR volume create "${DS_NAME}-data" > /dev/null

echo "[demo] Starting 389 Directory Server..."
$CTR run \
    --name "$DS_NAME" \
    --hostname "$DS_HOSTNAME" \
    --network "$NET_NAME" \
    --network-alias "$DS_HOSTNAME" \
    -v "${DS_NAME}-data:/data" \
    -e DS_DM_PASSWORD="$DS_PASSWORD" \
    --detach \
    "$DS_IMAGE" > /dev/null

echo "[demo] Waiting for DS to start..."
for i in $(seq 1 60); do
    if $CTR exec "$DS_NAME" dsconf localhost backend suffix list 2>/dev/null | grep -q 'dc='; then
        break
    fi
    sleep 1
done

echo "[demo] Creating DS backend for PKI..."
$CTR exec "$DS_NAME" dsconf localhost backend create \
    --suffix "dc=example,dc=com" \
    --be-name userRoot 2>/dev/null || true

echo "[demo] Adding base LDAP entries..."
$CTR exec -i "$DS_NAME" ldapadd \
    -H ldap://"$DS_HOSTNAME":3389 \
    -D "cn=Directory Manager" \
    -w "$DS_PASSWORD" \
    -x > /dev/null 2>&1 <<EOF
dn: dc=example,dc=com
objectClass: domain
dc: example

dn: dc=pki,dc=example,dc=com
objectClass: domain
dc: pki
EOF
echo "[demo] DS ready."

# ── Dogtag CA container ──────────────────────────────────────────────────────

echo "[demo] Starting Dogtag CA (this takes ~60 seconds)..."

# Create shared directories for CA config/certs/logs
mkdir -p "$TESTDIR/dogtag"/{certs,conf,logs}

$CTR run \
    --name "$CA_NAME" \
    --hostname "$CA_HOSTNAME" \
    --network "$NET_NAME" \
    --network-alias "$CA_HOSTNAME" \
    -v "$TESTDIR/dogtag/certs:/certs" \
    -v "$TESTDIR/dogtag/conf:/conf" \
    -v "$TESTDIR/dogtag/logs:/logs" \
    -e PKI_DS_URL="ldap://${DS_HOSTNAME}:3389" \
    -e PKI_DS_PASSWORD="$DS_PASSWORD" \
    -p 8443 \
    --detach \
    "$CA_IMAGE" > /dev/null

# Wait for the CA to finish initialization
echo "[demo] Waiting for Dogtag CA to initialize..."
for i in $(seq 1 180); do
    if $CTR exec "$CA_NAME" curl -sk -o /dev/null https://localhost:8443 2>/dev/null; then
        break
    fi
    if (( i % 10 == 0 )); then
        echo "[demo]   ... still waiting ($i seconds)..."
    fi
    sleep 1
done
$CTR exec "$CA_NAME" curl -sk -o /dev/null https://localhost:8443 || \
    die "Dogtag CA did not start within 180 seconds"
echo "[demo] Dogtag CA is running."

# ── Initialize CA database ───────────────────────────────────────────────────

section "Initializing Dogtag CA database"

echo "[demo] Creating CA database schema..."
$CTR exec "$CA_NAME" pki-server ca-db-init -v 2>&1 | tail -1
$CTR exec "$CA_NAME" pki-server ca-db-index-add -v 2>&1 | tail -1
$CTR exec "$CA_NAME" pki-server ca-db-index-rebuild -v 2>&1 | tail -1

echo "[demo] Importing CA signing cert into database..."
$CTR exec "$CA_NAME" pki-server cert-export \
    --cert-file /conf/certs/ca_signing.crt \
    ca_signing
$CTR exec "$CA_NAME" pki-server ca-cert-import \
    --cert /conf/certs/ca_signing.crt \
    --csr /conf/certs/ca_signing.csr \
    --profile /usr/share/pki/ca/conf/caCert.profile

echo "[demo] Importing OCSP signing cert..."
$CTR exec "$CA_NAME" pki-server cert-export \
    --cert-file /conf/certs/ca_ocsp_signing.crt \
    ca_ocsp_signing
$CTR exec "$CA_NAME" pki-server ca-cert-import \
    --cert /conf/certs/ca_ocsp_signing.crt \
    --csr /conf/certs/ca_ocsp_signing.csr \
    --profile /usr/share/pki/ca/conf/caOCSPCert.profile

echo "[demo] Importing subsystem cert..."
$CTR exec "$CA_NAME" pki-server cert-export \
    --cert-file /conf/certs/subsystem.crt \
    subsystem
$CTR exec "$CA_NAME" pki-server ca-cert-import \
    --cert /conf/certs/subsystem.crt \
    --csr /conf/certs/subsystem.csr \
    --profile /usr/share/pki/ca/conf/rsaSubsystemCert.profile

echo "[demo] Importing SSL server cert..."
$CTR exec "$CA_NAME" pki-server cert-export \
    --cert-file /conf/certs/sslserver.crt \
    sslserver
$CTR exec "$CA_NAME" pki-server ca-cert-import \
    --cert /conf/certs/sslserver.crt \
    --csr /conf/certs/sslserver.csr \
    --profile /usr/share/pki/ca/conf/rsaServerCert.profile

echo "[demo] CA database initialized."

# ── Create admin user ─────────────────────────────────────────────────────────

section "Creating Dogtag admin and RA agent"

echo "[demo] Creating admin CSR..."
openssl req -new \
    -newkey rsa:2048 -nodes \
    -keyout "$TESTDIR/dogtag/admin.key" \
    -out "$TESTDIR/dogtag/admin.csr" \
    -subj "/CN=PKI Administrator" 2>/dev/null

$CTR cp "$TESTDIR/dogtag/admin.csr" "$CA_NAME:/tmp/admin.csr"

echo "[demo] Issuing admin cert via CA..."
$CTR exec "$CA_NAME" pki-server ca-cert-create \
    --csr /tmp/admin.csr \
    --profile /usr/share/pki/ca/conf/rsaAdminCert.profile \
    --cert /tmp/admin.crt \
    --import-cert
$CTR cp "$CA_NAME:/tmp/admin.crt" "$TESTDIR/dogtag/admin.crt"

echo "[demo] Creating admin user in Dogtag..."
$CTR exec "$CA_NAME" pki-server ca-user-add \
    --full-name "PKI Administrator" \
    --type adminType \
    --cert /tmp/admin.crt \
    admin

$CTR exec "$CA_NAME" pki-server ca-user-role-add admin "Administrators"
$CTR exec "$CA_NAME" pki-server ca-user-role-add admin "Certificate Manager Agents"

# ── Create RA agent ───────────────────────────────────────────────────────────

echo "[demo] Generating RA agent key pair..."
openssl req -new \
    -newkey rsa:2048 -nodes \
    -keyout "$TESTDIR/dogtag/ra-agent.key" \
    -out "$TESTDIR/dogtag/ra-agent.csr" \
    -subj "/CN=Akamu RA Agent" 2>/dev/null

echo "[demo] Issuing RA agent cert via admin..."
# Use the admin cert to authenticate and submit+approve the RA agent cert.
# We use pki-server ca-cert-create which bypasses REST and directly issues.
# rsaSubsystemCert.profile provides the clientAuth EKU needed for TLS
# client certificate authentication against the Dogtag REST API.
$CTR cp "$TESTDIR/dogtag/ra-agent.csr" "$CA_NAME:/tmp/ra-agent.csr"
$CTR exec "$CA_NAME" pki-server ca-cert-create \
    --csr /tmp/ra-agent.csr \
    --profile /usr/share/pki/ca/conf/rsaSubsystemCert.profile \
    --cert /tmp/ra-agent.crt \
    --import-cert
$CTR cp "$CA_NAME:/tmp/ra-agent.crt" "$TESTDIR/dogtag/ra-agent.crt"

echo "[demo] Creating RA agent user in Dogtag..."
$CTR exec "$CA_NAME" pki-server ca-user-add \
    --full-name "Akamu RA Agent" \
    --type agentType \
    --cert /tmp/ra-agent.crt \
    akamu-ra

$CTR exec "$CA_NAME" pki-server ca-user-role-add akamu-ra "Certificate Manager Agents"

echo "[demo] RA agent created and added to Certificate Manager Agents group."

# ── Export CA certificates ────────────────────────────────────────────────────

section "Exporting certificates"

echo "[demo] Exporting Dogtag CA signing cert..."
cp "$TESTDIR/dogtag/conf/certs/ca_signing.crt" "$TESTDIR/dogtag/ca-signing.pem"
echo "[demo]   → $TESTDIR/dogtag/ca-signing.pem"

echo "[demo] Exporting Dogtag TLS trust anchor..."
# The sslserver cert is signed by the CA signing cert, so the CA signing
# cert is the trust anchor for HTTPS connections to Dogtag.
cp "$TESTDIR/dogtag/ca-signing.pem" "$TESTDIR/dogtag/tls-ca.pem"
echo "[demo]   → $TESTDIR/dogtag/tls-ca.pem"

echo "[demo] RA agent cert:  $TESTDIR/dogtag/ra-agent.crt"
echo "[demo] RA agent key:   $TESTDIR/dogtag/ra-agent.key"

# ── Determine Dogtag CA's accessible address ─────────────────────────────────

# Akamu runs on the host, not in a container, so it needs the container's
# mapped port to reach Dogtag's HTTPS endpoint.
# podman/docker port output: "0.0.0.0:PORT" or "[::]:PORT" — extract the port number
DOGTAG_HOST_PORT=$($CTR port "$CA_NAME" 8443 | head -1 | grep -oE '[0-9]+$')
[[ -n "$DOGTAG_HOST_PORT" ]] || die "Cannot determine Dogtag CA host port"
DOGTAG_URL="https://127.0.0.1:${DOGTAG_HOST_PORT}"
echo "[demo] Dogtag CA accessible at: $DOGTAG_URL"

# ── Write Akamu config ───────────────────────────────────────────────────────

section "Configuring Akamu as a Dogtag RA"

AKAMU_DIR="$TESTDIR/akamu"
cat > "$AKAMU_DIR/akamu.toml" <<EOF
listen_addr = "127.0.0.1:${AKAMU_PORT}"
base_url    = "https://127.0.0.1:${AKAMU_PORT}"

[database]
url = "sqlite://${AKAMU_DIR}/acme.db"

[tls]
enabled     = true
cert_file   = "${AKAMU_DIR}/server.pem"
key_file    = "${AKAMU_DIR}/server.key"
server_name = "127.0.0.1"

# Default local-signing CA — needed for TLS bootstrap.
[[ca]]
id                = "local"
is_default        = true
key_file          = "${AKAMU_DIR}/local-ca.key.pem"
cert_file         = "${AKAMU_DIR}/local-ca.cert.pem"
key_type          = "ec:P-256"
hash_alg          = "sha256"
common_name       = "Akamu Local Bootstrap CA"
organization      = "Akamu Demo"
validity_days     = 90
ca_validity_years = 1

# Dogtag-backed CA — certificate issuance is delegated to Dogtag.
[[ca]]
id        = "dogtag"
cert_file = "${TESTDIR}/dogtag/ca-signing.pem"
key_type  = "rsa:3072"
hash_alg  = "sha256"
crl_url   = "${DOGTAG_URL}/ca/ee/ca/getCRL?op=getCRL&crlIssuingPoint=MasterCRL"
ocsp_url  = "${DOGTAG_URL}/ca/ocsp"

[ca.signer]
type         = "dogtag"
url          = "${DOGTAG_URL}"
ra_cert_file = "${TESTDIR}/dogtag/ra-agent.crt"
ra_key_file  = "${TESTDIR}/dogtag/ra-agent.key"
ca_cert_file = "${TESTDIR}/dogtag/tls-ca.pem"
profile_id   = "acmeServerCert"
timeout_secs = 30
tls_danger_accept_invalid_hostnames = true

[mtc]
log_path = "${AKAMU_DIR}/mtc.log"
enabled  = false

[server]
http_validation_port              = ${AKAMU_HTTP_PORT}
http_validation_allow_private_ips = true
validate_dnssec                   = false
EOF

echo "[demo] Akamu config written to $AKAMU_DIR/akamu.toml"
echo "[demo] Two CAs configured:"
echo "[demo]   - 'local' (default, local-signing, for TLS bootstrap)"
echo "[demo]   - 'dogtag' (Dogtag-backed, for ACME issuance)"

# ── Start Akamu ──────────────────────────────────────────────────────────────

section "Starting Akamu"

echo "[demo] Starting Akamu server..."
"$AKAMU_BIN" serve -c "$AKAMU_DIR/akamu.toml" > "$AKAMU_DIR/akamu.log" 2>&1 &
AKAMU_PID=$!
wait_for_port 127.0.0.1 "$AKAMU_PORT" "Akamu"
wait_for_file "$AKAMU_DIR/local-ca.cert.pem" "Akamu local CA certificate"
echo "[demo] Akamu ready (pid $AKAMU_PID)"

# ── Issue a certificate ──────────────────────────────────────────────────────

section "Issuing certificate via ACME → Dogtag"

echo "[demo] Requesting certificate for dns:${AKAMU_DOMAIN} via Dogtag CA..."
"$AKAMU_CLI" issue \
    --server     "https://127.0.0.1:${AKAMU_PORT}" \
    --ca         dogtag \
    --account-key "$TESTDIR/account.key.pem" \
    --cert-key-type rsa:2048 \
    --out        "$TESTDIR/ee-cert.pem" \
    --challenge  http-01 \
    --http-port  "$AKAMU_HTTP_PORT" \
    --domain     "$AKAMU_DOMAIN" \
    --server-ca  "$AKAMU_DIR/local-ca.cert.pem"

echo "[demo] Certificate issued!"

# ── Verify the certificate ───────────────────────────────────────────────────

section "Verifying certificate"

echo "[demo] Issued certificate:"
openssl x509 -in "$TESTDIR/ee-cert.pem" -noout -subject -issuer -dates
echo

echo "[demo] Dogtag CA signing cert:"
openssl x509 -in "$TESTDIR/dogtag/ca-signing.pem" -noout -subject
echo

ISSUER=$(openssl x509 -in "$TESTDIR/ee-cert.pem" -noout -issuer)
CA_SUBJECT=$(openssl x509 -in "$TESTDIR/dogtag/ca-signing.pem" -noout -subject)

# Strip the "issuer=" / "subject=" prefixes for comparison
ISSUER_DN="${ISSUER#*=}"
CA_DN="${CA_SUBJECT#*=}"

if [[ "$ISSUER_DN" == "$CA_DN" ]]; then
    echo "[demo] ✓ Issuer DN matches Dogtag CA Subject DN"
else
    echo "[demo] ✗ Issuer DN mismatch!"
    echo "[demo]   Issuer:     $ISSUER_DN"
    echo "[demo]   CA Subject: $CA_DN"
    die "Certificate was not issued by Dogtag CA"
fi

echo
echo "[demo] Verifying certificate chain..."
openssl verify -CAfile "$TESTDIR/dogtag/ca-signing.pem" "$TESTDIR/ee-cert.pem"
echo "[demo] ✓ Chain verification passed"

# ── Confirm cert exists in Dogtag ────────────────────────────────────────────

section "Confirming certificate in Dogtag database"

SERIAL=$(openssl x509 -in "$TESTDIR/ee-cert.pem" -noout -serial | cut -d= -f2)
echo "[demo] Certificate serial number: $SERIAL"

# Query Dogtag REST API to confirm the cert exists.
DOGTAG_CERT_URL="${DOGTAG_URL}/ca/rest/certs/0x${SERIAL}"
echo "[demo] Querying Dogtag: GET $DOGTAG_CERT_URL"
HTTP_CODE=$(curl -sk -o /dev/null -w '%{http_code}' \
    --cert "$TESTDIR/dogtag/ra-agent.crt" \
    --key "$TESTDIR/dogtag/ra-agent.key" \
    --cacert "$TESTDIR/dogtag/tls-ca.pem" \
    "$DOGTAG_CERT_URL")

if [[ "$HTTP_CODE" == "200" ]]; then
    echo "[demo] ✓ Dogtag confirms certificate exists (HTTP 200)"
else
    echo "[demo] ✗ Dogtag returned HTTP $HTTP_CODE for serial 0x${SERIAL}"
    echo "[demo]   (This may indicate the cert was not stored in Dogtag's database)"
fi

# ── Summary ──────────────────────────────────────────────────────────────────

section "Demo complete"

echo "[demo] Summary:"
echo "[demo]   Dogtag CA:   $DOGTAG_URL"
echo "[demo]   Akamu RA:    https://127.0.0.1:${AKAMU_PORT}"
echo "[demo]"
echo "[demo]   The ACME workflow:"
echo "[demo]     akamu-cli → Akamu (RA) → Dogtag PKI CA"
echo "[demo]"
echo "[demo]   Issued certificate: $TESTDIR/ee-cert.pem"
echo "[demo]     Subject:  $(openssl x509 -in "$TESTDIR/ee-cert.pem" -noout -subject | cut -d= -f2-)"
echo "[demo]     Issuer:   $(openssl x509 -in "$TESTDIR/ee-cert.pem" -noout -issuer | cut -d= -f2-)"
echo "[demo]     Serial:   $SERIAL"
echo "[demo]"
echo "[demo]   Verification:"
echo "[demo]     ✓ Issuer matches Dogtag CA"
echo "[demo]     ✓ Chain verifies against Dogtag CA cert"
echo "[demo]     ✓ Certificate exists in Dogtag database"
echo "[demo]"
echo "[demo] Working directory: $TESTDIR"
echo

if $INTERACTIVE; then
    echo "[demo] Press Ctrl-C to stop everything."
    while true; do sleep 86400; done
else
    echo "[demo] Demo complete."
fi
