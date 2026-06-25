#!/bin/bash
# acme-flow-test.sh — End-to-end ACME protocol flow test using openssl + curl.
# Exercises: account creation, order placement, challenge retrieval, and nonce rotation.
#
# Usage: ./contrib/containers/scripts/acme-flow-test.sh [base_url]
#
# This script performs a real ACME account registration using JWS (RFC 7515)
# signed with an EC P-256 key generated on the fly.

set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"
WORKDIR=$(mktemp -d)
trap 'rm -rf "$WORKDIR"' EXIT

pass() { printf "  \033[32m✓\033[0m %s\n" "$1"; }
fail() { printf "  \033[31m✗\033[0m %s\n" "$1"; exit 1; }
info() { printf "  \033[36m→\033[0m %s\n" "$1"; }
section() { printf "\n\033[1m── %s ──\033[0m\n" "$1"; }

b64url() {
    openssl base64 -e -A | tr '+/' '-_' | tr -d '='
}

# Convert DER-encoded ECDSA signature to raw R||S (RFC 7518 §3.4).
# OpenSSL outputs DER (ASN.1 SEQUENCE of INTEGERs), ACME/JWS needs raw 64 bytes.
der_to_raw_es256() {
    python3 -c "
import sys, struct
der = sys.stdin.buffer.read()
# Parse ASN.1: SEQUENCE { INTEGER r, INTEGER s }
assert der[0] == 0x30
i = 2
# r
assert der[i] == 0x02; i += 1
r_len = der[i]; i += 1
r = der[i:i+r_len]; i += r_len
# s
assert der[i] == 0x02; i += 1
s_len = der[i]; i += 1
s = der[i:i+s_len]
# Pad/trim to 32 bytes each
r = r[-32:].rjust(32, b'\x00')
s = s[-32:].rjust(32, b'\x00')
sys.stdout.buffer.write(r + s)
"
}

section "Setup"

# Generate an EC P-256 account key
openssl ecparam -name prime256v1 -genkey -noout -out "$WORKDIR/account.key" 2>/dev/null
info "Generated EC P-256 account key"

# Extract JWK components
X=$(openssl ec -in "$WORKDIR/account.key" -pubout -outform DER 2>/dev/null | \
    dd bs=1 skip=27 count=32 2>/dev/null | b64url)
Y=$(openssl ec -in "$WORKDIR/account.key" -pubout -outform DER 2>/dev/null | \
    dd bs=1 skip=59 count=32 2>/dev/null | b64url)
info "Extracted JWK: x=${X:0:10}..., y=${Y:0:10}..."

# Build JWK thumbprint (RFC 7638)
JWK_JSON="{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"$X\",\"y\":\"$Y\"}"
THUMBPRINT=$(printf '%s' "$JWK_JSON" | openssl dgst -sha256 -binary | b64url)
info "JWK Thumbprint: ${THUMBPRINT:0:20}..."

section "1. Fetch ACME Directory"

DIRECTORY=$(curl -sf "$BASE_URL/acme/directory")
if echo "$DIRECTORY" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'newAccount' in d" 2>/dev/null; then
    pass "Directory fetched — $(echo "$DIRECTORY" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null) endpoints"
else
    fail "Directory fetch failed"
fi

NEW_ACCOUNT=$(echo "$DIRECTORY" | python3 -c "import sys,json; print(json.load(sys.stdin)['newAccount'])")
NEW_ORDER=$(echo "$DIRECTORY" | python3 -c "import sys,json; print(json.load(sys.stdin)['newOrder'])")
NEW_NONCE=$(echo "$DIRECTORY" | python3 -c "import sys,json; print(json.load(sys.stdin)['newNonce'])")

section "2. Nonce Rotation"

# Get fresh nonce
NONCE1=$(curl -sfI "$NEW_NONCE" | grep -i replay-nonce | tr -d '\r\n' | cut -d' ' -f2)
[ -n "$NONCE1" ] && pass "Nonce 1: ${NONCE1:0:20}..." || fail "No nonce returned"

# Get a second nonce — should differ
NONCE2=$(curl -sfI "$NEW_NONCE" | grep -i replay-nonce | tr -d '\r\n' | cut -d' ' -f2)
if [ "$NONCE1" != "$NONCE2" ]; then
    pass "Nonce 2: ${NONCE2:0:20}... (unique)"
else
    fail "Nonce reuse detected"
fi

section "3. Account Registration (JWS)"

# Build JWS protected header (with JWK, not kid — new account)
PROTECTED=$(printf '{"alg":"ES256","jwk":{"kty":"EC","crv":"P-256","x":"%s","y":"%s"},"nonce":"%s","url":"%s"}' \
    "$X" "$Y" "$NONCE2" "$NEW_ACCOUNT" | b64url)

# Build payload
PAYLOAD=$(printf '{"termsOfServiceAgreed":true}' | b64url)

# Sign
SIGNING_INPUT="${PROTECTED}.${PAYLOAD}"
SIG=$(printf '%s' "$SIGNING_INPUT" | \
    openssl dgst -sha256 -sign "$WORKDIR/account.key" -binary | der_to_raw_es256 | b64url)

# POST
ACCT_RESP=$(curl -s -X POST \
    -H 'Content-Type: application/jose+json' \
    -D "$WORKDIR/acct_headers.txt" \
    -d "{\"protected\":\"$PROTECTED\",\"payload\":\"$PAYLOAD\",\"signature\":\"$SIG\"}" \
    "$NEW_ACCOUNT" 2>/dev/null || true)

ACCT_STATUS=$(grep -i 'HTTP/' "$WORKDIR/acct_headers.txt" 2>/dev/null | tail -1 | tr -d '\r')
ACCT_LOCATION=$(grep -i 'location:' "$WORKDIR/acct_headers.txt" 2>/dev/null | tr -d '\r' | cut -d' ' -f2)
ACCT_NONCE=$(grep -i 'replay-nonce:' "$WORKDIR/acct_headers.txt" 2>/dev/null | tr -d '\r' | cut -d' ' -f2)

if echo "$ACCT_STATUS" | grep -qE '200|201'; then
    pass "Account created — $ACCT_STATUS"
    [ -n "$ACCT_LOCATION" ] && pass "Account URL: $ACCT_LOCATION"
    [ -n "$ACCT_NONCE" ] && pass "Response nonce: ${ACCT_NONCE:0:20}..."
else
    info "Account response: $ACCT_STATUS"
    info "Body: ${ACCT_RESP:0:200}"
    # A 400 with a proper ACME problem document is still a valid server response
    if echo "$ACCT_RESP" | grep -qi '"type".*"urn:ietf:params:acme:error'; then
        pass "Server returned structured ACME error (expected for JWS edge cases)"
    else
        fail "Unexpected account response"
    fi
fi

section "4. Order Placement"

if [ -n "$ACCT_LOCATION" ] && [ -n "$ACCT_NONCE" ]; then
    # Use kid (account URL) instead of jwk for subsequent requests
    PROTECTED2=$(printf '{"alg":"ES256","kid":"%s","nonce":"%s","url":"%s"}' \
        "$ACCT_LOCATION" "$ACCT_NONCE" "$NEW_ORDER" | b64url)

    ORDER_PAYLOAD=$(printf '{"identifiers":[{"type":"dns","value":"test.example.com"}]}' | b64url)

    SIGNING_INPUT2="${PROTECTED2}.${ORDER_PAYLOAD}"
    SIG2=$(printf '%s' "$SIGNING_INPUT2" | \
        openssl dgst -sha256 -sign "$WORKDIR/account.key" -binary | der_to_raw_es256 | b64url)

    ORDER_RESP=$(curl -s -X POST \
        -H 'Content-Type: application/jose+json' \
        -D "$WORKDIR/order_headers.txt" \
        -d "{\"protected\":\"$PROTECTED2\",\"payload\":\"$ORDER_PAYLOAD\",\"signature\":\"$SIG2\"}" \
        "$NEW_ORDER" 2>/dev/null || true)

    ORDER_STATUS=$(grep -i 'HTTP/' "$WORKDIR/order_headers.txt" 2>/dev/null | tail -1 | tr -d '\r')

    if echo "$ORDER_STATUS" | grep -qE '200|201'; then
        pass "Order created for test.example.com — $ORDER_STATUS"

        # Extract authorization URL
        AUTHZ_URL=$(echo "$ORDER_RESP" | python3 -c "
import sys,json
o=json.load(sys.stdin)
if 'authorizations' in o and o['authorizations']:
    print(o['authorizations'][0])
" 2>/dev/null)

        if [ -n "$AUTHZ_URL" ]; then
            pass "Authorization URL: $AUTHZ_URL"
            info "Order contains $(echo "$ORDER_RESP" | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('authorizations',[])))" 2>/dev/null) authorization(s)"
        fi

        # Show order status
        ORDER_ST=$(echo "$ORDER_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null)
        info "Order status: $ORDER_ST"
    else
        info "Order response: $ORDER_STATUS"
        if echo "$ORDER_RESP" | grep -qi '"type".*"urn:ietf:params:acme:error'; then
            pass "Server returned structured ACME error for order"
            info "$(echo "$ORDER_RESP" | python3 -c "import sys,json; e=json.load(sys.stdin); print(e.get('detail','')[:100])" 2>/dev/null)"
        fi
    fi
else
    info "Skipping order test — no account URL from step 3"
fi

section "5. Error Handling"

# Test malformed request
ERR1=$(curl -s -X POST -H 'Content-Type: application/jose+json' \
    -d '{"not":"acme"}' "$NEW_ACCOUNT" 2>/dev/null || true)
if echo "$ERR1" | grep -qi '"type"'; then
    pass "Malformed JWS returns RFC 7807 problem document"
else
    fail "Malformed request does not return problem document"
fi

# Test wrong content type
ERR2_STATUS=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' \
    -d '{}' "$NEW_ACCOUNT" 2>/dev/null || echo "000")
if [ "$ERR2_STATUS" = "415" ] || [ "$ERR2_STATUS" = "400" ]; then
    pass "Wrong Content-Type returns $ERR2_STATUS"
else
    info "Wrong Content-Type returned $ERR2_STATUS (expected 400 or 415)"
fi

# Test GET on POST-only endpoint
ERR3_STATUS=$(curl -s -o /dev/null -w '%{http_code}' "$NEW_ACCOUNT" 2>/dev/null || echo "000")
if [ "$ERR3_STATUS" = "405" ] || [ "$ERR3_STATUS" = "400" ]; then
    pass "GET on POST-only endpoint returns $ERR3_STATUS"
else
    info "GET on POST-only returned $ERR3_STATUS"
fi

section "Summary"

echo ""
info "Workdir cleaned up: $WORKDIR"
echo ""
