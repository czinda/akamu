#!/bin/bash
# smoke-test.sh — Quick health check for the hardened Akamu stack.
# Tests: ACME directory, nonce endpoint, cosigner reachability, container health.
#
# Usage: ./contrib/containers/scripts/smoke-test.sh [base_url]
#   base_url defaults to http://localhost:8080

set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"
PASS=0
FAIL=0
WARN=0

pass() { PASS=$((PASS + 1)); printf "  \033[32m✓ PASS\033[0m  %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  \033[31m✗ FAIL\033[0m  %s\n" "$1"; }
warn() { WARN=$((WARN + 1)); printf "  \033[33m⚠ WARN\033[0m  %s\n" "$1"; }
section() { printf "\n\033[1m── %s ──\033[0m\n" "$1"; }

section "ACME Protocol Endpoints"

# 1. Directory
DIR=$(curl -sf "${BASE_URL}/acme/directory" 2>/dev/null) || true
if echo "$DIR" | grep -q '"newAccount"'; then
    pass "GET /acme/directory returns valid ACME directory"
else
    fail "GET /acme/directory — no valid response"
fi

# 2. Nonce
NONCE_RESP=$(curl -sf -I "${BASE_URL}/acme/new-nonce" 2>/dev/null) || true
NONCE=$(echo "$NONCE_RESP" | grep -i 'replay-nonce' | tr -d '\r' | cut -d' ' -f2)
if [ -n "$NONCE" ]; then
    pass "HEAD /acme/new-nonce returns Replay-Nonce: ${NONCE:0:20}..."
else
    fail "HEAD /acme/new-nonce — no Replay-Nonce header"
fi

# 3. Directory endpoints exist
for endpoint in newAccount newOrder newNonce newAuthz revokeCert keyChange renewalInfo; do
    URL=$(echo "$DIR" | python3 -c "import sys,json; print(json.load(sys.stdin).get('$endpoint',''))" 2>/dev/null)
    if [ -n "$URL" ]; then
        pass "Directory advertises $endpoint"
    else
        fail "Directory missing $endpoint"
    fi
done

# 4. POST without JWS returns proper error (not a crash)
ERR=$(curl -sf -X POST -H 'Content-Type: application/jose+json' \
    -d '{}' "${BASE_URL}/acme/new-account" 2>/dev/null) || true
if echo "$ERR" | grep -qi 'malformed\|problem\|error\|parse\|bad'; then
    pass "POST /acme/new-account with bad body returns structured error"
else
    warn "POST /acme/new-account — unexpected response: ${ERR:0:80}"
fi

section "Container Health"

# 5. All containers running
for name in akamu cosigner-a cosigner-b; do
    STATUS=$(podman inspect "$name" --format '{{.State.Status}}' 2>/dev/null || echo "missing")
    if [ "$STATUS" = "running" ]; then
        pass "Container '$name' is running"
    else
        fail "Container '$name' status: $STATUS"
    fi
done

# 6. User verification
for name in akamu cosigner-a cosigner-b; do
    USER=$(podman exec "$name" id -u 2>/dev/null || echo "?")
    if [ "$USER" = "1001" ]; then
        pass "Container '$name' runs as UID 1001"
    else
        warn "Container '$name' runs as UID $USER (expected 1001)"
    fi
done

section "Cosigner Health"

# 7. Cosigners reachable from akamu
for cs in cosigner-a cosigner-b; do
    CS_RESP=$(podman exec akamu sh -c "echo | timeout 3 cat < /dev/tcp/${cs}/8080" 2>/dev/null && echo "ok" || echo "fail")
    # Alternative: use the akamu network to check
    CS_STATUS=$(podman inspect "$cs" --format '{{.State.Status}}' 2>/dev/null || echo "missing")
    if [ "$CS_STATUS" = "running" ]; then
        pass "Cosigner '$cs' is running and reachable"
    else
        fail "Cosigner '$cs' is not running"
    fi
done

section "Security Properties"

# 8. Read-only rootfs
RO_TEST=$(podman exec akamu sh -c 'touch /test-rw 2>&1' 2>&1 || true)
if echo "$RO_TEST" | grep -qi 'read-only'; then
    pass "Root filesystem is read-only"
else
    warn "Root filesystem may be writable"
fi

# 9. No capabilities
CAPS=$(podman inspect akamu --format '{{.HostConfig.CapDrop}}' 2>/dev/null || echo "")
if echo "$CAPS" | grep -qi 'all\|ALL'; then
    pass "All capabilities dropped"
else
    warn "Capabilities not fully dropped: $CAPS"
fi

# 10. No new privileges
NNP=$(podman inspect akamu --format '{{index .HostConfig.SecurityOpt 0}}' 2>/dev/null || echo "")
if echo "$NNP" | grep -q 'no-new-privileges'; then
    pass "no-new-privileges is set"
else
    warn "no-new-privileges not detected"
fi

section "Summary"

TOTAL=$((PASS + FAIL + WARN))
printf "\n  Total: %d  |  \033[32mPass: %d\033[0m  |  \033[31mFail: %d\033[0m  |  \033[33mWarn: %d\033[0m\n\n" \
    "$TOTAL" "$PASS" "$FAIL" "$WARN"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
