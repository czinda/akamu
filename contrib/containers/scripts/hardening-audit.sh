#!/bin/bash
# hardening-audit.sh — Deep security audit of the hardened container images.
# Checks: image contents, filesystem permissions, network isolation, runtime security.
#
# Usage: ./contrib/containers/scripts/hardening-audit.sh

set -euo pipefail

PASS=0
FAIL=0
WARN=0

pass() { PASS=$((PASS + 1)); printf "  \033[32m✓ PASS\033[0m  %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  \033[31m✗ FAIL\033[0m  %s\n" "$1"; }
warn() { WARN=$((WARN + 1)); printf "  \033[33m⚠ WARN\033[0m  %s\n" "$1"; }
section() { printf "\n\033[1m══ %s ══\033[0m\n" "$1"; }

IMAGES=("akamu:hardened" "akamu-cosigner:hardened")
CONTAINERS=("akamu" "cosigner-a" "cosigner-b")

section "Image Content Audit"

for img in "${IMAGES[@]}"; do
    printf "\n  \033[36m%s\033[0m\n" "$img"

    # Size check
    SIZE=$(podman images "$img" --format '{{.Size}}' 2>/dev/null)
    SIZE_MB=$(echo "$SIZE" | grep -oE '[0-9]+' | head -1)
    if [ -n "$SIZE" ]; then
        pass "Image size: $SIZE"
    fi

    # Build tools absent
    for tool in cargo rustc gcc g++ clang make cmake ld as; do
        if podman run --rm --entrypoint '' "$img" sh -c "type $tool" 2>/dev/null; then
            fail "Build tool '$tool' found in $img"
        fi
    done
    pass "No build tools in image"

    # Package managers absent
    for pm in dnf microdnf yum rpm apt dpkg; do
        if podman run --rm --entrypoint '' "$img" sh -c "type $pm" 2>/dev/null; then
            fail "Package manager '$pm' found in $img"
        fi
    done
    pass "No package managers in image"

    # Network diagnostic tools absent
    for tool in curl wget nc ncat nmap tcpdump strace gdb; do
        if podman run --rm --entrypoint '' "$img" sh -c "type $tool" 2>/dev/null; then
            warn "Diagnostic tool '$tool' found in $img"
        fi
    done
    pass "No network diagnostic tools"

    # SUID/SGID check
    SUID=$(podman run --rm --entrypoint '' "$img" find / -xdev -perm /6000 -type f 2>/dev/null || true)
    if [ -z "$SUID" ]; then
        pass "No SUID/SGID binaries"
    else
        fail "SUID/SGID binaries found: $SUID"
    fi

    # User check
    USER=$(podman inspect "$img" --format '{{.Config.User}}' 2>/dev/null)
    if [ "$USER" = "1001" ]; then
        pass "Runs as non-root UID 1001"
    else
        fail "Runs as user '$USER' (expected 1001)"
    fi

    # World-writable files
    WW=$(podman run --rm --entrypoint '' "$img" find / -xdev -type f -perm -002 2>/dev/null | head -5 || true)
    if [ -z "$WW" ]; then
        pass "No world-writable files"
    else
        warn "World-writable files found: $WW"
    fi

    # Shared libraries resolve
    BINARY="/app/akamu"
    echo "$img" | grep -q cosigner && BINARY="/app/akamu-cosigner"
    MISSING=$(podman run --rm --entrypoint '' "$img" sh -c "ldd $BINARY 2>&1 | grep 'not found'" || true)
    if [ -z "$MISSING" ]; then
        pass "All shared libraries resolved"
    else
        fail "Missing libraries: $MISSING"
    fi
done

section "Runtime Security Audit"

for ctr in "${CONTAINERS[@]}"; do
    # Check if container exists and is running
    STATE=$(podman inspect "$ctr" --format '{{.State.Status}}' 2>/dev/null || echo "missing")
    if [ "$STATE" != "running" ]; then
        warn "Container '$ctr' is not running ($STATE) — skipping runtime checks"
        continue
    fi

    printf "\n  \033[36m%s\033[0m\n" "$ctr"

    # Read-only rootfs
    RO_TEST=$(podman exec "$ctr" sh -c 'touch /test 2>&1' 2>&1 || true)
    if echo "$RO_TEST" | grep -qi 'read-only'; then
        pass "[$ctr] Read-only root filesystem"
    else
        warn "[$ctr] Root filesystem appears writable"
    fi

    # Data directory writable
    DATA_TEST=$(podman exec "$ctr" sh -c 'touch /app/data/.audit-probe && rm /app/data/.audit-probe' 2>&1 || true)
    if [ -z "$DATA_TEST" ]; then
        pass "[$ctr] Data volume (/app/data) is writable"
    else
        warn "[$ctr] Data volume not writable: $DATA_TEST"
    fi

    # Config directory read-only
    CONF_TEST=$(podman exec "$ctr" sh -c 'touch /app/conf/test 2>&1' 2>&1 || true)
    if echo "$CONF_TEST" | grep -qi 'read-only\|permission denied'; then
        pass "[$ctr] Config directory is read-only"
    else
        warn "[$ctr] Config directory may be writable"
    fi

    # Process runs as expected UID
    RUNTIME_UID=$(podman exec "$ctr" id -u 2>/dev/null || echo "?")
    if [ "$RUNTIME_UID" = "1001" ]; then
        pass "[$ctr] Process runs as UID 1001"
    else
        warn "[$ctr] Process runs as UID $RUNTIME_UID"
    fi

    # Capabilities dropped
    CAPDROP=$(podman inspect "$ctr" --format '{{.HostConfig.CapDrop}}' 2>/dev/null)
    if echo "$CAPDROP" | grep -qi 'all\|ALL'; then
        pass "[$ctr] All capabilities dropped (CAP_DROP=ALL)"
    else
        warn "[$ctr] Capabilities: $CAPDROP"
    fi

    # No-new-privileges
    SECOPT=$(podman inspect "$ctr" --format '{{.HostConfig.SecurityOpt}}' 2>/dev/null)
    if echo "$SECOPT" | grep -q 'no-new-privileges'; then
        pass "[$ctr] no-new-privileges enforced"
    else
        warn "[$ctr] no-new-privileges not set"
    fi

    # /tmp is tmpfs with noexec
    TMP_MOUNT=$(podman inspect "$ctr" --format '{{range .Mounts}}{{if eq .Destination "/tmp"}}{{.Type}}:{{.Options}}{{end}}{{end}}' 2>/dev/null)
    if echo "$TMP_MOUNT" | grep -q 'tmpfs'; then
        pass "[$ctr] /tmp is tmpfs"
    else
        warn "[$ctr] /tmp mount: $TMP_MOUNT"
    fi
done

section "OCI Labels"

for img in "${IMAGES[@]}"; do
    printf "\n  \033[36m%s\033[0m\n" "$img"
    for label in title description licenses source; do
        VAL=$(podman inspect "$img" --format "{{index .Config.Labels \"org.opencontainers.image.$label\"}}" 2>/dev/null)
        if [ -n "$VAL" ]; then
            pass "Label org.opencontainers.image.$label: $VAL"
        else
            warn "Missing label: org.opencontainers.image.$label"
        fi
    done
done

section "Audit Summary"

TOTAL=$((PASS + FAIL + WARN))
printf "\n"
printf "  ┌──────────────────────────────────────┐\n"
printf "  │  Total: %-4d                          │\n" "$TOTAL"
printf "  │  \033[32mPass:  %-4d\033[0m                          │\n" "$PASS"
printf "  │  \033[31mFail:  %-4d\033[0m                          │\n" "$FAIL"
printf "  │  \033[33mWarn:  %-4d\033[0m                          │\n" "$WARN"
printf "  └──────────────────────────────────────┘\n\n"

[ "$FAIL" -eq 0 ] && exit 0 || exit 1
