#!/bin/bash
# stack.sh — Lifecycle management for the hardened Akamu container stack.
#
# Usage:
#   ./contrib/containers/scripts/stack.sh start    Start the full hardened stack
#   ./contrib/containers/scripts/stack.sh stop     Stop all containers
#   ./contrib/containers/scripts/stack.sh restart   Stop then start
#   ./contrib/containers/scripts/stack.sh status    Show container and service status
#   ./contrib/containers/scripts/stack.sh logs [svc] Tail logs (default: akamu)
#   ./contrib/containers/scripts/stack.sh destroy   Stop and remove everything (volumes too)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
CONFIGS="$PROJECT_ROOT/contrib/containers/configs"

CONTAINERS=("cosigner-a" "cosigner-b" "akamu")
NETWORK="akamu-net"

cmd_start() {
    echo "Starting hardened Akamu stack..."
    echo ""

    podman network create "$NETWORK" 2>/dev/null || true

    echo "  → cosigner-a"
    podman run -d --name cosigner-a \
        --read-only \
        --tmpfs /tmp:size=32M,noexec,nosuid \
        --security-opt no-new-privileges:true \
        --cap-drop ALL \
        --user 1001:1001 \
        -v "$CONFIGS/cosigner-a.toml:/app/conf/cosigner.toml:ro" \
        -v cosigner-a-data:/app/data \
        --network "$NETWORK" \
        akamu-cosigner:hardened >/dev/null

    echo "  → cosigner-b"
    podman run -d --name cosigner-b \
        --read-only \
        --tmpfs /tmp:size=32M,noexec,nosuid \
        --security-opt no-new-privileges:true \
        --cap-drop ALL \
        --user 1001:1001 \
        -v "$CONFIGS/cosigner-b.toml:/app/conf/cosigner.toml:ro" \
        -v cosigner-b-data:/app/data \
        --network "$NETWORK" \
        akamu-cosigner:hardened >/dev/null

    echo "  → akamu"
    podman run -d --name akamu \
        --read-only \
        --tmpfs /tmp:size=64M,noexec,nosuid \
        --security-opt no-new-privileges:true \
        --cap-drop ALL \
        --user 1001:1001 \
        -v "$CONFIGS/akamu-server.toml:/app/conf/config.toml:ro" \
        -v akamu-data:/app/data \
        -p 8080:8080 \
        --network "$NETWORK" \
        akamu:hardened >/dev/null

    sleep 3
    echo ""
    cmd_status
}

cmd_stop() {
    echo "Stopping Akamu stack..."
    for ctr in "${CONTAINERS[@]}"; do
        podman stop "$ctr" 2>/dev/null && echo "  ■ $ctr stopped" || true
    done
    for ctr in "${CONTAINERS[@]}"; do
        podman rm "$ctr" 2>/dev/null || true
    done
    echo "Done."
}

cmd_status() {
    echo "════════════════════════════════════════"
    echo " Akamu Hardened Stack"
    echo "════════════════════════════════════════"
    echo ""

    for ctr in "${CONTAINERS[@]}"; do
        STATE=$(podman inspect "$ctr" --format '{{.State.Status}}' 2>/dev/null || echo "missing")
        case "$STATE" in
            running)  printf "  \033[32m●\033[0m %-14s running\n" "$ctr" ;;
            exited)   printf "  \033[31m●\033[0m %-14s exited\n" "$ctr" ;;
            *)        printf "  \033[90m○\033[0m %-14s %s\n" "$ctr" "$STATE" ;;
        esac
    done

    echo ""

    # Test ACME endpoint
    DIR=$(curl -sf http://localhost:8080/acme/directory 2>/dev/null || true)
    if echo "$DIR" | grep -q 'newAccount' 2>/dev/null; then
        printf "  \033[32m●\033[0m ACME endpoint   http://localhost:8080/acme/directory\n"
    else
        printf "  \033[31m●\033[0m ACME endpoint   not responding\n"
    fi

    echo ""
    echo "════════════════════════════════════════"
}

cmd_logs() {
    SVC="${1:-akamu}"
    podman logs -f "$SVC" 2>&1
}

cmd_destroy() {
    echo "Destroying Akamu stack (including volumes)..."
    cmd_stop
    for vol in akamu-data cosigner-a-data cosigner-b-data; do
        podman volume rm "$vol" 2>/dev/null && echo "  ✕ volume $vol removed" || true
    done
    podman network rm "$NETWORK" 2>/dev/null && echo "  ✕ network $NETWORK removed" || true
    echo "Done."
}

case "${1:-status}" in
    start)   cmd_start ;;
    stop)    cmd_stop ;;
    restart) cmd_stop; echo ""; cmd_start ;;
    status)  cmd_status ;;
    logs)    cmd_logs "${2:-}" ;;
    destroy) cmd_destroy ;;
    *)
        echo "Usage: $0 {start|stop|restart|status|logs [service]|destroy}"
        exit 1
        ;;
esac
