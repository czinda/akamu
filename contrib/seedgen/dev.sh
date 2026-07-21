#!/usr/bin/env bash
# dev.sh — launch a seeded Akamu instance + the webui dev server.
#
# Usage:
#   ./contrib/seedgen/dev.sh <artifacts-dir>
#
# <artifacts-dir> is the directory produced by akamu-seedgen: it contains
# akamu.toml, ca-*/ca.key, ca-*/ca.crt, and the database lives one level up
# as <stem>.sqlite3.
#
# The script:
#   1. Validates the artifacts directory.
#   2. Builds the akamu binary if it is not present.
#   3. Starts akamu serve in the background (cwd = artifacts dir so that the
#      relative database path "../<stem>.sqlite3" resolves correctly).
#   4. Waits until akamu is accepting connections.
#   5. Exports AKAMU_SERVER_URL and starts the Vite dev server.
#   6. Kills akamu when Vite exits (Ctrl-C or otherwise).
#
# Environment variables (all optional):
#   AKAMU_BIN      Path to the akamu binary. Default: auto-detect or build.
#   AKAMU_LOG      Log filter for the akamu process. Default: warn.
#   VITE_PORT      Port for the Vite dev server. Default: 9000.

set -euo pipefail

# ── Argument handling ──────────────────────────────────────────────────────────

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <artifacts-dir>" >&2
    echo "" >&2
    echo "  <artifacts-dir>  directory produced by akamu-seedgen" >&2
    echo "                   (contains akamu.toml and ca-*/ subdirectories)" >&2
    exit 1
fi

if [[ ! -d "$1" ]]; then
    echo "error: '$1' is not a directory" >&2
    exit 1
fi

ARTIFACTS_DIR="$(cd "$1" && pwd)"   # absolute path
CONFIG="$ARTIFACTS_DIR/akamu.toml"

if [[ ! -f "$CONFIG" ]]; then
    echo "error: $CONFIG not found" >&2
    echo "  Run akamu-seedgen first:" >&2
    echo "    cargo run -p akamu-seedgen -- --output <name>.sqlite3" >&2
    exit 1
fi

# ── Locate repository root and paths ──────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
WEBUI_DIR="$REPO_ROOT/webui"

if [[ ! -d "$WEBUI_DIR" ]]; then
    echo "error: webui directory not found at $WEBUI_DIR" >&2
    exit 1
fi

# ── Locate or build the akamu binary ──────────────────────────────────────────

if [[ -n "${AKAMU_BIN:-}" ]]; then
    if [[ ! -x "$AKAMU_BIN" ]]; then
        echo "error: AKAMU_BIN='$AKAMU_BIN' is not executable" >&2
        exit 1
    fi
    AKAMU="$AKAMU_BIN"
elif [[ -x "$REPO_ROOT/target/debug/akamu" ]]; then
    AKAMU="$REPO_ROOT/target/debug/akamu"
elif [[ -x "$REPO_ROOT/target/release/akamu" ]]; then
    AKAMU="$REPO_ROOT/target/release/akamu"
else
    echo "akamu binary not found — building (debug)..."
    cargo build --bin akamu --manifest-path "$REPO_ROOT/Cargo.toml"
    AKAMU="$REPO_ROOT/target/debug/akamu"
fi

# ── Parse listen address from akamu.toml ──────────────────────────────────────
#
# The generated config always has a line like:
#   listen_addr = "0.0.0.0:8080"
# Extract the port so we can build AKAMU_SERVER_URL for the Vite proxy.

LISTEN_LINE="$(grep -E '^\s*listen_addr\s*=' "$CONFIG" | head -1)"
LISTEN_ADDR="$(echo "$LISTEN_LINE" | sed -E 's/.*=\s*"([^"]+)".*/\1/')"
PORT="${LISTEN_ADDR##*:}"

if [[ -z "$PORT" || ! "$PORT" =~ ^[0-9]+$ ]]; then
    echo "warning: could not parse port from listen_addr='$LISTEN_ADDR'; defaulting to 8080" >&2
    PORT=8080
fi

AKAMU_SERVER_URL="http://localhost:$PORT"

# ── Start akamu in the background ─────────────────────────────────────────────

AKAMU_PID=""

cleanup() {
    if [[ -n "$AKAMU_PID" ]]; then
        echo ""
        echo "stopping akamu (pid $AKAMU_PID)..."
        kill "$AKAMU_PID" 2>/dev/null || true
        wait "$AKAMU_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "==> artifacts:  $ARTIFACTS_DIR"
echo "==> database:   $(ls "$ARTIFACTS_DIR"/../*.sqlite3 2>/dev/null | head -1 || echo '(not found)')"
echo "==> akamu:      $AKAMU"
echo "==> listen:     $AKAMU_SERVER_URL"
echo ""
echo "starting akamu..."

(cd "$ARTIFACTS_DIR" && exec env RUST_LOG="${AKAMU_LOG:-warn}" "$AKAMU" serve -c "$CONFIG") \
    >"$ARTIFACTS_DIR/akamu.log" 2>&1 &
AKAMU_PID=$!

# ── Wait for akamu to accept connections ──────────────────────────────────────

ACME_DIR="$AKAMU_SERVER_URL/acme/directory"
TIMEOUT=30
ELAPSED=0

echo -n "waiting for akamu to be ready"
while ! curl -sf --max-time 1 "$ACME_DIR" >/dev/null 2>&1; do
    if ! kill -0 "$AKAMU_PID" 2>/dev/null; then
        echo ""
        echo "error: akamu exited unexpectedly — check $ARTIFACTS_DIR/akamu.log" >&2
        cat "$ARTIFACTS_DIR/akamu.log" >&2
        exit 1
    fi
    if (( ELAPSED >= TIMEOUT )); then
        echo ""
        echo "error: akamu did not become ready within ${TIMEOUT}s" >&2
        echo "  check $ARTIFACTS_DIR/akamu.log for details" >&2
        exit 1
    fi
    sleep 0.5
    ELAPSED=$(( ELAPSED + 1 ))
    echo -n "."
done
echo " ready"
echo ""

# ── Start the Vite dev server ──────────────────────────────────────────────────

cd "$WEBUI_DIR"

if [[ ! -d node_modules ]]; then
    echo "installing webui dependencies..."
    npm install
fi

echo "starting webui dev server (proxying /admin and /acme → $AKAMU_SERVER_URL)"
echo "  open http://localhost:${VITE_PORT:-9000}/ui/"
echo ""

AKAMU_SERVER_URL="$AKAMU_SERVER_URL" \
    npm run dev -- --port "${VITE_PORT:-9000}"
