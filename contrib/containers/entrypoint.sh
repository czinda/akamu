#!/bin/sh
# Hardened entrypoint for the Akamu ACME CA container.
# Performs pre-flight checks and forwards signals to the akamu process.
set -e

# ── Pre-flight checks ────────────────────────────────────────────────────────

# Verify the data directory is writable (catches read-only volume misconfigs).
if [ -d /app/data ] && ! touch /app/data/.entrypoint-probe 2>/dev/null; then
    echo "FATAL: /app/data is not writable — mount a writable volume" >&2
    exit 1
fi
rm -f /app/data/.entrypoint-probe

# Verify the config file exists.
CONFIG="${1:-/app/conf/config.toml}"
if [ ! -f "$CONFIG" ]; then
    echo "FATAL: config file '$CONFIG' not found" >&2
    echo "  Mount your config at /app/conf/config.toml or pass the path as an argument." >&2
    echo "  An example config is available at /app/conf/config.toml.example" >&2
    exit 1
fi

# ── Launch ────────────────────────────────────────────────────────────────────
# exec replaces this shell so signals (SIGTERM, SIGINT) go directly to akamu,
# enabling clean shutdown without the shell as an intermediary.
exec /app/akamu "$@"
