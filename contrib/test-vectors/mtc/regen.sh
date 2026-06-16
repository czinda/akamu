#!/bin/bash
# Regenerate MTC reference artifacts from the Go demo tool.
# Run this when mtc.json is updated or the spec version changes.
# Requires Go 1.21+ and internet access.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

echo "Cloning merkle-tree-certs repo..."
git clone --depth=1 https://github.com/ietf-plants-wg/merkle-tree-certs.git "$WORK_DIR/repo"

echo "Running Go demo tool..."
cd "$WORK_DIR/repo/demo"
go run . -config "$SCRIPT_DIR/mtc.json" -out "$SCRIPT_DIR/reference"

echo "Done. Reference artifacts written to $SCRIPT_DIR/reference/"
ls -la "$SCRIPT_DIR/reference/"
