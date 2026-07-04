#!/usr/bin/env bash
# check-doc-toml.sh — validate TOML code blocks in documentation
#
# Extracts every ```toml fenced code block from docs/src/**/*.md and
# validates it with Python's tomllib.  Blocks that are clearly fragments
# (fewer than 2 non-empty lines, or containing placeholder syntax like
# <…>) are skipped automatically.
#
# Usage:
#   ./contrib/ci/check-doc-toml.sh          # run from the repo root
#
# Exit status:
#   0  all blocks parse (or are skipped)
#   1  one or more blocks contain invalid TOML
#
# Integration:
#   To add this check to local-ci.sh, register a new job that calls
#   this script.  It has no prerequisites and can run independently
#   alongside fmt or lint-workflows.

set -euo pipefail

# ── Locate repo root ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

DOCS_DIR="$REPO_ROOT/docs/src"

if [[ ! -d "$DOCS_DIR" ]]; then
    echo "error: docs/src/ not found at $DOCS_DIR" >&2
    exit 1
fi

# ── Require Python 3 with tomllib ─────────────────────────────────────────────
if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required but not found" >&2
    exit 1
fi

if ! python3 -c "import tomllib" 2>/dev/null; then
    echo "error: python3 tomllib module not available (requires Python 3.11+)" >&2
    exit 1
fi

# ── Run the validator ─────────────────────────────────────────────────────────
python3 -s - "$DOCS_DIR" <<'PYTHON_EOF'
"""Validate TOML code blocks extracted from Markdown documentation."""
import glob
import os
import re
import sys
import tomllib

docs_dir = sys.argv[1]
pattern = os.path.join(docs_dir, "**", "*.md")

errors = 0
checked = 0
skipped = 0

for filepath in sorted(glob.glob(pattern, recursive=True)):
    with open(filepath, encoding="utf-8") as fh:
        lines = fh.readlines()

    in_block = False
    block_start = 0
    block_lines: list[str] = []

    for lineno, line in enumerate(lines, start=1):
        stripped = line.rstrip("\n")

        if stripped.strip() == "```toml":
            in_block = True
            block_start = lineno
            block_lines = []
            continue

        if in_block and stripped.strip().startswith("```"):
            in_block = False
            block_text = "\n".join(block_lines)

            # Skip fragments: fewer than 2 non-empty lines
            non_empty = [l for l in block_lines if l.strip()]
            if len(non_empty) < 2:
                skipped += 1
                continue

            # Skip blocks with placeholder syntax (e.g. <profile-id>)
            if re.search(r"<[a-zA-Z][a-zA-Z0-9_-]*>", block_text):
                skipped += 1
                continue

            checked += 1
            try:
                tomllib.loads(block_text)
            except tomllib.TOMLDecodeError as exc:
                errors += 1
                relpath = os.path.relpath(filepath, os.path.dirname(docs_dir))
                print(f"FAIL docs/{relpath}:{block_start}: {exc}")
            continue

        if in_block:
            block_lines.append(stripped)

print(f"\nChecked {checked} TOML blocks, skipped {skipped} fragments, {errors} error(s).")
sys.exit(1 if errors else 0)
PYTHON_EOF
