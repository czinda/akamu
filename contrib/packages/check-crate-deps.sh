#!/bin/bash
# check-crate-deps — query dnf repos for crates listed in a Cargo.lock
#
# Reads a Cargo.lock, extracts every crates.io registry dependency, then
# checks whether the matching crate() RPM provide is present in the currently
# configured dnf repositories.  Git and path (workspace) dependencies are
# skipped — they have no system RPM equivalent.
#
# Usage:
#   ./check-crate-deps.sh [Cargo.lock]
#   ./check-crate-deps.sh path/to/Cargo.lock
#
# Exit codes:
#   0  — all registry crates are available as system packages
#   1  — one or more crates are missing
#   2  — bad arguments / file not found

set -euo pipefail

LOCKFILE="${1:-Cargo.lock}"

if [[ ! -f "$LOCKFILE" ]]; then
    printf 'error: %s: file not found\n' "$LOCKFILE" >&2
    exit 2
fi

# ── 1. Parse Cargo.lock ───────────────────────────────────────────────────────
# The file is TOML; each package is a [[package]] section.  We only care about
# crates whose source starts with "registry+" (i.e. comes from crates.io).
# Git and path deps are silently skipped.
readarray -t CRATES < <(awk '
    /^\[\[package\]\]/ {
        if (name != "" && version != "" && registry)
            print name " " version
        name = ""; version = ""; registry = 0
        next
    }
    /^name = /              { sub(/^name = "/, ""); sub(/"$/, ""); name = $0 }
    /^version = /           { sub(/^version = "/, ""); sub(/"$/, ""); version = $0 }
    /^source = "registry\+/ { registry = 1 }
    END {
        if (name != "" && version != "" && registry)
            print name " " version
    }
' "$LOCKFILE" | sort -u)

total=${#CRATES[@]}
if [[ $total -eq 0 ]]; then
    printf 'No crates.io entries found in %s.\n' "$LOCKFILE"
    exit 0
fi

# ── 2. Fetch crate() provides from all configured repos (single dnf query) ────
# dnf repoquery --provides is run once and its output filtered to crate() lines.
# This is far faster than invoking dnf once per crate.
#
# A temp file is used rather than a shell variable because storing the result in
# a variable and then piping it through "printf '%s\n' "$var" | grep -qF ..." is
# broken under "set -o pipefail": grep -q exits as soon as it finds a match,
# which causes printf to receive SIGPIPE (exit 141).  pipefail then reports the
# pipeline as failed and the crate is incorrectly classified as missing.
# Reading directly from a file avoids that SIGPIPE path entirely.
printf 'Fetching crate() provides from dnf repos... '
_provides_tmp=$(mktemp -t check-crate-deps.XXXXXX)
trap 'rm -f "$_provides_tmp"' EXIT
dnf repoquery --provides --quiet 2>/dev/null \
    | grep '^crate(' | sort -u > "$_provides_tmp" || true
printf 'done (%d provides).\n\n' "$(wc -l < "$_provides_tmp")"

# ── 3. Check each crate ───────────────────────────────────────────────────────
printf 'Checking %d registry crates from %s:\n\n' "$total" "$LOCKFILE"

found=0
missing=0
declare -a missing_list=()

for entry in "${CRATES[@]}"; do
    name="${entry%% *}"
    ver="${entry##* }"
    provide="crate(${name}) = ${ver}"

    # grep -F: fixed-string match; the parentheses in "crate(NAME) = VER" make
    # accidental partial matches (e.g. crate(foo) vs crate(foobar)) impossible.
    if grep -qF "$provide" "$_provides_tmp"; then
        printf '  ok  %s\n' "$provide"
        found=$(( found + 1 ))
    else
        printf ' --- %s\n' "$provide"
        missing=$(( missing + 1 ))
        missing_list+=( "$provide" )
    fi
done

# ── 4. Summary ────────────────────────────────────────────────────────────────
printf '\n%d / %d crates available as system packages, %d missing.\n' \
    "$found" "$total" "$missing"

if [[ ${#missing_list[@]} -gt 0 ]]; then
    printf '\nNot available (require vendor tarball or new packaging):\n'
    printf '  %s\n' "${missing_list[@]}"
    exit 1
fi
