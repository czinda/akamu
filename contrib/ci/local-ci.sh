#!/usr/bin/env bash
# local-ci.sh — run the Akāmu CI pipeline locally
#
# Usage:
#   ./contrib/ci/local-ci.sh all              # run all jobs in order
#   ./contrib/ci/local-ci.sh build fmt clippy # run specific jobs
#   ./contrib/ci/local-ci.sh --list           # print available job names
#   ./contrib/ci/local-ci.sh --no-color all   # disable ANSI colours
#   CARGO_TARGET_DIR=/tmp/akamu ./contrib/ci/local-ci.sh all

# Require bash 4+
if [ "${BASH_VERSINFO:-0}" -lt 4 ]; then
    echo "error: bash 4 or later is required (you have ${BASH_VERSION:-unknown})" >&2
    exit 1
fi

set -euo pipefail

# ── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

if [[ "${NO_COLOR:-}" == "1" ]]; then
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

# ── Flag parsing ──────────────────────────────────────────────────────────────
NO_DEPS=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-color)
            RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
            shift ;;
        --no-deps)
            NO_DEPS=1
            shift ;;
        *) break ;;
    esac
done

# ── Locate repo root ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [[ ! -f "$REPO_ROOT/Cargo.toml" ]]; then
    echo "error: Cargo.toml not found — run from the repository root or contrib/ci/" >&2
    exit 1
fi

cd "$REPO_ROOT"

if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    export CARGO_TARGET_DIR
    echo -e "${CYAN}Using CARGO_TARGET_DIR=${CARGO_TARGET_DIR}${NC}"
fi

export CARGO_TERM_COLOR=always
export RUSTDOCFLAGS="-D warnings"

# ── Tool detection ────────────────────────────────────────────────────────────
has_cargo=0
has_rustfmt=0
has_clippy=0
has_mdbook=0
has_mdbook_pandoc=0
has_actionlint=0
has_yamllint=0

detect_tools() {
    echo -e "${BOLD}${CYAN}Tool availability check:${NC}"

    if command -v cargo >/dev/null 2>&1; then
        has_cargo=1
        echo -e "  ${GREEN}✓${NC} cargo $(cargo --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} cargo (install from https://rustup.rs/)"
    fi

    if cargo fmt --version >/dev/null 2>&1; then
        has_rustfmt=1
        echo -e "  ${GREEN}✓${NC} rustfmt $(cargo fmt --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} rustfmt (install with: rustup component add rustfmt)"
    fi

    if cargo clippy --version >/dev/null 2>&1; then
        has_clippy=1
        echo -e "  ${GREEN}✓${NC} clippy $(cargo clippy --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} clippy (install with: rustup component add clippy)"
    fi

    if command -v mdbook >/dev/null 2>&1; then
        has_mdbook=1
        echo -e "  ${GREEN}✓${NC} mdbook $(mdbook --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} mdbook (optional, install with: cargo install mdbook)"
    fi

    if command -v mdbook-pandoc >/dev/null 2>&1; then
        has_mdbook_pandoc=1
        echo -e "  ${GREEN}✓${NC} mdbook-pandoc (found)"
    else
        echo -e "  ${YELLOW}○${NC} mdbook-pandoc (optional, for PDF output — cargo install mdbook-pandoc)"
    fi

    if command -v actionlint >/dev/null 2>&1; then
        has_actionlint=1
        echo -e "  ${GREEN}✓${NC} actionlint $(actionlint --version 2>/dev/null | head -n1 || echo '')"
    else
        echo -e "  ${YELLOW}○${NC} actionlint (optional, for workflow linting — https://github.com/rhysd/actionlint)"
    fi

    if command -v yamllint >/dev/null 2>&1; then
        has_yamllint=1
        echo -e "  ${GREEN}✓${NC} yamllint $(yamllint --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} yamllint (optional, fallback for workflow linting)"
    fi

    echo ""
}

if [[ "${1:-}" != "--list" && "${1:-}" != "--help" && "${1:-}" != "-h" && $# -gt 0 ]]; then
    detect_tools
fi

# ── Job tracking ──────────────────────────────────────────────────────────────
declare -A JOB_STATUS=()
declare -A JOB_SECS=()
FAILED_JOBS=()

ALL_JOBS=(build fmt clippy doc test bench lint-workflows)

# Mirrors the dependency ordering that would be expressed via 'needs:' in a
# GitHub Actions workflow.  When --no-deps is NOT set, a job whose prerequisite
# failed or was skipped is itself skipped rather than executed.
declare -A JOB_DEPS=(
    [clippy]="build"
    [doc]="build"
    [test]="build"
    [bench]="build"
)

# ── Utilities ─────────────────────────────────────────────────────────────────
step() { echo -e "\n${BOLD}${BLUE}▶ $*${NC}"; }
ok()   { echo -e "${GREEN}✔  $*${NC}"; }
fail() { echo -e "${RED}✘  $*${NC}"; }
warn() { echo -e "${YELLOW}!  $*${NC}"; }

run_job() {
    local name="$1"
    shift

    # Ensure prerequisites have been executed; skip this job if any dep failed.
    # Skipped when --no-deps is set (useful inside GitHub Actions where the
    # workflow already enforces ordering via 'needs:').
    if [[ "$NO_DEPS" == "0" ]]; then
        local dep
        for dep in ${JOB_DEPS[$name]:-}; do
            if [[ -z "${JOB_STATUS[$dep]:-}" ]]; then
                dispatch_job "$dep"
            fi
            if [[ "${JOB_STATUS[$dep]}" != "PASS" ]]; then
                JOB_STATUS[$name]="SKIP"
                warn "[$name] skipped — '$dep' did not pass"
                return 0
            fi
        done
    fi

    local t0; t0=$(date +%s)
    step "[$name]"
    if "$@"; then
        local t1; t1=$(date +%s)
        JOB_STATUS[$name]="PASS"
        JOB_SECS[$name]=$((t1 - t0))
        ok "[$name] passed (${JOB_SECS[$name]}s)"
    else
        local t1; t1=$(date +%s)
        JOB_STATUS[$name]="FAIL"
        JOB_SECS[$name]=$((t1 - t0))
        FAILED_JOBS+=("$name")
        fail "[$name] FAILED (${JOB_SECS[$name]}s)"
    fi
}

# ── Job implementations ───────────────────────────────────────────────────────

job_build() {
    if [[ "$has_cargo" -eq 0 ]]; then
        fail "cargo not found (install from https://rustup.rs/)"; return 1
    fi

    echo "Building workspace (debug)…"
    cargo build --workspace || return 1

    echo "Building bench binaries…"
    cargo build --benches
}

job_fmt() {
    if [[ "$has_cargo" -eq 0 ]]; then
        fail "cargo not found"; return 1
    fi
    if [[ "$has_rustfmt" -eq 0 ]]; then
        fail "rustfmt not found (install with: rustup component add rustfmt)"; return 1
    fi

    echo "Checking formatting…"
    cargo fmt -- --check
}

job_clippy() {
    if [[ "$has_cargo" -eq 0 ]]; then
        fail "cargo not found"; return 1
    fi
    if [[ "$has_clippy" -eq 0 ]]; then
        fail "clippy not found (install with: rustup component add clippy)"; return 1
    fi

    echo "Running Clippy…"
    cargo clippy -- -D warnings
}

job_doc() {
    if [[ "$has_cargo" -eq 0 ]]; then
        fail "cargo not found"; return 1
    fi

    echo "Building rustdoc…"
    cargo doc --no-deps || return 1

    if [[ "$has_mdbook" -eq 0 ]]; then
        warn "mdbook not found — skipping book build (install with: cargo install mdbook)"
        return 0
    fi

    echo "Building mdBook…"
    if [[ "$has_mdbook_pandoc" -eq 0 ]]; then
        warn "mdbook-pandoc not found — building without PDF output (install with: cargo install mdbook-pandoc)"
        local BOOK_TOML="docs/book.toml"
        local BOOK_BAK="${BOOK_TOML}.ci-bak"
        python3 -c "
import re, sys, shutil
shutil.copy('${BOOK_TOML}', '${BOOK_BAK}')
content = open('${BOOK_TOML}').read()
content = re.sub(r'\n\[output\.pandoc[^\n]*\].*?(?=\n\[(?!output\.pandoc)|\Z)', '', content, flags=re.DOTALL)
open('${BOOK_TOML}', 'w').write(content)
"
        local rc=0
        mdbook build docs/ || rc=$?
        mv "${BOOK_BAK}" "${BOOK_TOML}"
        return $rc
    fi
    mdbook build docs/
}

job_test() {
    if [[ "$has_cargo" -eq 0 ]]; then
        fail "cargo not found"; return 1
    fi

    echo "Running test suite…"
    cargo test --features test-utils
}

job_bench() {
    if [[ "$has_cargo" -eq 0 ]]; then
        fail "cargo not found"; return 1
    fi

    # Compile-only: ensures the bench binary stays buildable without the
    # wall-clock overhead of running the full issuance benchmark.
    echo "Compiling bench binary (compile-only check)…"
    cargo build --benches
    ok "bench binary compiles successfully"
}

job_lint_workflows() {
    echo "Validating GitHub Actions workflow files…"

    local workflows=()
    while IFS= read -r -d '' f; do
        workflows+=("$f")
    done < <(find .github/workflows -name '*.yml' -print0 2>/dev/null)

    if [[ ${#workflows[@]} -eq 0 ]]; then
        warn "No workflow files found in .github/workflows/ — skipping"
        return 0
    fi

    echo "Found ${#workflows[@]} workflow file(s)"

    if [[ "$has_actionlint" -eq 1 ]]; then
        echo "Using actionlint…"
        actionlint "${workflows[@]}"
        return
    fi

    warn "actionlint not found — falling back to yamllint (install from: https://github.com/rhysd/actionlint)"

    if [[ "$has_yamllint" -eq 1 ]]; then
        yamllint \
            -d "{extends: default, rules: {truthy: disable, line-length: {max: 120}}}" \
            "${workflows[@]}"
        return
    fi

    warn "yamllint not found — skipping workflow validation"
    warn "Install actionlint: https://github.com/rhysd/actionlint"
    warn "Install yamllint:   pip install yamllint"
}

# ── Dispatch table ────────────────────────────────────────────────────────────
dispatch_job() {
    case "$1" in
        build)          run_job build          job_build ;;
        fmt)            run_job fmt            job_fmt ;;
        clippy)         run_job clippy         job_clippy ;;
        doc)            run_job doc            job_doc ;;
        test)           run_job test           job_test ;;
        bench)          run_job bench          job_bench ;;
        lint-workflows) run_job lint-workflows job_lint_workflows ;;
        *)
            echo "Unknown job: $1" >&2
            echo "Run '$0 --list' for available jobs." >&2
            exit 1
            ;;
    esac
}

# ── Summary ───────────────────────────────────────────────────────────────────
print_summary() {
    local total_start="$1"
    local total_end; total_end=$(date +%s)

    echo
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}CI Summary${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    local job
    for job in "${ALL_JOBS[@]}"; do
        local status="${JOB_STATUS[$job]:-}"
        [[ -z "$status" ]] && continue
        local secs="${JOB_SECS[$job]:-0}"
        if [[ "$status" == "PASS" ]]; then
            printf "  ${GREEN}%-20s PASS${NC}  (%ds)\n" "$job" "$secs"
        elif [[ "$status" == "FAIL" ]]; then
            printf "  ${RED}%-20s FAIL${NC}  (%ds)\n" "$job" "$secs"
        else
            printf "  ${YELLOW}%-20s SKIP${NC}  (dep failed)\n" "$job"
        fi
    done

    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "Total time: $((total_end - total_start))s"

    if [[ ${#FAILED_JOBS[@]} -gt 0 ]]; then
        echo -e "${RED}${BOLD}FAILED: ${FAILED_JOBS[*]}${NC}"
        return 1
    else
        echo -e "${GREEN}${BOLD}All jobs passed.${NC}"
        return 0
    fi
}

# ── Help ──────────────────────────────────────────────────────────────────────
print_help() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <job> [job ...]

Run Akāmu CI jobs locally.

Special targets:
  all          Run every job in order

Available jobs:
  build          cargo build --workspace + bench binaries
  fmt            cargo fmt --all -- --check
  clippy         cargo clippy -- -D warnings
  doc            cargo doc --no-deps [+ mdbook build docs/]
  test           cargo test
  bench          compile bench binary (no measurements)
  lint-workflows actionlint / yamllint on .github/workflows/*.yml

Options:
  --list         Print available job names and exit
  --no-color     Disable ANSI colour output (also: NO_COLOR=1)
  --no-deps      Skip automatic prerequisite dispatching.  Use inside
                 a CI system that already enforces ordering via 'needs:'.

Environment:
  CARGO_TARGET_DIR   Redirect Cargo build output to an isolated directory.
  NO_COLOR           Set to 1 to disable ANSI colour output.

Examples:
  $(basename "$0") all
  $(basename "$0") build test
  $(basename "$0") --no-color all
  $(basename "$0") --no-deps clippy
  CARGO_TARGET_DIR=/tmp/akamu-ci $(basename "$0") all
EOF
}

# ── Entry point ───────────────────────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
    print_help
    exit 0
fi

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' all "${ALL_JOBS[@]}"
    exit 0
fi

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    print_help
    exit 0
fi

REQUESTED_JOBS=()
for arg in "$@"; do
    if [[ "$arg" == "all" ]]; then
        REQUESTED_JOBS+=("${ALL_JOBS[@]}")
    else
        REQUESTED_JOBS+=("$arg")
    fi
done

T0=$(date +%s)

for job in "${REQUESTED_JOBS[@]}"; do
    dispatch_job "$job"
done

print_summary "$T0"
