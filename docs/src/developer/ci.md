# Local CI

`contrib/ci/local-ci.sh` runs the same checks that a GitHub Actions workflow
would run, in the same order, without needing a CI account or a push.  Use it
to catch failures before committing or to reproduce a CI failure locally.

## Quick start

```bash
# Run the full pipeline
./contrib/ci/local-ci.sh all

# Run only formatting and lint checks
./contrib/ci/local-ci.sh fmt clippy

# List available jobs
./contrib/ci/local-ci.sh --list
```

## Requirements

| Tool | Install |
|:-----|:--------|
| `cargo` | <https://rustup.rs/> |
| `rustfmt` | `rustup component add rustfmt` |
| `clippy` | `rustup component add clippy` |
| `mdbook` | `cargo install mdbook` (optional, for the `doc` job) |
| `actionlint` | <https://github.com/rhysd/actionlint> (optional, for `lint-workflows`) |
| `yamllint` | `pip install yamllint` (optional, fallback for `lint-workflows`) |

The script detects which optional tools are present at startup and skips or
degrades gracefully for any that are missing.

## Jobs

| Job | Command | Depends on |
|:----|:--------|:-----------|
| `build` | `cargo build --workspace` + `cargo build --benches` | — |
| `fmt` | `cargo fmt -- --check` | — |
| `clippy` | `cargo clippy -- -D warnings` | `build` |
| `doc` | `cargo doc --no-deps` + `mdbook build docs/` | `build` |
| `test` | `cargo test --features test-utils` | `build` |
| `bench` | `cargo build --benches` (compile-only) | `build` |
| `lint-workflows` | `actionlint` or `yamllint` on `.github/workflows/*.yml` | — |

The `bench` job only compiles the benchmark binary; it does not run any
issuance measurements.  Use `cargo bench --bench acme_bench` directly when you
want timing numbers (see [Performance](../user/performance.md)).

## Dependency graph

When you request a job whose prerequisite has not run yet, the script runs the
prerequisite automatically.  If the prerequisite fails, the dependent job is
skipped rather than attempted:

```
build ──┬── clippy
        ├── doc
        ├── test
        └── bench
```

`fmt` and `lint-workflows` have no prerequisites and can run independently.

## Options

| Option | Effect |
|:-------|:-------|
| `--no-color` | Disable ANSI colour output (also honoured via `NO_COLOR=1`) |
| `--no-deps` | Skip prerequisite auto-dispatch — intended for use inside an actual CI system where `needs:` already serialises the jobs |
| `--list` | Print available job names and exit |
| `--help` / `-h` | Show usage and exit |

## Environment variables

| Variable | Effect |
|:---------|:-------|
| `CARGO_TARGET_DIR` | Redirect Cargo build artefacts to an isolated directory |
| `NO_COLOR` | Set to `1` to disable ANSI colour output |

## Summary output

After all requested jobs finish the script prints a table:

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CI Summary
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  build                PASS  (22s)
  fmt                  PASS  (1s)
  clippy               PASS  (0s)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total time: 23s
All jobs passed.
```

The script exits with status 0 when all executed jobs pass and 1 if any job
fails.  Skipped jobs (due to a failed dependency) are shown as `SKIP` and do
not affect the exit status.

## Use inside CI workflows

The project is hosted on Codeberg and uses Forgejo Actions
(`.github/workflows/ci.yml`).  Each workflow job runs on a self-hosted
`vdali` runner inside the `quay.io/hummingbird/rust:latest-builder`
container image.  Required system packages (OpenSSL, SQLite, libldap,
Kerberos, clang, etc.) are installed via `dnf` at the start of each job.

When running a single job from within a workflow step, pass `--no-deps` so
the script does not re-run prerequisites that the workflow `needs:` graph has
already enforced:

```yaml
- name: Clippy
  run: ./contrib/ci/local-ci.sh --no-deps clippy
```

Without `--no-deps`, the script would automatically invoke `build` before
`clippy`, duplicating work that another job already performed.

## Example invocations

```bash
# Full pipeline
./contrib/ci/local-ci.sh all

# Only the fast checks (no compilation required)
./contrib/ci/local-ci.sh fmt lint-workflows

# Isolated build directory (keeps the main target/ clean)
CARGO_TARGET_DIR=/tmp/akamu-ci ./contrib/ci/local-ci.sh all

# CI-mode: run one job without triggering its prerequisites
./contrib/ci/local-ci.sh --no-deps test

# No colour output (e.g. when piping to a log file)
./contrib/ci/local-ci.sh --no-color all
```

## Documentation TOML validation

`contrib/ci/check-doc-toml.sh` extracts every `` ```toml `` fenced code block
from `docs/src/**/*.md` and validates it with Python's `tomllib`.  Blocks
that are clearly fragments (fewer than 2 non-empty lines, or containing
placeholder syntax like `<profile-id>`) are skipped automatically.

```bash
./contrib/ci/check-doc-toml.sh
```

Requires Python 3.11+ (for the built-in `tomllib` module).  The script exits
with status 0 when all checked blocks parse and 1 if any block contains
invalid TOML.  It can be integrated into `local-ci.sh` as a standalone job
with no prerequisites.
