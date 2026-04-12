# Contributing

This chapter describes the conventions for code style, commit messages, and the pull request process for `Akāmu`.

## Running CI locally

Before pushing, verify the pipeline locally with `contrib/ci/local-ci.sh`:

```bash
./contrib/ci/local-ci.sh all
```

This runs the same jobs the CI system runs: build, fmt, clippy, doc, test,
bench (compile-only), and workflow linting.  See [Local CI](ci.md) for the
full reference.

## Code style

### Formatting

All Rust code is formatted with `rustfmt` using the default configuration:

```
cargo fmt
```

Run this before committing, or let the `fmt` job catch it:

```bash
./contrib/ci/local-ci.sh fmt
```

### Lints

Clippy is the linter. Address all warnings before submitting:

```
cargo clippy -- -D warnings
```

Or via the CI script:

```bash
./contrib/ci/local-ci.sh clippy
```

### Documentation comments

Public types, functions, and modules should have doc comments (`///` for items, `//!` for module-level). The standard format is:

```rust
/// Brief one-line summary.
///
/// Longer explanation if needed. Include:
/// - what the function does
/// - what each parameter means
/// - what the return value represents
/// - any notable edge cases or panics
pub fn my_function(arg: &str) -> Result<(), AcmeError> {
    // ...
}
```

### No `unwrap()` in production code

Use `?` or explicit error handling. Exceptions:
- Test code may use `unwrap()` freely.
- Truly infallible operations (e.g., `serde_json::to_string` on a value that is always serializable) may use `unwrap()` with a comment explaining why.

### Error variants

When adding a new operation that can fail, prefer returning a specific existing `AcmeError` variant over adding a new one. If a new variant is genuinely needed, add it to the `AcmeError` enum in `src/error.rs` and update:
- `AcmeError::acme_type()` — return the ACME error URN string.
- `AcmeError::http_status()` — return the appropriate HTTP status code.
- The test in `error.rs` that verifies all variants map correctly.

### Database access

All database access must go through the `db::` submodule functions, not raw SQL in route handlers. New database operations belong in the appropriate `src/db/*.rs` file, not in `routes/` or `ca/` modules.

Transactions must be used when writing to multiple tables atomically. Do not rely on SQLite's autocommit for multi-table writes.

### Async hygiene

- Do not call blocking I/O or CPU-intensive code directly from async tasks. Use `tokio::task::spawn_blocking` for synchronous blocking work.
- Do not hold mutex guards across `.await` points. SQLite access via `db.call()` does not hold any async mutex; it is safe.
- Background tasks spawned with `tokio::spawn` must be panic-safe. Use the observer task pattern to log panics.

## Commit conventions

Commits follow the format:

```
<type>: <short summary (imperative, lowercase, no period)>

[optional body]
```

Types used in this repository:

| Type | When to use |
|---|---|
| `feat` | A new feature visible to users or operators |
| `fix` | A bug fix |
| `doc` | Documentation changes only |
| `test` | Adding or modifying tests without changing production code |
| `refactor` | Code change that neither fixes a bug nor adds a feature |
| `perf` | Performance improvement |
| `chore` | Build system, dependency updates, CI |

Keep the summary line under 72 characters. Use the body to explain *why* the change was made, not *what* was changed (the diff explains what).

Examples from the repository:

```
doc: document thread-safety assumption for CaState key field
fix: eliminate TOCTOU race in MTC log open_or_create
fix: log panics in background validation task
fix: use compile-time-safe HeaderValue in error response
fix: use saturating_sub in nonce sweep to avoid debug-mode panic
```

## Pull request process

1. Fork the repository and create a topic branch from `main`.
2. Make your changes with appropriate tests.
3. Ensure `./contrib/ci/local-ci.sh all` passes (covers fmt, clippy, doc, test, and bench compilation).
4. Write a clear PR description explaining what problem the change solves and how it was tested.
5. Keep PRs focused on a single concern. Unrelated changes should be separate PRs.
6. Address review feedback by adding new commits; do not force-push to squash during review (it makes the diff hard to follow). Squashing happens at merge time if the reviewer requests it.

## Adding a new endpoint

When adding a new ACME or HTTP endpoint:

1. Create a handler function in a new or existing file under `src/routes/`.
2. Register the route in `routes::build_router` in `src/routes/mod.rs`.
3. Add the endpoint URL to the directory response in `routes::directory::get_directory` if it should be advertised.
4. Add any new database operations to the appropriate `src/db/*.rs` module.
5. Add unit tests for the handler logic and any new database functions.
6. Update the user-facing documentation for the affected feature.

## Adding a new challenge type

1. Create a new module in `src/validation/`, e.g., `src/validation/mytype01.rs`.
2. Export an async `validate(domain, key_auth)` function.
3. Add a new arm to `dispatch` in `src/validation/mod.rs`.
4. Add the new challenge type to the list of challenges created per identifier in `routes::order::new_order`.
5. Add tests, including both unit tests and, if possible, an integration test using a local stub server.
6. Document the new challenge type in `docs/src/user/challenges.md`.

### Workspace development

The repository is a Cargo workspace. When adding code to `crates/akamu-jose` or `crates/akamu-client`, run that crate's tests in isolation first:

```bash
cargo test -p akamu-jose
cargo test -p akamu-client
```

Then verify the full workspace:

```bash
cargo test
cargo clippy --workspace
cargo fmt -- --check
```

Do not add axum, rusqlite, or server-specific dependencies to `akamu-jose` or `akamu-client` — they must remain usable without a running server.
