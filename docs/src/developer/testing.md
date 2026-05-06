# Testing

`Akāmu` uses Rust's built-in test framework (`cargo test`). Tests are organized at three levels:

- **Unit tests** inside each source file (`#[cfg(test)] mod tests`).
- **Integration tests** in `tests/`, which test the full HTTP stack.

## Running tests

Run all tests:

```
cargo test
```

Run a specific test by name:

```
cargo test validate_csr
```

Run all tests in a specific module:

```
cargo test ca::csr::tests
```

Run with output visible (useful for debugging):

```
cargo test -- --nocapture
```

### Library crate tests

Each library crate ships its own unit tests:

```bash
cargo test -p akamu-jose    # 66 tests: JWK parsing, JWS sign/verify, ML-DSA
cargo test -p akamu-client  # 16 tests: AccountKey, EAB, CSR, challenge helpers
```

`akamu-jose` tests cover every key type including ML-DSA-44/65/87 round-trip sign/verify. `akamu-client` tests use real OpenSSL key generation (no mocking). See `crates/akamu-jose/src/` and `crates/akamu-client/src/` for test modules.

## Test dependencies

`dev-dependencies` in `Cargo.toml`:

| Crate | Purpose |
|---|---|
| `tokio` (with `test-util`) | `#[tokio::test]` macro for async tests |
| `tempfile` | Temporary files and directories for CA key tests and database tests |
| `tower` | `ServiceExt::oneshot` for integration test HTTP requests |

## Unit test coverage

### `src/config.rs`

Tests verify:
- Minimal TOML parses correctly with all required fields present.
- Default values are applied when optional fields are omitted.
- All optional fields parse correctly when present.
- `Config::from_file` returns a descriptive error for missing files.
- `Config::from_file` returns a descriptive error for invalid TOML.

### `src/error.rs`

Tests verify:
- Every `AcmeError` variant maps to the correct ACME type string.
- Every variant maps to the correct HTTP status code.
- `Display` strings are correct.
- `From<sqlx::Error>` converts correctly.
- `into_response` produces `Content-Type: application/problem+json` and the correct status.

### `src/routes/mod.rs`

Tests verify:
- `fmt_time(0)` returns `"1970-01-01T00:00:00Z"`.
- `fmt_time(1704067200)` returns `"2024-01-01T00:00:00Z"`.
- `unix_now()` returns a positive integer.
- `require_payload` returns `BadRequest` for an empty payload.
- `require_payload` returns `BadRequest` for invalid JSON.
- `require_payload` succeeds for valid JSON.

### `src/db/mod.rs`

Tests verify:
- `db::open(":memory:")` succeeds and accepts queries.
- `db::open(path)` creates the file and applies migrations (accounts table exists).

### `src/db/accounts.rs`, `orders.rs`, `authz.rs`, `challenges.rs`, `certs.rs`, `nonces.rs`

Each module has tests for:
- Happy-path insert and retrieval.
- Missing-row returns `None`.
- Update functions returning `false` for non-existent rows.
- Error propagation paths (using a raw connection with no schema).

### `src/ca/init.rs`

Tests verify:
- Each key type generates a non-empty SPKI DER.
- `"bogus:key-type"` returns `AcmeError::Internal`.
- `unix_to_generalized_time(0)` returns `"19700101000000Z"`.
- `load_or_generate` creates both files when neither exists.
- `load_or_generate` loads successfully when both files exist.
- `load_or_generate` returns an error when exactly one file exists.

### `src/ca/csr.rs`

Tests verify:
- A valid CSR parses correctly and SANs are extracted.
- A tampered signature is rejected with `BadCsr`.
- `cA=TRUE` in BasicConstraints is rejected.
- SANs not in the allowed set are rejected.
- Required identifiers missing from CSR SANs are rejected.
- IPv4 and IPv6 SAN parsing.
- Edge cases: no SAN extension, email SANs (ignored), non-extensionRequest attributes.
- DER helper functions: `strip_sequence`, `tlv_header`, `bytes_to_ip_string`.

### `src/ca/issue.rs`

Tests verify:
- End-to-end certificate issuance produces a parseable DER certificate.
- Serial number in issued cert matches `serial_hex`.
- PEM bundle contains exactly two certificates (leaf + CA).
- Chain verification passes using `synta-x509-verification`.
- CRL URL and OCSP URL extensions are included when configured.
- IP SAN issuance works.
- Invalid IP SAN string returns `AcmeError::Builder`.
- Unknown SAN type is silently skipped.
- `issue_ca_cert` produces a CA certificate with `BasicConstraints cA=TRUE` and no `pathLenConstraint`.
- `check_is_ca_cert` accepts a CA cert and rejects an end-entity cert.

### `src/ca/revoke.rs`

Tests verify:
- An empty CRL is generated with correct PEM headers.
- CRL with revoked entries is generated.
- `encode_integer_der` produces correct DER for edge cases (0, 127, 128, 255, 256).
- Invalid CA cert DER returns an error.

### `src/validation/mod.rs`

Tests verify:
- `unix_now()` returns a positive integer.
- `err_type` maps each `AcmeError` variant correctly.
- `dispatch` returns `IncorrectResponse` for unsupported challenge types.
- `on_valid` and `on_invalid` do not panic when called with non-existent IDs.
- `on_valid` with real DB rows updates challenge, authz, and order to valid/ready.
- `on_invalid` with real DB rows marks everything invalid.
- `validate_challenge` for http-01 with a live local server marks the challenge valid.
- Database error paths in `on_valid` and `on_invalid` are covered with partial-schema databases.

### `src/validation/http01.rs`

Tests use a local axum HTTP server on an ephemeral port:
- Correct key auth returns `Ok`.
- Unreachable domain returns `AcmeError::Connection`.
- HTTP 404 response returns `AcmeError::IncorrectResponse`.
- Response body over 1 MiB returns `AcmeError::IncorrectResponse`.
- Key auth mismatch returns `AcmeError::IncorrectResponse`.
- Direct connection to a private IP (e.g. `192.168.1.1`) with `allow_private_ips = false` returns `AcmeError::IncorrectResponse` (SSRF guard on initial target).
- Redirect to a private/link-local IP (e.g. `169.254.169.254`) returns `AcmeError::IncorrectResponse` (SSRF guard on redirect target).
- Redirect followed successfully when `allow_private_ips = true` (test-only override).
- More than 10 redirects returns `AcmeError::IncorrectResponse`.

### `src/validation/dns01.rs`

Tests use a hand-crafted UDP DNS stub server:
- Correct TXT value returns `Ok`.
- Wrong TXT value returns `AcmeError::IncorrectResponse`.
- Non-existent domain returns an error.
- Wildcard prefix is stripped before querying.

### `src/validation/tls_alpn01.rs`

Tests include both unit tests for the DER walker and integration tests using local TLS servers:
- `decode_length`, `read_tlv`, `strip_sequence`, `strip_octet_string`, `skip_tlv` — edge cases.
- `find_extension_value` with correct, missing, and wrong-OID extensions.
- `verify_acme_cert` with hand-crafted DER certificates.
- Local TLS 1.3 and TLS 1.2 servers for `validate_inner` coverage.
- `AcceptAnyCert` verifier always returns `Ok`.

### `src/mtc/log.rs`

Tests verify:
- `open_or_create` creates a new log file.
- Appending leaves increments the tree size.
- Re-opening an existing log file restores the leaf count.
- `compute_root` returns a 32-byte value for a non-empty log.

### `src/routes/account.rs`

Tests verify contact validation and `account_json` structure.

### `src/routes/order.rs`

Tests verify `order_json` for pending, valid, invalid, and expired orders.

## Integration tests

All integration test files live under `tests/`.  Each builds a full `AppState` with an in-memory database, a generated CA, and a real axum router.  They use `tower::ServiceExt::oneshot` to send HTTP requests directly to the router without binding a TCP port, except where a live TCP port is required by the protocol (tls-alpn-01 validation, cosigner HTTP server).

| File | What it covers |
|---|---|
| `tests/acme_flow.rs` | Core ACME lifecycle: account creation, order creation, challenge signaling, status transitions, and certificate download |
| `tests/ari_flow.rs` | ACME Renewal Information (RFC 9773) query and renewal window logic |
| `tests/dns_persist_flow.rs` | Full dns-persist-01 challenge flow against a local DNS stub server |
| `tests/mtc_cosigner_flow.rs` | End-to-end ACME issuance followed by MTC checkpoint production, cosignature gathering from an inline cosigner HTTP server, and `StandaloneCertificate` verification |
| `tests/tls_server.rs` | Helper module providing a local TLS server for tls-alpn-01 integration tests |
| `tests/mtc_playground_compat.rs` | Wire-compatibility tests for the C2SP tlog-tiles and signed-note implementation (RFC 9162 Merkle hashing, tile path encoding, checkpoint/cosignature note format, live HTTP endpoint smoke tests); optional DigiCert playground integration gated behind `MTC_PLAYGROUND_DIR` env var and `--ignored` |

## Adding new tests

Place unit tests in a `#[cfg(test)] mod tests { ... }` block at the bottom of the source file being tested. Use `tokio::test` for async tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn my_async_test() {
        // ...
    }

    #[test]
    fn my_sync_test() {
        // ...
    }
}
```

For tests that need a database, call `crate::db::open(":memory:").await.unwrap()` to get a fresh in-memory database with the full schema applied.

For tests that need a CA, call `crate::ca::init::load_or_generate(&config).unwrap()` with a `CaConfig` pointing to a `tempfile::TempDir`.

For tests that need a full `AppState` with multi-CA support, build `cas` as an `IndexMap` and populate `crl_caches` and `link_headers` as `HashMap`s keyed by CA ID. See the "Building a test AppState" section below for the canonical pattern.

## Building a test AppState

Integration tests that exercise ACME handlers need a full `AppState`. The multi-CA refactor changed several fields; the canonical test-setup pattern is:

```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use indexmap::IndexMap;

// 1. Open an in-memory database with the full schema.
let db = crate::db::open(":memory:").await.unwrap();

// 2. Generate a test CA (or load from tempfile).
let ca_cfg = CaConfig { id: "default".to_string(), key_type: "ec:P-256".to_string(), .. };
let (key, cert_der) = crate::ca::init::load_or_generate(&ca_cfg).unwrap();
let ca_state = Arc::new(CaState {
    id: ca_cfg.id.clone(),
    key_type: ca_cfg.key_type.clone(),
    key,
    cert_der,
    crl_next_update_secs: 86400,
    caa_identities: vec![],
    // … other required fields (hash_alg, validity_days, etc.) …
});

// 3. Build the IndexMap of CAs.
let mut cas_map = IndexMap::new();
cas_map.insert(ca_cfg.id.clone(), ca_state.clone());
let cas = Arc::new(cas_map);
let default_ca_id = Arc::new(ca_cfg.id.clone());

// 4. Build per-CA CRL cache and Link headers.
let mut crl_caches_map: HashMap<String, crate::state::CrlCache> = HashMap::new();
crl_caches_map.insert(ca_cfg.id.clone(), Arc::new(Mutex::new(None)));
let crl_caches = Arc::new(crl_caches_map);

let mut link_headers_map = HashMap::new();
let link_value = axum::http::HeaderValue::from_str(
    &format!("<{}/acme/directory>; rel=\"index\"", base_url)
).unwrap();
link_headers_map.insert(ca_cfg.id.clone(), Arc::new(link_value));
let link_headers = Arc::new(link_headers_map);

// 5. Assemble AppState.
let state = Arc::new(AppState {
    config: Arc::new(config),
    db,
    cas,
    default_ca_id,
    crl_caches,
    link_headers,
    // … all other required fields …
});
```

Key points:

- `CaState` now requires `id`, `key_type`, and `crl_next_update_secs` in addition to the existing fields. Tests that construct `CaState` directly must supply all three.
- `AppState::cas` is an `Arc<IndexMap<String, Arc<CaState>>>`, not a single `Arc<CaState>`. All lookups go through `state.get_ca(id)` or `state.default_ca()`.
- `AppState::crl_caches` is an `Arc<HashMap<String, CrlCache>>`. Each entry must be keyed by the same CA ID as the corresponding `cas` entry.
- `AppState::link_headers` is an `Arc<HashMap<String, Arc<HeaderValue>>>`. The `acme_headers` helper falls back to the default CA's header when a per-CA header is missing, but tests should always populate the map for every registered CA ID to avoid log noise.
- Tests that only need a single CA can keep using a single entry in the `IndexMap`; there is no requirement to configure multiple CAs in tests.

## Coverage

Coverage measurement is supported via the `measure_coverage.sh` script in the repository root. It uses `cargo llvm-cov` or a similar tool. See that script for the exact invocation.
