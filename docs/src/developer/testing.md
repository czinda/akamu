# Testing

`Akāmu` uses Rust's built-in test framework (`cargo test`). Tests are organized at three levels:

- **Unit tests** inside each source file (`#[cfg(test)] mod tests`).
- **Integration tests** in `tests/`, which test the full HTTP stack.

## Running tests

Run all tests:

```
cargo test --features test-utils
```

Several integration tests (`mtc_client_flow`, `mtc_cosigner_flow`, `multi_domain_flow`) require the `test-utils` feature flag. Without it, those tests are silently skipped by Cargo. Always pass `--features test-utils` to get full coverage.

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
cargo test -p akamu-jose             # 66 tests: JWK parsing, JWS sign/verify, ML-DSA
cargo test -p akamu-client           # 25 tests: AccountKey, EAB, CSR, challenge helpers
cargo test -p akamu-mtc-validator    # Layer B internal consistency checks against bundled mtc.json vectors
```

`akamu-jose` tests cover every key type including ML-DSA-44/65/87 round-trip sign/verify. `akamu-client` tests use real OpenSSL key generation (no mocking). See `crates/akamu-jose/src/` and `crates/akamu-client/src/` for test modules.

`akamu-mtc-validator` ships one integration test (`tests/mtc_vectors_compat.rs`) that loads `contrib/test-vectors/mtc/mtc.json` and runs all 10 Layer B checks (tree size, leaf hash lengths, null entry hashes, root computation, subtree alignment, subtree bounds, leaf-in-subtree, inclusion proofs, subtrees-for-interval, root-over-all-leaves). It does not require the Go reference artifacts and passes offline.

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
- `not_before_override` is honoured; values more than 5 minutes in the past are clamped.
- `not_after_override` is honoured; invalid values (not after `not_before`) fall back to `not_before + validity_days * 86400`.
- `issue_with_params` rejects issuance when `enforce_validity_cap=true` and `validity_days > 200`; allows exactly 200 days.

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

### `src/validation/dns_persist_01.rs`

Tests cover both the `parse_persist_until` timestamp parser and the `matches_record` record-matching logic:
- `parse_persist_until` accepts base-10 integer UNIX timestamps; rejects non-integer input including ISO 8601 strings.
- `matches_record` verifies issuer match (case-insensitive, trailing-dot stripped), `accounturi` match and mismatch, wildcard `policy` handling (case-insensitive), `persistUntil` expiry, unknown key-value tokens, and multi-issuer lists.
- Async integration tests using a UDP DNS stub server: matching record returns `Ok`, wrong issuer returns error, wildcard domain strips `*.` prefix, wildcard requires `policy=deny`, non-existent domain returns a DNS error.

### `src/validation/onion_csr_01.rs`

Tests cover v3 onion address validation and CSR cryptographic binding:
- `validate_onion_v3` accepts a valid 56-char base32 label and rejects v2 (16-char), too-short, wrong-chars, and non-.onion addresses.
- `base32_decode_no_pad` handles valid input, invalid chars, and non-zero trailing bits.
- `decode_onion_pubkey` rejects wrong version bytes; decodes a synthetic v3 address correctly.
- `ed25519_spki_der` produces the correct 44-byte DER structure.
- `decode_utf8string_or_raw` handles DER UTF8String tags and falls back to raw UTF-8.
- Full CSR validation: Ed25519 CSR key matches the onion address public key; missing nonce extension fails; wrong nonce value fails; wrong SAN fails.

### `src/validation/caa.rs`

Tests cover the `build_name_walk` helper and `check_caa` async lookups using a UDP DNS stub server:
- `build_name_walk` produces the correct ordered list of names to query (single subdomain, deep subdomain, trailing-dot stripped, single-label returns empty).
- `check_caa`: empty `ca_identities` is a no-op; no CAA records returns `Ok`; matching issuer returns `Ok`; non-matching issuer returns error; wildcard falls back from `issuewild` to `issue`; `validationmethods` tag filtering; `accounturi` matching and mismatch; case-insensitive CA identity comparison.

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
| `tests/admin_auth.rs` | Admin authentication paths: Bearer token, mTLS client-certificate, and expired-token rejection; operator deactivation purges live sessions; audit event end-to-end (write via `JournalWriter`, query via `GET /admin/audit`) |
| `tests/admin_rbac.rs` | Table-driven RBAC: for every `(route, method)` pair and each of the four operator roles, verifies allowed roles are not 403 and disallowed roles get exactly 403 |
| `tests/ari_flow.rs` | ACME Renewal Information (RFC 9773) query and renewal window logic |
| `tests/dns_persist_flow.rs` | Full dns-persist-01 challenge flow against a local DNS stub server |
| `tests/mtc_cosigner_flow.rs` | End-to-end ACME issuance followed by MTC checkpoint production, cosignature gathering from an inline cosigner HTTP server, and `StandaloneCertificate` verification |
| `tests/multi_ca.rs` | Multi-CA routing: per-CA directory and CRL endpoints, legacy path falls through to default CA, unknown CA ID returns 404, CRL isolation across CAs, order CA isolation |
| `tests/tls_server.rs` | Helper module providing a local TLS server for tls-alpn-01 integration tests |
| `tests/mtc_playground_compat.rs` | Wire-compatibility tests for the C2SP tlog-tiles and signed-note implementation (RFC 9162 Merkle hashing, tile path encoding, checkpoint/cosignature note format, live HTTP endpoint smoke tests); optional DigiCert playground integration gated behind `MTC_PLAYGROUND_DIR` env var and `--ignored` |
| `tests/mtc_cosigners_interop.rs` | Interop tests against external MTC cosigner stores (Google, Geomys): fetches store JSON, parses issuer/mirror metadata, verifies tlog checkpoints and tiles from live endpoints; external tests gated behind `#[ignore]`; includes a local `akamu_self_test` that exercises the shared tlog verification harness |
| `crates/akamu-mtc-validator/tests/mtc_vectors_compat.rs` | Layer B internal consistency suite against `contrib/test-vectors/mtc/mtc.json` (plants-04, 2036 entries); runs offline without Go reference artifacts |

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

## Shared test helpers (`tests/common/mod.rs`)

`tests/common/mod.rs` provides shared helpers for integration tests, gated behind `#![cfg(feature = "test-utils")]`. All integration test binaries include it via `mod common;`.

Key helpers:

- `common::bind_free_port()` — bind an ephemeral TCP port and return `(port, std::net::TcpListener)`.
- `common::bind_ephemeral()` — same, but returns a tokio `TcpListener`.
- `common::start_http01_solver(listener)` — start a minimal HTTP-01 challenge responder.
- `common::build_test_state(dir, base_url)` — build a full `AppState` with in-memory SQLite, a generated EC P-256 CA, and an Ed25519 MTC signing key. This is the preferred way to set up test state for MTC integration tests.

## Building a test AppState

For MTC integration tests, use `common::build_test_state()` (see above). For ACME handler tests that need finer control over the `AppState` fields, construct it manually. The canonical pattern is:

```rust
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
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
    hash_alg: "sha256".into(),
    validity_days: 90,
    crl_url: None,
    ocsp_url: None,
    aki_bytes: vec![],
    enforce_validity_cap: false,
    crl_next_update_secs: 86400,
    caa_identities: vec![],
});

// 3. Build the IndexMap of CAs.
let mut cas_map = IndexMap::new();
cas_map.insert(ca_cfg.id.clone(), ca_state.clone());
let cas = Arc::new(cas_map);
let default_ca_id = Arc::new(ca_cfg.id.clone());

// 4. Build per-CA CRL cache and Link headers.
let mut crl_caches_map: HashMap<String, crate::state::CrlCache> = HashMap::new();
crl_caches_map.insert(ca_cfg.id.clone(), Default::default());
let crl_caches = Arc::new(crl_caches_map);

let mut link_headers_map = HashMap::new();
let link_value = axum::http::HeaderValue::from_static(
    "<https://acme.test/acme/directory>;rel=\"index\""
);
link_headers_map.insert(ca_cfg.id.clone(), Arc::new(link_value));
let link_headers = Arc::new(link_headers_map);

// 5. Build the outbound HTTPS client for challenge validation.
let validation_client = {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_native_roots()
        .expect("native roots")
        .https_or_http()
        .enable_http1()
        .build();
    hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(https)
};

// 6. Assemble AppState.
let state = Arc::new(AppState {
    config: Arc::new(config),
    db,
    db_kind: crate::db::DbKind::Sqlite,
    cas,
    default_ca_id,
    mtc: Arc::new(MtcState {
        log: None,
        algorithm: synta_mtc::crypto::HashAlgorithm::Sha256,
        signing_key: None,
        signing_hash_alg: "sha256".into(),
        cosigner_clients: vec![],
        _log_lock: None,
    }),
    profiles: crate::profiles::ProfileRegistry::empty(&ca_state),
    tls: None,
    spki_cache: Arc::new(RwLock::new(HashMap::new())),
    nonces: Arc::new(NonceBucket::new()),
    link_headers,
    validation_client,
    crl_caches,
    gss_cred: None,
    admin_gss_cred: None,
    eab_master_secret: None,
    audit: Arc::new(crate::audit::AuditState::new()),
    audit_policy: Arc::new(crate::audit::AuditPolicy::default()),
    admin_sessions: None,
    admin_auth_limiter: None,
    startup_time: std::time::Instant::now(),
});
```

Key points:

- `CaState` requires all fields: `id`, `key_type`, `key`, `cert_der`, `hash_alg`, `validity_days`, `crl_url`, `ocsp_url`, `aki_bytes`, `enforce_validity_cap`, `crl_next_update_secs`, and `caa_identities`. None have defaults.
- `AppState::cas` is an `Arc<IndexMap<String, Arc<CaState>>>`, not a single `Arc<CaState>`. All lookups go through `state.get_ca(id)` or `state.default_ca()`.
- `AppState::db_kind` must be set; use `DbKind::Sqlite` for in-memory test databases.
- `AppState::profiles` holds the certificate profile registry; use `ProfileRegistry::empty(&ca)` to get a no-op registry that falls back to CA defaults for all issuance.
- `AppState::crl_caches` is an `Arc<HashMap<String, CrlCache>>`. Each entry must be keyed by the same CA ID as the corresponding `cas` entry; `Default::default()` yields `Arc::new(Mutex::new(None))`.
- `AppState::link_headers` is an `Arc<HashMap<String, Arc<HeaderValue>>>`. The `acme_headers` helper falls back to the default CA's header when a per-CA header is missing, but tests should always populate the map for every registered CA ID to avoid log noise.
- `AppState::nonces` holds the in-memory anti-replay nonce store; construct with `Arc::new(NonceBucket::new())`.
- `AppState::spki_cache` holds account key material; initialise with an empty `RwLock`-protected `HashMap`.
- `AppState::validation_client` is required even for tests that do not perform outbound challenge validation; build a standard HTTPS client as shown above.
- `AppState::audit` and `AppState::audit_policy` are always required; use `AuditState::new()` and `AuditPolicy::default()` respectively.
- Optional fields (`tls`, `gss_cred`, `admin_gss_cred`, `eab_master_secret`, `admin_sessions`, `admin_auth_limiter`) should be set to `None` unless the test exercises those features.
- Tests that only need a single CA can keep using a single entry in the `IndexMap`; there is no requirement to configure multiple CAs in tests.

## Coverage

Coverage measurement is supported via the `measure_coverage.sh` script in the repository root. It uses `cargo llvm-cov` or a similar tool. See that script for the exact invocation.
