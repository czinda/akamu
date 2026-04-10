# Architecture

This chapter describes the overall structure of `Akāmu`, the key modules, and the full request lifecycle from a TCP connection to an HTTP response.

## Crate layout

The project is a single Rust crate named `Akāmu`. The `src/` directory is organized as follows:

```
src/
  main.rs          Entry point; parses config, initializes subsystems, starts axum
  lib.rs           Re-exports public modules for integration tests
  config.rs        TOML configuration structs (Config, CaConfig, MtcConfig, ServerConfig)
  state.rs         Shared application state (AppState, CaState, MtcState)
  error.rs         AcmeError enum with HTTP mapping and problem+json serialization

  db/
    mod.rs         Database initialization (open, migrations, WAL mode)
    schema.rs      Row types mirroring SQLite columns
    accounts.rs    CRUD for accounts table
    authz.rs       CRUD for authorizations table
    certs.rs       CRUD for certificates table
    challenges.rs  CRUD for challenges table
    nonces.rs      Anti-replay nonce management
    orders.rs      CRUD for orders table

  routes/
    mod.rs         Router assembly, shared helpers (parse_jws, acme_headers, json_response)
    directory.rs   GET /acme/directory
    nonce.rs       HEAD/GET /acme/new-nonce
    account.rs     POST /acme/new-account, POST /acme/account/{id}
    order.rs       POST /acme/new-order, POST /acme/order/{id}
    authz.rs       POST /acme/authz/{id}
    challenge.rs   POST /acme/chall/{authz_id}/{type}
    finalize.rs    POST /acme/order/{id}/finalize
    certificate.rs GET /acme/cert/{id}
    revoke.rs      POST /acme/revoke-cert
    key_change.rs  POST /acme/key-change
    renewal_info.rs GET /acme/renewal-info/{cert_id}

  ca/
    mod.rs         Re-exports ca submodules
    init.rs        CA key and certificate load-or-generate
    csr.rs         PKCS#10 CSR parsing and validation
    issue.rs       End-entity certificate issuance
    revoke.rs      CRL generation

  validation/
    mod.rs         Challenge dispatch and DB state transitions (validate_challenge)
    http01.rs      http-01 validation (hyper HTTP client)
    dns01.rs       dns-01 validation (hickory-resolver)
    tls_alpn01.rs  tls-alpn-01 validation (rustls TLS client)

  mtc/
    mod.rs         Re-exports mtc submodules
    log.rs         Disk-backed Merkle Tree Certificate log integration

  jose/            JWS parsing, JWK handling, thumbprint computation, kid resolution
```

## Key types

### `AppState`

Defined in `src/state.rs`. Every axum handler receives an `Arc<AppState>` via axum's `State` extractor. It contains:

- `config: Arc<Config>` — immutable configuration parsed at startup.
- `db: Arc<Connection>` — shared tokio-rusqlite connection. All database access goes through this.
- `ca: Arc<CaState>` — CA private key, certificate, and signing policy.
- `mtc: Arc<MtcState>` — MTC log handle and algorithm (or `None` if disabled).

`AppState` is `Clone` because `Arc<T>` is `Clone`. Cloning is cheap (reference count bump). All mutable state (the database and MTC log) is protected at a lower level by tokio-rusqlite's internal background thread and a `tokio::sync::Mutex<DiskBackedLog>`, respectively.

### `CaState`

Holds the CA private key (`BackendPrivateKey` from `synta-certificate`) and the DER-encoded CA certificate. The key is used for both certificate signing and CRL signing. `CaState` is shared across all concurrent handler tasks via `Arc<CaState>`. The underlying `BackendPrivateKey` delegates to the OpenSSL backend, which serializes concurrent signing operations internally.

### `AcmeError`

Defined in `src/error.rs`. Implements `IntoResponse` so it can be returned directly from axum handlers. Maps each variant to:

- An ACME problem type string (`urn:ietf:params:acme:error:*`).
- An HTTP status code.
- A human-readable `detail` string.

The response body is `application/problem+json` (RFC 7807).

## Request lifecycle

### 1. TCP accept

The tokio runtime accepts a TCP connection on the configured `listen_addr`. axum's `serve` function passes it to the hyper HTTP/1.1 or HTTP/2 codec.

### 2. HTTP parsing

hyper parses the HTTP request (method, URL, headers, body). Tower middleware is applied in order; currently only `TraceLayer` is configured, which emits a tracing span for each request.

### 3. Route dispatch

axum matches the request method and path against the router built in `routes::build_router`. Each route maps to a handler function in the corresponding `routes/` module. The handler receives the following extractors:

- `State(state): State<Arc<AppState>>` — shared application state.
- `Path(...)` — URL path parameters (e.g., order ID, authz ID).
- `body: Bytes` — raw request body for JWS verification.

### 4. JWS verification (POST endpoints)

Almost every POST endpoint calls `routes::parse_jws` before processing the payload:

1. **Parse**: deserialize the `Bytes` body as a JWS flattened JSON serialization.
2. **Decode header**: base64url-decode the `protected` header and parse the JSON.
3. **URL check**: compare `header.url` with the expected full URL for this endpoint. A mismatch returns `unauthorized`.
4. **Nonce check**: look up `header.nonce` in the `nonces` database table and mark it consumed. A missing or already-used nonce returns `badNonce`. Anti-replay protection is thus database-backed, surviving server restarts.
5. **Key resolution**: if the header uses `jwk`, extract the SPKI DER from the JWK directly. If it uses `kid`, look up the account in the database and fetch its stored SPKI DER.
6. **Signature verification**: verify the JWS signature over `protected || "." || payload` using the resolved public key via `synta-certificate`.
7. **Payload decode**: base64url-decode the `payload` field.

The result is a `JwsContext` struct containing the decoded header, payload bytes, SPKI DER, and optional account ID.

### 5. Business logic

Each handler implements the ACME protocol semantics for its endpoint: reading from and writing to the database, dispatching validation, invoking the CA, etc.

For write operations that span multiple tables (e.g., creating an order with its authorizations and challenges), the handler uses a single SQLite transaction to ensure atomicity.

### 6. Response construction

Handlers return `Result<Response, AcmeError>`. On success, they call `routes::json_response`, which:

1. Generates a new anti-replay nonce.
2. Inserts it into the `nonces` table.
3. Adds the `Replay-Nonce` and `Link: <directory>; rel="index"` headers.
4. Serializes the JSON body and sets `Content-Type: application/json`.

On error, `AcmeError::into_response` builds a `application/problem+json` body.

### 7. Background tasks

Challenge validation does not block the HTTP response. When a challenge is triggered, the handler:

1. Marks the challenge `processing` in the database.
2. Spawns a `tokio::spawn` task running `validation::validate_challenge`.
3. Spawns a second observer task watching for panics via `JoinHandle::await`.
4. Returns immediately with the `processing` status.

Similarly, MTC log appends are spawned as background tasks after certificate issuance.

## Database access model

All database access goes through `tokio_rusqlite::Connection`, which runs `rusqlite` calls on a dedicated background OS thread. Calls cross the thread boundary via a channel. This means:

- `db.call(|conn| { ... })` is the only way to issue queries.
- The closure runs synchronously on the background thread and must not call async functions.
- For multi-statement atomicity, start a SQLite transaction inside the closure.

Foreign key enforcement is enabled at database open time (`PRAGMA foreign_keys=ON`). WAL journal mode is also enabled after migrations (`PRAGMA journal_mode=WAL`).

## Async design

The server is fully async on the tokio runtime. All I/O — TCP, HTTP, DNS, TLS — is async. CPU-bound work (DER encoding for MTC) is offloaded to `tokio::task::spawn_blocking`.

The only shared mutable state in the async domain is the `Mutex<DiskBackedLog>` for the MTC log. All other state is either immutable after startup (`AppState`, `Config`, `CaState`) or encapsulated in the database background thread.
