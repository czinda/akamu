# Error Handling

All fallible operations in `Akāmu` return `Result<T, AcmeError>`. The `AcmeError` type is defined in `src/error.rs` and implements both `std::error::Error` (via `thiserror`) and axum's `IntoResponse`.

## AcmeError taxonomy

### ACME-specific errors

These map to ACME problem type URNs (`urn:ietf:params:acme:error:*`):

| Variant | ACME type | HTTP status |
|---|---|---|
| `BadNonce` | `badNonce` | 400 |
| `BadSignatureAlgorithm(String)` | `badSignatureAlgorithm` | 400 |
| `Unauthorized(String)` | `unauthorized` | 401 |
| `AccountDoesNotExist` | `accountDoesNotExist` | 400 |
| `AccountAlreadyExists` | `accountAlreadyExists` | 409 |
| `InvalidContact(String)` | `invalidContact` | 400 |
| `UnsupportedContact` | `unsupportedContact` | 400 |
| `UserActionRequired(String)` | `userActionRequired` | 403 |
| `RejectedIdentifier(String)` | `rejectedIdentifier` | 400 |
| `UnsupportedIdentifier(String)` | `unsupportedIdentifier` | 400 |
| `OrderNotReady` | `orderNotReady` | 403 |
| `BadCsr(String)` | `badCSR` | 400 |
| `BadRevocationReason` | `badRevocationReason` | 400 |
| `AlreadyRevoked` | `alreadyRevoked` | 400 |
| `Caa(String)` | `caa` | 403 |
| `Connection(String)` | `connection` | 400 |
| `Dns(String)` | `dns` | 400 |
| `IncorrectResponse(String)` | `incorrectResponse` | 400 |
| `Tls(String)` | `tls` | 400 |

### Generic HTTP-mapped errors

These do not have dedicated ACME error types; they fall through to `serverInternal` in the ACME type, but carry the appropriate HTTP status:

| Variant | HTTP status |
|---|---|
| `NotFound` | 404 |
| `MethodNotAllowed` | 405 |
| `Conflict(String)` | 409 |
| `UnsupportedMediaType` | 415 |
| `PayloadTooLarge` | 413 |
| `BadRequest(String)` | 400 |

### Internal errors

These indicate server-side failures. They map to `serverInternal` in the ACME error type and HTTP 500:

| Variant | Meaning |
|---|---|
| `Database(String)` | SQLite error |
| `Crypto(String)` | Cryptographic operation failure |
| `Builder(String)` | Certificate or CRL builder error |
| `Mtc(String)` | MTC log operation failure |
| `Internal(String)` | General internal error |

## Response format

`AcmeError::into_response` builds a response with:

- HTTP status from `http_status()`.
- `Content-Type: application/problem+json` (RFC 7807).
- JSON body:

```json
{
  "type": "urn:ietf:params:acme:error:badNonce",
  "status": 400,
  "detail": "bad nonce"
}
```

The `detail` field is the `Display` string of the variant, which for parameterized variants includes the inner string.

## From implementations

One `From` implementation allows the `?` operator to be used with database errors:

- `From<sqlx::Error> for AcmeError` → wraps in `AcmeError::Database`.

This means any `sqlx::query!(...).fetch_one(&db).await?` will automatically convert database errors to `AcmeError::Database(msg)`.

## Error propagation in handlers

Handlers return `Result<Response, AcmeError>`. axum automatically calls `IntoResponse::into_response` on the error variant when building the HTTP response.

Example handler error propagation chain:

```
db::accounts::get_by_id(&db, &id).await?
  ↓ sqlx::Error
  ↓ From<sqlx::Error> for AcmeError
  ↓ AcmeError::Database("...")
  ↓ returned from handler as Err(AcmeError::Database(...))
  ↓ axum calls AcmeError::into_response()
  ↓ HTTP 500 with application/problem+json body
```

## Error handling in background tasks

Background validation tasks (`tokio::spawn`) must not panic and must not propagate errors. `validation::validate_challenge` is declared infallible: it calls `on_valid` or `on_invalid` internally and logs any database errors via `tracing::warn!`. Panics inside validation tasks are caught by the observer task pattern described in the [Validation](validation.md) chapter.

## Design principles

- **No `unwrap()` in production paths.** All fallible operations use `?` or explicit error handling.
- **Internal errors do not leak details to clients.** `AcmeError::Internal` and `AcmeError::Database` both map to `serverInternal` and HTTP 500. The `detail` field is included in the response because ACME clients need some indication of what went wrong, but sensitive internal state is not exposed.
- **Challenge errors are ACME errors.** The validation layer converts `hyper`, `hickory-resolver`, and `rustls` errors into specific `AcmeError` variants (`Connection`, `Dns`, `Tls`, `IncorrectResponse`) so the client receives a meaningful ACME error type.
