# EAB Internals

This chapter describes the internal implementation of External Account Binding (RFC 8555 §7.3.4): the database schema, the startup seeding pattern, the verification pipeline, and the atomic key-consumption transaction.

## `eab_keys` table schema

EAB keys are stored in the `eab_keys` table (added in a later migration than the core schema):

```sql
CREATE TABLE eab_keys (
    kid          TEXT    PRIMARY KEY,
    hmac_key_b64u TEXT   NOT NULL,    -- base64url-encoded raw HMAC key bytes
    created      INTEGER NOT NULL,    -- Unix epoch seconds
    used_at      INTEGER              -- NULL = unused; non-NULL = consumed timestamp
);
```

`hmac_key_b64u` stores the raw HMAC key in base64url encoding (no padding). The server base64url-decodes this before HMAC verification. A `NULL` `used_at` means the key is available for use; a non-`NULL` value means it has been consumed by an account-creation request and may not be reused.

## Startup seeding: `insert_if_absent`

EAB keys configured in `[server.eab_keys]` are seeded into the database on every server start via `db::eab::insert_if_absent`:

```rust
pub async fn insert_if_absent(
    executor: impl sqlx::Executor<'_, Database = sqlx::Any>,
    kid: &str,
    hmac_key_b64u: &str,
    now: i64,
) -> Result<(), AcmeError>
```

The underlying SQL uses a portable `WHERE NOT EXISTS` subquery (not `INSERT OR IGNORE`, which is SQLite-specific) to avoid overwriting keys that were already modified or consumed at runtime:

```sql
INSERT INTO eab_keys (kid, hmac_key_b64u, created)
SELECT ?, ?, ?
WHERE NOT EXISTS (SELECT 1 FROM eab_keys WHERE kid = ?)
```

This means:

- A config-file key that does not exist in the DB is inserted.
- A config-file key that exists in the DB (whether unconsumed, consumed, or modified by a future admin endpoint) is silently skipped.
- A restart never revives a consumed key.

The seeding loop in `src/main.rs` logs a `tracing::warn!` if `insert_if_absent` fails (e.g., due to a DB error), but does not abort startup.

## EAB verification pipeline (`src/jose/eab.rs`)

The server's EAB logic is split into two functions that are called in sequence from `routes::account::new_account`.

### Step 1: `parse_eab_kid`

```rust
pub fn parse_eab_kid(eab: &serde_json::Value) -> Result<String, AcmeError>
```

Decodes and parses only the `protected` header of the EAB JWS to extract the `kid`. This is a partial parse that deliberately skips HMAC verification, so that the `kid` can be used for a database lookup before the full verification step.

The function:
1. Deserializes the `protected` field as a base64url string.
2. Decodes the base64url bytes and parses as JSON.
3. Returns the `kid` string from the parsed header.

### Step 2: `verify_eab_jws`

```rust
pub fn verify_eab_jws(
    eab: &serde_json::Value,
    expected_url: &str,
    expected_kid: &str,
    account_thumbprint: &str,
    hmac_key: &[u8],
) -> Result<(), AcmeError>
```

Performs full EAB verification per RFC 8555 §7.3.4:

1. Decodes and parses the full EAB JWS (`protected`, `payload`, `signature`).
2. Parses the protected header and extracts `alg`, `kid`, and `url`.
3. Maps `alg` to a hash name: `"HS256"` → `"sha256"`, `"HS384"` → `"sha384"`, `"HS512"` → `"sha512"`. Any other value returns `AcmeError::BadRequest`.
4. Checks `header.kid == expected_kid`. A mismatch returns `AcmeError::Unauthorized`.
5. Checks `header.url == expected_url` (the new-account endpoint URL). A mismatch returns `AcmeError::Unauthorized`.
6. Decodes the `payload` from base64url, parses it as a `JwkPublic`, and computes its RFC 7638 thumbprint. The thumbprint must match `account_thumbprint` (the thumbprint of the outer JWS's account key). This check ensures the EAB payload contains the actual account public key.
7. Computes the signing input as `"{protected}.{payload}"` (ASCII bytes).
8. Calls `default_hmac_provider().hmac_verify(hash_alg, hmac_key, signing_input, &raw_sig)`. The OpenSSL backend performs a constant-time HMAC comparison.

### Handler integration (`src/routes/account.rs`)

The calling code in `new_account`:

```rust
let kid = crate::jose::eab::parse_eab_kid(eab_val)?;
let key_row = db::eab::get_by_kid(&state.db, &kid)
    .await?
    .ok_or_else(|| AcmeError::Unauthorized(format!("EAB: unknown kid '{kid}'")))?;

if key_row.used_at.is_some() {
    return Err(AcmeError::Unauthorized(format!("EAB: kid '{kid}' has already been used")));
}

let hmac_key = URL_SAFE_NO_PAD.decode(&key_row.hmac_key_b64u)?;
crate::jose::eab::verify_eab_jws(eab_val, &url, &kid, &thumbprint, &hmac_key)?;
```

After verification, `verified_eab_kid` is `Some(kid)` and the account insert and EAB mark are committed atomically:

```rust
let mut tx = db::begin_write(&state.db, state.db_kind).await?;
db::accounts::insert(&mut *tx, AccountRow { … }).await?;
if let Some(eab_kid) = verified_eab_kid {
    db::eab::mark_used(&mut *tx, &eab_kid, now).await?;
}
tx.commit().await.map_err(AcmeError::from)?;
```

The atomicity guarantee: either both the account row is inserted **and** the EAB key is marked used, or neither happens. A concurrent second request using the same `kid` will find `used_at IS NOT NULL` after the first transaction commits, and will be rejected with `Unauthorized`.

## `db::eab` module

| Function | Description |
|---|---|
| `insert_if_absent(executor, kid, hmac_key_b64u, now)` | Seed from config; silent no-op if `kid` already exists |
| `insert(executor, kid, hmac_key_b64u, now)` | Unconditional insert; returns `Conflict` if `kid` exists |
| `get_by_kid(executor, kid)` | Fetch `EabKeyRow`; returns `None` for unknown `kid` |
| `mark_used(executor, kid, now)` | Set `used_at`; intended to be called within a write transaction |
| `delete(executor, kid)` | Remove the key entirely (future admin endpoint) |

`EabKeyRow` mirrors the table columns:

```rust
pub struct EabKeyRow {
    pub kid: String,
    pub hmac_key_b64u: String,
    pub created: i64,
    pub used_at: Option<i64>,   // None = unused
}
```
