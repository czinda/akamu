# EAB Internals

This chapter describes the internal implementation of External Account Binding (RFC 8555 §7.3.4): the database schema, the startup seeding pattern, the verification pipeline, and the atomic key-consumption transaction.

## `eab_keys` table schema

EAB keys are stored in the `eab_keys` table. Migration `0007_profile_grants` added a `profile_grants` column:

```sql
CREATE TABLE eab_keys (
    kid            TEXT    PRIMARY KEY,
    hmac_key_b64u  TEXT    NOT NULL,    -- base64url-encoded raw HMAC key bytes
    created        INTEGER NOT NULL,    -- Unix epoch seconds
    used_at        INTEGER,             -- NULL = unused; non-NULL = consumed timestamp
    profile_grants TEXT                 -- NULL = no restriction; JSON array of profile IDs
);
```

`hmac_key_b64u` stores the raw HMAC key in base64url encoding (no padding). The server base64url-decodes this before HMAC verification. A `NULL` `used_at` means the key is available for use; a non-`NULL` value means it has been consumed by an account-creation request and may not be reused.

`profile_grants` stores a JSON array of profile ID strings (e.g. `'["tls-server","mtc-tls"]'`), or `NULL` when no restriction applies. When an account is created with this EAB key, the `profile_grants` value is copied atomically to the new account's `profile_grants` column.

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
- A config-file key that exists in the DB (whether unconsumed, consumed, or modified by the admin API) is silently skipped.
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
if let Err(e) = crate::jose::eab::verify_eab_jws(eab_val, &url, &kid, &thumbprint, &hmac_key) {
    // On HMAC verification failure, two audit events are emitted:
    //   EabReject  ("eab.reject", failure)  — records the rejected kid.
    //   SecurityViolation ("security.violation", failure) — feeds the FAU_ARP.1 alarm counter.
    state.record_audit(AuditEvent::failure(AuditEventType::EabReject).with_subject(&kid)).await;
    state.record_audit(
        AuditEvent::failure(AuditEventType::SecurityViolation)
            .with_subject(&kid)
            .with_detail("EAB HMAC verification failed"),
    ).await;
    return Err(e);
}
```

On successful HMAC verification an `EabUse` (`"eab.use"`, success) audit event is emitted for the `kid`.

After verification, `verified_eab_kid` is `Some(kid)` and the account insert, EAB mark, and profile grant transfer are committed atomically:

```rust
let mut tx = db::begin_write(&state.db, state.db_kind).await?;
db::accounts::insert(&mut *tx, AccountRow {
    profile_grants: eab_row.profile_grants.clone(),  // inherited from EAB key
    …
}).await?;
if let Some(eab_kid) = verified_eab_kid {
    db::eab::mark_used(&mut *tx, &eab_kid, now).await?;
}
tx.commit().await.map_err(AcmeError::from)?;
```

The atomicity guarantee: the account row insertion, EAB key consumption, and profile grant transfer all happen in a single transaction. Either all three succeed together, or none of them do. A concurrent second request using the same `kid` will find `used_at IS NOT NULL` after the first transaction commits and will be rejected with `Unauthorized`.

When the EAB key's `profile_grants` is `NULL`, the new account's `profile_grants` is also `NULL` (no restriction). When it contains a JSON array, the array is stored verbatim on the account row and immediately governs profile authorization for that account.

## `db::eab` module

| Function | Description |
|---|---|
| `insert_if_absent(executor, kid, hmac_key_b64u, now)` | Seed from config; silent no-op if `kid` already exists |
| `insert(executor, kid, hmac_key_b64u, now)` | Unconditional insert without grants; returns `Conflict` if `kid` exists |
| `insert_with_grants(executor, kid, hmac_key_b64u, profile_grants, now)` | Unconditional insert with optional grants (used by the Admin API); returns `Conflict` if `kid` exists |
| `get_by_kid(executor, kid)` | Fetch `EabKeyRow`; returns `None` for unknown `kid` |
| `mark_used(executor, kid, now)` | Set `used_at`; intended to be called within a write transaction. Returns `Conflict` when `rows_affected == 0`, meaning the key was already consumed by a concurrent request between the outer `get_by_kid` check and the transaction commit (TOCTOU guard). |
| `delete(executor, kid)` | Remove the key entirely |

`EabKeyRow` mirrors the table columns:

```rust
pub struct EabKeyRow {
    pub kid: String,
    pub hmac_key_b64u: String,
    pub created: i64,
    pub used_at: Option<i64>,        // None = unused
    pub profile_grants: Option<String>,  // None = no restriction; Some = JSON array
}
```

---

## Admin API internals (`src/routes/admin.rs`)

The Admin API routes are served on a dedicated admin listener built by `routes::build_admin_router`. Each handler enforces role-based access using the `require_role!` macro, which delegates to the `OperatorContext` extractor. The `OperatorContext` verifies the operator's session token and looks up their role in the `operators` table.

When the `[admin]` section is absent from the configuration, the admin router is not started and all admin endpoints are unreachable.

Role enforcement is applied per endpoint. A request from a role that is not authorised for that endpoint receives `403 Forbidden`. The full role matrix is documented in [Admin API and Operator Management](../user/admin-api.md).

### Account profile grants endpoints

`GET /admin/account/{id}/profile-grants` calls `db::accounts::get_profile_grants` and returns:

```json
{ "profile_grants": ["p1", "p2"] }
```

or `{"profile_grants": null}` for a NULL column. Returns 404 when the account ID is not found.

`PUT /admin/account/{id}/profile-grants` deserialises the body as `{"profile_grants": <array or null>}` and calls `db::accounts::set_profile_grants`. An empty JSON array and `null` both map to `NULL` in the database (the `grants_to_json` helper returns `None` for both). Returns 204 on success; 404 when the account is not found or is deactivated.

`DELETE /admin/account/{id}/profile-grants` calls `set_profile_grants` with `grants = None`, setting the column to `NULL`. Returns 204 on success; 404 when the account is not found or is deactivated.

### EAB key provisioning endpoint

`POST /admin/eab` deserialises the body as:

```json
{ "kid": "...", "hmac_key_b64u": "...", "profile_grants": ["p1"] }
```

`profile_grants` is optional (absent or `null` = no restriction). The handler calls `db::eab::insert_with_grants`, which inserts the key row with the `profile_grants` column set accordingly. Returns 201 with `{"kid": "...", "created": <unix-epoch>}`; returns 409 when the `kid` already exists (detected by a `UNIQUE` constraint violation).

Keys provisioned via this endpoint behave identically to keys seeded from `[server.eab_keys]` during EAB verification. The only difference is that config-file keys have `profile_grants = NULL` always (they are seeded via `insert_if_absent`, which does not write the `profile_grants` column), while admin-provisioned keys may carry grants.
