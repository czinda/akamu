# Account Management Internals

This chapter describes the internal implementation of ACME account creation, key rollover, and the SPKI cache.

## Database representation

Accounts are stored in the `accounts` table (defined in `src/db/schema.rs` and migration 001):

```sql
CREATE TABLE accounts (
    id             TEXT    PRIMARY KEY,           -- UUID v4
    status         TEXT    NOT NULL DEFAULT 'valid',
    contact        TEXT,                          -- JSON array e.g. ["mailto:a@b.com"]
    public_key     BLOB    NOT NULL,              -- DER-encoded SubjectPublicKeyInfo
    jwk_thumbprint TEXT    NOT NULL UNIQUE,       -- base64url SHA-256 JWK thumbprint (RFC 7638)
    created        INTEGER NOT NULL,
    updated        INTEGER NOT NULL
);
```

Two fields carry cryptographic identity:

- **`public_key`** — the raw DER-encoded `SubjectPublicKeyInfo` extracted from the outer JWS `jwk` at account creation time. Stored once; used to verify subsequent signed requests via a cache-aside pattern.
- **`jwk_thumbprint`** — the RFC 7638 SHA-256 thumbprint of the public JWK, base64url-encoded. Carries a `UNIQUE` constraint so the database enforces that no two accounts share the same key. This is the lookup key for "does an account already exist for this key?" checks at `new-account` time.

## Account creation flow (`src/routes/account.rs`)

`routes::account::new_account` handles `POST /acme/new-account`:

1. `parse_jws` verifies the outer JWS and extracts the `JwsKeyRef::Jwk { jwk }`.
2. `jwk.thumbprint()` computes the RFC 7638 thumbprint.
3. `db::accounts::get_by_thumbprint(&state.db, &thumbprint)` checks for an existing account. If found, returns HTTP 200 with the existing account (idempotent creation).
4. If `external_account_required` is set, the EAB JWS is validated (see [EAB Internals](eab.md)).
5. `contacts` are validated — only `mailto:` URIs are accepted.
6. A new UUID account ID is generated.
7. Account insertion and EAB key consumption happen atomically in a single `db::begin_write` transaction:

```rust
let mut tx = db::begin_write(&state.db, state.db_kind).await?;
db::accounts::insert(&mut *tx, AccountRow { … }).await?;
if let Some(eab_kid) = verified_eab_kid {
    db::eab::mark_used(&mut *tx, &eab_kid, now).await?;
}
tx.commit().await.map_err(AcmeError::from)?;
```

## SPKI cache (`AppState::spki_cache`)

Every authenticated `POST` endpoint (other than `new-account`) must look up the account's public key to verify the JWS signature. Fetching `public_key` from the database on every request would add a read round-trip to every ACME operation.

`AppState.spki_cache` is an `Arc<RwLock<HashMap<String, Vec<u8>>>>` that caches `account_id → SPKI DER`. After the first authenticated request for an account, the SPKI bytes are stored here. Subsequent requests hit the in-memory cache instead of the database.

Cache eviction occurs in two places:

- **Deactivation** (`update_account`): `state.spki_cache.write().unwrap().remove(&id)` removes the entry immediately after marking the account `deactivated`. This ensures that subsequent requests with the deactivated account's key are rejected at the database layer (where `status='valid'` is required for updates) rather than using a stale cached key.
- **Key rollover** (`key_change`): the same removal is applied after `db::accounts::update_key` succeeds, so the next request with the new key is re-loaded from the database rather than finding the old SPKI bytes.

The cache is not bounded in size because the number of accounts is expected to be small relative to available memory. A future improvement could add LRU eviction.

## Key rollover flow (`src/routes/key_change.rs`)

`routes::key_change::key_change` handles `POST /acme/key-change` per RFC 8555 §7.3.5. The outer JWS is signed with the **old** key (resolved via `kid`); the payload is itself an inner JWS signed with the **new** key. The steps are:

1. Verify the outer JWS with `parse_jws` — uses the old key from the SPKI cache or database.
2. Parse the payload as a `JwsFlattened` inner JWS.
3. Extract the new `JwkPublic` from the inner JWS header (`JwsKeyRef::Jwk`).
4. Convert the new JWK to SPKI DER: `new_jwk.to_spki_der()`.
5. Compute the new thumbprint: `new_jwk.thumbprint()`.
6. Verify the inner JWS signature over the new SPKI DER.
7. Decode the inner payload: `{ "account": "<account_url>", "oldKey": <old_jwk> }`.
8. Check `inner_payload.account == expected_account_url`.
9. Convert `inner_payload.old_key` to SPKI DER and compare with `ctx.spki_der` (the outer JWS's key). This is the RFC-mandated proof that the requester controls the old key.
10. Check that the new thumbprint is not already in use by another account: `db::accounts::get_by_thumbprint(&state.db, &new_thumbprint)`.
11. Call `db::accounts::update_key(&state.db, &account_id, new_spki, new_thumbprint, now)`.
12. Evict the old SPKI from the cache: `state.spki_cache.write().unwrap().remove(&account_id)`.

`db::accounts::update_key` updates both `public_key` (the DER BLOB) and `jwk_thumbprint` (the unique TEXT) atomically in a single SQL `UPDATE`:

```sql
UPDATE accounts SET public_key = ?, jwk_thumbprint = ?, updated = ?
WHERE id = ? AND status = 'valid'
```

The `AND status = 'valid'` guard ensures that a deactivated account's key cannot be rotated.

## Database module (`src/db/accounts.rs`)

The account DB module exposes:

| Function | SQL |
|---|---|
| `insert(executor, row)` | `INSERT INTO accounts …` |
| `get_by_id(executor, id)` | `SELECT … FROM accounts WHERE id = ?` |
| `get_by_thumbprint(executor, thumbprint)` | `SELECT … FROM accounts WHERE jwk_thumbprint = ?` |
| `update_contact(executor, id, contact, now)` | `UPDATE accounts SET contact = ? … WHERE id = ? AND status = 'valid'` |
| `update_status(executor, id, status, now)` | `UPDATE accounts SET status = ? …` |
| `update_key(executor, id, public_key, jwk_thumbprint, now)` | `UPDATE accounts SET public_key = ?, jwk_thumbprint = ? … WHERE id = ? AND status = 'valid'` |

All functions accept `impl sqlx::Executor<'_, Database = sqlx::Any>`, which allows them to be called with either a pool reference (`&Db`) or a mutable transaction reference (`&mut *tx`). This is the standard sqlx pattern for composing queries into transactions without changing the function signatures.
