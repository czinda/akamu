# EAB Internals

This chapter describes the internal implementation of External Account Binding (RFC 8555 §7.3.4): the database schema, the startup seeding pattern, the verification pipeline, and the atomic key-consumption transaction.

## `eab_keys` table schema

EAB keys are stored in the `eab_keys` table. The table was created in migration `0001_initial` and the `profile_grants` column was added by migration `0007_profile_grants`:

```sql
-- 0001_initial.sql
CREATE TABLE eab_keys (
    kid           TEXT    PRIMARY KEY,
    hmac_key_b64u TEXT    NOT NULL,    -- base64url-encoded raw HMAC key bytes
    created       INTEGER NOT NULL,    -- Unix epoch seconds
    used_at       INTEGER              -- NULL = unused; non-NULL = consumed timestamp
);

-- 0007_profile_grants.sql
ALTER TABLE eab_keys ADD COLUMN profile_grants TEXT;
-- NULL = no restriction; JSON array of profile IDs
```

The current effective schema after all migrations is therefore:

```sql
CREATE TABLE eab_keys (
    kid            TEXT    PRIMARY KEY,
    hmac_key_b64u  TEXT    NOT NULL,
    created        INTEGER NOT NULL,
    used_at        INTEGER,
    profile_grants TEXT
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

let hmac_key = URL_SAFE_NO_PAD
    .decode(&key_row.hmac_key_b64u)
    .map_err(|e| AcmeError::BadRequest(format!("EAB: invalid HMAC key encoding: {e}")))?;
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

After verification, `verified_eab` is `Some((kid, profile_grants))` and the account insert, EAB mark, and profile grant transfer are committed atomically:

```rust
// Profile grants inherited from the EAB key (None when no EAB was used).
let eab_profile_grants = verified_eab.as_ref().and_then(|(_, g)| g.clone());

let mut tx = db::begin_write(&state.db, state.db_kind).await?;
db::accounts::insert(&mut *tx, AccountRow {
    profile_grants: eab_profile_grants,  // inherited from EAB key
    …
}).await?;
if let Some((eab_kid, _)) = verified_eab {
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
| `list(db, used_filter, limit, offset)` | List keys with optional used-status filter (`Some(true)` = used only, `Some(false)` = unused only, `None` = all) and pagination |
| `mark_used(executor, kid, now)` | Set `used_at`; intended to be called within a write transaction. Returns `Conflict` when `rows_affected == 0`, meaning the key was already consumed by a concurrent request between the outer `get_by_kid` check and the transaction commit (TOCTOU guard). |
| `delete(executor, kid)` | Remove the key entirely; returns `Result<u64, AcmeError>` where the `u64` is the number of rows deleted (0 = not found) |

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

`profile_grants` is optional (absent or `null` = no restriction). The handler calls `db::eab::insert_with_grants`, which inserts the key row with the `profile_grants` column set accordingly. Returns 201 with `{"kid": "...", "created": <unix-epoch>}`; returns 409 when the `kid` already exists (detected by a `UNIQUE` constraint violation). Requires `administrator` or `ca_operations` role; `ca_ra` is intentionally excluded because EAB keys are server-global (not CA-scoped).

Keys provisioned via this endpoint behave identically to keys seeded from `[server.eab_keys]` during EAB verification. The only difference is that config-file keys have `profile_grants = NULL` always (they are seeded via `insert_if_absent`, which does not write the `profile_grants` column), while admin-provisioned keys may carry grants.

### EAB key listing endpoint

`GET /admin/eab` lists EAB keys. Query parameters:

- `used=true|false` — filter by used status (omit for all keys)
- `limit=N` — maximum rows returned (default 200, max 1000)
- `offset=N` — skip first N rows (default 0)

Returns `{"eab_keys": [...]}` where each element contains `kid`, `created`, `used_at`, and `profile_grants`. Calls `db::eab::list`. Requires any role.

### EAB key detail endpoint

`GET /admin/eab/{kid}` returns a single key's details:

```json
{ "kid": "...", "created": <unix-epoch>, "used_at": <unix-epoch or null>, "profile_grants": <array or null> }
```

Returns 404 when the `kid` is not found. Calls `db::eab::get_by_kid`. Requires any role.

### EAB key deletion endpoint

`DELETE /admin/eab/{kid}` removes the key row entirely. Returns 204 on success; 404 when the `kid` is not found. Calls `db::eab::delete`. Requires `administrator` or `ca_operations` role.

---

## HKDF-SHA-256 EAB credential derivation (`src/eab_derivation.rs`)

When `[server].eab_master_secret` is configured, EAB credentials for Kerberos-authenticated clients are derived deterministically rather than stored in advance.  The derivation is implemented in `src/eab_derivation.rs` and called from the `GET /acme/eab` handler in `src/routes/eab_identity.rs`.

### Public function

```rust
pub fn derive_eab_credentials(
    master_secret: &[u8],
    principal: &str,
) -> Result<(String, String), AcmeError>
```

Returns `(kid_b64u, hmac_key_b64u)` — both values are base64url-encoded (no padding).

### Derivation scheme

Two independent HKDF-SHA-256 (RFC 5869) invocations are performed, one for the kid and one for the HMAC key:

```
kid      = base64url( HKDF-Extract-Expand(IKM=master_secret, salt=<none>, info="akamu-eab-v1-kid:" + principal, L=16) )
hmac_key = base64url( HKDF-Extract-Expand(IKM=master_secret, salt=<none>, info="akamu-eab-v1-key:" + principal, L=32) )
```

No explicit salt is supplied to HKDF-Extract; RFC 5869 §2.2 specifies that an absent salt is treated as a string of zeroes of length `HashLen` (32 bytes for SHA-256).  This is acceptable because `master_secret` is already high-entropy input key material (at least 32 random bytes) and does not require additional salt-based extraction to achieve uniform randomness.

The `info` field domain-separates the two outputs, ensuring that the kid and HMAC key bytes are independent even though they share the same IKM and salt.

### Output sizes

| Output | Raw bytes | Base64url chars |
|--------|-----------|-----------------|
| `kid` | 16 | 22 (no padding) |
| `hmac_key` | 32 | 43 (no padding) |

### Determinism guarantee

The same `(master_secret, principal)` pair always yields identical `kid` and `hmac_key` values.  The `GET /acme/eab` handler inserts the derived key into `eab_keys` on the first call (using `insert_if_absent`) and returns the same values on subsequent calls.  This lets clients retry a failed registration without administrator intervention.

### Handler integration (`src/routes/eab_identity.rs`)

The `GET /acme/eab` handler in `src/routes/eab_identity.rs` ties derivation to persistence:

1. The `RemoteUser` extractor authenticates the caller via GSSAPI or proxy header, yielding a Kerberos principal string.
2. If `eab_master_secret` is not configured, the handler returns `{"principal": "..."}` (stub mode) and stops.
3. `derive_eab_credentials(master_secret, &principal)` produces the `(kid, hmac_key)` pair.
4. `db::eab::insert_if_absent` stores the key row with `bound_principal = Some(principal)`.  The `bound_principal` column records which Kerberos principal derived this key; it is later copied to the account row at registration (see [EAB-to-profile-grant flow](#eab-to-profile-grant-flow) below).
5. A follow-up `get_by_kid` check returns `409 Conflict` if `used_at` is already set (credentials were consumed by a prior `newAccount`).
6. Otherwise the handler returns `{ "principal", "kid", "hmac_key", "alg": "HS256" }`.

### Keying material lifetime

Once the `kid` has been consumed by a successful `newAccount` request, the `eab_keys.used_at` column is set and further calls to `GET /acme/eab` by the same principal return `409 Conflict`.  The administrator must delete the consumed key row (via the Admin API or `akamuctl eab remove`) to allow the principal to re-register.

---

## EAB-to-profile-grant flow

This section traces the end-to-end path from EAB credential derivation through account creation, profile grant inheritance, and Kerberos SAN injection at certificate issuance.

### Overview

```text
GET /acme/eab                       newAccount (POST)                   finalize (POST)
  Kerberos auth                       EAB JWS verification                profile auth + SAN injection
  +-----------+                       +------------------+                +-------------------+
  | principal |--HKDF--> kid,hmac_key | verify EAB JWS   |                | check_profile_auth|
  |           |          |            | lookup eab_keys   |                |   require_account |
  |           |          v            |   .profile_grants |---> account   |   _grant check    |
  |           |   eab_keys row        |   .bound_principal|     .profile_ |                   |
  |           |   .bound_principal    |          |        |     _grants   | KPN/UPN template  |
  +-----------+     = principal       |          v        |     .kerberos_|   expansion       |
                                      | insert account    |     _principal| inject_account_kpn|
                                      |   row atomically  |                +-------------------+
                                      +------------------+
```

### Step 1: EAB key derivation and `bound_principal` storage

When a Kerberos-authenticated client calls `GET /acme/eab`, the handler derives credentials via HKDF (see [above](#hkdf-sha-256-eab-credential-derivation-srceab_derivationrs)) and inserts them into the `eab_keys` table with:

- `bound_principal` = the authenticated Kerberos principal (e.g. `host/client.example.com@EXAMPLE.COM`)
- `profile_grants` = `NULL` (HKDF-derived keys do not carry grants; grants are attached only to admin-provisioned keys via `POST /admin/eab`)

The `bound_principal` column is what connects GSSAPI authentication to the account's Kerberos identity downstream.

### Step 2: Account creation and grant/principal inheritance

When the client calls `newAccount` with an `externalAccountBinding` JWS, the handler in `src/routes/account.rs` performs EAB verification and then captures two values from the `EabKeyRow`:

```rust
let grants = key_row.profile_grants.clone();       // Option<String>
let principal = key_row.bound_principal.clone();    // Option<String>
```

These are passed into the new `AccountRow`:

- `profile_grants` = inherited from `eab_keys.profile_grants` (the JSON array of permitted profile IDs, or `NULL`)
- `kerberos_principal` = inherited from `eab_keys.bound_principal`

The account insert, EAB key consumption (`mark_used`), and grant transfer all happen in a single database transaction, ensuring atomicity.

**Key distinction:** HKDF-derived keys always have `profile_grants = NULL` (no restriction), so accounts created via GSSAPI EAB start with unrestricted profile access unless an administrator subsequently sets grants via `PUT /admin/account/{id}/profile-grants`.  Admin-provisioned keys (`POST /admin/eab`) can carry `profile_grants`, which are then inherited by the account.

### Step 3: Profile authorization at finalization

When the client finalizes an order (`POST /acme/order/{id}/finalize`), the profile's `CertificateParameters` determine what checks apply.  The `check_profile_auth` function in `src/profiles/auth.rs` runs three AND-combined checks:

1. **Identifier patterns** (`allowed_identifier_patterns`) -- regex matching on order identifiers.
2. **External auth hook** (`auth_hook`) -- out-of-process authorization script.
3. **Account grant** (`require_account_grant`) -- the account's `profile_grants` JSON array must list this profile's ID.

The account grant check (`check_account_grant`) loads `accounts.profile_grants` via `db::accounts::get_profile_grants` and verifies the profile name is present in the JSON array.  If the column is `NULL` (no grants set), the check fails with `Unauthorized`.

### Step 4: Kerberos SAN injection at issuance

Three independent mechanisms inject Kerberos-related SANs into the issued certificate.  All three are evaluated in `src/routes/finalize.rs` and produce OtherName DER blobs that are passed to `SubjectAlternativeNameBuilder::other_name()`:

#### Option A: `kpn_san_templates` (template-based, DNS-derived)

Each entry in `CertificateParameters::kpn_san_templates` is expanded against the DNS SANs from the subscriber's CSR by `ca::krb5_san::expand_kpn_template`:

- Templates containing `{dns}` produce one KRB5PrincipalName OtherName per DNS SAN.
  - `"HTTP/{dns}@EXAMPLE.COM"` with DNS SANs `["web.example.com", "api.example.com"]` produces two SANs: `HTTP/web.example.com@EXAMPLE.COM` (NT-SRV-HST) and `HTTP/api.example.com@EXAMPLE.COM` (NT-SRV-HST).
  - `"{dns}@EXAMPLE.COM"` produces NT-PRINCIPAL type SANs.
- Templates without `{dns}` are static and produce exactly one OtherName regardless of DNS SANs.

#### Option A (cont.): `ms_upn_san_template` (template-based, DNS-derived)

A single MS-UPN OtherName (OID `1.3.6.1.4.1.311.20.2.3`) is produced by `ca::krb5_san::expand_ms_upn_template`.  The `{dns}` placeholder is replaced with the first DNS SAN from the CSR.  Static templates (no `{dns}`) inject a fixed UPN value.

#### Option B: `inject_account_kpn` (account-stored principal)

When `CertificateParameters::inject_account_kpn` is `true`, the handler loads the account's `kerberos_principal` from the database (`db::accounts::get_kerberos_principal`).  This is the Kerberos principal that was stored at registration time from `eab_keys.bound_principal` (see Step 2).

The principal string is parsed by `ca::krb5_san::encode_principal_str_other_name`:
- `"service/host@REALM"` is split at `/` and `@`, yielding name-type NT-SRV-HST(3) with components `["service", "host"]` and realm `REALM`.
- `"user@REALM"` (no slash) yields NT-PRINCIPAL(1) with component `["user"]`.

This mechanism is distinct from template-based injection: it uses the actual authenticated identity of the account holder rather than a template derived from DNS names.

### Configuration example

A profile that combines account-grant enforcement with KPN injection from the EAB-bound principal:

```toml
[profiles.providers.local.profiles.ipa-service]
description        = "IPA service certificate with Kerberos SAN"
validity_days      = 90
eku                = ["server_auth", "client_auth"]
require_account_grant = true
inject_account_kpn    = true
kpn_san_templates     = ["HTTP/{dns}@EXAMPLE.COM"]
ms_upn_san_template   = "{dns}@example.com"
```

With this configuration:

1. Only accounts whose `profile_grants` include `"ipa-service"` may use this profile.
2. The account's stored Kerberos principal (from EAB `bound_principal`) is injected as a KRB5PrincipalName OtherName SAN.
3. Each DNS SAN in the CSR additionally produces an `HTTP/<dns>@EXAMPLE.COM` KRB5PrincipalName SAN.
4. The first DNS SAN additionally produces an MS-UPN SAN.

### Code references

| Component | Source file | Key function / struct |
|-----------|------------|----------------------|
| HKDF derivation | `src/eab_derivation.rs` | `derive_eab_credentials` |
| EAB endpoint handler | `src/routes/eab_identity.rs` | `get_eab_identity` |
| Account creation + grant inheritance | `src/routes/account.rs` | `new_account` |
| EAB key row (includes `bound_principal`) | `src/db/eab.rs` | `EabKeyRow` |
| Account row (includes `kerberos_principal`) | `src/db/schema.rs` | `AccountRow` |
| Profile grant check | `src/profiles/auth.rs` | `check_profile_auth`, `check_account_grant` |
| KPN/UPN template expansion | `src/ca/krb5_san.rs` | `expand_kpn_template`, `expand_ms_upn_template`, `encode_principal_str_other_name` |
| SAN injection at finalization | `src/routes/finalize.rs` | `finalize_order` (lines ~227--258) |
| Profile parameters | `src/profiles/mod.rs` | `CertificateParameters` |
| Profile config (TOML) | `src/config/profiles.rs` | `BuiltinProfileConfig` |
