# Admin API and Operator Management

The akamu admin API is a separate HTTPS listener that exposes management
endpoints for operators.  It is completely independent of the main ACME
listener: it binds to a different address, uses its own TLS certificate, and
requires operator authentication on every request.  When the `[admin]` section
is absent from the configuration file, all admin endpoints return `404 Not Found`
and are unreachable.

See [`akamuctl`](akamuctl.md) for the command-line tool that wraps this API.
See [Configuration Reference — `[admin]`](configuration.md#admin) for all
configuration keys.

## Authentication

Every request to the admin API must be authenticated.  Three mechanisms are
supported.

### mTLS client certificate

The client presents a certificate during the TLS handshake.  The server computes
the SHA-256 fingerprint of the DER-encoded leaf certificate and looks it up in
the `operators` table.  On success, the server issues a session token and returns
it in the response body under `session_token` and in the `X-Session-Token`
response header.

### GSSAPI/Kerberos

The client sends an `Authorization: Negotiate <base64-SPNEGO-token>` header.
The server validates the token against the keytab configured in
`[admin.gssapi]`, extracts the Kerberos principal, and looks it up in the
`operators` table.  On success the server issues a session token (same as the
mTLS path) and may include a GSSAPI continuation token in a
`WWW-Authenticate: Negotiate <token>` response header.

### Bearer session token

After a successful mTLS or GSSAPI login, the client passes the returned token
as `Authorization: Bearer <token>` on subsequent requests.  The server looks up
the token in its in-memory session store and refreshes the idle timer.  Tokens
that have been idle for longer than `session_ttl_secs` (default 1 hour) are
expired and the client receives `401 Unauthorized`.

The session store is bounded at 1 000 active sessions.  When the cap is reached,
the least-recently-active session is evicted.

Token comparisons use constant-time equality to prevent timing side-channels.

## Roles

Each operator has exactly one role.  The role determines which admin endpoints
the operator may call.

| Role | Description |
|------|-------------|
| `administrator` | Full access to all admin endpoints. |
| `ca_operations` | Certificate, EAB, CRL, and revocation operations. Cannot manage operators. |
| `ca_ra` | Registration-authority operations: issue EAB keys, revoke certificates, read profile grants. |
| `auditor` | Read-only access: audit log, certificates, EAB keys, stats. |

## Endpoint reference

All paths are relative to the admin listener base URL.  The `[admin].listen_addr`
field controls the address; the default in the configuration example is
`https://127.0.0.1:9443`.

### Route and role matrix

| Method | Path | administrator | ca_operations | ca_ra | auditor |
|--------|------|:---:|:---:|:---:|:---:|
| `POST` | `/admin/session` | Y | Y | Y | Y |
| `DELETE` | `/admin/session` | Y | Y | Y | Y |
| `GET` | `/admin/operators` | Y | | | |
| `POST` | `/admin/operators` | Y | | | |
| `GET` | `/admin/operators/{id}` | Y | | | |
| `PUT` | `/admin/operators/{id}` | Y | | | |
| `PATCH` | `/admin/operators/{id}` | Y | | | |
| `POST` | `/admin/operators/{id}/unlock` | Y | | | |
| `GET` | `/admin/audit` | Y | | | Y |
| `GET` | `/admin/profiles` | Y | Y | Y | Y |
| `POST` | `/admin/profiles` | Y | | | |
| `PUT` | `/admin/profiles/{id}` | Y | | | |
| `DELETE` | `/admin/profiles/{id}` | Y | | | |
| `GET` | `/admin/accounts` | Y | Y | Y | Y |
| `GET` | `/admin/account/{id}` | Y | Y | Y | Y |
| `POST` | `/admin/account/{id}/deactivate` | Y | | | |
| `GET` | `/admin/account/{id}/profile-grants` | Y | Y | Y | Y |
| `PUT` | `/admin/account/{id}/profile-grants` | Y | Y | | |
| `DELETE` | `/admin/account/{id}/profile-grants` | Y | | | |
| `GET` | `/admin/certs` | Y | Y | | Y |
| `GET` | `/admin/certs/{id}` | Y | Y | | Y |
| `GET` | `/admin/certs/{id}/download` | Y | Y | | |
| `POST` | `/admin/eab` | Y | Y | Y | |
| `GET` | `/admin/eab/{kid}` | Y | Y | Y | Y |
| `DELETE` | `/admin/eab/{kid}` | Y | Y | | |
| `GET` | `/admin/eab` | Y | Y | Y | Y |
| `GET` | `/admin/orders` | Y | Y | Y | Y |
| `GET` | `/admin/orders/{id}` | Y | Y | Y | Y |
| `GET` | `/admin/config` | Y | | | |
| `POST` | `/admin/crl/force` | Y | Y | | |
| `POST` | `/admin/revoke` | Y | Y | Y | |
| `GET` | `/admin/stats` | Y | Y | Y | Y |

### `POST /admin/session`

Authenticate and obtain a session token.  The request must carry one of the
three credential types described above.

**Response `200 OK`:**

```json
{
  "session_token": "a4f1…64-hex-chars…",
  "role": "auditor",
  "expires_at": "2026-05-02T14:00:00Z"
}
```

The token is also returned in the `X-Session-Token` response header.

### `DELETE /admin/session`

Invalidate the current session token.  The server removes the token from its
in-memory store and records an `admin.logout` audit event.

**Response: `204 No Content`.**

### `GET /admin/operators`

List all registered operators, including deactivated ones.

Query parameters: `limit` (1–1000, default 1000), `offset` (default 0).

**Response `200 OK`:**

```json
{
  "operators": [
    {
      "id": 1,
      "name": "alice",
      "role": "administrator",
      "cert_fingerprint": "a3b4c5…",
      "gssapi_principal": null,
      "created_at": "2026-05-01T09:00:00Z",
      "last_seen_at": "2026-05-02T08:30:00Z",
      "active": true,
      "failed_attempts": 0,
      "locked_until": null
    }
  ]
}
```

### `POST /admin/operators`

Register a new operator.  At least one of `cert_fingerprint` or
`gssapi_principal` must be provided.

**Request body:**

```json
{
  "name": "bob",
  "role": "auditor",
  "cert_fingerprint": "b2c3d4…",
  "gssapi_principal": null
}
```

`cert_fingerprint` is the lowercase hex SHA-256 digest of the DER-encoded
client certificate leaf.  The `akamuctl operator add --cert-file` command
computes this automatically.

**Response `201 Created`:**

```json
{ "name": "bob", "created_at": "2026-05-02T10:00:00Z" }
```

Returns `409 Conflict` when an operator with the same fingerprint or principal
already exists.

### `GET /admin/operators/{id}`

Show a single operator's details.

**Response `200 OK`:**

```json
{
  "id": 3,
  "name": "alice",
  "role": "administrator",
  "cert_fingerprint": "a3b4c5…",
  "gssapi_principal": null,
  "created_at": "2026-05-01T09:00:00Z",
  "last_seen_at": "2026-05-02T08:30:00Z",
  "active": true,
  "failed_attempts": 0,
  "locked_until": null
}
```

Returns `404 Not Found` when the ID does not exist.

### `PUT /admin/operators/{id}`

Update operator fields.  Only provided fields are changed; omitted fields remain
unchanged.

**Request body:**

```json
{
  "name": "Alice Smith",
  "role": "ca_operations",
  "cert_fingerprint": "d4e5f6…",
  "gssapi_principal": "alice@NEWREALM.COM"
}
```

All fields are optional.  `role` must be one of `administrator`, `ca_operations`,
`ca_ra`, or `auditor` when provided.

**Response: `204 No Content`** on success, `404 Not Found` when the ID does not
exist.

### `PATCH /admin/operators/{id}`

Activate or deactivate an operator.

**Request body:**

```json
{ "active": false }
```

Set `active` to `false` to deactivate, `true` to reactivate.  Deactivating an
operator immediately invalidates all of that operator's active session tokens.

**Response: `204 No Content`** on success, `404 Not Found` when the ID does not
exist.

### `POST /admin/operators/{id}/unlock`

Reset the operator's failed-authentication counter and clear the lockout
timestamp (FIA_AFL.1).  Use this when an operator has been locked out due to
exceeding `max_failed_auth`.

**Response: `204 No Content`** on success, `404 Not Found` when the ID does not
exist.

### `GET /admin/audit`

Query the structured audit event log.  See [Audit Trail](admin-api.md#audit-trail)
for details on the event taxonomy.

Query parameters:

| Parameter | Description |
|-----------|-------------|
| `type` | Filter by event type string (e.g. `cert.issue`). |
| `subject` | Filter by subject (account UUID, certificate serial, JWK thumbprint, etc.). |
| `from` | RFC 3339 lower bound for `occurred_at`. |
| `until` | RFC 3339 upper bound for `occurred_at`. |
| `outcome` | `success` or `failure`. |
| `limit` | 1–1000, default 100. |
| `offset` | Default 0. |

Results are ordered newest-first.

**Response `200 OK`:**

```json
{
  "events": [
    {
      "id": 42,
      "occurred_at": "2026-05-02T08:30:00Z",
      "event_type": "cert.issue",
      "subject": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "principal": "acme:xZ9gF…",
      "outcome": "success",
      "detail": "{\"profile\":\"tlsserver\"}"
    }
  ],
  "limit": 100,
  "offset": 0
}
```

### `GET /admin/profiles`

List all loaded certificate profiles with their parameters.

**Response `200 OK`:**

```json
{
  "profiles": [
    {
      "id": "tlsserver",
      "description": "TLS server certificate",
      "validity_days": 90,
      "hash_alg": "SHA256",
      "extended_key_usages": ["serverAuth"],
      "issue_as_mtc": false
    }
  ]
}
```

### `POST /admin/profiles`

Add a new certificate profile to the runtime cache (FPT_NPE_EXT.1).
Requires the `administrator` role.

**Request body:**

```json
{
  "id": "codesigning",
  "description": "Code signing certificate",
  "validity_days": 365,
  "hash_alg": "sha256",
  "extended_key_usages": ["code_signing"],
  "require_account_grant": true
}
```

All fields except `id` are optional and have defaults (90 days validity, `sha256`
hash, no extended key usage restriction).  Returns `409 Conflict` when a profile
with the same `id` already exists.

**Response `201 Created`:**

```json
{ "id": "codesigning", "description": "Code signing certificate" }
```

### `PUT /admin/profiles/{id}`

Replace an existing certificate profile in the runtime cache (FPT_NPE_EXT.1).
The profile is identified by `{id}` in the URL path; the request body uses the
same schema as `POST /admin/profiles` but without the `id` field.
Requires the `administrator` role.

**Response: `204 No Content`** on success, `404 Not Found` when the profile does
not exist.

### `DELETE /admin/profiles/{id}`

Remove a certificate profile from the runtime cache (FPT_NPE_EXT.1).
Requires the `administrator` role.

**Response: `204 No Content`** on success, `404 Not Found` when the profile does
not exist.

### `GET /admin/accounts`

List ACME accounts with optional filtering and pagination.

Query parameters:

| Parameter | Description |
|-----------|-------------|
| `status` | Filter by account status (`valid` or `deactivated`). |
| `limit` | 1–1000, default 100. |
| `offset` | Default 0. |

**Response `200 OK`:**

```json
{
  "accounts": [
    {
      "id": "d290f1ee-…",
      "status": "valid",
      "contact": "[\"mailto:admin@example.com\"]",
      "jwk_thumbprint": "xZ9gF…",
      "created": 1746154800,
      "updated": 1746241200,
      "profile_grants": "[\"tlsserver\"]"
    }
  ],
  "limit": 100,
  "offset": 0
}
```

### `GET /admin/account/{id}`

Show a single account's details.

**Response `200 OK`:**

```json
{
  "id": "d290f1ee-…",
  "status": "valid",
  "contact": "[\"mailto:admin@example.com\"]",
  "jwk_thumbprint": "xZ9gF…",
  "created": 1746154800,
  "updated": 1746241200,
  "profile_grants": "[\"tlsserver\"]"
}
```

Returns `404 Not Found` when the account does not exist.

### `POST /admin/account/{id}/deactivate`

Admin-initiated account deactivation.  Sets the account status to `deactivated`.
The account can no longer create orders or issue certificates.

**Response: `204 No Content`** on success, `404 Not Found` when the account
does not exist.

### `GET /admin/account/{id}/profile-grants`

Return the profile grant list for account `{id}`.  `null` means the account
has no restrictions and may request any profile.

**Response `200 OK`:**

```json
{ "profile_grants": ["tlsserver", "codesigning"] }
```

or

```json
{ "profile_grants": null }
```

### `PUT /admin/account/{id}/profile-grants`

Replace the account's profile grant list.

**Request body:**

```json
{ "profile_grants": ["tlsserver"] }
```

**Response: `204 No Content`.**

### `DELETE /admin/account/{id}/profile-grants`

Clear all profile restrictions.  Sets `profile_grants` to `null`
(unrestricted).

**Response: `204 No Content`.**

### `GET /admin/certs`

Search the certificate table.

Query parameters: `serial`, `subject` (subject DN substring match), `account_id`,
`after` (RFC 3339), `before` (RFC 3339), `status` (`active` or `revoked`),
`limit` (1–1000, default 100), `offset`.

**Response `200 OK`:**

```json
{
  "certs": [
    {
      "id": "3fa85f64-…",
      "account_id": "d290f1ee-…",
      "serial_number": "0a1b2c3d",
      "status": "active",
      "not_before": "2026-05-01T00:00:00Z",
      "not_after": "2026-07-30T00:00:00Z",
      "revoked_at": null,
      "revocation_reason": null
    }
  ],
  "limit": 100,
  "offset": 0
}
```

### `GET /admin/certs/{id}`

Show a single certificate's metadata.  Does not return the PEM or DER content
(use the download endpoint for that).

**Response `200 OK`:**

```json
{
  "id": "3fa85f64-…",
  "order_id": "7b2e1a3f-…",
  "account_id": "d290f1ee-…",
  "serial_number": "0a1b2c3d",
  "status": "active",
  "not_before": "2026-05-01T00:00:00Z",
  "not_after": "2026-07-30T00:00:00Z",
  "revoked_at": null,
  "revocation_reason": null,
  "mtc_log_index": null,
  "created": 1746154800,
  "suggested_window_start": 1750000000,
  "suggested_window_end": 1751000000,
  "replaced_by": null
}
```

Returns `404 Not Found` when the certificate does not exist.

### `GET /admin/certs/{id}/download`

Download a certificate's content as PEM or DER.

Query parameters:

| Parameter | Description |
|-----------|-------------|
| `format` | `pem` (default) or `der`. |

**Response `200 OK`:**

- PEM format: `Content-Type: application/pem-certificate-chain`
- DER format: `Content-Type: application/pkix-cert`

Returns `404 Not Found` when the certificate does not exist.

### `POST /admin/eab`

Provision a new External Account Binding key.

**Request body:**

```json
{
  "kid": "my-device-001",
  "hmac_key_b64u": "c2VjcmV0LWhtYWMta2V5LWJ1ZmZlcg",
  "profile_grants": ["tlsserver"]
}
```

`profile_grants` is optional; omit it or set it to `null` for an unrestricted
key.  Returns `409 Conflict` when the `kid` already exists.

**Response `201 Created`:**

```json
{ "kid": "my-device-001", "created": 1746154800 }
```

### `GET /admin/eab/{kid}`

Show a single EAB key's details.

**Response `200 OK`:**

```json
{
  "kid": "my-device-001",
  "created": 1746154800,
  "used_at": null,
  "profile_grants": "[\"tlsserver\"]"
}
```

Returns `404 Not Found` when the key does not exist.

### `DELETE /admin/eab/{kid}`

Deactivate an EAB key.  The key is removed from the table; any previously
issued HMAC credentials for this `kid` are permanently invalidated.

**Response: `204 No Content`**, `404 Not Found` when the key does not exist.

### `GET /admin/eab`

List EAB keys.

Query parameters: `used` (`true`/`false` to filter by usage status), `limit`
(1–1000, default 200), `offset`.

**Response `200 OK`:**

```json
{
  "eab_keys": [
    {
      "kid": "my-device-001",
      "created": 1746154800,
      "used_at": null,
      "profile_grants": "[\"tlsserver\"]"
    }
  ]
}
```

### `GET /admin/orders`

List certificate orders with optional filtering and pagination.

Query parameters:

| Parameter | Description |
|-----------|-------------|
| `account_id` | Filter by account UUID. |
| `status` | Filter by order status (`pending`, `ready`, `processing`, `valid`, `invalid`). |
| `limit` | 1–1000, default 100. |
| `offset` | Default 0. |

**Response `200 OK`:**

```json
{
  "orders": [
    {
      "id": "7b2e1a3f-…",
      "account_id": "d290f1ee-…",
      "status": "valid",
      "identifiers": "[{\"type\":\"dns\",\"value\":\"example.com\"}]",
      "certificate_id": "3fa85f64-…",
      "profile": "tlsserver",
      "created": 1746154800,
      "updated": 1746241200,
      "expires": 1746760800
    }
  ],
  "limit": 100,
  "offset": 0
}
```

### `GET /admin/orders/{id}`

Show a single order's details, including authorization IDs.

**Response `200 OK`:**

```json
{
  "id": "7b2e1a3f-…",
  "account_id": "d290f1ee-…",
  "status": "valid",
  "identifiers": "[{\"type\":\"dns\",\"value\":\"example.com\"}]",
  "certificate_id": "3fa85f64-…",
  "profile": "tlsserver",
  "created": 1746154800,
  "updated": 1746241200,
  "expires": 1746760800,
  "not_before": null,
  "not_after": null,
  "replaces": null,
  "authorization_ids": ["a1b2c3d4-…", "e5f6a7b8-…"]
}
```

Returns `404 Not Found` when the order does not exist.

### `GET /admin/config`

Show the server's redacted runtime configuration.  Sensitive values such as the
database URL are masked.

**Response `200 OK`:**

```json
{
  "base_url": "https://acme.example.com",
  "db_url": "***",
  "mtc_enabled": false,
  "caa_identities": ["example.com"],
  "validate_dnssec": true
}
```

### `POST /admin/crl/force`

Force immediate CRL regeneration.  The cached CRL is invalidated so the next
`GET /ca/crl` request produces a fresh CRL reflecting all current revocations.

**Response: `204 No Content`.**

### `POST /admin/revoke`

Revoke a certificate by its internal ID.

**Request body:**

```json
{ "cert_id": "3fa85f64-…", "reason": 1 }
```

`reason` is an RFC 5280 reason code (0 = unspecified, 1 = keyCompromise,
3 = affiliationChanged, 4 = superseded, 5 = cessationOfOperation, etc.).
Revocation immediately invalidates the CRL cache.

**Response: `204 No Content`**, `404 Not Found` when the certificate is not
found or is already revoked.

### `GET /admin/stats`

Return live server statistics.  All authenticated roles may call this endpoint.

**Response `200 OK`:**

```json
{
  "server_version": "0.1.0",
  "uptime_secs": 3600,
  "accounts": { "total": 42, "active": 40 },
  "certs":    { "total": 200, "active": 180, "revoked": 20 },
  "eab_keys": { "total": 10, "used": 8, "unused": 2 },
  "audit_events": { "total": 5000 }
}
```

## Audit trail

Every admin operation is persisted to the `audit_events` database table.
The table is append-only at the application level.  Records include the
timestamp, event type, subject (the resource being acted on), principal (the
authenticated operator or ACME account), outcome (`success` or `failure`), and
a JSON `detail` object with operation-specific fields.

### Overflow policy (FAU_STG.4)

When `audit_max_rows` is set and the table reaches the limit, the
`audit_overflow` policy determines what happens.  The default is
`"drop_oldest"`, which deletes the oldest rows to make room.  The alternative
`"halt"` refuses all new requests until an administrator manually prunes the
table.

### Alarm response (FAU_ARP.1)

The server maintains an in-memory rolling 5-minute count of
`security.violation` audit events.  When the count reaches
`audit_alarm_threshold` (default 10), the `audit_alarm_action` fires:

- `"syslog"` (default) — a `CRIT`-level message is emitted via `tracing`,
  which is forwarded to the system log by the process manager.
- `"halt"` — the server stops accepting new requests until restarted.

The halt flag is also set when the `"halt"` overflow policy is triggered.

## Operator management workflow

### Initial setup

Akāmu auto-provisions the first administrator on first run.  Add two keys to
`[admin]` that point to where the bootstrap certificate and key should live:

```toml
[admin]
listen_addr    = "127.0.0.1:9443"
cert_file      = "/etc/akamu/admin-tls.pem"
key_file       = "/etc/akamu/admin-tls-key.pem"
ca_certs       = ["/etc/akamu/ca.pem"]

# Bootstrap operator — generated automatically on first run.
bootstrap_operator_cert_file = "/etc/akamu/admin-bootstrap.pem"
bootstrap_operator_key_file  = "/etc/akamu/admin-bootstrap-key.pem"
# bootstrap_operator_name    = "admin"   # default
# bootstrap_key_type         = "ec:P-256"  # default
```

On the first startup, if both files are absent **and** the operators table is
empty, Akāmu:

1. Generates a fresh private key (using `bootstrap_key_type`).
2. Issues a client certificate signed by the Akāmu CA with `CN=<bootstrap_operator_name>`.
3. Writes the key and certificate PEM files to the configured paths.
4. Registers the certificate's SHA-256 fingerprint in the operators table with
   the `administrator` role.

Both the admin listener TLS certificate (`cert_file`/`key_file`) and the
bootstrap operator cert are auto-generated if absent; the admin listener cert
uses `server_name` (default `"localhost"`) as the CN/SAN.

After first boot, use the bootstrap cert to authenticate and provision real
operator accounts:

```bash
# Add a permanent operator with their own client cert.
akamuctl --cert /etc/akamu/admin-bootstrap.pem \
         --key  /etc/akamu/admin-bootstrap-key.pem \
    operator add --name alice --role administrator \
                 --cert-file /etc/akamu/alice-client.pem

# Deactivate the bootstrap operator once a permanent one is in place.
akamuctl --cert /etc/akamu/admin-bootstrap.pem \
         --key  /etc/akamu/admin-bootstrap-key.pem \
    operator remove 1
```

> **Note:** If the bootstrap cert/key files are absent but the operators table
> already contains rows (e.g. after a mistaken file deletion), Akāmu refuses to
> start with an error rather than silently creating a duplicate administrator.
> Restore the files from backup, or remove `bootstrap_operator_cert_file` and
> `bootstrap_operator_key_file` from the config and manage operators entirely
> through `akamuctl`.

### Revoking access

Deactivate an operator with `akamuctl operator remove <id>` or
`PATCH /admin/operators/{id}` with `{"active":false}`.  The record is
preserved for audit trail continuity.  The operator's active sessions are
invalidated immediately and they cannot authenticate again until reactivated.
