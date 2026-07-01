# Admin API and Operator Management

> **API Reference** — This page documents the admin REST API for operators and automation tools. For the akamuctl CLI that wraps this API, see [akamuctl — Admin CLI](../user/akamuctl.md) in the Operator Guide.

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

Each operator has exactly one role that determines which admin endpoints they
may call.  For a full description of each role, its capabilities, restrictions,
and the complete route-by-role permission matrix, see
[Operator Roles](operator-roles.md).

## Endpoint reference

All paths are relative to the admin listener base URL.  The `[admin].listen_addr`
field controls the address; the default in the configuration example is
`https://127.0.0.1:9443`.

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
in-memory store, records an `admin.logout` audit event, and returns a
`Set-Cookie: session=; Max-Age=0` header that instructs the browser to
immediately expire the session cookie set at login.

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

Update the `active` status or `ca_id` scope of an operator.

**Request body:**

```json
{ "active": false }
```

or, to assign a CA scope to a `ca_ra` operator:

```json
{ "ca_id": "rsa" }
```

Set `active` to `false` to deactivate, `true` to reactivate. Deactivating an
operator immediately invalidates all of that operator's active session tokens.

When `ca_id` is provided, the operator's CA scope is updated. Setting
`role = "ca_ra"` without also providing a non-empty `ca_id` (either in this
request or already stored) is rejected with `422 Unprocessable Entity`.

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
      "occurred_at": "2026-05-02T08:30:00Z",
      "event_type": "cert.issue",
      "subject": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
      "principal": "acme:xZ9gF…",
      "outcome": "success",
      "detail": "{\"profile\":\"tlsserver\"}"
    }
  ],
  "total_since_startup": 5000,
  "limit": 100,
  "offset": 0
}
```

**Error responses:**

| Status | Condition |
|--------|-----------|
| `400 Bad Request` | The `from` or `until` parameter is not a valid RFC 3339 timestamp. The response body includes a `detail` field describing the error. |
| `500 Internal Server Error` | The audit backend (journal namespace socket, JSONL file, or journalctl subprocess) is inaccessible. The response body includes `{"status": 500, "detail": "journal query error"}`. |

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

### `GET /admin/profiles/{id}`

Return a single certificate profile by ID.

**Response `200 OK`:**

```json
{
  "id": "codesigning",
  "description": "Code signing certificate",
  "validity_days": 365,
  "hash_alg": "SHA256",
  "key_usage_bits": null,
  "extended_key_usages": ["code_signing"],
  "crl_url": null,
  "ocsp_url": null,
  "allowed_key_types": null,
  "certificate_policies": null,
  "issue_as_mtc": false,
  "allowed_identifier_patterns": null,
  "identifier_match_all": false,
  "auth_hook": null,
  "auth_hook_timeout_secs": null,
  "require_account_grant": true,
  "ca_ids": null
}
```

Returns `404 Not Found` when no profile with the given ID is loaded.

Requires any authenticated role.

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
| `ca_id` | Filter by CA ID. Only accounts registered via the named CA's `new-account` endpoint are returned. |
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

Query parameters: `ca_id` (filter by CA ID), `serial`, `subject` (subject DN substring match), `account_id`,
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
Requires the `administrator` or `ca_operations` role.

**Request body:**

```json
{
  "kid": "my-device-001",
  "hmac_key_b64u": "c2VjcmV0LWhtYWMta2V5LWJ1ZmZlcg",
  "profile_grants": ["tlsserver"],
  "alg": "sha256",
  "for_operator_id": 3
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `kid` | Yes | Unique key identifier string. |
| `hmac_key_b64u` | Yes | Base64url-encoded raw HMAC key bytes (no padding). |
| `profile_grants` | No | Array of profile names the EAB key pre-authorizes. Omit or set to `null` for an unrestricted key. |
| `alg` | No | HMAC algorithm: `"sha256"` (default), `"sha384"`, or `"sha512"`. |
| `for_operator_id` | No | **Administrator only.** When set, `created_by_operator_id` on the new key is set to this operator ID instead of the calling operator. This controls which operator the key is associated with for `POST /admin/session/eab` web UI login. |

EAB keys are server-global and are not bound to any CA, even when created by a
scoped `ca_operations` operator.  Only `administrator` may set `for_operator_id`;
a `ca_operations` caller that includes it receives `403 Forbidden`.

Returns `409 Conflict` when the `kid` already exists.

**Response `201 Created`:**

```json
{ "kid": "my-device-001", "created": 1746154800, "alg": "sha256" }
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
| `ca_id` | Filter by CA ID. |
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
  "audit_events": { "since_startup": 5000 }
}
```

## CA management endpoints

### `GET /admin/cas`

List all configured CAs.

**Response `200 OK`:**

```json
{
  "cas": [
    {
      "id": "rsa",
      "is_default": true,
      "key_type": "rsa:4096",
      "hash_alg": "sha256",
      "crl_url": "http://acme.example.com/ca/rsa/crl",
      "ocsp_url": "http://acme.example.com/ca/rsa/ocsp"
    }
  ]
}
```

### `GET /admin/cas/{id}`

Show details of a single CA including the CA certificate PEM.

**Response `200 OK`:**

```json
{
  "id": "rsa",
  "is_default": true,
  "key_type": "rsa:4096",
  "hash_alg": "sha256",
  "crl_url": "http://acme.example.com/ca/rsa/crl",
  "ocsp_url": "http://acme.example.com/ca/rsa/ocsp",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n"
}
```

Returns `404 Not Found` when the CA ID does not exist.

### `POST /admin/ca/{id}/crl/force`

Force immediate CRL regeneration for the specified CA. The cached CRL is
invalidated so the next `GET /ca/{id}/crl` request produces a fresh CRL
reflecting all current revocations for that CA.

Requires the `ca_operations` or `administrator` role.

**Response: `204 No Content`.** Returns `404 Not Found` when the CA ID does
not exist.

### `POST /admin/ca/{id}/cross-sign`

Issue a cross-certificate: CA `{id}` (the issuer) signs the public key of
another CA or an externally supplied certificate. The resulting cross-cert is
stored in the database and retrievable via `GET /admin/cross-certs/{id}` and
the public `GET /ca/{subject_id}/cross-certs` endpoint.

The issued cross-certificate always has `pathLenConstraint = 0` — the subject
CA cannot use it to issue further subordinate CAs.

**Request body** (exactly one of `subject_ca_id` or `subject_cert_pem` must
be provided):

```json
{ "subject_ca_id": "ec", "validity_years": 5 }
```

or

```json
{ "subject_cert_pem": "-----BEGIN CERTIFICATE-----\n…", "validity_years": 5 }
```

Requires the `administrator` or `ca_operations` role.

**Response `201 Created`:**

```json
{ "id": "a1b2c3d4-…", "created_at": "2026-05-06T12:00:00Z" }
```

Returns `404 Not Found` when the issuer CA ID or `subject_ca_id` does not exist.

### `GET /admin/cross-certs`

List stored cross-certificates.

Query parameters:

| Parameter | Description |
|-----------|-------------|
| `issuer_ca_id` | Filter by issuing CA ID. |
| `subject_ca_id` | Filter by subject CA ID. |
| `limit` | 1–1000, default 100. |
| `offset` | Default 0. |

**Response `200 OK`:**

```json
{
  "cross_certs": [
    {
      "id": "a1b2c3d4-…",
      "issuer_ca_id": "rsa",
      "subject_ca_id": "ec",
      "not_before": "2026-05-06T12:00:00Z",
      "not_after": "2031-05-06T12:00:00Z",
      "created_at": "2026-05-06T12:00:00Z"
    }
  ],
  "limit": 100,
  "offset": 0
}
```

### `GET /admin/cross-certs/{id}`

Show a single cross-certificate by UUID, including its PEM.

**Response `200 OK`:**

```json
{
  "id": "a1b2c3d4-…",
  "issuer_ca_id": "rsa",
  "subject_ca_id": "ec",
  "not_before": "2026-05-06T12:00:00Z",
  "not_after": "2031-05-06T12:00:00Z",
  "created_at": "2026-05-06T12:00:00Z",
  "cert_pem": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n"
}
```

Returns `404 Not Found` when the cross-cert ID does not exist.

## Delegation management endpoints

These endpoints are active only when `server.delegation_enabled = true` is set in the configuration. Delegations represent pre-configured RFC 9115 IdO-to-NDC delegation policies: a CSR template and an optional CNAME map. Read operations (`GET`) are available to all authenticated roles; write operations (`POST`, `PUT`, `DELETE`) require the `administrator` or `ca_operations` role.

### `GET /admin/delegations`

List all delegation objects. Optionally filter by account.

Query parameters:

| Parameter | Description |
|-----------|-------------|
| `account_id` | Filter by ACME account UUID. |
| `limit` | 1–1000, default 100. |
| `offset` | Default 0. |

**Response `200 OK`:**

```json
{
  "delegations": [
    {
      "id": "b1c2d3e4-…",
      "account_id": "d290f1ee-…",
      "csr_template": "{…}",
      "cname_map": null,
      "created": 1746154800,
      "updated": 1746154800
    }
  ],
  "limit": 100,
  "offset": 0
}
```

### `POST /admin/delegations`

Create a new delegation object. The `csr_template` field is validated against the RFC 9115 §4 schema at write time; a malformed template is rejected with `400 Bad Request`.

**Request body:**

```json
{
  "account_id": "d290f1ee-…",
  "csr_template": {
    "keyTypes": [{"type": "EC", "curve": "P-256"}],
    "subject": {"commonName": {}, "organization": "ExampleCorp"},
    "extensions": {
      "subjectAltName": {},
      "keyUsage": ["digitalSignature"],
      "extendedKeyUsage": ["1.3.6.1.5.5.7.3.1"]
    }
  },
  "cname_map": null
}
```

`cname_map` is optional. When present it is a JSON object mapping source FQDNs to target FQDNs (e.g. `{"cdn.example.com": "cdn.provider.example"}`).

**Response `201 Created`:**

```json
{ "id": "b1c2d3e4-…", "created": 1746154800 }
```

### `GET /admin/delegations/{id}`

Fetch a single delegation object by UUID.

**Response `200 OK`:**

```json
{
  "id": "b1c2d3e4-…",
  "account_id": "d290f1ee-…",
  "csr_template": "{…}",
  "cname_map": null,
  "created": 1746154800,
  "updated": 1746154800
}
```

Returns `404 Not Found` when the ID does not exist.

### `PUT /admin/delegations/{id}`

Replace the `csr_template` and/or `cname_map` of an existing delegation. The `csr_template` is re-validated at write time. Only `csr_template` and `cname_map` may be updated; `account_id` is immutable.

**Request body:**

```json
{
  "csr_template": {…},
  "cname_map": {"cdn.example.com": "cdn.provider.example"}
}
```

**Response: `204 No Content`** on success, `404 Not Found` when the ID does not exist.

### `DELETE /admin/delegations/{id}`

Delete a delegation object. Returns `409 Conflict` when one or more orders still reference this delegation (the orders must be finalized or deleted first).

**Response: `204 No Content`**, `404 Not Found` when the ID does not exist, `409 Conflict` when orders reference it.

### Audit events

Every write operation emits a structured audit event to the configured audit backend (systemd journal namespace, JSONL file, or in-process store):

| Operation | Event type |
|-----------|------------|
| `POST /admin/delegations` | `delegation.create` |
| `PUT /admin/delegations/{id}` | `delegation.update` |
| `DELETE /admin/delegations/{id}` | `delegation.delete` |

Query these events with `GET /admin/audit?type=delegation.create` or `akamuctl audit --type delegation.create`.

### CLI

All delegation management endpoints are wrapped by `akamuctl delegation`.  See
[akamuctl — Admin CLI](akamuctl.md#delegation-management) for the full command
reference including flags and examples.


## Audit trail

Every admin operation is written to a structured audit backend.  Three
backends are available:

1. **Systemd journal namespace** (default) — when running under systemd with
   `LogNamespace=akamu` (see `contrib/systemd/akamu.service`), events are
   stored in `/var/log/journal/<machine-id>.akamu/`.
2. **JSONL file** — when `[server].audit_log_file` is set, events are written
   as append-only JSON Lines to the specified file.  External `logrotate(8)`
   with `copytruncate` is expected for rotation.  Each query scans at most
   500,000 lines to prevent unbounded reads on unrotated files.
3. **In-process store** — in tests or development without systemd and without
   a configured file, an in-memory store is used automatically.

Each journal entry carries structured fields:

| Journal field | Content |
|---------------|---------|
| `AKAMU_EVENT_TYPE` | Event type string (e.g. `cert.issue`, `admin.login`) |
| `AKAMU_SUBJECT` | Resource identifier (account UUID, certificate serial, etc.) |
| `AKAMU_PRINCIPAL` | Authenticated operator name or `acme:<jwk_thumbprint>` |
| `AKAMU_OUTCOME` | `success` or `failure` |
| `AKAMU_DETAIL` | JSON object with operation-specific fields |

Query examples:

```bash
journalctl --namespace=akamu                              # all audit events
journalctl --namespace=akamu AKAMU_EVENT_TYPE=cert.issue   # by type
journalctl --namespace=akamu AKAMU_OUTCOME=failure         # failures only
```

Retention is managed by journald itself (see `contrib/systemd/journald@akamu.conf`
for default settings: 500 MB disk, 1 year max age).

### Overflow policy (FAU_STG.4)

When `audit_max_events` is set (backward-compatible alias: `audit_max_rows`),
the server tracks an in-memory event count since startup.  The
`audit_overflow` policy determines what happens when the count reaches the
limit.  The default is `"drop_oldest"`, which is effectively a no-op
(journald or the file backend manages its own retention).  The alternative
`"halt"` refuses all new requests until the server is restarted.

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
# bootstrap_operator_name    = "admin"   # default (bare name → directoryName SAN)
# bootstrap_operator_name    = "dns:admin.example.com"  # dNSName SAN
# bootstrap_key_type         = "ec:P-256"  # default
```

On the first startup, if both files are absent **and** the operators table is
empty, Akāmu:

1. Generates a fresh private key (using `bootstrap_key_type`).
2. Issues a client certificate signed by the Akāmu CA with `CN=<bootstrap_operator_name>` and a SubjectAltName extension. The SAN type is selected by an optional prefix on the name (`dns:`, `email:`, `ip:`, `uri:`, `dn:`); a bare name defaults to a `directoryName` SAN built from the Subject DN. See [`bootstrap_operator_name`](configuration.md#bootstrap_operator_name) for the full prefix table.
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
