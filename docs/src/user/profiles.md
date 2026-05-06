# Certificate Profiles

Certificate profiles let `Akāmu` issue certificates with different extension sets, validity periods, and key usage policies depending on the use case. Without profiles every order gets the same default profile: `digitalSignature` KeyUsage, `serverAuth` EKU, and the validity and URL settings from `[ca]`. With profiles configured, clients can request a named policy at order time and the server enforces it at issuance.

Profiles implement [draft-aaron-acme-profiles-01](https://www.ietf.org/archive/id/draft-aaron-acme-profiles-01.html).

---

## How it works

1. At startup `Akāmu` loads profile definitions from one or more *providers* (see below) and caches them in memory.
2. The directory endpoint advertises the available profiles in `meta.profiles`.
3. A client includes `"profile": "<name>"` in its `newOrder` request.
4. At finalize time the server resolves the profile's `CertificateParameters` and issues the certificate with those extension values; `Akāmu`'s own CA always signs.
5. A background task refreshes the cache every `refresh_interval_secs` seconds (default: 3600).

If no profile is requested, or no providers are configured, the server falls back to CA defaults unchanged.

---

## Configuration overview

```toml
[profiles]
refresh_interval_secs = 3600   # how often to reload from providers (default)

# ── Provider 1: inline TOML definitions ─────────────────────────────────────
[profiles.providers.local]
type = "builtin"

[profiles.providers.local.profiles.tlsserver]
description   = "Standard TLS server certificate"
validity_days = 90
key_usage     = ["digital_signature", "key_encipherment"]
eku           = ["server_auth"]

[profiles.providers.local.profiles.clientauth]
description   = "Client authentication certificate"
validity_days = 365
key_usage     = ["digital_signature"]
eku           = ["client_auth"]

# ── Provider 2: Dogtag PKI profile files ────────────────────────────────────
[profiles.providers.dogtag_prod]
type        = "dogtag"
profile_dir = "/etc/pki/pki-tomcat/ca/profiles/ca"
profiles    = ["caServerCert", "caIPAserviceCert"]   # empty = all

# ── Provider 3: FreeIPA/IPAThinCA via GSSAPI LDAP ───────────────────────────
[profiles.providers.ipa_prod]
type     = "ipa"
profiles = ["caIPAserviceCert", "IECUserRoles"]

[profiles.providers.ipa_prod.ldap]
uri     = "ldap://ipa.example.com:389"
base_dn = "o=ipaca"
gssapi  = true
```

---

## Provider types

### `builtin` — inline TOML

Define profiles directly in `config.toml`. No external system required.

```toml
[profiles.providers.local]
type = "builtin"

[profiles.providers.local.profiles.<profile-id>]
description   = "Human-readable description shown in meta.profiles"
validity_days = 90          # optional; inherits from [ca].validity_days
hash_alg      = "sha256"    # optional; inherits from [ca].hash_alg
key_usage     = ["digital_signature"]   # see table below
eku           = ["server_auth"]         # see table below
crl_url       = "http://crl.example.com/ca.crl"   # optional
ocsp_url      = "http://ocsp.example.com"          # optional
allowed_key_types = ["ec:P-256", "rsa:2048"]       # optional; empty = any
issue_as      = "mtc"       # optional; "mtc" or absent/"x509" for standard X.509

# Multi-CA restriction (optional; empty = available via all CAs)
ca_ids               = ["rsa", "ec"]              # restrict to specific CA IDs

# Per-profile authorization (all three checks are AND-combined)
allowed_identifiers  = ['^dns:.*\.example\.com$']  # optional; empty = no restriction
identifier_match     = "all"                        # "all" (default) or "any"
auth_hook            = "/etc/akamu/hooks/auth.sh"  # optional; path to executable
auth_hook_timeout_secs = 30                         # optional; default 30
require_account_grant  = false                      # optional; default false

[[profiles.providers.local.profiles.<profile-id>.certificate_policies]]
oid     = "2.23.140.1.2.1"                         # DV certificate
cps_uri = "https://example.com/cps"               # optional
```

**`key_usage` names**

| Name | KeyUsage bit |
|------|-------------|
| `digital_signature` | `digitalSignature` (bit 0) |
| `non_repudiation` / `content_commitment` | `nonRepudiation` (bit 1) |
| `key_encipherment` | `keyEncipherment` (bit 2) |
| `data_encipherment` | `dataEncipherment` (bit 3) |
| `key_agreement` | `keyAgreement` (bit 4) |
| `key_cert_sign` | `keyCertSign` (bit 5) |
| `crl_sign` | `cRLSign` (bit 6) |
| `encipher_only` | `encipherOnly` (bit 7) |
| `decipher_only` | `decipherOnly` (bit 8) |

**`eku` names and dotted-decimal OIDs**

| Name | OID |
|------|-----|
| `server_auth` | 1.3.6.1.5.5.7.3.1 |
| `client_auth` | 1.3.6.1.5.5.7.3.2 |
| `code_signing` | 1.3.6.1.5.5.7.3.3 |
| `email_protection` | 1.3.6.1.5.5.7.3.4 |
| `time_stamping` | 1.3.6.1.5.5.7.3.8 |
| `ocsp_signing` | 1.3.6.1.5.5.7.3.9 |
| `1.2.3.4.5.6` | raw dotted-decimal OID string |

**`crl_url` / `ocsp_url` three-state semantics**

| Value | Effect |
|-------|--------|
| Absent (key not set) | Inherit from `[ca].crl_url` / `[ca].ocsp_url` |
| `""` (empty string) | Suppress the extension — no CDP / AIA in the certificate |
| `"https://…"` | Override with the given URL |

---

### `dogtag` — Dogtag PKI profile files

Load profiles from a Dogtag PKI `.cfg` file directory. Each file is named `<profile-id>.cfg` and uses the Dogtag Java-properties format.

```toml
[profiles.providers.dogtag_prod]
type        = "dogtag"
profile_dir = "/etc/pki/pki-tomcat/ca/profiles/ca"
profiles    = ["caServerCert", "caIPAserviceCert"]
# profiles = []   # empty = load all .cfg files in the directory
```

| Key | Required | Description |
|-----|----------|-------------|
| `profile_dir` | Conditional | Path to directory of `.cfg` files |
| `ldap` | Conditional | LDAP connection sub-table; see LDAP options under [ipa](#ipa--freeipaipathinca) below |
| `profiles` | No | Allowlist of profile IDs; empty = all |

At least one of `profile_dir` or `ldap` must be set. When both are configured, `ldap` takes priority.

```toml
# LDAP source — simple bind, TLS via STARTTLS
[profiles.providers.dogtag_ldap]
type     = "dogtag"
profiles = ["caServerCert"]

[profiles.providers.dogtag_ldap.ldap]
uri                = "ldap://dogtag.example.com:389"
base_dn            = "dc=example,dc=com"
bind_dn            = "uid=admin,ou=people,dc=example,dc=com"
bind_password_file = "/etc/akamu/ldap-password"
tls_ca_cert_file   = "/etc/ssl/certs/ldap-ca.pem"   # triggers STARTTLS on ldap:// URIs

# LDAP source — multiple servers, GSSAPI
[profiles.providers.dogtag_ha]
type     = "dogtag"
profiles = ["caServerCert"]

[profiles.providers.dogtag_ha.ldap]
uris    = ["ldap://dogtag1.example.com:389", "ldap://dogtag2.example.com:389"]
base_dn = "dc=example,dc=com"
gssapi  = true
```

**Supported Dogtag policy classes**

| Class | Fields extracted |
|-------|-----------------|
| `validityDefaultImpl` | `params.range` + `params.rangeUnit` → validity days |
| `keyUsageExtDefaultImpl` | 9 `params.keyUsage*` booleans → KeyUsage bitmask |
| `extendedKeyUsageExtDefaultImpl` | `params.exKeyUsageOIDs` comma-separated OIDs → EKU list |
| `authInfoAccessExtDefaultImpl` | OCSP URL via method `1.3.6.1.5.5.7.48.1` → `ocsp_url` |
| `crlDistributionPointsExtDefaultImpl` | `params.crlDistPointsPointName_0` → `crl_url` |

Unrecognised policy class IDs are silently skipped.

---

### `ipa` — FreeIPA / IPAThinCA

Load profiles from a FreeIPA or IPAThinCA instance. Profile `.cfg` files use the same Dogtag format. The standard location for IPA-embedded Dogtag is `/etc/pki/pki-tomcat/ca/profiles/ca` on the IPA server, and LDAP profiles are stored at `ou=certificateProfiles,ou=ca,o=ipaca` — accessible on the standard LDAP ports (389 for plain/STARTTLS, 636 for LDAPS).

```toml
# Filesystem source
[profiles.providers.ipa_prod]
type        = "ipa"
profile_dir = "/etc/pki/pki-tomcat/ca/profiles/ca"
profiles    = ["caIPAserviceCert"]

# LDAP source — single server, simple bind
[profiles.providers.ipa_ldap]
type     = "ipa"
profiles = ["caIPAserviceCert"]

[profiles.providers.ipa_ldap.ldap]
uri                = "ldap://ipa.example.com:389"
base_dn            = "o=ipaca"
bind_dn            = "uid=admin,cn=users,cn=accounts,dc=example,dc=com"
bind_password_file = "/etc/akamu/ipa-ldap-password"

# LDAP source — multiple servers (failover list), GSSAPI
[profiles.providers.ipa_ha]
type     = "ipa"
profiles = ["caIPAserviceCert"]

[profiles.providers.ipa_ha.ldap]
uris    = ["ldap://ipa1.example.com:389", "ldap://ipa2.example.com:389"]
base_dn = "o=ipaca"
gssapi  = true

# LDAP source — SRV-based discovery, GSSAPI
[profiles.providers.ipa_gssapi]
type     = "ipa"
profiles = ["caIPAserviceCert"]

[profiles.providers.ipa_gssapi.ldap]
srv_domain = "example.com"   # resolves _ldap._tcp.example.com SRV records
base_dn    = "o=ipaca"
gssapi     = true
```

**LDAP server selection**

| Key | Description |
|-----|-------------|
| `uri` | Single LDAP URI: `ldap://host:port` or `ldaps://host:port`. |
| `uris` | List of LDAP URIs tried in order for failover. |
| `srv_domain` | Discover servers via DNS SRV (`_ldap._tcp.{srv_domain}`), sorted by RFC 2782 priority/weight. Appended after any explicit `uris`. |

At least one of `uri`, `uris`, or `srv_domain` must be set.

**LDAP authentication options**

| Key | Description |
|-----|-------------|
| `bind_dn` | Bind DN for simple authentication. Required for simple bind. |
| `bind_password_file` | Path to a file containing the simple bind password. Required when `bind_dn` is set. |
| `gssapi = true` | Use SASL GSSAPI (Kerberos). Pre-condition: the process must have a valid Kerberos TGT in its credential cache (e.g. obtained via `kinit` or a system keytab). No explicit credentials are passed to the server. |
| `tls_ca_cert_file` | Path to a PEM CA certificate for verifying the LDAP server's TLS certificate. When set on an `ldap://` URI, STARTTLS is negotiated automatically before any credentials are sent. |

> **Attribute name lowercasing**: the `akamu-ldap` library normalises all LDAP attribute names to lower case in the returned entries. Profile lookup keys such as `cn` and `certProfileConfig` are matched in lower case internally; this is transparent to the operator.

---

## Refresh behaviour

`Akāmu` loads all providers once at startup and caches the results. A background tokio task wakes every `refresh_interval_secs` seconds and re-loads all providers, atomically replacing the cache. Certificates being issued concurrently always see a consistent snapshot.

If a refresh fails (e.g., a `.cfg` file is temporarily unreadable), the previous cache is kept and a warning is logged. The server never stops serving because of a failed refresh.

The refresh task exits automatically when the server shuts down (it holds a weak reference to the registry).

```toml
[profiles]
refresh_interval_secs = 1800   # refresh every 30 minutes instead of 1 hour
```

---

## Precedence when multiple providers list the same profile

If two providers both export a profile with the same ID, the first provider listed in `config.toml` wins. The second is silently ignored. This is determined by `HashMap` iteration order over `[profiles.providers]`, which is non-deterministic in TOML. To avoid ambiguity, give each profile a unique ID across providers, or use a single canonical provider.

---

## Requesting a profile from an ACME client

Include `"profile"` in the `newOrder` payload:

```json
{
  "identifiers": [{ "type": "dns", "value": "example.com" }],
  "profile": "tlsserver"
}
```

The server:
1. Records the profile name on the order.
2. Validates the profile name at finalize time (rejects with `invalidProfile` if no longer loaded).
3. Runs per-profile authorization checks (see below).
4. Issues the certificate using the profile's `CertificateParameters`.

The profile name is echoed back in every order response:

```json
{
  "status": "valid",
  "profile": "tlsserver",
  "certificate": "https://acme.example.com/acme/cert/…"
}
```

---

## CA restriction (`ca_ids`)

When `ca_ids` is set on a `builtin` profile, the profile is only offered via
the ACME endpoints of the listed CAs. Requests for this profile via any other
CA's endpoint receive `urn:ietf:params:acme:error:invalidProfile` at finalize
time.

```toml
[profiles.providers.local.profiles.rsa-only]
description = "Certificate restricted to the RSA CA"
ca_ids      = ["rsa"]
```

Config validation rejects `ca_ids` entries that do not match any configured
CA `id`. When `ca_ids` is empty (the default), the profile is available via
all configured CAs.

## Per-profile authorization

Three independent checks are applied at finalize time. All configured checks must pass (AND logic) for issuance to proceed. Checks that are not configured are skipped.

### 1. Identifier patterns

`allowed_identifiers` is a list of regular expressions. Each order identifier is formatted as `"type:value"` (e.g. `"dns:example.com"`, `"dns:*.example.com"`) before being tested against the patterns.

```toml
[profiles.providers.local.profiles.internal]
description         = "Internal services only"
allowed_identifiers = ['^dns:.*\.internal\.example\.com$', '^dns:internal\.example\.com$']
identifier_match    = "all"   # "all" (default) or "any"
```

`identifier_match` controls how the patterns are applied:

| Value | Behaviour |
|-------|-----------|
| `"all"` (default) | Every identifier in the order must match at least one pattern. |
| `"any"` | At least one identifier must match at least one pattern; the others are unrestricted. |

When `allowed_identifiers` is empty (the default), no identifier restriction is applied.

An invalid regular expression in `allowed_identifiers` causes the finalize request to fail with `invalidProfile`.

### 2. External authorization hook

`auth_hook` is a path to an executable. The server spawns it at finalize time and sends a JSON object on stdin:

```json
{
  "account_id": "abc123",
  "profile": "internal",
  "identifiers": [
    { "type": "dns", "value": "svc.internal.example.com" }
  ]
}
```

- Exit code 0: issuance proceeds.
- Non-zero exit code: issuance is denied. The hook's standard output (trimmed) is forwarded to the ACME client as the denial reason.
- Standard error is discarded.

`auth_hook_timeout_secs` (default: `30`) sets the maximum time the server waits for the hook to exit. If the hook times out, issuance is denied.

```toml
[profiles.providers.local.profiles.internal]
description            = "Internal services"
auth_hook              = "/etc/akamu/hooks/check-service.sh"
auth_hook_timeout_secs = 10
```

### 3. Account grants

`require_account_grant = true` means the account requesting the order must have this profile's name in its `profile_grants` attribute.

```toml
[profiles.providers.local.profiles.privileged]
description           = "Privileged cert profile"
require_account_grant = true
```

Grants are managed two ways:

- **Admin API**: `PUT /admin/account/{id}/profile-grants` with body `{"profile_grants":["privileged"]}`. See [Admin API](#admin-api) below.
- **EAB key inheritance**: when an EAB key is provisioned with `profile_grants`, those grants are automatically copied to any account created using that key.

An account whose `profile_grants` is NULL (the default) is considered to have no grants. When `require_account_grant` is `true`, such an account is denied.

---

## MTC certificate issuance (`issue_as = "mtc"`)

A `builtin` profile can issue a Merkle Tree Certificate (MTC) `StandaloneCertificate` instead of a standard X.509 PEM chain by setting `issue_as = "mtc"`:

```toml
[mtc]
log_path = "/var/lib/akamu/mtc.log"
enabled  = true

[mtc.signing_key]
key_file = "/var/lib/akamu/mtc-signing.key"

[profiles.providers.local]
type = "builtin"

[profiles.providers.local.profiles.mtc-tls]
description = "MTC TLS certificate"
validity_days = 90
key_usage   = ["digital_signature"]
eku         = ["server_auth"]
issue_as    = "mtc"
```

When `issue_as = "mtc"`:

1. The finalize handler issues the certificate as usual (X.509 `TBSCertificate`).
2. The certificate is appended to the MTC log synchronously during finalization; the resulting leaf index is stored in the database.
3. A `StandaloneCertificate` (per §6.1 of draft-ietf-plants-merkle-tree-certs) is built from the `TBSCertificate`, a Merkle inclusion proof, and a signature from the MTC signing key.
4. The raw DER-encoded `StandaloneCertificate` is stored in the database and served at the certificate download URL with `Content-Type: application/pkix-cert`.

Requirements:
- `[mtc]` must be configured and `enabled = true`.
- `[mtc.signing_key]` must be configured (the standalone certificate requires a signature).
- If either condition is not met, finalization returns `invalidProfile`.

The download endpoint auto-detects MTC certificates by their PEM marker and switches the response `Content-Type` accordingly:

| Certificate type | `Content-Type` |
|-----------------|---------------|
| Standard X.509 chain | `application/pem-certificate-chain` |
| MTC StandaloneCertificate | `application/pkix-cert` |

---

## Admin API

The admin API is enabled by adding an `[admin]` section to `config.toml` with a `listen_addr` and at least one of `ca_certs` (for mTLS client certificates) or `[admin.gssapi]` (for Kerberos). See [Configuration Reference — `[admin]`](configuration.md#admin) for all configuration keys.

Operators authenticate via mTLS client certificate or GSSAPI/Kerberos session token. A successful login returns a `session_token` that is passed as `Authorization: Bearer <token>` on subsequent requests. Each endpoint enforces a role-based access policy; see [Admin API — Endpoint reference](admin-api.md#endpoint-reference) for the full role matrix.

When `[admin]` is absent from the configuration, the admin listener is not started and all admin endpoints are unreachable.

### Account profile grants

**`GET /admin/account/{id}/profile-grants`**

Returns the current grants for the account:

```json
{ "profile_grants": ["p1", "p2"] }
```

Returns `{"profile_grants": null}` when the account has no grants. Returns 404 when the account is not found.

**`PUT /admin/account/{id}/profile-grants`**

Replace the account's grants entirely. Body:

```json
{ "profile_grants": ["p1", "p2"] }
```

Send `{"profile_grants": null}` or `{"profile_grants": []}` to clear all grants (equivalent to NULL — account may use any profile). Returns 204 on success, 404 when not found.

**`DELETE /admin/account/{id}/profile-grants`**

Clear all grants for the account (set to NULL). Returns 204 on success, 404 when not found.

### EAB key provisioning

**`POST /admin/eab`**

Provision a new EAB key with optional profile grants:

```json
{
  "kid": "key-id-1",
  "hmac_key_b64u": "<base64url-encoded-HMAC-key>",
  "profile_grants": ["p1", "p2"]
}
```

`profile_grants` is optional; omit it or pass `null` for no restriction. When present, any account created with this EAB key will automatically inherit these grants at account creation time.

Returns 201 with `{"kid": "key-id-1", "created": <unix-epoch>}` on success. Returns 409 when the `kid` already exists.

To generate a suitable HMAC key:

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
```

---

## Legacy `[server.profiles]`

Prior to the `[profiles]` subsystem, profile names were declared as a flat string map under `[server]`:

```toml
[server.profiles]
"tls-server-auth" = "https://acme.example.com/docs/profiles/tls-server-auth"
```

This still works for **advertising** profile names in the directory (the `meta.profiles` field). However, the map is a pure label registry — no actual certificate parameters are loaded from it, and any profile name is accepted at order time (no enforcement of key usage or EKU). Use the new `[profiles]` section for real per-profile issuance policy.

When `[profiles]` providers are configured, `meta.profiles` is populated from the registry; `[server.profiles]` is ignored.
