# Configuration Reference

`Akāmu` reads a single TOML configuration file whose path is passed as the first command-line argument:

```
akamu /etc/akamu/config.toml
```

If no argument is given, the server looks for `config.toml` in the current working directory.

The file is parsed once at startup. Changes require a restart. Unknown keys produce a parse error on startup (serde's strict TOML parser).

## Complete example

```toml
listen_addr = "0.0.0.0:8080"
base_url    = "https://acme.example.com"

[database]
url = "sqlite:///var/lib/akamu/akamu.db"

[ca]
key_file         = "/etc/akamu/ca.key.pem"
cert_file        = "/etc/akamu/ca.cert.pem"
key_type         = "ec:P-256"
hash_alg         = "sha256"
validity_days    = 90
ca_validity_years = 10
common_name      = "Example ACME CA"
organization     = "Example Org"
crl_url              = "http://acme.example.com/ca/crl"
crl_next_update_secs = 86400
ocsp_url             = "http://acme.example.com/ca/ocsp"

[mtc]
log_path = "/var/lib/akamu/mtc.log"
enabled  = false

[server]
terms_of_service_url        = "https://acme.example.com/tos.html"
website_url                 = "https://acme.example.com"
caa_identities              = ["acme.example.com"]
external_account_required   = false
order_expiry_secs           = 86400
authz_expiry_secs           = 86400
max_body_bytes              = 65536
ari_retry_after_secs        = 21600
ari_explanation_url         = "https://acme.example.com/docs/renewal-policy"
allow_subdomain_auth        = false
star_min_lifetime_secs      = 86400
star_max_duration_secs      = 31536000
star_allow_certificate_get  = true
tor_connectivity_enabled    = false
dns_persist01_resolver_addr = "127.0.0.1:5354"
trusted_proxies             = ["127.0.0.1/32"]
eab_master_secret           = "Zm9vYmFyYmF6cXV4cXV1eGZvb2JhcmJhenF1eHF1dXg"

[server.gssapi]
keytab_file  = "/etc/akamu/http.keytab"
service_name = "HTTP"

[admin]
bearer_token = "change-me"

[profiles]
refresh_interval_secs = 3600

[profiles.providers.local]
type = "builtin"

[profiles.providers.local.profiles.tlsserver]
description   = "Standard TLS server certificate"
validity_days = 90
key_usage     = ["digital_signature", "key_encipherment"]
eku           = ["server_auth"]
```

---

## Top-level keys

### `listen_addr`

**Required.** The TCP address and port the server binds to.

```toml
listen_addr = "0.0.0.0:8080"
```

Use `127.0.0.1:8080` if you only want to accept connections from a local reverse proxy. The server does not support TLS on this socket; TLS termination must be handled upstream.

### `base_url`

**Required.** The public HTTPS base URL of the ACME server. This value is embedded in every URL the server returns to clients — directory endpoint URLs, account URLs, order URLs, certificate download URLs, etc.

```toml
base_url = "https://acme.example.com"
```

It must match the URL that ACME clients use to reach the directory. It must not end with a slash.

---

## `[database]`

### `url`

**Required.** Database connection URL. The format depends on the compiled backend:

| Backend | URL format |
|---------|-----------|
| SQLite | `sqlite:///absolute/path/to/akamu.db` or `sqlite::memory:` |
| PostgreSQL | `postgres://user:pass@host/dbname` |
| MariaDB/MySQL | `mariadb://user:pass@host/dbname` or `mysql://user:pass@host/dbname` |

For SQLite, the database file and its WAL journal are created automatically if they do not exist.

```toml
[database]
url = "sqlite:///var/lib/akamu/akamu.db"
```

Use `sqlite::memory:` for an ephemeral in-memory database (useful for testing; all data is lost when the process exits).

### `max_connections`

**Optional. Default: `1` for SQLite, `10` for PostgreSQL/MariaDB.**

Maximum number of pooled database connections. For SQLite, this must remain `1` to avoid `SQLITE_BUSY_SNAPSHOT` errors under concurrent writes; the default is correct for production SQLite deployments.

```toml
[database]
url      = "postgres://akamu:secret@localhost/akamu"
max_connections = 20
```

---

## `[ca]`

### `key_file`

**Required.** Path to the CA private key PEM file.

- If both `key_file` and `cert_file` are absent on disk, a new key is generated and written to this path on first run.
- If both files are present, they are loaded without modification.
- If exactly one file is present, the server refuses to start.

```toml
key_file = "/etc/akamu/ca.key.pem"
```

### `cert_file`

**Required.** Path to the CA certificate PEM file. Same presence rules as `key_file`.

```toml
cert_file = "/etc/akamu/ca.cert.pem"
```

### `key_type`

**Optional. Default: `"ec:P-256"`.**

Algorithm used when auto-generating a new CA key. Ignored when loading an existing key from `key_file`.

| Value | Algorithm |
|---|---|
| `"ec:P-256"` | ECDSA with NIST P-256 curve |
| `"ec:P-384"` | ECDSA with NIST P-384 curve |
| `"ec:P-521"` | ECDSA with NIST P-521 curve |
| `"rsa:2048"` | RSA 2048-bit, exponent 65537 |
| `"rsa:3072"` | RSA 3072-bit, exponent 65537 |
| `"rsa:4096"` | RSA 4096-bit, exponent 65537 |
| `"ed25519"` | Ed25519 |

```toml
key_type = "ec:P-256"
```

### `hash_alg`

**Optional. Default: `"sha256"`.**

Hash algorithm used for signing certificates and CRLs.

| Value | Algorithm |
|---|---|
| `"sha256"` | SHA-256 |
| `"sha384"` | SHA-384 |
| `"sha512"` | SHA-512 |

```toml
hash_alg = "sha256"
```

### `validity_days`

**Optional. Default: `90`.**

Default validity period in days for issued end-entity certificates. The validity window starts at the moment the certificate is signed.

```toml
validity_days = 90
```

### `ca_validity_years`

**Optional. Default: `10`.**

Validity period in years for the auto-generated CA certificate. Ignored when loading an existing certificate.

```toml
ca_validity_years = 10
```

### `common_name`

**Optional. Default: `"Akāmu CA"`.**

Common Name (CN) used in the Subject and Issuer fields of the auto-generated CA certificate.

```toml
common_name = "Example ACME CA"
```

### `organization`

**Optional. Default: `"Akāmu"`.**

Organization (O) used in the Subject and Issuer fields of the auto-generated CA certificate.

```toml
organization = "Example Org"
```

### `crl_url`

**Optional. Default: absent (no CDP extension).**

If set, this URL is included as a CRL Distribution Point (CDP) URI in the `CRLDistributionPoints` extension of every issued end-entity certificate.

```toml
crl_url = "http://acme.example.com/ca/crl"
```

Set this to the URL of the built-in `/ca/crl` endpoint (i.e. `{base_url}/ca/crl`) to use the server's built-in CRL endpoint. The endpoint is served by Akāmu and requires no external CRL generation.

### `ocsp_url`

**Optional. Default: absent (no AIA OCSP extension).**

If set, this URL is included in the `AuthorityInfoAccess` (AIA) extension as an OCSP responder URI in every issued end-entity certificate.

```toml
ocsp_url = "http://acme.example.com/ca/ocsp"
```

Set this to the URL of the built-in `/ca/ocsp` endpoint (i.e. `{base_url}/ca/ocsp`) to use the server's built-in OCSP responder. Both GET and POST OCSP requests are handled at this base URL.

### `crl_next_update_secs`

**Optional. Default: `86400` (1 day).**

Controls the `nextUpdate` field in the CRL served at `/ca/crl`. The `nextUpdate` is set to the current time plus this many seconds. Adjust to match how frequently clients are expected to re-fetch the CRL.

```toml
crl_next_update_secs = 86400   # one day (default)
```

---

## `[mtc]`

### `log_path`

**Required.** Path to the disk-backed Merkle Tree Certificate transparency log file.

```toml
[mtc]
log_path = "/var/lib/akamu/mtc.log"
```

The file is created automatically on first run when `enabled = true`. It is never written when `enabled = false`, but the path must still be specified.

### `enabled`

**Optional. Default: `false`.**

When `true`, each issued certificate is appended as a leaf to the MTC transparency log. The leaf index is stored in the `certificates` database table (`mtc_log_index` column).

```toml
enabled = false
```

### `checkpoint_interval_secs`

**Optional. Default: `3600` (1 hour).**

How often the checkpoint background task fires, in seconds. A checkpoint is produced only when the log has grown since the last one; if the tree size has not changed the task is a no-op. Requires `[mtc.signing_key]` to be configured.

```toml
checkpoint_interval_secs = 3600
```

### `checkpoint_retention_count`

**Optional. Default: `1000`.**

Maximum number of checkpoint rows to retain in the `mtc_checkpoints` database table. After each new checkpoint is produced, rows beyond this limit are pruned (oldest first). Their associated cosignature rows in `mtc_cosignatures` are also deleted via the foreign-key `ON DELETE CASCADE` constraint.

```toml
checkpoint_retention_count = 1000
```

### `landmark_interval_secs`

**Optional. Default: `86400` (1 day).**

How often the landmark background task fires, in seconds. A new landmark is allocated only when the tree has grown since the last landmark; otherwise the task is a no-op. Requires `[mtc.signing_key]` to be configured.

```toml
landmark_interval_secs = 86400
```

### `max_active_landmarks`

**Optional. Default: `100`.**

Maximum number of landmark rows to retain in the `mtc_landmarks` table. After each new landmark is built, rows beyond this limit are pruned (oldest first by sequence number).

```toml
max_active_landmarks = 100
```

### `[mtc.signing_key]`

Optional subsection. When present, enables checkpoint production and standalone/landmark certificate construction. The signing key **must** be distinct from the X.509 CA key (§5.5 of draft-ietf-plants-merkle-tree-certs).

#### `key_file`

**Required within `[mtc.signing_key]`.** Path to the MTC signing key PEM file. If absent on disk, a new key of `key_type` is generated and written here on startup.

#### `key_type`

**Optional. Default: `"ec:P-256"`.**

Key algorithm for auto-generation. Accepts the same values as `[ca].key_type`. Per §5.4.2 of the draft, only ECDSA P-256/P-384, Ed25519, and ML-DSA are valid MTC signing algorithms; prefer EC or EdDSA.

#### `hash_alg`

**Optional. Default: `"sha256"`.**

Hash algorithm used for ECDSA/RSA signing: `"sha256"`, `"sha384"`, `"sha512"`. Ignored for EdDSA and ML-DSA.

```toml
[mtc.signing_key]
key_file = "/var/lib/akamu/mtc-signing.key"
key_type = "ec:P-256"
hash_alg = "sha256"
```

### `[[mtc.cosigners]]`

Optional array of external cosigner entries. After each checkpoint is produced, Akāmu POSTs the DER-encoded `Checkpoint` to each cosigner URL and stores the returned `SubtreeSignature`. Multiple entries are supported; all cosigners are contacted in parallel.

Each entry has the following fields:

#### `url`

**Required.** URL to POST the DER-encoded `Checkpoint` to (e.g. `https://cosigner.example.com/sign`).

#### `cosigner_id_cert_pem`

**Optional.** Path to the cosigner's X.509 identity certificate PEM file. When set, the file is loaded at startup and added to the TLS trust store for that cosigner's HTTPS connection, in addition to the system root CAs. This allows cosigners whose TLS certificate chains to an operator-provisioned CA to be used without installing that CA system-wide.

```toml
[[mtc.cosigners]]
url                  = "https://cosigner1.example.com/sign"
cosigner_id_cert_pem = "/etc/akamu/cosigner1-id.pem"

[[mtc.cosigners]]
url = "https://cosigner2.example.com/sign"
```

---

## `[server]`

The `[server]` section is optional. When omitted entirely, all fields take their default values.

### `terms_of_service_url`

**Optional. Default: absent.**

URL of the Terms of Service document. When set, it appears in the `meta.termsOfService` field of the ACME directory response.

```toml
terms_of_service_url = "https://acme.example.com/tos.html"
```

### `website_url`

**Optional. Default: absent.**

URL of the operator's website. When set, it appears in the `meta.website` field of the directory response.

```toml
website_url = "https://acme.example.com"
```

### `caa_identities`

**Optional. Default: empty list.**

List of CA domain names for CAA record verification (RFC 8659). When set, Akāmu queries CAA DNS records before issuing each certificate and verifies that at least one `issue` (or `issuewild` for wildcard) record authorises one of these CA domain names. The values also appear in `meta.caaIdentities` of the directory response.

When the list is empty (the default), CAA checking is skipped entirely — including RFC 8657 `accounturi` enforcement, because `accounturi` is evaluated as part of the CAA record check.

```toml
caa_identities = ["acme.example.com"]
```

### `external_account_required`

**Optional. Default: `false`.**

When `true`, new-account requests must include an `externalAccountBinding` field (RFC 8555 §7.3.4). Requests without it are rejected with `urn:ietf:params:acme:error:externalAccountRequired` (HTTP 403). The directory response also includes `meta.externalAccountRequired: true`.

When enabled, the server performs full HMAC verification: it resolves the `kid` in the `eab_keys` database table (populated either from `[server.eab_keys]` at startup or by HKDF derivation via `GET /acme/eab`), verifies the HS256/HS384/HS512 MAC, confirms the payload is the account key, and atomically consumes the key at account creation so each EAB key can only be used once.

```toml
external_account_required = true
```

### `eab_keys`

**Optional. Default: `{}`.**

Pre-shared External Account Binding keys, expressed as a TOML table under `[server.eab_keys]`. Each entry maps a key identifier (`kid`) to its base64url-encoded raw HMAC key bytes. The key material must be at least 16 bytes; 32 bytes (256 bits) is recommended for HS256.

Keys are loaded at startup and persisted in the database. A key that has been consumed (used to create an account) is never overwritten on a subsequent restart, so spent keys remain invalidated across restarts.

```toml
[server.eab_keys]
"kid-1" = "c2VjcmV0LWhtYWMta2V5LWJ1ZmZlcg"   # base64url, no padding
"kid-2" = "YW5vdGhlci1rZXktaGVyZQ"
```

To generate a key:
```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
```

### `eab_master_secret`

**Optional. Default: absent.**

Base64url-encoded master secret (must decode to at least 32 bytes) used to derive deterministic EAB credentials via HKDF-SHA-256 (RFC 5869). When set, the `GET /acme/eab` endpoint derives a unique `(kid, hmac_key)` pair for each authenticated principal using the following construction:

```
kid      = base64url( HKDF-SHA256(IKM=master_secret, info="akamu-eab-v1-kid:<principal>", L=16) )
hmac_key = base64url( HKDF-SHA256(IKM=master_secret, info="akamu-eab-v1-key:<principal>", L=32) )
```

The same `(master_secret, principal)` pair always produces the same `(kid, hmac_key)`. Credentials are stored in the `eab_keys` table on first request and returned on subsequent requests. Once the `kid` has been consumed by an account registration, re-fetching `GET /acme/eab` for that principal returns HTTP 409 Conflict.

When `eab_master_secret` is absent, `GET /acme/eab` returns only `{"principal":"…"}` (backward-compatible stub behaviour, no EAB credentials).

Authentication for `GET /acme/eab` requires either `[server.gssapi]` (standalone GSSAPI/SPNEGO) or `trusted_proxies` (reverse-proxy mode supplying `X-Remote-User`).

Generate a suitable secret:

```bash
openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
```

```toml
[server]
external_account_required = true
eab_master_secret = "Zm9vYmFyYmF6cXV4cXV1eGZvb2JhcmJhenF1eHF1dXg"
```

### `order_expiry_secs`

**Optional. Default: `86400` (24 hours).**

Number of seconds after creation before an order expires. Expired orders cannot be finalized.

```toml
order_expiry_secs = 86400
```

### `authz_expiry_secs`

**Optional. Default: `86400` (24 hours).**

Number of seconds after creation before an authorization expires. Expired authorizations must be re-created via a new order.

```toml
authz_expiry_secs = 86400
```

### `max_body_bytes`

**Optional. Default: `65536` (64 KiB).**

Maximum size in bytes of JOSE+JSON request bodies. Requests larger than this limit are rejected with HTTP 413. This applies to all POST endpoints that carry ACME payloads.

```toml
max_body_bytes = 65536
```

### `http_validation_port`

**Optional. Default: `80`.**

TCP port used when the server fetches http-01 challenge responses. RFC 8555 §8.3 requires port 80 in production deployments. Override this to a high port for local testing or non-standard network environments.

```toml
http_validation_port = 80
```

### `dns_persist_issuer_domains`

**Optional. Default: absent (dns-persist-01 disabled).**

The issuer domain(s) placed in the `issuer-domain-names` field of `dns-persist-01` challenge objects and matched against the first token of TXT records during validation. When this field is set, the server offers `dns-persist-01` as an additional challenge type for all `dns` identifiers. When absent, `dns-persist-01` is not offered and existing clients are unaffected.

Accepts either a single string or an array of strings. Multi-tenant or multi-identity deployments can list all accepted issuer domains; validation succeeds when the TXT record's issuer domain matches any of the configured values.

See [dns-persist-01 Challenge](challenges.md#dns-persist-01) for the full description of the challenge type and TXT record format.

```toml
# Single domain
dns_persist_issuer_domains = "acme.example.com"

# Multiple domains (multi-tenant or multi-identity deployments)
dns_persist_issuer_domains = ["acme.example.com", "acme.example.org"]
```

### `dns_resolver_addr`

**Optional. Default: absent (system resolver).**

Override the DNS resolver used for `dns-01` and `dns-persist-01` challenge validation. Format: `"<ip>:<port>"`. When absent, the system default resolver is used. Useful for split-horizon DNS deployments where the ACME server cannot reach the public resolver, and for integration testing against a local stub server.

```toml
dns_resolver_addr = "127.0.0.1:5353"
```

### `dns_persist01_resolver_addr`

**Optional. Default: absent (falls back to `dns_resolver_addr`).**

Resolver override used exclusively for `dns-persist-01` TXT lookups at `_validation-persist.*`. When set, this address is used instead of `dns_resolver_addr` for dns-persist-01 validation only. Useful when persistent TXT records are served by a different DNS infrastructure than the one used for dns-01 and CAA lookups.

```toml
dns_resolver_addr           = "127.0.0.1:5353"   # used for dns-01 and CAA
dns_persist01_resolver_addr = "127.0.0.1:5354"   # used only for dns-persist-01
```

### `ari_retry_after_secs`

**Optional. Default: `21600` (6 hours).**

The value of the `Retry-After` header returned on `GET /acme/renewal-info/{cert-id}` responses (RFC 9773 §4.3). Controls how frequently ACME clients poll for renewal information.

```toml
ari_retry_after_secs = 21600
```

### `ari_explanation_url`

**Optional. Default: absent.**

URL included in `GET /acme/renewal-info/{cert-id}` responses as the `explanationURL` field (RFC 9773 §4.1). When set, it points clients to a human-readable page explaining why early renewal is being suggested (for example, an incident notice or CA policy update). When absent, the field is omitted from the response entirely.

```toml
ari_explanation_url = "https://acme.example.com/docs/renewal-policy"
```

### `allow_subdomain_auth`

**Optional. Default: `false`.**

When `true`, the directory `meta` includes `"subdomainAuthAllowed": true`, advertising that the server supports RFC 9444 subdomain authorization. Clients may then:
- Include `"subdomainAuthAllowed": true` in `POST /acme/new-authz` requests.
- Reference an ancestor domain in `newOrder` via the `ancestorDomain` identifier field.

```toml
allow_subdomain_auth = true
```

### `star_min_lifetime_secs`

**Optional. Default: absent (STAR not advertised).**

Minimum certificate lifetime in seconds for ACME STAR orders (RFC 8739). When set, the directory `meta` includes an `auto-renewal` object advertising STAR capability. Clients that place STAR orders must request a `lifetime` value greater than or equal to this minimum.

Setting this field enables the STAR background reissuance task.

```toml
star_min_lifetime_secs = 86400   # 1 day minimum
```

### `star_max_duration_secs`

**Optional. Default: absent.**

Maximum total renewal duration in seconds for ACME STAR orders. When set, it is included in the directory `meta.auto-renewal` object as `max-duration`. Clients must supply an `end-date` that does not exceed this value beyond the order creation time.

```toml
star_max_duration_secs = 31536000   # 1 year maximum
```

### `star_allow_certificate_get`

**Optional. Default: `true`.**

Controls whether the rolling STAR certificate URL (`/acme/cert/star/<order-id>`) can be fetched with an unauthenticated `GET` request. When `true`, the directory `meta.auto-renewal` object includes `"allow-certificate-get": true` and clients may request this capability per order by including `"allow-certificate-get": true` in the `auto-renewal` object of `newOrder`. When `false`, the capability is not advertised and unauthenticated GET requests are rejected.

```toml
star_allow_certificate_get = true
```

### `tor_connectivity_enabled`

**Optional. Default: `false`.**

Controls whether the server offers `http-01` and `tls-alpn-01` challenge types for `.onion` identifiers. RFC 9799 §4 prohibits offering those challenge types unless the CA can actually reach the Tor network. When `false` (the default), only `onion-csr-01` is offered for `.onion` identifiers. Set to `true` only when the Akāmu server process can make outbound Tor connections to hidden services (for example, via `torsocks` or a SOCKS5 proxy configured at the OS level).

```toml
tor_connectivity_enabled = true
```

### `validate_dnssec`

**Optional. Default: `true`.**

Controls whether DNSSEC validation is enforced during DNS-based challenge verification (dns-01, dns-persist-01) and CAA record lookups. CA/B Forum BR §3.2.2.4 and §3.2.2.8.1 require DNSSEC validation for publicly trusted CAs as of 2026-03-15. Set to `false` only for testing environments or deployments where the DNS infrastructure is not yet DNSSEC-signed; doing so makes the CA non-compliant.

```toml
validate_dnssec = true
```

### `trusted_proxies`

**Optional. Default: empty (proxy header mode disabled).**

List of CIDR blocks (IPv4 or IPv6) whose connecting IP address is trusted to
supply an `X-Remote-User` header. When a request arrives from one of these
addresses, akamu reads the header value as the already-authenticated principal
name — the reverse proxy is expected to have completed SPNEGO or another
authentication step before forwarding the request.

Requests from addresses not in this list never have `X-Remote-User` honoured,
regardless of what the header contains.

**Mutually exclusive with `[server.gssapi]`.** Setting both `trusted_proxies`
and `[server.gssapi]` at the same time is a configuration error; the server
exits at startup with an error message.

```toml
[server]
trusted_proxies = ["127.0.0.1/32", "::1/128", "10.0.0.0/8"]
```

Security note: keep this list tightly scoped to the IP addresses of your
reverse proxy or load balancer. Adding broad ranges (e.g. `0.0.0.0/0`) allows
any client to impersonate any principal.

### `[server.gssapi]`

**Optional. When absent, standalone GSSAPI mode is disabled.**

**Mutually exclusive with `trusted_proxies`.** Setting both at the same time is
a configuration error; the server exits at startup with an error message.

Configures akamu to accept `Authorization: Negotiate` tokens directly, without
a reverse proxy. At startup the server acquires an acceptor credential from
`keytab_file` and uses `gss_accept_sec_context` to validate each SPNEGO token.

Use this mode when you want akamu to handle Kerberos authentication itself
rather than delegating to a front-end proxy such as Apache or Nginx.

**Security behaviors in standalone GSSAPI mode:**

- **Token size limit.** `Authorization: Negotiate` tokens larger than 128 KiB
  are rejected with `400 Bad Request`. Legitimate Kerberos tickets are always
  smaller than this limit.
- **Case-insensitive scheme matching.** The `"Negotiate "` prefix is matched
  case-insensitively per RFC 7235 §2.1.
- **TLS channel bindings (RFC 5929).** When akamu terminates TLS itself, the
  `tls-server-end-point` binding is computed from the leaf certificate and
  passed to `gss_accept_sec_context`, binding the Kerberos exchange to the TLS
  channel. Channel bindings are disabled automatically when the server
  certificate uses ML-DSA (pure or composite) or Ed448, because RFC 5929
  defines no canonical hash for those algorithms.
- **Replay detection.** After a successful context acceptance, akamu verifies
  that `GSS_C_REPLAY_FLAG` is set. Contexts without replay detection are
  rejected with `403 Forbidden`.
- **GSSAPI without TLS.** Running standalone GSSAPI without TLS is permitted
  but emits a `warn`-level log at startup: SPNEGO tokens are vulnerable to
  interception and relay attacks without TLS.
- **No mechanism configured.** When neither `trusted_proxies` nor
  `[server.gssapi]` is set, authenticated endpoints return `404 Not Found`.

#### `keytab_file`

**Required within `[server.gssapi]`.** Path to the HTTP service keytab file.
The akamu process must be able to read this file; no other user should have
read access to it. The path is logged at `debug` level only.

```toml
keytab_file = "/etc/akamu/http.keytab"
```

Generate the keytab for an IPA-managed host:

```bash
ipa-getkeytab -s ipa.example.com -p HTTP/akamu.example.com@EXAMPLE.COM \
    -k /etc/akamu/http.keytab
chmod 600 /etc/akamu/http.keytab
chown akamu: /etc/akamu/http.keytab
```

#### `service_name`

**Optional. Default: `"HTTP"`.**

Host-based service name to acquire credentials for. MIT Kerberos appends
`@<local-hostname>` when no realm is specified, so `"HTTP"` is correct for a
single-homed host. Use `"HTTP@akamu.example.com"` to be explicit.

```toml
service_name = "HTTP"
```

#### Proxy mode example

```toml
[server]
trusted_proxies = ["192.168.1.10/32"]
```

In this configuration, only connections from `192.168.1.10` (the reverse proxy)
are allowed to supply `X-Remote-User`. Requests from any other source that reach
an authenticated endpoint return `404 Not Found` (no authentication mechanism
is configured for those connections).

#### Standalone GSSAPI example

```toml
[server.gssapi]
keytab_file  = "/etc/akamu/http.keytab"
service_name = "HTTP"
```

In this configuration, akamu handles `Authorization: Negotiate` directly. Clients
must obtain a Kerberos service ticket for `HTTP/<hostname>` before calling
authenticated endpoints.

---

## `[profiles]`

The `[profiles]` section configures the certificate profile subsystem. Profiles are loaded from one or more *providers* at startup, cached in memory, and refreshed periodically by a background task. `Akāmu`'s own CA always signs; profiles only control which extensions are included and with what values. When no providers are configured, every order falls back to CA defaults (`digitalSignature` KeyUsage, `serverAuth` EKU, and the `[ca]` validity/URL settings).

See [Certificate Profiles](profiles.md) for the complete reference including all provider types, key usage names, EKU OIDs, and three-state URL semantics.

### `refresh_interval_secs`

**Optional. Default: `3600` (1 hour).**

How often the background task re-reads profiles from all providers. Set to `0` to disable automatic refresh (profiles are loaded once at startup and never refreshed).

```toml
[profiles]
refresh_interval_secs = 1800   # refresh every 30 minutes
```

### `[profiles.providers.<name>]`

Each key under `[profiles.providers]` names a provider. The required `type` field selects the backend:

| `type` | Source |
|--------|--------|
| `"builtin"` | Inline TOML profile declarations in `config.toml` |
| `"dogtag"` | Dogtag PKI `.cfg` files — filesystem or LDAP (simple bind or GSSAPI/Kerberos) |
| `"ipa"` | FreeIPA/IPAThinCA — filesystem or LDAP (simple bind or GSSAPI/Kerberos) |

```toml
# Builtin provider: inline declarations
[profiles.providers.local]
type = "builtin"

[profiles.providers.local.profiles.tlsserver]
description   = "Standard TLS server certificate"
validity_days = 90
key_usage     = ["digital_signature", "key_encipherment"]
eku           = ["server_auth"]

# Dogtag provider: load .cfg files from a directory
[profiles.providers.dogtag_prod]
type        = "dogtag"
profile_dir = "/etc/pki/pki-tomcat/ca/profiles/ca"
profiles    = ["caServerCert"]   # empty = all .cfg files

# Dogtag provider: load profiles from LDAP (simple bind, single server)
# Setting tls_ca_cert_file triggers STARTTLS automatically on ldap:// URIs.
[profiles.providers.dogtag_ldap]
type     = "dogtag"
profiles = ["caServerCert"]

[profiles.providers.dogtag_ldap.ldap]
uri                = "ldap://dogtag.example.com:389"
base_dn            = "dc=example,dc=com"
bind_dn            = "uid=admin,ou=people,dc=example,dc=com"
bind_password_file = "/etc/akamu/ldap-password"
tls_ca_cert_file   = "/etc/ssl/certs/dogtag-ldap-ca.pem"   # triggers STARTTLS

# Dogtag provider: multiple servers for failover (GSSAPI)
[profiles.providers.dogtag_ha]
type     = "dogtag"
profiles = ["caServerCert"]

[profiles.providers.dogtag_ha.ldap]
uris    = ["ldap://dogtag1.example.com:389", "ldap://dogtag2.example.com:389"]
base_dn = "dc=example,dc=com"
gssapi  = true

# IPA provider: filesystem fallback
[profiles.providers.ipa_prod]
type        = "ipa"
profile_dir = "/etc/pki/pki-tomcat/ca/profiles/ca"
profiles    = ["caIPAserviceCert"]

# IPA provider: SRV-based discovery with GSSAPI
[profiles.providers.ipa_ldap]
type     = "ipa"
profiles = ["caIPAserviceCert"]

[profiles.providers.ipa_ldap.ldap]
srv_domain = "example.com"   # resolves _ldap._tcp.example.com SRV records
base_dn    = "o=ipaca"
gssapi     = true
```

**`[ldap]` sub-table fields** (applies to both `dogtag` and `ipa` providers)

*Server selection — at least one of the following is required*

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `uri` | string | absent | Single LDAP URI (`ldap://host:port` or `ldaps://host:636`). Kept for backward compatibility; use `uris` when listing multiple servers explicitly. |
| `uris` | array of strings | `[]` | Ordered list of LDAP URIs tried in turn for failover. All URIs are passed to `ldap_initialize` as a space-separated string. |
| `srv_domain` | string | absent | DNS domain for SRV discovery. Resolves `_ldap._tcp.{srv_domain}` SRV records; discovered servers are sorted by RFC 2782 priority/weight and appended after any explicit `uris`. |

Explicit servers (`uri` / `uris`) are always tried before SRV-discovered servers. An error is returned at startup if none of the three keys is set.

*Search parameters — required*

| Key | Type | Description |
|-----|------|-------------|
| `base_dn` | string | Base DN for the profile search. Dogtag: directory root suffix (e.g. `dc=example,dc=com`). IPA: `o=ipaca`. |

*Authentication — choose one method*

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `bind_dn` | string | absent | Bind DN for LDAP simple bind. Required when using simple authentication. |
| `bind_password_file` | string | absent | Path to a file containing the simple bind password (trailing newline is stripped). Required when `bind_dn` is set. |
| `gssapi` | boolean | `false` | Use SASL GSSAPI (Kerberos) authentication. Pre-condition: the process must hold a valid Kerberos TGT in its credential cache. Mutually exclusive with `bind_dn` / `bind_password_file`. |

*TLS*

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `tls_ca_cert_file` | string | absent | Path to a PEM CA certificate used to verify the LDAP server's TLS certificate. When this is set on an `ldap://` URI, STARTTLS is negotiated automatically before any credentials are sent. When set on an `ldaps://` URI, the CA is used for the immediate TLS handshake. When absent, the system trust store is used. |

**Additional `builtin` profile fields**

Beyond the core extension fields, each `builtin` profile supports three groups of optional settings:

*Certificate format*

| Key | Default | Description |
|-----|---------|-------------|
| `issue_as` | absent / `"x509"` | Set to `"mtc"` to issue a Merkle Tree Certificate `StandaloneCertificate` instead of a PEM chain. Requires `[mtc]` to be enabled. |

*Per-profile authorization*

| Key | Default | Description |
|-----|---------|-------------|
| `allowed_identifiers` | `[]` | List of regex patterns. Each order identifier is matched as `"type:value"` (e.g. `"dns:example.com"`). Empty = no restriction. |
| `identifier_match` | `"all"` | `"all"`: every identifier must match a pattern. `"any"`: at least one identifier must match. Ignored when `allowed_identifiers` is empty. |
| `auth_hook` | absent | Path to an external executable. Receives JSON on stdin; exit 0 = permit, non-zero = deny. |
| `auth_hook_timeout_secs` | `30` | Seconds to wait for the hook before denying. |
| `require_account_grant` | `false` | When `true`, the account must have this profile's name in its `profile_grants` attribute (set via the Admin API or inherited from its EAB key). |

See [Certificate Profiles](profiles.md) for detailed descriptions with examples.

---

## `[admin]`

The `[admin]` section enables the server-side Admin API. When this section is absent, all admin endpoints return 404 and are effectively invisible. This is the default; no admin access is possible without explicit configuration.

```toml
[admin]
bearer_token = "change-me-to-a-strong-random-value"
```

### `bearer_token`

**Required within `[admin]`.** The secret token that all admin API callers must supply in the `Authorization: Bearer <token>` HTTP header.

Generate a strong random value before deploying:

```bash
openssl rand -hex 32
```

When the header is absent, the endpoint returns 401. When the header is present but the token does not match, the endpoint returns 403.

**Admin endpoints exposed when this section is configured:**

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/admin/account/{id}/profile-grants` | Read current grants for an account |
| `PUT` | `/admin/account/{id}/profile-grants` | Replace grants for an account |
| `DELETE` | `/admin/account/{id}/profile-grants` | Revoke all grants from an account |
| `POST` | `/admin/eab` | Provision a new EAB key with optional grants |

See [Certificate Profiles — Admin API](profiles.md#admin-api) for the full request/response format of each endpoint.

