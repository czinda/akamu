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

[[ca]]
id               = "default"
is_default       = true
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
account_scope               = "server"
star_min_lifetime_secs      = 86400
star_max_duration_secs      = 31536000
star_allow_certificate_get  = true
tor_connectivity_enabled    = false
dns_resolver_addr           = "1.1.1.1:853"
dns_dot_server_name         = "cloudflare-dns.com"
dns_persist01_resolver_addr = "127.0.0.1:5354"
validate_dnssec             = true
trusted_proxies             = ["127.0.0.1/32"]
eab_master_secret           = "Zm9vYmFyYmF6cXV4cXV1eGZvb2JhcmJhenF1eHF1dXg"
delegation_enabled          = false
allow_certificate_get       = false

[server.gssapi]
keytab_file  = "/etc/akamu/http.keytab"
service_name = "HTTP"

[admin]
listen_addr = "127.0.0.1:9443"
cert_file   = "/etc/akamu/admin-tls.pem"
key_file    = "/etc/akamu/admin-tls-key.pem"
ca_certs    = ["/etc/akamu/operator-ca.pem"]

[email_challenge]
enabled             = true
from_address        = "acme-validation@example.com"
send_script         = "/etc/akamu/send-email.sh"
webhook_hmac_secret = "replace-with-output-of--openssl-rand-hex-32"

# [delegation_upstream]
# directory_url            = "https://upstream-ca.example.com/acme/directory"
# account_key_file         = "/etc/akamu/upstream-acme.key.pem"
# contacts                 = ["mailto:admin@example.com"]
# challenge_solver         = "dns-01"
# challenge_deploy_script  = "/etc/akamu/upstream-dns-deploy.sh"
# challenge_cleanup_script = "/etc/akamu/upstream-dns-cleanup.sh"
# poll_interval_secs       = 10

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

Use `127.0.0.1:8080` if you only want to accept connections from a local reverse proxy. To enable native TLS on this socket, configure the `[tls]` section; otherwise TLS termination must be handled upstream.

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

### `require_tls`

**Optional. Default: `false`.**

When `true`, the server refuses to start unless the database URL explicitly
enables SSL/TLS encryption:

| Backend | Required URL parameter |
|---------|------------------------|
| PostgreSQL | `sslmode=require`, `sslmode=verify-ca`, or `sslmode=verify-full` |
| MariaDB/MySQL | `ssl-mode=REQUIRED`, `ssl-mode=VERIFY_CA`, or `ssl-mode=VERIFY_IDENTITY` |
| SQLite | Ignored (local file, no network transport) |

Set `true` in production deployments where the database is not co-located
with the server process (FPT_ITT.1).

```toml
[database]
url         = "postgres://akamu:secret@db.example.com/akamu?sslmode=verify-full"
require_tls = true
```

---

## `[[ca]]` / `[ca]`

Akāmu supports one or more CA instances.  Use the TOML array-of-tables
syntax `[[ca]]` to configure multiple CAs; the legacy single `[ca]` table
continues to work and is treated as a single CA with `id = "default"` and
`is_default = true`.

```toml
# Single CA (backward-compatible)
[ca]
key_file  = "/etc/akamu/ca.key.pem"
cert_file = "/etc/akamu/ca.cert.pem"

# Multiple CAs
[[ca]]
id         = "rsa"
is_default = true
key_file   = "/etc/akamu/rsa-ca.key.pem"
cert_file  = "/etc/akamu/rsa-ca.cert.pem"

[[ca]]
id        = "ec"
key_file  = "/etc/akamu/ec-ca.key.pem"
cert_file = "/etc/akamu/ec-ca.cert.pem"
```

### `id`

**Required when multiple `[[ca]]` entries are present. Optional for a
single `[ca]` table (defaults to `"default"`).**

Unique identifier for this CA. Must be lowercase alphanumeric with `_`
or `-` allowed, at most 64 characters. Reserved ACME path segments
(`directory`, `new-nonce`, `new-account`, `new-order`, `new-authz`,
`revoke-cert`, `key-change`) are rejected at startup.

```toml
[[ca]]
id = "rsa"
```

### `is_default`

**Required (as `true`) for exactly one CA when multiple `[[ca]]` entries
are configured. Implicit `true` for the legacy single `[ca]` table.**

The default CA is also served at the backward-compatible `/acme/directory`
alias (without a CA ID prefix).

```toml
[[ca]]
id         = "rsa"
is_default = true
```

### `caa_identities` (per-CA)

**Optional. Default: `[]` (inherit from `[server].caa_identities`).**

Per-CA list of CA domain names for CAA record verification (RFC 8659).
When non-empty, this list overrides `[server].caa_identities` for orders
processed through this CA's ACME endpoint. When empty (the default), the
server-level list applies.

```toml
[[ca]]
id             = "rsa"
caa_identities = ["rsa.acme.example.com", "acme.example.com"]
```

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
| `"ed448"` | Ed448 |

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

**Optional. Default: `"ACME Server CA"`.**

Common Name (CN) used in the Subject and Issuer fields of the auto-generated CA certificate.

```toml
common_name = "Example ACME CA"
```

### `organization`

**Optional. Default: `"ACME Server"`.**

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

### `enforce_validity_cap`

**Optional. Default: `false`.**

When `true`, certificate issuance is rejected at the time of signing if the computed validity period exceeds 200 days (the current CA/B Forum BR §6.3.2 hard limit since 2026-03-15). When `false` (the default), the server only emits a startup warning for validity periods exceeding the limit, allowing private or enterprise PKI deployments to use longer validity periods without chaining to a public root.

Public WebPKI CAs should set this to `true` to enforce the limit at issuance time rather than relying solely on the startup warning.

```toml
[ca]
enforce_validity_cap = true
```

### `require_encrypted_key`

**Optional. Default: `false`.**

When `true`, the server refuses to load a plaintext (unencrypted) PEM private key
from a file (FCS_STG_EXT.1). Only PKCS#8 encrypted PEM (`ENCRYPTED PRIVATE KEY`)
or PKCS#11 URIs are accepted. Use `key_password_file` to supply the decryption
passphrase when using an encrypted PEM file.

```toml
[ca]
require_encrypted_key = true
key_password_file     = "/etc/akamu/ca-key-passphrase"
```

### `key_password_file`

**Optional. Default: absent.**

Path to a file containing the passphrase used to decrypt an encrypted PEM CA
private key. The file is read once at startup; trailing newlines are stripped.
Required when `require_encrypted_key = true` and `key_file` points to a
filesystem path (not a PKCS#11 URI).

```toml
[ca]
key_password_file = "/etc/akamu/ca-key-passphrase"
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

### `account_scope`

**Optional. Default: `"server"`.**

Controls whether ACME accounts are shared across all CAs or isolated per
CA.

| Value | Behaviour |
|-------|-----------|
| `"server"` | One account works with all CAs. This is the default and matches the behavior of single-CA deployments. |
| `"ca"` | Accounts are isolated per CA. An account registered via one CA's `new-account` endpoint cannot create orders via a different CA. |

```toml
[server]
account_scope = "server"
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

Maximum size in bytes of JOSE+JSON request bodies. Requests larger than this limit are rejected with HTTP 413. This applies to all POST endpoints that carry ACME payloads, and also to the admin API listener.


```toml
max_body_bytes = 65536   # 64 KiB
```

### `http_validation_port`

**Optional. Default: `80`.**

TCP port used when the server fetches http-01 challenge responses. RFC 8555 §8.3 requires port 80 in production deployments. Override this to a high port for local testing or non-standard network environments.

```toml
http_validation_port = 80
```

### `http_validation_allow_private_ips`

**Optional. Default: `false`.**

When `false` (the default), the **initial connection target** and any **redirect targets** that resolve to private, link-local, or loopback IP addresses (RFC 1918, 169.254.0.0/16, 127.0.0.0/8, fc00::/7, fe80::/10, etc.) are blocked to prevent SSRF attacks against cloud metadata endpoints such as `169.254.169.254`. Both IP literals and hostnames are checked: for hostnames, every resolved address must be globally routable.

Set to `true` only in isolated test environments where the http-01 challenge responder intentionally runs on a private address.

```toml
http_validation_allow_private_ips = false   # default — recommended for all production deployments
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

Override the DNS resolver used for `dns-01`, `dns-persist-01`, and CAA record lookups. Format: `"<ip>:<port>"`. When absent, the system default resolver is used. Useful for split-horizon DNS deployments where the ACME server cannot reach the public resolver, and for integration testing against a local stub server.

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

### `dns_dot_server_name`

**Optional. Default: absent (plain UDP).**

TLS server name (SNI hostname) for DNS-over-TLS (DoT, RFC 7858). When set, all DNS challenge validation queries — `dns-01`, `dns-persist-01`, and CAA record lookups — are sent over TLS to the resolver specified by `dns_resolver_addr` instead of plain UDP.

Use DoT when the network path between the Akāmu server and its resolver is untrusted: for example, when the resolver is a public DNS provider reached over the Internet, when the operator wants to prevent on-path DNS hijacking by an ISP, or to satisfy privacy requirements that prohibit cleartext DNS queries.

`dns_resolver_addr` must be set to the DoT server's IP address and port 853 when this field is present. The TLS certificate presented by the resolver is verified against the system root CA store (system OpenSSL). LDAP SRV lookups for certificate profile providers are unaffected — they always use plain UDP.

DoT and DNSSEC validation (`validate_dnssec = true`) are independent and can be enabled at the same time. DoT protects the query transport channel; DNSSEC authenticates the DNS response data itself.

```toml
# DoT only — encrypt queries to Cloudflare's resolver
dns_resolver_addr    = "1.1.1.1:853"
dns_dot_server_name  = "cloudflare-dns.com"
```

```toml
# DoT + DNSSEC — encrypted transport and cryptographic response validation
dns_resolver_addr    = "1.1.1.1:853"
dns_dot_server_name  = "cloudflare-dns.com"
validate_dnssec      = true
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

### `delegation_enabled`

**Optional. Default: `false`.**

When `true`, Akāmu activates the RFC 9115 delegation API surface:

- The directory `meta` object includes `"delegation-enabled": true`.
- Every account response includes a `"delegations"` URL.
- The delegation listing and fetch endpoints become active:
  - `POST /acme/delegations/{account_id}` — list delegations for an account (POST-as-GET).
  - `POST /acme/delegation/{id}` — fetch a single delegation object (POST-as-GET).
- `POST /acme/new-order` accepts the `"delegation"` field to link an order to a delegation.
- Delegation orders start in `ready` status and return `"authorizations": []`.

Delegations themselves are managed via the Admin API (`/admin/delegations`). The `[admin]` section must be configured before delegations can be created.

```toml
[server]
delegation_enabled = true
```

### `allow_certificate_get`

**Optional. Default: `false`.**

When `true`, the directory `meta` object includes `"allow-certificate-get": true` for RFC 9115 delegation orders (distinct from the `star_allow_certificate_get` flag, which covers RFC 8739 STAR certificates). When an order is placed with `"allow-certificate-get": true` in the `new-order` payload, the certificate endpoint for that order can be fetched with an unauthenticated `GET` rather than a POST-as-GET. The capability is advertised in the directory only when this flag is `true`.

```toml
[server]
allow_certificate_get = true
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

## `[tls]`

The `[tls]` section enables Akāmu to terminate TLS directly on the main `listen_addr` socket, without a reverse proxy. When this section is absent or `enabled = false`, the server operates over plain HTTP.

```toml
[tls]
enabled    = true
cert_file  = "/etc/akamu/server.pem"
key_file   = "/etc/akamu/server-key.pem"
protocols  = ["TLSv1.2", "TLSv1.3"]

[tls.client_auth]
required          = false
ca_files          = ["/etc/akamu/client-ca.pem"]
profile           = "webpki"
allow_post_quantum = false
max_chain_depth   = 8
minimum_rsa_modulus = 2048
```

### `enabled`

**Optional. Default: `false`.**

When `true`, the server listens with TLS on `listen_addr`. When `false`, the socket accepts plain HTTP connections.

```toml
[tls]
enabled = true
```

### `cert_file`

**Optional.** Path to the PEM file containing the server TLS certificate chain (leaf certificate first). When this file is absent on disk and `key_file` is also absent, Akāmu generates a self-signed certificate on first run using `bootstrap_key_type` and `server_name`.

```toml
cert_file = "/etc/akamu/server.pem"
```

### `key_file`

**Optional.** Path to the PEM file containing the server TLS private key (PKCS#8 or SEC1, unencrypted). Same auto-generation rules as `cert_file`.

```toml
key_file = "/etc/akamu/server-key.pem"
```

### `protocols`

**Optional. Default: `["TLSv1.2", "TLSv1.3"]`.**

List of TLS protocol versions the server accepts. Both TLS 1.2 and TLS 1.3 are enabled by default.

```toml
protocols = ["TLSv1.2", "TLSv1.3"]
```

### `server_name`

**Optional. Default: `"localhost"`.**

Hostname placed in the CN and SAN of the auto-generated server certificate. Only used when `cert_file` and `key_file` are absent on disk.

```toml
server_name = "acme.example.com"
```

### `bootstrap_key_type`

**Optional. Default: `"ec:P-256"`.**

Key algorithm for the auto-generated server certificate. Only used when `cert_file` and `key_file` are absent on disk. Accepts the same values as `[ca].key_type`.

```toml
bootstrap_key_type = "ec:P-256"
```

### `[tls.client_auth]`

**Optional. When absent, client certificate authentication is disabled.**

Configures mutual TLS (mTLS) client certificate authentication. When present, the server requests a client certificate during the TLS handshake.

#### `required`

**Optional. Default: `false`.**

When `true`, connections that present no client certificate are rejected. When `false`, client certificates are optional — presented certificates are still verified if provided.

```toml
required = true
```

#### `ca_files`

**Required within `[tls.client_auth]`.** List of PEM files containing the trusted CA certificates used to verify client certificates.

```toml
ca_files = ["/etc/akamu/client-ca.pem"]
```

#### `profile`

**Optional. Default: `"webpki"`.**

Certificate validation profile. Accepted values:

| Value | Behaviour |
|-------|-----------|
| `"webpki"` | CA/Browser Forum profile — enforces WebPKI policy rules (default). |
| `"rfc5280"` | RFC 5280 profile — less restrictive, accepts private or enterprise PKI chains. |

```toml
profile = "webpki"
```

#### `allow_post_quantum`

**Optional. Default: `false`.**

When `true`, ML-DSA and hybrid composite post-quantum signature algorithms (draft-ietf-lamps-pq-composite-sigs) are accepted in client certificates and `CertificateVerify` messages. When `false`, only classical algorithms are accepted.

```toml
allow_post_quantum = false
```

#### `max_chain_depth`

**Optional. Default: `8`.**

Maximum certificate chain depth accepted for client certificates. Chains longer than this value are rejected.

```toml
max_chain_depth = 8
```

#### `minimum_rsa_modulus`

**Optional. Default: `2048`.**

Minimum RSA modulus size in bits for RSA client certificates. Connections presenting an RSA certificate with a smaller key are rejected.

```toml
minimum_rsa_modulus = 2048
```

---

## `[email_challenge]`

The `[email_challenge]` section enables the RFC 8823 `email-reply-00` challenge type for S/MIME certificate issuance. When this section is absent or `enabled = false`, the server does not offer `email-reply-00` challenges and rejects orders with `email` identifier types.

See [email-reply-00](challenges.md#email-reply-00-rfc-8823) in the Challenges reference for the full protocol description, CSR requirements, and webhook payload format.

```toml
[email_challenge]
enabled             = true
from_address        = "acme-validation@example.com"
send_script         = "/etc/akamu/send-email.sh"
webhook_hmac_secret = "replace-with-output-of--openssl-rand-hex-32"
```

### `enabled`

**Optional. Default: `false`.**

Set to `true` to activate the `email-reply-00` challenge type. When `false`, any POST to `/acme/email-webhook` returns `503 Service Unavailable`.

### `from_address`

**Required when `enabled = true`.** The email address the server sends challenge emails from. This value is returned to clients in the `from` field of the challenge object and passed to the send script as `$ACME_FROM`.

```toml
from_address = "acme-validation@example.com"
```

The domain portion of this address is used to construct the `Message-ID` header (`<uuid@from-domain>`).

### `send_script`

**Required when `enabled = true`.** Absolute path to an executable that sends the challenge email. The server invokes it with no arguments; all parameters are passed as environment variables:

| Variable | Value |
|----------|-------|
| `ACME_TO` | Recipient email address (the identifier value) |
| `ACME_FROM` | Sender address (equals `from_address`) |
| `ACME_SUBJECT` | `ACME: <base64url(token-part1)>` |
| `ACME_MESSAGE_ID` | Server-generated `Message-ID` — the script must use this exactly in the outbound `Message-ID` header |
| `ACME_AUTO_SUBMITTED` | `auto-generated; type=acme` |
| `ACME_TOKEN_PART2` | token-part2 (base64url); the ACME challenge `token` field value, exposed for logging or advanced script use |

Exit code 0 = success. Any non-zero exit code marks the challenge invalid and the client may retry.

The script is responsible for DKIM signing of the outbound email. `Akāmu` does not perform SMTP or DKIM internally.

```toml
send_script = "/etc/akamu/send-email.sh"
```

### `send_script_timeout_secs`

**Optional. Default: `30`.**

Maximum time in seconds the server waits for `send_script` to exit. If the script does not exit within this limit, the server kills it and marks the challenge invalid. Must be at least 1. Increase this if your mail transfer agent has a slow startup or must authenticate to a relay.

```toml
send_script_timeout_secs = 30
```

### `webhook_hmac_secret`

**Required when `enabled = true`.** A shared secret used to authenticate `POST /acme/email-webhook` requests. The caller must include the header:

```
X-Akamu-Signature: sha256=<lowercase-hex(HMAC-SHA256(raw-body, webhook_hmac_secret))>
```

Choose a long random value (≥256 bits recommended). Requests with a missing, malformed, or incorrect signature are rejected with `403 Forbidden`.

```toml
webhook_hmac_secret = "replace-with-output-of--openssl-rand-hex-32"
```

**Keep this value secret.** Anyone who knows it can submit webhook payloads and influence challenge outcomes.


---

## `[delegation_upstream]`

The `[delegation_upstream]` section configures Akāmu to act as an ACME client toward an upstream CA when processing RFC 9115 delegation orders. When this section is present, a background task polls delegation orders in `processing` status and drives them through the full ACME flow on the upstream CA: account registration (if needed), order creation, dns-01 challenge deployment, finalization, and certificate retrieval.

When this section is absent, Akāmu operates only as an IdO ACME server — it issues delegation orders but does not drive an upstream CA leg. The background task is not started.

```toml
[delegation_upstream]
directory_url           = "https://upstream-ca.example.com/acme/directory"
account_key_file        = "/etc/akamu/upstream-acme.key.pem"
contacts                = ["mailto:admin@example.com"]
challenge_solver        = "dns-01"
challenge_deploy_script = "/etc/akamu/upstream-dns-deploy.sh"
# challenge_cleanup_script = "/etc/akamu/upstream-dns-cleanup.sh"
# poll_interval_secs = 10
```

### `directory_url`

**Required within `[delegation_upstream]`.** ACME directory URL of the upstream CA. Akāmu fetches the directory at startup to discover the upstream CA's endpoint URLs.

```toml
directory_url = "https://upstream-ca.example.com/acme/directory"
```

### `account_key_file`

**Required within `[delegation_upstream]`.** Path to a PEM file containing the ACME account key used when registering with the upstream CA. The file is loaded at startup. If the key file is absent on disk, a new EC P-256 key is generated and written to this path on first run.

```toml
account_key_file = "/etc/akamu/upstream-acme.key.pem"
```

### `contacts`

**Optional. Default: `[]`.**

List of contact URIs (e.g. `mailto:` addresses) submitted to the upstream CA when registering the ACME account. Omit if the upstream CA does not require contacts.

```toml
contacts = ["mailto:admin@example.com"]
```

### `challenge_solver`

**Required within `[delegation_upstream]`.** Challenge type used to satisfy the upstream CA's authorizations. Only `"dns-01"` is currently supported.

```toml
challenge_solver = "dns-01"
```

### `challenge_deploy_script`

**Required within `[delegation_upstream]`.** Absolute path to an executable that deploys the dns-01 TXT record at the upstream CA's direction. The script is invoked with `env_clear()`; only the following environment variables are set:

| Variable | Value |
|----------|-------|
| `CERTBOT_DOMAIN` | The domain name being validated (e.g. `_acme-challenge.example.com`) |
| `CERTBOT_VALIDATION` | The TXT record value to publish |

Exit code 0 = record deployed successfully. Any non-zero exit code marks the challenge attempt as failed.

```toml
challenge_deploy_script = "/etc/akamu/upstream-dns-deploy.sh"
```

The cleanup script is called only after the authorization has transitioned to `valid` at the upstream CA — not immediately after the deploy script exits. This ensures the TXT record remains queryable for the full upstream validation window.

### `challenge_cleanup_script`

**Optional. Default: absent (no cleanup).**

Absolute path to an optional cleanup executable invoked after the upstream authorization has become `valid`. Receives the same `CERTBOT_DOMAIN` and `CERTBOT_VALIDATION` variables as the deploy script, plus `CERTBOT_AUTH_OUTPUT=""`. Use it to remove the TXT record from DNS.

```toml
challenge_cleanup_script = "/etc/akamu/upstream-dns-cleanup.sh"
```

### `poll_interval_secs`

**Optional. Default: `10`.**

How often the background task polls the upstream CA for order and authorization status, in seconds.

```toml
poll_interval_secs = 10
```

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

Beyond the core extension fields, each `builtin` profile supports four groups of optional settings:

*Multi-CA restriction*

| Key | Default | Description |
|-----|---------|-------------|
| `ca_ids` | `[]` | List of CA IDs for which this profile is available. When non-empty, the profile is only accessible via the named CAs' ACME endpoints; requests via other CAs receive `invalidProfile`. Empty = available via all CAs. Config validation rejects entries not matching a configured CA `id`. |

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

The `[admin]` section enables the server-side Admin API on a dedicated listener with mutual TLS and/or GSSAPI/Kerberos authentication. When this section is absent, all admin endpoints return 404 and are effectively invisible. This is the default; no admin access is possible without explicit configuration.

Operator identity is verified by one or both of:

- **mTLS client certificates** — the connecting client presents a certificate signed by one of the CAs listed in `ca_certs`.
- **GSSAPI/Kerberos** — clients authenticate via a Kerberos session established through `[admin.gssapi]`.

At least one of `ca_certs` (non-empty) or `[admin.gssapi]` must be configured; the server exits at startup if neither is set.

```toml
[admin]
listen_addr = "127.0.0.1:9443"
cert_file   = "/etc/akamu/admin-tls.pem"       # auto-generated on first run if absent
key_file    = "/etc/akamu/admin-tls-key.pem"   # auto-generated on first run if absent
ca_certs    = ["/etc/akamu/ca.pem"]

# Bootstrap operator (mTLS) — generated and registered on first run when operators table is empty.
# bootstrap_operator_cert_file = "/etc/akamu/admin-bootstrap.pem"
# bootstrap_operator_key_file  = "/etc/akamu/admin-bootstrap-key.pem"

# Bootstrap operator (GSSAPI) — mutually exclusive with cert bootstrap above.
# When operators table is empty at startup, registers this principal as Administrator.
# bootstrap_operator_gssapi_principal = "admin@EXAMPLE.COM"

# Optional: also accept GSSAPI-authenticated operators
[admin.gssapi]
keytab_file  = "/etc/akamu/http.keytab"
service_name = "HTTP"
```

### `listen_addr`

**Required within `[admin]`.** The TCP address and port the dedicated admin listener binds to. Keep this separate from the main ACME listener and scope it to localhost or an internal management network.

```toml
listen_addr = "127.0.0.1:9443"
```

### `cert_file`

**Required within `[admin]`.** PEM file containing the admin listener's TLS server certificate chain (leaf certificate first). When both `cert_file` and `key_file` are absent on disk, Akāmu generates a server certificate signed by the Akāmu CA on first run, using `server_name` and `bootstrap_key_type`.

```toml
cert_file = "/etc/akamu/admin-tls.pem"
```

### `key_file`

**Required within `[admin]`.** PEM file containing the admin listener's TLS private key (PKCS#8 or SEC1, unencrypted). Auto-generated alongside `cert_file` when both are absent.

```toml
key_file = "/etc/akamu/admin-tls-key.pem"
```

### `server_name`

**Optional. Default: `"localhost"`.**

Hostname placed in the CN and SAN of the auto-generated admin server certificate. Only used when `cert_file`/`key_file` are absent on first run.

```toml
server_name = "admin.akamu.internal"
```

### `bootstrap_key_type`

**Optional. Default: `"ec:P-256"`.**

Key algorithm used when auto-generating the admin server certificate and the bootstrap operator certificate. Same syntax as `ca.key_type`.

```toml
bootstrap_key_type = "ec:P-256"
```

### `bootstrap_operator_cert_file`

**Optional.**

Path where the bootstrap Administrator operator's client certificate will be written on first run. When this file (and `bootstrap_operator_key_file`) are absent and the operators table is empty, Akāmu generates a client certificate signed by the Akāmu CA and registers the operator automatically. Both fields must be set together.

```toml
bootstrap_operator_cert_file = "/etc/akamu/admin-bootstrap.pem"
```

### `bootstrap_operator_key_file`

**Optional.**

Path where the bootstrap Administrator operator's client private key will be written on first run. Must be set alongside `bootstrap_operator_cert_file`.

```toml
bootstrap_operator_key_file = "/etc/akamu/admin-bootstrap-key.pem"
```

### `bootstrap_operator_name`

**Optional. Default: `"admin"`.**

Name recorded in the operators table for the auto-provisioned bootstrap administrator.

```toml
bootstrap_operator_name = "admin"
```

### `bootstrap_operator_gssapi_principal`

**Optional. Default: unset.**

Kerberos principal for the GSSAPI bootstrap Administrator operator (e.g. `"admin@REALM"`). When set and the operators table is empty at startup, Akāmu inserts an Administrator row with this principal so that the first `akamuctl login --gssapi` succeeds without a prior `akamuctl operator add`. Mutually exclusive with `bootstrap_operator_cert_file` / `bootstrap_operator_key_file`.

```toml
bootstrap_operator_gssapi_principal = "admin@EXAMPLE.COM"
```

### `ca_certs`

**Optional. Default: `[]`.**

List of PEM CA certificate files whose issued client certificates are accepted as operator credentials. When set, clients connecting to the admin listener must present a client certificate signed by one of these CAs. May be empty when `[admin.gssapi]` is the sole authentication method, but at least one of `ca_certs` or `[admin.gssapi]` must be configured.

```toml
ca_certs = ["/etc/akamu/operator-ca.pem"]
```

### `session_ttl_secs`

**Optional. Default: `3600` (1 hour).**

Inactive session expiry in seconds. Operator sessions that have had no activity for this duration are invalidated and require re-authentication.

```toml
session_ttl_secs = 3600
```

### `session_lock_secs`

**Optional. Default: `900` (15 minutes).**

Inactivity threshold before a session enters locked state (FTA_SSL_EXT.1). After
this many idle seconds, requests that present the session token receive
`423 Locked` instead of `401 Unauthorized`. The session is not destroyed; the
operator must re-authenticate to obtain a fresh token. This value must be less
than `session_ttl_secs`.

```toml
session_lock_secs = 900
```

### `max_failed_auth`

**Optional. Default: `5`.**

Maximum number of failed authentication attempts allowed for an operator before
the account is locked (FIA_AFL.1). Once the threshold is exceeded, further
authentication attempts return `423 Locked` until an administrator calls
`POST /admin/operators/{id}/unlock` (or uses `akamuctl operator unlock`).

```toml
max_failed_auth = 5
```

### `lockout_duration_secs`

**Optional. Default: `1800` (30 minutes).**

How long in seconds the operator account remains locked after exceeding
`max_failed_auth` (FIA_AFL.1). After this duration the lock is automatically
cleared; an administrator may also clear it early with `operator unlock`.

```toml
lockout_duration_secs = 1800
```

### `audit_max_rows`

**Optional. Default: absent (unlimited).**

Maximum number of rows to retain in the `audit_events` database table. When the limit is reached, the `audit_overflow` policy determines what happens.

```toml
audit_max_rows = 500000
```

### `audit_overflow`

**Optional. Default: `"drop_oldest"`.**

Policy applied when `audit_max_rows` is reached. Accepted values:

| Value | Behaviour |
|-------|-----------|
| `"drop_oldest"` | Delete the oldest audit rows to make room for new events (default). |
| `"halt"` | Refuse new requests until audit rows are pruned manually. |

```toml
audit_overflow = "drop_oldest"
```

### `audit_alarm_threshold`

**Optional. Default: `10`.**

Number of `SecurityViolation` audit events in a rolling 5-minute window that triggers the alarm response configured by `audit_alarm_action`.

```toml
audit_alarm_threshold = 10
```

### `audit_alarm_action`

**Optional. Default: `"syslog"`.**

Action taken when the `audit_alarm_threshold` is exceeded. Accepted values:

| Value | Behaviour |
|-------|-----------|
| `"syslog"` | Log a `CRIT`-level message to syslog (default). |
| `"halt"` | Halt the server process immediately. |

```toml
audit_alarm_action = "syslog"
```

### `[admin.gssapi]`

**Optional. When absent, GSSAPI authentication for the admin interface is disabled.**

Configures GSSAPI/Kerberos authentication for operators accessing the admin API. When set, operators can authenticate by presenting a Kerberos service ticket without requiring a client certificate.

#### `keytab_file`

**Required within `[admin.gssapi]`.** Path to the Kerberos keytab file for the admin service principal.

```toml
keytab_file = "/etc/akamu/http.keytab"
```

#### `service_name`

**Optional. Default: `"HTTP"`.**

Host-based service name. MIT Kerberos appends `@<local-hostname>` when no realm is specified.

```toml
service_name = "HTTP"
```

**Admin endpoints and RBAC roles:**

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
| `GET` | `/admin/cas` | Y | Y | Y | Y |
| `GET` | `/admin/cas/{id}` | Y | Y | Y | Y |
| `POST` | `/admin/ca/{id}/crl/force` | Y | Y | | |
| `POST` | `/admin/ca/{id}/cross-sign` | Y | Y | | |
| `GET` | `/admin/cross-certs` | Y | Y | Y | Y |
| `GET` | `/admin/cross-certs/{id}` | Y | Y | Y | Y |
| `GET` | `/admin/delegations` | Y | Y | | |
| `POST` | `/admin/delegations` | Y | | | |
| `GET` | `/admin/delegations/{id}` | Y | Y | | |
| `PUT` | `/admin/delegations/{id}` | Y | | | |
| `DELETE` | `/admin/delegations/{id}` | Y | | | |

See [Admin API and Operator Management](admin-api.md) for the full request/response format of each endpoint.

