# Configuration Reference

`Akāmu` reads a single TOML configuration file whose path is passed as the first command-line argument:

```
akamu /etc/akamu/config.toml
```

If no argument is given, the server looks for `config.toml` in the current working directory.

The file is parsed once at startup. Changes require a restart. Unknown keys produce a parse error on startup (serde's strict TOML parser).

## Complete example

```toml
listen_addr  = "0.0.0.0:8080"
base_url     = "https://acme.example.com"
crdt_db_url  = "sqlite:///var/lib/akamu/crdt.db"

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
# log_number = 1
# tree_minimum_index = 0
# trust_anchor_id = "1.3.6.1.4.1.44363.47.10.1"

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
keytab_file  = "/etc/akamu/http.keytab"   # omit and set gssproxy = true to use gssproxy instead
service_name = "HTTP"

# [server.webui]
# static_dir = "/usr/share/akamu/webui"

[tls.client_auth]
ca_files = ["/etc/akamu/operator-ca.pem"]
required = false

[admin]
session_ttl_secs = 3600

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

[tkauth]
enabled                 = false
# trusted_ta_ca_files   = ["/etc/akamu/ta-root.pem"]
# token_authority_url   = "https://ta.example.com"
# max_validity_secs     = 3600
# jti_prune_interval_secs = 3600
# [[tkauth.claim_encoders]]
# claim   = "sub"
# encoder = "krb5-kpn"

[gossip]
peers                      = ["https://node2.example.com", "https://node3.example.com"]
interval_secs              = 15
tombstone_ttl_secs         = 604800
ownership_ttl_secs         = 150
gossip_envelope_max_age_secs = 300
clock_skew_tolerance_secs  = 30
fan_out                    = 3

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

**Required.** The address the server binds to. Two forms are accepted:

| Form | Example | Description |
|------|---------|-------------|
| `"host:port"` | `"0.0.0.0:8080"` | TCP socket — bind on all interfaces, port 8080 |
| `"unix:/path"` or `"/path"` | `"unix:/run/akamu/akamu.sock"` | Unix domain socket at the given filesystem path |

```toml
# TCP (bind on all interfaces)
listen_addr = "0.0.0.0:8080"

# TCP (localhost only — behind a reverse proxy on the same host)
listen_addr = "127.0.0.1:8080"

# Unix domain socket (reverse proxy on the same host)
listen_addr = "unix:/run/akamu/akamu.sock"
```

The `AKAMU_LISTEN` environment variable overrides this field without touching the config file — useful for socket-activated deployments or overriding the bind address at start time:

```
AKAMU_LISTEN=unix:/run/akamu/akamu.sock akamu /etc/akamu/config.toml
```

**Constraint:** Unix domain sockets and `[tls]` are mutually exclusive. When `listen_addr` is a Unix path and `[tls].enabled = true`, the server exits at startup with an error. TLS termination must be handled by the reverse proxy in front of the socket.

See [Running behind a reverse proxy (Unix socket)](../quickstart/first-run.md#running-behind-a-reverse-proxy-unix-socket) in the quickstart for nginx, Apache, and systemd socket-activation examples.

### `base_url`

**Required.** The public HTTPS base URL of the ACME server. This value is embedded in every URL the server returns to clients — directory endpoint URLs, account URLs, order URLs, certificate download URLs, etc.

```toml
base_url = "https://acme.example.com"
```

It must match the URL that ACME clients use to reach the directory. It must not end with a slash.

### `crdt_db_url`

**Optional. Default: absent (uses `[database].url`).**

SQLite connection URL for the separate CRDT database used when multi-node clustering is enabled (see `[gossip]`). When absent, CRDT tables are created in the main `[database]` database. A separate database is recommended in production clustering deployments to isolate CRDT write traffic from ACME traffic.

Only SQLite is supported for the CRDT database (`sqlite://…` URL format). The file and its WAL journal are created automatically if they do not exist.

```toml
crdt_db_url = "sqlite:///var/lib/akamu/crdt.db"
```

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
| `"ml-dsa-44"` | Pure ML-DSA-44 (FIPS 204 parameter set 2) — requires OpenSSL 3.5+ |
| `"ml-dsa-65"` | Pure ML-DSA-65 (FIPS 204 parameter set 3) — requires OpenSSL 3.5+ |
| `"ml-dsa-87"` | Pure ML-DSA-87 (FIPS 204 parameter set 5) — requires OpenSSL 3.5+ |

**Composite ML-DSA variants** (draft-ietf-lamps-pq-composite-sigs-19, sub-arcs 37–54 — requires OpenSSL 3.5+):

| Value | Algorithm | OID sub-arc |
|---|---|---|
| `"composite-mldsa44-rsa2048-pss-sha256"` | ML-DSA-44 + RSA-2048-PSS-SHA-256 | 37 |
| `"composite-mldsa44-rsa2048-pkcs15-sha256"` | ML-DSA-44 + RSA-2048-PKCS#1v1.5-SHA-256 | 38 |
| `"composite-mldsa44-ed25519-sha512"` | ML-DSA-44 + Ed25519-SHA-512 | 39 |
| `"composite-mldsa44-ecdsa-p256-sha256"` | ML-DSA-44 + ECDSA-P256-SHA-256 | 40 |
| `"composite-mldsa65-rsa3072-pss-sha512"` | ML-DSA-65 + RSA-3072-PSS-SHA-512 | 41 |
| `"composite-mldsa65-rsa3072-pkcs15-sha512"` | ML-DSA-65 + RSA-3072-PKCS#1v1.5-SHA-512 | 42 |
| `"composite-mldsa65-rsa4096-pss-sha512"` | ML-DSA-65 + RSA-4096-PSS-SHA-512 | 43 |
| `"composite-mldsa65-rsa4096-pkcs15-sha512"` | ML-DSA-65 + RSA-4096-PKCS#1v1.5-SHA-512 | 44 |
| `"composite-mldsa65-ecdsa-p256-sha512"` | ML-DSA-65 + ECDSA-P256-SHA-512 | 45 |
| `"composite-mldsa65-ecdsa-p384-sha512"` | ML-DSA-65 + ECDSA-P384-SHA-512 | 46 |
| `"composite-mldsa65-ecdsa-brainpoolp256r1-sha512"` | ML-DSA-65 + ECDSA-brainpoolP256r1-SHA-512 | 47 |
| `"composite-mldsa65-ed25519-sha512"` | ML-DSA-65 + Ed25519-SHA-512 | 48 |
| `"composite-mldsa87-ecdsa-p384-sha512"` | ML-DSA-87 + ECDSA-P384-SHA-512 | 49 |
| `"composite-mldsa87-ecdsa-brainpoolp384r1-sha512"` | ML-DSA-87 + ECDSA-brainpoolP384r1-SHA-512 | 50 |
| `"composite-mldsa87-ed448-shake256"` | ML-DSA-87 + Ed448-SHAKE-256 | 51 |
| `"composite-mldsa87-rsa3072-pss-sha512"` | ML-DSA-87 + RSA-3072-PSS-SHA-512 | 52 |
| `"composite-mldsa87-rsa4096-pss-sha512"` | ML-DSA-87 + RSA-4096-PSS-SHA-512 | 53 |
| `"composite-mldsa87-ecdsa-p521-sha512"` | ML-DSA-87 + ECDSA-P521-SHA-512 | 54 |

Each composite variant also accepts the canonical `COMPSIG-*` label (case-insensitive, with or without the `COMPSIG-` prefix). For example, sub-arc 40 accepts all three forms: `"composite-mldsa44-ecdsa-p256-sha256"`, `"COMPSIG-MLDSA44-ECDSA-P256-SHA256"`, and `"mldsa44-ecdsa-p256-sha256"`.

> **`hash_alg` is ignored for composite CA keys.** The hash algorithm is fixed by the composite algorithm specification (e.g. SHA-256 for sub-arc 40, SHA-512 for sub-arc 46). Set `hash_alg` to a valid value for any non-composite CA that shares the same config stanza; Akāmu silently ignores it for composite keys. For pure ML-DSA keys, `hash_alg` is also ignored — ML-DSA has no separate hash parameter.

> **OID stability note:** The composite OIDs (sub-arcs 37–54) are defined by draft-ietf-lamps-pq-composite-sigs-19 and are provisional pending IANA allocation. They may change as the draft advances toward RFC publication.

```toml
key_type = "ec:P-256"
```

Example: composite CA key with ML-DSA-65 + ECDSA-P384:

```toml
[[ca]]
id       = "composite-pq"
key_file  = "/etc/akamu/composite-ca.key.pem"
cert_file = "/etc/akamu/composite-ca.cert.pem"
key_type  = "composite-mldsa65-ecdsa-p384-sha512"
hash_alg  = "sha512"   # ignored for composite keys; set for documentation clarity
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

### `mtc`

**Optional. Default: absent (CA does not participate in an MTC log).**

Per-CA MTC transparency log configuration. When present, this CA participates
in a Merkle Tree Certificate log with the settings given here. The sub-table
accepts the same fields as the top-level `[mtc]` section (see below).

When absent, the CA falls back to the global `[mtc]` section if one exists.
Prefer the per-CA form for new deployments; the global `[mtc]` section is
deprecated and retained only for backward compatibility.

```toml
[[ca]]
id        = "default"
key_file  = "/etc/akamu/ca.key.pem"
cert_file = "/etc/akamu/ca.cert.pem"

[ca.mtc]
log_path = "/var/lib/akamu/mtc.log"
enabled  = true
```

---

## `[mtc]`

> **Deprecated.** The top-level `[mtc]` section is retained for backward
> compatibility. Prefer the per-CA `[ca.mtc]` sub-table instead. When a CA
> has its own `[ca.mtc]`, the global section is ignored for that CA.

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

### MTC standalone certificate format

When `issue_as = "mtc"` is set in a profile, the server builds a standalone certificate for each issued certificate. The standalone certificate is a standard X.509 v3 `Certificate` where:

- `signatureAlgorithm` is `id-alg-mtcProof` (experimental OID `1.3.6.1.4.1.44363.47.0` from the Cloudflare PEN arc)
- `signatureValue` carries a TLS-encoded `MTCProof` (inclusion proof + cosignature records); per draft-04 §4.3, `MTCProof` has a leading `extensions` field (uint16 length-prefixed; empty = `\x00\x00`), `start`/`end` as uint48 (6-byte big-endian), and a uint8-prefixed `cosigner_id` in each `MtcSignature`
- `serialNumber` encodes the log entry index per draft §6.1

The `GET /acme/mtc/cert/{cert_id}/standalone` and `GET /acme/mtc/landmarks/{seq}/cert` endpoints return the DER-encoded certificate with `Content-Type: application/pkix-cert` and the `X-MTC-Version: draft-04` response header.

> **OID stability note:** The OIDs are experimental and pre-IANA. They will change when draft-ietf-plants-merkle-tree-certs is published as an RFC, requiring a coordinated update of the `synta-mtc` library and relying implementations. When `[mtc]` is enabled and `[mtc.signing_key]` is configured, the auto-generated CA certificate includes the `id-pe-mtcCertificationAuthority` extension (experimental OID `1.3.6.1.4.1.44363.47.2`), identifying the CA as an MTC-capable issuer.

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

### `hash_alg`

**Optional. Default: `"sha256"`.**

Hash algorithm used for Merkle tree leaf hashing. Valid values:

| Value | Algorithm |
|-------|-----------|
| `"sha256"` | SHA-256 (32-byte leaf hashes) |
| `"sha384"` | SHA-384 (48-byte leaf hashes) |
| `"sha512"` | SHA-512 (64-byte leaf hashes) |
| `"sha3-256"` | SHA3-256 (32-byte leaf hashes) |
| `"sha3-384"` | SHA3-384 (48-byte leaf hashes) |
| `"sha3-512"` | SHA3-512 (64-byte leaf hashes) |

The algorithm is stored in the log file's header at creation time and cannot be changed for an existing log. If you change `hash_alg` after the log file already exists, Akāmu will refuse to start with an error identifying the mismatch. To switch algorithms you must delete the log file (and its lock file, if any) and let the server recreate it from scratch.

```toml
[mtc]
hash_alg = "sha256"
```

### `log_number`

**Optional. Default: `1`.**

Log number for `serialNumber` encoding per draft-04 §6.1. The serial number of each standalone certificate is computed as `(log_number << 48) | entry_index`. Each CA log should receive a unique, consecutive-from-1 log number.

```toml
[mtc]
log_number = 1
```

### `tree_minimum_index`

**Optional. Default: absent.**

Minimum valid entry index (§5.2.3 log pruning). When set, the value is included in the `Checkpoint.treeMinimumIndex` field, indicating that entries below this index may have been pruned from the log. Relying parties should not attempt to verify inclusion proofs for entries below this index.

```toml
[mtc]
tree_minimum_index = 100
```

### `trust_anchor_id`

**Optional. Default: absent.**

The CA's own `TrustAnchorID` OID in dotted-decimal notation. Per draft-04 §5.4, each CA MUST operate a CA cosigner whose cosigner ID is the same as its CA ID. When set, a self-cosignature is produced alongside any external cosignatures during checkpoint production. The signing key configured in `[mtc.signing_key]` is used for the self-cosignature.

When absent, no self-cosignature is produced.

```toml
[mtc]
trust_anchor_id = "1.3.6.1.4.1.44363.47.10.1"
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

Hash algorithm used for ECDSA/RSA signing of MTC checkpoints and cosignatures: `"sha256"`, `"sha384"`, `"sha512"`. Ignored for EdDSA and ML-DSA signing key types.

This field controls the *signing* hash only and is unrelated to the Merkle tree leaf-hash algorithm, which is configured separately via `[mtc].hash_alg`.

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

**Optional.** Path to the cosigner's X.509 identity certificate PEM file. When set, the file is loaded at startup and added to the TLS trust store for that cosigner's HTTPS connection, in addition to the system root CAs. This allows cosigners whose TLS certificate chains to an operator-provisioned CA to be used without installing that CA system-wide. The certificate is also used for cryptographic verification of received `SubtreeSignature` values.

#### `trust_anchor_id`

**Optional.** The expected `TrustAnchorID` OID of the cosigner in dotted-decimal notation (e.g. `"1.3.6.1.4.1.44363.47.10.1"`). Per draft-ietf-plants-merkle-tree-certs-04 §4.1, `CosignerID` is now an `OBJECT IDENTIFIER` (`TrustAnchorID ::= OBJECT IDENTIFIER`) rather than a SEQUENCE of hash algorithm and public key. When set, Akāmu verifies that the `SubtreeSignature.cosigner` OID in each response matches this value. When absent, the OID identity check is skipped; cryptographic verification via `cosigner_id_cert_pem` still applies when that field is set. Operators must agree on the OID value with their cosigner operator.

> **Security constraint:** Setting `trust_anchor_id` without also setting `cosigner_id_cert_pem` is a hard startup error. OID-only verification provides no cryptographic assurance — anyone who knows the OID could forge a cosignature. Both fields must be set together to enable verified cosignature acceptance.

```toml
[[mtc.cosigners]]
url                  = "https://cosigner1.example.com/sign"
cosigner_id_cert_pem = "/etc/akamu/cosigner1-id.pem"
trust_anchor_id      = "1.3.6.1.4.1.44363.47.10.1"   # optional; TrustAnchorID OID

[[mtc.cosigners]]
url = "https://cosigner2.example.com/sign"
```

---

## `[server]`

The `[server]` section is optional. When omitted entirely, all fields take their default values.

### `audit_log_file`

**Optional. Default: absent (use systemd journal namespace).**

Path to a JSONL (JSON Lines) audit log file. When set, audit events are written as append-only JSON Lines to this file instead of the systemd journal namespace socket. Each line is a JSON object with `occurred_at`, `AKAMU_EVENT_TYPE`, `AKAMU_OUTCOME`, and optional `AKAMU_SUBJECT`, `AKAMU_PRINCIPAL`, `AKAMU_DETAIL` fields.

When absent (the default), the server writes to the `akamu` journal namespace (see `contrib/systemd/journald@akamu.conf`). Use this option on systems without systemd or when journal namespace sockets are not available.

External `logrotate(8)` with `copytruncate` is expected for log rotation. Each audit query scans at most 500,000 lines to prevent unbounded reads on unrotated files.

```toml
[server]
audit_log_file = "/var/log/akamu/audit.jsonl"
```

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

### `profiles`

> **Deprecated.** Use the top-level [`[profiles]`](#profiles) section instead,
> which supports multiple provider backends (builtin, dogtag, ipa) and
> per-profile extension control. `[server].profiles` is retained for backward
> compatibility and will be removed in a future release.

**Optional. Default: `{}` (empty map).**

Simple map of profile identifier to human-readable description or documentation URL. When non-empty, the profile identifiers are advertised in the ACME directory `meta` object and clients may request a profile by name in `newOrder` (draft-ietf-acme-profiles). When empty, profile selection is not advertised.

```toml
# Deprecated — prefer [profiles.providers.local] instead
[server.profiles]
"tlsserver" = "Standard TLS server certificate"
"smime"     = "S/MIME email protection certificate"
```

**Migrating to `[profiles]`:** move each entry from `[server.profiles]` to a
`builtin` provider under `[profiles.providers]`. The profile identifier becomes
a sub-table key and the description string becomes the `description` field:

```toml
# Before (deprecated):
[server.profiles]
"tlsserver" = "Standard TLS server certificate"

# After (recommended):
[profiles.providers.local]
type = "builtin"

[profiles.providers.local.profiles.tlsserver]
description   = "Standard TLS server certificate"
validity_days = 90
key_usage     = ["digital_signature", "key_encipherment"]
eku           = ["server_auth"]
```

The top-level `[profiles]` form also supports Dogtag and IPA provider backends,
per-profile key usage / EKU / validity overrides, identifier restrictions, and
authorization hooks. See [`[profiles]`](#profiles) for the full reference.

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

List of entries whose connecting IP address is trusted to supply an
`X-Remote-User` header. Each entry is either a CIDR block (IPv4 or IPv6) or
the special literal `"local addresses"` which expands at runtime to all IP
addresses assigned to local network interfaces (via `getifaddrs`, refreshed
every 30 seconds). When a request arrives from a matching address, akamu reads
the header value as the already-authenticated principal name — the reverse
proxy is expected to have completed SPNEGO or another authentication step
before forwarding the request.

Requests from addresses not in this list never have `X-Remote-User` honoured,
regardless of what the header contains.

**Mutually exclusive with `[server.gssapi]`.** Setting both `trusted_proxies`
and `[server.gssapi]` at the same time is a configuration error; the server
exits at startup with an error message.

```toml
[server]
# Explicit CIDRs
trusted_proxies = ["127.0.0.1/32", "::1/128", "10.0.0.0/8"]

# Or use "local addresses" when the proxy runs on the same host
# trusted_proxies = ["local addresses"]
```

Security note: keep this list tightly scoped to the IP addresses of your
reverse proxy or load balancer. Adding broad ranges (e.g. `0.0.0.0/0`) allows
any client to impersonate any principal.

### `[server.gssapi]`

**Optional. When absent, standalone GSSAPI mode is disabled.**

**Mutually exclusive with `trusted_proxies`.** Setting both at the same time is
a configuration error; the server exits at startup with an error message.

Configures akamu to accept `Authorization: Negotiate` tokens directly, without
a reverse proxy. At startup the server acquires a combined initiator+acceptor
credential (`GSS_C_BOTH`) using `gss_acquire_cred_from` and then uses
`gss_accept_sec_context` to validate each SPNEGO token. The `GSS_C_BOTH` usage
flag is required for S4U2Self constrained delegation (used internally for LDAP
profile lookups). Credentials are acquired either directly from `keytab_file`
or, when `gssproxy = true`, via the [gssproxy](https://github.com/gssapi/gssproxy)
daemon (which intercepts the underlying GSSAPI call and supplies credentials
from its own keytab configuration).

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
- **Replay detection.** After a successful context acceptance, akamu checks
  whether `GSS_C_REPLAY_FLAG` is set. When the flag is absent (common when
  clients connect over TLS, because TLS already provides replay protection),
  a `debug`-level log entry is emitted and the authentication proceeds
  normally. This behaviour is intentional: browsers and TLS-first clients
  typically do not negotiate Kerberos-level replay protection.
- **GSSAPI without TLS.** Running standalone GSSAPI without TLS is permitted
  but emits a `warn`-level log at startup: SPNEGO tokens are vulnerable to
  interception and relay attacks without TLS.
- **No mechanism configured.** When neither `trusted_proxies` nor
  `[server.gssapi]` is set, authenticated endpoints return `404 Not Found`.

#### `keytab_file`

**Required when `gssproxy = false` (the default). Must be absent when `gssproxy = true`.**
Path to the HTTP service keytab file. The akamu process must be able to read
this file; no other user should have read access to it. The path is logged at
`debug` level only. Setting both `keytab_file` and `gssproxy = true` is a
configuration error; the server exits at startup.

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

#### `gssproxy`

**Optional. Default: `false`.**

When `true`, GSSAPI credential acquisition is delegated to the
[gssproxy](https://github.com/gssapi/gssproxy) daemon instead of reading a
keytab file directly. The akamu process must have a matching entry in
`/etc/gssproxy/conf.d/` (typically matched by UID). The server sets
`GSS_USE_PROXY=yes` in its environment before the first GSSAPI call so that the
GSSAPI library routes the credential request through gssproxy. No direct access
to a keytab file on disk is needed. `keytab_file` must be absent when this is
`true`.

```toml
# gssproxy mode — no keytab access required for the akamu process
[server.gssapi]
gssproxy     = true
service_name = "HTTP"
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

#### Standalone GSSAPI examples

Keytab mode — akamu reads the keytab file directly:

```toml
[server.gssapi]
keytab_file  = "/etc/akamu/http.keytab"
service_name = "HTTP"
```

gssproxy mode — akamu delegates credential acquisition to gssproxy (no direct
keytab access required for the akamu process):

```toml
[server.gssapi]
gssproxy     = true
service_name = "HTTP"
```

In both configurations, akamu handles `Authorization: Negotiate` directly.
Clients must obtain a Kerberos service ticket for `HTTP/<hostname>` before
calling authenticated endpoints.

### `[server.webui]`

**Optional. When absent, the `/ui/` routes are not registered and return 404.**

When present, Akāmu serves the built PatternFly management web UI from a
directory of static files. The UI is mounted at `/ui/*` on the same listener
as the ACME and admin APIs; no separate process or proxy is required.

When `[server.webui]` is absent (the default), no `/ui/*` routes are
registered at all. Requests to `/ui/` and `GET /` receive 404 responses as
if the routes did not exist.

When `[server.webui]` is present:

- `GET /ui/*` serves static files from `static_dir`.
- Directory requests fall back to `index.html` inside that directory (SPA
  routing support).
- `GET /` permanently redirects to `/ui/`.
- Security headers (`Content-Security-Policy`, `X-Frame-Options`, etc.) are
  added to every `/ui/*` response.

The admin API (`/admin/*`) is served on the same listener and is called
directly by the browser — no additional proxy is needed.

#### `static_dir`

**Optional. Default: absent (web UI disabled).**

Absolute path to the directory containing the built web UI files. The
directory must contain at minimum an `index.html` file.

| Deployment | Typical path |
|------------|--------------|
| Fedora / RHEL package | `/usr/share/akamu/webui` |
| Source build | `webui/dist/` (relative to the repository root, absolute path required) |

When `static_dir` is absent but `[server.webui]` is present, the section is
accepted without error and no routes are registered — the behavior is identical
to omitting `[server.webui]` entirely. Set `static_dir` to actually serve the UI.

Config validation rejects a relative path with a startup error.

```toml
[server.webui]
static_dir = "/usr/share/akamu/webui"
```

Source build example (absolute path required):

```toml
[server.webui]
static_dir = "/home/user/akamu/webui/dist"
```

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

**Required within `[delegation_upstream]`.** Challenge type used to satisfy the upstream CA's authorizations. Accepted values: `"dns-01"`, `"http-01"`, `"tls-alpn-01"`.

```toml
challenge_solver = "dns-01"
```

### `challenge_deploy_script`

**Required when `challenge_solver = "dns-01"`.** Absolute path to an executable that deploys the dns-01 TXT record at the upstream CA's direction. The script is invoked with `env_clear()`; only the following environment variables are set:

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

## `[tkauth]`

The `[tkauth]` section enables the RFC 9447 `tkauth-01` challenge type for `TNAuthList` (RFC 9448) and `JWTClaimConstraints` (draft-ietf-acme-authority-token-jwtclaimcon) identifier types. When this section is absent or `enabled = false`, orders containing these identifier types are rejected.

See [tkauth-01](challenges.md#tkauth-01-rfc-9447--rfc-9448) in the Challenges reference for the full protocol description including the authority token format, validation steps, and claim encoder configuration.

```toml
[tkauth]
enabled                 = true
trusted_ta_ca_files     = ["/etc/akamu/ta-root.pem"]
token_authority_url     = "https://ta.example.com"   # optional hint
max_validity_secs       = 3600
jti_prune_interval_secs = 3600

[[tkauth.claim_encoders]]
claim   = "sub"
encoder = "krb5-kpn"
```

### `enabled`

**Optional. Default: `false`.**

Set to `true` to activate the `tkauth-01` challenge type. When `false`, any order with `TNAuthList` or `JWTClaimConstraints` identifiers is rejected with `unsupportedIdentifier`.

### `trusted_ta_ca_files`

**Required when `enabled = true`.** List of absolute paths to PEM files containing trusted CA certificates for Token Authority signing certificate validation. The signing certificate presented in the authority token (via `x5u` or `x5c`) must chain to one of these CA roots. Not used for `kid`-signed tokens (which rely on `trust_jwks_urls` in per-profile configuration instead).

```toml
trusted_ta_ca_files = ["/etc/akamu/ta-root.pem"]
```

### `token_authority_url`

**Optional. Default: absent.**

URL hint included in `tkauth-01` challenge responses as the `token-authority` field. When set, ACME clients that read this field can use it to discover where to obtain an authority token. This is informational only; the server does not contact this URL itself.

```toml
token_authority_url = "https://ta.example.com"
```

### `max_validity_secs`

**Optional. Default: `3600` (1 hour).**

Maximum accepted lifetime of an authority token: tokens with `exp − now > max_validity_secs` are rejected. This caps how long into the future a Token Authority may pre-issue tokens, limiting the window in which a stolen token could be replayed.

```toml
max_validity_secs = 3600
```

### `jti_prune_interval_secs`

**Optional. Default: `3600` (1 hour).**

How often the background task purges expired JTI (JWT ID) entries from the replay-prevention cache in the database. Lower values reduce database growth at the cost of more frequent pruning queries. The background task only runs when `[tkauth]` is enabled.

```toml
jti_prune_interval_secs = 3600
```

Operators can also trigger manual pruning via the admin API or `akamuctl`:

```
POST /admin/tkauth/prune-jti
POST /admin/tkauth/prune-jti?dry_run=true
```

```bash
akamuctl tkauth prune-jti
akamuctl tkauth prune-jti --dry-run   # count without deleting
```

### `[[tkauth.claim_encoders]]`

Optional array of claim-to-extension encoder entries. Each entry maps a JWT claim name in `permittedValues` of the validated `JWTClaimConstraints` token to a built-in certificate extension encoder. The encoder runs at finalize time and injects the claim value as a Subject Alternative Name in the issued certificate.

```toml
[[tkauth.claim_encoders]]
claim   = "sub"
encoder = "krb5-kpn"
# default_realm = "EXAMPLE.COM"   # appended when claim value has no '@'

[[tkauth.claim_encoders]]
claim   = "upn"
encoder = "ms-upn"

[[tkauth.claim_encoders]]
claim   = "dns"
encoder = "dns-san"
```

**Built-in encoder names:**

| Encoder | SAN type | Notes |
|---------|----------|-------|
| `krb5-kpn` | OtherName (id-pkinit-san, OID `1.3.6.1.5.2.2`) | `principal@REALM`; if `@` is absent, `default_realm` is appended |
| `ms-upn` | OtherName (OID `1.3.6.1.4.1.311.20.2.3`) | `user@domain` |
| `dns-san` | dNSName | Plain hostname; wildcards rejected; lowercased before injection |

Each encoder entry has these fields:

| Field | Required | Description |
|-------|----------|-------------|
| `claim` | yes | JWT claim name in the authority token's `permittedValues` |
| `encoder` | yes | Encoder name: `"krb5-kpn"`, `"ms-upn"`, or `"dns-san"` |
| `default_realm` | no | Kerberos realm appended when the claim value contains no `@`. Only meaningful for `"krb5-kpn"`. |

A `permittedValues` entry with exactly one value is injected as a SAN using the matching encoder. Entries with multiple permitted values are skipped (the server cannot determine which specific value to attest).

---

## `[gossip]`

The `[gossip]` section enables multi-node clustering via CRDT replication. When present, Akāmu gossips CRDT deltas to the listed peer nodes over HTTP (`POST /gossip/sync`). All domain state — accounts, orders, authorizations, challenges, certificates, EAB keys, operators, delegations, and MTC data — is replicated to every cluster member. When absent, the node operates in single-node mode with no replication.

Gossip envelopes are signed with ML-KEM-768 + ECDSA-P256 to authenticate the source. Before gossip can proceed between two nodes, each node's keys must be registered on the other node via `POST /admin/gossip/register`.

```toml
[gossip]
peers                        = ["https://node2.example.com", "https://node3.example.com"]
interval_secs                = 15
tombstone_ttl_secs           = 604800
ownership_ttl_secs           = 150
gossip_envelope_max_age_secs = 300
clock_skew_tolerance_secs    = 30
fan_out                      = 3
```

### `peers`

**Optional. Default: `[]`.**

List of peer gossip URLs to push CRDT state to. Each entry must be the HTTPS base URL of a peer Akāmu node (scheme, host, and optional port; no trailing path). Peers are contacted each gossip round; the `fan_out` setting limits how many are contacted per round.

```toml
peers = ["https://node2.acme.internal:8443", "https://node3.acme.internal:8443"]
```

### `interval_secs`

**Optional. Default: `15`.**

How often (in seconds) the background gossip loop fires and pushes CRDT deltas to peers. Lower values reduce replication lag at the cost of more network traffic.

```toml
interval_secs = 15
```

### `tombstone_ttl_secs`

**Optional. Default: `604800` (7 days).**

How long tombstone records are retained in the CRDT before they are garbage-collected. Tombstones must be retained long enough to ensure every peer in the cluster has received the deletion before the record is purged.

```toml
tombstone_ttl_secs = 604800
```

### `ownership_ttl_secs`

**Optional. Default: `150`.**

Lease duration in seconds for write-ownership of orders and MTC entries. Each node refreshes its ownership lease every gossip round. When a lease expires (the owning node has been silent for `ownership_ttl_secs`), another node may take over.

```toml
ownership_ttl_secs = 150
```

### `gossip_envelope_max_age_secs`

**Optional. Default: `300` (5 minutes).**

Maximum age in seconds of a gossip envelope. Envelopes timestamped more than this many seconds in the past are rejected as potential replays.

```toml
gossip_envelope_max_age_secs = 300
```

### `clock_skew_tolerance_secs`

**Optional. Default: `30`.**

Maximum acceptable clock difference between cluster nodes in seconds. Gossip envelopes timestamped more than this many seconds in the *future* are rejected. Ensure NTP synchronisation across all cluster members keeps skew well below this threshold.

```toml
clock_skew_tolerance_secs = 30
```

### `fan_out`

**Optional. Default: `0` (contact all peers).**

Maximum number of peers contacted per gossip round. When set to a positive integer, only that many peers are selected at random each round; this reduces O(N²) gossip overhead in clusters larger than roughly five nodes while convergence still occurs transitively in O(log_k(N)) rounds. Set to `0` to contact all configured peers every round.

```toml
fan_out = 3   # recommended for clusters of 5+ nodes
```

---

## `[profiles]`

The `[profiles]` section configures the certificate profile subsystem. Profiles are loaded from one or more *providers* at startup, cached in memory, and refreshed periodically by a background task. `Akāmu`'s own CA always signs; profiles only control which extensions are included and with what values. When no providers are configured, every order falls back to CA defaults (`digitalSignature` KeyUsage, `serverAuth` EKU, and the `[ca]` validity/URL settings).

When at least one provider is configured and a `newOrder` request omits the `profile` field, the server checks whether a profile named `"default"` exists in the registry. If it does, `"default"` is applied automatically and echoed back in the order response. If no `"default"` profile exists, the order falls back to the CA's built-in defaults.

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

*Kerberos / UPN SAN injection*

| Key | Default | Description |
|-----|---------|-------------|
| `kpn_san_templates` | `[]` | KPN SAN templates expanded against the order's DNS SANs at issuance. `{dns}` is replaced with each DNS SAN. Syntax: `"HTTP/{dns}@REALM"` produces an NT-SRV-HST(3) KPN; `"{dns}@REALM"` produces an NT-PRINCIPAL(1) KPN. Templates without `{dns}` are injected once (static). |
| `ms_upn_san_template` | absent | MS-UPN SAN template (OID `1.3.6.1.4.1.311.20.2.3`). `{dns}` is replaced with the first DNS SAN from the CSR. Use a literal value for a static UPN. |
| `inject_account_kpn` | `false` | When `true`, inject the account's stored Kerberos principal (copied from the EAB `bound_principal` at registration) as a KRB5PrincipalName OtherName SAN. |

*Certificate format*

| Key | Default | Description |
|-----|---------|-------------|
| `issue_as` | absent / `"x509"` | Set to `"mtc"` to issue a Merkle Tree Certificate standalone certificate instead of a PEM chain. Requires `[mtc]` to be enabled. The standalone certificate is a standard X.509 v3 `Certificate` where `signatureAlgorithm` is `id-alg-mtcProof` (OID `1.3.6.1.4.1.44363.47.0`, experimental pre-IANA) and `signatureValue` carries a TLS-encoded `MTCProof`. Per draft-04 §4.3, `MTCProof` contains a leading `extensions` field (uint16 length-prefixed; empty = `\x00\x00`), `start`/`end` as uint48 (6-byte big-endian), and a uint8-prefixed `cosigner_id` in each `MtcSignature`. The OID will change when the draft is published as an RFC. |

*Per-profile authorization*

| Key | Default | Description |
|-----|---------|-------------|
| `allowed_identifiers` | `[]` | List of regex patterns. Each order identifier is matched as `"type:value"` (e.g. `"dns:example.com"`). Empty = no restriction. |
| `identifier_match` | `"all"` | `"all"`: every identifier must match a pattern. `"any"`: at least one identifier must match. Ignored when `allowed_identifiers` is empty. |
| `auth_hook` | absent | Path to an external executable. Receives JSON on stdin; exit 0 = permit, non-zero = deny. |
| `auth_hook_timeout_secs` | `30` | Seconds to wait for the hook before denying. |
| `require_account_grant` | `false` | When `true`, the account must have this profile's name in its `profile_grants` attribute (set via the Admin API or inherited from its EAB key). |

*tkauth-01 JWKS trust*

| Key | Default | Description |
|-----|---------|-------------|
| `trust_jwks_urls` | `[]` | List of HTTPS or `http+unix://` URLs of JWKS endpoints trusted for `kid`-signed authority tokens (RFC 9447 tkauth-01). Only meaningful when `[tkauth]` is enabled. When empty, `kid`-signed tokens are rejected for this profile. |

The `http+unix://` form allows co-located Token Authorities (for example, an Ekishib IdP on the same host) to be reached without a network port. Encode the socket path with `/` as `%2F`:

```toml
[profiles.providers.local.profiles.kerberos-svc]
description     = "Kerberos service certificate"
ca_ids          = ["kerberos-ca"]
trust_jwks_urls = [
    "https://idp.example.com/jwks",
    "http+unix://%2Frun%2Fekishib%2Fekishib.sock/jwks",
]
```

JWKS responses are cached in memory for 5 minutes and refreshed independently per URL.

See [Certificate Profiles](profiles.md) for detailed descriptions with examples.

---

## `[admin]`

The `[admin]` section enables the server-side Admin API. Admin endpoints (`/admin/*`) are served on the same listener as the main ACME API — there is no separate admin listener. When this section is absent, all admin endpoints return 404. This is the default; no admin access is possible without explicit configuration.

Operator authentication uses one or more of:

- **mTLS client certificates** — configure `[tls.client_auth]` with `required = false` and the operator CA(s); the connecting client presents a certificate signed by one of those CAs.
- **Proxy-forwarded client certificates** — when Akamu runs behind a TLS-terminating reverse proxy (Nginx, Apache, Envoy), configure `[admin.proxy_auth]` so the proxy can forward the verified client certificate in an HTTP header.
- **GSSAPI/Kerberos** — configure `[admin.gssapi]`; clients authenticate via a Kerberos service ticket without requiring a client certificate.

At least one of `[tls.client_auth]`, `[admin.proxy_auth]`, or `[admin.gssapi]` must be configured; the server exits at startup if none is set.

```toml
# mTLS client authentication — operator CA(s) accepted for /admin/* requests.
[tls.client_auth]
ca_files = ["/etc/akamu/operator-ca.pem"]
required = false   # allow GSSAPI-only clients that carry no cert

[admin]
session_ttl_secs = 3600

# Bootstrap operator (mTLS, PEM) — generated and registered on first run when operators table is empty.
# bootstrap_operator_cert_file = "/etc/akamu/admin-bootstrap.pem"
# bootstrap_operator_key_file  = "/etc/akamu/admin-bootstrap-key.pem"

# Bootstrap operator (mTLS, PKCS#12) — alternative to PEM pair above.
# bootstrap_operator_pkcs12_file     = "/etc/akamu/admin-bootstrap.p12"
# bootstrap_operator_pkcs12_password = ""

# Bootstrap operator (GSSAPI) — can be combined with cert bootstrap above.
# When operators table is empty at startup, registers this principal as Administrator.
# bootstrap_operator_gssapi_principal = "admin@EXAMPLE.COM"

# Optional: also accept GSSAPI-authenticated operators
[admin.gssapi]
keytab_file  = "/etc/akamu/http.keytab"   # omit and set gssproxy = true to use gssproxy instead
service_name = "HTTP"
```

### `bootstrap_key_type`

**Optional. Default: `"ec:P-256"`.**

Key algorithm used when auto-generating the bootstrap operator certificate. Same syntax as `ca.key_type`.

```toml
bootstrap_key_type = "ec:P-256"
```

### `bootstrap_operator_cert_file`

**Optional.**

Path where the bootstrap Administrator operator's client certificate will be written on first run. When this file (and `bootstrap_operator_key_file`) are absent and the operators table is empty, Akāmu generates a client certificate signed by the Akāmu CA and registers the operator automatically. Both fields must be set together. Mutually exclusive with `bootstrap_operator_pkcs12_file`.

```toml
bootstrap_operator_cert_file = "/etc/akamu/admin-bootstrap.pem"
```

### `bootstrap_operator_key_file`

**Optional.**

Path where the bootstrap Administrator operator's client private key will be written on first run. Must be set alongside `bootstrap_operator_cert_file`. Mutually exclusive with `bootstrap_operator_pkcs12_file`.

```toml
bootstrap_operator_key_file = "/etc/akamu/admin-bootstrap-key.pem"
```

### `bootstrap_operator_pkcs12_file`

**Optional.**

PKCS#12 / PFX file for the bootstrap Administrator operator's client certificate and private key. When set and the file is absent and the operators table is empty, Akāmu generates a client certificate and key, bundles them into a PKCS#12 file, and registers the operator automatically. Mutually exclusive with `bootstrap_operator_cert_file` / `bootstrap_operator_key_file`.

```toml
bootstrap_operator_pkcs12_file = "/etc/akamu/admin-bootstrap.p12"
```

### `bootstrap_operator_pkcs12_password`

**Optional. Default: `""` (empty string).**

Password for the PKCS#12 bundle written by `bootstrap_operator_pkcs12_file`. The key is still encrypted with PBES2/AES-256-CBC even with an empty password — leave the password field blank or press Enter when tools prompt for it.

```toml
bootstrap_operator_pkcs12_password = ""
```

### `bootstrap_operator_name`

**Optional. Default: `"admin"`.**

Name recorded in the operators table for the auto-provisioned bootstrap administrator. This value is also used as the Common Name (CN) in the bootstrap client certificate's Subject DN, and determines the SubjectAltName (SAN) extension added to the certificate.

The value may carry an optional type prefix to select the SAN type:

| Prefix | SAN type | Example |
|--------|----------|---------|
| *(none)* | `directoryName` (copy of Subject DN) | `admin` |
| `dn:` | `directoryName` (copy of Subject DN) | `dn:Operator` |
| `dns:` | `dNSName` | `dns:admin.example.com` |
| `email:` | `rfc822Name` | `email:admin@example.com` |
| `ip:` | `iPAddress` | `ip:192.168.1.1` |
| `uri:` | `uniformResourceIdentifier` | `uri:https://example.com/admin` |

When a prefix is present, the portion after the colon is used as the CN. A bare name (no prefix) defaults to a `directoryName` SAN built from the Subject DN.

```toml
# Bare name — CN="admin", SAN=directoryName (default)
bootstrap_operator_name = "admin"

# DNS SAN — CN="admin.example.com", SAN=dNSName
# bootstrap_operator_name = "dns:admin.example.com"

# Email SAN — CN="admin@example.com", SAN=rfc822Name
# bootstrap_operator_name = "email:admin@example.com"
```

### `bootstrap_operator_gssapi_principal`

**Optional. Default: unset.**

Kerberos principal for the GSSAPI bootstrap Administrator operator (e.g. `"admin@REALM"`). When set and no certificate bootstrap is configured, Akāmu inserts an Administrator row with this principal at startup (if the operators table is empty) so that the first `akamuctl login --gssapi` succeeds without a prior `akamuctl operator add`.

When set alongside `bootstrap_operator_pkcs12_file` or `bootstrap_operator_cert_file` / `bootstrap_operator_key_file`, the principal is stored on the same bootstrapped operator row so that the operator can authenticate via either mTLS or GSSAPI.

```toml
bootstrap_operator_gssapi_principal = "admin@EXAMPLE.COM"
```

### `auth_rate_limit`

**Optional. Default: `20`.**

Maximum credential presentations (Bearer session token, mTLS client certificate, or GSSAPI token) accepted from a single source IP in a rolling 5-minute window before that source receives `429 Too Many Requests`. This limits audit-event floods that could otherwise trigger the `audit_alarm_action` or, when `audit_overflow = "halt"`, refuse all new requests.

```toml
auth_rate_limit = 20
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

### `audit_max_events`

**Optional. Default: absent (unlimited). Backward-compatible alias: `audit_max_rows`.**

Maximum number of audit events since startup before the `audit_overflow` policy triggers. Audit events are written to the configured audit backend (systemd journal namespace, JSONL file, or in-process store), not to the database. The counter is in-memory and resets on restart. The audit backend manages its own disk retention independently (see `contrib/systemd/journald@akamu.conf` for journald, or external `logrotate(8)` for the file backend).

Negative values are treated as unlimited (with a startup warning). Zero is also treated as unlimited.

```toml
audit_max_events = 500000
```

### `audit_overflow`

**Optional. Default: `"drop_oldest"`.**

Policy applied when `audit_max_events` is reached. Accepted values:

| Value | Behaviour |
|-------|-----------|
| `"drop_oldest"` | Continue recording events; journald manages its own retention (default). This is effectively a no-op. |
| `"halt"` | Refuse new requests until the server is restarted. |

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

**Required when `gssproxy = false` (the default). Must be absent when `gssproxy = true`.**
Path to the Kerberos keytab file for the admin service principal. The akamu
process must be able to read this file; no other user should have read access
to it. Setting both `keytab_file` and `gssproxy = true` is a configuration
error; the server exits at startup.

```toml
keytab_file = "/etc/akamu/http.keytab"
```

#### `gssproxy`

**Optional. Default: `false`.**

When `true`, GSSAPI credential acquisition for the admin service principal is
delegated to the [gssproxy](https://github.com/gssapi/gssproxy) daemon. The
akamu process must have a matching entry in `/etc/gssproxy/conf.d/`. The server
sets `GSS_USE_PROXY=yes` in its environment before the first GSSAPI call. No
direct access to a keytab file on disk is needed. `keytab_file` must be absent
when this is `true`.

```toml
# gssproxy mode for the admin interface
[admin.gssapi]
gssproxy     = true
service_name = "HTTP"
```

#### `service_name`

**Optional. Default: `"HTTP"`.**

Host-based service name. MIT Kerberos appends `@<local-hostname>` when no realm is specified.

```toml
service_name = "HTTP"
```

### `[admin.proxy_auth]`

**Optional. When absent, proxy-forwarded client certificate authentication is disabled.**

When Akamu runs behind a TLS-terminating reverse proxy, the TLS handshake
happens at the proxy and the client certificate never reaches Akamu's TLS
accept loop. This section configures Akamu to read the client certificate
from an HTTP header injected by the proxy, gated on a trusted-proxy CIDR
list to prevent header spoofing.

Three header conventions are supported:

| `header_format` | Header name | Cert encoding |
|-----------------|-------------|---------------|
| `"x-ssl-client-cert"` *(default)* | `X-SSL-Client-Cert` | URL-encoded PEM |
| `"ssl-client-cert"` | `SSL_CLIENT_CERT` | URL-encoded PEM |
| `"xfcc"` | `X-Forwarded-Client-Cert` | Envoy XFCC format; `Cert=` value is URL-encoded PEM |

```toml
[admin.proxy_auth]
# Trusted proxies (required, must be non-empty).
# Accepts CIDR ranges and the literal "local addresses" (all local IPs).
trusted_proxies = ["127.0.0.1/32", "::1/128"]

# Or when the proxy runs on the same host:
# trusted_proxies = ["local addresses"]

# Header convention: "x-ssl-client-cert" | "ssl-client-cert" | "xfcc"
# Default: "x-ssl-client-cert"
header_format = "x-ssl-client-cert"
```

**Security:** the proxy-forwarded certificate header is only read when the
TCP peer address falls within one of the `trusted_proxies` ranges. Requests
from untrusted IPs that include the header silently ignore it — the header
is never parsed. Proxy-forwarded cert auth records `"method":"cert-proxy"`
in audit events, distinguishing it from direct mTLS (`"method":"cert"`).

#### `trusted_proxies`

**Required when `[admin.proxy_auth]` is present.**

List of reverse proxies allowed to inject the client certificate header.
Must be non-empty. Each entry is either a CIDR range or the literal
`"local addresses"` (all local interface IPs, refreshed every 30 seconds).

```toml
trusted_proxies = ["10.0.0.1/32", "fd00::/8"]

# Or when the proxy runs on the same host:
# trusted_proxies = ["local addresses"]
```

#### `header_format`

**Optional. Default: `"x-ssl-client-cert"`.**

Selects which HTTP header to read and how to parse it.

- `"x-ssl-client-cert"` — Nginx convention. The proxy sets `X-SSL-Client-Cert`
  to the URL-encoded PEM of the client certificate.
- `"ssl-client-cert"` — Apache convention. The proxy sets `SSL_CLIENT_CERT`
  to the URL-encoded PEM of the client certificate.
- `"xfcc"` — Envoy convention. The proxy sets `X-Forwarded-Client-Cert`
  to a semicolon-separated key-value list. Akamu extracts the `Cert=` value
  from the last element (nearest proxy) and URL-decodes it as PEM.

##### Nginx example

```nginx
server {
    listen 443 ssl;
    ssl_client_certificate /etc/nginx/operator-ca.pem;
    ssl_verify_client optional;

    location /admin/ {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-SSL-Client-Cert $ssl_client_escaped_cert;
    }
}
```

```toml
[admin.proxy_auth]
trusted_proxies = ["127.0.0.1/32"]
header_format   = "x-ssl-client-cert"
```

##### Envoy example

Envoy sets `X-Forwarded-Client-Cert` automatically when `forward_client_cert_details`
is set to `APPEND_FORWARD` or `SANITIZE_SET` in the HTTP connection manager.

```toml
[admin.proxy_auth]
trusted_proxies = ["10.0.0.0/8"]
header_format   = "xfcc"
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
| `GET` | `/admin/cas` | Y | Y | | |
| `GET` | `/admin/cas/{id}` | Y | Y | | |
| `GET` | `/admin/cas/{id}/cert` | Y | Y | | |
| `POST` | `/admin/ca/{id}/crl/force` | Y | Y | | |
| `POST` | `/admin/ca/{id}/cross-sign` | Y | Y | | |
| `GET` | `/admin/cross-certs` | Y | Y | | Y |
| `GET` | `/admin/cross-certs/{id}` | Y | Y | | Y |
| `GET` | `/admin/delegations` | Y | Y | Y | Y |
| `POST` | `/admin/delegations` | Y | Y | | |
| `GET` | `/admin/delegations/{id}` | Y | Y | Y | Y |
| `PUT` | `/admin/delegations/{id}` | Y | Y | | |
| `DELETE` | `/admin/delegations/{id}` | Y | Y | | |
| `GET` | `/admin/gossip/status` | Y | Y | Y | Y |
| `POST` | `/admin/gossip/register` | Y | | | |
| `POST` | `/admin/tkauth/prune-jti` | Y | Y | | |

See [Admin API and Operator Management](admin-api.md) for the full request/response format of each endpoint.

