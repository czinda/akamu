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
path = "/var/lib/akamu/akamu.db"

[ca]
key_file         = "/etc/akamu/ca.key.pem"
cert_file        = "/etc/akamu/ca.cert.pem"
key_type         = "ec:P-256"
hash_alg         = "sha256"
validity_days    = 90
ca_validity_years = 10
common_name      = "Example ACME CA"
organization     = "Example Org"
crl_url          = "http://acme.example.com/crl/ca.crl"
ocsp_url         = "http://ocsp.example.com"

[mtc]
log_path = "/var/lib/akamu/mtc.log"
enabled  = false

[server]
terms_of_service_url   = "https://acme.example.com/tos.html"
website_url            = "https://acme.example.com"
caa_identities         = ["acme.example.com"]
external_account_required = false
order_expiry_secs      = 86400
authz_expiry_secs      = 86400
max_body_bytes         = 65536
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

### `path`

**Required.** Path to the SQLite database file. The file and its WAL journal are created automatically if they do not exist.

```toml
[database]
path = "/var/lib/akamu/akamu.db"
```

Use `:memory:` for an ephemeral in-memory database (useful for testing; all data is lost when the process exits).

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
crl_url = "http://acme.example.com/crl/ca.crl"
```

The server does not serve the CRL itself at this URL. You must arrange for the CRL file to be available at this location separately (for example, by generating it with a custom script or tool that uses the CA key).

### `ocsp_url`

**Optional. Default: absent (no AIA OCSP extension).**

If set, this URL is included in the `AuthorityInfoAccess` (AIA) extension as an OCSP responder URI in every issued end-entity certificate.

```toml
ocsp_url = "http://ocsp.example.com"
```

The server does not implement an OCSP responder. You must run a separate OCSP responder at this URL.

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

List of CA domain names for CAA record verification. When set, these strings appear in the `meta.caaIdentities` field of the directory response. ACME clients that check CAA records will use these values to confirm the CA is authorised to issue for a domain.

```toml
caa_identities = ["acme.example.com"]
```

The server itself does not perform CAA record lookups; it only advertises the list.

### `external_account_required`

**Optional. Default: `false`.**

When `true`, the directory response includes `meta.externalAccountRequired: true`. This signals to ACME clients that they must use External Account Binding (EAB) when creating a new account. The server advertises this requirement but does not currently validate EAB credentials; enforcement must happen at the network or application layer.

```toml
external_account_required = false
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

### `dns_persist_issuer_domain`

**Optional. Default: absent (dns-persist-01 disabled).**

The issuer domain placed in the `issuer-domain-names` field of `dns-persist-01` challenge objects and matched against the first token of TXT records during validation. When this field is set, the server offers `dns-persist-01` as an additional challenge type for all `dns` identifiers. When absent, `dns-persist-01` is not offered and existing clients are unaffected.

See [dns-persist-01 Challenge](dns-persist-01.md) for the full description of the challenge type and TXT record format.

```toml
dns_persist_issuer_domain = "acme.example.com"
```

### `dns_resolver_addr`

**Optional. Default: absent (system resolver).**

Override the DNS resolver used for `dns-01` and `dns-persist-01` challenge validation. Format: `"<ip>:<port>"`. When absent, the system default resolver is used. Useful for split-horizon DNS deployments where the ACME server cannot reach the public resolver, and for integration testing against a local stub server.

```toml
dns_resolver_addr = "127.0.0.1:5353"
```
