# MTC Cosigner Daemon

`akamu-cosigner` is a standalone binary that acts as an external MTC (Merkle Tree Certificate) cosigner.  When the main `akamu` server produces a checkpoint, it POSTs the DER-encoded `Checkpoint` to each configured cosigner URL.  `akamu-cosigner` signs the checkpoint with its own key and returns a DER-encoded `SubtreeSignature`.  The signature is then embedded in every `StandaloneCertificate` produced from that checkpoint.

Operators who run an independent MTC log can expose `akamu-cosigner` as a public cosigning service.  Operators who want additional signatures on their own log can run one or more cosigner instances as part of their infrastructure.

## Binary

Build from source:

```bash
cargo build -p akamu-cosigner --release
```

The binary is placed at `target/release/akamu-cosigner`.

Run:

```bash
akamu-cosigner /etc/akamu/cosigner.toml
```

If no argument is given, the daemon looks for `cosigner.toml` in the current working directory.

## Configuration file

`akamu-cosigner` reads a single TOML configuration file.  All sections are described below.

### Complete example

```toml
[server]
listen_addr = "0.0.0.0:8080"
base_url    = "https://cosigner.example.com"

[tls]
cert_file = "/etc/akamu/cosigner-tls.crt"
key_file  = "/etc/akamu/cosigner-tls.key"

[signing_key]
key_file = "/var/lib/akamu/cosigner-signing.key"
key_type = "ec:P-256"
hash_alg = "sha256"

[cosigner_id]
cert_file = "/var/lib/akamu/cosigner-id.crt"

[acme_bootstrap]
server_url    = "https://acme.example.com/acme/directory"
account_email = "ops@example.com"
eab_kid       = "my-eab-key-id"
eab_hmac      = "c2VjcmV0LWhtYWMta2V5LWJ1ZmZlcg"
domain        = "cosigner.example.com"
challenge_type = "http-01"
cert_file     = "/var/lib/akamu/cosigner-tls.crt"
key_file      = "/var/lib/akamu/cosigner-tls.key"
```

---

## `[server]`

### `listen_addr`

**Optional. Default: `"0.0.0.0:8080"`.**

TCP address and port the daemon binds to.

```toml
[server]
listen_addr = "0.0.0.0:8443"
```

### `base_url`

**Required.**

Public HTTPS base URL of the cosigner.  Used as the dNSName SAN when auto-generating the self-signed cosigner-id certificate.

```toml
[server]
base_url = "https://cosigner.example.com"
```

---

## `[tls]`

**Optional.**  When present, the daemon serves HTTPS using the given certificate and key.  When absent, the daemon listens on plain HTTP — only suitable behind a TLS-terminating reverse proxy.

When `[acme_bootstrap]` is configured and the `[tls]` section is absent, the daemon derives TLS configuration from the ACME-issued certificate and key paths specified in `[acme_bootstrap]`.

### `cert_file`

**Required within `[tls]`.** Path to the TLS server certificate PEM file (leaf + chain).

### `key_file`

**Required within `[tls]`.** Path to the TLS server private key PEM file.

```toml
[tls]
cert_file = "/etc/akamu/cosigner-tls.crt"
key_file  = "/etc/akamu/cosigner-tls.key"
```

---

## `[signing_key]`

The MTC signing key.  This key **must** be distinct from any TLS certificate key.  Its public half is embedded in the cosigner-id certificate so that relying parties can verify the `SubtreeSignature`.

### `key_file`

**Required.**  Path to the signing key PEM file.  If the file does not exist, a new key of `key_type` is generated and written here on startup.

### `key_type`

**Optional. Default: `"ec:P-256"`.**

Key algorithm for auto-generation.  Accepts the same values as `[ca].key_type` in `akamu`: `"ec:P-256"`, `"ec:P-384"`, `"ec:P-521"`, `"rsa:2048"`, `"rsa:3072"`, `"rsa:4096"`, `"ed25519"`.

### `hash_alg`

**Optional. Default: `"sha256"`.**

Hash algorithm for ECDSA/RSA signing: `"sha256"`, `"sha384"`, `"sha512"`.  Ignored for EdDSA keys.

```toml
[signing_key]
key_file = "/var/lib/akamu/cosigner-signing.key"
key_type = "ec:P-256"
hash_alg = "sha256"
```

---

## `[cosigner_id]`

The cosigner identity certificate.  Its issuer Name and serial number are embedded in every `SubtreeSignature.cosigner` field so that akamu servers and relying parties can identify which cosigner produced the signature.

### `cert_file`

**Required.**  Path to the cosigner-id PEM certificate file.

- If the file exists, it is loaded as the identity certificate.
- If the file is absent and `[acme_bootstrap]` is configured and the bootstrap certificate exists, that certificate is used as the cosigner-id.
- Otherwise, a self-signed certificate is auto-generated from the `[signing_key]` and written to this path.  The self-signed cert uses `base_url`'s hostname as its dNSName SAN and has 10-year validity.

```toml
[cosigner_id]
cert_file = "/var/lib/akamu/cosigner-id.crt"
```

---

## `[acme_bootstrap]`

**Optional.**  When present, `akamu-cosigner` uses `akamu-client` to obtain a certificate from the configured ACME server at startup (if the certificate is absent or expiring within 30 days).  The issued certificate is used as both the TLS server certificate and the source of the cosigner-id.

### `server_url`

**Required.**  ACME server directory URL, e.g. `"https://acme.example.com/acme/directory"`.

### `account_email`

**Optional.**  Contact e-mail for the ACME account.  The `mailto:` prefix is added automatically.

### `eab_kid`

**Required.**  External Account Binding key identifier provisioned by the CA.

### `eab_hmac`

**Required.**  EAB HMAC key, base64url-encoded without padding.

### `domain`

**Required.**  DNS name to certify.  Must be publicly resolvable for the chosen challenge type.

### `challenge_type`

**Optional. Default: `"http-01"`.**

ACME challenge type to use: `"http-01"`, `"dns-01"`, `"dns-persist-01"`, or `"tls-alpn-01"`.

### `dns_hook`

**Optional.**  Shell command invoked for `dns-01` DNS provisioning.  Called with `ACME_DOMAIN` and `ACME_TXT_VALUE` environment variables set.  An exit code of 0 indicates the record was provisioned.  When absent and `challenge_type = "dns-01"`, the daemon logs the required TXT record and exits with an error — the operator must set the record manually and restart.

### `dns_persist_hook`

**Optional.**  Shell command invoked for `dns-persist-01` DNS provisioning.  Called with the following environment variables:

| Variable | Value |
|---|---|
| `ACME_DOMAIN` | The domain being certified |
| `ACME_TXT_NAME` | Full record name, e.g. `_validation-persist.example.com` |
| `ACME_TXT_VALUE` | Full record value, e.g. `"acme.example.com; accounturi=https://…"` |
| `ACME_ACCOUNT_URI` | The ACME account URI |
| `ACME_ISSUER_DOMAIN` | The issuer domain from the challenge |

An exit code of 0 indicates the record was provisioned.

### `cert_file`

**Required.**  Where to write the issued certificate PEM chain.

### `key_file`

**Required.**  Where to write the private key PEM for the issued certificate.

### `csr_key_type`

**Optional. Default: `"ec:P-256"`.**

Key type for the ACME CSR key.  Accepts the same values as `[signing_key].key_type`.

```toml
[acme_bootstrap]
server_url     = "https://acme.example.com/acme/directory"
account_email  = "ops@example.com"
eab_kid        = "my-eab-key-id"
eab_hmac       = "c2VjcmV0LWhtYWMta2V5LWJ1ZmZlcg"
domain         = "cosigner.example.com"
challenge_type = "http-01"
cert_file      = "/var/lib/akamu/cosigner-tls.crt"
key_file       = "/var/lib/akamu/cosigner-tls.key"
csr_key_type   = "ec:P-256"
```

---

## HTTP endpoints

`akamu-cosigner` exposes the following endpoints:

### `POST /sign`

Accepts a DER-encoded `Checkpoint` (`Content-Type: application/octet-stream`).  Returns a DER-encoded `SubtreeSignature` with HTTP 200.

The `SubtreeSignature` covers the full checkpoint range `[0, tree_size)` and is signed with the `[signing_key]`.  The `cosigner` field in the response contains the issuer and serial extracted from the cosigner-id certificate.

### `GET /.well-known/acme-challenge/:token`

Serves http-01 challenge tokens during the ACME bootstrap phase.  Only active while the bootstrap flow is running; this endpoint returns 404 at all other times.

---

## Integrating with akamu

Add a `[[mtc.cosigners]]` entry in the akamu server configuration for each `akamu-cosigner` instance:

```toml
[[mtc.cosigners]]
url                  = "https://cosigner.example.com/sign"
cosigner_id_cert_pem = "/etc/akamu/cosigner-id.crt"
```

See [Configuration Reference — `[[mtc.cosigners]]`](configuration.md#mtccosigners) for the full field reference.

---

## Startup sequence

On each startup, `akamu-cosigner`:

1. Loads and validates the configuration file.
2. Loads or generates the `[signing_key]`.
3. Runs the ACME bootstrap if `[acme_bootstrap]` is configured and the certificate is absent or expiring within 30 days.
4. Loads or generates the cosigner-id certificate at `[cosigner_id].cert_file`.
5. Starts the HTTP (or HTTPS) server.

The daemon does not persist any state other than the key and certificate files on disk.

## Logging

`akamu-cosigner` uses the `tracing` crate.  Control log verbosity with the `RUST_LOG` environment variable:

```bash
RUST_LOG=info  akamu-cosigner /etc/akamu/cosigner.toml
RUST_LOG=debug akamu-cosigner /etc/akamu/cosigner.toml
```
