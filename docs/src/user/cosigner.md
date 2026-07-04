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
cert_file       = "/var/lib/akamu/cosigner-id.crt"
trust_anchor_id = "1.3.6.1.4.1.44363.47.10.1"

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

Address the daemon binds to. Two forms are accepted:

| Form | Example | Description |
|------|---------|-------------|
| `"host:port"` | `"0.0.0.0:8080"` | TCP socket |
| `"unix:/path"` or `"/path"` | `"unix:/run/akamu/akamu-cosigner.sock"` | Unix domain socket |

```toml
[server]
listen_addr = "0.0.0.0:8443"

# Or, for a Unix domain socket behind a reverse proxy:
# listen_addr = "unix:/run/akamu/akamu-cosigner.sock"
```

The `AKAMU_COSIGNER_LISTEN` environment variable overrides this field:

```
AKAMU_COSIGNER_LISTEN=unix:/run/akamu/akamu-cosigner.sock akamu-cosigner /etc/akamu/cosigner.toml
```

**Constraint:** Unix domain sockets and `[tls]` are mutually exclusive. When `listen_addr` is a Unix path and a `[tls]` section is present (or `[acme_bootstrap]` is configured, which implies TLS), the daemon exits at startup with an error.

**Systemd socket activation:** The provided `akamu-cosigner.socket` unit pre-binds `/run/akamu/akamu-cosigner.sock` (mode `0660`, user/group `akamu-cosigner`). Enable with `systemctl enable --now akamu-cosigner.socket akamu-cosigner.service`. When socket activation is active, `listen_addr` in the config file is ignored — the pre-bound socket is passed via `LISTEN_FDS`.

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

Key algorithm for auto-generation.  Accepts the same values as `[[ca]].key_type` in `akamu`: `"ec:P-256"`, `"ec:P-384"`, `"ec:P-521"`, `"rsa:2048"`, `"rsa:3072"`, `"rsa:4096"`, `"ed25519"`, `"ed448"`.

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

The cosigner identity configuration.  Per draft-ietf-plants-merkle-tree-certs-04 §4.1, `CosignerID` is now `TrustAnchorID ::= OBJECT IDENTIFIER`.  The `trust_anchor_id` OID is embedded in every `SubtreeSignature.cosigner` field so that akamu servers and relying parties can identify which cosigner produced the signature.  The certificate file is retained for cryptographic verification by relying parties.

### `cert_file`

**Required.**  Path to the cosigner-id PEM certificate file.

- If the file exists, it is loaded as the identity certificate.
- If the file is absent and `[acme_bootstrap]` is configured and the bootstrap certificate exists, that certificate is used as the cosigner-id.
- Otherwise, a self-signed certificate is auto-generated from the `[signing_key]` and written to this path.  The self-signed cert uses `base_url`'s hostname as its dNSName SAN and has 10-year validity.

### `trust_anchor_id`

**Required.**  The OID (dotted-decimal) that identifies this cosigner as a `TrustAnchorID`.  This value is embedded in every `SubtreeSignature.cosigner` field.  Operators must agree on this OID with log operators before deploying.  Example: `"1.3.6.1.4.1.44363.47.10.1"`.

```toml
[cosigner_id]
cert_file       = "/var/lib/akamu/cosigner-id.crt"
trust_anchor_id = "1.3.6.1.4.1.44363.47.10.1"
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

The `SubtreeSignature` covers the full checkpoint range `[0, tree_size)` and is signed with the `[signing_key]`.  The `cosigner` field in the response contains the `TrustAnchorID` OID configured in `[cosigner_id].trust_anchor_id`.

### `GET /.well-known/acme-challenge/:token`

Serves http-01 challenge tokens during the ACME bootstrap phase.  Only active while the bootstrap flow is running; this endpoint returns 404 at all other times.

---

## Integrating with akamu

Add a `[[mtc.cosigners]]` entry in the akamu server configuration for each `akamu-cosigner` instance:

```toml
[[mtc.cosigners]]
url                  = "https://cosigner.example.com/sign"
cosigner_id_cert_pem = "/etc/akamu/cosigner-id.crt"
trust_anchor_id      = "1.3.6.1.4.1.44363.47.10.1"   # optional; must match cosigner's [cosigner_id].trust_anchor_id
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

---

## Admin interface

`akamu-cosigner` includes its own admin HTTP listener.  When the `[admin]`
section is present in the configuration file, the daemon starts a second
HTTPS server for operator access.  The admin listener is independent of the
signing endpoint and supports the same mTLS and session-token authentication
model as the main akamu server.

When the `[admin]` section is absent, all admin endpoints return `401 Unauthorized` and a warning is logged at startup.

### Configuration

Add an `[admin]` section and one or more `[[admin.operators]]` entries to
`cosigner.toml`:

```toml
[admin]
listen_addr    = "127.0.0.1:9444"
cert_file      = "/etc/akamu/cosigner-admin-tls.pem"
key_file       = "/etc/akamu/cosigner-admin-tls.key"
ca_certs       = ["/etc/akamu/operator-ca.pem"]
session_ttl_secs = 3600

[[admin.operators]]
name             = "alice"
role             = "administrator"
cert_fingerprint = "a3b4c5…"    # SHA-256 hex of the DER leaf cert

[[admin.operators]]
name             = "bob"
role             = "auditor"
cert_fingerprint = "b2c3d4…"
```

Operators are defined statically in the config file rather than in a database.
Changes to the operator list require a daemon restart.

### `[admin]` fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `listen_addr` | Yes | — | TCP address and port for the admin listener. |
| `cert_file` | Yes | — | PEM file for the admin listener's TLS server certificate. |
| `key_file` | Yes | — | PEM file for the admin listener's TLS private key. |
| `ca_certs` | No | `[]` | PEM CA files whose issued client certificates are accepted as operator credentials. |
| `session_ttl_secs` | No | `3600` | Idle session expiry in seconds. |

### `[[admin.operators]]` fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Human-readable operator name (shown in logs). |
| `role` | Yes | `"administrator"` or `"auditor"`. |
| `cert_fingerprint` | At least one | Lowercase hex SHA-256 of the DER leaf certificate. |
| `gssapi_principal` | At least one | Kerberos principal (reserved for future use). |

### Admin endpoints

| Method | Path | administrator | auditor |
|--------|------|:---:|:---:|
| `POST` | `/admin/session` | Y | Y |
| `DELETE` | `/admin/session` | Y | Y |
| `GET` | `/admin/status` | Y | Y |
| `GET` | `/admin/stats` | Y | Y |
| `GET` | `/admin/config` | Y | |

#### `POST /admin/session`

Authenticate with a client certificate and receive a session token.

**Response `200 OK`:**

```json
{
  "session_token": "a4f1…64-hex-chars…",
  "role": "administrator",
  "expires_at": "2026-05-02T14:00:00Z"
}
```

#### `DELETE /admin/session`

Invalidate the current session token.

**Response: `204 No Content`.**

#### `GET /admin/status`

Liveness check.  All authenticated operators may call this endpoint.

**Response `200 OK`:**

```json
{ "status": "ok", "uptime_secs": 3600 }
```

#### `GET /admin/stats`

Return signing statistics.

**Response `200 OK`:**

```json
{
  "uptime_secs": 3600,
  "checkpoints_signed": 42,
  "last_checkpoint_at": "2026-05-02T13:45:00Z"
}
```

#### `GET /admin/config`

Return a redacted view of the running configuration: operator names, roles, and
session TTL.  Private key material and CA certificate paths are not included.
Requires the `administrator` role.

**Response `200 OK`:**

```json
{
  "operators": [
    { "name": "alice", "role": "administrator" },
    { "name": "bob",   "role": "auditor" }
  ],
  "session_ttl_secs": 3600
}
```

### Querying via akamuctl

The `akamuctl cosigner` subcommands target the cosigner's admin listener.
Configure the connection in the `[cosigner]` section of
`~/.config/akamu/akamuctl.toml`:

```toml
[cosigner]
url       = "https://cosigner.example.com:9444"
ca_cert   = "/etc/akamu/cosigner-admin-ca.pem"
cert_file = "/etc/akamu/operator.pem"
key_file  = "/etc/akamu/operator.key"
```

```bash
akamuctl cosigner status
akamuctl cosigner stats
```

See [akamuctl — Cosigner administration](akamuctl.md#cosigner-administration)
for the full command reference.

## See also

- [Merkle Tree Certificate Log](mtc.md) — MTC log, checkpoints, and cosigner integration on the server side
- [TLS Configuration](tls.md) — cosigner TLS setup and native TLS modes
