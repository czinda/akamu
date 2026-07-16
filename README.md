# Akāmu — ACME Certificate Authority

Akāmu is a self-hosted [ACME (RFC 8555)](https://www.rfc-editor.org/rfc/rfc8555) certificate
authority written in Rust.  The name is Akkadian for *mist* or *dust cloud* — fitting for a
server that issues a myriad of certificates.  It is designed for deployment inside private
networks or behind a reverse proxy, and works with any standards-compliant ACME client
(certbot, acme.sh, Caddy, etc.).

**License:** GPL-3.0-or-later

---

## Features

- **Full RFC 8555 ACME v2** — accounts, orders, authorizations, challenges, revocation
- **Challenge types:** `http-01`, `dns-01`, `tls-alpn-01`, `dns-persist-01`, `onion-csr-01`
- **Post-quantum account keys** — ML-DSA-44 / 65 / 87 (FIPS 204, draft-ietf-cose-dilithium-11)
- **HSM / PKCS#11 CA keys** — load the CA private key from a hardware security module via a
  `pkcs11:` URI; key material never leaves the token
- **Multi-backend database** — SQLite (default), PostgreSQL, MariaDB/MySQL
- **Short-Term Automatic Renewal (STAR)** — RFC 8739 rolling certificates with a cancel endpoint
- **Renewal Information (ARI)** — RFC 9773 renewal windows and certificate replacement
- **Tor `.onion` domains** — RFC 9799 `onion-csr-01` validation
- **CAA enforcement** — RFC 8659 + RFC 8657 `accounturi` and `validationmethods` extensions
- **Subdomain authorization** — RFC 9444 ancestor-domain reuse
- **IP identifier validation** — RFC 8738 IPv4/IPv6 certificates
- **Merkle Tree Certificate (MTC) transparency** — append-only on-disk transparency log with client-side query and inclusion proof verification
- **Optional server TLS + mTLS** — rustls, post-quantum composite client certificates
- **Certificate profiles** — draft-aaron-acme-profiles-01 named profiles
- **External Account Binding (EAB)** — single-use HMAC-based account provisioning

---

## Workspace

| Crate | Description |
|-------|-------------|
| `akamu` | ACME server binary |
| `akamu-jose` | JWK / JWS / thumbprint primitives (RFC 7517/7515, ML-DSA) |
| `akamu-client` | Async ACME client library (tokio + hyper) with MTC log query and verification |
| `akamu-cli` | Command-line ACME client (`akamu-cli`) with MTC transparency log subcommands |
| `akamu-mtc-validator` | MTC test vector validation tool (draft-ietf-plants-merkle-tree-certs-05 compliance) |

---

## Quick Start

### 1. Build

```bash
cargo build --release
```

Enable additional database backends via features:

```bash
cargo build --release --features backend-postgres
cargo build --release --features backend-mariadb
```

### 2. Configure

Create `/etc/akamu/config.toml`:

```toml
listen_addr = "0.0.0.0:8080"
base_url    = "https://acme.example.com"

[database]
url = "sqlite:///var/lib/akamu/akamu.db"

[ca]
key_file  = "/etc/akamu/ca.key.pem"
cert_file = "/etc/akamu/ca.cert.pem"

[mtc]
log_path = "/var/lib/akamu/mtc.log"
enabled  = false
```

On first run, the CA private key and self-signed certificate are auto-generated if the files do
not exist.

### 3. Run

```bash
akamu /etc/akamu/config.toml
```

```bash
# Verify
curl https://acme.example.com/acme/directory
```

### 4. Trust the CA

```bash
sudo cp /etc/akamu/ca.cert.pem /usr/local/share/ca-certificates/akamu-ca.crt
sudo update-ca-certificates
```

### 5. Reverse proxy (nginx)

```nginx
server {
    listen 443 ssl;
    server_name acme.example.com;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
    }
}
```

---

## Configuration Reference

All options are documented in [`docs/src/user/configuration.md`](docs/src/user/configuration.md).
The most commonly used sections:

### `[ca]`

| Key | Default | Description |
|-----|---------|-------------|
| `key_file` | — | CA private key PEM path, or a `pkcs11:…` URI for HSM keys |
| `cert_file` | — | CA certificate PEM path (auto-generated on first run) |
| `key_type` | `ec:P-256` | Key algorithm: `ec:P-256/384/521`, `rsa:2048/3072/4096`, `ed25519`, `ml-dsa-44/65/87` |
| `hash_alg` | `sha256` | Signing hash: `sha256`, `sha384`, `sha512` |
| `validity_days` | `90` | Issued certificate lifetime in days |
| `ca_validity_years` | `10` | CA certificate validity |
| `crl_url` | — | CRL Distribution Point URL added to issued certificates |
| `ocsp_url` | — | OCSP responder URL added to issued certificates |

### `[server]` (selected)

| Key | Default | Description |
|-----|---------|-------------|
| `caa_identities` | `[]` | CA domain names for CAA record checking |
| `external_account_required` | `false` | Require EAB on new accounts |
| `order_expiry_secs` | `86400` | Order lifetime |
| `authz_expiry_secs` | `86400` | Authorization lifetime |
| `allow_subdomain_auth` | `false` | Enable RFC 9444 subdomain authorization |
| `tor_connectivity_enabled` | `false` | Offer `http-01`/`tls-alpn-01` for `.onion` domains |
| `dns_resolver_addr` | system | Custom DNS resolver `"ip:port"` |
| `eab_keys` | `{}` | Pre-shared EAB key table: `"kid" = "base64url-key"` |

### `[tls]` (optional)

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Enable server-side TLS |
| `cert_file`, `key_file` | — | TLS certificate chain and private key |
| `[tls.client_auth]` | — | Optional mutual TLS — see docs for full options |

---

## HSM / PKCS#11 CA Keys

Set `key_file` to a `pkcs11:` URI instead of a PEM path:

```toml
[ca]
key_file  = "pkcs11:token=MyHSM;object=ca-key;type=private?pin-value=1234"
cert_file = "/etc/akamu/ca.cert.pem"
```

**OpenSSL backend:** configure `pkcs11-provider` via `OPENSSL_CONF` before starting the server.

**NSS backend:** register the PKCS#11 module in the NSS secmod database via `modutil`.  Both
`token=` and `object=` attributes are required.

See [`docs/src/user/configuration.md`](docs/src/user/configuration.md) for step-by-step setup.

---

## RFC Support

| RFC | Description | Status |
|-----|-------------|--------|
| RFC 8555 | ACME v2 | Full |
| RFC 8659 | CAA DNS Resource Record | Full |
| RFC 8657 | CAA `accounturi` + `validationmethods` | Full |
| RFC 8737 | TLS-ALPN-01 challenge | Full |
| RFC 8738 | IP Identifier Validation | Full |
| RFC 8739 | ACME STAR | Full |
| RFC 9444 | ACME for Subdomains | Full |
| RFC 9773 | ACME Renewal Information (ARI) | Full |
| RFC 9799 | ACME for `.onion` (onion-csr-01) | Full |
| RFC 5280 | X.509 v3 Profile | Full |
| draft-ietf-cose-dilithium-11 | ML-DSA account keys | Full |
| draft-aaron-acme-profiles-01 | Named certificate profiles | Full |

Full compliance table: [`docs/src/user/rfc-support.md`](docs/src/user/rfc-support.md)

---

## Documentation

Build and serve the documentation locally:

```bash
cd docs && mdbook serve
```

Key sections:

- [Introduction](docs/src/introduction.md)
- [Quickstart](docs/src/quickstart/first-run.md)
- [Configuration](docs/src/user/configuration.md)
- [RFC Support](docs/src/user/rfc-support.md)
- [Client Library](docs/src/client/overview.md)
- [Developer Guide](docs/src/developer/architecture.md)

---

## Development

```bash
# Run all tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- config.toml

# Lint
cargo clippy --all-targets

# Format
cargo fmt
```

Local CI:

```bash
contrib/ci/local-ci.sh all
```
