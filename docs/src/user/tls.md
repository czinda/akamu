# TLS Configuration

By default Akāmu listens on a plain TCP socket and relies on an upstream reverse proxy
(nginx, Caddy, HAProxy, …) for TLS termination.  If you want a fully self-contained
deployment without a proxy, set `[tls] enabled = true` and Akāmu will accept HTTPS
connections directly.

Backward compatibility is strict: deployments without a `[tls]` section in
`config.toml` see zero behavior change.

---

## When to use native TLS vs. a reverse proxy

| Scenario | Recommendation |
|----------|----------------|
| Single-host lab / development | Native TLS — fewer moving parts |
| High-traffic or load-balanced production | Reverse proxy — better performance, centralized cert management |
| Mutual-TLS client authentication | Native TLS — the proxy would need to forward raw TLS which most do not |
| Post-quantum hybrid mTLS | Native TLS — composite ML-DSA schemes require direct OpenSSL integration |

---

## Minimal configuration

```toml
[tls]
enabled   = true
cert_file = "/etc/akamu/server.crt"   # PEM chain: leaf cert first, then intermediates/CA
key_file  = "/etc/akamu/server.key"   # PEM private key (PKCS#8 or SEC1, unencrypted)
```

If both `cert_file` and `key_file` are **absent** when the server starts, Akāmu
auto-generates a server certificate signed by the Akāmu CA and writes both files.
This makes the first-run experience zero-configuration: any client that already
trusts the Akāmu CA will also trust the TLS channel.

If only one of the two files exists, startup fails with an explicit error.

---

## Certificate and key format

- **cert_file**: PEM file with one or more `-----BEGIN CERTIFICATE-----` blocks.
  The leaf certificate must come first; intermediate and root certificates follow
  in order.  When Akāmu generates the file it writes `<leaf>\n<CA>` automatically.

- **key_file**: PEM file with a single private key — `-----BEGIN PRIVATE KEY-----`
  (PKCS#8) or `-----BEGIN EC PRIVATE KEY-----` (SEC1).  The file must be
  unencrypted (no passphrase).  Akāmu never reads an encrypted key file.

---

## Full `[tls]` field reference

```toml
[tls]
# Whether to enable native TLS.  Default: false.
enabled = true

# PEM file with the server certificate chain (leaf first).
cert_file = "/etc/akamu/server.crt"

# PEM file with the server private key (unencrypted PKCS#8 or SEC1).
key_file = "/etc/akamu/server.key"

# TLS protocol versions to accept.  Default: ["TLSv1.2", "TLSv1.3"].
protocols = ["TLSv1.3"]

# Hostname placed in CN and SAN of the auto-generated server certificate.
# Only used when cert_file/key_file are both absent.  Default: "localhost".
server_name = "akamu.internal"

# Key algorithm for the auto-generated server certificate.
# Accepted values: "ec:P-256", "ec:P-384", "ec:P-521",
#                  "rsa:2048", "rsa:3072", "rsa:4096", "ed25519".
# Default: "ec:P-256".
bootstrap_key_type = "ec:P-256"
```

---

## Mutual TLS client certificate authentication

`[tls.client_auth]` enables mTLS: Akāmu requests a client certificate and validates
the chain against a configurable set of trusted CAs.

```toml
[tls.client_auth]
# Reject connections that present no client certificate.  Default: false.
required = true

# PEM files containing trusted root CA certificates.
# Each file may contain multiple PEM blocks.
ca_files = [
    "/etc/akamu/client-ca.crt",
]

# Validation profile: "webpki" (CAB Forum) or "rfc5280".  Default: "webpki".
profile = "webpki"

# Allow ML-DSA / composite post-quantum algorithms in client cert chains.
# Default: false.
allow_post_quantum = false

# Maximum certificate chain depth (leaf not counted).  Default: 8.
max_chain_depth = 8

# Minimum RSA modulus size in bits.  Default: 2048.
minimum_rsa_modulus = 2048
```

### `profile` — CAB Forum vs RFC 5280

| Setting | Behaviour |
|---------|-----------|
| `"webpki"` | CAB Forum / Web PKI profile enforced by `synta-x509-verification`. Rejects certificates that violate Baseline Requirements (e.g. missing SAN, weak key). Suitable for publicly-trusted client CAs. |
| `"rfc5280"` | Strict RFC 5280 profile. More permissive than WebPKI on some extensions; suitable for enterprise or private PKI that does not follow CAB Forum rules. |

### Post-quantum support (`allow_post_quantum = true`)

When enabled, Akāmu accepts:

- **Pure ML-DSA certificate chains**: verified by `synta-x509-verification` using
  the OpenSSL backend (pqc-prs fork).
- **Composite ML-DSA+classical TLS 1.3 `CertificateVerify` signatures**: provisional
  code points from draft-ietf-lamps-pq-composite-sigs are advertised and verified
  via the OpenSSL EVP interface.

Classical verification is always performed via the ring crypto provider.
TLS 1.2 `CertificateVerify` always uses classical ring verification — composite
schemes are TLS 1.3 only and never appear in a TLS 1.2 handshake.

---

## Full annotated example with mTLS

```toml
[server]
listen_addr = "0.0.0.0:8443"
base_url    = "https://akamu.internal:8443"

[tls]
enabled             = true
cert_file           = "/etc/akamu/server.crt"
key_file            = "/etc/akamu/server.key"
protocols           = ["TLSv1.3"]
server_name         = "akamu.internal"
bootstrap_key_type  = "ec:P-384"

[tls.client_auth]
required           = true
ca_files           = ["/etc/akamu/client-ca.crt", "/etc/akamu/sub-ca.crt"]
profile            = "rfc5280"
allow_post_quantum = true
max_chain_depth    = 5
minimum_rsa_modulus = 3072
```

---

## Known limitations

- **Composite scheme code points** (`src/tls/schemes.rs`) are taken from the
  provisional IANA allocations in draft-ietf-lamps-pq-composite-sigs.  They must
  be verified against the current draft version before deploying to production;
  if the draft advances and code points change, only that file needs updating.

- **Composite OpenSSL binding**: composite ML-DSA+classical `CertificateVerify`
  verification relies on the pqc-prs OpenSSL fork exposing composite NIDs via
  `PKey::public_key_from_der`.  If those NIDs are not yet in the Rust binding
  layer, the function will return an OpenSSL error at runtime.  The fix is to add
  composite NID support to the Rust openssl bindings in the pqc-prs fork, not to
  Akāmu itself.

- **Pure ML-DSA TLS `SignatureScheme` code points**: no IANA code points exist yet
  for standalone ML-DSA (non-composite) TLS schemes.  Even with
  `allow_post_quantum = true`, only composite schemes are advertised.

- **Client remote address**: when native TLS is active, handlers can extract the
  client's remote address via `axum::extract::ConnectInfo<SocketAddr>` — this is
  available because the server is started with
  `into_make_service_with_connect_info::<SocketAddr>()`.

---

## Troubleshooting

| Error | Likely cause |
|-------|--------------|
| `TLS cert file 'X' contains no PEM blocks` | Wrong file path, or file is DER-encoded (convert to PEM first) |
| `TLS cert and key must both be present or both absent` | One file exists but the other does not; either supply both or remove both |
| `build client-auth trust store: …` | A CA PEM file is malformed or contains non-certificate data |
| `client cert verification failed: …` | Client presented a cert that does not chain to the configured CA, has expired, or violates the chosen profile |
| `composite signature verification failed: …` | pqc-prs OpenSSL fork does not expose the composite NID for the scheme used; see Known Limitations |
| `TLS versions: …` | `protocols` list contains an unsupported value; use `"TLSv1.2"` and/or `"TLSv1.3"` |
