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

## Deployment modes overview

```mermaid
flowchart TD
    A([Akāmu startup]) --> B{"tls section<br/>in config.toml?"}
    B -->|No| C["Mode 1 — Plain HTTP<br/>Bind plain TCP socket<br/>Upstream proxy handles TLS"]
    B -->|Yes, enabled=true| D{"cert_file AND<br/>key_file both exist?"}
    D -->|Neither exists| E["Mode 2 — Auto-generated TLS<br/>Generate server key + cert<br/>signed by Akāmu CA<br/>Write files for next start"]
    D -->|One missing| ERR["Error: both or neither required<br/>startup aborted"]
    D -->|Both exist| F{"tls.client_auth<br/>section present?"}
    F -->|No| G["Mode 3 — Native TLS<br/>Load externally-issued cert + key<br/>Serve HTTPS directly"]
    F -->|Yes| H["Mode 4 — Mutual TLS<br/>Require client certificate<br/>signed by configured CA<br/>Handshake fails for unknown clients"]
    C & E & G & H --> READY([Server ready])

    classDef ok   fill:#f0fdf4,stroke:#16a34a,color:#0f172a
    classDef fail fill:#fef2f2,stroke:#dc2626,color:#0f172a
    class READY ok
    class ERR fail
```

## Deployment walkthroughs

The sections below walk through each of the four supported operating modes in
order of increasing complexity.  Pick the one that matches your environment.

---

### Mode 1 — Plain HTTP behind a reverse proxy

This is the default and requires no `[tls]` section at all.  Akāmu binds to a
plain TCP socket — typically on a loopback or private address — and an upstream
reverse proxy handles HTTPS termination and forwards requests over HTTP.

**`config.toml` (no `[tls]` section)**

```toml
listen_addr = "127.0.0.1:8080"
base_url    = "https://acme.example.com"

[database]
path = "/var/lib/akamu/akamu.db"

[ca]
key_file  = "/etc/akamu/ca.key.pem"
cert_file = "/etc/akamu/ca.cert.pem"

[mtc]
log_path = "/var/lib/akamu/mtc.log"
enabled  = false
```

`base_url` must be the external HTTPS URL that ACME clients use to reach the
directory — not the internal loopback address.  Akāmu embeds this value in every
URL it returns to clients (account URLs, order URLs, certificate download URLs,
etc.).  If `base_url` points at `127.0.0.1` clients will receive unusable URLs.

**nginx example**

```nginx
server {
    listen 443 ssl;
    server_name acme.example.com;

    ssl_certificate     /etc/nginx/tls/acme.example.com.crt;
    ssl_certificate_key /etc/nginx/tls/acme.example.com.key;

    location / {
        proxy_pass         http://127.0.0.1:8080;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
    }
}
```

**Caddy example**

```caddy
acme.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy automatically obtains and renews its own TLS certificate for the public
hostname; no extra TLS configuration is needed on the Akāmu side.

---

### Mode 2 — Native TLS with auto-generated certificate (development / lab)

Use this when you want Akāmu to speak HTTPS directly without a proxy but you
do not yet have an externally-issued certificate.  Akāmu will generate a server
certificate signed by its own CA on first start.

**Step 1.** Add a `[tls]` section with `enabled = true` and supply paths for
`cert_file` and `key_file`.  The files do not need to exist yet.

```toml
listen_addr = "0.0.0.0:8443"
base_url    = "https://akamu.internal:8443"

[tls]
enabled     = true
cert_file   = "/etc/akamu/server.crt"
key_file    = "/etc/akamu/server.key"
server_name = "akamu.internal"
```

`listen_addr` and `base_url` must agree on the port (`8443` here).  `base_url`
is the URL clients will use; `listen_addr` is what the OS socket binds to.
`0.0.0.0` binds on all interfaces; restrict to a specific IP if needed.

**Step 2.** Start Akāmu.  Because `cert_file` and `key_file` are both absent,
the server generates a TLS certificate automatically:

1. A fresh server key is generated using the `bootstrap_key_type` algorithm (default `ec:P-256`).
2. A server certificate for `server_name` is signed by the Akāmu CA.
3. The PEM chain (`leaf + CA`) is written to `cert_file` and the private key to
   `key_file`.

On every subsequent start the existing files are loaded without regeneration.

**Step 3.** Trust the Akāmu CA on the client.  The auto-generated server
certificate chains to the Akāmu CA — the same CA that signs ACME-issued
certificates.  Its PEM is at the path configured in `[ca] cert_file`.  Pass it
to curl with `--cacert`:

```sh
curl --cacert /etc/akamu/ca.cert.pem \
     https://akamu.internal:8443/acme/directory
```

ACME client software (certbot, acme.sh, …) typically has an equivalent option
for specifying a custom CA bundle.

---

### Mode 3 — Native TLS with an externally-issued certificate (production, no proxy)

Use this when ACME clients cannot be pre-configured to trust the Akāmu CA and
a publicly-trusted TLS certificate is required for the ACME endpoint itself.

The Akāmu CA (which signs certificates issued to your ACME clients) is entirely
separate from the TLS server certificate.  Obtaining a public TLS cert for the
ACME server hostname does not affect the CA or the certificates it issues.

**Step 1.** Obtain a certificate for the Akāmu server hostname from a public CA
(Let's Encrypt, ZeroSSL, your organisation's PKI, etc.).  You can use any ACME
client pointed at a public CA — Akāmu itself does not need to be running yet for
this step.

**Step 2.** Place the PEM certificate chain in `cert_file` (leaf first, then
any intermediates) and the unencrypted private key in `key_file`.

**Step 3.** Configure Akāmu:

```toml
listen_addr = "0.0.0.0:8443"
base_url    = "https://acme.example.com:8443"

[tls]
enabled     = true
cert_file   = "/etc/akamu/server.crt"   # publicly-trusted chain, leaf first
key_file    = "/etc/akamu/server.key"   # unencrypted PKCS#8 or EC key
server_name = "acme.example.com"        # used only if cert/key are absent (bootstrap)
```

Because `cert_file` and `key_file` already exist when Akāmu starts, the
bootstrap step is skipped entirely.  `server_name` has no effect at runtime but
is kept as documentation of the hostname and makes the config self-describing.

**Step 4.** When the public certificate is renewed, replace `cert_file` and
`key_file` on disk and restart Akāmu (or send `SIGHUP` if live reload is
supported by your deployment).

---

### Mode 4 — Mutual TLS (mTLS)

Mutual TLS requires every connecting client to present a certificate signed by a
trusted CA.  This is useful for restricting access to the ACME server to known
ACME agents or administrative tooling.

The TLS handshake enforces client authentication before any HTTP request is
processed.  A client that presents no certificate or an untrusted certificate
receives a TLS handshake error — not an ACME-level error response.

**Step 1.** Decide on a client CA.  This can be the Akāmu CA itself (so that
only clients holding Akāmu-issued certificates may connect) or a separate
private CA dedicated to client authentication.  The CA certificate(s) must be
available as PEM files on the Akāmu host.

**Step 2.** Add a `[tls.client_auth]` section.  For a private PKI use
`profile = "rfc5280"` to avoid CAB Forum restrictions that do not apply to
internally-issued certificates.

```toml
listen_addr = "0.0.0.0:8443"
base_url    = "https://akamu.internal:8443"

[tls]
enabled   = true
cert_file = "/etc/akamu/server.crt"
key_file  = "/etc/akamu/server.key"

[tls.client_auth]
required = true
ca_files = ["/etc/akamu/client-ca.crt"]
profile  = "rfc5280"
```

**Step 3.** Test with curl, supplying both a CA bundle for server certificate
verification and a client certificate with its key:

```sh
curl --cacert /etc/akamu/ca.cert.pem \
     --cert   client.crt \
     --key    client.key \
     https://akamu.internal:8443/acme/directory
```

**Step 4.** Understand the failure modes.  When a client connects without a
certificate or with a certificate that does not chain to the configured
`ca_files`, the TLS handshake is aborted.  The client sees a TLS alert (for
example `handshake failure` or `certificate required`), not an HTTP 4xx
response.  Check the Akāmu log for `client cert verification failed: …` to
diagnose chain or profile issues.

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
#                  "rsa:2048", "rsa:3072", "rsa:4096", "ed25519", "ed448".
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

- **Pure ML-DSA certificate chains**: verified via the OpenSSL backend.
- **Composite ML-DSA+classical TLS 1.3 `CertificateVerify` signatures**: provisional
  code points from draft-ietf-lamps-pq-composite-sigs are advertised and verified.

Classical algorithms are always verified using a standard cryptographic backend.
Composite schemes are TLS 1.3 only and never appear in a TLS 1.2 handshake.

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

- **Composite scheme code points**: the composite ML-DSA+classical scheme identifiers
  are taken from the provisional IANA allocations in draft-ietf-lamps-pq-composite-sigs.
  They must be verified against the current draft version before deploying to production;
  if the draft advances and code points change, a code update is required.

- **Composite scheme support depends on the OpenSSL version**: composite ML-DSA+classical
  `CertificateVerify` verification requires OpenSSL 3.5 or later with composite NID support.
  If the installed OpenSSL version does not support the required NIDs, verification will
  return an OpenSSL error at runtime.

- **Pure ML-DSA TLS signature schemes**: no IANA code points exist yet
  for standalone ML-DSA (non-composite) TLS schemes.  Even with
  `allow_post_quantum = true`, only composite schemes are advertised.

- **Client remote address**: when native TLS is active, the client's remote IP address
  is available to handlers through the standard axum connection-info mechanism.

---

## Troubleshooting

| Error | Likely cause |
|-------|--------------|
| `TLS cert file 'X' contains no PEM blocks` | Wrong file path, or file is DER-encoded (convert to PEM first) |
| `TLS cert and key must both be present or both absent` | One file exists but the other does not; either supply both or remove both |
| `build client-auth trust store: …` | A CA PEM file is malformed or contains non-certificate data |
| `client cert verification failed: …` | Client presented a cert that does not chain to the configured CA, has expired, or violates the chosen profile |
| `composite signature verification failed: …` | OpenSSL does not support the composite NID for the scheme used; see Known Limitations |
| `TLS versions: …` | `protocols` list contains an unsupported value; use `"TLSv1.2"` and/or `"TLSv1.3"` |
