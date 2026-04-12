# Introduction

`Akāmu` is a self-hosted certificate authority that speaks the ACME protocol defined in [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555). It is written in Rust and is designed to be operated inside a private network or behind a reverse proxy, issuing X.509 certificates to ACME clients such as certbot, acme.sh, or any RFC 8555-compliant library.

For a detailed breakdown of RFC and draft coverage — including which sections are implemented, which are intentionally omitted, and post-quantum support — see the [RFC Support Reference](user/rfc-support.md).

## What it does

- Implements the full RFC 8555 ACME server protocol: directory, nonces, accounts, orders, authorizations, challenges, certificate issuance, and revocation.
- Validates domain ownership using **http-01**, **dns-01**, **tls-alpn-01**, and **dns-persist-01** challenge types (RFC 8555 §8, RFC 8737, and the [Let's Encrypt dns-persist-01 specification](https://letsencrypt.org/2026/02/18/dns-persist-01)).
- Issues end-entity certificates signed by a built-in Certificate Authority whose key and self-signed root are generated automatically on first run, or loaded from existing PEM files.
- Maintains a SQLite database for all ACME objects (accounts, orders, authorizations, challenges, certificates, nonces).
- Generates and serves CRLs (Certificate Revocation Lists).
- Exposes OCSP responder URLs in issued certificates when configured.
- Implements the ACME Renewal Information extension ([RFC 9773](https://www.rfc-editor.org/rfc/rfc9773)) so ACME clients know when to renew.
- Optionally appends issued certificates to a Merkle Tree Certificate transparency log using the `synta-mtc` library.
- When `external_account_required = true`, performs full HMAC verification of the `externalAccountBinding` JWS (HS256/HS384/HS512), confirms the payload is the account key, and atomically consumes the EAB key on account creation. Keys are provisioned in the TOML config under `[server.eab_keys]`.
- Optionally terminates TLS directly using rustls, with an auto-generated certificate on first run. Supports mutual TLS (mTLS) client certificate authentication with configurable CA trust anchors, chain depth, RSA modulus enforcement, and post-quantum client certificate acceptance.

## What it does not do

- It does not serve the CRL or OCSP responses over HTTP itself; those endpoints must be provided separately if you enable `crl_url` or `ocsp_url`.
- It does not support wildcard certificates via http-01 or tls-alpn-01 (only dns-01 and dns-persist-01 can authorize wildcard identifiers per RFC 8555 §7.1.3).

## Technology stack

| Component | Library |
|---|---|
| Async runtime | tokio |
| HTTP framework | axum 0.8 |
| Database | rusqlite (system SQLite) + tokio-rusqlite |
| Schema migrations | rusqlite_migration |
| X.509 / PKCS#10 / CRL | synta-certificate |
| MTC transparency log | synta-mtc |
| DNS resolution | hickory-resolver |
| TLS server | axum-server + rustls |
| TLS client | rustls + tokio-rustls |
| HTTP client | hyper 1 |
| Configuration | TOML |

## Standards implemented

- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) — Automatic Certificate Management Environment (ACME)
- [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659) — DNS CAA Resource Record
- [RFC 8657](https://www.rfc-editor.org/rfc/rfc8657) — CAA Extensions: accounturi and validationmethods
- [RFC 8737](https://www.rfc-editor.org/rfc/rfc8737) — ACME TLS-ALPN-01 Challenge Type
- [RFC 8738](https://www.rfc-editor.org/rfc/rfc8738) — ACME IP Identifier Validation
- [RFC 8739](https://www.rfc-editor.org/rfc/rfc8739) — ACME Short-Term, Automatically Renewed (STAR) Certificates
- [RFC 9444](https://www.rfc-editor.org/rfc/rfc9444) — ACME for Subdomains
- [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773) — ACME Renewal Information (ARI)
- [RFC 9799](https://www.rfc-editor.org/rfc/rfc9799) — ACME Extensions for .onion Special-Use Domain Names
- [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807) — Problem Details for HTTP APIs (error responses)
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) — X.509 Certificate and CRL profile
- [Let's Encrypt dns-persist-01](https://letsencrypt.org/2026/02/18/dns-persist-01) — Persistent DNS challenge type
- [draft-aaron-acme-profiles-01](https://www.ietf.org/archive/id/draft-aaron-acme-profiles-01.html) — ACME certificate profiles
- [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) — ML-DSA composite TLS signature schemes (provisional code points)

## Quick navigation

New to Akāmu? Start with the [Quick Start](quickstart/install.md) guide. If you want to understand every configuration key, see the [Configuration Reference](user/configuration.md). Developers should read the [Architecture](developer/architecture.md) chapter first.
