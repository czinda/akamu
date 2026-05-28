# Introduction

`Akāmu` is a self-hosted certificate authority that speaks the ACME protocol defined in [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555). It is written in Rust and is designed to be operated inside a private network or behind a reverse proxy, issuing X.509 certificates to ACME clients such as certbot, acme.sh, or any RFC 8555-compliant library. The project is organized as a Cargo workspace. In addition to the server binary, it ships standalone client libraries — see [Client Libraries](client/overview.md).

For a detailed breakdown of RFC and draft coverage — including which sections are implemented, which are intentionally omitted, and post-quantum support — see the [RFC Support Reference](user/rfc-support.md).

## What it does

- Implements the full RFC 8555 ACME server protocol: directory, nonces, accounts, orders, authorizations, challenges, certificate issuance, and revocation.
- Validates domain ownership using **http-01**, **dns-01**, **tls-alpn-01**, and **dns-persist-01** challenge types (RFC 8555 §8, RFC 8737, and the [Let's Encrypt dns-persist-01 specification](https://letsencrypt.org/2026/02/18/dns-persist-01)).
- Validates `TNAuthList` and `JWTClaimConstraints` identifiers using the **tkauth-01** challenge type (RFC 9447 / RFC 9448), verifying signed authority tokens issued by an external Token Authority.
- Issues end-entity certificates signed by a built-in Certificate Authority whose key and self-signed root are generated automatically on first run, or loaded from existing PEM files.
- Persists all ACME objects (accounts, orders, authorizations, challenges, certificates, nonces) in a SQL database. The supported backends are **SQLite** (default; single-file, no external service required), **PostgreSQL**, and **MariaDB/MySQL**, selected by the `database.url` configuration key.
- Generates and serves CRLs (Certificate Revocation Lists) at `GET /ca/crl`.
- Serves OCSP responses at `GET /ca/ocsp/{request}` and `POST /ca/ocsp` (RFC 6960).
- Implements the ACME Renewal Information extension ([RFC 9773](https://www.rfc-editor.org/rfc/rfc9773)) so ACME clients know when to renew.
- Optionally appends issued certificates to a Merkle Tree Certificate transparency log using the `synta-mtc` library.
- When `external_account_required = true`, performs full HMAC verification of the `externalAccountBinding` JWS (HS256/HS384/HS512), confirms the payload is the account key, and atomically consumes the EAB key on account creation. EAB keys can be provisioned in two ways: statically in the TOML config under `[server.eab_keys]`, or derived on demand via HKDF-SHA-256 (RFC 5869) when `[server].eab_master_secret` is set and the client authenticates via GSSAPI or a trusted proxy (`GET /acme/eab`).
- Optionally terminates TLS directly using rustls, with an auto-generated certificate on first run. Supports mutual TLS (mTLS) client certificate authentication with configurable CA trust anchors, chain depth, RSA modulus enforcement, and post-quantum client certificate acceptance.
- Supports multi-node clustering through a built-in CRDT + gossip replication layer. All domain state (accounts, orders, authorizations, challenges, certificates, EAB keys, operators, delegations, MTC) is replicated to every cluster member via signed gossip envelopes. Nodes are registered with each other via the `POST /admin/gossip/register` admin endpoint. When the `[gossip]` section is absent the node runs in single-node mode with no replication overhead.

## What it does not do

- It does not support wildcard certificates via http-01 or tls-alpn-01 (only dns-01 and dns-persist-01 can authorize wildcard identifiers per RFC 8555 §7.1.3).

## Technology stack

| Component | Library |
|---|---|
| Async runtime | tokio |
| HTTP framework | axum 0.8 |
| Database | sqlx 0.8 (SQLite / PostgreSQL / MariaDB via `Any` backend) |
| Schema migrations | sqlx built-in migrate |
| X.509 / PKCS#10 / CRL | synta-certificate |
| MTC transparency log | synta-mtc |
| DNS resolution | hickory-resolver |
| TLS server | axum-server + rustls |
| TLS client | rustls + tokio-rustls |
| HTTP client | hyper 1 |
| Configuration | TOML |
| JWK/JWS primitives | akamu-jose (workspace crate) |
| ACME client library | akamu-client (workspace crate) |
| CLI | akamu-cli (workspace crate) |
| CRDT replication | akamu-crdt (workspace crate) — LWW-register, OR-map, LWW-map, GrowSet primitives |

## Standards implemented

- [RFC 8555](https://www.rfc-editor.org/rfc/rfc8555) — Automatic Certificate Management Environment (ACME)
- [RFC 8659](https://www.rfc-editor.org/rfc/rfc8659) — DNS CAA Resource Record
- [RFC 8657](https://www.rfc-editor.org/rfc/rfc8657) — CAA Extensions: accounturi and validationmethods
- [RFC 8737](https://www.rfc-editor.org/rfc/rfc8737) — ACME TLS-ALPN-01 Challenge Type
- [RFC 8738](https://www.rfc-editor.org/rfc/rfc8738) — ACME IP Identifier Validation
- [RFC 8739](https://www.rfc-editor.org/rfc/rfc8739) — ACME Short-Term, Automatically Renewed (STAR) Certificates
- [RFC 9444](https://www.rfc-editor.org/rfc/rfc9444) — ACME for Subdomains
- [RFC 9447](https://www.rfc-editor.org/rfc/rfc9447) — ACME Challenges Using an Authority Token (tkauth-01)
- [RFC 9448](https://www.rfc-editor.org/rfc/rfc9448) — ACME TNAuthList Authority Token
- [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773) — ACME Renewal Information (ARI)
- [RFC 9799](https://www.rfc-editor.org/rfc/rfc9799) — ACME Extensions for .onion Special-Use Domain Names
- [RFC 7807](https://www.rfc-editor.org/rfc/rfc7807) — Problem Details for HTTP APIs (error responses)
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) — X.509 Certificate and CRL profile
- [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) — Online Certificate Status Protocol (OCSP)
- [Let's Encrypt dns-persist-01](https://letsencrypt.org/2026/02/18/dns-persist-01) — Persistent DNS challenge type
- [draft-ietf-acme-profiles-01](https://datatracker.ietf.org/doc/draft-ietf-acme-profiles/) — ACME certificate profiles
- [draft-ietf-lamps-pq-composite-sigs](https://datatracker.ietf.org/doc/draft-ietf-lamps-pq-composite-sigs/) — ML-DSA composite TLS signature schemes (provisional code points)
- [draft-ietf-plants-merkle-tree-certs-04](https://davidben.github.io/merkle-tree-certs/) — Merkle Tree Certificates (MTC), transparency-log-backed certificate format (experimental OIDs, pre-IANA)

## Reading guide

The documentation is split into three sections targeting distinct audiences:

| Section | Who it is for | What it covers |
|---|---|---|
| **Operator Guide** | System administrators deploying and running Akāmu | Installation, configuration, account policies, certificate issuance, revocation, TLS, backup |
| **API Reference** | Developers consuming Akāmu's HTTP APIs or using the Rust client libraries | Admin REST API, ACME protocol details (algorithms, challenge types, error codes, wire formats), `akamu-jose` / `akamu-client` / `akamu-cli` |
| **Implementation Guide** | Contributors working on the Akāmu source code | Architecture, database schema, CA internals, challenge validation, EAB and account internals, testing |

## Quick navigation

**New to Akāmu?** Start with the [Quick Start](quickstart/install.md) guide.

**Deploying or configuring the server?** See the [Configuration Reference](user/configuration.md) for every configuration key, or [Operator Roles](user/operator-roles.md) for RBAC setup.

**Building an ACME client or integrating via the API?** Start with [ACME Protocol Reference](client/protocol.md) for the wire-level details, [Admin API](user/admin-api.md) for the management REST API, or [akamu-client](client/client-library.md) for the Rust library.

**Contributing to Akāmu?** Read the [Architecture](developer/architecture.md) chapter first — it includes a full system diagram covering all subsystems and their interactions.
