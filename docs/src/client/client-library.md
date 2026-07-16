# akamu-client — ACME Client Library

`akamu-client` is an async Rust library that implements the full RFC 8555 ACME client lifecycle. It targets applications that need to obtain and renew certificates programmatically without shelling out to certbot or acme.sh.

## Overview

The library covers:

- ACME directory discovery and nonce management (automatic, with nonce recycling)
- Account registration with optional External Account Binding (EAB)
- Account lookup (`find_account`), state retrieval (`get_account`), contact updates (`update_account`)
- Account key rollover (`key_change`, RFC 8555 §7.3.5)
- Account deactivation
- Order creation, authorization retrieval, challenge triggering, and status polling
- CSR construction (`build_csr`)
- Order finalization and certificate download
- Certificate revocation via account key or certificate's own key (RFC 8555 §7.6)
- ARI renewal window query (`get_renewal_info`, RFC 9773)
- Built-in http-01 challenge solver (`Http01Solver`)
- Built-in tls-alpn-01 challenge solver (`TlsAlpn01Solver`, RFC 8737)
- DNS challenge helpers (`Dns01Helper`, `DnsPersist01Helper`)
- DNS hook solver (`DnsHookSolver`) — delegates TXT record management to an external script
- onion-csr-01 CSR builder (`build_onion_csr`, RFC 9799)
- A `ChallengeSolver` trait for custom solvers
- `AccountKey::from_jwk_private` — load an account key from a certbot-style private JWK
- `RenewalConfig` — serialisable struct for persisting renewal parameters alongside a certificate
- `MtcClient` — HTTP client for querying Merkle Tree Certificate transparency logs
- `mtc_verify` module — standalone certificate parsing, leaf hashing, and inclusion proof verification
- `cert_id_from_url` — extract certificate ID from an ACME certificate URL
- `HashAlgorithm` — re-exported from `synta-mtc` for use with MTC verification functions

Dependencies: `tokio`, `hyper-rustls` (TLS enabled by default), `akamu-jose`, `synta-mtc`, `synta-krb5` (Kerberos SAN decoding). No database or server dependencies.

## End-to-end example: P-256 key, http-01 challenge

```rust
use akamu_client::{
    AccountKey, AccountOptions, AcmeClient,
    Http01Solver, Identifier, build_csr, ChallengeSolver as _,
};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Account key
    let key = Arc::new(AccountKey::generate("ec:P-256")?);

    // 2. Connect to the ACME server (HTTPS by default)
    let client = AcmeClient::new("https://acme.example.com/acme/directory").await?;

    // 3. Register an account
    let opts = AccountOptions {
        contacts: &["mailto:ops@example.com"],
        agree_tos: true,
        eab: None,
    };
    let account = client.new_account(Arc::clone(&key), &opts).await?;

    // 4. Place an order
    let ids = vec![Identifier::dns("example.com")];
    let order = client.new_order(&account, &ids).await?;

    // 5. Solve each authorization
    let solver = Http01Solver::new(80);
    solver.start().await?;

    for authz_url in &order.authorizations {
        let authz = client.get_authorization(&account, authz_url).await?;
        if authz.status == "valid" { continue; }

        let challenge = authz.find_challenge("http-01")
            .expect("http-01 challenge not offered");

        let token = challenge.token.as_deref().expect("challenge has no token");
        let key_auth = account.key_authorization(token);
        solver.present(token, &key_auth).await?;

        client.trigger_challenge(&account, challenge).await?;
        let _order = client.poll_order(&account, &order.url).await?;

        solver.cleanup(token).await?;
    }

    // 6. Finalize
    let cert_key = AccountKey::generate("ec:P-256")?;
    let csr_der = build_csr(&["example.com"], cert_key.private_key())?;
    let finalized = client.finalize(&account, &order, &csr_der).await?;

    // 7. Download
    let cert_url = finalized.certificate.expect("order has no certificate URL");
    let pem = client.download_certificate(&account, &cert_url).await?;
    std::fs::write("cert.pem", &pem)?;
    println!("Certificate written to cert.pem");
    Ok(())
}
```

## AccountKey

`AccountKey` holds the ACME account private key. It wraps a `BackendPrivateKey` from `synta-certificate`.

### Generating a key

```rust
let key = AccountKey::generate("ec:P-256")?;   // or "rsa:2048", "ed25519", "ml-dsa-65", ...
```

Supported key types: `ec:P-256`, `ec:P-384`, `ec:P-521`, `rsa:2048`, `rsa:3072`, `rsa:4096`, `ed25519`, `ed448`, `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87`.

### Saving and loading

```rust
let pem = key.to_pem()?;
std::fs::write("account.key", &pem)?;

let loaded = AccountKey::from_pem(&pem)?;
```

### Loading from a certbot JWK

`AccountKey::from_jwk_private` parses a private JWK JSON string (the format used by certbot's `private_key.json`) and returns an `AccountKey`. Supported key types: EC P-256, P-384, P-521, and RSA.

```rust
use akamu_client::AccountKey;

let jwk_json = std::fs::read_to_string("/etc/letsencrypt/accounts/.../private_key.json")?;
let key = AccountKey::from_jwk_private(&jwk_json)?;
```

This is the same conversion performed internally by `akamu-cli import certbot`.

### Thumbprint and key authorization

```rust
let thumb = key.thumbprint();                        // base64url SHA-256 of JWK (no fallible call needed)
let key_auth = key.key_authorization("some-token");  // "<token>.<thumb>"
```

### JWS algorithm

```rust
let alg = key.alg();   // "ES256", "EdDSA", "ML-DSA-65", etc.
```

## AcmeClient

### Directory discovery

`AcmeClient::new` fetches the ACME directory over HTTPS and caches the endpoint URLs. Nonces are recycled from `Replay-Nonce` response headers; `HEAD /new-nonce` is only called on a cache miss.

```rust
let client = AcmeClient::new("https://acme.example.com/acme/directory").await?;
```

The client also transparently retries any request that receives a `badNonce` error exactly once.

### Account registration

```rust
use std::sync::Arc;

let key = Arc::new(AccountKey::generate("ec:P-256")?);
let opts = AccountOptions {
    contacts: &["mailto:admin@example.com"],
    agree_tos: true,
    eab: None,
};
let account = client.new_account(Arc::clone(&key), &opts).await?;
```

The returned `Account` contains:

- `account.url` — the account URL (a.k.a. kid), used in subsequent requests
- `account.status` — `"valid"`, `"deactivated"`, or `"revoked"`
- `account.contacts` — the contact URIs registered

### Finding an existing account

POST to `/new-account` with `onlyReturnExisting: true` (RFC 8555 §7.3.1). Fails with `accountDoesNotExist` if no account is registered for the key.

```rust
let account = client.find_account(Arc::clone(&key)).await?;
```

### Fetching current account state

POST-as-GET to the account URL (RFC 8555 §7.3.2). Returns a fresh `Account` reflecting the server's current view.

```rust
let account = client.get_account(&account).await?;
println!("{} {:?}", account.status, account.contacts);
```

### Updating account contacts

```rust
let updated = client.update_account(
    &account,
    &["mailto:new@example.com", "mailto:ops@example.com"],
).await?;
```

Pass an empty slice to clear all contacts.

### Account key rollover (RFC 8555 §7.3.5)

Replaces the account key on the server with a new key. After this call the old `account` is no longer valid; use the returned `Account`, which holds the new key.

```rust
let new_key = Arc::new(AccountKey::generate("ec:P-384")?);
let updated = client.key_change(&account, Arc::clone(&new_key)).await?;
// updated.key is now new_key; old account key is rejected by the server
```

### Account deactivation

```rust
client.deactivate_account(&account).await?;
```

After deactivation the account status becomes `"deactivated"`. The server will reject all future requests signed with that account key.

## External Account Binding (EAB)

Some ACME servers require EAB before accepting new accounts. EAB proves that the account request is authorized by an out-of-band credential.

Pass an `EabOptions` inside `AccountOptions`:

```rust
use akamu_client::{AccountOptions, EabOptions};

let eab_key_bytes: Vec<u8> = /* base64url-decode your HMAC key here */ vec![];

let opts = AccountOptions {
    contacts: &["mailto:admin@example.com"],
    agree_tos: true,
    eab: Some(EabOptions {
        kid: "eab-key-id-from-your-ca",
        hmac_key: &eab_key_bytes,  // raw bytes, NOT base64
        alg: "HS256",              // "HS256", "HS384", or "HS512"
    }),
};
let account = client.new_account(Arc::clone(&key), &opts).await?;
```

The library builds the EAB JWS internally, signs it with the HMAC key, and embeds it in the new-account request as `externalAccountBinding`.

## GSSAPI-authenticated EAB fetch

When the ACME server uses Kerberos to authenticate EAB requests, use
`fetch_eab_via_gssapi` to retrieve the authenticated principal identity from the
server's `GET /acme/eab` endpoint before registering:

```rust
use akamu_client::{fetch_eab_via_gssapi, GssapiEabResult};

let result: GssapiEabResult = fetch_eab_via_gssapi(
    "https://acme.example.com/acme/eab",
    "/etc/akamu/client.keytab",
).await?;
println!("Authenticated as: {}", result.principal);
```

The function:

1. Loads an initiator credential from `keytab_file` via `akamu-gssapi`.
2. Derives the target service name as `HTTP@<hostname>` from the URL.
3. Calls `gss_init_sec_context` (via `tokio::task::spawn_blocking`) to produce a
   Kerberos token.
4. Sends `GET <eab_url>` with `Authorization: Negotiate <base64-token>`.
5. Parses `{"principal": "..."}` from the response body.

The returned `GssapiEabResult` currently contains only the `principal` field.
Full EAB key derivation is not yet implemented server-side; the endpoint echoes
the authenticated principal name as confirmation that Kerberos authentication
succeeded.

Both `fetch_eab_via_gssapi` and `GssapiEabResult` are re-exported from the crate
root.

## Order lifecycle

```mermaid
sequenceDiagram
    participant App as Your App
    participant Lib as AcmeClient
    participant Srv as ACME Server

    App->>Lib: new_order(account, ids)
    Lib->>Srv: POST /acme/new-order
    Srv-->>Lib: 201 Order {authorizations, finalize}
    Lib-->>App: Order

    loop For each authorization URL
        App->>Lib: get_authorization(account, url)
        Lib->>Srv: POST /acme/authz/{id}
        Srv-->>Lib: 200 Authorization {challenges}
        Lib-->>App: Authorization

        App->>App: Present challenge (http-01 / dns-01 / ...)

        App->>Lib: trigger_challenge(account, challenge)
        Lib->>Srv: POST /acme/chall/{authz_id}/{type}
        Srv-->>Lib: 200 Challenge {status: processing}

        loop Poll until valid
            Lib->>Srv: POST-as-GET /acme/order/{id}
            Srv-->>Lib: 200 Order {status}
        end
    end

    App->>Lib: finalize(account, order, csr_der)
    Lib->>Srv: POST /acme/order/{id}/finalize
    Srv-->>Lib: 200 Order {certificate URL}
    Lib-->>App: Order (finalized)

    App->>Lib: download_certificate(account, cert_url)
    Lib->>Srv: POST /acme/cert/{id}
    Srv-->>Lib: 200 PEM bundle
    Lib-->>App: PEM bytes
```

### new_order

```rust
let ids = vec![
    Identifier::dns("example.com"),
    Identifier::dns("www.example.com"),
    Identifier::ip("192.0.2.1"),          // RFC 8555 ip-type identifier
    Identifier::onion("foo.onion"),        // RFC 9799 onion identifier
];
let order = client.new_order(&account, &ids).await?;
// order.authorizations — Vec<String> of authz URLs
// order.finalize       — finalize URL
// order.status         — "pending"
```

### get_authorization

```rust
let authz = client.get_authorization(&account, &authz_url).await?;
// authz.identifier   — Identifier { type, value }
// authz.status       — "pending", "valid", "invalid", ...
// authz.challenges   — Vec<Challenge>

// Convenience method to find a challenge by type:
let chall = authz.find_challenge("http-01").expect("no http-01 challenge offered");
```

### trigger_challenge

```rust
client.trigger_challenge(&account, &challenge).await?;
```

Sends an empty-body POST (`{}`) to the challenge URL, signaling that the client is ready. The server begins validation asynchronously.

### trigger_challenge_onion (RFC 9799)

For onion-csr-01 challenges, use this instead of `trigger_challenge`. It posts a `{"csr": "<base64url>"}` payload:

```rust
let csr_der = akamu_client::build_onion_csr(&domain, &key_auth, &hs_key_pem)?;
client.trigger_challenge_onion(&account, &challenge.url, &csr_der).await?;
```

### poll_order

```rust
let order = client.poll_order(&account, &order.url).await?;
```

Polls with exponential backoff until `order.status` is `"ready"` or `"valid"`. Respects the `Retry-After` header from the server. The internal deadline is 30 seconds; wrap with `tokio::time::timeout` for longer limits.

### finalize

```rust
let csr_der = build_csr(&["example.com", "www.example.com"], cert_key.private_key())?;
let finalized = client.finalize(&account, &order, &csr_der).await?;
```

Submits the CSR. Returns the updated order which, when the server is done, contains a `certificate` URL.

### download_certificate

```rust
let pem = client.download_certificate(&account, &cert_url).await?;
// pem is a Vec<u8> containing a PEM bundle (leaf + intermediates)
```

## Certificate revocation (RFC 8555 §7.6)

### Via account key

```rust
use akamu_client::pem_to_der;

let cert_pem = std::fs::read("cert.pem")?;
let cert_der = pem_to_der(&cert_pem).into_iter().next()
    .expect("no certificate in PEM");

// reason: None = unspecified; Some(0..=10, not 7) = CRL reason code
client.revoke_certificate(&account, &cert_der, None).await?;
```

### Via certificate's own private key (self-revocation)

Use this when the account key is unavailable but the certificate's private key is known.

```rust
let cert_key = Arc::new(AccountKey::from_pem(&std::fs::read("cert.key.pem")?)?);
client.revoke_certificate_with_cert_key(&cert_key, &cert_der, Some(1)).await?;
```

## ARI renewal information (RFC 9773)

```rust
let cert_pem = std::fs::read("cert.pem")?;
let info = client.get_renewal_info(&cert_pem).await?;
// info.window_start  — RFC 3339 string (start of suggested renewal window)
// info.window_end    — RFC 3339 string
// info.retry_after_secs — Option<u64> from Retry-After header
println!("Renew between {} and {}", info.window_start, info.window_end);
```

Returns `Err` if the server does not advertise a `renewalInfo` endpoint.

## STAR order API (RFC 8739)

ACME STAR (Short-Term, Automatically Renewed) orders let a client place a single order and receive a continuous stream of short-lived certificates without repeating domain validation. Use `StarOrderParams` to describe the order and `AcmeClient::new_star_order()` to place it.

### Placing a STAR order

```rust
use akamu_client::{StarOrderParams, Identifier};

let params = StarOrderParams {
    identifiers: &[Identifier::dns("example.com")],
    end_date: "2026-12-31T00:00:00Z",   // RFC 3339
    lifetime_secs: 86400,               // each cert is valid for 1 day
    start_date: None,                   // start when order becomes ready
    lifetime_adjust_secs: 0,            // no clock-skew pre-dating
    allow_certificate_get: true,        // allow unauthenticated rolling GET
};

let star_order = client.new_star_order(&account, &params).await?;
// star_order.status         — "pending"
// star_order.authorizations — authz URLs to solve, same as a regular order
// star_order.finalize       — finalize URL
```

After placing the order, solve the authorizations and finalize using the standard `get_authorization`, `trigger_challenge`, and `finalize` calls. The server then automatically reissues a new certificate before each one expires.

### `StarOrderParams` fields

| Field | Required | Description |
|-------|----------|-------------|
| `identifiers` | Yes | Identifiers to certify. |
| `end_date` | Yes | RFC 3339 timestamp; the last certificate's `notBefore` must not exceed this. |
| `lifetime_secs` | Yes | Validity period of each automatically issued certificate, in seconds. |
| `start_date` | No | RFC 3339 timestamp for the earliest `notBefore` of the first certificate. Defaults to when the order becomes ready. |
| `lifetime_adjust_secs` | No | Pre-dates each certificate's `notBefore` by this many seconds to create an overlap window (RFC 8739 §3.1.1). Default: `0`. |
| `allow_certificate_get` | No | When `true`, the rolling certificate URL can be fetched without authentication. |

### Downloading the rolling certificate

After finalization `star_order.star_certificate` contains the rolling URL. Download it either with an authenticated POST-as-GET or (when `allow_certificate_get` was requested) an unauthenticated GET:

```rust
// Authenticated download (always works):
let pem = client.download_star_certificate(&account, &star_cert_url).await?;

// Unauthenticated GET (only when allow_certificate_get was true):
let pem = client.get_star_certificate(&star_cert_url).await?;
```

Both methods return the current PEM certificate chain.

### Canceling a STAR order

```rust
client.cancel_star_order(&account, &star_order.url).await?;
```

After cancellation the rolling certificate URL returns HTTP 403 (`autoRenewalCanceled`). The currently active short-lived certificate remains usable until it expires.

## Identifier constructors

```rust
Identifier::dns("example.com")       // {"type":"dns","value":"example.com"}
Identifier::dns("*.example.com")     // wildcard (dns-01 only)
Identifier::ip("192.0.2.1")          // RFC 8555 §7.1.4 ip-type
Identifier::ip("2001:db8::1")        // IPv6
Identifier::onion("foo.onion")       // RFC 9799 Tor hidden service
```

## ChallengeSolver trait

Implement this trait to provide a custom challenge solver (for example, a DNS-01 solver that calls your registrar's API):

```rust
pub trait ChallengeSolver: Send + Sync {
    fn present(
        &self,
        token: &str,
        key_auth: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ClientError>> + Send + '_>>;

    fn cleanup(
        &self,
        token: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ClientError>> + Send + '_>>;
}
```

`present` is called before `trigger_challenge`. `cleanup` is called after the authorization reaches a terminal state.

## Http01Solver

The built-in http-01 solver starts a small HTTP server that serves key authorization values at `/.well-known/acme-challenge/<token>`.

```rust
let solver = Http01Solver::new(80);  // listen port
solver.start().await?;               // spawns a background task
```

Port 80 requires elevated privileges on most Linux systems. Either run as root, use `CAP_NET_BIND_SERVICE`, or configure an iptables redirect from port 80 to a high port.

`Http01Solver` implements `ChallengeSolver`. Call `present` before triggering and `cleanup` after validation completes.

## TlsAlpn01Solver (RFC 8737)

Serves ephemeral ACME challenge certificates over TLS for tls-alpn-01. The solver binds port 443 (or another port), responds to SNI lookups from the ACME server, and completes the TLS handshake with ALPN `acme-tls/1`.

```rust
use akamu_client::TlsAlpn01Solver;

let mut solver = TlsAlpn01Solver::new(443);
solver.start().await?;

// For each authorization:
let key_auth = account.key_authorization(token);
solver.present(
    &authz.identifier.value,  // domain or IP string
    &authz.identifier.r#type, // "dns" or "ip"
    &key_auth,
).await?;

client.trigger_challenge(&account, &challenge).await?;
client.poll_order(&account, &order.url).await?;

// When done with all authorizations:
solver.cleanup();  // note: not async, takes &mut self
```

- `new(port)` — creates the solver; does not bind yet.
- `start()` — binds the port and spawns the TLS accept loop.
- `present(domain, id_type, key_auth)` — generates an ephemeral P-256 certificate with the `id-pe-acmeIdentifier` extension and registers it for SNI lookup.
- `cleanup()` — aborts the background listener.

tls-alpn-01 cannot validate wildcard identifiers (RFC 8737 §3).

## DNS helpers

### Dns01Helper

Computes the TXT record value for dns-01. Does not modify DNS — you must add and remove the record yourself.

```rust
use akamu_client::Dns01Helper;

let txt = Dns01Helper::txt_value(&key_auth)?;
// Add TXT record: _acme-challenge.example.com  TXT  <txt>
// After validation completes, remove the record.
```

### DnsPersist01Helper

Same computation for the dns-persist-01 challenge variant. The record name is `_validation-persist.<domain>` and it is long-lived (set once per account key):

```rust
use akamu_client::DnsPersist01Helper;

let txt = DnsPersist01Helper::txt_value(&key_auth)?;
// Add TXT record: _validation-persist.example.com  TXT  <txt>
```

### DnsHookSolver

`DnsHookSolver` implements `ChallengeSolver` by delegating TXT record management to an external script. It is designed for automated pipelines where a registrar API or DDNS tool handles DNS updates.

The hook is invoked as:

```
<hook_script> add
<hook_script> remove
```

All values are passed through environment variables only (never as command-line arguments):

| Variable | Value |
|---|---|
| `AKAMU_DOMAIN` | DNS name being validated (wildcard prefix stripped) |
| `AKAMU_TOKEN` | ACME challenge token |
| `AKAMU_TXT` | TXT record value: `base64url(SHA-256(key_authorization))` |
| `AKAMU_KEY_AUTH` | Full key authorization string (`<token>.<jwk_thumbprint>`) |

Exit code `0` is success. Non-zero causes a `ClientError` that includes captured stderr.

```rust
use akamu_client::DnsHookSolver;

let solver = DnsHookSolver::new("/etc/akamu/hooks/dns-update.sh".to_string());

// Before triggering the ACME challenge:
solver.deploy(&domain, token, &key_auth).await?;
client.trigger_challenge(&account, &challenge).await?;
client.poll_order(&account, &order.url).await?;

// After the challenge completes (success or failure):
solver.clean(&domain, token, &key_auth).await?;
```

For `dns-persist-01`, call only `deploy`; do not call `clean` on success because the TXT record is long-lived.

## build_onion_csr (RFC 9799)

Builds a DER-encoded CSR for an onion-csr-01 challenge. The CSR carries the `cabf-onion-csr-nonce` extension (OID 2.23.140.41) containing the key authorization as a DER UTF8String, and is signed by the hidden-service Ed25519 private key.

```rust
use akamu_client::build_onion_csr;

let hs_key_pem = std::fs::read("hs_ed25519_secret_key.pem")?;
let csr_der = build_onion_csr(
    "example.onion",   // .onion domain
    &key_auth,         // token.thumbprint
    &hs_key_pem,       // Ed25519 hidden-service private key (PEM)
)?;
client.trigger_challenge_onion(&account, &challenge.url, &csr_der).await?;
```

## build_csr

Generates a PKCS#10 CSR in DER format. The first element of the domains slice becomes the CN; all elements become Subject Alternative Names.

```rust
let cert_key = AccountKey::generate("ec:P-256")?;
let csr_der = build_csr(&["example.com", "www.example.com"], cert_key.private_key())?;
```

Wildcard domains are supported: pass `"*.example.com"`. The CSR key type is independent of the account key type.

## pem_to_der

Re-exported from `synta_certificate` for convenience. Decodes all PEM blocks in a byte slice to DER:

```rust
use akamu_client::pem_to_der;

let cert_pem = std::fs::read("cert.pem")?;
let ders: Vec<Vec<u8>> = pem_to_der(&cert_pem);
let cert_der = ders.into_iter().next().expect("no certificate");
```

## RenewalConfig

`RenewalConfig` is a serialisable/deserialisable struct that captures every parameter needed to repeat a certificate issuance. It is used by `akamu-cli issue` (written to `<out>.renewal.toml`) and by `akamu-cli import certbot` (generated from certbot's renewal config).

```rust
use akamu_client::{RenewalConfig, Identifier};
use std::path::PathBuf;

let config = RenewalConfig {
    server: "https://acme.example.com/acme/directory".into(),
    domains: vec![Identifier::dns("example.com")],
    account_key: PathBuf::from("/etc/akamu/account.pem"),
    account_key_type: "ec:P-256".into(),
    cert_path: PathBuf::from("/etc/ssl/example.com/fullchain.pem"),
    cert_key_path: PathBuf::from("/etc/ssl/example.com/fullchain.pem.key.pem"),
    cert_key_type: "ec:P-256".into(),
    challenge_type: "dns-01".into(),
    http_port: 80,
    tls_port: 443,
    onion_key: None,
    poll_timeout: 120,
    contacts: vec!["mailto:admin@example.com".into()],
    eab_kid: None,
    eab_key: None,
    eab_alg: "HS256".into(),
    gssapi_keytab: None,
    dns_hook: Some("/etc/akamu/hooks/dns-update.sh".into()),
};

let toml = toml::to_string_pretty(&config)?;
std::fs::write("fullchain.pem.renewal.toml", &toml)?;

// Round-trip:
let loaded: RenewalConfig = toml::from_str(&toml)?;
```

Fields with defaults (`account_key_type`, `cert_key_type`, `challenge_type`, `http_port`, `tls_port`, `poll_timeout`, `eab_alg`) are optional in TOML files; missing fields are filled with sensible defaults on deserialisation. The `gssapi_keytab` field is also optional (defaults to absent when not present in the file, via `#[serde(default)]`).

## MtcClient

`MtcClient` is an HTTP client for querying Merkle Tree Certificate (MTC) transparency log endpoints exposed by an akamu server. It derives the MTC base URL from a standard ACME directory URL.

### Constructors

```rust
use akamu_client::MtcClient;

// From a directory URL (http or https)
let client = MtcClient::new("https://acme.example.com/acme/directory")?;

// With an extra CA certificate for TLS verification
let pem = std::fs::read("ca.pem")?;
let client = MtcClient::new_with_extra_root("https://acme.example.com/acme/directory", &pem)?;

// HTTPS-only (rejects http:// URLs)
let client = MtcClient::new_https_only("https://acme.example.com/acme/directory")?;
```

### Configuration

```rust
// Set maximum response body size (default: 10 MiB)
client.set_max_response_bytes(5 * 1024 * 1024);

// Set request timeout (default: 30 seconds)
client.set_request_timeout(std::time::Duration::from_secs(60));
```

### Query methods

All methods are `async` and return `Result<T, ClientError>`.

| Method | Returns | Description |
|---|---|---|
| `tree_size()` | `TreeSize` | Current number of entries in the log |
| `root()` | `TreeRoot` | Current tree size and root hash |
| `inclusion_proof(cert_id)` | `InclusionProofResponse` | Inclusion proof for a certificate |
| `standalone_cert(cert_id)` | `Vec<u8>` | Standalone DER certificate |
| `landmark_cert_for(cert_id)` | `CertFetchResult` | Landmark certificate for a given cert |
| `landmarks()` | `Vec<Landmark>` | List of all landmarks |
| `landmark_list()` | `String` | Text representation of the landmark list |
| `landmark_cert(seq)` | `CertFetchResult` | Landmark certificate by sequence number |
| `consistency_proof(from, to)` | `ConsistencyProofResponse` | Consistency proof between two tree sizes |
| `subtree_root(start, end)` | `SubtreeRootResponse` | Root hash of a subtree range |
| `revoked_ranges()` | `Vec<[i64; 2]>` | Revoked entry ranges |
| `tlog_checkpoint()` | `String` | Signed checkpoint text |
| `tlog_tile(path)` | `Vec<u8>` | Raw tile data |
| `tlog_cosignature()` | `String` | Cosignature text |

`CertFetchResult` is either `Ok(Vec<u8>)` (DER bytes) or `RetryAfter(u64)` (seconds to wait).

### End-to-end verification example

```rust
use akamu_client::{MtcClient, HashAlgorithm, mtc_verify};

let client = MtcClient::new("https://acme.example.com/acme/directory")?;
let algorithm = HashAlgorithm::Sha256;

// Fetch and parse the standalone certificate
let der = client.standalone_cert("cert-uuid").await?;
let (details, proof) = mtc_verify::extract_cert_and_proof(&der)?;

// Compute the leaf hash and fetch the root
let leaf_hash = mtc_verify::compute_leaf_hash(&der, algorithm)?;
let sr = client.subtree_root(proof.start, proof.end).await?;
let root_hash = mtc_verify::parse_hex_hash(&sr.root_hash)?;

// Verify inclusion
mtc_verify::verify_standalone_inclusion(
    &leaf_hash, details.entry_index, &proof, &root_hash, algorithm,
)?;
println!("Verification passed for {}", details.subject);
```

## cert_id_from_url

Extracts the certificate ID (the last path segment) from an ACME certificate URL. Returns `None` for empty strings or trailing-slash URLs.

```rust
use akamu_client::cert_id_from_url;

assert_eq!(cert_id_from_url("https://host/acme/cert/abc123"), Some("abc123"));
assert_eq!(cert_id_from_url(""), None);
assert_eq!(cert_id_from_url("https://host/acme/cert/"), None);
```

## mtc_verify

The `mtc_verify` module provides standalone MTC certificate verification with no I/O coupling.

### Functions

| Function | Description |
|---|---|
| `parse_standalone_cert(der) -> (OwnedCert, MtcProof)` | Parse DER into an owned certificate and its embedded MTC proof |
| `extract_cert_and_proof(der) -> (CertDetails, MtcProof)` | Single-pass parse returning display details and proof (preferred over calling `parse_standalone_cert` + `extract_cert_details` separately) |
| `extract_cert_details(der) -> CertDetails` | Parse DER into display-oriented certificate details |
| `split_serial(serial) -> (entry_index, log_number)` | Decompose a serial number into its 48-bit entry index and upper log number |
| `compute_leaf_hash(der, algorithm) -> Vec<u8>` | Compute the Merkle tree leaf hash for a DER certificate |
| `verify_standalone_inclusion(leaf_hash, entry_index, proof, root_hash, algorithm)` | Verify an inclusion proof against a root or subtree hash |
| `proof_sibling_count(proof, algorithm) -> usize` | Count sibling hashes in the inclusion proof |
| `parse_hex_hash(hex_str) -> Vec<u8>` | Parse a hex-encoded hash string into bytes |

### CertDetails

```rust
#[derive(Debug, Clone)]
pub struct CertDetails {
    pub subject: String,       // RFC 4514 distinguished name
    pub issuer: String,        // RFC 4514 distinguished name
    pub not_before: String,    // formatted validity start
    pub not_after: String,     // formatted validity end
    pub serial_hex: String,    // hex-encoded serial number
    pub entry_index: u64,      // lower 48 bits of serial
    pub log_number: u64,       // upper bits of serial
    pub sans: Vec<String>,     // formatted SANs (DNS:, IP:, email:, KRB5:, URI:)
    pub extensions: Vec<ExtensionDetail>,
}

#[derive(Debug, Clone)]
pub struct ExtensionDetail {
    pub name: String,          // OID name or numeric OID
    pub critical: bool,
    pub value: Option<String>, // human-readable value, if decodable
}
```

SAN entries are formatted with type prefixes: `DNS:example.com`, `IP:192.0.2.1`, `email:user@example.com`, `KRB5:user@REALM` (decoded from otherName via `synta-krb5`), `URI:https://...`.

## ClientError

```rust
pub enum ClientError {
    Jose(JoseError),          // JWK/JWS error from akamu-jose
    Http(String),             // HTTP transport error (hyper)
    Acme { acme_type: String, detail: String },  // server returned problem+json
    Crypto(String),           // key generation or CSR error
    Io(String),               // I/O error
    Gssapi(String),           // GSSAPI / Kerberos error from akamu-gssapi
    Mtc(String),              // MTC verification or parsing error
}
```

Handle `Acme` errors by inspecting `acme_type`:

```rust
match err {
    ClientError::Acme { acme_type, detail } => {
        eprintln!("ACME error {acme_type}: {detail}");
        // acme_type examples:
        //   "urn:ietf:params:acme:error:badNonce"
        //   "urn:ietf:params:acme:error:unauthorized"
        //   "urn:ietf:params:acme:error:incorrectResponse"
        //   "urn:ietf:params:acme:error:accountDoesNotExist"
    }
    _ => eprintln!("Other error: {err}"),
}
```

`badNonce` errors are retried automatically once by the library; if they appear in user code it means the retry also failed.
