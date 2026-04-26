# akamu-client

Full ACME client library for the Akamu project (RFC 8555), with support for
classical and post-quantum (ML-DSA) account keys.

## What this crate provides

- **`AcmeClient`** — directory-aware async client.  Fetches the ACME directory
  on construction, manages anti-replay nonces, and handles the complete order
  lifecycle.
- **`AccountKey`** — account key holder.  Generates or loads PEM private keys
  (EC P-256/P-384/P-521, RSA 2048/3072/4096, Ed25519, Ed448, ML-DSA-44/65/87),
  derives the public JWK, computes the RFC 7638 thumbprint, and determines the
  correct JWS `alg` string automatically.
- **`Account`** — registered account, returned by `new_account()`.  Carries the
  account URL and key reference used for all subsequent signed requests.
- **`AccountOptions`** / **`EabOptions`** — registration options, including
  optional External Account Binding (RFC 8555 §7.3.4).
- **`ChallengeSolver`** trait — implement this for custom challenge types.
- **`Http01Solver`** — built-in http-01 solver.  Binds a minimal HTTP/1.1
  server on a configurable port and serves
  `/.well-known/acme-challenge/<token>` responses.
- **`Dns01Helper`** / **`DnsPersist01Helper`** — compute the
  `base64url(SHA-256(key_authorization))` value for dns-01 and dns-persist-01
  TXT records.  DNS provisioning is the caller's responsibility.
- **`build_csr(domains, key)`** — build a DER-encoded CSR.  The first domain
  becomes the Common Name; all domains are added as dNSName SANs.
- **STAR order API** — `new_star_order()`, `cancel_star_order()`,
  `get_star_certificate()`, and `download_star_certificate()` implement RFC 8739
  Short-Term, Automatically Renewed (STAR) certificate orders.  Use
  `StarOrderParams` to configure the end date, per-certificate lifetime, and
  optional `lifetime-adjust` clock-skew window.
- **`ClientError`** — unified error type wrapping `JoseError`, HTTP errors,
  ACME problem document errors, crypto errors, and I/O errors.

## End-to-end example

```rust
use std::sync::Arc;
use akamu_client::{
    AccountKey, AccountOptions, AcmeClient, Http01Solver, Identifier,
    build_csr, ChallengeSolver as _,
};
use synta_certificate::BackendPrivateKey;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate an account key.
    let account_key = Arc::new(AccountKey::generate("ec:P-256")?);

    // 2. Connect to the ACME directory.
    let client = AcmeClient::new("https://acme-v02.api.letsencrypt.org/directory").await?;

    // 3. Register a new account.
    let opts = AccountOptions {
        contacts: &["mailto:admin@example.com"],
        agree_tos: true,
        eab: None,
    };
    let account = client.new_account(Arc::clone(&account_key), &opts).await?;
    println!("Account URL: {}", account.url);

    // 4. Place an order.
    let ids = vec![Identifier::dns("example.com")];
    let order = client.new_order(&account, &ids).await?;

    // 5. Start the http-01 challenge responder (port 80).
    let solver = Http01Solver::new(80);
    solver.start().await?;

    // 6. Satisfy each authorization.
    for authz_url in &order.authorizations {
        let authz = client.get_authorization(&account, authz_url).await?;
        if authz.status == "valid" { continue; }

        let chall = authz.find_challenge("http-01").expect("no http-01 challenge");
        let token = chall.token.as_deref().expect("challenge missing token");
        let key_auth = account.key_authorization(token);

        solver.present(token, &key_auth).await?;
        client.trigger_challenge(&account, chall).await?;
        client.poll_order(&account, &order.url).await?;
        solver.cleanup(token).await?;
    }

    // 7. Build a CSR and finalize the order.
    let cert_key = BackendPrivateKey::generate_ec("P-256").unwrap();
    let csr_der = build_csr(&["example.com"], &cert_key)?;
    let order = client.finalize(&account, &order, &csr_der).await?;

    // 8. Poll if the server did not finalize synchronously.
    let order = if order.certificate.is_some() {
        order
    } else {
        client.poll_order(&account, &order.url).await?
    };

    // 9. Download the certificate chain.
    let cert_url = order.certificate.as_deref().expect("no certificate URL");
    let pem = client.download_certificate(&account, cert_url).await?;
    std::fs::write("chain.pem", &pem)?;
    Ok(())
}
```

## Account deactivation

After registering, you can deactivate an account with a single call:

```rust
client.deactivate_account(&account).await?;
```

This posts `{"status":"deactivated"}` to the account URL (RFC 8555 §7.3.7).

## External Account Binding

When the CA requires EAB, pass `EabOptions` inside `AccountOptions`:

```rust
use akamu_client::{AccountOptions, EabOptions};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

let raw_hmac_key = URL_SAFE_NO_PAD.decode("base64url-encoded-key-from-CA")?;

let opts = AccountOptions {
    contacts: &["mailto:admin@example.com"],
    agree_tos: true,
    eab: Some(EabOptions {
        kid: "kid-assigned-by-ca",
        hmac_key: &raw_hmac_key,
        alg: "HS256", // "HS256", "HS384", or "HS512"
    }),
};
```

The `hmac_key` field takes raw bytes; decode from base64url before passing it
in.  The `alg` field defaults to `"HS256"` when left unspecified in higher-level
callers.

## Key type strings

`AccountKey::generate` and the CLI `--key-type` / `--cert-key-type` flags
accept these strings:

| String | Algorithm |
|--------|-----------|
| `ec:P-256` | ECDSA P-256 (ES256) |
| `ec:P-384` | ECDSA P-384 (ES384) |
| `ec:P-521` | ECDSA P-521 (ES512) |
| `rsa:2048` | RSA-PSS 2048-bit (PS256) |
| `rsa:3072` | RSA-PSS 3072-bit (PS256) |
| `rsa:4096` | RSA-PSS 4096-bit (PS256) |
| `ed25519` | EdDSA Ed25519 |
| `ed448` | EdDSA Ed448 |
| `ml-dsa-44` | ML-DSA-44 (post-quantum) |
| `ml-dsa-65` | ML-DSA-65 (post-quantum) |
| `ml-dsa-87` | ML-DSA-87 (post-quantum) |

The JWS `alg` string is inferred automatically from the key material.

## Dependency note — PQC support

This crate depends on `akamu-jose` and `synta-certificate` with the `pqc`
feature.  ML-DSA and other post-quantum primitives are provided via
`native-ossl`, which is published on crates.io.  No git fork or
`[patch.crates-io]` block is required.

## License

GPL-3.0-or-later
