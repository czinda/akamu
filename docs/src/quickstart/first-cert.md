# Your First Certificate

This chapter shows how to obtain a certificate from your freshly running `Akāmu` using two common ACME clients: **certbot** and **acme.sh**.

Both examples use the http-01 challenge, which is the simplest to set up: the ACME server makes an HTTP request to port 80 of the domain being validated.

## Before you begin

Make sure:

1. `Akāmu` is running and reachable at `https://acme.example.com/acme/directory`.
2. The CA certificate (`/etc/akamu/ca.cert.pem`) has been added to the system trust store, or you plan to pass it explicitly to the ACME client.
3. Port 80 is reachable on the domain you want to certify so the http-01 challenge can succeed.

## Using certbot

### Install certbot

```
sudo apt install certbot      # Debian/Ubuntu
sudo dnf install certbot      # Fedora/RHEL
```

### Obtain a certificate

```
sudo certbot certonly \
  --standalone \
  --server https://acme.example.com/acme/directory \
  --email admin@yourdomain.com \
  --agree-tos \
  -d yourdomain.com
```

If the CA certificate is not yet trusted system-wide, pass it via `--no-verify-ssl` (insecure, for testing only) or add it to certbot's CA bundle.

### What happens

1. certbot fetches the directory at `https://acme.example.com/acme/directory`.
2. It creates an ACME account with the provided email address.
3. It places a new order for `yourdomain.com`.
4. `Akāmu` creates an authorization and a set of challenge objects for the domain.
5. certbot writes the key authorization file to `/.well-known/acme-challenge/<token>` on port 80.
6. certbot signals readiness by POSTing to the challenge URL.
7. `Akāmu` fetches `http://yourdomain.com/.well-known/acme-challenge/<token>` and verifies the response matches the expected key authorization.
8. Once the challenge is valid, certbot POSTs a CSR to the finalize URL.
9. `Akāmu` validates the CSR, issues the certificate, and returns the certificate URL.
10. certbot downloads the certificate from `https://acme.example.com/acme/cert/<id>`.

The certificate and private key are written to `/etc/letsencrypt/live/yourdomain.com/`.

## Using acme.sh

### Install acme.sh

```
curl https://get.acme.sh | sh -s email=admin@yourdomain.com
```

### Register an account and obtain a certificate

```
~/.acme.sh/acme.sh \
  --issue \
  --standalone \
  --server https://acme.example.com/acme/directory \
  -d yourdomain.com \
  --ca-bundle /etc/akamu/ca.cert.pem
```

The `--ca-bundle` flag tells acme.sh to trust your private CA when connecting to the ACME server. Remove it if the CA is already in the system trust store.

### Install the certificate to a target location

```
~/.acme.sh/acme.sh \
  --install-cert \
  -d yourdomain.com \
  --cert-file /etc/ssl/yourdomain.com/cert.pem \
  --key-file /etc/ssl/yourdomain.com/key.pem \
  --fullchain-file /etc/ssl/yourdomain.com/fullchain.pem \
  --reloadcmd "systemctl reload nginx"
```

## Checking the issued certificate

After a successful run, inspect the certificate:

```
openssl x509 -in /etc/letsencrypt/live/yourdomain.com/cert.pem -text -noout
```

Key fields to verify:

- **Issuer**: matches the `common_name` and `organization` from your `[ca]` configuration.
- **Subject Alternative Name**: contains `DNS:yourdomain.com`.
- **Extended Key Usage**: `TLS Web Server Authentication`.
- **Validity**: 90 days from issuance (default; adjustable via `validity_days`).

## Renewal

Both clients support automatic renewal. They check the certificate expiry and renew when less than 30 days remain.

For certbot:

```
sudo systemctl enable --now certbot.timer
```

For acme.sh, renewal is installed automatically as a cron job during `--install-cert`.

The ACME Renewal Information endpoint (`/acme/renewal-info/<cert_id>`) is available for clients that support RFC 9773. It suggests a renewal window in the last third of the certificate's validity period by default.

## Troubleshooting

**Challenge validation fails with a connection error**

Ensure port 80 is open on the domain being validated. For the http-01 challenge the server makes a plain HTTP request to port 80; no TLS is involved.

**Certificate is not trusted**

The certificate is issued by your private CA. Install the CA certificate (`/etc/akamu/ca.cert.pem`) in the trust store of every system that needs to trust the issued certificates.

**"account does not exist" error on renewal**

If you re-created the database, existing accounts were lost. Re-register with `certbot register` or re-run `acme.sh --register-account`.

## Using akamu-client (Rust)

If you are writing a Rust application and want to obtain a certificate programmatically, you can use the `akamu-client` library directly. For command-line usage without writing Rust code, see [akamu-cli](../client/cli.md).

```rust
use akamu_client::{
    AccountKey, AccountOptions, AcmeClient,
    Http01Solver, Identifier, build_csr,
};
use std::{fs, time::Duration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate or load an account key
    let key = if std::path::Path::new("account.pem").exists() {
        let pem = fs::read("account.pem")?;
        AccountKey::from_pem(&pem)?
    } else {
        let k = AccountKey::generate("ec:P-256")?;
        fs::write("account.pem", k.to_pem()?)?;
        k
    };

    // 2. Connect to the ACME directory
    let client = AcmeClient::new("https://acme.example.com/acme/directory").await?;

    // 3. Register an account (agree to Terms of Service)
    let opts = AccountOptions {
        contacts: vec!["mailto:admin@example.com".to_string()],
        agree_tos: true,
        eab: None,
    };
    let account = client.new_account(&key, opts).await?;

    // 4. Place an order for the desired identifiers
    let ids = vec![Identifier::Dns("example.com".to_string())];
    let order = client.new_order(&account, ids).await?;

    // 5. Start the built-in http-01 solver on port 80
    let solver = Http01Solver::new(80);
    solver.start().await?;

    // 6. Solve each authorization
    for authz_url in &order.authorizations {
        let authz = client.get_authorization(&account, authz_url).await?;
        let challenge = authz
            .challenges
            .into_iter()
            .find(|c| c.challenge_type == "http-01")
            .ok_or("http-01 challenge not available")?;

        // Present the key authorization at the well-known URL
        let key_auth = account.key_authorization(&challenge.token);
        solver.present(&challenge.token, &key_auth).await?;

        // Signal readiness to the ACME server
        client.trigger_challenge(&account, &challenge).await?;

        // Poll until the authorization is validated
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let updated = client.get_authorization(&account, authz_url).await?;
            match updated.status.as_str() {
                "valid"   => break,
                "invalid" => return Err("authorization failed".into()),
                _         => continue,
            }
        }

        // Remove the challenge token from the solver
        solver.cleanup(&challenge.token).await?;
    }

    // 7. Generate a certificate key, build a CSR, and finalize the order
    let cert_key = AccountKey::generate("ec:P-256")?;
    fs::write("cert.key.pem", cert_key.to_pem()?)?;

    let csr_der  = build_csr(&["example.com"], &cert_key)?;
    let finalized = client.finalize(&account, &order, &csr_der).await?;

    let cert_url = finalized.certificate.ok_or("no certificate URL")?;

    // 8. Download the certificate bundle and write to disk
    let pem = client.download_certificate(&account, &cert_url).await?;
    fs::write("cert.pem", &pem)?;

    println!("Certificate written to cert.pem");
    println!("Private key written to cert.key.pem");
    Ok(())
}
```

Add the following to your `Cargo.toml`:

```toml
[dependencies]
akamu-client = { path = "/path/to/akamu/crates/akamu-client" }
tokio = { version = "1", features = ["full"] }
```
