//! Thin ACME client helpers for the seed-data generator.
//!
//! Wraps `akamu-client` to drive the full HTTP-01 order lifecycle:
//! new-account → new-order → challenge → finalize → download.

use std::sync::Arc;

use akamu_client::{
    account::AccountKey,
    client::AcmeClient,
    csr::build_csr,
    error::ClientError,
    types::{AccountOptions, Identifier},
    Account,
};
use synta_certificate::BackendPrivateKey;

use crate::challenge::ChallengeResponder;

/// Data returned after a successful certificate issuance.
///
/// Holds all fields needed by `postprocess.rs` to locate the DB rows and
/// apply state mutations (revocation, expiry, ARI chains, etc.).
#[derive(Debug)]
pub struct IssuedCert {
    /// ACME account URL — maps to `accounts.id` in the DB.
    pub account_url: String,
    /// ACME order URL — maps to `orders.id` in the DB.
    pub order_url: String,
    /// ACME certificate download URL (the `certificate` field of the order).
    pub cert_url: String,
    /// Certificate ID — last path segment of `cert_url`; maps to `certificates.id`.
    pub cert_id: String,
    /// Downloaded PEM chain — first certificate is the end-entity.
    pub cert_pem: Vec<u8>,
    /// Profile that was requested for this order (for reference; already stored
    /// in the DB via the ACME `profile` field in the new-order payload).
    pub profile: Option<String>,
    /// CA ID the order was placed against.
    pub ca_id: String,
}

/// Register a new ACME account using the server-level endpoint.
///
/// Accounts are always registered server-wide (using `/acme/directory`) so
/// that the returned account URL is the non-CA-scoped form
/// `{base_url}/acme/account/{UUID}`, which `account_id_from_kid` can parse.
/// Use `new_ca_client` to obtain an ordering client for a specific CA.
pub async fn register_account(
    base_url: &str,
    contact: &str,
    key_type: &str,
) -> Result<Account, ClientError> {
    let dir_url = format!("{base_url}/acme/directory");
    let client = AcmeClient::new(&dir_url).await?;

    let key = AccountKey::generate(key_type)
        .map_err(|e| ClientError::Crypto(format!("account key: {e}")))?;

    let contacts = [contact];
    let opts = AccountOptions {
        contacts: &contacts,
        agree_tos: true,
        eab: None,
    };

    let account = client.new_account(Arc::new(key), &opts).await?;
    Ok(account)
}

/// Build an `AcmeClient` initialised from a specific CA's directory.
///
/// This client has the CA-specific `new-order` URL and can be paired with any
/// server-scoped `Account` (registered via `register_account`) to place orders
/// against that CA.
pub async fn new_ca_client(base_url: &str, ca_id: &str) -> Result<AcmeClient, ClientError> {
    let dir_url = format!("{base_url}/acme/{ca_id}/directory");
    AcmeClient::new(&dir_url).await
}

/// Drive the full ACME HTTP-01 cycle for the given domains.
///
/// 1. Places a new order (with optional profile).
/// 2. For each authorization: presents the HTTP-01 challenge, triggers it,
///    and cleans up after validation.
/// 3. Polls the order until ready or valid.
/// 4. Generates `cert_key_type` key, builds and submits the CSR.
/// 5. Polls until `valid`, downloads the certificate.
pub async fn issue_cert(
    client: &AcmeClient,
    account: &Account,
    responder: &ChallengeResponder,
    domains: &[String],
    cert_key_type: &str,
    profile: Option<&str>,
    ca_id: &str,
) -> Result<IssuedCert, ClientError> {
    let ids: Vec<Identifier> = domains.iter().map(Identifier::dns).collect();

    // Place the order.
    let order = client
        .new_order_with_profile(account, &ids, profile)
        .await?;
    let order_url = order.url.clone();

    // Resolve each authorization via HTTP-01, cleaning up tokens on all
    // exit paths (success or error).
    let mut presented_tokens: Vec<String> = Vec::new();
    let result = async {
        for authz_url in &order.authorizations {
            let authz = client.get_authorization(account, authz_url).await?;

            // Skip already-valid authorizations (e.g. from a previous order).
            if authz.status == "valid" {
                continue;
            }

            let challenge = authz
                .find_challenge("http-01")
                .ok_or_else(|| ClientError::Http("no http-01 challenge in authorization".into()))?
                .clone();

            let token = challenge
                .token
                .as_deref()
                .ok_or_else(|| ClientError::Http("http-01 challenge has no token".into()))?;

            let key_auth = account.key_authorization(token);

            responder.present(token, &key_auth).await;
            presented_tokens.push(token.to_string());

            client.trigger_challenge(account, &challenge).await?;
        }

        // Poll until all authorizations are valid (order becomes ready or valid).
        let order = client.poll_order(account, &order_url).await?;

        // Generate the leaf key; RSA/ML-DSA generation is CPU-intensive so run it
        // off the async executor via block_in_place.
        let key_type_owned = cert_key_type.to_string();
        let cert_key = tokio::task::block_in_place(|| generate_leaf_key(&key_type_owned))?;

        let domain_refs: Vec<&str> = domains.iter().map(String::as_str).collect();
        let csr_der = build_csr(&domain_refs, &cert_key)?;

        // Submit the CSR and poll for the final certificate.
        let order = client.finalize(account, &order, &csr_der).await?;
        let order = if order.status == "valid" {
            order
        } else {
            client.poll_order(account, &order_url).await?
        };

        let cert_url = order.certificate.ok_or_else(|| {
            ClientError::Http("order has no certificate URL after finalization".into())
        })?;

        let cert_pem = client.download_certificate(account, &cert_url).await?;

        let cert_id = cert_url.rsplit('/').next().unwrap_or("").to_string();
        Ok(IssuedCert {
            account_url: account.url.clone(),
            order_url: order_url.clone(),
            cert_url,
            cert_id,
            cert_pem,
            profile: profile.map(String::from),
            ca_id: ca_id.to_string(),
        })
    }
    .await;

    // Always clean up HTTP-01 tokens regardless of success or failure.
    for token in &presented_tokens {
        responder.cleanup(token).await;
    }

    result
}

/// Generate a leaf certificate private key from a type string like `"ec:P-256"`.
pub(crate) fn generate_leaf_key(key_type: &str) -> Result<BackendPrivateKey, ClientError> {
    let err = |e: &dyn std::fmt::Display| {
        ClientError::Crypto(format!("generate leaf key '{key_type}': {e}"))
    };
    match key_type {
        "ec:P-256" | "P-256" => BackendPrivateKey::generate_ec("P-256").map_err(|e| err(&e)),
        "ec:P-384" | "P-384" => BackendPrivateKey::generate_ec("P-384").map_err(|e| err(&e)),
        "ec:P-521" | "P-521" => BackendPrivateKey::generate_ec("P-521").map_err(|e| err(&e)),
        "rsa:2048" => BackendPrivateKey::generate_rsa(2048, 65537).map_err(|e| err(&e)),
        "rsa:3072" => BackendPrivateKey::generate_rsa(3072, 65537).map_err(|e| err(&e)),
        "rsa:4096" => BackendPrivateKey::generate_rsa(4096, 65537).map_err(|e| err(&e)),
        "ed25519" => BackendPrivateKey::generate_ed25519().map_err(|e| err(&e)),
        "ed448" => BackendPrivateKey::generate_ed448().map_err(|e| err(&e)),
        "ml-dsa-44" | "ML-DSA-44" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-44").map_err(|e| err(&e))
        }
        "ml-dsa-65" | "ML-DSA-65" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-65").map_err(|e| err(&e))
        }
        "ml-dsa-87" | "ML-DSA-87" => {
            BackendPrivateKey::generate_ml_dsa("ML-DSA-87").map_err(|e| err(&e))
        }
        other => Err(ClientError::Crypto(format!(
            "unsupported cert key type '{other}'; use ec:P-256, rsa:2048, ed25519, ml-dsa-44, …"
        ))),
    }
}
