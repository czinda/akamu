//! ACME EAB bootstrap for akamu-cosigner.
//!
//! When `[acme_bootstrap]` is configured, this module runs at startup to
//! obtain a certificate from the ACME server using External Account Binding.
//! The issued certificate is stored on disk and used as the TLS server
//! certificate.  The cosigner's identity is the `TrustAnchorID` OID from
//! `cosigner_id.trust_anchor_id`; the ACME certificate plays no role in the
//! `SubtreeSignature.cosigner` field under draft-04.
//!
//! Challenge types supported:
//! - `"http-01"` — tokens served by the main Axum server at
//!   `GET /.well-known/acme-challenge/:token`; requires port 80 to be
//!   reachable by the ACME server (or an upstream proxy).
//! - `"dns-01"` — TXT record value is logged; an optional `dns_hook` shell
//!   command is called with `ACME_DOMAIN` and `ACME_TXT_VALUE` env vars to
//!   automate DNS provisioning.
//! - `"tls-alpn-01"` — ephemeral challenge certs served by a temporary TLS
//!   server on port 443.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use akamu_client::{
    build_csr, AccountKey, AccountOptions, AcmeClient, Dns01Helper, EabOptions, Identifier,
    TlsAlpn01Solver,
};

use crate::config::AcmeBootstrapConfig;
use crate::error::CosignerError;

/// Run the ACME EAB bootstrap flow.
///
/// Returns the issued certificate and private key as PEM bytes.  Both are
/// written to `cfg.cert_file` and `cfg.key_file`.
///
/// `challenge_tokens` is the shared http-01 token store from `AppState`;
/// tokens inserted here are served by the main Axum router.
pub async fn run_bootstrap(
    cfg: &AcmeBootstrapConfig,
    challenge_tokens: Arc<RwLock<HashMap<String, String>>>,
) -> Result<(), CosignerError> {
    tracing::info!(
        server_url = %cfg.server_url,
        domain = %cfg.domain,
        challenge = %cfg.challenge_type,
        "starting ACME EAB bootstrap"
    );

    // ── Generate CSR key ──────────────────────────────────────────────────────
    let csr_key_path = format!("{}.acme-account.key", cfg.key_file);
    let account_key = if std::path::Path::new(&csr_key_path).exists() {
        let pem = std::fs::read(&csr_key_path)?;
        AccountKey::from_pem(&pem)?
    } else {
        let ak = AccountKey::generate(&cfg.csr_key_type)?;
        crate::key::write_private_file(&csr_key_path, &ak.to_pem()?)?;
        ak
    };
    let csr_backend_key =
        synta_certificate::BackendPrivateKey::from_pem(&account_key.to_pem()?, None)
            .map_err(|e| CosignerError::Crypto(format!("CSR key: {e}")))?;

    // ── Connect to ACME directory ─────────────────────────────────────────────
    let client = AcmeClient::new(&cfg.server_url).await?;

    // ── Register / find account ───────────────────────────────────────────────
    let hmac_bytes = decode_eab_hmac(&cfg.eab_hmac)?;
    let contacts: Vec<&str> = cfg
        .account_email
        .as_deref()
        .map(|e| {
            // Leak is OK: this runs once at startup, lifetime doesn't matter.
            Box::leak(format!("mailto:{e}").into_boxed_str()) as &str
        })
        .into_iter()
        .collect();
    let eab = EabOptions {
        kid: &cfg.eab_kid,
        hmac_key: &hmac_bytes,
        alg: "HS256",
    };
    let opts = AccountOptions {
        contacts: &contacts,
        agree_tos: true,
        eab: Some(eab),
    };
    let acct = client.new_account(Arc::new(account_key), &opts).await?;

    // ── Place order ───────────────────────────────────────────────────────────
    let order = client
        .new_order(&acct, &[Identifier::dns(cfg.domain.clone())])
        .await?;

    // ── TLS-ALPN-01 solver setup (if needed) ─────────────────────────────────
    let mut tls_alpn_solver: Option<TlsAlpn01Solver> = None;
    if cfg.challenge_type == "tls-alpn-01" {
        let mut solver = TlsAlpn01Solver::new(443);
        solver.start().await?;
        tls_alpn_solver = Some(solver);
    }

    // ── Solve authorizations ──────────────────────────────────────────────────
    for auth_url in &order.authorizations {
        let auth = client.get_authorization(&acct, auth_url).await?;
        if auth.status == "valid" {
            continue;
        }

        let challenge = auth
            .find_challenge(&cfg.challenge_type)
            .ok_or_else(|| CosignerError::NoChallengeType(cfg.challenge_type.clone()))?;

        match cfg.challenge_type.as_str() {
            "http-01" => {
                let token = challenge.token.as_deref().ok_or_else(|| {
                    CosignerError::BadRequest("http-01 challenge has no token".into())
                })?;
                let key_auth = acct.key_authorization(token);
                challenge_tokens
                    .write()
                    .unwrap_or_else(|e| {
                        tracing::error!("challenge_tokens RwLock poisoned; recovering: {e}");
                        e.into_inner()
                    })
                    .insert(token.to_owned(), key_auth);
            }
            "dns-01" => {
                let token = challenge.token.as_deref().ok_or_else(|| {
                    CosignerError::BadRequest("dns-01 challenge has no token".into())
                })?;
                let key_auth = acct.key_authorization(token);
                let txt = Dns01Helper::txt_value(&key_auth)?;
                tracing::info!(
                    domain = %cfg.domain,
                    txt = %txt,
                    "dns-01: set TXT record _acme-challenge.{} = {}",
                    cfg.domain,
                    txt
                );
                if let Some(hook) = &cfg.dns_hook {
                    let status = tokio::process::Command::new(hook)
                        .env("ACME_DOMAIN", &cfg.domain)
                        .env("ACME_TXT_VALUE", &txt)
                        .status()
                        .await
                        .map_err(|e| {
                            CosignerError::Acme(format!("dns_hook '{}' failed: {e}", hook))
                        })?;
                    if !status.success() {
                        return Err(CosignerError::Acme(format!(
                            "dns_hook '{}' exited with {}",
                            hook, status
                        )));
                    }
                } else {
                    tracing::warn!(
                        "dns-01: no dns_hook configured — set the TXT record manually, \
                         then restart akamu-cosigner"
                    );
                    return Err(CosignerError::Acme(
                        "dns-01 requires dns_hook or manual DNS setup".into(),
                    ));
                }
            }
            "dns-persist-01" => {
                let issuer_domain = challenge
                    .issuer_domain_names
                    .as_deref()
                    .and_then(|v| v.first())
                    .map(String::as_str)
                    .ok_or_else(|| {
                        CosignerError::Acme(
                            "dns-persist-01 challenge has no issuer-domain-names".into(),
                        )
                    })?;
                let account_uri = &acct.url;
                let base_domain = cfg.domain.trim_start_matches("*.");
                let txt_name = format!("_validation-persist.{base_domain}");
                let txt_value = format!("{issuer_domain}; accounturi={account_uri}");
                tracing::info!(
                    domain = %cfg.domain,
                    txt_name = %txt_name,
                    txt_value = %txt_value,
                    "dns-persist-01: set TXT record {} = {}",
                    txt_name,
                    txt_value
                );
                if let Some(hook) = &cfg.dns_persist_hook {
                    let status = tokio::process::Command::new(hook)
                        .env("ACME_DOMAIN", &cfg.domain)
                        .env("ACME_TXT_NAME", &txt_name)
                        .env("ACME_TXT_VALUE", &txt_value)
                        .env("ACME_ACCOUNT_URI", account_uri.as_str())
                        .env("ACME_ISSUER_DOMAIN", issuer_domain)
                        .status()
                        .await
                        .map_err(|e| {
                            CosignerError::Acme(format!("dns_persist_hook '{}' failed: {e}", hook))
                        })?;
                    if !status.success() {
                        return Err(CosignerError::Acme(format!(
                            "dns_persist_hook '{}' exited with {}",
                            hook, status
                        )));
                    }
                } else {
                    tracing::warn!(
                        "dns-persist-01: no dns_persist_hook configured — set the TXT record \
                         manually ({txt_name} = \"{txt_value}\"), then restart akamu-cosigner"
                    );
                    return Err(CosignerError::Acme(
                        "dns-persist-01 requires dns_persist_hook or manual DNS setup".into(),
                    ));
                }
            }
            "tls-alpn-01" => {
                let token = challenge.token.as_deref().ok_or_else(|| {
                    CosignerError::BadRequest("tls-alpn-01 challenge has no token".into())
                })?;
                let key_auth = acct.key_authorization(token);
                if let Some(ref solver) = tls_alpn_solver {
                    solver
                        .present(&auth.identifier.value, &auth.identifier.r#type, &key_auth)
                        .await?;
                }
            }
            t => return Err(CosignerError::UnknownChallengeType(t.to_owned())),
        }

        client.trigger_challenge(&acct, challenge).await?;
    }

    // ── Poll order until ready ────────────────────────────────────────────────
    let ready_order = poll_order_until_ready(&client, &acct, &order.url).await?;

    // ── Build CSR and finalize ────────────────────────────────────────────────
    let csr_der = build_csr(&[cfg.domain.as_str()], &csr_backend_key)?;
    let valid_order = client.finalize(&acct, &ready_order, &csr_der).await?;
    let valid_order = poll_order_until_ready(&client, &acct, &valid_order.url).await?;

    // ── Download certificate ──────────────────────────────────────────────────
    let cert_url = valid_order
        .certificate
        .as_deref()
        .ok_or_else(|| CosignerError::Acme("order has no certificate URL".into()))?;
    let cert_pem = client.download_certificate(&acct, cert_url).await?;

    // ── Persist cert + key ────────────────────────────────────────────────────
    std::fs::write(&cfg.cert_file, &cert_pem)?;

    // Write the CSR key as TLS key (same key used for the CSR).
    let key_pem = csr_backend_key
        .to_pem(None)
        .map_err(|e| CosignerError::Crypto(format!("TLS key to PEM: {e}")))?;
    crate::key::write_private_file(&cfg.key_file, &key_pem)?;

    tracing::info!(
        cert_file = %cfg.cert_file,
        key_file = %cfg.key_file,
        "ACME bootstrap complete"
    );

    // Cleanup TLS-ALPN solver.
    if let Some(mut solver) = tls_alpn_solver {
        solver.cleanup();
    }

    // Cleanup http-01 tokens.
    challenge_tokens
        .write()
        .unwrap_or_else(|e| {
            tracing::error!("challenge_tokens RwLock poisoned during cleanup; recovering: {e}");
            e.into_inner()
        })
        .clear();

    Ok(())
}

/// Decode a base64url-encoded EAB HMAC key.
fn decode_eab_hmac(b64u: &str) -> Result<Vec<u8>, CosignerError> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    URL_SAFE_NO_PAD
        .decode(b64u)
        .map_err(|e| CosignerError::Config(format!("eab_hmac is not valid base64url: {e}")))
}

/// Poll `order_url` with exponential backoff until status is `"ready"` or `"valid"`.
async fn poll_order_until_ready(
    client: &AcmeClient,
    acct: &akamu_client::Account,
    order_url: &str,
) -> Result<akamu_client::Order, CosignerError> {
    client
        .poll_order(acct, order_url, std::time::Duration::from_secs(30))
        .await
        .map_err(Into::into)
}

/// Check whether the certificate at `cert_file` is expiring within `days` days.
///
/// Returns `true` if the cert is absent, unparseable, or expires within the threshold.
pub fn cert_needs_renewal(cert_file: &str, days: i64) -> bool {
    let Ok(pem) = std::fs::read(cert_file) else {
        tracing::warn!(
            cert_file,
            "cert_needs_renewal: cannot read file; treating as needing renewal"
        );
        return true;
    };
    let der = match synta_certificate::pem_to_der(&pem).into_iter().next() {
        Some(d) => d,
        None => {
            tracing::warn!(
                cert_file,
                "cert_needs_renewal: no certificate found in PEM; treating as needing renewal"
            );
            return true;
        }
    };
    // Parse validity from the first cert in the chain.
    let not_after = match parse_not_after(&der) {
        Some(t) => t,
        None => {
            tracing::warn!(cert_file, "cert_needs_renewal: cannot parse certificate validity; treating as needing renewal");
            return true;
        }
    };
    let threshold_secs = days * 86400;
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    not_after - now_secs < threshold_secs
}

fn parse_not_after(der: &[u8]) -> Option<i64> {
    use synta::{Decoder, Encoding};
    use synta_certificate::owned::Certificate;

    let mut dec = Decoder::new(der, Encoding::Der);
    let cert: Certificate = dec.decode().ok()?;
    let na = &cert.tbs_certificate.validity.not_after;
    Some(time_to_unix(na))
}

fn time_to_unix(t: &synta_certificate::owned::Time) -> i64 {
    use synta_certificate::owned::Time;
    match t {
        Time::GeneralTime(gt) => gt.to_unix(),
        Time::UtcTime(ut) => {
            // Convert UtcTime fields into a GeneralizedTime then to unix.
            synta::GeneralizedTime::new(
                ut.year, ut.month, ut.day, ut.hour, ut.minute, ut.second, None,
            )
            .map(|gt| gt.to_unix())
            .unwrap_or(0)
        }
    }
}
