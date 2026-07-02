use std::{fs, sync::Arc};

use akamu_client::AcmeClient;

use crate::args::RevokeArgs;
use crate::helpers::{load_account_url_for_ca, load_key, resolve_directory_url};

// ── revoke ────────────────────────────────────────────────────────────────────

pub(crate) async fn cmd_revoke(args: RevokeArgs) -> Result<(), String> {
    // Validate reason code client-side for a better error message.
    if let Some(r) = args.reason {
        if r == 7 || r > 10 {
            return Err(format!("invalid reason code {r}; valid values: 0–6, 8–10"));
        }
    }

    // Read and decode the certificate PEM → DER.
    let cert_pem =
        fs::read(&args.cert).map_err(|e| format!("read {}: {e}", args.cert.display()))?;
    let cert_ders = akamu_client::pem_to_der(&cert_pem);
    let cert_der = cert_ders
        .into_iter()
        .next()
        .ok_or_else(|| format!("no certificate found in {}", args.cert.display()))?;

    let dir_url = resolve_directory_url(&args.server, args.ca.as_deref());
    let client = AcmeClient::new(&dir_url).await.map_err(|e| e.to_string())?;

    if let Some(cert_key_path) = &args.cert_key {
        // Self-revocation: sign with the certificate's own private key.
        let cert_key = load_key(cert_key_path)?;
        let cert_key = Arc::new(cert_key);
        client
            .revoke_certificate_with_cert_key(&cert_key, &cert_der, args.reason)
            .await
            .map_err(|e| e.to_string())?;
    } else {
        // Account-key revocation.
        let key = load_key(&args.account_key)?;
        let key = Arc::new(key);
        let account_url = load_account_url_for_ca(&args.account_key, args.ca.as_deref())?;
        let account = akamu_client::Account::new(account_url, "valid".into(), vec![], key);
        client
            .revoke_certificate(&account, &cert_der, args.reason)
            .await
            .map_err(|e| e.to_string())?;
    }

    println!("Revoked: {}", args.cert.display());
    Ok(())
}
