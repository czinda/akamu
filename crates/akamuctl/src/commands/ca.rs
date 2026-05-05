//! CA management subcommands (akamuctl ca …).

use std::path::PathBuf;

use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::urlenc;

/// List all configured CAs.
pub async fn list(client: &AdminClient, fmt: &Format) -> Result<(), CtlError> {
    let resp = client.get("/admin/cas").await?;
    print(fmt, &resp);
    Ok(())
}

/// Show details for a single CA (certificate metadata, key type, expiry).
pub async fn show(client: &AdminClient, fmt: &Format, id: &str) -> Result<(), CtlError> {
    let resp = client.get(&format!("/admin/cas/{}", urlenc(id))).await?;
    print(fmt, &resp);
    Ok(())
}

/// Download the CA certificate PEM.
pub async fn cert(
    client: &AdminClient,
    id: &str,
    output: Option<PathBuf>,
) -> Result<(), CtlError> {
    let resp = client
        .get(&format!("/admin/cas/{}/cert", urlenc(id)))
        .await?;
    let pem = resp
        .as_str()
        .ok_or_else(|| CtlError::Api("unexpected response format".into()))?;
    if let Some(path) = output {
        std::fs::write(&path, pem)?;
        println!("written to {}", path.display());
    } else {
        print!("{pem}");
    }
    Ok(())
}

/// Invalidate the CRL cache for a specific CA (forces next request to regenerate).
pub async fn crl_force(client: &AdminClient, id: &str) -> Result<(), CtlError> {
    client
        .post(&format!("/admin/cas/{}/crl/force", urlenc(id)), None)
        .await?;
    println!("CRL cache for CA '{id}' invalidated.");
    Ok(())
}

/// Issue a cross-certificate: `issuer_id` signs the public key of another CA.
///
/// Either `subject_ca_id` (same-server CA) or `subject_cert` (PEM file for an
/// external CA) must be provided; they are mutually exclusive.
pub async fn cross_sign(
    client: &AdminClient,
    fmt: &Format,
    issuer_id: &str,
    subject_ca_id: Option<String>,
    subject_cert: Option<PathBuf>,
    validity_years: u32,
) -> Result<(), CtlError> {
    let mut body = serde_json::json!({"validity_years": validity_years});

    match (subject_ca_id, subject_cert) {
        (Some(ca_id), None) => {
            body["subject_ca_id"] = serde_json::Value::String(ca_id);
        }
        (None, Some(path)) => {
            let pem = std::fs::read_to_string(&path)
                .map_err(|e| CtlError::Io(e))?;
            body["subject_cert_pem"] = serde_json::Value::String(pem);
        }
        (Some(_), Some(_)) => {
            return Err(CtlError::Config(
                "exactly one of --subject-ca-id or --subject-cert must be provided".into(),
            ));
        }
        (None, None) => {
            return Err(CtlError::Config(
                "one of --subject-ca-id or --subject-cert is required".into(),
            ));
        }
    }

    let resp = client
        .post(
            &format!("/admin/cas/{}/cross-sign", urlenc(issuer_id)),
            Some(&body),
        )
        .await?;
    print(fmt, &resp);
    Ok(())
}
