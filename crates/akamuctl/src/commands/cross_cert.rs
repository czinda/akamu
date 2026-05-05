//! Cross-certificate management subcommands (akamuctl cross-cert …).

use std::path::PathBuf;

use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::urlenc;

/// List cross-certificates with optional CA filters.
pub async fn list(
    client: &AdminClient,
    fmt: &Format,
    issuer_ca: Option<String>,
    subject_ca: Option<String>,
    limit: u32,
    offset: u32,
) -> Result<(), CtlError> {
    let mut path = format!("/admin/cross-certs?limit={limit}&offset={offset}");
    if let Some(ref id) = issuer_ca {
        path.push_str(&format!("&issuer_ca_id={}", urlenc(id)));
    }
    if let Some(ref id) = subject_ca {
        path.push_str(&format!("&subject_ca_id={}", urlenc(id)));
    }
    let resp = client.get(&path).await?;
    print(fmt, &resp);
    Ok(())
}

/// Download a single cross-certificate PEM by its UUID.
pub async fn download(
    client: &AdminClient,
    id: &str,
    output: Option<PathBuf>,
) -> Result<(), CtlError> {
    let resp = client
        .get(&format!("/admin/cross-certs/{}", urlenc(id)))
        .await?;
    let pem = resp["cross_cert_pem"]
        .as_str()
        .ok_or_else(|| CtlError::Api("cross_cert_pem field missing in response".into()))?;
    if let Some(path) = output {
        std::fs::write(&path, pem)?;
        println!("written to {}", path.display());
    } else {
        print!("{pem}");
    }
    Ok(())
}
