use std::sync::{Arc, Mutex};

use crate::client::AdminClient;
use crate::config::{CosignerConfig, SessionCache};
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::read_file_opt;

pub fn build_client(
    cosigner_cfg: Option<&CosignerConfig>,
    ca_cert_fallback: Option<Vec<u8>>,
    cert_fallback: Option<Vec<u8>>,
    key_fallback: Option<Vec<u8>>,
    session_cache: Arc<Mutex<SessionCache>>,
) -> Result<AdminClient, CtlError> {
    let cosigner_url = cosigner_cfg
        .and_then(|c| c.url.clone())
        .unwrap_or_else(|| "https://localhost:9444".into());
    let cos_ca = read_file_opt(
        cosigner_cfg
            .and_then(|c| c.ca_cert.as_deref())
            .map(std::path::Path::new),
    )?
    .or(ca_cert_fallback);
    let cos_cert = read_file_opt(
        cosigner_cfg
            .and_then(|c| c.cert_file.as_deref())
            .map(std::path::Path::new),
    )?
    .or(cert_fallback);
    let cos_key = read_file_opt(
        cosigner_cfg
            .and_then(|c| c.key_file.as_deref())
            .map(std::path::Path::new),
    )?
    .or(key_fallback);
    let cos_gssapi = cosigner_cfg.and_then(|c| c.gssapi_service.clone());
    AdminClient::new(
        cosigner_url,
        cos_ca,
        cos_cert,
        cos_key,
        session_cache,
        true,
        cos_gssapi,
    )
}

pub async fn login(client: &AdminClient, fmt: &Format) -> Result<(), CtlError> {
    let resp = client.post("/admin/session", None).await?;
    print(fmt, &resp);
    Ok(())
}

pub async fn logout(client: &AdminClient) -> Result<(), CtlError> {
    client.delete("/admin/session").await?;
    client.clear_session();
    println!("logged out (cosigner)");
    Ok(())
}

pub async fn status(client: &AdminClient, fmt: &Format) -> Result<(), CtlError> {
    let resp = client.get("/admin/status").await?;
    print(fmt, &resp);
    Ok(())
}

pub async fn stats(client: &AdminClient, fmt: &Format) -> Result<(), CtlError> {
    let resp = client.get("/admin/stats").await?;
    print(fmt, &resp);
    Ok(())
}

pub async fn config(client: &AdminClient, fmt: &Format) -> Result<(), CtlError> {
    let resp = client.get("/admin/config").await?;
    print(fmt, &resp);
    Ok(())
}
