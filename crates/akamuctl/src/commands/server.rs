use serde_json::json;

use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};

pub async fn stats(client: &AdminClient, fmt: &Format) -> Result<(), CtlError> {
    let resp = client.get("/admin/stats").await?;
    print(fmt, &resp);
    Ok(())
}

pub async fn revoke(client: &AdminClient, cert_id: &str, reason: u8) -> Result<(), CtlError> {
    let body = json!({"cert_id": cert_id, "reason": reason});
    client.post("/admin/revoke", Some(&body)).await?;
    println!("certificate {cert_id} revoked");
    Ok(())
}

pub async fn crl_force(client: &AdminClient) -> Result<(), CtlError> {
    client.post("/admin/crl/force", None).await?;
    println!("CRL regeneration triggered");
    Ok(())
}
