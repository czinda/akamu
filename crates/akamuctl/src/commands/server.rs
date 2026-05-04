use serde_json::json;

use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::urlenc;

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

pub async fn profile_list(client: &AdminClient, fmt: &Format) -> Result<(), CtlError> {
    let resp = client.get("/admin/profiles").await?;
    print(fmt, &resp);
    Ok(())
}

pub async fn profile_add(
    client: &AdminClient,
    fmt: &Format,
    id: &str,
    params_file: &std::path::Path,
) -> Result<(), CtlError> {
    let data = std::fs::read_to_string(params_file)?;
    let mut body: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| CtlError::Api(format!("parsing {}: {e}", params_file.display())))?;
    body["id"] = json!(id);
    let resp = client.post("/admin/profiles", Some(&body)).await?;
    print(fmt, &resp);
    Ok(())
}

pub async fn profile_update(
    client: &AdminClient,
    fmt: &Format,
    id: &str,
    params_file: &std::path::Path,
) -> Result<(), CtlError> {
    let data = std::fs::read_to_string(params_file)?;
    let body: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| CtlError::Api(format!("parsing {}: {e}", params_file.display())))?;
    let resp = client.put(&format!("/admin/profiles/{id}"), &body).await?;
    print(fmt, &resp);
    Ok(())
}

pub async fn profile_remove(client: &AdminClient, _fmt: &Format, id: &str) -> Result<(), CtlError> {
    client.delete(&format!("/admin/profiles/{id}")).await
}

#[allow(clippy::too_many_arguments)]
pub async fn order_list(
    client: &AdminClient,
    fmt: &Format,
    account_id: Option<String>,
    status: Option<String>,
    limit: u32,
    offset: u32,
) -> Result<(), CtlError> {
    let mut path = format!("/admin/orders?limit={limit}&offset={offset}");
    if let Some(a) = &account_id {
        path.push_str(&format!("&account_id={}", urlenc(a)));
    }
    if let Some(st) = &status {
        path.push_str(&format!("&status={}", urlenc(st)));
    }
    let resp = client.get(&path).await?;
    print(fmt, &resp);
    Ok(())
}

pub async fn order_show(client: &AdminClient, fmt: &Format, id: &str) -> Result<(), CtlError> {
    let resp = client.get(&format!("/admin/orders/{}", urlenc(id))).await?;
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
