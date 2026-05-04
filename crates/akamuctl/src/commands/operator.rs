use std::path::PathBuf;

use serde_json::json;

use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::sha256_hex;

pub async fn list(client: &AdminClient, fmt: &Format) -> Result<(), CtlError> {
    let resp = client.get("/admin/operators").await?;
    print(fmt, &resp);
    Ok(())
}

pub async fn add(
    client: &AdminClient,
    fmt: &Format,
    name: String,
    role: String,
    cert_file: Option<PathBuf>,
    gssapi_principal: Option<String>,
) -> Result<(), CtlError> {
    let cert_fp = if let Some(path) = cert_file {
        let pem = std::fs::read(&path)?;
        let ders = synta_certificate::pem_to_der(&pem);
        let der = ders
            .into_iter()
            .next()
            .ok_or_else(|| CtlError::Config("cert_file contains no certificate".into()))?;
        Some(sha256_hex(&der)?)
    } else {
        None
    };
    let body = json!({
        "name": name,
        "role": role,
        "cert_fingerprint": cert_fp,
        "gssapi_principal": gssapi_principal,
    });
    let resp = client.post("/admin/operators", Some(&body)).await?;
    print(fmt, &resp);
    Ok(())
}

pub async fn show(client: &AdminClient, fmt: &Format, id: i64) -> Result<(), CtlError> {
    let resp = client.get(&format!("/admin/operators/{id}")).await?;
    print(fmt, &resp);
    Ok(())
}

pub async fn update(
    client: &AdminClient,
    id: i64,
    name: Option<String>,
    role: Option<String>,
    cert_file: Option<PathBuf>,
    gssapi_principal: Option<String>,
) -> Result<(), CtlError> {
    let cert_fp = if let Some(path) = cert_file {
        let pem = std::fs::read(&path)?;
        let ders = synta_certificate::pem_to_der(&pem);
        let der = ders
            .into_iter()
            .next()
            .ok_or_else(|| CtlError::Config("cert_file contains no certificate".into()))?;
        Some(sha256_hex(&der)?)
    } else {
        None
    };
    let body = json!({
        "name": name,
        "role": role,
        "cert_fingerprint": cert_fp,
        "gssapi_principal": gssapi_principal,
    });
    client.put(&format!("/admin/operators/{id}"), &body).await?;
    println!("operator {id} updated");
    Ok(())
}

pub async fn remove(client: &AdminClient, fmt: &Format, id: i64) -> Result<(), CtlError> {
    let body = json!({"active": false});
    let resp = client
        .patch(&format!("/admin/operators/{id}"), &body)
        .await?;
    print(fmt, &resp);
    Ok(())
}

pub async fn activate(client: &AdminClient, fmt: &Format, id: i64) -> Result<(), CtlError> {
    let body = json!({"active": true});
    let resp = client
        .patch(&format!("/admin/operators/{id}"), &body)
        .await?;
    print(fmt, &resp);
    Ok(())
}
