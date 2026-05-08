//! RFC 9115 delegation management subcommands (akamuctl delegation …).

use std::path::Path;

use serde_json::{json, Value};

use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::urlenc;

fn load_json(path: &Path) -> Result<Value, CtlError> {
    let data = std::fs::read_to_string(path)?;
    serde_json::from_str(&data)
        .map_err(|e| CtlError::Api(format!("parsing {}: {e}", path.display())))
}

/// List delegation objects, optionally filtered by account.
pub async fn list(
    client: &AdminClient,
    fmt: &Format,
    account_id: Option<String>,
) -> Result<(), CtlError> {
    let path = match account_id {
        Some(ref id) => format!("/admin/delegations?account_id={}", urlenc(id)),
        None => "/admin/delegations".to_string(),
    };
    let resp = client.get(&path).await?;
    print(fmt, &resp);
    Ok(())
}

/// Show a single delegation object by ID.
pub async fn show(client: &AdminClient, fmt: &Format, id: &str) -> Result<(), CtlError> {
    let resp = client
        .get(&format!("/admin/delegations/{}", urlenc(id)))
        .await?;
    print(fmt, &resp);
    Ok(())
}

/// Create a delegation for an account.
pub async fn add(
    client: &AdminClient,
    fmt: &Format,
    account_id: String,
    csr_template_file: &Path,
    cname_map_file: Option<&Path>,
) -> Result<(), CtlError> {
    let csr_template = load_json(csr_template_file)?;
    let cname_map = cname_map_file.map(load_json).transpose()?;

    let mut body = json!({
        "account_id": account_id,
        "csr_template": csr_template,
    });
    if let Some(cm) = cname_map {
        body["cname_map"] = cm;
    }

    let resp = client.post("/admin/delegations", Some(&body)).await?;
    print(fmt, &resp);
    Ok(())
}

/// Replace the CSR template (and optionally the CNAME map) for a delegation.
pub async fn update(
    client: &AdminClient,
    id: &str,
    csr_template_file: &Path,
    cname_map_file: Option<&Path>,
    clear_cname_map: bool,
) -> Result<(), CtlError> {
    let csr_template = load_json(csr_template_file)?;
    let cname_map: Value = if clear_cname_map {
        Value::Null
    } else {
        cname_map_file
            .map(load_json)
            .transpose()?
            .unwrap_or(Value::Null)
    };

    let body = json!({
        "csr_template": csr_template,
        "cname_map": cname_map,
    });

    client
        .put(&format!("/admin/delegations/{}", urlenc(id)), &body)
        .await?;
    println!("delegation {id} updated");
    Ok(())
}

/// Delete a delegation. Fails if active orders still reference it.
pub async fn remove(client: &AdminClient, id: &str) -> Result<(), CtlError> {
    client
        .delete(&format!("/admin/delegations/{}", urlenc(id)))
        .await?;
    println!("delegation {id} deleted");
    Ok(())
}
