//! Certificate management subcommands (akamuctl cert …).

use std::path::Path;

use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::urlenc;

/// List issued certificates with optional filters.
#[allow(clippy::too_many_arguments)]
pub async fn list(
    client: &AdminClient,
    fmt: &Format,
    serial: Option<String>,
    subject: Option<String>,
    after: Option<String>,
    before: Option<String>,
    status: Option<String>,
    ca_id: Option<String>,
    limit: u32,
    offset: u32,
) -> Result<(), CtlError> {
    let mut path = format!("/admin/certs?limit={limit}&offset={offset}");
    if let Some(s) = &serial {
        path.push_str(&format!("&serial={}", urlenc(s)));
    }
    if let Some(s) = &subject {
        path.push_str(&format!("&subject={}", urlenc(s)));
    }
    if let Some(a) = &after {
        path.push_str(&format!("&after={}", urlenc(a)));
    }
    if let Some(b) = &before {
        path.push_str(&format!("&before={}", urlenc(b)));
    }
    if let Some(st) = &status {
        path.push_str(&format!("&status={}", urlenc(st)));
    }
    if let Some(ca) = &ca_id {
        path.push_str(&format!("&ca_id={}", urlenc(ca)));
    }
    let resp = client.get(&path).await?;
    print(fmt, &resp);
    Ok(())
}

/// Show metadata for a single certificate by serial or database ID.
pub async fn show(client: &AdminClient, fmt: &Format, id: &str) -> Result<(), CtlError> {
    let resp = client.get(&format!("/admin/certs/{}", urlenc(id))).await?;
    print(fmt, &resp);
    Ok(())
}

/// Download a certificate in PEM or DER format, writing to a file or stdout.
pub async fn download(
    client: &AdminClient,
    id: &str,
    format: &str,
    output: Option<&Path>,
) -> Result<(), CtlError> {
    let path = format!(
        "/admin/certs/{}/download?format={}",
        urlenc(id),
        urlenc(format)
    );
    let content = client.get_text(&path).await?;
    if let Some(out_path) = output {
        std::fs::write(out_path, &content)?;
        println!("written to {}", out_path.display());
    } else {
        print!("{content}");
    }
    Ok(())
}
