//! Account management subcommands (akamuctl account …).
//!
//! Wraps the `GET /admin/accounts`, `GET /admin/account/{id}`,
//! `POST /admin/account/{id}/deactivate`, and profile-grant endpoints.

use serde_json::json;

use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::urlenc;

/// List ACME accounts, optionally filtered by status.
pub async fn list(
    client: &AdminClient,
    fmt: &Format,
    status: Option<String>,
    limit: u32,
    offset: u32,
) -> Result<(), CtlError> {
    let mut path = format!("/admin/accounts?limit={limit}&offset={offset}");
    if let Some(st) = &status {
        path.push_str(&format!("&status={}", urlenc(st)));
    }
    let resp = client.get(&path).await?;
    print(fmt, &resp);
    Ok(())
}

/// Show a single ACME account by ID.
pub async fn show(client: &AdminClient, fmt: &Format, id: &str) -> Result<(), CtlError> {
    let resp = client
        .get(&format!("/admin/account/{}", urlenc(id)))
        .await?;
    print(fmt, &resp);
    Ok(())
}

/// Deactivate an ACME account, preventing further issuance.
pub async fn deactivate(client: &AdminClient, id: &str) -> Result<(), CtlError> {
    client
        .post(&format!("/admin/account/{}/deactivate", urlenc(id)), None)
        .await?;
    println!("account {id} deactivated");
    Ok(())
}

/// Retrieve profile grants for an account.
pub async fn grants_get(client: &AdminClient, fmt: &Format, id: &str) -> Result<(), CtlError> {
    let resp = client
        .get(&format!("/admin/account/{}/profile-grants", urlenc(id)))
        .await?;
    print(fmt, &resp);
    Ok(())
}

/// Replace all profile grants for an account.
pub async fn grants_set(
    client: &AdminClient,
    fmt: &Format,
    id: &str,
    profiles: Vec<String>,
) -> Result<(), CtlError> {
    let body = json!({"profile_grants": profiles});
    let resp = client
        .put(
            &format!("/admin/account/{}/profile-grants", urlenc(id)),
            &body,
        )
        .await?;
    print(fmt, &resp);
    Ok(())
}

/// Remove all profile grants from an account.
pub async fn grants_clear(client: &AdminClient, id: &str) -> Result<(), CtlError> {
    client
        .delete(&format!("/admin/account/{}/profile-grants", urlenc(id)))
        .await?;
    println!("profile grants cleared for account {id}");
    Ok(())
}
