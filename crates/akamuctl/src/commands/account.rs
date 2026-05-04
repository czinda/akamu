use serde_json::json;

use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::urlenc;

pub async fn grants_get(client: &AdminClient, fmt: &Format, id: &str) -> Result<(), CtlError> {
    let resp = client
        .get(&format!("/admin/account/{}/profile-grants", urlenc(id)))
        .await?;
    print(fmt, &resp);
    Ok(())
}

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

pub async fn grants_clear(client: &AdminClient, id: &str) -> Result<(), CtlError> {
    client
        .delete(&format!("/admin/account/{}/profile-grants", urlenc(id)))
        .await?;
    println!("profile grants cleared for account {id}");
    Ok(())
}
