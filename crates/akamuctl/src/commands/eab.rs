//! External Account Binding (EAB) key management subcommands (akamuctl eab …).

use serde_json::{json, Value};

use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::urlenc;

/// List EAB keys, optionally filtering to used or unused only.
pub async fn list(
    client: &AdminClient,
    fmt: &Format,
    used: bool,
    unused: bool,
) -> Result<(), CtlError> {
    let mut path = "/admin/eab".to_string();
    if used && !unused {
        path.push_str("?used=true");
    } else if unused && !used {
        path.push_str("?used=false");
    }
    let resp = client.get(&path).await?;
    print(fmt, &resp);
    Ok(())
}

/// Provision a new EAB key, optionally specifying KID, HMAC key, and profile grants.
pub async fn add(
    client: &AdminClient,
    fmt: &Format,
    kid: Option<String>,
    hmac_key: Option<String>,
    profiles: Vec<String>,
) -> Result<(), CtlError> {
    let mut body = json!({});
    if let Some(k) = kid {
        body["kid"] = Value::String(k);
    }
    if let Some(h) = hmac_key {
        body["hmac_key_b64u"] = Value::String(h);
    }
    if !profiles.is_empty() {
        body["profile_grants"] = Value::Array(profiles.into_iter().map(Value::String).collect());
    }
    let resp = client.post("/admin/eab", Some(&body)).await?;
    print(fmt, &resp);
    Ok(())
}

/// Show details for a single EAB key by KID.
pub async fn show(client: &AdminClient, fmt: &Format, kid: &str) -> Result<(), CtlError> {
    let resp = client.get(&format!("/admin/eab/{}", urlenc(kid))).await?;
    print(fmt, &resp);
    Ok(())
}

/// Deactivate an EAB key so it can no longer be used for account creation.
pub async fn remove(client: &AdminClient, kid: &str) -> Result<(), CtlError> {
    client
        .delete(&format!("/admin/eab/{}", urlenc(kid)))
        .await?;
    println!("EAB key {kid} deactivated");
    Ok(())
}
