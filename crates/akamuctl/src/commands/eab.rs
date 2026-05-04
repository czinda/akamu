use serde_json::{json, Value};

use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::urlenc;

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

pub async fn remove(client: &AdminClient, kid: &str) -> Result<(), CtlError> {
    client
        .delete(&format!("/admin/eab/{}", urlenc(kid)))
        .await?;
    println!("EAB key {kid} deactivated");
    Ok(())
}
