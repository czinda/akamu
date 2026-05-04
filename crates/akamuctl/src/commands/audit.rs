use crate::client::AdminClient;
use crate::error::CtlError;
use crate::output::{print, Format};
use crate::urlenc;

#[allow(clippy::too_many_arguments)]
pub async fn query(
    client: &AdminClient,
    fmt: &Format,
    r#type: Option<String>,
    subject: Option<String>,
    from: Option<String>,
    until: Option<String>,
    outcome: Option<String>,
    limit: u32,
    offset: u32,
) -> Result<(), CtlError> {
    let mut path = format!("/admin/audit?limit={limit}&offset={offset}");
    if let Some(t) = &r#type {
        path.push_str(&format!("&type={}", urlenc(t)));
    }
    if let Some(s) = &subject {
        path.push_str(&format!("&subject={}", urlenc(s)));
    }
    if let Some(f) = &from {
        path.push_str(&format!("&from={}", urlenc(f)));
    }
    if let Some(u) = &until {
        path.push_str(&format!("&until={}", urlenc(u)));
    }
    if let Some(o) = &outcome {
        path.push_str(&format!("&outcome={}", urlenc(o)));
    }
    let resp = client.get(&path).await?;
    print(fmt, &resp);
    Ok(())
}
